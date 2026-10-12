"""Hash-locked conditional increment (XBT-055 / B4 merge into B1).

A Spilman state that already pays `uncond` to the payee plus `cond` to a P2WSH hashlock:

    OP_IF    OP_SHA256 <H> OP_EQUALVERIFY <P> OP_CHECKSIG
    OP_ELSE  <Δ> OP_CSV OP_DROP <A> OP_CHECKSIG
    OP_ENDIF

RDTS-legal: OP_IF is in P2WSH, not tapscript. The seller claims with preimage k (sha256(k)=H);
the buyer refunds the increment after `csv_delta` blocks if k never arrives. The parent channel
close/refund still covers the uncond balance. After k is revealed off-chain the buyer signs an
unconditional upgrade (uncond+cond), which both sides prefer.
"""
import hashlib

from .channel import DUST, ChannelError, ChannelParams
from .tx import (OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY,
                 OP_IF, OP_SHA256, SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxOut, p2wsh_spk, push,
                 script_num, unified_sighash)
from . import ecc


CSV_DELTA = 10


def hashlock_script(payee_pub: bytes, payer_pub: bytes, h: bytes, csv_delta: int = CSV_DELTA) -> bytes:
    if len(h) != 32:
        raise ChannelError("bad_hashlock", "H must be 32 bytes")
    return (bytes([OP_IF, OP_SHA256]) + push(h) + bytes([OP_EQUALVERIFY])
            + push(payee_pub) + bytes([OP_CHECKSIG, OP_ELSE])
            + script_num(csv_delta) + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP])
            + push(payer_pub) + bytes([OP_CHECKSIG, OP_ENDIF]))


def xor_stream(key: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:n]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: bytes, k: bytes) -> bytes:
    return xor(plaintext, xor_stream(k, len(plaintext)))


decrypt = encrypt


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def preimage_from_tx(tx, h: bytes) -> bytes:
    """k from a hash-lock claim (any witness item whose SHA-256 is H), or b"" if `tx` reveals none.
    The claim that pays the provider publishes k, so a payer holding the ciphertext always gets the
    deliverable, even when the paid response never arrived (AGP-005 M7)."""
    from .tx import Tx
    if isinstance(tx, str):
        tx = bytes.fromhex(tx)
    if isinstance(tx, bytes):
        tx = Tx.parse(tx)
    return next((w for i in tx.inputs for w in (i.witness or []) if sha256(w) == h), b"")


class ConditionalParams:
    def __init__(self, channel: ChannelParams, h: bytes, cond_amount: int, csv_delta: int = CSV_DELTA):
        if cond_amount < DUST:
            raise ChannelError("bad_amount", "conditional increment below dust")
        self.channel, self.h, self.cond_amount, self.csv_delta = channel, h, cond_amount, csv_delta
        self.script = hashlock_script(bytes.fromhex(channel.payee_pub), bytes.fromhex(channel.payer_pub),
                                      h, csv_delta)
        self.spk = p2wsh_spk(self.script)

    def state_tx(self, uncond: int) -> Tx:
        """uncond to payee, cond to hashlock, remainder to payer, the close fee out of
        close_fee_payer's side. Under payee-pays (v1.2) the fee comes out of the payee's
        unconditional output, which must then exist and clear dust after it (uncond >= min_amount):
        the hash-lock output stays exactly cond_amount, so a payer that reclaims it through the CSV
        branch never pays the payee's close fee, and the payer's change is capacity - uncond - cond."""
        p = self.channel
        if (uncond or p.payee_fee) and not p.min_amount <= uncond <= p.max_amount:
            raise ChannelError("bad_amount", f"uncond {uncond} out of range [{p.min_amount}, {p.max_amount}]")
        total = uncond + self.cond_amount + p.payer_fee
        if total > p.capacity:
            raise ChannelError("channel_exhausted", "conditional increment does not fit")
        outs = []
        if uncond:
            outs.append(TxOut(p.payee_value(uncond), bytes.fromhex(p.payee_spk)))
        outs.append(TxOut(self.cond_amount, self.spk))
        change = p.capacity - total
        if change >= DUST:
            outs.append(TxOut(change, bytes.fromhex(p.payer_spk)))
        return Tx(version=2, inputs=[p._funding_in()], outputs=outs, locktime=0)

    def sighash(self, tx: Tx) -> bytes:
        return unified_sighash(tx, [self.channel.funding_prevout()], 0, ST_WITNESS_V0,
                               self.channel.script, SIGHASH_ALL_UNIFIED)

    def claim_tx(self, close_txid: str, vout: int, k: bytes, payee_secret: int, dest: bytes, fee: int) -> Tx:
        from .tx import TxIn
        if sha256(k) != self.h:
            raise ChannelError("bad_preimage", "sha256(k) != H")
        tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(close_txid)[::-1], vout, 0xFFFFFFFD)],
                outputs=[TxOut(self.cond_amount - fee, dest)], locktime=0)
        prev = TxOut(self.cond_amount, self.spk)
        h = unified_sighash(tx, [prev], 0, ST_WITNESS_V0, self.script, SIGHASH_ALL_UNIFIED)
        sig = ecc.sign(payee_secret, h) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, k, b"\x01", self.script]
        return tx
