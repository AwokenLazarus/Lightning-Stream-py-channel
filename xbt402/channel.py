"""xbt402 Spillman-style unidirectional channel: funding script, state (commitment) txs,
payee close and payer refund. Every channel signature is SIGHASH_ALL|UNIFIED (0x21).

Funding output is P2WSH of

    OP_IF
        <payee_pub> OP_CHECKSIGVERIFY
    OP_ELSE
        <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
    OP_ENDIF
    <payer_pub> OP_CHECKSIG

- pay path  (any time):        witness = [payer_sig, payee_sig, 0x01, script]
- refund    (height >= expiry): witness = [payer_sig, <empty>, script], nLockTime = expiry

The CLTV branch replaces the presigned refund of the original Spillman design, so the payer
needs nothing from the payee before funding, and segwit makes the funding txid final.
"""
from dataclasses import dataclass, asdict

from . import ecc
from .tx import (OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_ELSE,
                 OP_ENDIF, OP_IF, SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxIn, TxOut,
                 p2wpkh_spk, p2wsh_spk, push, script_num, tagged_hash, unified_sighash)

DUST = 546            # conservative dust floor for any output we create
STATE_VSIZE = 190     # 1-in/2-out close: ~113 B base + ~229 B witness -> ~171 vB, plus room for a P2TR change
REFUND_VSIZE = 140    # 1-in/1-out refund
EXPIRY_MAX = 500_000_000  # below this nLockTime/CLTV is a block height


class ChannelError(ValueError):
    """A state or funding the protocol refuses; `code` is the wire error code."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


def funding_script(payer_pub: bytes, payee_pub: bytes, expiry: int) -> bytes:
    if not 0 < expiry < EXPIRY_MAX:
        raise ChannelError("bad_expiry", "expiry must be a block height")
    return (bytes([OP_IF]) + push(payee_pub) + bytes([OP_CHECKSIGVERIFY, OP_ELSE])
            + script_num(expiry) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_ENDIF])
            + push(payer_pub) + bytes([OP_CHECKSIG]))


def _payee_tweak(pay_to: bytes, payer_pub: bytes, expiry: int) -> int:
    return int.from_bytes(tagged_hash("xbt-channel/payee", pay_to + payer_pub + expiry.to_bytes(4, "little")),
                          "big") % ecc.N


def channel_payee_pub(pay_to: bytes, payer_pub: bytes, expiry: int) -> bytes:
    """Per-channel payee key P = payTo + t*G, t = H(payTo || A || expiry). The payer derives it
    from the 402 challenge alone, so opening is one round trip, and no two channels share a key."""
    x, y = ecc._add(ecc._decode_pub(pay_to), ecc._mul(_payee_tweak(pay_to, payer_pub, expiry)))
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def channel_payee_secret(pay_to_secret: int, payer_pub: bytes, expiry: int) -> int:
    return (pay_to_secret + _payee_tweak(ecc.pubkey(pay_to_secret), payer_pub, expiry)) % ecc.N


@dataclass
class ChannelParams:
    """Everything both sides need to rebuild any state tx byte for byte."""
    payer_pub: str      # hex, 33 bytes
    payee_pub: str
    expiry: int         # absolute block height
    payer_spk: str      # hex scriptPubKey of the payer's change
    payee_spk: str      # hex scriptPubKey of the payee's earnings
    close_fee: int      # sats, fixed at open (x402 extra.closeFeeSat); the payer pays it
    funding_txid: str = ""
    funding_vout: int = 0
    capacity: int = 0   # sats in the funding output

    @property
    def script(self) -> bytes:
        return funding_script(bytes.fromhex(self.payer_pub), bytes.fromhex(self.payee_pub), self.expiry)

    @property
    def spk(self) -> bytes:
        return p2wsh_spk(self.script)

    @property
    def channel_id(self) -> str:
        return f"{self.funding_txid}:{self.funding_vout}"

    @classmethod
    def derive(cls, pay_to: str, payer_pub: str, expiry: int, close_fee: int, payer_spk: str = "") -> "ChannelParams":
        """Terms both sides compute from the challenge + the payer's key and expiry."""
        payee = channel_payee_pub(bytes.fromhex(pay_to), bytes.fromhex(payer_pub), expiry)
        return cls(payer_pub=payer_pub, payee_pub=payee.hex(), expiry=expiry,
                   payer_spk=payer_spk or p2wpkh_spk(bytes.fromhex(payer_pub)).hex(),
                   payee_spk=p2wpkh_spk(payee).hex(), close_fee=close_fee)

    @property
    def max_amount(self) -> int:
        """Most the payer can ever sign to the payee."""
        return self.capacity - self.close_fee

    def to_dict(self):
        return asdict(self)

    def funding_prevout(self) -> TxOut:
        return TxOut(self.capacity, self.spk)

    def _funding_in(self, sequence=0xFFFFFFFD) -> TxIn:
        return TxIn(bytes.fromhex(self.funding_txid)[::-1], self.funding_vout, sequence)

    # --- state (commitment) txs -----------------------------------------------------------
    def state_tx(self, amount: int) -> Tx:
        """Close tx paying `amount` (cumulative) to the payee; payer gets the rest minus fee.

        A payer remainder below dust is dropped into the fee rather than creating dust.
        """
        if not DUST <= amount <= self.max_amount:
            raise ChannelError("bad_amount", f"amount {amount} outside [{DUST}, {self.max_amount}]")
        outs = [TxOut(amount, bytes.fromhex(self.payee_spk))]
        change = self.capacity - self.close_fee - amount
        if change >= DUST:
            outs.append(TxOut(change, bytes.fromhex(self.payer_spk)))
        return Tx(version=2, inputs=[self._funding_in()], outputs=outs, locktime=0)

    def sighash(self, tx: Tx) -> bytes:
        return unified_sighash(tx, [self.funding_prevout()], 0, ST_WITNESS_V0, self.script,
                               SIGHASH_ALL_UNIFIED)

    def refund_tx(self, payer_secret: int, dest_spk: bytes = None, fee: int = None) -> Tx:
        """Payer's unilateral refund, valid once the chain reaches `expiry`."""
        dest = dest_spk if dest_spk is not None else bytes.fromhex(self.payer_spk)
        fee = self.close_fee if fee is None else fee
        tx = Tx(version=2, inputs=[self._funding_in(0xFFFFFFFE)],
                outputs=[TxOut(self.capacity - fee, dest)],
                locktime=self.expiry)
        sig = ecc.sign(payer_secret, self.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, b"", self.script]
        return tx


class Payer:
    """Client side: holds the payer key, signs ever-increasing cumulative amounts."""

    def __init__(self, params: ChannelParams, secret: int):
        if ecc.pubkey(secret).hex() != params.payer_pub:
            raise ChannelError("bad_key", "secret does not match payer_pub")
        self.params, self.secret = params, secret
        self.signed = 0  # highest cumulative amount signed so far

    def sign_state(self, amount: int) -> bytes:
        if amount < self.signed:
            raise ChannelError("stale_amount", "never sign a lower cumulative amount")
        tx = self.params.state_tx(amount)
        sig = ecc.sign(self.secret, self.params.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        self.signed = amount
        return sig


class Payee:
    """Server side of one channel: verifies payer states, keeps the best one, closes."""

    def __init__(self, params: ChannelParams, secret: int):
        if ecc.pubkey(secret).hex() != params.payee_pub:
            raise ChannelError("bad_key", "secret does not match payee_pub")
        self.params, self.secret = params, secret
        self.best_amount, self.best_sig = 0, b""

    def verify_state(self, amount: int, sig: bytes) -> None:
        """Raise ChannelError unless `sig` is the payer's valid 0x21 signature for `amount`."""
        if not sig or sig[-1] != SIGHASH_ALL_UNIFIED:
            raise ChannelError("bad_sighash", "state signatures must be SIGHASH_ALL|UNIFIED (0x21)")
        tx = self.params.state_tx(amount)
        if not ecc.verify(bytes.fromhex(self.params.payer_pub), self.params.sighash(tx), sig[:-1]):
            raise ChannelError("bad_sig", "payer signature does not verify")

    def accept(self, amount: int, sig: bytes) -> int:
        """Verify and store a state; returns the newly paid delta in sats (0 if a replay)."""
        if amount <= self.best_amount:
            if amount == self.best_amount and sig == self.best_sig:
                return 0
            raise ChannelError("stale_amount", f"have {self.best_amount}, got {amount}")
        self.verify_state(amount, sig)
        delta = amount - self.best_amount
        self.best_amount, self.best_sig = amount, sig
        return delta

    def close_tx(self) -> Tx:
        """Fully signed close for the best state; broadcast it before expiry - margin."""
        if not self.best_sig:
            raise ChannelError("no_state", "nothing to close")
        tx = self.params.state_tx(self.best_amount)
        mine = ecc.sign(self.secret, self.params.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [self.best_sig, mine, b"\x01", self.params.script]
        return tx
