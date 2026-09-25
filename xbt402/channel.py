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
                 OP_ENDIF, OP_IF, SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED, ST_WITNESS_V0,
                 Tx, TxIn, TxOut, p2wpkh_script_code, p2wpkh_spk, p2wsh_spk, push, script_num,
                 tagged_hash, unified_sighash)

DUST = 546            # conservative dust floor for any output we create
STATE_VSIZE = 190     # 1-in/2-out close: ~113 B base + ~229 B witness -> ~171 vB, plus room for a P2TR change
REFUND_VSIZE = 140    # 1-in/1-out refund
EXPIRY_MAX = 500_000_000  # below this nLockTime/CLTV is a block height


class ChannelError(ValueError):
    """A state or funding the protocol refuses; `code` is the wire error code."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


def canonical_chan(chan) -> str:
    """The one spelling of a channel id: 64 lowercase hex txid, ':', decimal vout. bitcoind parses
    txids case-insensitively, so without this one outpoint could be opened (and credited) under
    many ids."""
    if not isinstance(chan, str):
        raise ChannelError("unknown_channel", "chan must be txid:vout")
    txid, sep, vout = chan.partition(":")
    if not sep or len(txid) != 64 or not vout.isdigit() or len(vout) > 10:
        raise ChannelError("unknown_channel", "chan must be txid:vout")
    try:
        txid = bytes.fromhex(txid).hex()
    except ValueError:
        raise ChannelError("unknown_channel", "txid is not hex")
    return f"{txid}:{int(vout)}"


def check_payout_spk(spk: str) -> str:
    """A payout scriptPubKey both sides can put in every state: P2WPKH, P2WSH or P2TR, which are
    standard and fit the RDTS 34-byte output cap. Anything else could make every close
    non-standard or consensus-invalid while the provider keeps serving. Returns canonical hex."""
    try:
        b = bytes.fromhex(spk)
    except (TypeError, ValueError):
        raise ChannelError("bad_payer_spk", "payerSpk is not hex")
    if not (len(b) == 22 and b[:2] == b"\x00\x14" or len(b) == 34 and b[:2] in (b"\x00\x20", b"\x51\x20")):
        raise ChannelError("bad_payer_spk", "payerSpk must be P2WPKH, P2WSH or P2TR")
    return b.hex()


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


def channel_auth_key(secret: int, other_pub: bytes) -> bytes:
    """Per-channel request-authentication key, ECDH(A, P): the payer computes it with a and P, the
    payee with p and A. Nobody else can, so a known channel id alone buys nothing."""
    return tagged_hash("xbt402/auth-key", ecc.ecdh(secret, other_pub))


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

    def state_tx_a3(self, amount: int) -> Tx:
        """Payee-only output: SIGHASH_SINGLE|ANYONECANPAY|UNIFIED (0xA3) lets the payee add fee inputs."""
        if not DUST <= amount <= self.max_amount:
            raise ChannelError("bad_amount", f"amount {amount} outside [{DUST}, {self.max_amount}]")
        return Tx(version=2, inputs=[self._funding_in()],
                  outputs=[TxOut(amount, bytes.fromhex(self.payee_spk))], locktime=0)

    def sighash_a3(self, tx: Tx) -> bytes:
        return unified_sighash(tx, [self.funding_prevout()], 0, ST_WITNESS_V0, self.script,
                               SIGHASH_SINGLE_ACP_UNIFIED)

    def rollover_tx(self, amount: int, next_spk: bytes, next_capacity: int) -> Tx:
        """Close that pays the payee and funds the next channel from the payer leftover."""
        if not DUST <= amount <= self.max_amount:
            raise ChannelError("bad_amount", f"amount {amount} outside [{DUST}, {self.max_amount}]")
        if next_capacity < DUST:
            raise ChannelError("bad_amount", "next channel capacity below dust")
        leftover = self.capacity - amount - next_capacity
        if leftover < 0:
            raise ChannelError("bad_amount", "rollover does not leave a non-negative fee")
        return Tx(version=2, inputs=[self._funding_in()],
                  outputs=[TxOut(amount, bytes.fromhex(self.payee_spk)),
                           TxOut(next_capacity, next_spk)], locktime=0)


class Payer:
    """Client side: holds the payer key, signs ever-increasing cumulative amounts.

    `backend` (a ChannelSigner) may supply signatures so this object never sees the secret —
    that is the B2 policy-signer path. Tests still pass a raw `secret`.
    """

    def __init__(self, params: ChannelParams, secret: int = None, backend=None):
        self.params, self.secret, self.backend = params, secret, backend
        if backend is None:
            if secret is None or ecc.pubkey(secret).hex() != params.payer_pub:
                raise ChannelError("bad_key", "secret does not match payer_pub")
        self.signed = 0  # highest cumulative amount signed so far

    def sign_state(self, amount: int) -> bytes:
        if amount < self.signed:
            raise ChannelError("stale_amount", "never sign a lower cumulative amount")
        if self.backend is not None:
            sig = self.backend.sign_state(self.params.channel_id, amount)
            sig = bytes.fromhex(sig) if isinstance(sig, str) else sig
        else:
            tx = self.params.state_tx(amount)
            sig = ecc.sign(self.secret, self.params.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        self.signed = amount
        return sig

    def sign_state_a3(self, amount: int) -> bytes:
        if amount < self.signed:
            raise ChannelError("stale_amount", "never sign a lower cumulative amount")
        if self.backend is not None:
            sig = self.backend.sign_state_a3(self.params.channel_id, amount)
            sig = bytes.fromhex(sig) if isinstance(sig, str) else sig
        else:
            tx = self.params.state_tx_a3(amount)
            sig = ecc.sign(self.secret, self.params.sighash_a3(tx)) + bytes([SIGHASH_SINGLE_ACP_UNIFIED])
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

    def close_tx_with_fee_input(self, extra_prev: TxOut, extra_in: TxIn, extra_secret: int,
                                extra_change: bytes, extra_fee: int, sig_a3: bytes) -> Tx:
        """Complete a 0xA3 state by adding a fee input. Output 0 (payee) stays exactly as signed."""
        if not sig_a3 or sig_a3[-1] != SIGHASH_SINGLE_ACP_UNIFIED:
            raise ChannelError("bad_sighash", "fee-input variant needs SIGHASH_SINGLE|ACP|UNIFIED (0xA3)")
        tx = self.params.state_tx_a3(self.best_amount)
        tx.inputs.append(extra_in)
        change = extra_prev.value - extra_fee
        if change >= DUST:
            tx.outputs.append(TxOut(change, extra_change))
        prevouts = [self.params.funding_prevout(), extra_prev]
        mine = ecc.sign(self.secret, unified_sighash(tx, prevouts, 0, ST_WITNESS_V0,
                                                     self.params.script, SIGHASH_ALL_UNIFIED))
        tx.inputs[0].witness = [sig_a3, mine + bytes([SIGHASH_ALL_UNIFIED]), b"\x01", self.params.script]
        pub = ecc.pubkey(extra_secret)
        sc = p2wpkh_script_code(pub)
        h = unified_sighash(tx, prevouts, 1, ST_WITNESS_V0, sc, SIGHASH_ALL_UNIFIED)
        tx.inputs[1].witness = [ecc.sign(extra_secret, h) + bytes([SIGHASH_ALL_UNIFIED]), pub]
        return tx


def sign_p2wpkh(secret: int, tx: Tx, prevouts, index: int = 0) -> Tx:
    """Sign input `index` as P2WPKH with 0x21 (CPFP child, extra fee input)."""
    pub = ecc.pubkey(secret)
    sc = p2wpkh_script_code(pub)
    h = unified_sighash(tx, prevouts, index, ST_WITNESS_V0, sc, SIGHASH_ALL_UNIFIED)
    tx.inputs[index].witness = [ecc.sign(secret, h) + bytes([SIGHASH_ALL_UNIFIED]), pub]
    return tx


def cpfp_child(close_txid: str, vout: int, value: int, payee_spk: bytes, payee_secret: int,
               fee: int) -> Tx:
    """Child that spends the payee close output, bumping the parent (CPFP)."""
    if value - fee < DUST:
        raise ChannelError("bad_amount", "CPFP fee leaves dust")
    tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(close_txid)[::-1], vout, 0xFFFFFFFD)],
            outputs=[TxOut(value - fee, payee_spk)], locktime=0)
    return sign_p2wpkh(payee_secret, tx, [TxOut(value, payee_spk)])
