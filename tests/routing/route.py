"""Two-hop xbt402 route model for AGP-019 (tests only, nothing here is product code).

A route is client -> hub -> provider over two ordinary xbt402 v1.1 Spillman channels: ch1 (client
pays hub) and ch2 (hub pays provider). A routed payment is an *adaptor-locked* state on each hop:
the payer pre-signs its next cumulative state under a point, the payee can complete it only with
the point's discrete log, and completing it hands that secret to whoever holds the pre-signature.

    provider: t, T = t*G (in its quote)          client: r (per-hop tweak, sent to the hub)
    ch1: client pre-signs cum1 + d + fee under T1 = T + r*G
    ch2: hub pre-signs cum2 + d under T      (only after pre-verifying ch1)
    provider completes ch2 with t            -> a plain 0x21 state it can close with
    hub learns t (from the provider, or from ch2's close on-chain), completes ch1 with t + r
    client learns t + r (from the hub, or from ch1's close on-chain), so t: its receipt

The completed signature is an ordinary 0x21 state signature, so B1's Payee, close and watcher
take it unchanged. `Hop` holds both ends of one channel so the tests can play every role.
"""
from xbt402.channel import ChannelError, Payee, Payer
from xbt402.tx import SIGHASH_ALL_UNIFIED

from adaptor import adapt, extract, point_of, preverify, presign


def route_ok(tip: int, in_expiry: int, out_expiry: int, close_margin: int, delta: int) -> bool:
    """May the hub forward a lock from the channel expiring at `in_expiry` into the one expiring at
    `out_expiry`? An adaptor-locked state has no timeout of its own: the provider can complete and
    close ch2 until ch2's close margin, and its close can confirm as late as `out_expiry`. The hub
    then needs `delta` blocks to learn t and get ch1's close confirmed before ch1's margin."""
    return tip < out_expiry - close_margin and out_expiry + delta <= in_expiry - close_margin


class Hop:
    """One channel of the route, both ends. Payer side: `lock`. Payee side: `offer`, `complete`."""

    def __init__(self, params, payer_secret: int, payee_secret: int):
        self.params = params
        self.payer = Payer(params, payer_secret)
        self.payee = Payee(params, payee_secret)
        self.sent = None       # payer: the outstanding lock (cum, pre, Y)
        self.held = None       # payee: the outstanding lock it accepted

    # --- payer --------------------------------------------------------------------------------
    def pay(self, cum: int) -> bytes:
        """A plain 0x21 state (earlier traffic, or a fold)."""
        if self.sent and cum < self.sent[0]:
            raise ChannelError("lock_outstanding", "a plain state under an outstanding lock")
        sig = self.payer.sign_state(cum)
        self.payee.accept(cum, sig)
        if self.sent and cum >= self.sent[0]:
            self.sent = None                                   # the lock is dominated
        return sig

    def lock(self, delta: int, Y):
        """Pre-sign `signed + delta` under Y. One outstanding lock per channel: a later lock would
        sit on top of this one's amount, so revealing the later secret would pay for both."""
        if self.sent:
            raise ChannelError("lock_outstanding", "one adaptor lock per channel at a time")
        cum = self.payer.signed + delta
        pre = presign(self.payer.secret, self.params.sighash(self.params.state_tx(cum)), Y)
        self.sent = (cum, pre, Y)
        return cum, pre

    def resolved(self, y: int):
        """The payer learned y: the lock is now a plain state for its amount."""
        cum, pre, Y = self.sent
        if point_of(y) != Y:
            raise ChannelError("bad_secret", "y*G != Y")
        self.payer.signed, self.sent = cum, None

    # --- payee --------------------------------------------------------------------------------
    def offer(self, cum: int, pre, Y, delta: int):
        """Accept a lock only if it is the next state (best + delta) and pre-verifies against the
        exact state tx. Nothing is signed back."""
        if self.held:
            raise ChannelError("lock_outstanding", "one adaptor lock per channel at a time")
        if cum != self.payee.best_amount + delta:
            raise ChannelError("bad_amount", f"lock pays {cum}, expected {self.payee.best_amount + delta}")
        z = self.params.sighash(self.params.state_tx(cum))
        if not preverify(bytes.fromhex(self.params.payer_pub), z, Y, pre):
            raise ChannelError("bad_adaptor", "pre-signature does not verify under Y")
        self.held = (cum, pre, Y)

    def complete(self, y: int) -> bytes:
        """Complete the held lock with y; the result is stored as the best plain state."""
        cum, pre, Y = self.held
        if point_of(y) != Y:
            raise ChannelError("bad_secret", "y*G != Y")
        sig = adapt(pre, y) + bytes([SIGHASH_ALL_UNIFIED])
        self.payee.accept(cum, sig)
        self.held = None
        return sig

    def secret_from_close(self, close_tx):
        """Payer side: y from the payee's close, whose witness[0] is the completed signature."""
        cum, pre, Y = self.sent
        return extract(pre, close_tx.inputs[0].witness[0], Y)
