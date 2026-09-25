"""L13 (Low) a flood of junk /x402/verify calls slows every paid call.

`/x402/verify` (and the close behind `/x402/settle`) is unauthenticated. For every call naming a known
channel, v1.1 took the global ledger lock, derived the channel's payee (payTo·G, then pubkey(p) in
Payee) and ran the ECDSA verify, all under the lock. So anyone who knows a channel id (it is the
funding outpoint, public on-chain) could queue each paid call behind a stream of junk signatures.

Fix: the provider caches its payTo bytes and each channel's Payee (derived once), and checks the
signature outside the ledger lock; the lock is taken only to look the channel up and, for a valid
state, to record it. The close request's signature is checked outside the lock too.

The test makes one ECDSA verify cost DELAY (a sleep inside ecc.verify, so the effect does not depend
on the backend or the machine) and runs FLOODERS threads posting junk states to /x402/verify on the
paid channel. Stated bound: under the flood, a paid call's median serve time stays below
BOUND = DELAY + 70 ms (its own verify plus bookkeeping). On v1.1 (075a8a7) it waits for the junk
verifies holding the lock and exceeds the bound.
"""
import os
import statistics
import sys
import threading
import time
import unittest

from condhelp import ORIGIN, Rig
from sechelp import V11R1, Repro, load, v11r1

DELAY = 0.03
FLOODERS = 8
CALLS = 5
BOUND = DELAY + 0.07


def paid_call_times(xm, calls=CALLS):
    """Median and all serve times of `calls` paid calls on one channel while FLOODERS threads post
    junk signed states for that channel to the provider's /x402/verify."""
    r = Rig(xm)
    r.client.request("GET", ORIGIN + "/v1/x")                 # open the channel; its id is now known
    chan = r.cch.payer.params.channel_id
    real = xm.ecc.verify

    def slow_verify(*a, **kw):
        time.sleep(DELAY)
        return real(*a, **kw)
    times, serve = [], r.prov.serve

    def timed_serve(method, path, headers, body, url=""):
        t = time.perf_counter()
        out = serve(method, path, headers, body, url)
        if "PAYMENT-SIGNATURE" in headers:
            times.append(time.perf_counter() - t)
        return out
    stop, junk_calls = threading.Event(), []

    def flood():
        req = xm.facilitator_request(r.prov.requirements(150),
                                     {"chan": chan, "cum": "150000", "sig": os.urandom(70).hex() + "21"})
        while not stop.is_set():
            r.prov.facilitator_verify(req)
            junk_calls.append(1)
    xm.ecc.verify = slow_verify
    r.prov.serve = timed_serve
    threads = [threading.Thread(target=flood, daemon=True) for _ in range(FLOODERS)]
    try:
        for t in threads:
            t.start()
        time.sleep(3 * DELAY)
        for _ in range(calls):
            st = r.client.request("GET", ORIGIN + "/v1/x")[0]
            assert st == 200, st
    finally:
        stop.set()
        for t in threads:
            t.join(5)
        xm.ecc.verify = real
    assert junk_calls, "the flood never ran"
    return statistics.median(times), times, len(junk_calls)


class VerifyFlood(Repro, unittest.TestCase):
    REPRO_BASE = V11R1

    def test_repro_junk_verifies_queue_paid_calls(self):
        med, times, junk = paid_call_times(v11r1("x402_channel"), calls=3)
        self.reproduces(med > BOUND, f"paid call median {med * 1000:.0f} ms under {FLOODERS} junk-verify threads "
                                     f"({junk} junk calls), bound {BOUND * 1000:.0f} ms")

    def test_fixed_paid_call_within_bound_under_flood(self):
        med, times, junk = paid_call_times(load("x402_channel"))
        sys.stderr.write(f"\n    paid call median {med * 1000:.0f} ms under the flood (bound {BOUND * 1000:.0f} ms) ")
        self.assertLess(med, BOUND, f"paid call median {med * 1000:.0f} ms under the flood "
                                    f"({[round(t * 1000) for t in times]} ms, {junk} junk calls)")

    def test_fixed_verify_and_close_sig_checked_outside_the_lock(self):
        xm = load("x402_channel")
        r = Rig(xm)
        r.client.request("GET", ORIGIN + "/v1/x")
        p = r.cch.payer
        chan = p.params.channel_id
        real, held = xm.ecc.verify, []

        def spy(*a, **kw):
            held.append(r.prov.ledger.lock.locked())
            return real(*a, **kw)
        xm.ecc.verify = spy
        try:
            bad = xm.facilitator_request(r.prov.requirements(150),
                                         {"chan": chan, "cum": "5000", "sig": os.urandom(70).hex() + "21"})
            self.assertFalse(r.prov.facilitator_verify(bad)["isValid"])
            good = xm.facilitator_request(r.prov.requirements(150),
                                          {"chan": chan, "cum": "5000", "sig": p.sign_state(5000).hex()})
            self.assertTrue(r.prov.facilitator_verify(good)["isValid"])
            self.assertEqual(r.chan.best_cum, 5000)                    # a valid state is still recorded
            with self.assertRaises(xm.ChannelError):
                r.prov.close({"chan": chan, "sig": os.urandom(70).hex()})
            self.assertFalse(r.chan.closed_txid)
        finally:
            xm.ecc.verify = real
        self.assertEqual(held, [False, False, False])

    def test_fixed_payee_derived_once_per_channel(self):
        xm = load("x402_channel")
        r = Rig(xm)
        r.client.request("GET", ORIGIN + "/v1/x")
        chan = r.cch.payer.params.channel_id
        calls, real = [], xm.channel_payee_secret

        def count(*a, **kw):
            calls.append(1)
            return real(*a, **kw)
        xm.channel_payee_secret = count
        try:
            for _ in range(5):
                r.prov.facilitator_verify(xm.facilitator_request(
                    r.prov.requirements(150), {"chan": chan, "cum": "5000", "sig": os.urandom(70).hex() + "21"}))
                r.client.request("GET", ORIGIN + "/v1/x")
        finally:
            xm.channel_payee_secret = real
        self.assertEqual(calls, [])                                    # cached at the first paid call


if __name__ == "__main__":
    unittest.main()
