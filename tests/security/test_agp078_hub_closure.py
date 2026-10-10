"""AGP-078: the hub findings the closure audit (AGP-077) found still open (in-process: FakeNode + a
fake HTTP transport). xbt-rs has the same tests, in `hub_routing_safety.rs` (rollover) and
`routing_checks.rs` (seq, config).

H1/H2 by rollover: `ChannelProvider.rollover` never looked at `route_lock` / `stale_locks`, and the hub
serves `POST /x402/xbt-channel/rollover` for ch1. A client that rolled ch1 over at its old state while a
lock was in flight (or held after a write-off) closed ch1 below the lock; the hub still paid the
provider on ch2. The cooperative close was refused `lock_pending`; the rollover was not.
T4b: the seq an authentic request spent was kept only in memory when the hub's /x402/route or the
provider's /x402/xbt-channel/lock refused it, so after a restart the refused header authenticated again.
Config: `max_lock_sat` was bounded when a HubConfig was constructed, not when a hub was built from one.
"""
import json
import os
import secrets
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402  (the AGP-064 harness: W)
from sechelp import crashed  # noqa: E402

from xbt402 import adaptor, ecc  # noqa: E402
from xbt402.channel import SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams, channel_auth_key  # noqa: E402
from xbt402.hub import HubConfig, RouteHub  # noqa: E402
from xbt402.route import ROUTE_LOCK_PATH, lock_auth, next_cum  # noqa: E402
from xbt402.x402_channel import b64json, request_auth, request_digest_v2  # noqa: E402

ROLLOVER_PATH = "/x402/xbt-channel/rollover"
HUB_ROUTE_PATH = "/x402/route"


def rollover_ch1(w, amount):
    """The client rolls ch1 over at `amount` through the hub's own rollover endpoint."""
    p = w.st1().params
    sk2 = secrets.randbelow(ecc.N - 1) + 1
    expiry = w.node.getblockcount() + 2000
    nxt = ChannelParams.derive(w.hub.pay_to, ecc.pubkey(sk2).hex(), expiry, p.close_fee, network=R.NET,
                               close_fee_payer=p.close_fee_payer)
    tx = p.rollover_tx(amount, nxt.spk, p.rollover_next_capacity(amount))
    sig = ecc.sign(w.pay.signer._secret(p.channel_id), p.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
    body = json.dumps({"chan": p.channel_id, "amount": amount, "sig": sig.hex(),
                       "next": {"payerPub": nxt.payer_pub, "expiry": expiry}}).encode()
    s, _h, b = w.hub.serve("POST", ROLLOVER_PATH, {}, body, R.HUB + ROLLOVER_PATH)
    return s, json.loads(b)


def error_of(resp):
    return json.loads(resp[2]).get("error")


class RolloverWithALockOpen(unittest.TestCase):
    def test_h1_a_ch1_rollover_while_a_lock_is_in_flight_is_refused(self):
        # a rollover spends ch1's funding exactly as a close does: at the client's old state it would
        # close ch1 below the lock the hub is forwarding, and the hub would pay the provider for nothing
        w = T.W([None])
        w.paid(0)
        before = w.st1().best_cum
        join = w.lock_in_flight(0)
        self.assertTrue(w.st1().extra.get("route_lock"))
        with self.assertRaises(ChannelError) as cm:  # control: the cooperative close is refused
            w.pay.close()
        self.assertEqual(cm.exception.code, "lock_pending")
        status, doc = rollover_ch1(w, before)
        w.provs[0].open()
        self.assertEqual(join()["status"], "paid")
        st1 = w.st1()
        self.assertFalse(st1.closed_txid, f"ch1 was rolled over at {before}, below a lock in flight (HTTP {status}: {doc})")
        self.assertEqual((status, doc.get("error")), (400, "lock_pending"), doc)
        self.assertTrue(st1.best_cum > before and st1.best_cum >= w.routed(), "the lock completed on ch1")
        # the lock is done: the same client rolls over at the state that covers it
        status, doc = rollover_ch1(w, st1.best_cum)
        self.assertEqual(status, 200, doc)
        self.assertEqual(w.st1().closed_txid, doc["txid"])

    def test_h2_a_ch1_rollover_below_a_held_written_off_lock_is_refused(self):
        # the provider takes the lock, keeps the pre-signature and answers 400: the lock is held in
        # ch1's base. Rolling ch1 over would leave it behind, and the provider could still use t on ch2
        w = T.W([None])
        w.paid(0)
        before = w.st1().best_cum
        w.provs[0].refuse = True
        r = w.lock(0)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        stale = w.stale1()
        self.assertTrue(len(stale) == 1 and stale[0].get("hold"), stale)
        with self.assertRaises(ChannelError) as cm:  # control: the cooperative close is refused
            w.pay.close()
        self.assertEqual(cm.exception.code, "lock_pending")
        # at the old state, and at the highest state the client has signed
        for amount in (before, max(before, int(stale[0]["cum"]))):
            status, doc = rollover_ch1(w, amount)
            self.assertFalse(w.st1().closed_txid, f"ch1 was rolled over at {amount}, below a held lock (HTTP {status}: {doc})")
            self.assertEqual((status, doc.get("error")), (400, "lock_pending"), doc)
        # the provider uses t after all: its ch2 close gives the hub t, ch1 moves up and the lock is no
        # longer open, so the rollover goes through at a state that pays for it
        T.close_now(w.provs[0].inner, w.st2(0))
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        st1 = w.st1()
        self.assertGreater(st1.best_cum, before, "ch1 was completed from the ch2 close")
        status, doc = rollover_ch1(w, st1.best_cum)
        self.assertEqual(status, 200, doc)

    def test_h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_from_rolling_over(self):
        # as for the close: nothing can complete a lock that never left the hub, so the rollover drops it
        w = T.W([None])
        w.paid(0)
        best = w.st1().best_cum
        w.hub.withhold = "all"
        R.stream(w.pay, w.shards[0], 10)
        self.assertEqual(w.pay.lock(w.shards[0])["status"], "pending")
        self.assertTrue(w.st1().extra.get("route_lock"))
        w.hub.withhold = ""
        status, doc = rollover_ch1(w, best)
        self.assertEqual(status, 200, doc)
        self.assertTrue(any(e.get("event") == "orphan_lock_dropped" for e in w.hub.events))


class RefusedSeq(unittest.TestCase):
    def test_t4b_a_seq_spent_on_a_refused_route_survives_a_hub_restart(self):
        # an authentic /route the hub refuses (here for its amount) has spent its seq
        node, net, hub, _provs, pay, shards = R.world(1)
        sh = next(iter(shards.values()))
        R.stream(pay, sh, 10)
        sent, http = {}, pay.http

        def recording(method, url, body=b"", headers=None):
            sent.update(body=body, headers=dict(headers or {}))
            return http(method, url, body, headers)
        pay.http = recording
        _st, doc = R.route_request(pay, sh, tamper=lambda pl, rt: rt.__setitem__("amount", 1_000_000))
        self.assertEqual(doc.get("error"), "bad_amount", doc)
        seq = pay.ch.seq

        def send(h):
            return h.serve("POST", HUB_ROUTE_PATH, sent["headers"], sent["body"], R.HUB + HUB_ROUTE_PATH)
        self.assertEqual(hub.inbound.ledger.channels[pay.chan].seq, seq)
        self.assertEqual(error_of(send(hub)), "bad_auth", "control: the seq is spent in the running hub")
        crashed(hub)
        hub2 = RouteHub(node, 0x4B4B, R.NET, os.path.dirname(hub.out.path), node.fund_address, http=net.http,
                        close_margin=36, delta=36)
        self.assertEqual(hub2.inbound.ledger.channels[pay.chan].seq, seq, "the refused route's seq was only in memory")
        self.assertEqual(error_of(send(hub2)), "bad_auth", "the refused header still authenticates after a restart")

    def test_t4b_a_seq_spent_on_a_refused_lock_survives_a_provider_restart(self):
        # the same on the provider's /lock, for a refusal before the lock is looked at (ch2 inside its
        # close margin) and for one after (the hub repriced it)
        for closing in (True, False):
            with self.subTest(closing=closing):
                path = os.path.join(tempfile.mkdtemp(), "prov.sqlite")
                node, _net, hub, provs, pay, shards = R.world(1, secret=0x5151, ledger=path)
                (origin, prov), sh = next(iter(provs.items())), next(iter(shards.values()))
                R.stream(pay, sh, 10)
                # a ch2 lock as the hub would send it (test_agp021 ProviderLockChecks._hub_lock)
                oc = hub.out.chans[origin]
                p2, inv, d = oc.p(), sh.invoice, 3
                cum = next_cum(oc.routed, d, p2.min_amount)
                pre = adaptor.presign(int(oc.secret, 16), p2.sighash(p2.state_tx(cum)), adaptor.dec(inv["point"]))
                route = {"session": sh.session, "lockId": inv["lockId"], "amount": d if closing else 4, "hub": hub.pay_to,
                         "lockAuth": lock_auth(sh.key, sh.session, inv["lockId"], d, inv["point"], hub.pay_to)}
                oc.seq += 1
                pl = {"chan": p2.channel_id, "seq": oc.seq, "cum": str(cum), "point": inv["point"], "adaptor": pre.to_json()}
                body = json.dumps({"route": route}).encode()
                key = channel_auth_key(int(oc.secret, 16), bytes.fromhex(p2.payee_pub))
                pl["auth"] = request_auth(key, p2.channel_id, oc.seq, pl["cum"], None,
                                          request_digest_v2("POST", origin + ROUTE_LOCK_PATH, body))
                headers = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": {}, "payload": pl})}
                if closing:
                    node.height = p2.expiry - 36

                def send(p):
                    return p.serve("POST", ROUTE_LOCK_PATH, headers, body, origin + ROUTE_LOCK_PATH)
                self.assertEqual(error_of(send(prov)), "channel_closing" if closing else "bad_auth")
                self.assertEqual(prov.ledger.channels[p2.channel_id].seq, oc.seq)
                crashed(prov)
                prov2 = R.provider(node, R.Net(), origin, secret=0x5151, ledger=path)
                self.assertEqual(prov2.ledger.channels[p2.channel_id].seq, oc.seq, "the refused lock's seq was only in memory")
                r = send(prov2)
                self.assertEqual((r[0], error_of(r)), (401, "bad_auth"), "the refused header still authenticates after a restart")


class Config(unittest.TestCase):
    def test_hub_bounds_max_lock_sat_however_its_config_was_built(self):
        # AGP-064's bound (a lock is at most half of a ch2) was made when a HubConfig was constructed: a
        # config changed afterwards went around it
        node, net = R.RouteNode(), R.Net()
        root = tempfile.mkdtemp()

        def new(max_lock_sat):
            cfg = HubConfig(ch2_capacity=100_000)
            cfg.max_lock_sat = max_lock_sat
            d = os.path.join(root, f"hub-{max_lock_sat}")
            return d, lambda: RouteHub(node, 0x4B4B, R.NET, d, node.fund_address, cfg, http=net.http)
        for over in (0, 50_001, 90_000):
            d, build = new(over)
            with self.assertRaises(ValueError, msg=f"max_lock_sat {over} of ch2_capacity 100000"):
                build()
            self.assertFalse(os.path.exists(d), "refused before anything is written")
        new(50_000)[1]()
        with self.assertRaises(ValueError):
            HubConfig(max_lock_sat=90_000, ch2_capacity=100_000)


if __name__ == "__main__":
    unittest.main()
