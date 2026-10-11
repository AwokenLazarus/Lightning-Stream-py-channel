"""AGP-073: the hub follow-ups AGP-063 and AGP-064 left (in-process: FakeNode + a fake HTTP transport).
xbt-rs has the same tests (crates/xbt402-interop/tests/hub_followups.rs).

* K1: the hub's state file (ch2.json) held every ch2 payer key in plaintext.
* A ch2 with a written-off lock (the provider refused or timed out after the pre-signature left) was
  blocked for its whole life, until its close or its refund at expiry.
* A ch1 lock a hub crash left (written ahead, never on ch2) was dropped only on ch1's close path, and
  that path dropped a lock whose ch2 had already written it off (pre-signature out).
* The routed funders (the route payer, the hub's ch2 funding) broadcast before /open. B1's route payer
  already asked first (its open is XbtChannelClient._open, AGP-067); the hub did not.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
from sechelp import crashed  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.hub import RouteHub  # noqa: E402
from xbt402.route import ROUTE_LOCK_PATH  # noqa: E402

PRICE = 300 * 10 ** 21   # 300 sat a call: a lock (10 calls) is well above ch1's dust floor
OPEN_PATH = "/x402/xbt-channel/open"
OPTS = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
            reveal_timeout=0.3, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
            settle_lock_multiple=0, refill_ahead_locks=0, spend_final_depth=1,   # (AGP-094: one confirmation, as written)
            policy=FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36))


class Svc:
    """A service as the others see it over the net: /open can be refused (its policy changed after its
    402 or /terms), and a 200 to /lock can be turned into a 400 (the provider keeps the pre-signature)."""

    def __init__(self, inner):
        self.inner, self.refuse_open, self.refuse_lock = inner, False, False

    def serve(self, method, path, headers, body, url):
        if path == OPEN_PATH and self.refuse_open:
            return 400, {"Content-Type": "application/json"}, b'{"error":"bad_expiry","detail":"the policy changed"}'
        r = self.inner.serve(method, path, headers, body, url)
        # (AGP-094: the lock, not the hub's check of it)
        if path == ROUTE_LOCK_PATH and not R.is_lock_check(path, body) and self.refuse_lock and r[0] == 200:
            return 400, {"Content-Type": "application/json"}, b'{"error":"refused","detail":"no"}'
        return r


class Counting:
    """The node's fund hook, counting what it funds."""

    def __init__(self, node):
        self.node, self.n = node, 0

    def __call__(self, address, sats):
        self.n += 1
        return self.node.fund_address(address, sats)


def provider(node, net, origin):
    svc = Svc(R.provider(node, net, origin, amsat_per_call=PRICE))
    net.apps[origin] = svc
    return svc


class W:
    def __init__(self, n=1, open_=True):
        self.node, self.net, self.dir = R.RouteNode(), R.Net(), tempfile.mkdtemp(prefix="hub073-")
        self.hub_funds, self.pay_funds = Counting(self.node), Counting(self.node)
        self._start()
        self.origins, self.provs = [], []
        for i in range(n):
            o = f"http://p{i}.test"
            self.provs.append(provider(self.node, self.net, o))
            self.origins.append(o)
            self.hub.connect(o)
        self.node.confirm_all()
        self.hub.watch_tick()
        from xbt402.signer import ChannelSigner
        self.pay = R.payer(self.node, self.net, signer=ChannelSigner(fund=self.pay_funds))
        self.shards = []
        if open_:
            self.pay.open()
            self.shards = [self.pay.shard(o + "/v1/chunk") for o in self.origins]

    def _start(self, **kw):
        self.hub = RouteHub(self.node, 0x4B4B, R.NET, self.dir, self.hub_funds, http=self.net.http, **{**OPTS, **kw})
        self.hub_svc = Svc(self.hub)
        self.net.apps[R.HUB] = self.hub_svc

    def restart(self, down=None):
        """The hub stops (its ledger is let go) and starts again from its data dir; `down()` runs while
        it is stopped."""
        self.net.apps.pop(R.HUB, None)
        crashed(self.hub, self.dir)
        if down:
            down()
        self._start()

    def path(self, name="ch2.json"):
        return os.path.join(self.dir, name)

    def st1(self):
        return self.hub.inbound.ledger.channels[self.pay.chan]

    def routed(self):
        return int((self.st1().extra or {}).get("routed_sat", 0))

    def stale1(self):
        return list((self.st1().extra or {}).get("stale_locks", []))

    def chan2(self, i):
        return self.hub.out.chans[self.origins[i]].p().channel_id

    def lock(self, i):
        R.stream(self.pay, self.shards[i], 10)
        return self.pay.lock(self.shards[i])

    def paid(self, i):
        r = self.lock(i)
        assert r["status"] == "paid", r

    def written_off(self, i, refuse):
        """p`i`'s next lock is written off: refused after the provider took it (`refuse`), or its answer
        lost until revealTimeout. Returns d + f."""
        o = self.origins[i]
        if refuse:
            self.provs[i].refuse_lock = True
        else:
            self.net.drop[o] = lambda m, p: p == ROUTE_LOCK_PATH
        r = self.lock(i)
        assert (r["status"], r.get("error")) == ("refused", "route_failed"), r
        self.provs[i].refuse_lock = False
        self.net.drop.pop(o, None)
        s = self.stale1()
        assert len(s) == 1, s
        return s[0]["d"] + s[0]["f"]

    def opens(self):
        return sum(1 for c in self.net.calls if c[2] == OPEN_PATH)


def has(acts, event):
    return any(a.get("event") == event for a in acts)


def records(doc):
    """Every ch2 record in a state file: the live and next ones, the archive, and a rollover's next ch2
    written ahead inside a record."""
    out = list(doc["chans"].values()) + list(doc.get("next_chans", {}).values()) + list(doc.get("archived", []))
    return out + [r["next"] for r in out if isinstance(r.get("next"), dict) and "params" in r["next"]]


def hub_keys(hub):
    """The ch2 payer keys the hub holds (in memory)."""
    keys = [c.secret for c in list(hub.out.chans.values()) + list(hub.out.next_chans.values())]
    keys += [r["secret"] for r in hub.out.archived]
    keys += [c.next["secret"] for c in hub.out.chans.values() if c.next.get("secret")]
    return keys


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def keys_everywhere(w):
    """p0's ch2 replaced by its next one (live + archived), a next ch2 funded ahead, and a rollover's
    next key written ahead: a key in every place a state file holds one."""
    o = w.origins[0]
    w.hub.connect_next(o)
    w.node.confirm_all()
    w.hub.watch_tick()
    assert w.hub.out.next_chans[o].state == "open"
    live = w.hub.out.chans[o]
    w.hub.close_ch2(live, refill=True)          # too small to roll over, say: its next one takes over
    assert w.chan2(0) != live.p().channel_id
    w.hub.connect_next(o)
    with w.hub.out.lock:
        w.hub.out.chans[o].next = asdict(w.hub.out.next_chans[o])
        w.hub.out.save()


class K1(unittest.TestCase):
    def test_k1_the_state_file_holds_no_plaintext_ch2_key(self):
        w = W(1)
        w.paid(0)
        keys_everywhere(w)
        keys = hub_keys(w.hub)
        self.assertGreaterEqual(len(keys), 4)
        with open(w.path()) as f:
            raw = f.read()
        for k in keys:
            self.assertNotIn(k, raw, "a ch2 payer key is in ch2.json in plaintext")
        recs = records(json.loads(raw))
        self.assertEqual(len(recs), len(keys))
        for r in recs:
            self.assertNotIn("secret", r, r.get("origin"))
            s = r["secret_sealed"]
            self.assertEqual((s["alg"], s["aad"], s["kdf"]), ("aes-256-gcm", "xbt402/hub-ch2", "keyfile"))
        self.assertEqual(mode(w.path()), 0o600)
        self.assertEqual(mode(w.path("hub-wrap-key")), 0o600)
        # a restart opens every key again, and routes
        w.restart()
        self.assertEqual(sorted(hub_keys(w.hub)), sorted(keys))
        w.paid(0)

    def test_k1_a_legacy_plaintext_state_file_is_read_once_and_rewritten_sealed(self):
        w = W(2)
        w.paid(0)
        o = w.origins[0]
        keys = hub_keys(w.hub)
        legacy = {"chans": {k: asdict(c) for k, c in w.hub.out.chans.items()}, "archived": [],
                  "origins": {k: c.pay_to for k, c in w.hub.out.chans.items()}, "next_chans": {}}

        def down():
            os.remove(w.path("hub-wrap-key"))
            with open(w.path(), "w") as f:
                json.dump(legacy, f)
            with open(w.path()) as f:
                self.assertIn(keys[0], f.read())
        w.restart(down)
        with open(w.path()) as f:
            raw = f.read()
        for k in keys:
            self.assertNotIn(k, raw, "the legacy plaintext key was not rewritten sealed")
        ev = next(e for e in w.hub.events if e.get("event") == "ch2_keys_sealed")
        self.assertEqual(ev["count"], 2)
        self.assertIn(w.hub.out.chans[o].secret, keys)
        w.paid(0)
        w.paid(1)

    def test_k1_a_wrong_wrap_key_or_a_swapped_blob_is_refused(self):
        from xbt402.hub_keys import WrapKey
        w = W(2)
        w.paid(0)
        w.paid(1)

        def down():
            with open(w.path()) as f:
                good = f.read()

            def opened(wrap=None):
                RouteHub(w.node, 0x4B4B, R.NET, w.dir, w.hub_funds, http=w.net.http, wrap_key=wrap, **OPTS)
            with self.assertRaises(ChannelError) as e:
                opened(WrapKey(b"\x09" * 32))
            self.assertEqual(e.exception.code, "keystore", "another wrap key")
            crashed(w.dir)
            # p0's sealed key moved onto p1's record (and back): each opens, neither is its record's key
            doc = json.loads(good)
            a, b = w.origins
            ca, cb = doc["chans"][a], doc["chans"][b]
            ca["secret_sealed"], cb["secret_sealed"] = cb["secret_sealed"], ca["secret_sealed"]
            with open(w.path(), "w") as f:
                json.dump(doc, f)
            with self.assertRaises(ChannelError) as e:
                opened()
            self.assertEqual(e.exception.code, "keystore")
            crashed(w.dir)
            # one byte of a blob changed
            doc = json.loads(good)
            ct = doc["chans"][a]["secret_sealed"]["ct"]
            doc["chans"][a]["secret_sealed"]["ct"] = ("1" if ct[0] == "0" else "0") + ct[1:]
            with open(w.path(), "w") as f:
                json.dump(doc, f)
            with self.assertRaises(ChannelError) as e:
                opened()
            self.assertEqual(e.exception.code, "keystore")
            crashed(w.dir)
            with open(w.path(), "w") as f:
                f.write(good)
        w.restart(down)
        w.paid(0)
        # a wrap key from elsewhere (a secrets mount): none is made in the data dir
        node, net, d = R.RouteNode(), R.Net(), tempfile.mkdtemp(prefix="hub073-")
        hub = RouteHub(node, 0x4B4B, R.NET, d, node.fund_address, http=net.http, wrap_key=WrapKey(b"\x05" * 32), **OPTS)
        provider(node, net, "http://p0.test")
        hub.connect("http://p0.test")
        self.assertFalse(os.path.exists(os.path.join(d, "hub-wrap-key")))
        with open(os.path.join(d, "ch2.json")) as f:
            self.assertIsInstance(json.load(f)["chans"]["http://p0.test"]["secret_sealed"], dict)
        crashed(hub, d)
        shutil.rmtree(d, ignore_errors=True)


class WrittenOff(unittest.TestCase):
    def test_written_off_a_refused_lock_ch2_is_closed_and_refilled(self):
        # p0 takes the lock, keeps the pre-signature and answers 400. The hub asks p0 to close that ch2 at
        # once and funds a new one; p0's close reveals t, so the hub collects what it held
        w = W(2)
        routed0 = w.routed()
        first = w.written_off(0, True)
        self.assertEqual(w.routed(), routed0 + first, "held in the base")
        old = w.chan2(0)
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "ch2_close" and a.get("chan") == old and a.get("why") == "written_off"
                            for a in acts), acts)
        new = w.hub.out.chans[w.origins[0]]
        self.assertNotEqual(new.p().channel_id, old, "no refill")
        self.assertEqual(new.state, "funded")
        acts += w.hub.watch_tick()
        self.assertTrue(has(acts, "secret_from_close"), acts)
        self.assertEqual(w.stale1(), [])
        self.assertEqual(w.routed(), routed0 + first, "the hold was paid: nothing given back, nothing counted twice")
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.hub.out.chans[w.origins[0]].state, "open")
        w.paid(0)

    def test_written_off_with_a_next_ch2_the_hub_switches_and_has_the_old_one_closed(self):
        w = W(1)
        w.paid(0)
        o = w.origins[0]
        w.hub.connect_next(o)
        w.node.confirm_all()
        w.hub.watch_tick()
        nxt = w.hub.out.next_chans[o].p().channel_id
        old = w.chan2(0)
        w.written_off(0, True)
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "ch2_switch" and a.get("why") == "written_off" for a in acts), acts)
        self.assertEqual(w.chan2(0), nxt)
        self.assertTrue(any(a.get("event") == "ch2_close" and a.get("chan") == old for a in acts),
                        f"the retired ch2 is not closed: {acts}")
        acts += w.hub.watch_tick()
        self.assertTrue(has(acts, "secret_from_close"), acts)
        self.assertEqual(w.stale1(), [])
        w.paid(0)

    def test_written_off_on_a_timeout_the_ch2_is_closed_and_not_refilled(self):
        # the provider never answered in time: the hub stops routing to it (AGP-064) and asks it to close
        # that ch2 now, so the held lock resolves; it does not fund that provider again
        w = W(1)
        w.paid(0)
        routed0 = w.routed()
        first = w.written_off(0, False)
        old = w.chan2(0)
        n = w.hub_funds.n
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "ch2_close" and a.get("chan") == old for a in acts), acts)
        self.assertEqual(w.hub_funds.n, n, "a provider the hub stopped routing to was funded again")
        acts += w.hub.watch_tick()
        self.assertTrue(has(acts, "secret_from_close"), acts)
        self.assertEqual(w.stale1(), [])
        self.assertEqual(w.routed(), routed0 + first)


class Orphan(unittest.TestCase):
    def test_orphan_a_lock_a_crash_left_is_swept_by_the_watcher(self):
        # the hub wrote its ch1 lock and stopped before the ch2 one (the withholding hook leaves the same
        # state). After the restart nothing can complete it; the watcher drops it, ch1 takes locks again
        w = W(1)
        w.paid(0)
        w.hub.withhold = "all"
        self.assertEqual(w.lock(0)["status"], "pending")
        w.restart()
        self.assertTrue(w.st1().extra.get("route_lock"), "the lock is on disk")
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, "orphan_lock_dropped"), acts)
        self.assertFalse(w.st1().extra.get("route_lock"))
        self.assertEqual(w.stale1(), [])

    def test_orphan_a_lock_its_ch2_wrote_off_before_the_crash_is_held_not_dropped(self):
        # the crash came between a void's two writes: ch2 has the lock written off (its pre-signature may
        # be out), ch1 still has it as its lock. Dropping it would let ch1 close below it
        w = W(1)
        w.paid(0)
        routed0 = w.routed()
        w.hub.withhold = "all"
        self.assertEqual(w.lock(0)["status"], "pending")
        w.hub.withhold = ""
        rl = dict(w.st1().extra["route_lock"])
        with w.hub.out.lock:
            w.hub.out.chans[w.origins[0]].stale.append({"lockId": rl["lockId"], "cum": 5000, "pre": None, "T": rl["T"], "d": rl["d"],
                                                         "ch1": w.pay.chan, "at": 0.0, "voided": 0.0, "why": "test"})
            w.hub.out.save()
        with self.assertRaises(ChannelError) as e:
            w.pay.close()
        self.assertFalse(w.st1().closed_txid, "ch1 closed below a lock whose ch2 pre-signature may be out")
        self.assertEqual(e.exception.code, "lock_pending")
        stale = w.stale1()
        self.assertEqual(len(stale), 1, stale)
        self.assertIsInstance(stale[0].get("hold"), dict)
        self.assertEqual(w.routed(), routed0 + rl["d"] + rl["f"], "held in the base")
        self.assertTrue(any(e.get("event") == "orphan_lock_held" for e in w.hub.events))


class C2(unittest.TestCase):
    def test_c2_the_route_payer_asks_the_hub_before_it_funds_ch1(self):
        w = W(1, open_=False)
        w.hub_svc.refuse_open = True
        with self.assertRaises(ChannelError) as e:
            w.pay.open()
        self.assertEqual(e.exception.code, "bad_expiry")
        self.assertEqual(w.pay_funds.n, 0, "ch1 was funded before the hub said it would open it")
        w.hub_svc.refuse_open = False
        n = w.opens()
        w.pay.open()
        self.assertEqual((w.pay_funds.n, w.opens() - n), (1, 2), "one preflight, one funded open")

    def test_c2_the_hub_asks_the_provider_before_it_funds_ch2(self):
        w = W(0, open_=False)
        p = provider(w.node, w.net, "http://p9.test")
        p.refuse_open = True
        with self.assertRaises(ChannelError) as e:
            w.hub.connect("http://p9.test")
        self.assertEqual(e.exception.code, "bad_expiry")
        self.assertEqual(w.hub_funds.n, 0, "ch2 was funded before the provider said it would open it")
        self.assertNotIn("http://p9.test", w.hub.out.chans, "a record for a ch2 that was never funded")
        p.refuse_open = False
        oc = w.hub.connect("http://p9.test")
        self.assertEqual((oc.state, w.hub_funds.n), ("funded", 1))
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.hub.out.chans["http://p9.test"].state, "open")


if __name__ == "__main__":
    unittest.main()
