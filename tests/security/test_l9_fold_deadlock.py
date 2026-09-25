"""L9 (Low) a lost fold blocks every later conditional call on the channel (client SDK).

`request_conditional` never re-sent an unacknowledged fold: it signed the next conditional state over
`uncond = payer.signed` (the fold the provider never got), and the provider, still holding an
outstanding increment, refused with `conditional_outstanding`. The SDK then crashed on the 402 body
(KeyError 'preimage') on every retry, so an agent that only makes conditional calls was locked out of
the channel until a plain call happened to carry the fold. No funds at risk.

Fix: `request_conditional` first hands over any signed-but-unacknowledged state through
`/x402/verify`, and a refused conditional call raises a ChannelError with the provider's code.
"""
import unittest

from condhelp import ORIGIN, PLAIN, Rig
from sechelp import V11, Repro, load, v11


def lost_fold(xm):
    r = Rig(xm)
    r.fold = False
    r.client.request_conditional("GET", ORIGIN + "/v1/cond")        # the fold never arrives
    r.fold = True                                                   # the network is fine again
    return r


class FoldDeadlock(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_conditional_calls_locked_out(self):
        r = lost_fold(v11("x402_channel"))
        errors = []
        for _ in range(3):
            try:
                r.client.request_conditional("GET", ORIGIN + "/v1/cond")
            except Exception as e:  # noqa: BLE001
                errors.append(type(e).__name__)
        self.reproduces(errors == ["KeyError"] * 3 and '"conditional_outstanding"' in r.log[-1][2].decode(),
                        f"3 conditional calls after a lost fold: {errors}, provider says conditional_outstanding")

    def test_fixed_next_conditional_call_sends_the_fold_first(self):
        r = lost_fold(load("x402_channel"))
        st, _, _, plain = r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual((st, plain), (200, PLAIN))
        self.assertEqual(r.chan.best_cum, r.cch.payer.signed)          # both increments folded

    def test_fixed_refusal_is_a_channel_error(self):
        from xbt402.channel import ChannelError
        r = lost_fold(load("x402_channel"))
        r.fold = False                                                # the fold still cannot get through
        with self.assertRaises(ChannelError) as e:
            r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual(e.exception.code, "conditional_outstanding")


if __name__ == "__main__":
    unittest.main()
