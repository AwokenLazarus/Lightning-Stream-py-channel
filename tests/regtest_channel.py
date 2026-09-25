"""Channel lifecycle against a real Knots BLAKE2b node (private regtest from scripts/node.sh).

Run: scripts/node.sh up && python3 -m tests.regtest_channel
Exercises: open, 10 payments, payee close mined; forged higher state rejected by the node;
refund non-final before expiry, valid at expiry; close still valid after expiry (the race the
payee must avoid); the funding-check helper refusing a coinbase funding.
"""
import sys
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelParams, Payee, Payer
from xbt402.funding import FundingPolicy, check_funding
from xbt402.rpc import RPC, RPCError
from xbt402.tx import SIGHASH_ALL_UNIFIED, Tx, address_to_spk, segwit_address

SAT = 100_000_000


class Ctx:
    node = RPC.from_env()
    w = node.wallet("w")


def mine(n=1):
    return Ctx.node.generatetoaddress(n, Ctx.w.getnewaddress())


def open_channel(capacity, expiry_delta, payer_secret, payee_secret, close_fee=380):
    height = Ctx.node.getblockcount()
    p = ChannelParams(
        payer_pub=ecc.pubkey(payer_secret).hex(), payee_pub=ecc.pubkey(payee_secret).hex(),
        expiry=height + expiry_delta,
        payer_spk=address_to_spk(Ctx.w.getnewaddress("", "bech32")).hex(),
        payee_spk=address_to_spk(Ctx.w.getnewaddress("", "bech32")).hex(), close_fee=close_fee)
    addr = segwit_address("bcrt", p.spk)
    txid = Ctx.w.sendtoaddress(addr, capacity / SAT)
    raw = Ctx.node.getrawtransaction(txid, True)
    vout = next(o["n"] for o in raw["vout"] if o["scriptPubKey"]["hex"] == p.spk.hex())
    p.funding_txid, p.funding_vout, p.capacity = txid, vout, capacity
    return p


def accept(tx: Tx):
    return Ctx.node.testmempoolaccept([tx.hex()])[0]


class RegtestChannel(unittest.TestCase):
    def test_pay_close(self):
        p = open_channel(200_000, 200, 0xA11CE, 0xB0B)
        mine(1)
        check_funding(Ctx.node, p, FundingPolicy(min_conf=1))
        payer, payee = Payer(p, 0xA11CE), Payee(p, 0xB0B)
        for i in range(1, 11):
            amt = 1000 + 250 * i
            payee.accept(amt, payer.sign_state(amt))
        # Forged: payee rewrites the amount upward but reuses the payer's last signature.
        forged = p.state_tx(payee.best_amount + 50_000)
        good = payee.close_tx()
        forged.inputs[0].witness = list(good.inputs[0].witness)
        res = accept(forged)
        self.assertFalse(res["allowed"])
        print("  forged state:", res.get("reject-reason"))
        res = accept(good)
        self.assertTrue(res["allowed"], res)
        txid = Ctx.node.sendrawtransaction(good.hex())
        mine(1)
        got = Ctx.node.getrawtransaction(txid, True)
        self.assertGreaterEqual(got["confirmations"], 1)
        self.assertEqual(round(got["vout"][0]["value"] * SAT), 3500)
        sig = good.inputs[0].witness[0]
        self.assertEqual(sig[-1], SIGHASH_ALL_UNIFIED)
        print(f"  close {txid} mined, payee 3500 sat, vsize {got['vsize']}, fee {p.close_fee} sat,"
              f" payer sighash 0x{sig[-1]:02x}")

    def test_refund_after_expiry(self):
        p = open_channel(50_000, 12, 0xC0FFEE, 0xD00D)
        mine(1)
        payer, payee = Payer(p, 0xC0FFEE), Payee(p, 0xD00D)
        payee.accept(5000, payer.sign_state(5000))
        refund = p.refund_tx(0xC0FFEE)
        res = accept(refund)
        self.assertFalse(res["allowed"])
        print("  refund before expiry:", res.get("reject-reason"))
        mine(p.expiry - Ctx.node.getblockcount())   # next block is expiry+1 > locktime
        self.assertTrue(accept(refund)["allowed"])
        # The payee's close is ALSO still valid: after expiry it is a race, so the payee
        # must close by expiry - margin.
        self.assertTrue(accept(payee.close_tx())["allowed"])
        txid = Ctx.node.sendrawtransaction(refund.hex())
        mine(1)
        self.assertGreaterEqual(Ctx.node.getrawtransaction(txid, True)["confirmations"], 1)
        with self.assertRaises(RPCError):
            Ctx.node.sendrawtransaction(payee.close_tx().hex())
        print(f"  refund {txid} mined at expiry {p.expiry}; late close rejected")

    def test_coinbase_funding_refused(self):
        blk = Ctx.node.getblock(Ctx.node.getbestblockhash())
        cb = Ctx.node.getrawtransaction(blk["tx"][0], True)
        p = ChannelParams(ecc.pubkey(1).hex(), ecc.pubkey(2).hex(), 10_000, "", "", 600,
                          funding_txid=cb["txid"], funding_vout=0,
                          capacity=round(cb["vout"][0]["value"] * SAT))
        with self.assertRaises(Exception) as e:
            check_funding(Ctx.node, p, FundingPolicy(min_conf=0))
        self.assertIn("coinbase", str(e.exception))


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
