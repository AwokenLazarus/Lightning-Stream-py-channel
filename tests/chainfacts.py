"""Re-check the chain facts the xbt402 v1.1 spec states, on a Knots 29.4.2 regtest node (RDTS + #419).

Run through scripts/chainfacts.sh (a fresh isolated node; env XBT_BIN, XBT402_RPCPORT, XBT402_P2PPORT,
XBT402_DATADIR). Prints one line per fact, measured by the node itself (testmempoolaccept vsize and
verdicts); exits non-zero if an expectation fails.

  sizes   funding script, close (with and without change, P2WPKH and P2TR change), refund,
          conditional close, hash-lock claim, 0xA3 close with a fee input
  CSV     the payer's hash-lock branch is non-final before csvDelta confirmations, final at csvDelta
  CLTV    the refund is non-final before expiry, final at expiry
  dust    the node's dust floor for each output type the protocol creates, against DUST = 546
  0x21    a 0x21 close is accepted; 0xA3 with a fee input is accepted
  RDTS    a 35-byte payout script (P2PK) is refused
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xbt402 import ecc                                               # noqa: E402
from xbt402.channel import (DUST, ChannelParams, Payee, Payer,       # noqa: E402
                            channel_payee_secret)
from xbt402.conditional import ConditionalParams, sha256             # noqa: E402
from xbt402.rpc import RPC                                           # noqa: E402
from xbt402.tx import (SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxIn, TxOut, p2wpkh_spk,  # noqa: E402
                       segwit_address, unified_sighash)
from xbt402.x402_channel import network_id                           # noqa: E402

SAT = 100_000_000
DD = os.environ["XBT402_DATADIR"]
node = RPC(int(os.environ["XBT402_RPCPORT"]), os.path.join(DD, "regtest", ".cookie"))
w = node.wallet("w")
NET = network_id(node.getblockhash(101))
PAYTO = 0xB0B5
failures, facts = [], {}


def report(ok, what, key=None, value=None):
    print(("  ok   " if ok else "  FAIL ") + what)
    if key:
        facts[key] = value
    if not ok:
        failures.append(what)


def mine(n=1):
    return node.generatetoaddress(n, w.getnewaddress())


def accept(tx):
    r = node.testmempoolaccept([tx.hex() if isinstance(tx, Tx) else tx])[0]
    return r.get("allowed", False), r.get("vsize"), r.get("reject-reason", "")


def fund(spk: bytes, sats: int):
    addr = segwit_address("bcrt", spk)
    txid = w.sendtoaddress(addr, sats / SAT)
    raw = node.getrawtransaction(txid, True)
    vout = next(o["n"] for o in raw["vout"] if o["scriptPubKey"]["hex"] == spk.hex())
    mine()
    return txid, vout


def channel(a: int, capacity: int, expiry_in: int = 50, payer_spk: str = "", close_fee: int = 600):
    expiry = node.getblockcount() + expiry_in
    p = ChannelParams.derive(ecc.pubkey(PAYTO).hex(), ecc.pubkey(a).hex(), expiry, close_fee, payer_spk,
                             network=NET)
    p.funding_txid, p.funding_vout = fund(p.spk, capacity)
    p.capacity = capacity
    payee = Payee(p, channel_payee_secret(NET, PAYTO, bytes.fromhex(p.payer_pub), expiry))
    return p, Payer(p, a), payee


def close(p, payer, payee, cum):
    payee.accept(cum, payer.sign_state(cum))
    return payee.close_tx()


def main():
    print(f"node {node.getnetworkinfo()['subversion']} height {node.getblockcount()} network {NET}")

    # --- sizes -------------------------------------------------------------------------------
    p, payer, payee = channel(0xA1, 100_000)
    report(len(p.script) == 79 and len(p.spk) == 34, f"funding: witness script {len(p.script)} B, P2WSH output "
                                                     f"{len(p.spk)} B (spec: 79, 34)", "funding_script", len(p.script))
    tx = close(p, payer, payee, 10_000)
    ok, vs, why = accept(tx)
    report(ok and 170 <= vs <= 171, f"close, 2 outputs (P2WPKH change): {vs} vB, fee 600 = "
                                    f"{600 / vs:.2f} sat/vB (spec: 170-171 vB, ~3.5) {why}", "close_vsize", vs)
    node.sendrawtransaction(tx.hex())
    mine()

    p2, payer2, payee2 = channel(0xA2, 100_000, payer_spk="5120" + "33" * 32)
    ok, vs, why = accept(close(p2, payer2, payee2, 10_000))
    report(ok, f"close, 2 outputs (P2TR change): {vs} vB {why}", "close_vsize_p2tr", vs)
    facts["close_vsize_p2tr"] = vs

    p3, payer3, payee3 = channel(0xA3, 20_000)
    ok, vs, why = accept(close(p3, payer3, payee3, 20_000 - 600))
    report(ok, f"close, 1 output (no change): {vs} vB {why}", "close_vsize_nochange", vs)

    # --- CLTV refund -------------------------------------------------------------------------
    p4, _, _ = channel(0xA4, 50_000, expiry_in=5)
    refund = p4.refund_tx(0xA4)
    ok, vs, why = accept(refund)
    report(not ok and "non-final" in why, f"refund before expiry: refused ({why})")
    mine(p4.expiry - node.getblockcount())
    ok, vs, why = accept(refund)
    report(ok, f"refund at expiry: accepted, {vs} vB (REFUND_VSIZE 140) {why}", "refund_vsize", vs)

    # --- conditional close, claim and CSV ----------------------------------------------------
    p5, payer5, payee5 = channel(0xA5, 100_000)
    k = os.urandom(32)
    cp = ConditionalParams(p5, sha256(k), 1_000)
    ctx = cp.state_tx(5_000)
    a_sig = ecc.sign(0xA5, cp.sighash(ctx)) + bytes([SIGHASH_ALL_UNIFIED])
    b_sig = ecc.sign(payee5.secret, cp.sighash(ctx)) + bytes([SIGHASH_ALL_UNIFIED])
    ctx.inputs[0].witness = [a_sig, b_sig, b"\x01", p5.script]
    ok, vs, why = accept(ctx)
    report(ok, f"conditional close, 3 outputs (payee, hash lock, change): {vs} vB, fee 600 = {600 / vs:.2f} sat/vB "
               f"{why}", "cond_close_vsize", vs)
    close_txid = node.sendrawtransaction(ctx.hex())
    vout = next(i for i, o in enumerate(ctx.outputs) if o.script_pubkey == cp.spk)
    report(len(cp.script) <= 256, f"hash-lock witness script {len(cp.script)} B (RDTS push limit 256)",
           "hashlock_script", len(cp.script))
    claim = cp.claim_tx(close_txid, vout, k, payee5.secret, bytes.fromhex(p5.payee_spk), 300)
    ok, vs, why = accept(claim)
    report(ok, f"claim (unconfirmed close, CPFP-style child): {vs} vB, fee 300 = {300 / vs:.2f} sat/vB {why}",
           "claim_vsize", vs)

    def payer_branch(seq):
        t = Tx(version=2, inputs=[TxIn(bytes.fromhex(close_txid)[::-1], vout, seq)],
               outputs=[TxOut(1_000 - 300, p2wpkh_spk(ecc.pubkey(0xA5)))], locktime=0)
        h = unified_sighash(t, [TxOut(1_000, cp.spk)], 0, ST_WITNESS_V0, cp.script, SIGHASH_ALL_UNIFIED)
        t.inputs[0].witness = [ecc.sign(0xA5, h) + bytes([SIGHASH_ALL_UNIFIED]), b"", cp.script]
        return t
    mine()                                                            # close: 1 confirmation
    ok, _, why = accept(payer_branch(cp.csv_delta))
    report(not ok and "non-BIP68-final" in why, f"payer hash-lock branch at 1 confirmation: refused ({why})")
    mine(cp.csv_delta - 2)                                            # csvDelta - 1 confirmations
    ok, _, why = accept(payer_branch(cp.csv_delta))
    report(not ok and "non-BIP68-final" in why,
           f"payer branch at {cp.csv_delta - 1} confirmations: refused ({why})")
    ok, _, why = accept(payer_branch(cp.csv_delta - 1))
    report(not ok, f"payer branch with nSequence {cp.csv_delta - 1} < csvDelta: refused ({why})")
    mine()                                                            # csvDelta confirmations
    ok, vs, why = accept(payer_branch(cp.csv_delta))
    report(ok, f"payer branch at csvDelta = {cp.csv_delta} confirmations: accepted, {vs} vB {why}",
           "csv_refund_vsize", vs)
    ok, _, why = accept(claim)
    report(ok, f"claim still valid at csvDelta (the two race from here) {why}")
    rbf = cp.claim_tx(close_txid, vout, k, payee5.secret, bytes.fromhex(p5.payee_spk), 454)
    node.sendrawtransaction(payer_branch(cp.csv_delta).hex())
    ok, _, why = accept(rbf)
    report(ok, f"a claim paying more replaces the payer's branch in the mempool (RBF) {why}")

    # --- dust ------------------------------------------------------------------------------------
    for name, spk in (("P2WPKH", p2wpkh_spk(ecc.pubkey(7))), ("P2WSH", cp.spk),
                      ("P2TR", bytes.fromhex("5120" + "44" * 32))):
        txid, n = fund(p2wpkh_spk(ecc.pubkey(0xD1)), 10_000)
        floor = None
        for v in range(250, 600):
            t = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], n, 0xFFFFFFFD)],
                   outputs=[TxOut(v, spk), TxOut(10_000 - v - 300, p2wpkh_spk(ecc.pubkey(0xD1)))], locktime=0)
            from xbt402.channel import sign_p2wpkh
            sign_p2wpkh(0xD1, t, [TxOut(10_000, p2wpkh_spk(ecc.pubkey(0xD1)))])
            if accept(t)[0]:
                floor = v
                break
        report(floor is not None and floor <= DUST, f"dust floor {name}: {floor} sat accepted, {floor - 1} refused "
                                                     f"(DUST 546 is above it)", f"dust_{name}", floor)

    # --- 0xA3 with a fee input -------------------------------------------------------------------
    p6, payer6, payee6 = channel(0xA6, 100_000)
    sig_a3 = payer6.sign_state_a3(10_000)
    payee6.best_amount = 10_000
    fee_spk = p2wpkh_spk(ecc.pubkey(0xFEE))
    ftxid, fn = fund(fee_spk, 5_000)
    tx = payee6.close_tx_with_fee_input(TxOut(5_000, fee_spk), TxIn(bytes.fromhex(ftxid)[::-1], fn, 0xFFFFFFFD),
                                        0xFEE, fee_spk, 2_000, sig_a3)
    ok, vs, why = accept(tx)
    report(ok, f"0xA3 close + fee input: accepted, {vs} vB {why}", "a3_vsize", vs)

    # --- RDTS -------------------------------------------------------------------------------------
    txid, n = fund(p2wpkh_spk(ecc.pubkey(0xD2)), 10_000)
    t = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], n, 0xFFFFFFFD)],
           outputs=[TxOut(9_000, bytes([33]) + ecc.pubkey(9) + b"\xac")], locktime=0)
    from xbt402.channel import sign_p2wpkh
    sign_p2wpkh(0xD2, t, [TxOut(10_000, p2wpkh_spk(ecc.pubkey(0xD2)))])
    ok, _, why = accept(t)
    report(not ok, f"35-byte P2PK output refused ({why})")

    print(json.dumps(facts))
    print(f"{len(failures)} failed" if failures else "all chain facts hold")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
