"""Settle the chain-rule questions behind xbt-channel on Knots 29.4.2 (RDTS on from blake2b@101).

Run through scripts/rules.sh (fresh isolated nodes: Knots A + Knots B peered, Core 29.0 peered
to A and stuck at the last shared block 100). Prints one line per finding; exits non-zero if an
expectation fails.

(a) SIGHASH_UNIFIED on BIP341: taproot key path and tapscript spends signed 0x21.
(b) RDTS + 29.4.2 relay of the P2WSH channel: funding, close and refund accepted by A's mempool
    and relayed over P2P to B; tapscript OP_IF and a 35-byte output refused.
(r) Replay: a channel funding that spends a pre-split coin, signed ALL (0x01) vs ALL|UNIFIED (0x21),
    checked against Core 29.0 (the SHA-256 chain) and Knots.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xbt402 import ecc, schnorr                                    # noqa: E402
from xbt402.channel import ChannelParams, Payee, Payer             # noqa: E402
from xbt402.rpc import RPC, RPCError                               # noqa: E402
from xbt402.tx import (OP_CHECKSIG, OP_ENDIF, OP_IF, ST_TAPROOT, ST_TAPSCRIPT,  # noqa: E402
                       ST_WITNESS_V0, SIGHASH_ALL, SIGHASH_ALL_UNIFIED, Tx, TxIn, TxOut, address_to_spk,
                       bip143_sighash, p2wpkh_script_code, p2wpkh_spk, push, unified_sighash)

PRESPLIT_SK = 0x9E5B11  # block 1's coinbase pays P2WPKH(this key): scripts/rules.sh mines it

SAT = 100_000_000
ROOT = os.environ.get("RULES_ROOT", os.path.expanduser("~/xbt-rnd/xbt-060/run"))
A = RPC(int(os.environ.get("RULES_A_RPC", "30130")), f"{ROOT}/rules-a/regtest/.cookie")
B = RPC(int(os.environ.get("RULES_B_RPC", "30132")), f"{ROOT}/rules-b/regtest/.cookie")
CORE = RPC(int(os.environ.get("RULES_CORE_RPC", "30134")), f"{ROOT}/rules-core/regtest/.cookie")
W = A.wallet("w")
failures = []


def report(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        failures.append(what)


def mine(n=1):
    """Mine on A and wait until B has the same tip, so relay tests never race block propagation."""
    hashes = A.generatetoaddress(n, W.getnewaddress())
    for _ in range(240):
        if B.getbestblockhash() == hashes[-1]:
            break
        time.sleep(0.25)
    return hashes


def fund_spk(spk: bytes, sats: int):
    """Have A's wallet pay `sats` to an arbitrary scriptPubKey; returns (txid, vout)."""
    raw = Tx(outputs=[TxOut(sats, spk)]).serialize(False).hex()
    funded = W.fundrawtransaction(raw)["hex"]
    signed = W.signrawtransactionwithwallet(funded)["hex"]
    txid = A.sendrawtransaction(signed)
    vout = next(i for i, o in enumerate(Tx.parse(bytes.fromhex(signed)).outputs) if o.script_pubkey == spk)
    return txid, vout


def spend_tx(txid, vout, sats, fee=1000):
    dest = address_to_spk(W.getnewaddress("", "bech32"))
    return Tx(inputs=[TxIn(bytes.fromhex(txid)[::-1], vout)], outputs=[TxOut(sats - fee, dest)])


def tma(node, tx_hex):
    r = node.testmempoolaccept([tx_hex])[0]
    return r["allowed"], r.get("reject-reason", "")


def in_mempool_of(node, txid, secs=60):
    for _ in range(secs * 4):
        if txid in node.getrawmempool():
            return True
        time.sleep(0.25)
    return False


def main():
    print(f"A {A.getnetworkinfo()['subversion']} h={A.getblockcount()}  B h={B.getblockcount()}"
          f"  Core {CORE.getnetworkinfo()['subversion']} h={CORE.getblockcount()}")
    return run_all()


def section_replay():
    """A channel funding that spends a pre-split coin (block 1's coinbase), signed two ways."""
    cb1 = A.getblock(A.getblockhash(1))["tx"][0]
    out = A.getrawtransaction(cb1, True)["vout"][0]
    value = round(out["value"] * SAT)
    pub = ecc.pubkey(PRESPLIT_SK)
    assert out["scriptPubKey"]["hex"] == p2wpkh_spk(pub).hex(), "block 1 not mined to PRESPLIT_SK"
    p = ChannelParams(ecc.pubkey(0x5EED01).hex(), ecc.pubkey(0x5EED02).hex(), 1000,
                      p2wpkh_spk(ecc.pubkey(0x5EED01)).hex(), p2wpkh_spk(ecc.pubkey(0x5EED02)).hex(), 600)

    def funding(hash_type):
        tx = Tx(inputs=[TxIn(bytes.fromhex(cb1)[::-1], 0)], outputs=[TxOut(value - 2000, p.spk)])
        if hash_type == SIGHASH_ALL:
            msg = bip143_sighash(tx, 0, p2wpkh_script_code(pub), value)
        else:
            msg = unified_sighash(tx, [TxOut(value, p2wpkh_spk(pub))], 0, ST_WITNESS_V0,
                                  p2wpkh_script_code(pub), hash_type)
        tx.inputs[0].witness = [ecc.sign(PRESPLIT_SK, msg) + bytes([hash_type]), pub]
        return tx
    legacy, unified = funding(SIGHASH_ALL), funding(SIGHASH_ALL_UNIFIED)
    cl, cu = tma(CORE, legacy.hex()), tma(CORE, unified.hex())
    kl, ku = tma(A, legacy.hex()), tma(A, unified.hex())
    report(kl[0], f"(r) pre-split funding signed ALL (0x01): Knots 29.4.2 accepts {kl}")
    report(cl[0], f"(r) the SAME bytes on Core 29.0: accepted -> replayable on the SHA-256 chain {cl}")
    report(ku[0], f"(r) funding signed ALL|UNIFIED (0x21): Knots 29.4.2 accepts {ku}")
    report(not cu[0], f"(r) the 0x21 funding on Core 29.0: rejected -> {cu[1]}")
    if ku[0]:
        A.sendrawtransaction(unified.hex())
        mine(1)
        report(A.getrawtransaction(unified.txid(), True).get("confirmations", 0) >= 1,
               "(r) the unified funding confirmed on XBT")


def section_channel():
    # --- (b) P2WSH channel funding / close / refund: mempool + P2P relay under RDTS --------
    h = A.getblockcount()
    p = ChannelParams(ecc.pubkey(0xAA01).hex(), ecc.pubkey(0xAA02).hex(), h + 30,
                      p2wpkh_spk(ecc.pubkey(0xAA01)).hex(), p2wpkh_spk(ecc.pubkey(0xAA02)).hex(), 600)
    txid, vout = fund_spk(p.spk, 100_000)
    report(in_mempool_of(B, txid), f"(b) P2WSH funding (34-byte output) relayed A -> B: {txid[:16]}..")
    mine(1)
    p.funding_txid, p.funding_vout, p.capacity = txid, vout, 100_000
    payer, payee = Payer(p, 0xAA01), Payee(p, 0xAA02)
    payee.accept(4000, payer.sign_state(4000))
    close = payee.close_tx()
    ok, why = tma(A, close.hex())
    report(ok, f"(b) close (P2WSH OP_IF branch, 2x 0x21) accepted by 29.4.2 mempool {why}")
    A.sendrawtransaction(close.hex())
    report(in_mempool_of(B, close.txid()), "(b) close relayed A -> B over P2P")
    mine(1)
    # refund on a second channel
    p2 = ChannelParams(ecc.pubkey(0xAB01).hex(), ecc.pubkey(0xAB02).hex(), A.getblockcount() + 5,
                       p2wpkh_spk(ecc.pubkey(0xAB01)).hex(), p2wpkh_spk(ecc.pubkey(0xAB02)).hex(), 600)
    t2, v2 = fund_spk(p2.spk, 50_000)
    p2.funding_txid, p2.funding_vout, p2.capacity = t2, v2, 50_000
    mine(p2.expiry - A.getblockcount())
    refund = p2.refund_tx(0xAB01)
    ok, why = tma(A, refund.hex())
    report(ok, f"(b) refund (CLTV OP_ELSE branch, 0x21) accepted at expiry {why}")
    A.sendrawtransaction(refund.hex())
    report(in_mempool_of(B, refund.txid()), "(b) refund relayed A -> B over P2P")
    mine(1)



def section_taproot():
    # --- (a) SIGHASH_UNIFIED on BIP341 --------------------------------------------------------
    spk, tweaked, _ = schnorr.taproot_output(0x7A01)
    t, v = fund_spk(spk, 60_000)
    mine(1)
    tx = spend_tx(t, v, 60_000)
    prevouts = [TxOut(60_000, spk)]
    wrong = unified_sighash(tx, prevouts, 0, ST_WITNESS_V0, b"", SIGHASH_ALL_UNIFIED)
    tx.inputs[0].witness = [schnorr.sign(tweaked, wrong) + b"\x21"]
    ok, why = tma(A, tx.hex())
    report(not ok, f"(a) control: 0x21 key-path sig over the WRONG message is rejected ({why})")
    msg = unified_sighash(tx, prevouts, 0, ST_TAPROOT, b"", SIGHASH_ALL_UNIFIED)
    tx.inputs[0].witness = [schnorr.sign(tweaked, msg) + b"\x21"]
    ok, why = tma(A, tx.hex())
    report(ok, f"(a) taproot KEY PATH signed 0x21 over UnifiedSighash(script type 2) accepted {why}")
    if ok:
        A.sendrawtransaction(tx.hex())
        report(in_mempool_of(B, tx.txid()), "(a) key-path 0x21 spend relayed A -> B")

    leaf = push(schnorr.xonly(0x7B02)) + bytes([OP_CHECKSIG])
    spk, _, control = schnorr.taproot_output(0x7B01, leaf)
    t, v = fund_spk(spk, 60_000)
    mine(1)
    tx = spend_tx(t, v, 60_000)
    msg = unified_sighash(tx, [TxOut(60_000, spk)], 0, ST_TAPSCRIPT, b"", SIGHASH_ALL_UNIFIED,
                          schnorr.leaf_hash(leaf))
    tx.inputs[0].witness = [schnorr.sign(0x7B02, msg) + b"\x21", leaf, control]
    ok, why = tma(A, tx.hex())
    report(ok, f"(a) TAPSCRIPT leaf <X> CHECKSIG signed 0x21 (script type 3 + leaf hash) accepted {why}")
    if ok:
        A.sendrawtransaction(tx.hex())
    mine(1)



def section_rdts():
    # --- (b) RDTS is really on: OP_IF in tapscript and a 35-byte output are refused ----------
    leaf = bytes([0x51, OP_IF]) + push(schnorr.xonly(0x7C02)) + bytes([OP_CHECKSIG, OP_ENDIF])
    spk, _, control = schnorr.taproot_output(0x7C01, leaf)
    t, v = fund_spk(spk, 60_000)
    mine(1)
    tx = spend_tx(t, v, 60_000)
    msg = unified_sighash(tx, [TxOut(60_000, spk)], 0, ST_TAPSCRIPT, b"", SIGHASH_ALL_UNIFIED,
                          schnorr.leaf_hash(leaf))
    tx.inputs[0].witness = [schnorr.sign(0x7C02, msg) + b"\x21", leaf, control]
    ok, why = tma(A, tx.hex())
    report(not ok, f"(b) RDTS: tapscript with OP_IF refused by mempool ({why})")
    try:
        A.generateblock(W.getnewaddress(), [tx.hex()])
        report(False, "(b) RDTS: block with a tapscript OP_IF spend was ACCEPTED")
    except RPCError as e:
        report(True, f"(b) RDTS: block with a tapscript OP_IF spend is consensus-invalid ({e})")

    p2pk = push(ecc.pubkey(0x7D01)) + bytes([OP_CHECKSIG])   # 35-byte scriptPubKey
    raw = W.signrawtransactionwithwallet(W.fundrawtransaction(Tx(outputs=[TxOut(10_000, p2pk)]).serialize(False).hex())["hex"])["hex"]
    ok, why = tma(A, raw)
    report(not ok, f"(b) RDTS: creating a 35-byte output refused by mempool ({why})")
    try:
        A.generateblock(W.getnewaddress(), [raw])
        report(False, "(b) RDTS: block creating a 35-byte output was ACCEPTED")
    except RPCError as e:
        report(True, f"(b) RDTS: block creating a 35-byte output is consensus-invalid ({e})")



def run_all():
    for sec in (section_replay, section_channel, section_taproot, section_rdts):
        try:
            sec()
        except Exception as e:  # noqa: BLE001 - report and continue with the next question
            report(False, f"{sec.__name__} crashed: {type(e).__name__}: {e}")
    print("rules:", "all expectations held" if not failures else f"{len(failures)} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
