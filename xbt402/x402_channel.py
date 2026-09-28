"""x402 v2 scheme `xbt-channel`: HTTP 402 payments over XBT Spillman channels (xbt402 v1.1).

Spec: docs/x402/xbt402-spec-v1.1-draft.md (was ~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402
HTTP 402 payment channels.md). v1.1: the payee key commits to the network (extra.derivation "v2"),
PAYMENT-RESPONSE is an x402 SettlementResponse, /x402/verify and /x402/settle take and answer the x402
v2 facilitator shapes.

  402 + PAYMENT-REQUIRED: base64(PaymentRequired)      (same JSON in the body)
  PaymentRequired = {x402Version: 2, error?, resource: {url}, accepts: [PaymentRequirements]}
  PaymentRequirements = {scheme: "xbt-channel", network: "bip122:<first 32 hex of block 961640>",
      amount: "<sats per call, max>", asset: "XBT:sat", payTo: "<33-byte compressed pubkey hex>",
      maxTimeoutSeconds, extra: {minCapacity, maxCapacity, minExpiryBlocks, maxExpiryBlocks,
      closeMarginBlocks, minConf, closeFeeSat, openUrl, closeUrl, billing: "postpay"|"prepay",
      derivation: "v2", closeFeePayer?: "payer"|"payee" (v1.2, absent = payer)}}
      payee key P = payTo + t*G, t = H("xbt-channel/payee/v2", len8(network) network payTo A LE32(expiry))

  open:   POST extra.openUrl {x402Version, network, channel: {txid, vout, capacity, expiry, payerPub,
          payerSpk?, redeemScript}}  -> {chan, expiry, maxCum, confirmations}
  pay:    PAYMENT-SIGNATURE: base64({x402Version: 2, accepted: <requirements>,
          payload: {chan, seq, cum, sig?, auth}})  sig = payer DER || 0x21 over the state for cum
          auth = HMAC-SHA256(tagged_hash("xbt402/auth-key", ECDH(A, P)),
                 "xbt402/auth|chan|seq|cum|sig|sha256(method|path|body)"), seq above every earlier one
  result: PAYMENT-RESPONSE: base64(SettlementResponse {success, transaction: "", network, payer: A,
          amount: "", extra: {chargedAmount, receipt: {scheme, chan, seq, cum, charged, spentMsat,
          owedMsat, creditMsat, expiry, req, sig}}})  sig = receipt by the channel payee key
  close:  POST extra.closeUrl {chan, sig, payload?}  sig = payer over tagged_hash("xbt402/close", chan);
          payload = a final state paying what is owed (postpay)
  facilitator: GET /x402/supported, POST /x402/verify and /x402/settle with {x402Version,
          paymentPayload: {x402Version, accepted, payload}, paymentRequirements} -> VerifyResponse
          {isValid, invalidReason?, payer, extra: {chan, cum}} / SettlementResponse (settle = close);
          only under /x402/, so a paid API keeps its own /verify, /settle and /supported routes
"""
import base64
import copy
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

from . import ecc
from .channel import (DERIVATION, DUST, FEE_PAYERS, SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams, Payee, Payer,
                      canonical_chan, channel_auth_key, channel_payee_secret, check_payout_spk, settle_due)
from .conditional import CSV_DELTA
from .funding import FundingPolicy, check_funding
from .ledger import ChannelState, Ledger
from .tx import segwit_address, tagged_hash

SCHEME = "xbt-channel"
MAX_BODY = 1 << 20                                          # default bytes per request body (overridable)
XBT_MAINNET = "bip122:0000000000000050c1e5f69672f45929"   # block 961640, the first BLAKE2b block
FACILITATOR_VERIFY, FACILITATOR_SETTLE, FACILITATOR_SUPPORTED = "/x402/verify", "/x402/settle", "/x402/supported"


def b64json(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def unb64json(s: str):
    return json.loads(base64.b64decode(s))


def request_digest(method: str, path: str, body: bytes) -> str:
    return hashlib.sha256(method.encode() + b"|" + path.encode() + b"|" + body).hexdigest()


def unsafe_headers(hdrs: dict) -> bool:
    """A CR, LF or NUL in a response header name or value: a handler reflecting request data would
    inject headers (or split the response) on transports that do not check, like http.server."""
    return any(c in str(k) + str(v) for k, v in hdrs.items() for c in "\r\n\0")


def request_auth(key: bytes, chan: str, seq, cum, sig, req: str) -> str:
    """payload.auth: binds one paid request (method, path, body) to the channel, a fresh seq and the
    state it carries. Without it `{chan, cum}` was a bearer token anyone could spend."""
    msg = "|".join(("xbt402/auth", chan, str(seq), str(cum), sig or "", req)).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def receipt_message(r: dict) -> bytes:
    keys = ("chan", "seq", "cum", "charged", "spentMsat", "req")
    return tagged_hash("xbt402/receipt", "|".join(str(r[k]) for k in keys).encode())


def close_message(chan: str) -> bytes:
    return tagged_hash("xbt402/close", chan.encode())


def network_id(first_blake2b_block_hash: str) -> str:
    return "bip122:" + first_blake2b_block_hash[:32]


# x402 v2 facilitator reasons (VerifyResponse.invalidReason, SettlementResponse.errorReason) for the
# protocol's own codes. The 402 `error` field keeps the short codes until the scheme name is settled
# (`xbt-channel` or a `batch-settlement` binding would change the prefix; docs/x402/PUBLISHING.md).
UPSTREAM_CODES = {"unsupported_scheme_or_network": "invalid_xbt_channel_scheme_or_network",
                  "bad_payload": "invalid_xbt_channel_payload", "bad_auth": "invalid_xbt_channel_auth",
                  "channel_closing": "invalid_xbt_channel_closing", "bad_sig": "invalid_xbt_channel_signature",
                  "wrong_network": "invalid_network", "close_failed": "unexpected_settle_error"}


def safe_code(code) -> bool:
    """A short snake_case identifier: the only provider-chosen string an error code may be (L12)."""
    return isinstance(code, str) and 0 < len(code) <= 40 and code.replace("_", "").isalpha() and code.islower()


def upstream_code(code: str) -> str:
    return UPSTREAM_CODES.get(code) or "invalid_xbt_channel_" + (code or "payload")


def settlement_response(receipt: dict, network: str, payer: str, success: bool) -> dict:
    """PAYMENT-RESPONSE as an x402 v2 SettlementResponse. A paid call broadcasts nothing, so
    `transaction` and `amount` are empty; the signed channel receipt rides in `extra`."""
    return {"success": success, "transaction": "", "network": network, "payer": payer, "amount": "",
            "extra": {"chargedAmount": receipt["charged"], "receipt": receipt}}


def receipt_of(resp: dict) -> dict:
    """The signed channel receipt inside a PAYMENT-RESPONSE SettlementResponse."""
    r = ((resp or {}).get("extra") or {}).get("receipt") if isinstance(resp, dict) else None
    if not isinstance(r, dict) or r.get("scheme") != SCHEME:
        raise ChannelError("bad_receipt", "PAYMENT-RESPONSE carries no xbt-channel receipt in extra.receipt")
    if str(resp["extra"].get("chargedAmount")) != str(r.get("charged")):
        raise ChannelError("bad_receipt", "extra.chargedAmount differs from the signed receipt")
    return r


def facilitator_request(accepted: dict, payload: dict) -> dict:
    """Body of POST /x402/verify and /x402/settle: {x402Version, paymentPayload, paymentRequirements}."""
    return {"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": accepted, "payload": payload},
            "paymentRequirements": accepted}


# --- provider ---------------------------------------------------------------------------------
class RefundCustody:
    """Store refunds at open; broadcast any whose expiry has been reached."""

    def __init__(self, path: str, broadcast: Callable[[str], str] = None):
        self.path, self.broadcast, self.lock = path, broadcast, threading.Lock()
        self.items = []
        if os.path.exists(path):
            with open(path) as f:
                self.items = json.load(f)

    def add(self, refund_hex: str, expiry: int, chan: str = ""):
        with self.lock:
            self.items.append({"hex": refund_hex, "expiry": expiry, "chan": chan, "txid": "", "done": False})
            self._save()

    def due(self, height: int) -> list:
        out = []
        with self.lock:
            for it in self.items:
                if it["done"] or height < it["expiry"]:
                    continue
                if not self.broadcast:
                    continue
                try:
                    it["txid"] = self.broadcast(it["hex"])
                    it["done"] = True
                    out.append({"chan": it["chan"], "txid": it["txid"], "expiry": it["expiry"]})
                except Exception as e:
                    it["error"] = str(e)
            self._save()
        return out

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.items, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


class XbtChannelProvider:
    """Facilitator-less x402 resource server for `xbt-channel`. Wraps `handler(method, path, body)
    -> (status, headers, body)`; `price(method, path)` is the per-call max in sats. `charge` may
    lower the actual charge after serving (metered/`upto` style)."""

    def __init__(self, rpc, pay_to_secret: int, network: str, ledger_path: str,
                 price: Callable[[str, str], int], handler: Callable, billing: str = "postpay",
                 close_fee: int = 600, close_margin: int = 144, policy: FundingPolicy = None,
                 charge: Callable = None, hrp: str = "bcrt", height_ttl: float = 2.0, claim_fee: int = 300,
                 max_body: int = MAX_BODY, route_max_body: Dict[str, int] = None, settle_multiple: int = 20,
                 close_fee_payer: str = "payer", route_close_fee_payer: str = "payee", rollover_grace: int = 36):
        if billing not in ("postpay", "prepay"):
            raise ValueError("billing is postpay or prepay")
        if close_fee_payer not in FEE_PAYERS or route_close_fee_payer not in FEE_PAYERS:
            raise ValueError("close fee payer is payer or payee")
        if int(max_body) < 1:
            raise ValueError("max_body must be >= 1")
        self.rpc, self.secret, self.network = rpc, pay_to_secret, network
        self.pay_to = ecc.pubkey(pay_to_secret).hex()
        self._pay_to_bytes = bytes.fromhex(self.pay_to)
        self._payees: Dict[str, Payee] = {}     # per channel: its secret and params, derived once (L13)
        self.ledger, self.price, self.handler, self.charge = Ledger(ledger_path), price, handler, charge
        self.billing, self.close_fee, self.close_margin, self.hrp = billing, close_fee, close_margin, hrp
        # v1.2 closeFeePayer: plain channels keep payer-pays (v1.1) unless configured; channels a hub
        # funds to this provider (routed ch2) default to payee-pays (Mike, 2026-09-28): the provider
        # pays its own settlement, so settle_due counts it against the net payout
        self.close_fee_payer, self.route_close_fee_payer = close_fee_payer, route_close_fee_payer
        self.rollover_grace = int(rollover_grace)   # blocks before the close margin a rollover is due anyway
        self.claim_fee = claim_fee      # sats the hash-lock claim pays out of condAmount (M6)
        self.policy = policy or FundingPolicy(min_expiry_blocks=1_008, close_margin=close_margin)
        self._height, self._height_at, self.height_ttl = 0, 0.0, height_ttl
        self._auth_keys: Dict[str, bytes] = {}
        self.max_body = int(max_body)
        self.route_max_body = dict(route_max_body or {})
        # AGP-021 hub routing: routed paths, their sessions and the adaptor-locked ch2 states
        from .route import RouteSeller
        self.settle_multiple = int(settle_multiple)   # settle once the net payout >= this x closeFee (settle_due)
        self.routes = RouteSeller(self, (ledger_path[:-5] if ledger_path.endswith(".json") else ledger_path)
                                  + ".routes.json")

    def offer_route(self, path: str, window: float = 1.0, lock_wait: float = 2.0, invoice_ttl: float = 15.0,
                    hubs="any", amsat_per_call: int = 0, unit: str = "call", credit_msat: int = 0,
                    charge: Callable = None):
        """Sell `path` through hubs (AGP-021). Its 402 carries `extra.route`: the signed price quote and,
        for a client that names its route key (ROUTE-CLIENT header), a session with a fresh lock point
        T per window, signed by payTo. Calls carry ROUTE-AUTH and are metered in amsat
        (`amsat_per_call`, or `charge(method, path, status, body) -> amsat`); each window's accrued
        amount is paid by one adaptor-locked ch2 state from a hub. A session is served while its
        unpaid charges are younger than `window + lock_wait` (the lock wait is configurable)."""
        o = self.routes.offer(path, window=window, lock_wait=lock_wait, invoice_ttl=invoice_ttl, hubs=hubs,
                              amsat_per_call=amsat_per_call, unit=unit, credit_msat=credit_msat)
        o.charge = charge
        return o

    def terms(self) -> dict:
        """GET /x402/xbt-channel/terms: the requirements a hub needs to open (and roll over) a
        hub-funded channel to this provider without a paid call first."""
        req = self.requirements(0)
        req["extra"]["settleMultiple"] = self.settle_multiple
        req["extra"]["closeFeePayer"] = self.route_close_fee_payer    # for hub-funded channels (v1.2)
        req["extra"]["rolloverGraceBlocks"] = self.rollover_grace
        req["extra"]["routes"] = sorted(self.routes.offers)
        return req

    def body_limit(self, path: str, max_body: int = None) -> int:
        """Request-body bound for this path. `max_body` (serve kwarg) wins, then a route option,
        then the provider default (MAX_BODY = 1 MiB). ASGI and http.server both call this."""
        if max_body is not None:
            n = int(max_body)
            if n < 1:
                raise ValueError("max_body must be >= 1")
            return n
        key = path.split("?", 1)[0]
        if key in self.route_max_body:
            return int(self.route_max_body[key])
        return self.max_body

    def height(self) -> int:
        """Chain tip, cached for height_ttl seconds so a paid call costs no RPC."""
        if time.time() - self._height_at > self.height_ttl:
            self._height, self._height_at = self.rpc.getblockcount(), time.time()
        return self._height

    def requirements(self, price: int) -> dict:
        p = self.policy
        return {"scheme": SCHEME, "network": self.network, "amount": str(price), "asset": "XBT:sat",
                "payTo": self.pay_to, "maxTimeoutSeconds": 30,
                "extra": {"minCapacity": str(p.min_capacity), "maxCapacity": str(p.max_capacity),
                          "minExpiryBlocks": p.min_expiry_blocks, "maxExpiryBlocks": p.max_expiry_blocks,
                          "closeMarginBlocks": self.close_margin, "minConf": p.min_conf,
                          "closeFeeSat": str(self.close_fee), "openUrl": "/x402/xbt-channel/open",
                          "closeUrl": "/x402/xbt-channel/close", "billing": self.billing,
                          "derivation": DERIVATION,
                          # v1.2: absent means payer-pays, so a v1.1 payer's 402 is unchanged
                          **({"closeFeePayer": self.close_fee_payer} if self.close_fee_payer != "payer" else {})}}

    def _payment_required(self, url: str, price: int, error: str, st: ChannelState = None):
        body = {"x402Version": 2, "error": error, "resource": {"url": url}, "accepts": [self.requirements(price)]}
        if st:
            body["channel"] = {"chan": st.params.channel_id, "cum": str(st.best_cum), "seq": st.seq,
                               "spentMsat": str(st.spent_msat)}
        return 402, {"PAYMENT-REQUIRED": b64json(body), "Content-Type": "application/json"}, json.dumps(body).encode()

    # control endpoints ------------------------------------------------------------------
    def open(self, req: dict) -> dict:
        if req.get("network") != self.network:
            raise ChannelError("wrong_network", f"this provider is on {self.network}")
        c = req["channel"]
        payer_pub = bytes.fromhex(c["payerPub"])
        ecc._decode_pub(payer_pub)
        payer_spk = check_payout_spk(c["payerSpk"]) if c.get("payerSpk") else ""
        # v1.2 closeFeePayer: payer-pays (v1.1, the default) is always accepted, since it only costs the
        # payer; payee-pays only where this provider offered it (hub-bound channels: /terms; plain
        # channels: its 402). The funding script does not depend on it, so it is fixed here, at open,
        # and every state both sides build from these params carries it.
        fee_payer = c.get("closeFeePayer", "payer")
        offered = self.route_close_fee_payer if req.get("hub") else self.close_fee_payer
        if fee_payer not in ("payer", offered):
            raise ChannelError("bad_fee_payer", f"closeFeePayer {fee_payer!r} not offered for this channel")
        # v1.1 derivation only: a redeemScript built with the v1.0 tweak (no network) fails here
        p = ChannelParams.derive(self.pay_to, payer_pub.hex(), int(c["expiry"]), self.close_fee, payer_spk,
                                 network=self.network, close_fee_payer=fee_payer)
        if c["redeemScript"].lower() != p.script.hex():
            raise ChannelError("bad_funding", "redeemScript does not match payTo/payerPub/expiry")
        chan = canonical_chan(f"{c['txid']}:{int(c['vout'])}")
        p.funding_txid, p.funding_vout, p.capacity = chan.split(":")[0], int(c["vout"]), int(c["capacity"])
        hub = ""
        if req.get("hub"):
            # a hub-funded routing channel (AGP-021): the hub's payTo signs the channel id, and only
            # locks relayed for that hub are completed on this channel
            from .route import hub_channel_message
            hub = str(req["hub"].get("payTo", ""))
            if not ecc.verify(bytes.fromhex(hub), hub_channel_message(p.channel_id), bytes.fromhex(req["hub"]["sig"])):
                raise ChannelError("bad_sig", "hub binding not signed by the hub's payTo")
        with self.ledger.lock:
            if p.channel_id in self.ledger.channels:
                raise ChannelError("duplicate_channel")
            confs = check_funding(self.rpc, p, self.policy)
            st = self.ledger.channels[p.channel_id] = ChannelState(p)
            if hub:
                st.extra = {"hub": hub}
            self.ledger.save(st)
        out = {"chan": p.channel_id, "expiry": p.expiry, "maxCum": str(p.max_amount), "confirmations": confs}
        if p.close_fee_payer != "payer":
            out.update(closeFeePayer=p.close_fee_payer, minCum=str(p.min_amount))
        return out

    def settle_due(self, p: ChannelParams, cum: int, tip: int = None, margin: int = 0) -> bool:
        """This provider's settlement policy (cmp CONTRACT "Settlement policy", AGP-023): settle once
        the net payout of the state for `cum` (what the payee's output holds after any close fee it
        pays) is at least settle_multiple x closeFee, so fees stay <= 1/settle_multiple of the payout;
        or when the channel is within `margin` blocks of its close margin (at tip)."""
        if settle_due(p, cum, self.settle_multiple):
            return True
        return tip is not None and tip >= p.expiry - self.close_margin - margin

    def _chan_secret(self, p: ChannelParams) -> int:
        """The channel payee secret p = payTo_secret + t, t committing to this provider's network (M2).
        It never leaves the provider: one leaked p gives payTo_secret."""
        return self._channel_payee(p).secret

    def _channel_payee(self, p: ChannelParams) -> Payee:
        """The channel's Payee with no state, derived once per channel and then only read (its
        verify_state is pure), so a signature check needs neither the ledger lock nor the two EC
        multiplications the derivation costs (L13)."""
        payee = self._payees.get(p.channel_id)
        if payee is None:
            payee = Payee(p, channel_payee_secret(self.network, self.secret, bytes.fromhex(p.payer_pub),
                                                  p.expiry, pay_to=self._pay_to_bytes))
            self._payees[p.channel_id] = payee
        return payee

    def _payee(self, st: ChannelState) -> Payee:
        payee = copy.copy(self._channel_payee(st.params))
        payee.best_amount, payee.best_sig = st.best_cum, bytes.fromhex(st.best_sig) if st.best_sig else b""
        return payee

    def _channel(self, chan) -> ChannelState:
        with self.ledger.lock:
            st = self.ledger.channels.get(canonical_chan(chan))
        if not st:
            raise ChannelError("unknown_channel")
        return st

    def _authentic(self, st: ChannelState, pl: dict, method: str, path: str, body: bytes) -> bool:
        """payload.auth is the channel's HMAC over this request and a seq above every earlier one."""
        try:
            seq = int(pl["seq"])
        except (KeyError, TypeError, ValueError):
            return False
        if seq <= st.seq:
            return False
        cid = st.params.channel_id
        if cid not in self._auth_keys:
            p = st.params
            self._auth_keys[cid] = channel_auth_key(
                self._chan_secret(p), bytes.fromhex(p.payer_pub))
        want = request_auth(self._auth_keys[cid], cid, seq, pl.get("cum"), pl.get("sig"),
                            request_digest(method, path, body))
        return hmac.compare_digest(want, str(pl.get("auth", "")))

    def _apply(self, st: ChannelState, pl: dict):
        """O(1) per call: at most one ECDSA verify and a few comparisons. Never touches seq: only an
        authenticated paid request moves it (serve)."""
        cum = int(pl["cum"])
        if cum > st.best_cum:
            if "sig" not in pl:
                raise ChannelError("bad_sig", "a higher cum needs a signature")
            payee = self._payee(st)
            sig = bytes.fromhex(pl["sig"])
            payee.accept(cum, sig)
            st.best_cum, st.best_sig = cum, sig.hex()
        elif cum < st.best_cum:
            raise ChannelError("stale_amount", f"have {st.best_cum}, got {cum}")
        elif pl.get("sig") and bytes.fromhex(pl["sig"]) != bytes.fromhex(st.best_sig or ""):
            raise ChannelError("bad_sig", "signature differs from the stored state for this cum")

    def close(self, req: dict) -> dict:
        st = self._channel(req["chan"])
        # unauthenticated until this check passes: it runs outside the ledger lock (L13)
        if not ecc.verify(bytes.fromhex(st.params.payer_pub), close_message(st.params.channel_id),
                          bytes.fromhex(req["sig"])):
            raise ChannelError("bad_sig", "close request not signed by the payer")
        with self.ledger.lock:
            if req.get("payload") and not st.closed_txid:   # after the close a state changes nothing (L10)
                self._apply(st, req["payload"])
            txid = self._close_locked(st)
            report = self._close_report(st)
        return {"chan": st.params.channel_id, "txid": txid, **report}

    # hash-locked conditional state (XBT-061 M6) ---------------------------------------------
    def _cond_state(self, st: ChannelState):
        """The stored conditional state as (ConditionalParams, uncond, k), or None."""
        c = (st.extra or {}).get("cond")
        if not (st.cond_sig and c):
            return None
        from .conditional import ConditionalParams
        return (ConditionalParams(st.params, bytes.fromhex(st.cond_hash), st.cond_amount, int(c["csv"])),
                int(c["uncond"]), bytes.fromhex(c["k"]))

    def _cond_value(self, st: ChannelState) -> int:
        """What closing with the conditional state is worth to the payee after it claims the hash
        lock with k (0 if there is none or the claim would leave dust)."""
        cond = self._cond_state(st)
        if not cond or cond[0].cond_amount - self.claim_fee < DUST:
            return 0
        return cond[1] + cond[0].cond_amount - self.claim_fee

    def _cond_outstanding(self, st: ChannelState) -> bool:
        """A conditional increment the payer has not yet folded into a plain 0x21 state."""
        cond = self._cond_state(st)
        return bool(cond) and st.best_cum < cond[1] + cond[0].cond_amount

    def _close_tx(self, st: ChannelState):
        """The payee's best close: the conditional state when it pays more than the best plain state
        (the payer took the deliverable and never signed the upgrade), else the best plain state."""
        if self._cond_value(st) > st.best_cum:
            cp, uncond, _ = self._cond_state(st)
            tx = cp.state_tx(uncond)
            payee = self._chan_secret(st.params)
            mine = ecc.sign(payee, cp.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
            tx.inputs[0].witness = [bytes.fromhex(st.cond_sig), mine, b"\x01", st.params.script]
            return tx, True
        return self._payee(st).close_tx(), False

    def _claim_tx(self, st: ChannelState, fee: int):
        """Spend the hash-lock output of a conditional close with k, to the channel payee key. Must
        confirm before csvDelta blocks after the close, when the payer's refund branch opens."""
        from .tx import Tx
        cp, _, k = self._cond_state(st)
        close = Tx.parse(bytes.fromhex(st.extra["close_hex"]))
        vout = next(i for i, o in enumerate(close.outputs) if o.script_pubkey == cp.spk)
        payee = self._chan_secret(st.params)
        return cp.claim_tx(st.closed_txid, vout, k, payee, bytes.fromhex(st.params.payee_spk), fee), vout

    def _claim(self, st: ChannelState):
        """Broadcast the hash-lock claim unless the output is already spent. Idempotent: the watcher
        calls it every tick until the claim confirms. While the claim waits in the mempool and the
        close gets buried, its fee doubles per block of the close's depth (capped above dust) and it
        is replaced: at csvDelta the payer's branch opens and could outbid a stuck claim (L8)."""
        fee = int(st.extra.get("claim_fee", self.claim_fee))
        tx, vout = self._claim_tx(st, fee)
        if self.rpc.gettxout(st.closed_txid, vout, True) is None:      # spent, in a block or the mempool
            chain = self.rpc.gettxout(st.closed_txid, vout, False)
            if chain is None:                  # the claim confirmed (or the close has not yet)
                return
            depth = min(int(chain.get("confirmations", 0)), 32)
            bumped = min(self.claim_fee << depth, self._cond_state(st)[0].cond_amount - DUST)
            if bumped <= fee:
                return
            fee = bumped
            tx, _ = self._claim_tx(st, fee)
        try:
            st.extra["claim_txid"] = self.rpc.sendrawtransaction(tx.hex())
            st.extra["claim_fee"] = fee
        except Exception as e:  # noqa: BLE001 - e.g. the close itself is not relayed yet: retry
            raise ChannelError("claim_failed", str(e))

    def _tx_known(self, txid: str, tx) -> bool:
        """The node has `tx`: in its mempool (or txindex), or with an output still unspent."""
        try:
            if self.rpc.getrawtransaction(txid):
                return True
        except Exception:  # noqa: BLE001 - "No such mempool or blockchain transaction"
            pass
        return any(self.rpc.gettxout(txid, n, True) is not None for n in range(len(tx.outputs)))

    def _close_locked(self, st: ChannelState) -> str:
        if not st.closed_txid:
            tx, conditional = self._close_tx(st)
            txid = tx.txid()
            # write-ahead (M8): a close the node took but we never recorded (lost RPC answer, crash
            # before the save) would never be claimed, and once it confirms no re-send is accepted
            st.extra = {**(st.extra or {}), "close_intent": {"hex": tx.hex(), "txid": txid, "cond": conditional}}
            self.ledger.save(st)
            try:
                self.rpc.sendrawtransaction(tx.hex())
            except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                if not self._tx_known(txid, tx):
                    raise ChannelError("close_failed", str(e))
            self._closed(st, tx.hex(), txid, conditional)
        return st.closed_txid

    def _closed(self, st: ChannelState, close_hex: str, txid: str, conditional: bool):
        """Record the close the node has, then claim the hash lock of a conditional one."""
        from .tx import Tx
        st.closed_txid = txid
        mine = {st.params.payee_spk} | ({self._cond_state(st)[0].spk.hex()} if conditional else set())
        paid = sum(o.value for o in Tx.parse(bytes.fromhex(close_hex)).outputs if o.script_pubkey.hex() in mine)
        # the exact close sent: a later (higher) state must not change what the watcher rebroadcasts,
        # nor what close and /x402/settle report (L10)
        st.extra = {**(st.extra or {}), "close_hex": close_hex, "cond_close": conditional, "close_paid": paid}
        self.ledger.save(st)
        if conditional:
            try:
                self._claim(st)
            except ChannelError as e:     # the watcher retries every tick
                st.close_error = str(e)
            self.ledger.save(st)

    def _watch_one(self, st: ChannelState, h: int, out: list):
        p = st.params
        if st.closed_txid:
            # funding still unspent even counting the mempool: the close was evicted, send it again
            if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is not None:
                self.rpc.sendrawtransaction(st.extra.get("close_hex") or self._close_tx(st)[0].hex())
            if st.extra.get("cond_close"):
                self._claim(st)           # the hash lock is ours only until csvDelta: retry every tick
            return
        intent = (st.extra or {}).get("close_intent")
        if intent:
            from .tx import Tx
            if self._tx_known(intent["txid"], Tx.parse(bytes.fromhex(intent["hex"]))):
                self._closed(st, intent["hex"], intent["txid"], intent["cond"])   # sent, never recorded (M8)
                out.append(st.closed_txid)
                if intent["cond"]:
                    self._claim(st)
                return
        utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
        st.suspended = utxo is None or utxo.get("confirmations", 0) < self.policy.conf_for(p.capacity)
        if (st.best_sig or st.cond_sig) and h >= p.expiry - self.close_margin:
            out.append(self._close_locked(st))
            if st.extra.get("cond_close"):
                self._claim(st)           # raises (recorded in close_error) if the claim did not go out

    def close_due(self) -> list:
        """Watcher tick (every block), channel by channel so that one failing channel never stops
        the rest: suspend channels whose funding left the chain, close channels that reached
        expiry - closeMarginBlocks, rebroadcast closes that fell out of the mempool."""
        h, out = self.rpc.getblockcount(), []
        with self.ledger.lock:
            for st in list(self.ledger.channels.values()):
                try:
                    self._watch_one(st, h, out)
                    st.close_error = ""
                except Exception as e:  # noqa: BLE001 - isolate every channel
                    st.close_error = str(e) if isinstance(e, ChannelError) else f"{type(e).__name__}: {e}"
                    sys.stderr.write(f"xbt402 watcher: {st.params.channel_id}: {st.close_error}\n")
            self.ledger.save()
        return out

    def watch(self, interval: float = 30.0, cpfp_fee: int = 0):
        """Start a watcher.Watcher on this provider (a daemon thread that never dies on an error):
        without one every payer's refund beats the provider's close."""
        from .watcher import Watcher
        w = Watcher(self, interval=interval, cpfp_fee=cpfp_fee)
        w.start()
        return w

    def cpfp(self, close_txid: str, fee: int) -> str:
        from .watcher import cpfp_from_close
        with self.ledger.lock:
            st = next((s for s in self.ledger.channels.values() if s.closed_txid == close_txid), None)
            if not st:
                raise ChannelError("unknown_channel", "no channel closed with that txid")
            secret = self._chan_secret(st.params)
            close_hex = (st.extra or {}).get("close_hex")
        return cpfp_from_close(self.rpc, close_txid, st.params.payee_spk, secret, fee, close_hex=close_hex)

    def sweep_payee(self, chan: str, dest_spk: bytes, fee: int) -> dict:
        """Move this channel's payee close output, P2WPKH(P) with p = payTo_secret + t, to
        `dest_spk` (witness v0 only: P2WPKH or P2WSH), signed SIGHASH_ALL|UNIFIED (0x21). p is used
        here and never returned or written anywhere. Reads the close from the ledger (the exact close
        hex this provider sent), so it needs no txindex. Idempotent: a sweep already made is returned."""
        from .channel import sign_p2wpkh
        from .tx import Tx, TxIn, TxOut
        dest_spk = bytes(dest_spk)
        if not (len(dest_spk) in (22, 34) and dest_spk[0] == 0 and dest_spk[1] == len(dest_spk) - 2):
            raise ChannelError("bad_dest", "sweep destination must be a witness v0 script (P2WPKH or P2WSH)")
        with self.ledger.lock:
            st = self.ledger.channels.get(canonical_chan(chan))
            if not st:
                raise ChannelError("unknown_channel")
            done = (st.extra or {}).get("payee_sweep")
            if done:
                return {**done, "already": True}
            if not st.closed_txid or not (st.extra or {}).get("close_hex"):
                raise ChannelError("not_closed", "the channel has no recorded close to sweep")
            close = Tx.parse(bytes.fromhex(st.extra["close_hex"]))
            payee_spk = bytes.fromhex(st.params.payee_spk)
            vout = next((n for n, o in enumerate(close.outputs) if o.script_pubkey == payee_spk), None)
            if vout is None:
                raise ChannelError("no_payee_output", "the close pays nothing to the payee key")
            value = close.outputs[vout].value
            if value - int(fee) < DUST:
                raise ChannelError("bad_amount", f"fee {fee} leaves dust from {value}")
            if self.rpc.gettxout(st.closed_txid, vout, True) is None:
                raise ChannelError("payee_spent", "the payee output is spent or its close is not on this node")
            tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(st.closed_txid)[::-1], vout, 0xFFFFFFFD)],
                    outputs=[TxOut(value - int(fee), dest_spk)], locktime=0)
            sign_p2wpkh(self._chan_secret(st.params), tx, [TxOut(value, payee_spk)])
            txid = tx.txid()
            rec = {"txid": txid, "outpoint": f"{st.closed_txid}:{vout}", "value": value, "fee": int(fee),
                   "swept": value - int(fee), "dest_spk": dest_spk.hex()}
            st.extra = {**st.extra, "payee_sweep_intent": {**rec, "hex": tx.hex()}}   # write-ahead (M8)
            self.ledger.save(st)
            try:
                self.rpc.sendrawtransaction(tx.hex())
            except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                if not self._tx_known(txid, tx):
                    raise ChannelError("sweep_failed", str(e))
            st.extra = {**st.extra, "payee_sweep": rec}
            self.ledger.save(st)
            return rec

    def supported(self) -> dict:
        return {"kinds": [{"x402Version": 2, "scheme": SCHEME, "network": self.network}],
                "extensions": [], "signers": {}}

    def _facilitator_payload(self, req: dict) -> dict:
        """The scheme payload of an x402 v2 facilitator body, once both the requirements and the
        payload's `accepted` name this scheme, network and payTo."""
        if not isinstance(req, dict) or req.get("x402Version") != 2:
            raise ChannelError("bad_payload", "x402Version 2 facilitator body expected")
        pp, want = req.get("paymentPayload"), req.get("paymentRequirements")
        if not (isinstance(pp, dict) and isinstance(want, dict) and isinstance(pp.get("accepted"), dict)
                and isinstance(pp.get("payload"), dict)) or pp.get("x402Version") != 2:
            raise ChannelError("bad_payload", "paymentPayload {x402Version, accepted, payload} and "
                                              "paymentRequirements expected")
        for acc in (want, pp["accepted"]):
            if acc.get("scheme") != SCHEME or acc.get("network") != self.network or acc.get("payTo") != self.pay_to:
                raise ChannelError("unsupported_scheme_or_network")
        return pp["payload"]

    def facilitator_verify(self, req: dict) -> dict:
        """x402 VerifyResponse for a signed state, kept if higher. Unauthenticated, so it needs a payer
        signature for exactly the cum it names, reports nothing the caller did not send, and never
        moves seq: otherwise it would tell anyone a channel's cum, or let them lock the payer out with
        a huge seq."""
        try:
            pl = self._facilitator_payload(req)
            st = self._channel(pl.get("chan"))
            cum = int(pl["cum"])
            if not pl.get("sig"):
                raise ChannelError("bad_sig", "verify needs a signed state")
            # anyone can call this: the signature check, all a stranger can make us compute, runs
            # outside the ledger lock against the channel's cached payee, so a flood of junk states
            # never queues paid calls behind it (L13)
            self._channel_payee(st.params).verify_state(cum, bytes.fromhex(pl["sig"]))
            with self.ledger.lock:
                if cum > st.best_cum and not st.closed_txid:
                    st.best_cum, st.best_sig = cum, pl["sig"]
                    self.ledger.save(st)
                # a VerifyResponse is what a resource server serves on: never isValid for a state this
                # channel can no longer settle (L11). A higher state is still kept while closing.
                if st.closed_txid or self.height() >= st.params.expiry - self.close_margin:
                    raise ChannelError("channel_closing")
                if st.suspended:
                    raise ChannelError("unconfirmed")
        except (ChannelError, KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
            return {"isValid": False, "invalidReason": upstream_code(getattr(e, "code", "bad_payload"))}
        return {"isValid": True, "payer": st.params.payer_pub, "extra": {"chan": st.params.channel_id, "cum": str(cum)}}

    def _close_paid(self, st: ChannelState) -> int:
        """Sat the payer paid by the recorded close: its gross state (a conditional close: uncond +
        condAmount, before the claim fee). Under v1.2 payee-pays the provider's outputs hold this less
        payeeFee (AGP-029): the fee is the provider's cost, never an amount the payer still owes."""
        if "close_paid" in (st.extra or {}):      # the provider's outputs of the close actually sent
            return int(st.extra["close_paid"]) + st.params.payee_fee
        cond = self._cond_state(st) if (st.extra or {}).get("cond_close") else None
        return cond[1] + cond[0].cond_amount if cond else st.best_cum

    def _close_report(self, st: ChannelState) -> dict:
        """The close answer's amounts: `cum` gross and `unpaidMsat` = spent - gross. A payee-pays
        channel adds `payeeFee` and `payeeNet` (what the provider's outputs hold); a payer-pays (v1.1)
        answer is unchanged byte for byte."""
        paid = self._close_paid(st)
        out = {"cum": str(paid), "unpaidMsat": str(max(0, st.spent_msat - paid * 1000))}
        if st.params.payee_fee:
            out.update(payeeFee=str(st.params.payee_fee), payeeNet=str(max(0, paid - st.params.payee_fee)))
        return out

    def facilitator_settle(self, req: dict) -> dict:
        """x402 SettlementResponse for a close request ({chan, sig, payload?}, as extra.closeUrl takes)."""
        try:
            r = self.close(self._facilitator_payload(req))
            with self.ledger.lock:
                st = self.ledger.channels[r["chan"]]
                payer = st.params.payer_pub
        except (ChannelError, KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
            return {"success": False, "errorReason": upstream_code(getattr(e, "code", "bad_payload")),
                    "transaction": "", "network": self.network}
        extra = {"chan": r["chan"], "unpaidMsat": r["unpaidMsat"]}
        if "payeeFee" in r:
            extra.update(payeeFee=r["payeeFee"], payeeNet=r["payeeNet"])
        return {"success": True, "transaction": r["txid"], "network": self.network, "payer": payer,
                "amount": r["cum"], "extra": extra}

    def rollover(self, req: dict) -> dict:
        """POST /x402/xbt-channel/rollover (AGP-021): co-sign and broadcast the payer's rollover of a
        channel, one tx that pays this provider `amount` (at least its best state) and funds the next
        channel with the rest less the close fee (ChannelParams.rollover_tx). The payer's signature
        over that exact tx is the authorisation. The next channel opens through extra.openUrl once it
        confirms."""
        st = self._channel(req["chan"])
        p = st.params
        amount, nxt = int(req["amount"]), req["next"]
        payer_pub = bytes.fromhex(nxt["payerPub"])
        ecc._decode_pub(payer_pub)
        expiry = int(nxt["expiry"])
        h = self.height()
        if not h + self.policy.min_expiry_blocks <= expiry <= h + self.policy.max_expiry_blocks:
            raise ChannelError("bad_expiry", "next channel expiry outside this provider's policy")
        payer_spk = check_payout_spk(nxt["payerSpk"]) if nxt.get("payerSpk") else ""
        nparams = ChannelParams.derive(self.pay_to, payer_pub.hex(), expiry, p.close_fee, payer_spk,
                                       network=self.network, close_fee_payer=p.close_fee_payer)
        next_cap = p.rollover_next_capacity(amount)
        if next_cap < self.policy.min_capacity:
            raise ChannelError("bad_amount", "rollover leaves less than the minimum channel capacity")
        # payee-pays: this settlement's fee is ours, so we co-sign only when our policy says it is worth
        # it (net payout >= settleMultiple x closeFee) or the channel nears its close margin. A payer
        # rolling early and often would otherwise make us pay a close fee per small payout.
        if p.payee_fee and not self.settle_due(p, amount, h, margin=self.rollover_grace):
            raise ChannelError("settle_early", f"net payout {p.payee_value(amount)} < {self.settle_multiple} x "
                                               f"closeFee {p.close_fee}, and the channel is not near its margin")
        tx = p.rollover_tx(amount, nparams.spk, next_cap)
        sig = bytes.fromhex(req["sig"])
        digest = p.sighash(tx)
        if not sig or sig[-1] != SIGHASH_ALL_UNIFIED or not ecc.verify(bytes.fromhex(p.payer_pub), digest, sig[:-1]):
            raise ChannelError("bad_sig", "payer signature does not verify for this rollover")
        tx.inputs[0].witness = [sig, ecc.sign(self._chan_secret(p), digest) + bytes([SIGHASH_ALL_UNIFIED]),
                                b"\x01", p.script]
        with self.ledger.lock:
            if st.closed_txid:
                raise ChannelError("channel_closing", "already settled")
            if amount < st.best_cum:
                raise ChannelError("bad_amount", f"a rollover pays at least the best state {st.best_cum}")
            txid = tx.txid()
            st.extra = {**(st.extra or {}), "close_intent": {"hex": tx.hex(), "txid": txid, "cond": False}}
            self.ledger.save(st)
            try:
                self.rpc.sendrawtransaction(tx.hex())
            except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                if not self._tx_known(txid, tx):
                    raise ChannelError("close_failed", str(e))
            self._closed(st, tx.hex(), txid, False)
            st.extra = {**st.extra, "rollover_to": f"{txid}:1"}
            self.ledger.save(st)
        return {"chan": p.channel_id, "txid": txid, "amount": amount, "nextChan": f"{txid}:1",
                "nextCapacity": next_cap}

    def _route_lock(self, method: str, path: str, headers: dict, body: bytes):
        """POST /x402/xbt-channel/lock: a hub's adaptor-locked state on its ch2 to us. Authenticated
        like a paid call (the hub's channel HMAC covers the JSON body with the route terms)."""
        def err(code, detail="", status=400):
            return status, {"Content-Type": "application/json"}, json.dumps({"error": code, "detail": detail}).encode()
        hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
        try:
            pl = unb64json(hdr)["payload"]
            route = json.loads(body)["route"]
            if not isinstance(pl, dict) or not isinstance(route, dict):
                raise TypeError("objects expected")
        except (ValueError, KeyError, TypeError, AttributeError):
            return err("bad_payload")
        with self.ledger.lock:
            try:
                st = self.ledger.channels.get(canonical_chan(pl.get("chan")))
            except ChannelError:
                st = None
            if not st:
                return err("unknown_channel")
            if not self._authentic(st, pl, method, path, body):
                return err("bad_auth", status=401)
            st.seq = int(pl["seq"])
            if st.closed_txid or self.height() >= st.params.expiry - self.close_margin:
                return err("channel_closing")
            if st.suspended:
                return err("unconfirmed")
            try:
                out = self.routes.complete_lock(st, pl, route)
            except ChannelError as e:
                self.ledger.save(st)
                return err(e.code, str(e))
        return (202 if "held" in out else 200), {"Content-Type": "application/json"}, json.dumps(out).encode()

    def _routed_call(self, method: str, path: str, path_key: str, hdr: str, body: bytes, url: str):
        from .route import AMSAT_PER_MSAT  # noqa: F401
        o = self.routes.offers[path_key]
        s, error = self.routes.begin_call(path_key, hdr, method, path, body)
        if error:
            st, h, b = self._payment_required(url, self.price(method, path), error)
            doc = json.loads(b)
            doc["accepts"][0]["extra"]["route"] = self.routes.route_extra(path_key)
            if s is not None:
                with self.routes.lock:
                    doc["routeState"] = self.routes.state(s)
            h["PAYMENT-REQUIRED"] = b64json(doc)
            return 402, h, json.dumps(doc).encode()
        status, hdrs, out = self.handler(method, path, body)
        if unsafe_headers(hdrs):
            status, hdrs, out = 500, {}, b"handler returned a header with CR/LF"
        charge = int(o.amsat_per_call)
        if getattr(o, "charge", None):
            charge = int(o.charge(method, path, status, out))
        if status >= 500:
            charge = 0
        state = self.routes.end_call(s, max(0, charge))
        hdrs = dict(hdrs)
        hdrs["ROUTE-STATE"] = b64json(state)
        return status, hdrs, out

    def offer_conditional(self, path: str, price: int, plaintext: bytes, k: bytes = None):
        """Prepare a hash-locked deliverable for `path`. Returns (H, ciphertext, k). The 402 carries
        H and the ciphertext; each sale reveals k (to the payer, and on-chain if claimed), so after a
        sale the path is offered again under a fresh k. `k` fixes the first key (test vectors only:
        a k already revealed decrypts this ciphertext for anyone)."""
        k = k or os.urandom(32)
        from .conditional import encrypt, sha256
        h = sha256(k)
        self._cond = getattr(self, "_cond", {})
        self._cond[path] = {"k": k, "h": h, "price": price, "cipher": encrypt(plaintext, k),
                            "plain": plaintext}
        return h, self._cond[path]["cipher"], k

    # paid requests ----------------------------------------------------------------------
    def serve(self, method: str, path: str, headers: dict, body: bytes, url: str = "", max_body: int = None):
        # body bound before any billing: a too-large body is an unbilled 400 on every transport
        if len(body or b"") > self.body_limit(path, max_body):
            return 400, {}, b"bad request framing or body over MAX_BODY"
        # facilitator endpoints live under /x402/ only: bare /verify, /settle and /supported shadowed
        # a paid API's own routes of those names (XBT-061 L6)
        control = {("GET", FACILITATOR_SUPPORTED): lambda: self.supported(),
                   ("POST", FACILITATOR_VERIFY): lambda: self.facilitator_verify(json.loads(body)),
                   ("POST", FACILITATOR_SETTLE): lambda: self.facilitator_settle(json.loads(body))}
        if path.split("?", 1)[0] in (FACILITATOR_SUPPORTED, FACILITATOR_VERIFY, FACILITATOR_SETTLE):
            action = control.get((method, path.split("?", 1)[0]))
            if not action:
                return 405, {}, b"method not allowed"
            try:
                return 200, {"Content-Type": "application/json"}, json.dumps(action()).encode()
            except (ChannelError, KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
                return 400, {"Content-Type": "application/json"}, json.dumps(
                    {"error": getattr(e, "code", "bad_request"), "detail": str(e)}).encode()
        if path == "/x402/xbt-channel/lock":
            if method != "POST":
                return 405, {}, b"method not allowed"
            return self._route_lock(method, path, headers, body)
        if path == "/x402/xbt-channel/terms" and method == "GET":
            return 200, {"Content-Type": "application/json"}, json.dumps(self.terms()).encode()
        if path.startswith("/x402/xbt-channel/"):
            action = {"/x402/xbt-channel/open": self.open, "/x402/xbt-channel/close": self.close,
                      "/x402/xbt-channel/rollover": self.rollover}.get(path)
            if not action or method != "POST":
                return 404, {}, b"not found"
            try:
                return 200, {"Content-Type": "application/json"}, json.dumps(action(json.loads(body))).encode()
            except (ChannelError, KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
                return 400, {"Content-Type": "application/json"}, json.dumps(
                    {"error": getattr(e, "code", "bad_request"), "detail": str(e)}).encode()
        url = url or path
        uh = {k.upper(): v for k, v in headers.items()}
        path_key = path.split("?", 1)[0]
        if path_key in self.routes.offers and uh.get("ROUTE-AUTH") and not uh.get("PAYMENT-SIGNATURE"):
            return self._routed_call(method, path, path_key, uh["ROUTE-AUTH"], body, url)
        price = self.price(method, path)
        hdr = uh.get("PAYMENT-SIGNATURE")
        cond_offers = getattr(self, "_cond", {})
        if not hdr and path_key in self.routes.offers:
            status, h, b = self._payment_required(url, price, "payment_required")
            doc = json.loads(b)
            try:
                doc["accepts"][0]["extra"]["route"] = self.routes.route_extra(path_key, uh.get("ROUTE-CLIENT", ""))
            except (ValueError, TypeError):
                return 400, {}, b"bad ROUTE-CLIENT key"
            h["PAYMENT-REQUIRED"] = b64json(doc)
            return 402, h, json.dumps(doc).encode()
        if not hdr:
            status, h, b = self._payment_required(url, price, "payment_required")
            if path_key in cond_offers:
                offer = json.loads(b)
                # the ciphertext goes out before the payer signs: whatever happens to the paid
                # response, the claim that pays us publishes k, so the payer can decrypt (M7)
                offer["accepts"][0]["extra"]["conditional"] = {
                    "hash": cond_offers[path_key]["h"].hex(), "amount": str(cond_offers[path_key]["price"]),
                    "csvDelta": CSV_DELTA, "cipher": cond_offers[path_key]["cipher"].hex(),
                }
                body_out = json.dumps(offer).encode()
                h["PAYMENT-REQUIRED"] = b64json(offer)
                return 402, h, body_out
            return status, h, b
        try:
            pp = unb64json(hdr)
            acc, pl = pp["accepted"], pp["payload"]
            if not isinstance(acc, dict) or not isinstance(pl, dict):
                raise TypeError("accepted and payload are objects")
            if pp.get("x402Version") != 2 or acc.get("scheme") != SCHEME or acc.get("network") != self.network \
                    or acc.get("payTo") != self.pay_to:
                return self._payment_required(url, price, "unsupported_scheme_or_network")
        except (ValueError, KeyError, TypeError):
            return self._payment_required(url, price, "bad_payload")
        with self.ledger.lock:
            try:
                st = self.ledger.channels.get(canonical_chan(pl.get("chan")))
            except ChannelError:
                st = None
            if not st:
                return self._payment_required(url, price, "unknown_channel")
            if not self._authentic(st, pl, method, path, body):   # no channel details for strangers
                return self._payment_required(url, price, "bad_auth")
            st.seq = int(pl["seq"])                               # spent, whatever happens next
            if st.closed_txid or self.height() >= st.params.expiry - self.close_margin:
                return self._payment_required(url, price, "channel_closing", st)
            if st.suspended:
                return self._payment_required(url, price, "unconfirmed", st)
            best = st.best_cum
            try:
                if not pl.get("hashlock"):
                    self._apply(st, pl)
            except (ChannelError, ValueError, TypeError, KeyError) as e:
                return self._payment_required(url, price, getattr(e, "code", "bad_payload"), st)

            def refuse(error):
                if st.best_cum != best:   # a higher state that still does not cover this call: keep it
                    self.ledger.save(st)
                return self._payment_required(url, price, error, st)
            if pl.get("hashlock") and path_key in cond_offers:
                from .conditional import ConditionalParams
                offer = cond_offers[path_key]
                if self._cond_outstanding(st):     # the provider can close with one conditional state
                    return refuse("conditional_outstanding")
                try:
                    if bytes.fromhex(pl["hashlock"]) != offer["h"]:
                        return refuse("bad_hashlock")
                    cond = ConditionalParams(st.params, offer["h"], offer["price"], CSV_DELTA)
                    tx = cond.state_tx(st.best_cum)
                    sig = bytes.fromhex(pl["sig"])
                except (ChannelError, ValueError, TypeError, KeyError) as e:
                    return refuse(getattr(e, "code", "bad_payload"))
                if not sig or sig[-1] != 0x21 or not ecc.verify(bytes.fromhex(st.params.payer_pub),
                                                                cond.sighash(tx), sig[:-1]):
                    return refuse("bad_sig")
                st.cond_hash, st.cond_amount, st.cond_sig = offer["h"].hex(), offer["price"], pl["sig"]
                # enough to close with this state and claim it after a restart (k is revealed below)
                st.extra = {**(st.extra or {}), "cond": {"uncond": st.best_cum, "csv": CSV_DELTA,
                                                         "k": offer["k"].hex()}}
                price = offer["price"]
            else:
                paid = st.best_cum * 1000
                need = st.spent_msat + (price * 1000 if self.billing == "prepay" else 0)
                if paid < need:
                    return refuse("insufficient_payment")
            if st.spent_msat + price * 1000 > st.params.max_amount * 1000:
                return refuse("channel_exhausted")
            st.spent_msat += price * 1000        # reserve the max; refunded below if metered lower
            self.ledger.save(st)
        status, hdrs, out = self.handler(method, path, body)
        if unsafe_headers(hdrs):                 # no header injection, whatever the transport
            status, hdrs, out = 500, {}, b"handler returned a header with CR/LF"
        if path_key in getattr(self, "_cond", {}) and pl.get("hashlock"):
            offer = self._cond[path_key]
            out = json.dumps({"cipher": offer["cipher"].hex(), "preimage": offer["k"].hex(),
                              "hash": offer["h"].hex()}).encode()
            hdrs = {"Content-Type": "application/json"}
            status = 200
            # one k per sale: the ciphertext is public in the 402 and a claim publishes k on-chain, so
            # the next payer must get a new k (M7)
            self.offer_conditional(path_key, offer["price"], offer["plain"])
        charged = price
        if self.charge:
            charged = max(0, min(price, int(self.charge(method, path, status, out))))
        with self.ledger.lock:
            st.spent_msat -= (price - charged) * 1000
            if status >= 500:                   # don't bill failed calls
                st.spent_msat -= charged * 1000
                charged = 0
            if charged != price:
                self.ledger.save(st)
            r = {"scheme": SCHEME, "chan": st.params.channel_id, "seq": st.seq, "cum": str(st.best_cum), "charged": str(charged), "spentMsat": str(st.spent_msat),
                 "owedMsat": str(max(0, st.spent_msat - st.best_cum * 1000)),
                 "creditMsat": str(max(0, st.best_cum * 1000 - st.spent_msat)), "expiry": st.params.expiry,
                 "req": request_digest(method, path, body)}
            secret = self._chan_secret(st.params)
        r["sig"] = ecc.sign(secret, receipt_message(r)).hex()
        hdrs = dict(hdrs)
        hdrs["PAYMENT-RESPONSE"] = b64json(settlement_response(r, self.network, st.params.payer_pub, status < 400))
        return status, hdrs, out

    def http_server(self, port: int) -> ThreadingHTTPServer:
        app = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _refuse(self, status, why):
                self.close_connection = True
                self.send_response(status)
                self.send_header("Content-Length", str(len(why)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(why)

            def _go(self):
                # Content-Length only, bounded: a chunked body read as the next request smuggles one
                # request inside another behind a proxy; a negative or huge length pins a thread
                if self.headers.get("Transfer-Encoding"):
                    return self._refuse(501, b"transfer-encoding not supported")
                cl = self.headers.get_all("Content-Length") or ["0"]
                limit = app.body_limit(self.path)
                if len(cl) != 1 or not cl[0].isdigit() or int(cl[0]) > limit:
                    return self._refuse(413 if cl[0].isdigit() else 400, b"bad content-length")
                if len(self.headers.get_all("PAYMENT-SIGNATURE") or []) > 1:
                    return self._refuse(400, b"duplicate PAYMENT-SIGNATURE")
                status, hdrs, out = app.serve(self.command, self.path, dict(self.headers), self.rfile.read(int(cl[0])),
                                              f"http://{self.headers.get('Host', '')}{self.path}")
                if unsafe_headers(hdrs):
                    return self._refuse(500, b"handler returned a header with CR/LF")
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = _go

            def log_message(self, *a):
                pass

        return ThreadingHTTPServer(("127.0.0.1", port), H)


# --- client SDK -------------------------------------------------------------------------------
@dataclass
class ClientChannel:
    payer: Payer
    origin: str
    accepted: dict
    refund_hex: str = ""
    auth_key: bytes = b""        # without a signer; with one, the signer computes payload.auth
    price: int = 0               # sat per call agreed at open: a 402 may not raise it mid-channel
    slack_msat: int = 0          # charges adopted from a 402 without a receipt, over the channel's life
    seq: int = 0
    spent_msat: int = 0          # from the last verified receipt
    last_sig: str = ""           # our signature for payer.signed, resent until a receipt shows it arrived
    pending_cond: dict = field(default_factory=dict)   # {hash, cipher, amount} of a signed hash lock
    acked_cum: int = 0           # the provider's best cum per its last receipt
    receipts: list = field(default_factory=list)


class XbtChannelClient:
    """Payer SDK. `fund(address, sats) -> (txid, vout)` is the only wallet hook: in production it is
    the B2 agent-wallet MCP (policy-checked, 0x21-signed), so the SDK never holds funding keys.

    When `signer` is set (ChannelSigner / B2 socket), per-channel payer keys live there and this
    object never sees them. `refunds` is optional RefundCustody (broadcast after expiry).
    Budgets: per-call (`max_price`), per-channel (`capacity`), per-day (`daily_budget`).
    """

    def __init__(self, network: str, fund: Callable[[str, int], tuple], height: Callable[[], int],
                 capacity=200_000, expiry_blocks=1_008, max_price=1_000, max_close_fee=2_000,
                 budget_sats=1_000_000, on_open: Callable = None, on_refund: Callable = None,
                 signer=None, refunds: RefundCustody = None, daily_budget=0):
        self.network, self.fund, self.height = network, fund, height
        self.capacity, self.expiry_blocks, self.max_price = capacity, expiry_blocks, max_price
        self.max_close_fee, self.budget_sats = max_close_fee, budget_sats
        self.on_open, self.on_refund = on_open, on_refund
        self.signer, self.refunds = signer, refunds
        self.daily_budget, self.day_spent, self.day_start = daily_budget, 0, time.time()
        self.channels: Dict[str, ClientChannel] = {}
        self.opened_sats = 0

    @staticmethod
    def http(method, url, body=b"", headers=None):
        req = urllib.request.Request(url, body or None, headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, {k.upper(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.upper(): v for k, v in e.headers.items()}, e.read()

    def _post(self, url, obj):
        st, _, out = self.http("POST", url, json.dumps(obj).encode(), {"Content-Type": "application/json"})
        data = json.loads(out)
        if st != 200:
            # the provider's words go in the message, never in the code an agent tool reports (L12)
            code = data.get("error") if isinstance(data, dict) else None
            raise ChannelError(code if safe_code(code) else "provider_error",
                               str(data.get("detail", "") if isinstance(data, dict) else data))
        return data

    def _pick(self, pr: dict) -> dict:
        for acc in pr.get("accepts", []):
            if acc.get("scheme") == SCHEME and acc.get("network") == self.network:
                if int(acc["amount"]) > self.max_price:
                    raise ChannelError("too_expensive", f"{acc['amount']} sat > max {self.max_price}")
                if int(acc["extra"]["closeFeeSat"]) > self.max_close_fee:
                    raise ChannelError("bad_offer", "closeFeeSat above our cap")
                if acc["extra"].get("closeFeePayer", "payer") not in FEE_PAYERS:
                    raise ChannelError("bad_offer", "unknown closeFeePayer")
                if acc["extra"].get("derivation") != DERIVATION:   # before funding: never strand coins
                    raise ChannelError("bad_offer", f"payee key derivation {acc['extra'].get('derivation')!r}, "
                                                    f"this client speaks {DERIVATION!r} (xbt402 v1.1)")
                return acc
        raise ChannelError("no_scheme", f"no {SCHEME} offer on {self.network}")

    def _open(self, origin: str, acc: dict) -> ClientChannel:
        ex = acc["extra"]
        fee_payer = ex.get("closeFeePayer", "payer")
        cap = max(self.capacity, int(ex["minCapacity"]))
        if cap > int(ex.get("maxCapacity", cap)) or self.opened_sats + cap > self.budget_sats:
            raise ChannelError("budget", "channel capacity outside provider range or our budget")
        if self.signer:
            pub = self.signer.new_key(origin)
            secret = None
        else:
            secret = secrets.randbelow(ecc.N - 1) + 1
            pub = ecc.pubkey(secret).hex()
        blocks = min(max(self.expiry_blocks, int(ex["minExpiryBlocks"]) + 6), int(ex["maxExpiryBlocks"]) - 1)
        expiry = self.height() + blocks
        p = ChannelParams.derive(acc["payTo"], pub, expiry, int(ex["closeFeeSat"]), network=self.network,
                                 close_fee_payer=fee_payer)
        fund = self.signer.fund if self.signer and getattr(self.signer, "fund", None) else self.fund
        txid, vout = fund(segwit_address(self.hrp_for(), p.spk), cap)
        p.funding_txid, p.funding_vout, p.capacity = txid, vout, cap
        self.opened_sats += cap
        if self.signer:
            self.signer.attach(origin, p)
            refund_hex = self.signer.sign_refund(p.channel_id)
            payer = Payer(p, backend=self.signer)
        else:
            refund_hex = p.refund_tx(secret).hex()
            payer = Payer(p, secret)
        ch = ClientChannel(payer, origin, acc, refund_hex=refund_hex,
                           auth_key=b"" if self.signer else channel_auth_key(secret, bytes.fromhex(p.payee_pub)))
        if self.refunds:
            self.refunds.add(ch.refund_hex, expiry, p.channel_id)
        ch.price = int(acc["amount"])
        if self.on_refund:
            self.on_refund(ch.refund_hex, expiry)
        if self.on_open:
            self.on_open(ch)
        c = {"txid": txid, "vout": vout, "capacity": cap, "expiry": expiry, "payerPub": p.payer_pub,
             "payerSpk": p.payer_spk, "redeemScript": p.script.hex()}
        if fee_payer != "payer":
            c["closeFeePayer"] = fee_payer
        r = self._post(origin + ex["openUrl"], {"x402Version": 2, "network": self.network, "channel": c})
        if isinstance(r, dict) and r.get("closeFeePayer", "payer") != fee_payer:
            # a provider that did not take our terms would refuse every state we sign: stop before paying
            raise ChannelError("bad_fee_payer", "the provider opened the channel with another closeFeePayer")
        return ch

    def hrp_for(self) -> str:
        return "bc" if self.network == XBT_MAINNET else "bcrt"

    def _auth(self, ch: ClientChannel, pl: dict, method: str, path: str, body: bytes) -> dict:
        """Add payload.auth for this request. With a signer the ECDH key never leaves it."""
        req = request_digest(method, path, body)
        if self.signer:
            pl["auth"] = self.signer.request_auth(pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        else:
            pl["auth"] = request_auth(ch.auth_key, pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        return pl

    def _payload(self, ch: ClientChannel, price: int, method: str = "", path: str = "", body: bytes = b"") -> dict:
        billing = ch.accepted["extra"].get("billing", "postpay")
        need_msat = ch.spent_msat + (price * 1000 if billing == "prepay" else 0)
        cum = max(-(-need_msat // 1000), ch.payer.signed)
        if 0 < cum < ch.payer.params.min_amount:
            cum = ch.payer.params.min_amount
        self._check_daily(cum - ch.payer.signed)
        remaining = ch.payer.params.max_amount - max(ch.payer.signed, ch.spent_msat // 1000)
        if remaining < price and ch.payer.signed:
            self._rollover(ch)
            remaining = ch.payer.params.max_amount - ch.payer.signed
        ch.seq += 1
        pl = {"chan": ch.payer.params.channel_id, "seq": ch.seq, "cum": str(cum)}
        if cum > ch.payer.signed:
            if cum > ch.payer.params.max_amount:
                raise ChannelError("exhausted", "channel capacity used up: close and reopen")
            delta = cum - ch.payer.signed
            pl["sig"] = ch.last_sig = ch.payer.sign_state(cum).hex()
            self.day_spent += max(0, delta)
        elif cum == ch.payer.signed > ch.acked_cum and ch.last_sig:
            pl["sig"] = ch.last_sig        # signed (a conditional upgrade) but not yet seen to arrive
        return self._auth(ch, pl, method, path, body)

    def _check_daily(self, sats: int):
        if self.daily_budget and time.time() - self.day_start > 86400:
            self.day_spent, self.day_start = 0, time.time()
        if self.daily_budget and self.day_spent + sats > self.daily_budget:
            raise ChannelError("budget", "daily budget exhausted")

    def request(self, method: str, url: str, body: bytes = b""):
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        ch = self.channels.get(origin)
        hdrs = {}
        if ch:
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": ch.accepted,
                                                  "payload": self._payload(ch, int(ch.accepted["amount"]),
                                                                          method, path, body)})}
        status, rh, out = self.http(method, url, body, hdrs)
        if status == 402:
            pr = unb64json(rh["PAYMENT-REQUIRED"])
            acc = self._pick(pr)
            if not ch:
                ch = self._open(origin, acc)
                self.channels[origin] = ch
            if ch.price and int(acc["amount"]) > ch.price:
                raise ChannelError("bad_offer", f"price raised mid-channel: {ch.price} -> {acc['amount']} sat")
            ch.accepted = acc
            if "channel" in pr:   # provider's view: at most one unreceipted call over the channel's life
                claimed = int(pr["channel"]["spentMsat"])
                extra = claimed - ch.spent_msat
                if extra > 0 and ch.slack_msat + extra > int(acc["amount"]) * 1000:
                    raise ChannelError("bad_offer", "provider claims charges we have no receipts for")
                ch.slack_msat += max(0, extra)
                ch.spent_msat = max(ch.spent_msat, claimed)
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc,
                                                  "payload": self._payload(ch, int(acc["amount"]), method, path, body)})}
            status, rh, out = self.http(method, url, body, hdrs)
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body)
        return status, rh, out

    def _receipt(self, ch: ClientChannel, resp: dict, method, path, body, quote: int = None):
        """`quote` is what this call may cost: the price pinned at open for a plain call, the
        conditional amount (already checked against max_price) for a conditional one. Never a
        quote the provider can raise afterwards (H6: a `conditional` quote in any 402 lifted the
        cap on plain calls)."""
        quote = quote or ch.price or int(ch.accepted["amount"])
        r = receipt_of(resp)
        if resp.get("network") != self.network or resp.get("payer") != ch.payer.params.payer_pub:
            raise ChannelError("bad_receipt", "PAYMENT-RESPONSE is for another network or payer")
        if r["req"] != request_digest(method, path, body):
            raise ChannelError("bad_receipt", "receipt is for another request")
        if not ecc.verify(bytes.fromhex(ch.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        if int(r["cum"]) > ch.payer.signed or int(r["charged"]) > quote:
            raise ChannelError("bad_receipt", "provider claims more than we signed or were quoted")
        if int(r["spentMsat"]) - ch.spent_msat > quote * 1000:
            raise ChannelError("bad_receipt", "provider charged more than one call")
        ch.spent_msat = int(r["spentMsat"])
        ch.acked_cum = max(ch.acked_cum, int(r["cum"]))
        ch.receipts.append(r)

    def close(self, origin: str) -> dict:
        """Cooperative close; in postpay the final state pays exactly what is owed."""
        ch = self.channels[origin]
        pl = self._payload(ch, 0)
        if self.signer:
            sig = self.signer.sign_close(ch.payer.params.channel_id)
        else:
            sig = ecc.sign(ch.payer.secret, close_message(ch.payer.params.channel_id)).hex()
        return self._post(origin + ch.accepted["extra"]["closeUrl"],
                          {"chan": ch.payer.params.channel_id, "sig": sig, "payload": pl})

    def _rollover(self, ch: ClientChannel):
        """Close whose payer output is the next channel's funding. Needs a live signer or secret."""
        origin, acc, ex = ch.origin, ch.accepted, ch.accepted["extra"]
        owed = max(ch.spent_msat // 1000, ch.payer.signed)
        if owed < ch.payer.params.min_amount:
            owed = ch.payer.params.min_amount
        if self.signer:
            pub = self.signer.new_key(origin + "/next")
        else:
            secret2 = secrets.randbelow(ecc.N - 1) + 1
            pub = ecc.pubkey(secret2).hex()
        expiry = self.height() + min(max(self.expiry_blocks, int(ex["minExpiryBlocks"]) + 6),
                                     int(ex["maxExpiryBlocks"]) - 1)
        nxt = ChannelParams.derive(acc["payTo"], pub, expiry, int(ex["closeFeeSat"]), network=self.network,
                                   close_fee_payer=ch.payer.params.close_fee_payer)
        next_cap = min(self.capacity, ch.payer.params.rollover_next_capacity(owed))
        if next_cap < int(ex["minCapacity"]):
            raise ChannelError("exhausted", "not enough leftover to roll into a new channel")
        tx = ch.payer.params.rollover_tx(owed, nxt.spk, next_cap)
        # Treat rollover as a cooperative close of the old channel, then register the new one
        # after the close confirms. The demo exercises this offline; live path uses close().
        raise ChannelError("exhausted", "channel low: close and reopen (rollover tx built)")

    def request_conditional(self, method: str, url: str, body: bytes = b""):
        """Pay-on-preimage: sign a hash-locked increment, receive cipher+k, upgrade if k checks."""
        from .conditional import ConditionalParams, decrypt, sha256
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        ch = self.channels.get(origin)
        status, rh, out = self.http(method, url, body)
        if status != 402:
            raise ChannelError("bad_offer", "expected a 402 with a hashlock")
        pr = unb64json(rh["PAYMENT-REQUIRED"])
        acc = self._pick(pr)
        extra = acc["extra"].get("conditional") or {}
        if not extra.get("hash"):
            raise ChannelError("bad_offer", "no conditional hashlock in the 402")
        try:
            cipher = bytes.fromhex(extra["cipher"])
        except (KeyError, TypeError, ValueError):
            # without the ciphertext first, k (off-chain or in the claim) buys nothing (M7)
            raise ChannelError("bad_offer", "conditional offer carries no ciphertext")
        if not ch:
            ch = self._open(origin, acc)
            self.channels[origin] = ch
        if ch.price and int(acc["amount"]) > ch.price:
            raise ChannelError("bad_offer", f"price raised mid-channel: {ch.price} -> {acc['amount']} sat")
        ch.accepted = acc
        if ch.payer.signed > ch.acked_cum and ch.last_sig:
            # a signed state the provider never acknowledged (a lost fold): hand it over first, or the
            # provider still holds an outstanding increment and refuses this call (L9)
            self._hand_over(ch, acc, ch.payer.signed, ch.last_sig)
        h = bytes.fromhex(extra["hash"])
        cond_amt = int(extra["amount"])
        # the increment is a call's price: held to the same caps before anything is signed (H6). Since
        # M6 the provider can close with a conditional state and claim it, so an unchecked amount let
        # one conditional call take the whole channel.
        if cond_amt > self.max_price:
            raise ChannelError("too_expensive", f"conditional {cond_amt} sat > max {self.max_price}")
        if cond_amt < DUST:
            raise ChannelError("bad_offer", "conditional amount below dust")
        self._check_daily(cond_amt)
        cond = ConditionalParams(ch.payer.params, h, cond_amt, int(extra.get("csvDelta", 10)))
        uncond = ch.payer.signed
        tx = cond.state_tx(uncond)
        if self.signer:
            sig = self.signer.sign_conditional(ch.payer.params.channel_id, uncond, cond)
        else:
            sig = (ecc.sign(ch.payer.secret, cond.sighash(tx)) + bytes([0x21])).hex()
        self.day_spent += cond_amt
        ch.pending_cond = {"hash": h.hex(), "cipher": cipher.hex(), "amount": cond_amt}
        ch.seq += 1
        pl = {"chan": ch.payer.params.channel_id, "seq": ch.seq, "cum": str(uncond),
              "hashlock": extra["hash"], "sig": sig}
        self._auth(ch, pl, method, path, body)
        hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": pl})}
        status, rh, out = self.http(method, url, body, hdrs)
        if status == 402:                      # refused: the provider did not keep the conditional state
            ch.pending_cond = {}
            try:
                code = json.loads(out).get("error") or "refused"
            except (ValueError, AttributeError):
                code = "refused"
            raise ChannelError(code if isinstance(code, str) and code.isidentifier() else "refused",
                               "conditional call refused")
        try:
            k = bytes.fromhex(json.loads(out)["preimage"])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ChannelError("no_preimage", f"HTTP {status} without k: if the provider closes with the hash "
                                              f"lock, recover_conditional() reads k from its claim")
        if sha256(k) != h:
            raise ChannelError("bad_preimage", "provider preimage does not match H")
        plain = decrypt(cipher, k)             # the offered ciphertext, whatever the response carries
        ch.pending_cond = {}
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body, cond_amt)
        # upgrade: fold the increment into an unconditional state and hand it over now, so the
        # provider can close with a plain state (until then it closes with the hash lock, M6)
        new_cum = max(uncond + cond_amt, ch.payer.params.min_amount)
        if new_cum > ch.payer.signed:
            ch.last_sig = ch.payer.sign_state(new_cum).hex()
        self._hand_over(ch, acc, new_cum, ch.last_sig)
        return status, rh, out, plain

    def _hand_over(self, ch: ClientChannel, acc: dict, cum: int, sig: str):
        """POST a signed state to /x402/verify; on failure the next paid call carries it again."""
        try:
            v = self._post(ch.origin + FACILITATOR_VERIFY, facilitator_request(
                acc, {"chan": ch.payer.params.channel_id, "cum": str(cum), "sig": sig}))
            if v.get("isValid") is True:
                ch.acked_cum = max(ch.acked_cum, cum)
        except (ChannelError, ValueError, OSError):
            pass

    def recover_conditional(self, origin: str, tx) -> bytes:
        """The deliverable of a signed hash lock whose paid response never arrived, from the
        provider's claim transaction (hex or Tx), which reveals k on-chain."""
        from .conditional import decrypt, preimage_from_tx
        pc = self.channels[origin].pending_cond
        if not pc:
            raise ChannelError("no_state", "no pending conditional call on this channel")
        k = preimage_from_tx(tx, bytes.fromhex(pc["hash"]))
        if not k:
            raise ChannelError("bad_preimage", "this transaction does not reveal k")
        return decrypt(bytes.fromhex(pc["cipher"]), k)
