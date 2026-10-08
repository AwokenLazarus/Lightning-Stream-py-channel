"""x402 v2 scheme `batch-settlement` (XBT channel binding; `xbt-channel` accepted as an alias): HTTP 402 payments over XBT Spillman channels (xbt402 v1.1).

Spec: docs/x402/xbt402-spec-v1.1-draft.md (was ~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402
HTTP 402 payment channels.md). v1.1: the payee key commits to the network. v1.3 (AGP-068,
extra.derivation "v3"): a payment binds the request's scheme, host and port with length-prefixed
fields, and the receipt covers the answer's status and body. PAYMENT-RESPONSE is an x402 SettlementResponse, /x402/verify and /x402/settle take and answer the x402
v2 facilitator shapes.

  402 + PAYMENT-REQUIRED: base64(PaymentRequired)      (same JSON in the body)
  PaymentRequired = {x402Version: 2, error?, resource: {url}, accepts: [PaymentRequirements]}
  PaymentRequirements = {scheme: "batch-settlement" (alias "xbt-channel" accepted on input),
      network: "bip122:<first 32 hex of block 961640>",
      amount: "<sats per call, max>", asset: "XBT:sat", payTo: "<33-byte compressed pubkey hex>",
      maxTimeoutSeconds, extra: {minCapacity, maxCapacity, minExpiryBlocks, maxExpiryBlocks,
      closeMarginBlocks, minConf, closeFeeSat, openUrl, closeUrl, billing: "postpay"|"prepay",
      derivation: "v3", assetTransferMethod: "channel",
      closeFeePayer?: "payer"|"payee" (v1.2, absent = payer)}}
      payee key P = payTo + t*G, t = H("xbt-channel/payee/v2", len8(network) network payTo A LE32(expiry))

  open:   POST extra.openUrl {x402Version, network, channel: {txid, vout, capacity, expiry, payerPub,
          payerSpk?, redeemScript}}  -> {chan, expiry, maxCum, confirmations}
  pay:    PAYMENT-SIGNATURE: base64({x402Version: 2, accepted: <requirements>,
          payload: {chan, seq, cum, sig?, auth}})  sig = payer DER || 0x21 over the state for cum
          auth = HMAC-SHA256(tagged_hash("xbt402/auth-key", ECDH(A, P)),
                 "xbt402/auth|chan|seq|cum|sig|req"), seq above every earlier one,
          req = hex(tagged_hash("xbt402/req/v2", f(method) f(scheme) f(host) f(port) f(target) f(body))),
          f(x) = LE64(len(x)) x  (request_digest_v2)
  result: PAYMENT-RESPONSE: base64(SettlementResponse {success, transaction: "", network, payer: A,
          amount: "", extra: {chargedAmount, receipt: {scheme, chan, seq, cum, charged, spentMsat,
          owedMsat, creditMsat, expiry, req, status, bodyHash, sig}}})  sig = receipt by the channel
          payee key over tagged_hash("xbt402/receipt/v2", f(chan) … f(bodyHash)); bodyHash = sha256(body)
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
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

from . import ecc
from .channel import (DERIVATION, DUST, FEE_PAYERS, SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams, Payee, Payer,
                      canonical_chan, channel_auth_key, channel_payee_secret, check_payout_spk, settle_due)
from .conditional import CSV_DELTA
from .funding import FundingPolicy, check_funding
from .ledger import ChannelState, Ledger
from .tx import segwit_address, tagged_hash

SCHEME = "batch-settlement"
SCHEME_ALIAS = "xbt-channel"                                # one-release input alias; emit SCHEME
ASSET_TRANSFER_METHOD = "channel"
MAX_BODY = 1 << 20                                          # default bytes per request body (overridable)
MAX_RESPONSE = 64 << 20                                     # a payer never buffers more than this (review T3)
HEAD_DEADLINE = 10                                          # a header that never finishes (review T1)
BODY_DEADLINE = 30                                          # a body that never arrives holds a slot until this
MAX_HEADER_LINE = 8 * 1024
MAX_HEADERS = 32 * 1024
MAX_CONNECTIONS = 64


def scheme_accepted(s) -> bool:
    """True for the canonical scheme or the one-release `xbt-channel` alias."""
    return s in (SCHEME, SCHEME_ALIAS)
XBT_MAINNET = "bip122:0000000000000050c1e5f69672f45929"   # block 961640, the first BLAKE2b block
FACILITATOR_VERIFY, FACILITATOR_SETTLE, FACILITATOR_SUPPORTED = "/x402/verify", "/x402/settle", "/x402/supported"


def b64json(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def unb64json(s: str):
    return json.loads(base64.b64decode(s))


def _alower(s: str) -> str:
    return "".join(c.lower() if "A" <= c <= "Z" else c for c in s)


def request_url(url: str):
    """(scheme, host, port, target) of `scheme://host[:port]target` as request_digest_v2 binds them:
    scheme and host lowercased (ASCII), an IPv6 literal kept in brackets, userinfo and a fragment
    dropped, the port in decimal without leading zeros or the scheme's default (80 http, 443 https),
    the target as sent ("/" when the URL has no path). Without "://" it is a bare target, which
    binds no origin."""
    if "://" not in url:
        return "", "", "", url
    scheme, rest = url.split("://", 1)
    rest = rest.split("#", 1)[0]
    ends = [i for i in (rest.find("/"), rest.find("?")) if i >= 0]
    end = min(ends) if ends else len(rest)
    authority, tail = rest[:end], rest[end:]
    authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("[") and "]" in authority:
        i = authority.index("]")
        host, port = authority[:i + 1], authority[i + 1:]
        port = port[1:] if port.startswith(":") else ""
    elif ":" in authority:
        host, port = authority.rsplit(":", 1)
    else:
        host, port = authority, ""
    scheme = _alower(scheme)
    if port and all(c in "0123456789" for c in port) and int(port) <= 0xFFFF:
        port = str(int(port))
    elif not port:
        port = {"http": "80", "https": "443"}.get(scheme, "")
    target = tail if tail.startswith("/") else "/" + tail
    return scheme, _alower(host), port, target


def url_origin(url: str) -> str:
    """`scheme://authority` of an absolute URL, or "" for a bare target."""
    i = url.find("://")
    if i < 0:
        return ""
    rest = url[i + 3:]
    ends = [j for j in (rest.find("/"), rest.find("?"), rest.find("#")) if j >= 0]
    return url[:i + 3 + (min(ends) if ends else len(rest))]


def _fields(*xs: bytes) -> bytes:
    """LE64(len(x)) ‖ x for each field: no two field lists share an encoding."""
    return b"".join(len(x).to_bytes(8, "little") + x for x in xs)


def request_digest_v2(method: str, url: str, body: bytes) -> str:
    """Which request a payment or receipt is for (AGP-068, review T2): hex of
    tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body)),
    f(x) = LE64(len(x)) ‖ x. `url` is the absolute URL the payer sent the request to; the server
    rebuilds it from its public scheme, the Host header and the request target. v1,
    sha256(method|path|body), ran its fields together and bound no origin."""
    scheme, host, port, target = request_url(url)
    return tagged_hash("xbt402/req/v2", _fields(method.encode(), scheme.encode(), host.encode(), port.encode(),
                                                target.encode(), body)).hex()


def binding_url(url: str, path: str) -> str:
    """What a server binds a request's payment to: the origin it was reached at and the target it
    routes on. A `url` without an origin binds the target alone."""
    return url_origin(url) + path


def unsafe_headers(hdrs: dict) -> bool:
    """A CR, LF or NUL in a response header name or value: a handler reflecting request data would
    inject headers (or split the response) on transports that do not check, like http.server."""
    return any(c in str(k) + str(v) for k, v in hdrs.items() for c in "\r\n\0")


def request_auth(key: bytes, chan: str, seq, cum, sig, req: str) -> str:
    """payload.auth: binds one paid request (method, path, body) to the channel, a fresh seq and the
    state it carries. Without it `{chan, cum}` was a bearer token anyone could spend."""
    msg = "|".join(("xbt402/auth", chan, str(seq), str(cum), sig or "", req)).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


RECEIPT_FIELDS = ("chan", "seq", "cum", "charged", "spentMsat", "req", "status", "bodyHash")


def receipt_message(r: dict) -> bytes:
    """tagged_hash("xbt402/receipt/v2", f(chan) ‖ f(seq) ‖ … ‖ f(bodyHash)), each field as str(),
    f(x) = LE64(len(x)) ‖ x. AGP-068 adds the answer's status and bodyHash (review T4)."""
    return tagged_hash("xbt402/receipt/v2", _fields(*(str(r[k]).encode() for k in RECEIPT_FIELDS)))


def body_hash(body: bytes) -> str:
    """A receipt's bodyHash: hex sha256 of the answer's body exactly as sent."""
    return hashlib.sha256(body).hexdigest()


def close_message(chan: str) -> bytes:
    return tagged_hash("xbt402/close", chan.encode())


def network_id(first_blake2b_block_hash: str) -> str:
    return "bip122:" + first_blake2b_block_hash[:32]


# x402 v2 facilitator reasons (VerifyResponse.invalidReason, SettlementResponse.errorReason) for the
# protocol's own codes. The 402 `error` field keeps the short codes; facilitator answers use the
# XBT batch-settlement prefix (docs/x402/PUBLISHING.md).
UPSTREAM_CODES = {"unsupported_scheme_or_network": "invalid_batch_settlement_xbt_scheme_or_network",
                  "bad_payload": "invalid_batch_settlement_xbt_payload", "bad_auth": "invalid_batch_settlement_xbt_auth",
                  "channel_closing": "invalid_batch_settlement_xbt_closing", "bad_sig": "invalid_batch_settlement_xbt_signature",
                  "wrong_network": "invalid_network", "close_failed": "unexpected_settle_error"}


def safe_code(code) -> bool:
    """A short snake_case identifier: the only provider-chosen string an error code may be (L12)."""
    return isinstance(code, str) and 0 < len(code) <= 40 and code.replace("_", "").isalpha() and code.islower()


def upstream_code(code: str) -> str:
    return UPSTREAM_CODES.get(code) or "invalid_batch_settlement_xbt_" + (code or "payload")


def settlement_response(receipt: dict, network: str, payer: str, success: bool) -> dict:
    """PAYMENT-RESPONSE as an x402 v2 SettlementResponse. A paid call broadcasts nothing, so
    `transaction` and `amount` are empty; the signed channel receipt rides in `extra`."""
    return {"success": success, "transaction": "", "network": network, "payer": payer, "amount": "",
            "extra": {"chargedAmount": receipt["charged"], "receipt": receipt}}


def locks_open(st) -> bool:
    """A hub's ch1 holds a routed lock that its best state does not cover (AGP-064): the one in flight
    (`route_lock`), or one written off (`stale_locks`) above the best state, which the hub may still
    have to pay on its ch2. Closing ch1 now would close below it."""
    ex = st.extra or {}
    if ex.get("route_lock"):
        return True
    def above(s) -> bool:
        try:
            return int(s["cum"]) > st.best_cum
        except (KeyError, TypeError, ValueError):
            return True
    return any(above(s) for s in ex.get("stale_locks") or [])


def receipt_of(resp: dict) -> dict:
    """The signed channel receipt inside a PAYMENT-RESPONSE SettlementResponse."""
    r = ((resp or {}).get("extra") or {}).get("receipt") if isinstance(resp, dict) else None
    if not isinstance(r, dict) or not scheme_accepted(r.get("scheme")):
        raise ChannelError("bad_receipt", "PAYMENT-RESPONSE carries no batch-settlement receipt in extra.receipt")
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
                 close_fee_payer: str = "payer", route_close_fee_payer: str = "payee", rollover_grace: int = 36,
                 rollover_zero_conf_max: int = None, route_wal: str = None, settle_lock_multiple: int = 4):
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
        # funds to this provider (routed ch2) default to payee-pays (2026-09-28): the provider
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
        # AGP-053 make-before-break: a hub-bound channel's rollover child is taken unconfirmed (its parent
        # is our own confirmed channel, and only we can sign a conflicting spend of it before its expiry),
        # up to this cum while it stays unconfirmed. None: two settlements' worth; 0: never (open at minConf)
        self.rollover_zero_conf_max = (2 * self.settle_multiple * int(close_fee) if rollover_zero_conf_max is None
                                       else int(rollover_zero_conf_max))
        # AGP-056: a hub rolls a ch2 over at settle_lock_multiple x the largest lock when that is above
        # our threshold (locks larger than settleMultiple x closeFee), so the default cap follows it: two
        # such settlements' worth. An explicit rollover_zero_conf_max is used as it is
        self._zc_max_fixed = rollover_zero_conf_max is not None
        self.settle_lock_multiple = int(settle_lock_multiple)
        # AGP-054 route_wal: a path makes each routed session's meter (seq, calls, accrued) durable
        # before its ROUTE-STATE leaves, written ahead while the handler runs (offer_route precharge)
        self.routes = RouteSeller(self, (ledger_path[:-5] if ledger_path.endswith(".json") else ledger_path)
                                  + ".routes.json", wal_path=route_wal)
        # AGP-059: direct calls between their reservation and their settlement, per channel; and the
        # (chan, msat) reservations refunded now, which a crash mid-call left recorded: never charged
        self._in_call: dict = {}
        self.recovered_reservations = self._recover_reservations()

    def _recover_reservations(self) -> list:
        out = []
        with self.ledger.lock:
            for chan, st in self.ledger.channels.items():
                resv = (st.extra or {}).get("resv")
                if not resv:
                    continue
                msat = sum(int(v) for v in resv.values())
                st.spent_msat = max(0, st.spent_msat - msat)
                st.extra = {k: v for k, v in st.extra.items() if k != "resv"}
                self.ledger.save(st)
                out.append((chan, msat))
        return out

    def _release(self, st: ChannelState, seq: int):
        """Call `seq` settled (ledger lock held): drop its reservation record and its in-flight mark."""
        resv = {k: v for k, v in ((st.extra or {}).get("resv") or {}).items() if k != str(seq)}
        st.extra = {**{k: v for k, v in (st.extra or {}).items() if k != "resv"}, **({"resv": resv} if resv else {})}
        chan = st.params.channel_id
        left = self._in_call.get(chan, 0) - 1
        if left > 0:
            self._in_call[chan] = left
        else:
            self._in_call.pop(chan, None)

    def offer_route(self, path: str, window: float = 1.0, lock_wait: float = 2.0, invoice_ttl: float = 15.0,
                    hubs="any", amsat_per_call: int = 0, unit: str = "call", credit_msat: int = 0,
                    charge: Callable = None, precharge: Callable = None):
        """Sell `path` through hubs (AGP-021). Its 402 carries `extra.route`: the signed price quote and,
        for a client that names its route key (ROUTE-CLIENT header), a session with a fresh lock point
        T per window, signed by payTo. Calls carry ROUTE-AUTH and are metered in amsat
        (`amsat_per_call`, or `charge(method, path, status, body) -> amsat`); each window's accrued
        amount is paid by one adaptor-locked ch2 state from a hub. A session is served while its
        unpaid charges are younger than `window + lock_wait` (the lock wait is configurable).

        With a `route_wal` (AGP-054), `precharge(method, path, body) -> amsat` is what the call will
        bill, known before it runs (a flat path needs none: amsat_per_call). Its session's meter is
        then written ahead while the handler runs, and the answer waits only for what is left of that
        fsync. A charge that differs from it costs one more fsync; None or an exception: no overlap."""
        o = self.routes.offer(path, window=window, lock_wait=lock_wait, invoice_ttl=invoice_ttl, hubs=hubs,
                              amsat_per_call=amsat_per_call, unit=unit, credit_msat=credit_msat)
        o.charge = charge
        o.precharge = precharge
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
                          "assetTransferMethod": ASSET_TRANSFER_METHOD,
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
            zc = None
            try:
                confs = check_funding(self.rpc, p, self.policy)
            except ChannelError as e:
                zc = self._zero_conf_child(p, hub) if e.code == "unconfirmed" else None
                if zc is not None:
                    confs = check_funding(self.rpc, p, replace(self.policy, zero_conf_max=p.capacity))
                elif e.code == "unconfirmed" and hub:
                    # AGP-057: not a child we take unconfirmed. A block that came while we looked makes it
                    # neither: the funding read above had no confirmation yet, and the parent is now spent
                    # in that block. Look at the funding once more (still unconfirmed: the same refusal)
                    confs = check_funding(self.rpc, p, self.policy)
                else:
                    raise
            st = self.ledger.channels[p.channel_id] = ChannelState(p)
            if hub:
                st.extra = {"hub": hub}
                # a rollover child carries its line's largest lock on (AGP-056: the next child's cap)
                big = max((int((s.extra or {}).get("max_lock", 0)) for s in self.ledger.channels.values()
                           if (s.extra or {}).get("rollover_to") == p.channel_id and (s.extra or {}).get("hub") == hub),
                          default=0)
                if big:
                    st.extra["max_lock"] = big
            if zc:
                st.extra["zero_conf"] = zc
            self.ledger.save(st)
        out = {"chan": p.channel_id, "expiry": p.expiry, "maxCum": str(p.max_amount), "confirmations": confs}
        if p.close_fee_payer != "payer":
            out.update(closeFeePayer=p.close_fee_payer, minCum=str(p.min_amount))
        if zc:
            out["zeroConf"] = {"parent": zc["parent"], "maxCum": str(zc["maxCum"]), "until": zc["until"]}
        return out

    def _zero_conf_child(self, p: ChannelParams, hub: str) -> Optional[dict]:
        """AGP-053: the unconfirmed channel `p` is the rollover child of one of our hub-bound channels
        (the tx we co-signed and broadcast, `rollover_to`), bound to the same hub, whose own funding is
        confirmed (conf_for) and which is before its close margin: take it now, bounded (`zero_conf` on
        the child). Before the parent's expiry only this provider can sign a spend of the parent other
        than that rollover, so the child exists unless we replace it ourselves, or the rollover is still
        unconfirmed at the parent's expiry (the payer's refund): locks are taken until `until` only."""
        if not hub or self.rollover_zero_conf_max <= 0:
            return None
        cid = p.channel_id
        parent = next((s for s in self.ledger.channels.values()
                       if (s.extra or {}).get("rollover_to") == cid and (s.extra or {}).get("hub") == hub), None)
        if parent is None:
            return None
        pp = parent.params
        need = self.policy.conf_for(pp.capacity)
        until = pp.expiry - self.close_margin
        if self.height() >= until or not self._confirmed(pp.funding_txid, pp.funding_vout, need):
            return None
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is None:
            return None
        return {"parent": pp.channel_id, "need": need, "maxCum": self.zero_conf_max_for(parent), "until": until,
                "confirmed": False}

    def zero_conf_max_for(self, parent: ChannelState) -> int:
        """The most a rollover child of `parent` takes while unconfirmed: rollover_zero_conf_max, and by
        default (AGP-056) at least 2 x settle_lock_multiple x the largest lock the parent's line took, so
        a provider paid in locks larger than its settle threshold is not capped below one lock."""
        if self._zc_max_fixed:
            return self.rollover_zero_conf_max
        big = int((parent.extra or {}).get("max_lock", 0))
        return max(self.rollover_zero_conf_max, 2 * self.settle_lock_multiple * big)

    def _confirmed(self, txid: str, vout: int, need: int) -> bool:
        """The output is in a block with `need` confirmations (spent in the mempool or not)."""
        utxo = self.rpc.gettxout(txid, vout, False)
        return utxo is not None and utxo.get("confirmations", 0) >= need

    def _zc_confirmed(self, st: ChannelState, live: bool = False) -> bool:
        """Not an unconfirmed rollover child (AGP-053): a plain channel, or a child that confirmed (as
        the watcher last saw it, or `live` from the node now; the caller holds the ledger lock)."""
        zc = (st.extra or {}).get("zero_conf")
        if not zc or zc.get("confirmed"):
            return True
        if live and self._confirmed(st.params.funding_txid, st.params.funding_vout, self.policy.conf_for(st.params.capacity)):
            st.extra = {**st.extra, "zero_conf": {**zc, "confirmed": True}}
            self.ledger.save(st)
            return True
        return False

    def _zero_conf_ok(self, st: ChannelState, h: int) -> bool:
        """An unconfirmed rollover child (AGP-053) is served while it is in the mempool, its parent
        still has its confirmations (a reorg of the parent ends it), and before the parent's margin."""
        zc = (st.extra or {}).get("zero_conf")
        if not zc or h >= zc["until"]:
            return False
        p = st.params
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is None:
            return False
        ptxid, pvout = zc["parent"].split(":")
        return self._confirmed(ptxid, int(pvout), zc["need"])

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

    def _authentic(self, st: ChannelState, pl: dict, method: str, bind: str, body: bytes) -> bool:
        """payload.auth is the channel's HMAC over this request and a seq above every earlier one.
        `bind` is the request's URL as request_digest_v2 binds it (binding_url)."""
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
                            request_digest_v2(method, bind, body))
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
            # AGP-064 (H1): a hub's route() writes its lock and lets go of the ledger before it forwards,
            # so a close here could otherwise land between the two
            if not st.closed_txid and locks_open(st):
                raise ChannelError("lock_pending", "a routed lock is open on this channel")
            if req.get("payload") and not st.closed_txid:   # after the close a state changes nothing (L10)
                self._apply(st, req["payload"])
            txid = self._close_locked(st)
            report = self._close_report(st)
        return {"chan": st.params.channel_id, "txid": txid, **report}

    def close_channel(self, chan: str) -> dict:
        """Close one channel now with the best signed state (AGP-059), exactly as the watcher does at
        the close margin (write-ahead intent, broadcast, record, hash-lock claim). Returns the
        cooperative close's answer: chan, txid, cum, unpaidMsat (and payeeFee/payeeNet under payee-pays).

        Refused with a ChannelError, nothing changed: unknown_channel; channel_closed (already closed
        or rolled over); lock_pending (a routed lock is open on it); hub_channel (a hub-funded ch2:
        its hub rolls it over or closes it, and the margin close still protects it); call_in_flight
        (a paid call is being served: the best state does not cover it yet); no_state (nothing
        signed)."""
        st = self._channel(chan)
        with self.ledger.lock:
            ex = st.extra or {}
            if st.closed_txid:
                raise ChannelError("channel_closed", f"closed by {st.closed_txid}")
            if locks_open(st):
                raise ChannelError("lock_pending", "a routed lock is open on this channel")
            if ex.get("hub"):
                raise ChannelError("hub_channel", "a hub-funded channel is rolled over or closed by its hub")
            if self._in_call.get(st.params.channel_id):
                raise ChannelError("call_in_flight", "a paid call is being served on this channel")
            if not (st.best_sig or st.cond_sig):
                raise ChannelError("no_state", "the payer has signed no state to close with")
            txid = st.closed_txid if self._adopt_intent(st) else self._close_locked(st)
            report = self._close_report(st)
        return {"chan": st.params.channel_id, "txid": txid, **report}

    def _adopt_intent(self, st: ChannelState) -> bool:
        """A close this provider sent and never recorded (M8: the intent is written ahead): record it.
        True when the channel is now closed by it."""
        intent = (st.extra or {}).get("close_intent")
        if not intent:
            return False
        from .tx import Tx
        if not self._tx_known(intent["txid"], Tx.parse(bytes.fromhex(intent["hex"]))):
            return False
        self._closed(st, intent["hex"], intent["txid"], intent["cond"])
        return True

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
        if self._adopt_intent(st):               # sent, never recorded (M8)
            out.append(st.closed_txid)
            if st.extra.get("cond_close"):
                self._claim(st)
            return
        utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
        st.suspended = utxo is None or utxo.get("confirmations", 0) < self.policy.conf_for(p.capacity)
        zc = (st.extra or {}).get("zero_conf")
        if zc:
            # AGP-053: confirmed (again, after a reorg) or not; unconfirmed, it is served under its rules
            zc = {**zc, "confirmed": not st.suspended}
            st.extra = {**st.extra, "zero_conf": zc}
            if st.suspended and self._zero_conf_ok(st, h):
                st.suspended = False
        if (st.best_sig or st.cond_sig) and h >= p.expiry - self.close_margin:
            # AGP-064: a lock in flight (seconds: the hub's revealTimeout) is let finish, in the first half
            # of the margin only. Never for a written-off lock: a skipped margin close lets the payer
            # refund the whole channel at expiry
            if (st.extra or {}).get("route_lock") and h < p.expiry - (self.close_margin + 1) // 2:
                return
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
            if not scheme_accepted(acc.get("scheme")) or acc.get("network") != self.network or acc.get("payTo") != self.pay_to:
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
        with self.ledger.lock:
            if not self._zc_confirmed(st, live=True):
                raise ChannelError("unconfirmed", "the channel's funding (a rollover) is not confirmed yet")
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

    def _route_lock(self, method: str, bind: str, headers: dict, body: bytes):
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
            if not self._authentic(st, pl, method, bind, body):
                return err("bad_auth", status=401)
            st.seq = int(pl["seq"])
            if st.closed_txid or self.height() >= st.params.expiry - self.close_margin:
                return err("channel_closing")
            if st.suspended:
                # AGP-057: `suspended` is the watcher's last look, and a block that came during that look
                # leaves a rollover child suspended although it confirmed (the parent was then spent in a
                # block, so it was no zero-conf child either). A hub looks at the chain itself before it
                # sends a lock: so do we before refusing one on an unconfirmed child
                zc = (st.extra or {}).get("zero_conf")
                if not (zc and not zc.get("confirmed") and self._zc_confirmed(st, live=True)):
                    return err("unconfirmed")
                st.suspended = False
                self.ledger.save(st)
            if not self._zc_confirmed(st):
                # AGP-053: an unconfirmed rollover child, taken up to its cap and before the parent's margin
                zc = st.extra["zero_conf"]
                try:
                    cum = int(pl.get("cum"))
                except (TypeError, ValueError):
                    return err("bad_payload")
                # past a bound: look at the chain first (it may have confirmed since the watcher's tick)
                if (self.height() >= zc["until"] or cum > zc["maxCum"]) and not self._zc_confirmed(st, live=True):
                    if self.height() >= zc["until"]:
                        return err("unconfirmed", "rollover unconfirmed at the parent's close margin")
                    return err("zero_conf_cap", f"cum {cum} > {zc['maxCum']} while the rollover is unconfirmed")
            try:
                out = self.routes.complete_lock(st, pl, route)
            except ChannelError as e:
                self.ledger.save(st)
                return err(e.code, str(e))
        return (202 if "held" in out else 200), {"Content-Type": "application/json"}, json.dumps(out).encode()

    def _routed_call(self, method: str, path: str, path_key: str, hdr: str, body: bytes, url: str):
        from .route import AMSAT_PER_MSAT  # noqa: F401
        o = self.routes.offers[path_key]
        s, error = self.routes.begin_call(path_key, hdr, method, binding_url(url, path), body)
        if error:
            st, h, b = self._payment_required(url, self.price(method, path), error)
            doc = json.loads(b)
            doc["accepts"][0]["extra"]["route"] = self.routes.route_extra(path_key)
            if s is not None:
                rs = self.routes.refusal_state(s)
                if rs is not None:
                    doc["routeState"] = rs
            h["PAYMENT-REQUIRED"] = b64json(doc)
            return 402, h, json.dumps(doc).encode()
        ticket = None
        if self.routes.wal is not None:
            expect = int(o.amsat_per_call) if not getattr(o, "charge", None) else None
            if getattr(o, "precharge", None):
                try:
                    expect = o.precharge(method, path, body)
                except Exception:  # noqa: BLE001 - a bad hint only costs the overlap
                    expect = None
            if expect is not None:
                ticket = self.routes.reserve(s, int(expect))
        try:
            status, hdrs, out = self.handler(method, path, body)
        except BaseException:
            self.routes.cancel(s, ticket)
            raise
        if unsafe_headers(hdrs):
            status, hdrs, out = 500, {}, b"handler returned a header with CR/LF"
        charge = int(o.amsat_per_call)
        if getattr(o, "charge", None):
            charge = int(o.charge(method, path, status, out))
        if status >= 500:
            charge = 0
        try:
            state = self.routes.end_call(s, max(0, charge), ticket)
        except ChannelError as e:
            if e.code != "route_wal_failed":
                raise
            return 500, {"Content-Type": "application/json"}, json.dumps(
                {"error": "route_wal_failed", "detail": "the route meter is not durable: this call is not billed"}).encode()
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
        bind = binding_url(url, path)
        if path == "/x402/xbt-channel/lock":
            if method != "POST":
                return 405, {}, b"method not allowed"
            return self._route_lock(method, bind, headers, body)
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
            if pp.get("x402Version") != 2 or not scheme_accepted(acc.get("scheme")) or acc.get("network") != self.network \
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
            if not self._authentic(st, pl, method, bind, body):   # no channel details for strangers
                return self._payment_required(url, price, "bad_auth")
            st.seq = int(pl["seq"])                               # spent, whatever happens next

            def refuse(error):
                # every refusal is durable: the seq it spent, and a higher state that still does not
                # cover this call (review T4: a seq kept only in memory came back after a restart,
                # and the refused header with it)
                self.ledger.save(st)
                return self._payment_required(url, price, error, st)
            try:
                height = self.height()
            except BaseException:
                self.ledger.save(st)
                raise
            if st.closed_txid or height >= st.params.expiry - self.close_margin:
                return refuse("channel_closing")
            if st.suspended:
                return refuse("unconfirmed")
            try:
                if not pl.get("hashlock"):
                    self._apply(st, pl)
            except (ChannelError, ValueError, TypeError, KeyError) as e:
                return refuse(getattr(e, "code", "bad_payload"))
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
            seq, metered = st.seq, self.charge is not None
            st.spent_msat += price * 1000        # reserve the max; refunded below if metered lower
            if metered:
                # AGP-059: the charge is not known yet. Recorded, so a restart refunds a call that
                # never settled; an unmetered call's reservation is its exact charge already
                st.extra = {**(st.extra or {}), "resv": {**((st.extra or {}).get("resv") or {}), str(seq): price * 1000}}
            self.ledger.save(st)
            numbers = (st.best_cum, st.spent_msat)      # this call's own reservation (review T4)
            self._in_call[st.params.channel_id] = self._in_call.get(st.params.channel_id, 0) + 1
        try:
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
        except BaseException:
            # the handler or the charge raised: nothing was charged, so the reservation goes back
            with self.ledger.lock:
                self._release(st, seq)
                st.spent_msat -= price * 1000
                self.ledger.save(st)
            raise
        with self.ledger.lock:
            self._release(st, seq)
            refund = (price - charged) * 1000
            if status >= 500:                   # don't bill failed calls
                refund, charged = price * 1000, 0
            st.spent_msat -= refund
            if metered or charged != price:
                # a metered call's charge is durable before its answer leaves: the row on disk held
                # the reservation, which a restart refunds (AGP-059)
                try:
                    self.ledger.save(st)
                except BaseException:
                    st.spent_msat -= charged * 1000
                    raise
            # the numbers of this call's own reservation: calls running beside it move the channel,
            # not this receipt. Calls reserved before it count at what they reserved.
            cum, spent = numbers[0], numbers[1] - refund
            r = {"scheme": SCHEME, "chan": st.params.channel_id, "seq": seq, "cum": str(cum), "charged": str(charged),
                 "spentMsat": str(spent), "owedMsat": str(max(0, spent - cum * 1000)),
                 "creditMsat": str(max(0, cum * 1000 - spent)), "expiry": st.params.expiry,
                 "req": request_digest_v2(method, bind, body), "status": status, "bodyHash": body_hash(out)}
            secret = self._chan_secret(st.params)
        r["sig"] = ecc.sign(secret, receipt_message(r)).hex()
        hdrs = dict(hdrs)
        hdrs["PAYMENT-RESPONSE"] = b64json(settlement_response(r, self.network, st.params.payer_pub, status < 400))
        return status, hdrs, out

    def http_server(self, port: int) -> ThreadingHTTPServer:
        app = self

        class Bound(ThreadingHTTPServer):
            """At most MAX_CONNECTIONS reads at once. A slow header or body holds a slot, not every
            worker, and the slot is released when the handler finishes (review T1)."""

            def __init__(self, addr, handler):
                super().__init__(addr, handler)
                self._open = 0
                self._lk = threading.Lock()

            def process_request(self, request, client_address):
                with self._lk:
                    if self._open >= MAX_CONNECTIONS:
                        try:
                            msg = b"too many connections"
                            request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n"
                                            b"Connection: close\r\n\r\n%s" % (len(msg), msg))
                        except OSError:
                            pass
                        request.close()
                        return
                    self._open += 1
                super().process_request(request, client_address)

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _refuse(self, status, why):
                self.close_connection = True
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", str(len(why)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(why)
                except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
                    pass

            def handle_one_request(self):
                # Headers are read here, with a line cap and a deadline, before any worker runs.
                # http.server's own parser accepts a 64 KiB line and waits forever.
                self.close_connection = True
                self.request_version, self.requestline, self.command = "HTTP/1.1", "", ""
                try:
                    deadline = time.monotonic() + HEAD_DEADLINE
                    block = bytearray()
                    line_len = 0
                    while True:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            return self._refuse(408, b"timeout")
                        self.connection.settimeout(left)    # absolute: a drip of bytes does not renew it
                        b = self.rfile.read(1)
                        if not b:
                            return
                        block.append(b[0])
                        if len(block) > MAX_HEADERS:
                            return self._refuse(431, b"header too large")
                        if b == b"\n":
                            line_len = 0
                        else:
                            line_len += 1
                            if line_len > MAX_HEADER_LINE:
                                return self._refuse(431, b"header too large")
                        if block.endswith(b"\r\n\r\n"):
                            break
                except (TimeoutError, socket.timeout):
                    return self._refuse(408, b"timeout")
                except (ConnectionResetError, BrokenPipeError):
                    return
                from http.client import parse_headers
                from io import BytesIO
                head, _, _rest = bytes(block).partition(b"\r\n")
                parts = head.decode("iso-8859-1", "replace").split(" ")
                if len(parts) < 2 or not parts[0] or not parts[1]:
                    return self._refuse(400, b"bad request")
                self.requestline = head.decode("iso-8859-1", "replace")
                self.command, self.path = parts[0], parts[1]
                self.request_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                if self.command not in ("GET", "POST"):
                    return self._refuse(501, b"unsupported method")
                try:
                    self.headers = parse_headers(BytesIO(bytes(block).split(b"\r\n", 1)[1]))
                except Exception:
                    return self._refuse(400, b"bad headers")
                self._go()

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
                n = int(cl[0])
                if n and (self.headers.get("Expect") or "").strip().lower() == "100-continue":
                    try:
                        self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                    except OSError:
                        return
                body = bytearray()
                deadline = time.monotonic() + BODY_DEADLINE
                try:
                    while len(body) < n:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            return self._refuse(408, b"timeout")
                        self.connection.settimeout(left)
                        chunk = self.rfile.read1(min(n - len(body), 1 << 16))
                        if not chunk:
                            return self._refuse(400, b"bad body")
                        body += chunk
                except (TimeoutError, socket.timeout):
                    return self._refuse(408, b"timeout")
                except OSError:
                    return
                body = bytes(body)
                fwd = (self.headers.get("X-Forwarded-Proto") or "").strip()
                proto = "https" if fwd.lower() == "https" else "http"
                host = self.headers.get("Host") or ""
                status, hdrs, out = app.serve(self.command, self.path, dict(self.headers), body,
                                              f"{proto}://{host}{self.path}")
                if unsafe_headers(hdrs):
                    return self._refuse(500, b"handler returned a header with CR/LF")
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(out)

            def finish(self):
                try:
                    super().finish()
                finally:
                    srv = self.server
                    with srv._lk:
                        if srv._open:
                            srv._open -= 1

            def log_message(self, *a):
                pass

        return Bound(("127.0.0.1", port), H)


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
    def _read_capped(r):
        """A body over the cap, or cut short of its Content-Length, is an error. Reading to the cap
        and returning the short buffer booked a truncated answer as the one paid for (review T3)."""
        declared = r.headers.get("Content-Length")
        n = int(declared) if declared and str(declared).isdigit() else None
        if n is not None and n > MAX_RESPONSE:
            raise ChannelError("response_too_large", f"response is {n} bytes; the cap is {MAX_RESPONSE}")
        out = r.read(MAX_RESPONSE + 1)
        if len(out) > MAX_RESPONSE:
            raise ChannelError("response_too_large", f"response exceeds {MAX_RESPONSE} bytes")
        if n is not None and len(out) != n:
            raise ChannelError("response_truncated", f"response body is {len(out)} of {n} bytes")
        status = getattr(r, "status", None)
        if status is None:
            status = r.code
        return status, {k.upper(): v for k, v in r.headers.items()}, out

    @staticmethod
    def http(method, url, body=b"", headers=None):
        req = urllib.request.Request(url, body or None, headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return XbtChannelClient._read_capped(r)
        except urllib.error.HTTPError as e:
            return XbtChannelClient._read_capped(e)

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
            if scheme_accepted(acc.get("scheme")) and acc.get("network") == self.network:
                if int(acc["amount"]) > self.max_price:
                    raise ChannelError("too_expensive", f"{acc['amount']} sat > max {self.max_price}")
                if int(acc["extra"]["closeFeeSat"]) > self.max_close_fee:
                    raise ChannelError("bad_offer", "closeFeeSat above our cap")
                if acc["extra"].get("closeFeePayer", "payer") not in FEE_PAYERS:
                    raise ChannelError("bad_offer", "unknown closeFeePayer")
                if acc["extra"].get("derivation") != DERIVATION:   # before funding: never strand coins
                    raise ChannelError("bad_offer", f"payee key derivation {acc['extra'].get('derivation')!r}, this "
                                                    f"client speaks {DERIVATION!r} (xbt402 v1.1)")
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

    def _auth(self, ch: ClientChannel, pl: dict, method: str, bind: str, body: bytes) -> dict:
        """Add payload.auth for this request. With a signer the ECDH key never leaves it. `bind`:
        where the request goes, origin + path (request_digest_v2); a close's payload binds the empty
        request."""
        req = request_digest_v2(method, bind, body)
        if self.signer:
            pl["auth"] = self.signer.request_auth(pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        else:
            pl["auth"] = request_auth(ch.auth_key, pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        return pl

    def _payload(self, ch: ClientChannel, price: int, method: str = "", path: str = "", body: bytes = b"",
                 chosen: int | None = None) -> dict:
        billing = ch.accepted["extra"].get("billing", "postpay")
        need_msat = ch.spent_msat + (price * 1000 if billing == "prepay" else 0)
        cum = max(-(-need_msat // 1000), ch.payer.signed)
        if 0 < cum < ch.payer.params.min_amount:
            cum = ch.payer.params.min_amount
        if chosen is not None:
            cum = self._chosen_cum(ch, chosen)
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
        return self._auth(ch, pl, method, ch.origin + path if path else "", body)

    @staticmethod
    def _chosen_cum(ch: ClientChannel, c: int) -> int:
        """A caller-chosen cumulative amount (AGP-059), bounded: never below the last signed state,
        above the channel's capacity, or above the receipted spend plus one call at the pinned price.
        Under the channel's minimum state (nothing signed yet) the call goes unsigned: never rounded up."""
        if isinstance(c, bool) or not isinstance(c, int) or c < 0:
            raise ChannelError("bad_amount", "cum is a non-negative integer of sats")
        signed, p = ch.payer.signed, ch.payer.params
        if c < signed:
            raise ChannelError("bad_amount", f"cum {c} is below the last signed state {signed}")
        if c > p.max_amount:
            raise ChannelError("exhausted", f"cum {c} is above the channel's capacity for states {p.max_amount}")
        most = max(-(-ch.spent_msat // 1000) + (ch.price or int(ch.accepted["amount"])), signed)
        if c > most:
            raise ChannelError("too_expensive", f"cum {c} is above the receipted spend plus one call ({most} sat)")
        return 0 if c < p.min_amount else c

    @staticmethod
    def _extra_headers(headers) -> dict:
        """The caller's own request headers (AGP-059): never the payment header, never a split line."""
        out = dict(headers or {})
        for k, v in out.items():
            if not isinstance(k, str) or not isinstance(v, str) or not k or k.upper() == "PAYMENT-SIGNATURE" \
                    or unsafe_headers({k: v}):
                raise ChannelError("bad_header", f"extra header {k!r} is not allowed")
        return out

    def _check_daily(self, sats: int):
        if self.daily_budget and time.time() - self.day_start > 86400:
            self.day_spent, self.day_start = 0, time.time()
        if self.daily_budget and self.day_spent + sats > self.daily_budget:
            raise ChannelError("budget", "daily budget exhausted")

    def request(self, method: str, url: str, body: bytes = b"", headers: dict | None = None,
                cum: int | None = None):
        """One paid HTTP request; opens a channel on the first 402 from an origin.

        AGP-059, for an embedder: `headers` are its own request headers, sent with every request of
        the call (the first try and the paid retry); `cum` is the cumulative sats to sign when it
        meters the channel itself. A chosen cum replaces only the amount; every check still applies.
        Refused: below the last signed state (bad_amount), above the channel's capacity (exhausted),
        above the receipted spend plus one call at the pinned price (too_expensive), over the daily
        budget (budget). Under the channel's minimum state with nothing signed, the call goes unsigned."""
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        own = self._extra_headers(headers)
        ch = self.channels.get(origin)
        hdrs = {}
        if ch:
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": ch.accepted,
                                                  "payload": self._payload(ch, int(ch.accepted["amount"]),
                                                                          method, path, body, cum)})}
        status, rh, out = self.http(method, url, body, {**own, **hdrs})
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
                                                  "payload": self._payload(ch, int(acc["amount"]), method, path, body,
                                                                          cum)})}
            status, rh, out = self.http(method, url, body, {**own, **hdrs})
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body, (status, out))
        return status, rh, out

    def _receipt(self, ch: ClientChannel, resp: dict, method, path, body, answer, quote: int = None):
        """`answer` is the (status, body) the receipt came with: it must be the answer the provider
        signed for (AGP-068). `quote` is what this call may cost: the price pinned at open for a plain call, the
        conditional amount (already checked against max_price) for a conditional one. Never a
        quote the provider can raise afterwards (H6: a `conditional` quote in any 402 lifted the
        cap on plain calls)."""
        quote = quote or ch.price or int(ch.accepted["amount"])
        r = receipt_of(resp)
        if resp.get("network") != self.network or resp.get("payer") != ch.payer.params.payer_pub:
            raise ChannelError("bad_receipt", "PAYMENT-RESPONSE is for another network or payer")
        if r["req"] != request_digest_v2(method, ch.origin + path, body):
            raise ChannelError("bad_receipt", "receipt is for another request")
        status = r.get("status")
        if type(status) is not int or status != answer[0] or r.get("bodyHash") != body_hash(answer[1]):
            # a truncated or altered answer is not the one the provider signed for
            raise ChannelError("bad_receipt", "receipt is for another answer (status or body differs)")
        if not ecc.verify(bytes.fromhex(ch.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        if int(r["cum"]) > ch.payer.signed or int(r["charged"]) > quote:
            raise ChannelError("bad_receipt", "provider claims more than we signed or were quoted")
        if int(r["spentMsat"]) - ch.spent_msat > quote * 1000:
            raise ChannelError("bad_receipt", "provider charged more than one call")
        ch.spent_msat = int(r["spentMsat"])
        ch.acked_cum = max(ch.acked_cum, int(r["cum"]))
        ch.receipts.append(r)

    def close(self, origin: str, cum: int | None = None) -> dict:
        """Cooperative close; in postpay the final state pays exactly what is owed. `cum` (AGP-059):
        the caller's own final amount, under the bounds of `request`."""
        ch = self.channels[origin]
        pl = self._payload(ch, 0, chosen=cum)
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
        self._auth(ch, pl, method, ch.origin + path, body)
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
        if "PAYMENT-RESPONSE" in rh:
            # while the hash lock is pending: after a bad_receipt, recover_conditional still reads k
            # from the provider's claim
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body, (status, out), cond_amt)
        plain = decrypt(cipher, k)             # the offered ciphertext, whatever the response carries
        ch.pending_cond = {}
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
