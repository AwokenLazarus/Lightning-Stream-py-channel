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
import ipaddress
import json
import math
import os
import secrets
import socket
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
                      canonical_chan, channel_auth_key, channel_payee_secret, check_payout_spk, cpfp_child, settle_due)
from .conditional import CSV_DELTA
from .funding import OWNER_MAX_EXPIRY_BLOCKS, FundingPolicy, check_funding, offer_expiry_blocks, offer_retry_floor
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
MAX_PER_ADDRESS = 48                                        # of those, from one client address (AGP-081)
CPFP_CHILD_VSIZE = 110      # a CPFP child: one P2WPKH input, one P2WPKH output (109.25 vB, rounded up)


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


_SCHEME_FIRST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_SCHEME_REST = _SCHEME_FIRST + "0123456789+-."


def split_scheme(url: str):
    """(scheme, rest) of an absolute URL `scheme://rest`, or None. The scheme is the whole string before
    the first "://" and is spelled as RFC 3986 spells one (a letter, then letters, digits, "+", "-",
    "."). Anything else is a bare target, whatever its query holds (AGP-090, review T2): the split used
    to be at the first "://" anywhere, so `/a?next=http://h/x` was read as scheme `/a?next=http` and
    host `h`, both lowercased, and shared a digest with `/A?next=HTTP://H/x`. One function for
    request_url and url_origin (and through it same_origin_url), as xbt-rs wire::split_scheme."""
    i = url.find("://")
    if i < 1 or url[0] not in _SCHEME_FIRST or any(c not in _SCHEME_REST for c in url[1:i]):
        return None
    return url[:i], url[i + 3:]


def request_url(url: str):
    """(scheme, host, port, target) of `scheme://host[:port]target` as request_digest_v2 binds them:
    scheme and host lowercased (ASCII), an IPv6 literal kept in brackets, userinfo and a fragment
    dropped, the port in decimal without leading zeros or the scheme's default (80 http, 443 https),
    the target as sent ("/" when the URL has no path). Anything that is not absolute (split_scheme) is
    a bare target, bound byte for byte: it binds no origin."""
    split = split_scheme(url)
    if split is None:
        return "", "", "", url
    scheme, rest = split
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


def no_fragment(url: str) -> str:
    """Refuse a URL or request target that holds a `#` (AGP-081, review T2). request_url drops a
    fragment, so a payment for `/a` would authenticate `/a#b` too, and a server routes on the target
    as it arrives. Payer and provider both call this before anything is signed, sent or served; the
    digest and its published vectors are unchanged."""
    if "#" in url:
        raise ChannelError("bad_request", "a URL with a # fragment is outside the request binding: not paid and not served")
    return url


FRAGMENT_REFUSED = b"request target with a # fragment"      # the body of the provider's 400


_USERINFO_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:%")
_HOST_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_")


def _host_spelled_one_way(host: str) -> bool:
    """A host as request_url returns it that every URL parser and resolver reads as written: see
    sendable_url. (An IPv4-mapped IPv6 literal is the one place this differs from xbt-rs: each
    language accepts the form its own standard library prints.)"""
    if host.startswith("["):
        try:
            return host.endswith("]") and str(ipaddress.IPv6Address(host[1:-1])) == host[1:-1]
        except ValueError:
            return False
    if not host or not set(host) <= _HOST_OK:
        return False
    # the WHATWG rule for "this host is an IPv4 address", which a resolver follows too: its last
    # label is a number
    last = host.removesuffix(".").rsplit(".", 1)[-1]
    number = (last != "" and all(c in "0123456789" for c in last)) or \
             (last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]))
    if not number:
        return True
    try:
        return str(ipaddress.IPv4Address(host)) == host
    except ValueError:
        return False


def sendable_url(url: str) -> str:
    """Refuse a URL whose host could be read two ways; return it unchanged otherwise.

    The rule (AGP-105 in xbt-rs, wire::sendable_url; fourth audit list 1 items 1 and 15; ported
    here by AGP-107): the host a payer keys its book by and binds a payment to is the host the
    request is sent to. request_url decides the host; a transport parses the string again and
    resolves the name, and `http://127.1/`, `http://2130706433/` and `http://0x7f.0.0.1/` are
    127.0.0.1 to a resolver and three more keys in the book: a seller that refused every funded
    open was funded once per spelling. Refused, before anything is signed, funded or sent:

    - not `scheme://...`; a backslash, whitespace or a control character anywhere;
    - a second `@`, or userinfo with a character outside RFC 3986's set for it;
    - an empty host, or a host with a character other than a letter, digit, `.`, `-` or `_` (so no
      percent-encoding and no non-ASCII name);
    - a host whose last label is a number and that is not a dotted quad in its usual form;
    - a bracketed host that is not an IPv6 address in its usual form, or with anything but a port
      after it; a port that is not a decimal number below 65536.

    Case, a default port, a port's leading zeros and a trailing dot on a name are not refused (a
    trailing dot is still its own key: a stated limit). xbt-rs also rebuilds the URL it hands its
    transport, because that transport's parser reads a backslash another way; urllib reads these
    strings as request_url does, so the caller's string is sent as it is."""
    def refuse(why):
        raise ChannelError("bad_request", f"the URL {why}: its host could be read two ways, so nothing is paid or sent")
    if any(c == "\\" or c.isspace() or ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in url):
        refuse("has a backslash, a space or a control character")
    split = split_scheme(url)
    if split is None:
        refuse("is not scheme://host")
    rest = split[1].split("#", 1)[0]
    ends = [i for i in (rest.find("/"), rest.find("?")) if i >= 0]
    authority = rest[:min(ends) if ends else len(rest)]
    userinfo, at, hostport = authority.partition("@")
    if not at:
        hostport = authority
    elif "@" in hostport:
        refuse("has a second @")
    elif not set(userinfo) <= _USERINFO_OK:
        refuse("has userinfo outside RFC 3986")
    _, host, port, _ = request_url(url)
    if hostport.startswith("[") and ("]" not in hostport or hostport.split("]", 1)[1][:1] not in ("", ":")):
        refuse("has something other than a port after a bracketed host")
    if not _host_spelled_one_way(host):
        refuse("has a host that is not a plain name or an address in its usual form")
    if port and not (all(c in "0123456789" for c in port) and int(port) < 65536):
        refuse("has a port that is not a number below 65536")
    return url


def canonical_origin(url: str) -> str:
    """The origin of an absolute URL as request_url reads it: lowercase scheme and host, no userinfo,
    and no port when it is the scheme's default. "" for a bare target.

    The rule (AGP-096, audit item 18; as xbt-rs wire::canonical_origin): one seller is one origin,
    however a caller spells it. The request binding has always read HTTPS://API.example:443 and
    https://u@api.example as https://api.example, while a payer's channel book was keyed by the
    spelling, so one seller could be funded once per spelling."""
    scheme, host, port, _ = request_url(url)
    if not scheme:
        return ""
    if not port or (scheme, port) in (("http", "80"), ("https", "443")):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def split_url(url: str) -> tuple:
    """(origin, "/path?query") of a URL: the key of a payer's book and the request target. The origin
    of an absolute URL is canonical_origin; anything else is split at its third "/"."""
    origin = canonical_origin(url)
    if origin:
        return origin, request_url(url)[3]
    return "/".join(url.split("/")[:3]), "/" + "/".join(url.split("/")[3:])


def url_origin(url: str) -> str:
    """`scheme://authority` of an absolute URL, or "" for a bare target."""
    split = split_scheme(url)
    if split is None:
        return ""
    i, rest = len(split[0]), split[1]
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


def address_key(host: str) -> str:
    """What the per-address connection cap counts a peer as (AGP-081, review T1): an IPv4 address, an
    IPv4-mapped IPv6 address as that IPv4 address, any other IPv6 address as its /64 (one subscriber
    holds a whole /64). A host that is no IP address counts as itself."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 4:
        return str(ip)
    if ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return f"{int(ip) >> 64:x}/64" + (f"%{ip.scope_id}" if ip.scope_id else "")


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


def intent_open(st) -> bool:
    """A close or rollover of this channel was signed and written ahead (`close_intent`, M8) and is not
    recorded as its close yet: the node answered the broadcast with an error, or we stopped before its
    answer. That transaction is complete and can still confirm, so the channel takes no state above it
    (AGP-084): no paid call. It ends when the node shows the spend (`_adopt_intent`: the
    latest intent or one it replaced, AGP-085),
    when the watcher gets a close through, or when the client rolls over or closes again."""
    return not st.closed_txid and bool((st.extra or {}).get("close_intent"))


MAX_KEPT_INTENTS = 8    # unresolved spends a channel keeps beside its latest intent (`close_intents`, AGP-085)


def intents_full(st) -> bool:
    """A spend of this channel is unresolved and one slot is left among the kept ones: no request makes
    another.

    AGP-088 rule: a channel never keeps more than MAX_KEPT_INTENTS, whatever its payer asks. Each spend
    written ahead is a signed transaction that can still confirm, so none is forgotten; the bound is
    kept by making no new one. A new spend comes only from a rollover (another next channel or amount)
    or from a close at another state. So once one slot is left a rollover is refused channel_closing and
    the channel's state no longer moves (a close's payload and /x402/verify raise nothing): every close
    is then the same transaction, and the last slot stays for the payee's own close, which is never
    refused."""
    return intent_open(st) and len((st.extra or {}).get("close_intents") or []) + 1 >= MAX_KEPT_INTENTS


def set_intent(st, intent: dict):
    """Write `intent` ahead as the channel's `close_intent` (the caller saves). AGP-085: an earlier one
    for another transaction is not forgotten. It is complete and signed and can still confirm, so it
    moves to `close_intents` and `_adopt_intent` goes on looking for it."""
    ex = dict(st.extra or {})
    old = ex.get("close_intent")
    if old and old.get("txid") != intent.get("txid"):
        kept = [k for k in ex.get("close_intents") or [] if k.get("txid") not in (old.get("txid"), intent.get("txid"))]
        ex["close_intents"] = kept + [old]
    ex["close_intent"] = intent
    st.extra = ex


def intents(st) -> list:
    """The spends written ahead for this channel and not recorded: the latest first, then the ones it
    replaced, newest to oldest."""
    ex = st.extra or {}
    return [i for i in [ex.get("close_intent")] + list(reversed(ex.get("close_intents") or [])) if i]


def closing(st) -> bool:
    """The channel is closed, or a spend of it may be on its way (see `intent_open`)."""
    return bool(st.closed_txid) or intent_open(st)


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
                 close_fee_payer: str = "payer", rollover_grace: int = 36,
                 close_bump_max_fee: int = 10_000, close_min_feerate: float = 1.0, close_bump_blocks: int = 3):
        if billing not in ("postpay", "prepay"):
            raise ValueError("billing is postpay or prepay")
        if close_fee_payer not in FEE_PAYERS:
            raise ValueError("close fee payer is payer or payee")
        if int(max_body) < 1:
            raise ValueError("max_body must be >= 1")
        self.rpc, self.secret, self.network = rpc, pay_to_secret, network
        self.pay_to = ecc.pubkey(pay_to_secret).hex()
        self._pay_to_bytes = bytes.fromhex(self.pay_to)
        self._payees: Dict[str, Payee] = {}     # per channel: its secret and params, derived once (L13)
        self.ledger, self.price, self.handler, self.charge = Ledger(ledger_path), price, handler, charge
        self.billing, self.close_fee, self.close_margin, self.hrp = billing, close_fee, close_margin, hrp
        # v1.2 closeFeePayer: channels keep payer-pays (v1.1) unless configured. Under payee-pays the
        # provider pays its own settlement, so settle_due counts it against the net payout
        self.close_fee_payer = close_fee_payer
        self.rollover_grace = int(rollover_grace)   # blocks before the close margin a rollover is due anyway
        self.claim_fee = claim_fee      # sats the hash-lock claim pays out of condAmount (M6)
        # AGP-067 (review C1): the watcher bumps a close still unconfirmed before expiry with a CPFP child
        # from this provider's own close output, at most close_bump_max_fee sats (0: never), to a package
        # feerate of at least close_min_feerate; doubled after close_bump_blocks without a confirmation in
        # the second half of the close margin (an estimate that lags the market)
        self.close_bump_max_fee, self.close_min_feerate = int(close_bump_max_fee), float(close_min_feerate)
        self.close_bump_blocks = int(close_bump_blocks)
        self.policy = policy or FundingPolicy(min_expiry_blocks=1_008, close_margin=close_margin)
        self._height, self._height_at, self.height_ttl = 0, 0.0, height_ttl
        self._auth_keys: Dict[str, bytes] = {}
        self.max_body = int(max_body)
        self.route_max_body = dict(route_max_body or {})
        self.settle_multiple = int(settle_multiple)   # settle once the net payout >= this x closeFee (settle_due)
        # AGP-059: calls between their reservation and their settlement, per channel; and the
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

    def terms(self) -> dict:
        """GET /x402/xbt-channel/terms: this provider's requirements without a paid call first (the
        price is 0), with its settlement terms. `closeFeePayer` is always named here, "payer" too."""
        req = self.requirements(0)
        req["extra"]["settleMultiple"] = self.settle_multiple
        req["extra"]["closeFeePayer"] = self.close_fee_payer
        req["extra"]["rolloverGraceBlocks"] = self.rollover_grace
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
        # payer; payee-pays only where this provider offered it (its 402 and /terms). The funding
        # script does not depend on it, so it is fixed here, at open, and every state both sides build
        # from these params carries it.
        fee_payer = c.get("closeFeePayer", "payer")
        if fee_payer not in ("payer", self.close_fee_payer):
            raise ChannelError("bad_fee_payer", f"closeFeePayer {fee_payer!r} not offered for this channel")
        # v1.1 derivation only: a redeemScript built with the v1.0 tweak (no network) fails here
        p = ChannelParams.derive(self.pay_to, payer_pub.hex(), int(c["expiry"]), self.close_fee, payer_spk,
                                 network=self.network, close_fee_payer=fee_payer)
        if c["redeemScript"].lower() != p.script.hex():
            raise ChannelError("bad_funding", "redeemScript does not match payTo/payerPub/expiry")
        if req.get("preflight") is True:
            return self._open_preflight(p, c)
        chan = canonical_chan(f"{c['txid']}:{int(c['vout'])}")
        p.funding_txid, p.funding_vout, p.capacity = chan.split(":")[0], int(c["vout"]), int(c["capacity"])
        with self.ledger.lock:
            if p.channel_id in self.ledger.channels:
                raise ChannelError("duplicate_channel")
            confs = check_funding(self.rpc, p, self.policy)
            st = self.ledger.channels[p.channel_id] = ChannelState(p)
            self.ledger.save(st)
        out = {"chan": p.channel_id, "expiry": p.expiry, "maxCum": str(p.max_amount), "confirmations": confs}
        if p.close_fee_payer != "payer":
            out.update(closeFeePayer=p.close_fee_payer, minCum=str(p.min_amount))
        return out

    def _open_preflight(self, p: ChannelParams, c: dict) -> dict:
        """AGP-067 (review C2): `"preflight": true` with no outpoint. The answer a funded open of these
        terms would get, or its refusal, before the payer funds anything; nothing is recorded. The
        funding checks (the output, its confirmations) wait for the funded open. Pre-067 providers
        answer bad_request (no vout) only after the terms checks above, so a payer may fund then."""
        pol = self.policy
        p.capacity = int(c["capacity"])
        if not pol.min_capacity <= p.capacity <= pol.max_capacity:
            raise ChannelError("bad_capacity", f"capacity outside [{pol.min_capacity}, {pol.max_capacity}]")
        left = p.expiry - self.height()
        if not pol.min_expiry_blocks <= left <= pol.max_expiry_blocks:
            raise ChannelError("bad_expiry", f"{left} blocks to expiry, need [{pol.min_expiry_blocks}, {pol.max_expiry_blocks}]")
        out = {"preflight": True, "expiry": p.expiry, "maxCum": str(p.max_amount), "minConf": pol.conf_for(p.capacity)}
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
            # AGP-084: an earlier spend the node has after all is this channel's close, before a new
            # close replaces its intent
            self._adopt_intent(st)
            # (AGP-088: nor with the kept intents full: this close is then the one already written ahead)
            if req.get("payload") and not st.closed_txid and not intents_full(st):   # after the close a state changes nothing (L10)
                self._apply(st, req["payload"])
            txid = self._close_locked(st)
            report = self._close_report(st)
        return {"chan": st.params.channel_id, "txid": txid, **report}

    def close_channel(self, chan: str) -> dict:
        """Close one channel now with the best signed state (AGP-059), exactly as the watcher does at
        the close margin (write-ahead intent, broadcast, record, hash-lock claim). Returns the
        cooperative close's answer: chan, txid, cum, unpaidMsat (and payeeFee/payeeNet under payee-pays).

        Refused with a ChannelError, nothing changed: unknown_channel; channel_closed (already closed
        or rolled over); call_in_flight (a paid call is being served: the best state does not cover
        it yet); no_state (nothing signed)."""
        st = self._channel(chan)
        with self.ledger.lock:
            if st.closed_txid:
                raise ChannelError("channel_closed", f"closed by {st.closed_txid}")
            if self._in_call.get(st.params.channel_id):
                raise ChannelError("call_in_flight", "a paid call is being served on this channel")
            if not (st.best_sig or st.cond_sig):
                raise ChannelError("no_state", "the payer has signed no state to close with")
            txid = st.closed_txid if self._adopt_intent(st) else self._close_locked(st)
            report = self._close_report(st)
        return {"chan": st.params.channel_id, "txid": txid, **report}

    def _adopt_intent(self, st: ChannelState) -> bool:
        """A close this provider sent and never recorded (M8: the intent is written ahead): record it.
        True when the channel is now closed by it. AGP-085: every unresolved intent is looked for, the
        latest first, not only the last one written."""
        from .tx import Tx
        for intent in intents(st):
            if not self._tx_known(intent["txid"], Tx.parse(bytes.fromhex(intent["hex"]))):
                continue
            self._closed(st, intent["hex"], intent["txid"], intent["cond"])
            if intent.get("next"):
                # a rollover (AGP-084): the next channel is the one this tx funds
                st.extra = {**st.extra, "rollover_to": intent["next"]}
                self.ledger.save(st)
            return True
        return False

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
            set_intent(st, {"hex": tx.hex(), "txid": txid, "cond": conditional})
            self.ledger.save(st)
            try:
                self.rpc.sendrawtransaction(tx.hex())
            except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                # AGP-067 (C1): refused alone (below the mempool's floor), it goes in with a child
                bumped, why = False, str(e)
                if self.close_bump_max_fee > 0:
                    try:
                        self._bump_close(st, self.height(), txid, tx, refused_alone=True)
                        bumped = True
                    except Exception as b:  # noqa: BLE001 - reported with the close's own refusal
                        why = f"{e}; bump: {b}"
                if not bumped and not self._tx_known(txid, tx):
                    raise ChannelError("close_failed", why)
            self._closed(st, tx.hex(), txid, conditional)
        return st.closed_txid

    # AGP-067 (review C1): the close-fee bump ------------------------------------------------
    def _estimate_fee_rate(self, target: int):
        """`estimatesmartfee` in sat/vB; None without an estimate (or a node that has no such call)."""
        if not hasattr(self.rpc, "estimatesmartfee"):
            return None
        try:
            f = (self.rpc.estimatesmartfee(target) or {}).get("feerate") or 0
        except Exception:  # noqa: BLE001 - no estimate: the floor and the doubling still apply
            return None
        return f * 1e8 / 1000 if f > 0 else None

    def _mempool_min_fee(self):
        """The least feerate the node's mempool takes now (sat/vB): max(mempoolminfee, minrelaytxfee)."""
        if not hasattr(self.rpc, "getmempoolinfo"):
            return None
        try:
            r = self.rpc.getmempoolinfo() or {}
        except Exception:  # noqa: BLE001 - unknown: the estimate and close_min_feerate still apply
            return None
        f = max(float(r.get("mempoolminfee") or 0), float(r.get("minrelaytxfee") or 0)) * 1e8 / 1000
        return f if f > 0 else None

    def _submit_package(self, hexes: list):
        """`submitpackage` (a parent below the floor gets in on its child's fee); a node without it:
        each in order, a refusal of the parent left to show as the child's missing input."""
        if not hasattr(self.rpc, "submitpackage"):
            for i, h in enumerate(hexes):
                try:
                    self.rpc.sendrawtransaction(h)
                except Exception:  # noqa: BLE001
                    if i + 1 == len(hexes):
                        raise
            return
        r = self.rpc.submitpackage(list(hexes)) or {}
        if r.get("package_msg") == "success":
            return
        errs = [t.get("error") for t in (r.get("tx-results") or {}).values() if isinstance(t, dict) and t.get("error")]
        raise ChannelError("rpc_error", f"submitpackage: {r.get('package_msg')} {'; '.join(errs)}")

    def _close_rate_wanted(self, p: ChannelParams, tip: int, last) -> float:
        """The package feerate (sat/vB) a close needs at `tip`: the estimate for confirming within a
        quarter of the blocks left to expiry, the mempool's floor and close_min_feerate, whichever is
        highest; doubled from the last send once close_bump_blocks passed without a confirmation in
        the second half of the close margin."""
        left = max(0, p.expiry - tip)
        want = self.close_min_feerate
        for r in (self._estimate_fee_rate(min(max(left // 4, 1), 1008)), self._mempool_min_fee()):
            if r:
                want = max(want, r)
        if last and tip >= int(last.get("at", 0)) + self.close_bump_blocks and left <= self.close_margin // 2:
            want = max(want, float(last.get("rate", 0)) * 2)
        return want

    def _bump_close(self, st: ChannelState, tip: int, txid: str, close, refused_alone: bool = False):
        """review C1: get the close `txid` confirmed before the payer's refund is valid. Each block (each
        call while it is not in the mempool) the close goes out alone if its own fee meets
        _close_rate_wanted, else with a CPFP child that spends this provider's close output back to the
        same key and pays the difference, replacing the last child (BIP125: the new one pays at least
        the old fee plus its own vsize). The child's fee is capped at close_bump_max_fee and at the
        output less dust. Recorded in extra["close_bump"] (at: the last send, rate, fee, the child's
        txid/hex, capped, replaced). `refused_alone`: the node just refused the close alone, so it is
        not sent alone again. The same as xbt-rs Provider::bump_close."""
        p = st.params
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, False) is None:
            return          # spent in a block: the close confirmed, or the channel is gone
        last = (st.extra or {}).get("close_bump")
        last = dict(last) if isinstance(last, dict) else None
        num = lambda k: int((last or {}).get(k) or 0)  # noqa: E731
        child_txid = (last or {}).get("txid") or ""
        # a node may still answer for an evicted close's txid: in the pool only while the funding is spent there
        in_pool = self._tx_known(txid, close) and self._funding_spent_in_pool(p)
        child_in_pool = bool(child_txid) and self._has_tx(child_txid)
        if last is not None and in_pool and (not child_txid or child_in_pool) and num("seen") == tip:
            return          # looked at this block already
        close_hex = close.hex()
        close_fee = max(0, p.capacity - sum(o.value for o in close.outputs))
        cv = close.vsize()
        want = self._close_rate_wanted(p, tip, last)
        have_fee, have_vs = (close_fee + num("fee"), cv + CPFP_CHILD_VSIZE) if child_in_pool else (close_fee, cv)
        rec = last or {"at": tip, "rate": close_fee / cv, "fee": 0}
        rec["seen"] = tip

        def put():
            st.extra = {**(st.extra or {}), "close_bump": rec}

        def send_alone():
            if refused_alone:
                raise ChannelError("close_failed", "the node refused the close alone")
            try:
                try:
                    self.rpc.sendrawtransaction(close_hex)
                except Exception as e:  # noqa: BLE001
                    if not self._tx_known(txid, close):
                        raise ChannelError("close_failed", str(e))
                rec["at"] = tip
            finally:
                put()

        if in_pool and have_fee >= want * have_vs:
            put()
            return
        payee = bytes.fromhex(p.payee_spk)
        vout = next((n for n, o in enumerate(close.outputs) if o.script_pubkey == payee), None)
        swept = "payee_sweep" in (st.extra or {}) or "payee_sweep_intent" in (st.extra or {})
        if vout is None or swept or close_fee >= want * cv:
            return send_alone()   # nothing of ours to spend, a sweep spends it, or enough alone
        value = close.outputs[vout].value
        fee = max(0, math.ceil(want * (cv + CPFP_CHILD_VSIZE)) - close_fee)
        last_fee = num("fee")
        if last_fee > 0:
            fee = max(fee, last_fee + CPFP_CHILD_VSIZE)
        cap = min(self.close_bump_max_fee, max(0, value - DUST))
        capped = fee > cap
        fee = min(fee, cap)
        if last_fee > 0 and fee <= last_fee:
            child_hex, child_id = rec.get("hex") or "", child_txid   # at the cap: the last child again
        else:
            child = cpfp_child(txid, vout, value, payee, self._chan_secret(p), fee)
            child_hex, child_id = child.hex(), child.txid()
        if not child_hex or fee == 0:
            return send_alone()
        try:
            self._submit_package([close_hex, child_hex])
        except Exception as e:  # noqa: BLE001
            put()
            raise ChannelError("close_bump_failed", str(e))
        if child_txid and child_id != child_txid:
            rec["replaced"] = list(rec.get("replaced") or []) + [[child_txid, last_fee]]
        fee = last_fee if child_id == child_txid else fee
        rec.update(at=tip, rate=(close_fee + fee) / (cv + CPFP_CHILD_VSIZE), fee=fee, txid=child_id, hex=child_hex,
                   capped=capped)
        put()

    def _funding_spent_in_pool(self, p) -> bool:
        try:
            return self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is None
        except Exception:  # noqa: BLE001 - unknown: send again (a resend of the same tx is harmless)
            return False

    def _has_tx(self, txid: str) -> bool:
        try:
            return bool(self.rpc.getrawtransaction(txid))
        except Exception:  # noqa: BLE001 - "No such mempool or blockchain transaction"
            return False

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
            from .tx import Tx
            close_hex = st.extra.get("close_hex") or self._close_tx(st)[0].hex()
            if self.close_bump_max_fee > 0:
                self._bump_close(st, h, st.closed_txid, Tx.parse(bytes.fromhex(close_hex)))
            elif self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is not None:
                # funding still unspent even counting the mempool: the close was evicted, send it again
                self.rpc.sendrawtransaction(close_hex)
            if st.extra.get("cond_close"):
                self._claim(st)           # the hash lock is ours only until csvDelta: retry every tick
            return
        if self._adopt_intent(st):               # sent, never recorded (M8)
            out.append(st.closed_txid)
            if st.extra.get("cond_close"):
                self._claim(st)
            return
        # AGP-084: a close the node answered with an error is sent again every tick. The channel takes
        # no state until then, so it is the same close. Never a rollover: its client was told it failed
        # and may no longer hold the next channel's key
        if intent_open(st) and not st.extra["close_intent"].get("next"):
            out.append(self._close_locked(st))
            if st.extra.get("cond_close"):
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
        """A CPFP child of this close paying `fee`, recorded in extra["close_bump"] as the watcher's own
        bump is (AGP-067), so the next bump replaces it rather than conflicting with it."""
        from .tx import Tx
        from .watcher import cpfp_from_close
        with self.ledger.lock:
            st = next((s for s in self.ledger.channels.values() if s.closed_txid == close_txid), None)
            if not st:
                raise ChannelError("unknown_channel", "no channel closed with that txid")
            secret = self._chan_secret(st.params)
            close_hex = (st.extra or {}).get("close_hex")
            if not close_hex:
                return cpfp_from_close(self.rpc, close_txid, st.params.payee_spk, secret, fee)
            close = Tx.parse(bytes.fromhex(close_hex))
            payee = bytes.fromhex(st.params.payee_spk)
            n = next((i for i, o in enumerate(close.outputs) if o.script_pubkey == payee), None)
            if n is None:
                raise ChannelError("no_payee_output", "the close pays nothing to the payee key")
            last = dict((st.extra or {}).get("close_bump") or {})
            child = cpfp_child(close_txid, n, close.outputs[n].value, payee, secret, int(fee))
            self._submit_package([close_hex, child.hex()])
            close_fee = max(0, st.params.capacity - sum(o.value for o in close.outputs))
            tip = self.height()
            if last.get("txid") and last["txid"] != child.txid():
                last["replaced"] = list(last.get("replaced") or []) + [[last["txid"], int(last.get("fee") or 0)]]
            last.update(at=tip, seen=tip, rate=(close_fee + int(fee)) / (close.vsize() + CPFP_CHILD_VSIZE), fee=int(fee),
                        txid=child.txid(), hex=child.hex(), capped=False)
            st.extra = {**st.extra, "close_bump": last}
            self.ledger.save(st)
            return child.txid()

    def _payee_found(self, st, close, vout: int) -> tuple:
        """(txid, vout, sats): the close's payee output `vout`, or the output of the CPFP child (the
        latest, or one it replaced) that moved it to the same key and that this node shows (AGP-067)."""
        base = close.outputs[vout].value
        from_txid, value = st.closed_txid, base
        bump = (st.extra or {}).get("close_bump") or {}
        if int(bump.get("fee") or 0) > 0:
            kids = [(bump.get("txid") or "", int(bump.get("fee") or 0))] + [(t, int(f)) for t, f in bump.get("replaced") or []]
            for kid, kfee in reversed([k for k in kids if k[0]]):
                if self.rpc.gettxout(kid, 0, True) is not None:
                    from_txid, vout, value = kid, 0, max(0, base - kfee)
        return from_txid, vout, value

    def payee_output(self, chan: str) -> Optional[tuple]:
        """AGP-104: where this closed channel's payout is now, (txid, vout, sats): the close's payee
        output, or the CPFP child's. None: the channel has no recorded close, or its close pays nothing
        to the payee key."""
        from .tx import Tx
        with self.ledger.lock:
            st = self.ledger.channels.get(canonical_chan(chan))
            if not st:
                raise ChannelError("unknown_channel")
            if not st.closed_txid or not (st.extra or {}).get("close_hex"):
                return None
            close = Tx.parse(bytes.fromhex(st.extra["close_hex"]))
            payee_spk = bytes.fromhex(st.params.payee_spk)
            vout = next((n for n, o in enumerate(close.outputs) if o.script_pubkey == payee_spk), None)
            return None if vout is None else self._payee_found(st, close, vout)

    def sweep_payee(self, chan: str, dest_spk: bytes, fee: int) -> dict:
        """Move this channel's payee close output, P2WPKH(P) with p = payTo_secret + t, to
        `dest_spk` (witness v0 only: P2WPKH or P2WSH), signed SIGHASH_ALL|UNIFIED (0x21). p is used
        here and never returned or written anywhere. Reads the close from the ledger (the exact close
        hex this provider sent), so it needs no txindex. Idempotent: a sweep already made is returned.

        AGP-104 rule: one signed sweep per output. A sweep written ahead (`payee_sweep_intent`) whose
        send failed is the one sent again, with the destination and fee it was signed for, whatever this
        call names: signing another would spend the same output twice."""
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
            from_txid, vout, value = self._payee_found(st, close, vout)
            intent = (st.extra or {}).get("payee_sweep_intent") or {}
            if intent.get("hex") and intent.get("outpoint") == f"{from_txid}:{vout}":
                tx = Tx.parse(bytes.fromhex(intent["hex"]))
                try:
                    self.rpc.sendrawtransaction(intent["hex"])
                except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                    if not self._tx_known(tx.txid(), tx):
                        raise ChannelError("sweep_failed", str(e))
                rec = {k: v for k, v in intent.items() if k != "hex"}
                st.extra = {**st.extra, "payee_sweep": rec}
                self.ledger.save(st)
                return rec
            if value - int(fee) < DUST:
                raise ChannelError("bad_amount", f"fee {fee} leaves dust from {value}")
            if self.rpc.gettxout(from_txid, vout, True) is None:
                raise ChannelError("payee_spent", "the payee output is spent or its close is not on this node")
            tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(from_txid)[::-1], vout, 0xFFFFFFFD)],
                    outputs=[TxOut(value - int(fee), dest_spk)], locktime=0)
            sign_p2wpkh(self._chan_secret(st.params), tx, [TxOut(value, payee_spk)])
            txid = tx.txid()
            rec = {"txid": txid, "outpoint": f"{from_txid}:{vout}", "value": value, "fee": int(fee),
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
                # (AGP-088: not once the kept intents are full: a higher state would make the watcher's
                # next close another transaction)
                if cum > st.best_cum and not st.closed_txid and not intents_full(st):
                    st.best_cum, st.best_sig = cum, pl["sig"]
                    self.ledger.save(st)
                # a VerifyResponse is what a resource server serves on: never isValid for a state this
                # channel can no longer settle (L11). A higher state is still kept while closing.
                if closing(st) or self.height() >= st.params.expiry - self.close_margin:
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
            # AGP-084: an earlier spend the node has after all is this channel's close, before this
            # rollover replaces its intent
            self._adopt_intent(st)
            if st.closed_txid:
                raise ChannelError("channel_closing", "already settled")
            if amount < st.best_cum:
                raise ChannelError("bad_amount", f"a rollover pays at least the best state {st.best_cum}")
            txid = tx.txid()
            if intents_full(st):
                # AGP-085: each one is kept until the chain settles it, and a client could ask without end.
                # AGP-088: one slot short of the bound, which the payee's own close may still need
                raise ChannelError("channel_closing", f"{MAX_KEPT_INTENTS - 1} earlier spends of this channel are unresolved: close it")
            set_intent(st, {"hex": tx.hex(), "txid": txid, "cond": False, "next": f"{txid}:1"})
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
        if "#" in path:                 # before anything is authenticated or routed (AGP-081, review T2)
            return 400, {}, FRAGMENT_REFUSED
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
        price = self.price(method, path)
        hdr = uh.get("PAYMENT-SIGNATURE")
        cond_offers = getattr(self, "_cond", {})
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
            if closing(st) or height >= st.params.expiry - self.close_margin:
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

    def http_server(self, port: int, max_per_address: int = MAX_PER_ADDRESS) -> ThreadingHTTPServer:
        """The reference HTTP server on 127.0.0.1:`port`. `max_per_address`: connections one client
        address may hold at once (address_key); 0 turns that cap off, for a server whose only peer is
        its reverse proxy (every connection then comes from the proxy's address)."""
        app = self

        class Bound(ThreadingHTTPServer):
            """At most MAX_CONNECTIONS reads at once, and at most `max_per_address` of them from one
            address (AGP-081: one address could hold all 64). A slow header or body holds a slot, not
            every worker, and the slot is released when the handler finishes (review T1)."""

            def __init__(self, addr, handler):
                super().__init__(addr, handler)
                self._open = 0
                self._by_address = {}
                self._lk = threading.Lock()

            def process_request(self, request, client_address):
                key = address_key(client_address[0])
                with self._lk:
                    if self._open >= MAX_CONNECTIONS or 0 < max_per_address <= self._by_address.get(key, 0):
                        try:
                            msg = b"too many connections"
                            request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n"
                                            b"Connection: close\r\n\r\n%s" % (len(msg), msg))
                        except OSError:
                            pass
                        request.close()
                        return
                    self._open += 1
                    self._by_address[key] = self._by_address.get(key, 0) + 1
                super().process_request(request, client_address)

            def release(self, client_address):
                key = address_key(client_address[0])
                with self._lk:
                    if self._open:
                        self._open -= 1
                    if self._by_address.get(key, 0) > 1:
                        self._by_address[key] -= 1
                    else:
                        self._by_address.pop(key, None)

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
                if "#" in self.path:                        # as serve does, before the body is read
                    return self._refuse(400, FRAGMENT_REFUSED)
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
                    self.server.release(self.client_address)

            def log_message(self, *a):
                pass

        return Bound(("127.0.0.1", port), H)


# --- client SDK -------------------------------------------------------------------------------
# Most earlier scripts of an open that was never funded kept per origin (XbtChannelClient.unfunded),
# as xbt-rs client::MAX_KEPT.
MAX_KEPT = 16


@dataclass
class ClientChannel:
    payer: Payer
    origin: str
    accepted: dict
    refund_hex: str = ""
    auth_key: bytes = b""        # without a signer; with one, the signer computes payload.auth
    price: int = 0               # sat per call agreed at open: a 402 may not raise it mid-channel
    # charges adopted over the channel's life that no request of ours accounts for: at most one call
    # (a request sent just before a crash, whose answer and count were both lost)
    slack_msat: int = 0
    seq: int = 0
    spent_msat: int = 0          # from the last verified receipt
    last_sig: str = ""           # our signature for payer.signed, resent until a receipt shows it arrived
    pending_cond: dict = field(default_factory=dict)   # {hash, cipher, amount} of a signed hash lock
    acked_cum: int = 0           # the provider's best cum per its last receipt
    receipts: list = field(default_factory=list)
    # How far the open has got (AGP-090, review C2; as xbt-rs client::Stage). "keyed": it has a key and
    # terms; its funding has not left, or the call that sends it has not answered. "funded": funded
    # and bound, the refund held; the provider has not answered the funded open. "open": the only
    # stage a state is signed in. A keyed channel without an outpoint is funded by a later call only
    # if the seller still offers its terms and it is not too near its expiry; else it moves to
    # XbtChannelClient.unfunded and a new one is derived (AGP-096).
    stage: str = "open"
    # What the paid requests the provider has not answered may have cost: one quote each, added when a
    # request leaves, taken off when the provider refuses it (a 402: not charged), cleared by a
    # verified receipt (AGP-090, review T4). An answer lost on the way, or one refused for its receipt,
    # leaves its request here: the provider may have served it, so its spent total may be ahead of
    # ours by this much (and by what is left of slack_msat's one call).
    unanswered_msat: int = 0
    # The wallet was asked to fund this channel (AGP-096): `fund` can fail after it sent, so the
    # channel may hold coins though no outpoint is known. Only such a channel is kept in
    # XbtChannelClient.unfunded when it is derived again; one the wallet never heard of is dropped.
    fund_tried: bool = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib then raises the 3xx as an HTTPError, which `http` returns."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT = urllib.request.build_opener(_NoRedirect)


def same_origin_url(origin: str, value) -> str:
    """AGP-080 X1: where a seller says its open or close endpoint is, held to the seller's own origin.
    `origin + value` let "@evil.example/open" name another host. Accepted: a path starting with exactly
    one "/", or an absolute URL on `origin`; no backslash, whitespace or control character either way,
    and no "#" (AGP-081, no_fragment). Anything else is refused before a request is made."""
    def refuse():
        return ChannelError("seller_url", "the seller's URL is not on its own origin; refused before any request")
    if not isinstance(value, str) or not value:
        raise refuse()
    if any(c in "\\#" or c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise refuse()
    if value.startswith("/") and not value.startswith("//"):
        return origin + value
    if not origin or url_origin(value) != origin:       # url_origin: "" for anything not absolute
        raise refuse()
    return value


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
                 signer=None, refunds: RefundCustody = None, daily_budget=0,
                 max_expiry_blocks=OWNER_MAX_EXPIRY_BLOCKS):
        self.network, self.fund, self.height = network, fund, height
        self.capacity, self.expiry_blocks, self.max_price = capacity, expiry_blocks, max_price
        self.max_close_fee, self.budget_sats = max_close_fee, budget_sats
        self.on_open, self.on_refund = on_open, on_refund
        self.signer, self.refunds = signer, refunds
        self.daily_budget, self.day_spent, self.day_start = daily_budget, 0, time.time()
        # the most blocks to expiry this client funds, whatever an offer asks for (AGP-090)
        self.max_expiry_blocks = max_expiry_blocks
        self.channels: Dict[str, ClientChannel] = {}
        # keyed channels that a later call could not fund as they were (too near their expiry, or on
        # terms the seller no longer offered) and derived again, per origin: `fund` can fail after it
        # sent, so their terms are kept (AGP-090, AGP-096). They all pay one key, the key of the
        # origin's next channel, so past MAX_KEPT the oldest script is forgotten and its key is not.
        self.unfunded: Dict[str, list] = {}
        self.opened_sats = 0

    @staticmethod
    def _read_capped(r, method: str = ""):
        """A body over the cap, or cut short of its Content-Length, is an error. Reading to the cap
        and returning the short buffer booked a truncated answer as the one paid for (review T3)."""
        declared = r.headers.get("Content-Length")
        n = int(declared) if declared and str(declared).isdigit() else None
        if n is not None and n > MAX_RESPONSE:
            raise ChannelError("response_too_large", f"response is {n} bytes; the cap is {MAX_RESPONSE}")
        out = r.read(MAX_RESPONSE + 1)
        if len(out) > MAX_RESPONSE:
            raise ChannelError("response_too_large", f"response exceeds {MAX_RESPONSE} bytes")
        status = getattr(r, "status", None)
        if status is None:
            status = r.code
        # an answer to a HEAD, and a 1xx, 204 or 304, has no body by its framing: its Content-Length
        # is the length a GET would get, so there is nothing to compare (AGP-090)
        bodiless = method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200
        if n is not None and len(out) != n and not bodiless:
            raise ChannelError("response_truncated", f"response body is {len(out)} of {n} bytes")
        return status, {k.upper(): v for k, v in r.headers.items()}, out

    @staticmethod
    def http(method, url, body=b"", headers=None, timeout=30):
        """One request, one answer. A 3xx is returned as the answer and never followed (AGP-080 X1, as
        the Rust transport): a payer that checked the origin against an allowlist must not be sent on
        to another host, least of all with its PAYMENT-SIGNATURE header. `timeout` is urllib's: for
        the connect and for each read, not for the whole answer."""
        req = urllib.request.Request(url, body or None, headers or {}, method=method)
        try:
            with _NO_REDIRECT.open(req, timeout=timeout) as r:
                return XbtChannelClient._read_capped(r, method)
        except urllib.error.HTTPError as e:
            return XbtChannelClient._read_capped(e, method)

    def _post(self, url, obj):
        st, _, out = self.http("POST", url, json.dumps(obj).encode(), {"Content-Type": "application/json"})
        data = json.loads(out)
        if st != 200:
            # the provider's words go in the message, never in the code an agent tool reports (L12)
            code = data.get("error") if isinstance(data, dict) else None
            raise ChannelError(code if safe_code(code) else "provider_error",
                               str(data.get("detail", "") if isinstance(data, dict) else data))
        return data

    def _preflight(self, url: str, channel: dict, fee_payer: str):
        """POST /open {"preflight": true} (no outpoint): a refusal (a stale payTo after a restart, terms
        out of the provider's policy) costs the payer nothing on-chain. A provider from before AGP-067
        answers bad_request (no vout) only after its terms checks passed: then fund and open as before."""
        try:
            r = self._post(url, {"x402Version": 2, "network": self.network, "preflight": True, "channel": channel})
        except ChannelError as e:
            if e.code == "bad_request":
                return
            raise
        if not isinstance(r, dict) or r.get("preflight") is not True:
            raise ChannelError("bad_open", "the provider did not answer the open preflight")
        if r.get("closeFeePayer", "payer") != fee_payer:
            raise ChannelError("bad_fee_payer", "the provider would open the channel with another closeFeePayer")

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

    def _ensure_open(self, origin: str, acc: dict) -> ClientChannel:
        """Bring `origin`'s channel to stage "open". Every open goes through here (a plain call, a
        conditional call, a retry after any failure).

        The rule (AGP-090, review C2; as xbt-rs Client::ensure_open): a channel's key is on the books
        before its funding leaves, its refund before the provider is asked to open it, and an origin
        that has a channel on the books is never funded a second time. The client used to keep a
        channel only after the provider answered the funded open: a seller that said yes to the
        preflight and no to the open (or an answer lost on the way) left the coins in a script whose
        only payer key had been dropped, and every later call funded another channel."""
        keyed_now = origin not in self.channels
        if keyed_now:
            self._key_channel(origin, acc)
        if self.channels[origin].stage == "keyed":
            self._fund_keyed(origin, acc, keyed_now)
        ch = self.channels[origin]
        if ch.stage == "funded":
            self._post_open(ch)
        return ch

    def _key_channel(self, origin: str, acc: dict):
        """Terms, a key and the preflight for a new channel, on the books before anything is funded."""
        ex = acc["extra"]
        fee_payer = ex.get("closeFeePayer", "payer")
        cap = max(self.capacity, int(ex["minCapacity"]))
        if cap > int(ex.get("maxCapacity", cap)) or self.opened_sats + cap > self.budget_sats:
            raise ChannelError("budget", "channel capacity outside provider range or our budget")
        # refused bad_offer, before a key is made or anything funded, on an offer without its terms
        # or one that asks for more blocks than the owner's bound
        blocks = offer_expiry_blocks(ex, self.expiry_blocks, self.max_expiry_blocks)
        open_url = same_origin_url(origin, ex["openUrl"])
        # One key for every channel derived for an origin until one is funded (AGP-096): a signer
        # answers the key it issued and has not bound, and a local key is read back from `unfunded`.
        # So no retry of an open makes a key that could be dropped.
        kept = self.unfunded.get(origin) or []
        if self.signer:
            pub = self.signer.new_key(origin)
            secret = None
        elif kept and kept[-1].payer.secret:
            secret = kept[-1].payer.secret
            pub = kept[-1].payer.params.payer_pub
        else:
            secret = secrets.randbelow(ecc.N - 1) + 1
            pub = ecc.pubkey(secret).hex()
        expiry = self.height() + blocks
        p = ChannelParams.derive(acc["payTo"], pub, expiry, int(ex["closeFeeSat"]), network=self.network,
                                 close_fee_payer=fee_payer)
        p.capacity = cap
        # review C2 (AGP-067): the provider's answer to these exact terms before anything is funded
        self._preflight(open_url, self._open_terms(p), fee_payer)
        payer = Payer(p, backend=self.signer) if self.signer else Payer(p, secret)
        ch = ClientChannel(payer, origin, acc, stage="keyed",
                           auth_key=b"" if self.signer else channel_auth_key(secret, bytes.fromhex(p.payee_pub)))
        ch.price = int(acc["amount"])
        self.channels[origin] = ch

    @staticmethod
    def _open_terms(p: ChannelParams) -> dict:
        """The `channel` object of an open request (the outpoint too, once `p` is funded)."""
        c = {"capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub, "payerSpk": p.payer_spk,
             "redeemScript": p.script.hex()}
        if p.close_fee_payer != "payer":
            c["closeFeePayer"] = p.close_fee_payer
        if p.funding_txid:
            c = {"txid": p.funding_txid, "vout": p.funding_vout, **c}
        return c

    def _fund_keyed(self, origin: str, acc: dict, keyed_now: bool):
        """Fund the keyed channel of `origin` (unless an earlier call did), bind it to its key and hold
        its refund: stage "funded", before the provider hears of the outpoint. `acc`: the offer of this
        call. `keyed_now`: this call derived the channel from it. A retry after a `fund` that raised
        pays the same script under the same key: `fund` is a bare callable here, so the client cannot
        ask the wallet whether the first call sent, and whatever it did is refundable with the key on
        the books."""
        ch = self.channels[origin]
        p = ch.payer.params
        if not p.funding_txid:
            if not keyed_now and not self._still_offered(origin, acc):
                # set aside as too old: the same offer, a new expiry, funded by this call
                self._key_channel(origin, acc)
                return self._fund_keyed(origin, acc, True)
            # The budget, on the day the coins leave (AGP-096): it was checked when the channel was
            # derived, and channels to other origins may have been funded since.
            if self.opened_sats + p.capacity > self.budget_sats:
                raise ChannelError("budget", "channel capacity outside our budget")
            fund = self.signer.fund if self.signer and getattr(self.signer, "fund", None) else self.fund
            ch.fund_tried = True
            txid, vout = fund(segwit_address(self.hrp_for(), p.spk), p.capacity)
            p.funding_txid, p.funding_vout = txid, vout
            self.opened_sats += p.capacity
        if self.signer:
            self.signer.attach(origin, p)
            ch.refund_hex = self.signer.sign_refund(p.channel_id)
        else:
            ch.refund_hex = p.refund_tx(ch.payer.secret).hex()
        if self.refunds:
            self.refunds.add(ch.refund_hex, p.expiry, p.channel_id)
        if self.on_refund:
            self.on_refund(ch.refund_hex, p.expiry)
        if self.on_open:
            self.on_open(ch)
        ch.stage = "funded"

    def _still_offered(self, origin: str, acc: dict) -> bool:
        """Whether the keyed channel of `origin`, derived by an earlier call and not funded since, is
        funded by this one: `acc`, the offer of this call, still describes it, the provider answers
        yes to its terms again, and it has the blocks a funding needs.

        The rule (AGP-096, audit items 6 and 18; as xbt-rs Client::still_offered): a channel is funded
        only on terms the seller offers and says yes to in the call that funds it, and a channel that
        holds no coins never stands between its origin and the next one. The preflight was asked
        once, when the channel was derived, so a later call funded it on the terms of that day: after
        a seller changed its payTo key the capacity was locked until the expiry. And a channel too
        near its expiry stayed on the books with a signer, or was refused for good after sixteen with
        a local key, so one failed `fund` call could end a payer's business with a seller.

        A channel that fails one of the three is set aside (`unfunded`); every channel derived after
        it pays the same key. Too near its expiry (offer_retry_floor) on an offer that is otherwise
        the same: False, and the caller derives it again and funds that in this call. Terms the
        seller changed or now refuses: the channel is derived again from this call's offer and the
        call fails open_unresolved with nothing funded; the next call funds it, after this same
        check. An answer that never came (anything but a ChannelError) says nothing about the terms:
        it goes back to the caller and the channel stays for the next call."""
        ch = self.channels[origin]
        p, ex = ch.payer.params, acc["extra"]
        now = ChannelParams.derive(acc["payTo"], p.payer_pub, p.expiry, int(ex["closeFeeSat"]), network=self.network,
                                   close_fee_payer=ex.get("closeFeePayer", "payer"))
        offered = (now.script == p.script and now.payee_spk == p.payee_spk and now.close_fee == p.close_fee
                   and now.close_fee_payer == p.close_fee_payer
                   and int(ex["minCapacity"]) <= p.capacity <= int(ex.get("maxCapacity", p.capacity))
                   # a price above the one pinned when the channel was derived would be refused on
                   # every call once it is open ("price raised mid-channel")
                   and int(acc["amount"]) <= (ch.price or int(ch.accepted["amount"])))
        if not offered:
            why = "the seller no longer offers its terms"
        elif p.expiry < self.height() + offer_retry_floor(ex):
            self._set_aside(origin)
            return False
        else:
            try:
                self._preflight(same_origin_url(origin, ex["openUrl"]), self._open_terms(p), p.close_fee_payer)
                return True
            except ChannelError as e:
                why = f"the seller refused its terms ({e.code})"
        self._set_aside(origin)
        try:
            # derived again now, so that the next call finds the channel it funds; a seller that
            # refuses the new terms too answers that call itself
            self._key_channel(origin, acc)
        except ChannelError:
            pass
        raise ChannelError("open_unresolved", f"an earlier open to {origin} was never funded and {why}: it is set "
                                              f"aside, nothing was funded, and the next call opens a new channel")

    def _set_aside(self, origin: str):
        """Take `origin`'s unfunded keyed channel off the books. If the wallet was asked to fund it, it
        moves to `unfunded`: the `fund` call that failed may have sent after all, so its terms are
        kept. If the wallet never heard of it, it is dropped (so a seller that changes its offer on
        every call fills nothing). Every channel derived for an origin pays one key, so past MAX_KEPT
        the oldest script goes and its key stays, in a newer record; a record with a key of its own is
        not dropped, except with a signer, whose keys are the signer's to keep."""
        ch = self.channels.pop(origin)
        if not ch.fund_tried:
            return
        kept = self.unfunded.setdefault(origin, [])
        if len(kept) >= MAX_KEPT:
            def pays(c, k):
                return c.payer.params.payer_pub == k.payer.params.payer_pub
            shared = [i for i, k in enumerate(kept) if any(pays(c, k) for c in kept[i + 1:] + [ch])]
            if shared or self.signer:
                del kept[shared[0] if shared else 0]
        kept.append(ch)

    def forget_unfunded(self, origin: str) -> int:
        """Drop the channels of `origin` that were never funded: the keyed one without an outpoint, and
        those in `unfunded`. Call it only when the wallet shows no send to their scripts: their keys
        go with them. Returns how many were dropped. Nothing needs it to go on paying (AGP-096): it
        only tidies the book."""
        origin = self._book_key(origin)
        n = len(self.unfunded.pop(origin, []))
        ch = self.channels.get(origin)
        if ch and ch.stage == "keyed" and not ch.payer.params.funding_txid:
            del self.channels[origin]
            n += 1
        return n

    def _book_key(self, origin: str) -> str:
        """The key of `origin` in the book: as given when a record is there under that spelling (an
        embedder that filled `channels` itself), else the origin as split_url reads it."""
        if origin in self.channels or origin in self.unfunded:
            return origin
        return canonical_origin(origin) or origin

    def _post_open(self, ch: ClientChannel):
        """Ask the provider to open the funded channel. Asked again on every call until it answers: a
        provider that already has the channel (its first answer was lost) says duplicate_channel,
        which is the yes that never arrived."""
        p = ch.payer.params
        try:
            r = self._post(same_origin_url(ch.origin, ch.accepted["extra"]["openUrl"]),
                           {"x402Version": 2, "network": self.network, "channel": self._open_terms(p)})
        except ChannelError as e:
            if e.code != "duplicate_channel":
                raise
            r = None
        if isinstance(r, dict) and r.get("closeFeePayer", "payer") != p.close_fee_payer:
            # a provider that did not take our terms would refuse every state we sign: stop before paying
            raise ChannelError("bad_fee_payer", "the provider opened the channel with another closeFeePayer")
        ch.stage = "open"

    def hrp_for(self) -> str:
        return "bc" if self.network == XBT_MAINNET else "bcrt"

    def _auth(self, ch: ClientChannel, pl: dict, method: str, bind: str, body: bytes) -> dict:
        """Add payload.auth for this request. With a signer the ECDH key never leaves it. `bind`:
        where the request goes, origin + path (request_digest_v2); a close's payload binds the empty
        request."""
        req = request_digest_v2(method, no_fragment(bind), body)
        if self.signer:
            pl["auth"] = self.signer.request_auth(pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        else:
            pl["auth"] = request_auth(ch.auth_key, pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        return pl

    def _payload(self, ch: ClientChannel, price: int, method: str = "", path: str = "", body: bytes = b"",
                 chosen: int | None = None) -> dict:
        if ch.stage != "open":
            # one choke point for every signature of a state: none before the provider opened it
            raise ChannelError("no_channel", "the channel is not open at the provider yet")
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
        if path:
            # a call (a close charges nothing): the provider may serve it whether or not its answer
            # reaches us, so its quote counts until a receipt says what was charged
            ch.unanswered_msat += (ch.price or int(ch.accepted["amount"])) * 1000
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
        sendable_url(no_fragment(url))
        origin, path = split_url(url)
        own = self._extra_headers(headers)
        ch = self.channels.get(origin)
        hdrs = {}
        if ch and ch.stage == "open":
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": ch.accepted,
                                                  "payload": self._payload(ch, int(ch.accepted["amount"]),
                                                                          method, path, body, cum)})}
        status, rh, out = self.http(method, url, body, {**own, **hdrs})
        if status == 402:
            if hdrs:
                self._refused(ch)
            pr = unb64json(rh["PAYMENT-REQUIRED"])
            acc = self._pick(pr)
            ch = self._ensure_open(origin, acc)
            if ch.price and int(acc["amount"]) > ch.price:
                raise ChannelError("bad_offer", f"price raised mid-channel: {ch.price} -> {acc['amount']} sat")
            ch.accepted = acc
            if "channel" in pr:
                # The provider's view of what it charged, unsigned. It may be ahead of our receipts by
                # the requests it never answered, at one quote each (AGP-090, review T4), plus the one
                # call of slack a channel has over its life. The slack alone was the bound, so a second
                # lost answer ended the channel in bad_offer. A request it refused with a 402 is not
                # among them: a provider that serves nothing can claim nothing (M3).
                claimed = int(pr["channel"]["spentMsat"])
                extra = max(0, claimed - ch.spent_msat)
                unproven = max(0, extra - ch.unanswered_msat)
                if unproven > 0 and ch.slack_msat + unproven > int(acc["amount"]) * 1000:
                    raise ChannelError("bad_offer", "provider claims charges we have no receipts for")
                ch.unanswered_msat -= extra - unproven
                ch.slack_msat += unproven
                ch.spent_msat = max(ch.spent_msat, claimed)
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc,
                                                  "payload": self._payload(ch, int(acc["amount"]), method, path, body,
                                                                          cum)})}
            status, rh, out = self.http(method, url, body, {**own, **hdrs})
            if status == 402:
                self._refused(ch)
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body, (status, out))
        elif hdrs:
            self._unreceipted(status)
        return status, rh, out

    @staticmethod
    def _refused(ch: ClientChannel, quote: int = None):
        """The provider answered the paid request just sent with a 402: by its own word it did not
        charge it."""
        ch.unanswered_msat = max(0, ch.unanswered_msat - (quote or ch.price or int(ch.accepted["amount"])) * 1000)

    @staticmethod
    def _unreceipted(status: int):
        """The answer to a request that carried a payment came without a PAYMENT-RESPONSE (AGP-081,
        review T4c). A success is refused: with the receipt stripped on the way, any body passed as
        the paid answer. An answer of 400 or above may have none (the provider's own failures carry
        no receipt): the caller returns it as it is and nothing is adopted from it."""
        if status < 400:
            raise ChannelError("bad_receipt", "paid call returned no receipt")

    def _receipt(self, ch: ClientChannel, resp: dict, method, path, body, answer, quote: int = None):
        """`answer` is the (status, body) the receipt came with: it must be the answer the provider
        signed for (AGP-068). `quote` is what this call may cost: the price pinned at open for a plain call, the
        conditional amount (already checked against max_price) for a conditional one. Never a
        quote the provider can raise afterwards (H6: a `conditional` quote in any 402 lifted the
        cap on plain calls)."""
        pinned = ch.price or int(ch.accepted["amount"])
        quote = quote or pinned
        r = receipt_of(resp)
        if resp.get("network") != self.network or resp.get("payer") != ch.payer.params.payer_pub:
            raise ChannelError("bad_receipt", "PAYMENT-RESPONSE is for another network or payer")
        if r["req"] != request_digest_v2(method, ch.origin + path, body):
            raise ChannelError("bad_receipt", "receipt is for another request")
        if type(r.get("seq")) is not int or r["seq"] != ch.seq:
            # The receipt of the request we just sent, and of no other (AGP-090, review T4): an identical
            # earlier request has the same digest, so whoever sits between could answer this one with
            # the earlier answer and its genuine receipt.
            raise ChannelError("bad_receipt", f"receipt is for seq {r.get('seq')!r}, this call was seq {ch.seq}")
        status = r.get("status")
        # An answer that has no body by its framing (to a HEAD, or a 204 or 304) is checked on its
        # status: the receipt's bodyHash is of the body the provider did not send (AGP-090).
        bodiless = not answer[1] and (str(method).upper() == "HEAD" or answer[0] in (204, 304))
        if type(status) is not int or status != answer[0] or (not bodiless and r.get("bodyHash") != body_hash(answer[1])):
            # a truncated or altered answer is not the one the provider signed for
            raise ChannelError("bad_receipt", "receipt is for another answer (status or body differs)")
        if not ecc.verify(bytes.fromhex(ch.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        if int(r["cum"]) > ch.payer.signed or int(r["charged"]) > quote:
            raise ChannelError("bad_receipt", "provider claims more than we signed or were quoted")
        if int(r["cum"]) < 0 or int(r["charged"]) < 0 or int(r["spentMsat"]) < 0:
            raise ChannelError("bad_receipt", "receipt amounts are not non-negative integers")
        # The spent total may have grown, since the last receipt we verified, by one quote for each
        # request the provider has not answered: this one and those whose answers were lost on the way
        # (AGP-090, review T4), plus what is left of the channel's one call of slack. It was held to one
        # call, so after one lost answer every later receipt was refused and the provider went on
        # charging for answers the payer threw away. A lost answer is paid for once, like the call it
        # answered; a request the provider refused is not paid for at all.
        unproven = max(0, int(r["spentMsat"]) - ch.spent_msat - ch.unanswered_msat)
        if unproven > 0 and ch.slack_msat + unproven > pinned * 1000:
            raise ChannelError("bad_receipt", "provider charged more than the calls we sent")
        ch.slack_msat += unproven
        ch.spent_msat = int(r["spentMsat"])
        ch.unanswered_msat = 0
        ch.acked_cum = max(ch.acked_cum, int(r["cum"]))
        ch.receipts.append(r)

    def close(self, origin: str, cum: int | None = None) -> dict:
        """Cooperative close; in postpay the final state pays exactly what is owed. `cum` (AGP-059):
        the caller's own final amount, under the bounds of `request`."""
        origin = self._book_key(origin)
        ch = self.channels[origin]
        pl = self._payload(ch, 0, chosen=cum)
        if self.signer:
            sig = self.signer.sign_close(ch.payer.params.channel_id)
        else:
            sig = ecc.sign(ch.payer.secret, close_message(ch.payer.params.channel_id)).hex()
        return self._post(same_origin_url(origin, ch.accepted["extra"]["closeUrl"]),
                          {"chan": ch.payer.params.channel_id, "sig": sig, "payload": pl})

    def _rollover(self, ch: ClientChannel):
        """Close whose payer output is the next channel's funding. Needs a live signer or secret."""
        origin, acc, ex = ch.origin, ch.accepted, ch.accepted["extra"]
        owed = max(ch.spent_msat // 1000, ch.payer.signed)
        if owed < ch.payer.params.min_amount:
            owed = ch.payer.params.min_amount
        expiry = self.height() + offer_expiry_blocks(ex, self.expiry_blocks, self.max_expiry_blocks)    # as an open: bad_offer first
        if self.signer:
            pub = self.signer.new_key(origin + "/next")
        else:
            secret2 = secrets.randbelow(ecc.N - 1) + 1
            pub = ecc.pubkey(secret2).hex()
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
        sendable_url(no_fragment(url))
        origin, path = split_url(url)
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
        ch = self._ensure_open(origin, acc)
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
        ch.unanswered_msat += cond_amt * 1000
        pl = {"chan": ch.payer.params.channel_id, "seq": ch.seq, "cum": str(uncond),
              "hashlock": extra["hash"], "sig": sig}
        self._auth(ch, pl, method, ch.origin + path, body)
        hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": pl})}
        status, rh, out = self.http(method, url, body, hdrs)
        if status == 402:                      # refused: the provider did not keep the conditional state
            ch.pending_cond = {}
            self._refused(ch, cond_amt)
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
        # while the hash lock is pending: after a bad_receipt, recover_conditional still reads k from
        # the provider's claim
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body, (status, out), cond_amt)
        else:
            self._unreceipted(status)
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
        pc = self.channels[self._book_key(origin)].pending_cond
        if not pc:
            raise ChannelError("no_state", "no pending conditional call on this channel")
        k = preimage_from_tx(tx, bytes.fromhex(pc["hash"]))
        if not k:
            raise ChannelError("bad_preimage", "this transaction does not reveal k")
        return decrypt(bytes.fromhex(pc["cipher"]), k)
