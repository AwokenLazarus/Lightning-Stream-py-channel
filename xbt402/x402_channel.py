"""x402 v2 scheme `xbt-channel`: HTTP 402 payments over XBT Spillman channels.

Spec: ~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402 HTTP 402 payment channels.md

  402 + PAYMENT-REQUIRED: base64(PaymentRequired)      (same JSON in the body)
  PaymentRequired = {x402Version: 2, error?, resource: {url}, accepts: [PaymentRequirements]}
  PaymentRequirements = {scheme: "xbt-channel", network: "bip122:<first 32 hex of block 961640>",
      amount: "<sats per call, max>", asset: "XBT:sat", payTo: "<33-byte compressed pubkey hex>",
      maxTimeoutSeconds, extra: {minCapacity, maxCapacity, minExpiryBlocks, maxExpiryBlocks,
      closeMarginBlocks, minConf, closeFeeSat, openUrl, closeUrl, billing: "postpay"|"prepay"}}

  open:   POST extra.openUrl {x402Version, network, channel: {txid, vout, capacity, expiry, payerPub,
          payerSpk?, redeemScript}}  -> {chan, expiry, maxCum, confirmations}
  pay:    PAYMENT-SIGNATURE: base64({x402Version: 2, accepted: <requirements>,
          payload: {chan, seq, cum, sig?, auth}})  sig = payer DER || 0x21 over the state for cum
          auth = HMAC-SHA256(tagged_hash("xbt402/auth-key", ECDH(A, P)),
                 "xbt402/auth|chan|seq|cum|sig|sha256(method|path|body)"), seq above every earlier one
  result: PAYMENT-RESPONSE: base64({success, scheme, network, chan, seq, cum, charged, spentMsat,
          owedMsat, creditMsat, expiry, req, sig})  sig = receipt by the channel payee key
  close:  POST extra.closeUrl {chan, sig, payload?}  sig = payer over tagged_hash("xbt402/close", chan);
          payload = a final state paying what is owed (postpay)
  facilitator: GET /x402/supported, POST /x402/verify {payload}, POST /x402/settle (= close); only
          under /x402/, so a paid API keeps its own /verify, /settle and /supported routes
"""
import base64
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
from .channel import (DUST, ChannelError, ChannelParams, Payee, Payer, canonical_chan, channel_auth_key,
                      channel_payee_secret, check_payout_spk)
from .funding import FundingPolicy, check_funding
from .ledger import ChannelState, Ledger
from .tx import segwit_address, tagged_hash

SCHEME = "xbt-channel"
MAX_BODY = 1 << 20                                          # bytes per request body
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
                 charge: Callable = None, hrp: str = "bcrt", height_ttl: float = 2.0):
        if billing not in ("postpay", "prepay"):
            raise ValueError("billing is postpay or prepay")
        self.rpc, self.secret, self.network = rpc, pay_to_secret, network
        self.pay_to = ecc.pubkey(pay_to_secret).hex()
        self.ledger, self.price, self.handler, self.charge = Ledger(ledger_path), price, handler, charge
        self.billing, self.close_fee, self.close_margin, self.hrp = billing, close_fee, close_margin, hrp
        self.policy = policy or FundingPolicy(min_expiry_blocks=1_008, close_margin=close_margin)
        self._height, self._height_at, self.height_ttl = 0, 0.0, height_ttl
        self._auth_keys: Dict[str, bytes] = {}

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
                          "closeUrl": "/x402/xbt-channel/close", "billing": self.billing}}

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
        p = ChannelParams.derive(self.pay_to, payer_pub.hex(), int(c["expiry"]), self.close_fee, payer_spk)
        if c["redeemScript"].lower() != p.script.hex():
            raise ChannelError("bad_funding", "redeemScript does not match payTo/payerPub/expiry")
        chan = canonical_chan(f"{c['txid']}:{int(c['vout'])}")
        p.funding_txid, p.funding_vout, p.capacity = chan.split(":")[0], int(c["vout"]), int(c["capacity"])
        with self.ledger.lock:
            if p.channel_id in self.ledger.channels:
                raise ChannelError("duplicate_channel")
            confs = check_funding(self.rpc, p, self.policy)
            st = self.ledger.channels[p.channel_id] = ChannelState(p)
            self.ledger.save(st)
        return {"chan": p.channel_id, "expiry": p.expiry, "maxCum": str(p.max_amount), "confirmations": confs}

    def _payee(self, st: ChannelState) -> Payee:
        payee = Payee(st.params, channel_payee_secret(self.secret, bytes.fromhex(st.params.payer_pub), st.params.expiry))
        payee.best_amount, payee.best_sig = st.best_cum, bytes.fromhex(st.best_sig) if st.best_sig else b""
        return payee

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
                channel_payee_secret(self.secret, bytes.fromhex(p.payer_pub), p.expiry), bytes.fromhex(p.payer_pub))
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
        with self.ledger.lock:
            st = self.ledger.channels.get(canonical_chan(req["chan"]))
            if not st:
                raise ChannelError("unknown_channel")
            if not ecc.verify(bytes.fromhex(st.params.payer_pub), close_message(st.params.channel_id),
                              bytes.fromhex(req["sig"])):
                raise ChannelError("bad_sig", "close request not signed by the payer")
            if req.get("payload"):
                self._apply(st, req["payload"])
            owed = st.spent_msat - st.best_cum * 1000
            txid = self._close_locked(st)
        return {"chan": st.params.channel_id, "txid": txid, "cum": str(st.best_cum), "unpaidMsat": str(max(0, owed))}

    def _close_locked(self, st: ChannelState) -> str:
        if not st.closed_txid:
            try:
                st.closed_txid = self.rpc.sendrawtransaction(self._payee(st).close_tx().hex())
            except ChannelError:
                raise
            except Exception as e:  # noqa: BLE001 - node errors become protocol errors
                raise ChannelError("close_failed", str(e))
            self.ledger.save(st)
        return st.closed_txid

    def _watch_one(self, st: ChannelState, h: int, out: list):
        p = st.params
        if st.closed_txid:
            # funding still unspent even counting the mempool: the close was evicted, send it again
            if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is not None:
                self.rpc.sendrawtransaction(self._payee(st).close_tx().hex())
            return
        utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
        st.suspended = utxo is None or utxo.get("confirmations", 0) < self.policy.conf_for(p.capacity)
        if st.best_sig and h >= p.expiry - self.close_margin:
            out.append(self._close_locked(st))

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
            secret = channel_payee_secret(self.secret, bytes.fromhex(st.params.payer_pub), st.params.expiry)
        return cpfp_from_close(self.rpc, close_txid, st.params.payee_spk, secret, fee)

    def supported(self) -> dict:
        return {"kinds": [{"scheme": SCHEME, "network": self.network}]}

    def facilitator_verify(self, req: dict) -> dict:
        """Check (and keep, if higher) a signed state. Unauthenticated, so it needs a payer signature
        for exactly the cum it names, reports nothing the caller did not send, and never moves seq:
        otherwise it would tell anyone a channel's cum, or let them lock the payer out with a huge seq."""
        pl = req.get("payload") or req
        with self.ledger.lock:
            st = self.ledger.channels.get(canonical_chan(pl.get("chan")))
            if not st:
                raise ChannelError("unknown_channel")
            cum = int(pl["cum"])
            if not pl.get("sig"):
                raise ChannelError("bad_sig", "verify needs a signed state")
            self._payee(st).verify_state(cum, bytes.fromhex(pl["sig"]))
            if cum > st.best_cum:
                st.best_cum, st.best_sig = cum, pl["sig"]
                self.ledger.save(st)
            return {"valid": True, "chan": st.params.channel_id, "cum": str(cum)}

    def facilitator_settle(self, req: dict) -> dict:
        return self.close(req)

    def offer_conditional(self, path: str, price: int, plaintext: bytes):
        """Prepare a hash-locked deliverable for `path`. Returns (H, ciphertext, k)."""
        k = os.urandom(32)
        from .conditional import encrypt, sha256
        h = sha256(k)
        self._cond = getattr(self, "_cond", {})
        self._cond[path] = {"k": k, "h": h, "price": price, "cipher": encrypt(plaintext, k),
                            "plain": plaintext}
        return h, self._cond[path]["cipher"], k

    # paid requests ----------------------------------------------------------------------
    def serve(self, method: str, path: str, headers: dict, body: bytes, url: str = ""):
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
        if path.startswith("/x402/xbt-channel/"):
            action = {"/x402/xbt-channel/open": self.open, "/x402/xbt-channel/close": self.close}.get(path)
            if not action or method != "POST":
                return 404, {}, b"not found"
            try:
                return 200, {"Content-Type": "application/json"}, json.dumps(action(json.loads(body))).encode()
            except (ChannelError, KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
                return 400, {"Content-Type": "application/json"}, json.dumps(
                    {"error": getattr(e, "code", "bad_request"), "detail": str(e)}).encode()
        url = url or path
        price = self.price(method, path)
        hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
        cond_offers = getattr(self, "_cond", {})
        path_key = path.split("?", 1)[0]
        if not hdr:
            status, h, b = self._payment_required(url, price, "payment_required")
            if path_key in cond_offers:
                offer = json.loads(b)
                offer["accepts"][0]["extra"]["conditional"] = {
                    "hash": cond_offers[path_key]["h"].hex(), "amount": str(cond_offers[path_key]["price"]),
                    "csvDelta": 10,
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
                try:
                    if bytes.fromhex(pl["hashlock"]) != offer["h"]:
                        return refuse("bad_hashlock")
                    cond = ConditionalParams(st.params, offer["h"], offer["price"])
                    tx = cond.state_tx(st.best_cum)
                    sig = bytes.fromhex(pl["sig"])
                except (ChannelError, ValueError, TypeError, KeyError) as e:
                    return refuse(getattr(e, "code", "bad_payload"))
                if not sig or sig[-1] != 0x21 or not ecc.verify(bytes.fromhex(st.params.payer_pub),
                                                                cond.sighash(tx), sig[:-1]):
                    return refuse("bad_sig")
                st.cond_hash, st.cond_amount, st.cond_sig = offer["h"].hex(), offer["price"], pl["sig"]
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
            r = {"success": status < 400, "scheme": SCHEME, "network": self.network, "chan": st.params.channel_id,
                 "seq": st.seq, "cum": str(st.best_cum), "charged": str(charged), "spentMsat": str(st.spent_msat),
                 "owedMsat": str(max(0, st.spent_msat - st.best_cum * 1000)),
                 "creditMsat": str(max(0, st.best_cum * 1000 - st.spent_msat)), "expiry": st.params.expiry,
                 "req": request_digest(method, path, body)}
            secret = channel_payee_secret(self.secret, bytes.fromhex(st.params.payer_pub), st.params.expiry)
        r["sig"] = ecc.sign(secret, receipt_message(r)).hex()
        hdrs = dict(hdrs)
        hdrs["PAYMENT-RESPONSE"] = b64json(r)
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
                if len(cl) != 1 or not cl[0].isdigit() or int(cl[0]) > MAX_BODY:
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
            raise ChannelError(data.get("error", "http_error"), data.get("detail", ""))
        return data

    def _pick(self, pr: dict) -> dict:
        for acc in pr.get("accepts", []):
            if acc.get("scheme") == SCHEME and acc.get("network") == self.network:
                if int(acc["amount"]) > self.max_price:
                    raise ChannelError("too_expensive", f"{acc['amount']} sat > max {self.max_price}")
                if int(acc["extra"]["closeFeeSat"]) > self.max_close_fee:
                    raise ChannelError("bad_offer", "closeFeeSat above our cap")
                return acc
        raise ChannelError("no_scheme", f"no {SCHEME} offer on {self.network}")

    def _open(self, origin: str, acc: dict) -> ClientChannel:
        ex = acc["extra"]
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
        p = ChannelParams.derive(acc["payTo"], pub, expiry, int(ex["closeFeeSat"]))
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
        self._post(origin + ex["openUrl"], {"x402Version": 2, "network": self.network, "channel": {
            "txid": txid, "vout": vout, "capacity": cap, "expiry": expiry, "payerPub": p.payer_pub,
            "payerSpk": p.payer_spk, "redeemScript": p.script.hex()}})
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
        if 0 < cum < DUST:
            cum = DUST
        if self.daily_budget and time.time() - self.day_start > 86400:
            self.day_spent, self.day_start = 0, time.time()
        if self.daily_budget and self.day_spent + cum - ch.payer.signed > self.daily_budget:
            raise ChannelError("budget", "daily budget exhausted")
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
            pl["sig"] = ch.payer.sign_state(cum).hex()
            self.day_spent += max(0, delta)
        return self._auth(ch, pl, method, path, body)

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

    def _receipt(self, ch: ClientChannel, r: dict, method, path, body):
        if r["req"] != request_digest(method, path, body):
            raise ChannelError("bad_receipt", "receipt is for another request")
        if not ecc.verify(bytes.fromhex(ch.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        quote = int(ch.accepted["amount"])
        cond = (ch.accepted.get("extra") or {}).get("conditional") or {}
        if cond.get("amount"):
            quote = max(quote, int(cond["amount"]))
        if int(r["cum"]) > ch.payer.signed or int(r["charged"]) > quote:
            raise ChannelError("bad_receipt", "provider claims more than we signed or were quoted")
        if int(r["spentMsat"]) - ch.spent_msat > quote * 1000:
            raise ChannelError("bad_receipt", "provider charged more than one call")
        ch.spent_msat = int(r["spentMsat"])
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
        if owed < DUST:
            owed = DUST
        if self.signer:
            pub = self.signer.new_key(origin + "/next")
        else:
            secret2 = secrets.randbelow(ecc.N - 1) + 1
            pub = ecc.pubkey(secret2).hex()
        expiry = self.height() + min(max(self.expiry_blocks, int(ex["minExpiryBlocks"]) + 6),
                                     int(ex["maxExpiryBlocks"]) - 1)
        nxt = ChannelParams.derive(acc["payTo"], pub, expiry, int(ex["closeFeeSat"]))
        next_cap = min(self.capacity, ch.payer.params.capacity - owed - ch.payer.params.close_fee)
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
        if not ch:
            ch = self._open(origin, acc)
            self.channels[origin] = ch
        if ch.price and int(acc["amount"]) > ch.price:
            raise ChannelError("bad_offer", f"price raised mid-channel: {ch.price} -> {acc['amount']} sat")
        ch.accepted = acc
        h = bytes.fromhex(extra["hash"])
        cond_amt = int(extra["amount"])
        cond = ConditionalParams(ch.payer.params, h, cond_amt, int(extra.get("csvDelta", 10)))
        uncond = ch.payer.signed
        tx = cond.state_tx(uncond)
        if self.signer:
            sig = self.signer.sign_conditional(ch.payer.params.channel_id, uncond, cond)
        else:
            sig = (ecc.sign(ch.payer.secret, cond.sighash(tx)) + bytes([0x21])).hex()
        ch.seq += 1
        pl = {"chan": ch.payer.params.channel_id, "seq": ch.seq, "cum": str(uncond),
              "hashlock": extra["hash"], "sig": sig}
        self._auth(ch, pl, method, path, body)
        hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": pl})}
        status, rh, out = self.http(method, url, body, hdrs)
        data = json.loads(out)
        k = bytes.fromhex(data["preimage"])
        if sha256(k) != h:
            raise ChannelError("bad_preimage", "provider preimage does not match H")
        plain = decrypt(bytes.fromhex(data["cipher"]), k)
        # upgrade: fold the increment into an unconditional state
        new_cum = max(uncond + cond_amt, DUST)
        if new_cum > ch.payer.signed:
            ch.payer.sign_state(new_cum)
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body)
        return status, rh, out, plain
