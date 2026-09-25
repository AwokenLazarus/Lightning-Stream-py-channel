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
          payload: {chan, seq, cum, sig?}})        sig = payer DER || 0x21 over the state for cum
  result: PAYMENT-RESPONSE: base64({success, scheme, network, chan, seq, cum, charged, spentMsat,
          owedMsat, creditMsat, expiry, req, sig})  sig = receipt by the channel payee key
  close:  POST extra.closeUrl {chan, sig, payload?}  sig = payer over tagged_hash("xbt402/close", chan);
          payload = a final state paying what is owed (postpay)
"""
import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

from . import ecc
from .channel import DUST, ChannelError, ChannelParams, Payee, Payer, channel_payee_secret
from .funding import FundingPolicy, check_funding
from .tx import segwit_address, tagged_hash

SCHEME = "xbt-channel"
XBT_MAINNET = "bip122:0000000000000050c1e5f69672f45929"   # block 961640, the first BLAKE2b block


def b64json(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def unb64json(s: str):
    return json.loads(base64.b64decode(s))


def request_digest(method: str, path: str, body: bytes) -> str:
    return hashlib.sha256(method.encode() + b"|" + path.encode() + b"|" + body).hexdigest()


def receipt_message(r: dict) -> bytes:
    keys = ("chan", "seq", "cum", "charged", "spentMsat", "req")
    return tagged_hash("xbt402/receipt", "|".join(str(r[k]) for k in keys).encode())


def close_message(chan: str) -> bytes:
    return tagged_hash("xbt402/close", chan.encode())


def network_id(first_blake2b_block_hash: str) -> str:
    return "bip122:" + first_blake2b_block_hash[:32]


# --- provider ---------------------------------------------------------------------------------
@dataclass
class ChannelState:
    params: ChannelParams
    best_cum: int = 0
    best_sig: str = ""
    seq: int = 0
    spent_msat: int = 0
    closed_txid: str = ""


class Ledger:
    """Latest (cum, sig) per channel, written atomically before a call is served. Prototype: one
    JSON file. Production: a DB row per channel (SQLite WAL / Postgres), keys in the B2 signer."""

    def __init__(self, path: str):
        self.path, self.lock = path, threading.Lock()
        self.channels: Dict[str, ChannelState] = {}
        if os.path.exists(path):
            with open(path) as f:
                for cid, d in json.load(f).items():
                    d["params"] = ChannelParams(**d["params"])
                    self.channels[cid] = ChannelState(**d)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({c: {**asdict(s), "params": s.params.to_dict()} for c, s in self.channels.items()}, f)
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
        ecc._decode_pub(bytes.fromhex(c["payerPub"]))
        p = ChannelParams.derive(self.pay_to, c["payerPub"], int(c["expiry"]), self.close_fee, c.get("payerSpk", ""))
        if c["redeemScript"] != p.script.hex():
            raise ChannelError("bad_funding", "redeemScript does not match payTo/payerPub/expiry")
        p.funding_txid, p.funding_vout, p.capacity = c["txid"], int(c["vout"]), int(c["capacity"])
        with self.ledger.lock:
            if p.channel_id in self.ledger.channels:
                raise ChannelError("duplicate_channel")
            confs = check_funding(self.rpc, p, self.policy)
            self.ledger.channels[p.channel_id] = ChannelState(p)
            self.ledger.save()
        return {"chan": p.channel_id, "expiry": p.expiry, "maxCum": str(p.max_amount), "confirmations": confs}

    def _payee(self, st: ChannelState) -> Payee:
        payee = Payee(st.params, channel_payee_secret(self.secret, bytes.fromhex(st.params.payer_pub), st.params.expiry))
        payee.best_amount, payee.best_sig = st.best_cum, bytes.fromhex(st.best_sig) if st.best_sig else b""
        return payee

    def _apply(self, st: ChannelState, pl: dict):
        """O(1) per call: at most one ECDSA verify and a few comparisons."""
        cum, seq = int(pl["cum"]), int(pl.get("seq", 0))
        if cum > st.best_cum:
            if "sig" not in pl:
                raise ChannelError("bad_sig", "a higher cum needs a signature")
            payee = self._payee(st)
            payee.accept(cum, bytes.fromhex(pl["sig"]))
            st.best_cum, st.best_sig = cum, pl["sig"]
        elif cum < st.best_cum:
            raise ChannelError("stale_amount", f"have {st.best_cum}, got {cum}")
        elif pl.get("sig") and pl["sig"] != st.best_sig:
            raise ChannelError("bad_sig", "signature differs from the stored state for this cum")
        st.seq = max(st.seq, seq)

    def close(self, req: dict) -> dict:
        with self.ledger.lock:
            st = self.ledger.channels.get(req["chan"])
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
            st.closed_txid = self.rpc.sendrawtransaction(self._payee(st).close_tx().hex())
            self.ledger.save()
        return st.closed_txid

    def close_due(self) -> list:
        """Watcher tick (every block): close channels that reached expiry - closeMarginBlocks."""
        h, out = self.rpc.getblockcount(), []
        with self.ledger.lock:
            for st in self.ledger.channels.values():
                if not st.closed_txid and st.best_sig and h >= st.params.expiry - self.close_margin:
                    out.append(self._close_locked(st))
        return out

    # paid requests ----------------------------------------------------------------------
    def serve(self, method: str, path: str, headers: dict, body: bytes, url: str = ""):
        if path.startswith("/x402/xbt-channel/"):
            action = {"/x402/xbt-channel/open": self.open, "/x402/xbt-channel/close": self.close}.get(path)
            if not action or method != "POST":
                return 404, {}, b"not found"
            try:
                return 200, {"Content-Type": "application/json"}, json.dumps(action(json.loads(body))).encode()
            except (ChannelError, KeyError, ValueError) as e:
                return 400, {"Content-Type": "application/json"}, json.dumps(
                    {"error": getattr(e, "code", "bad_request"), "detail": str(e)}).encode()
        url = url or path
        price = self.price(method, path)
        hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
        if not hdr:
            return self._payment_required(url, price, "payment_required")
        try:
            pp = unb64json(hdr)
            acc, pl = pp["accepted"], pp["payload"]
            if pp.get("x402Version") != 2 or acc.get("scheme") != SCHEME or acc.get("network") != self.network \
                    or acc.get("payTo") != self.pay_to:
                return self._payment_required(url, price, "unsupported_scheme_or_network")
        except (ValueError, KeyError, TypeError):
            return self._payment_required(url, price, "bad_payload")
        with self.ledger.lock:
            st = self.ledger.channels.get(pl.get("chan", ""))
            if not st:
                return self._payment_required(url, price, "unknown_channel")
            if st.closed_txid or self.height() >= st.params.expiry - self.close_margin:
                return self._payment_required(url, price, "channel_closing", st)
            try:
                self._apply(st, pl)
            except (ChannelError, ValueError) as e:
                return self._payment_required(url, price, getattr(e, "code", "bad_payload"), st)
            paid = st.best_cum * 1000
            need = st.spent_msat + (price * 1000 if self.billing == "prepay" else 0)
            if paid < need:
                return self._payment_required(url, price, "insufficient_payment", st)
            if st.spent_msat + price * 1000 > st.params.max_amount * 1000:
                return self._payment_required(url, price, "channel_exhausted", st)
            st.spent_msat += price * 1000        # reserve the max; refunded below if metered lower
            self.ledger.save()
        status, hdrs, out = self.handler(method, path, body)
        charged = price
        if self.charge:
            charged = max(0, min(price, int(self.charge(method, path, status, out))))
        with self.ledger.lock:
            st.spent_msat -= (price - charged) * 1000
            if status >= 500:                   # don't bill failed calls
                st.spent_msat -= charged * 1000
                charged = 0
            if charged != price:
                self.ledger.save()
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

            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                status, hdrs, out = app.serve(self.command, self.path, dict(self.headers), self.rfile.read(n),
                                              f"http://{self.headers.get('Host', '')}{self.path}")
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
    seq: int = 0
    spent_msat: int = 0          # from the last verified receipt
    receipts: list = field(default_factory=list)


class XbtChannelClient:
    """Payer SDK. `fund(address, sats) -> (txid, vout)` is the only wallet hook: in production it is
    the B2 agent-wallet MCP (policy-checked, 0x21-signed), so the SDK never holds funding keys. The
    per-channel payer key is created here; `on_refund(hex, expiry)` hands the refund to the wallet."""

    def __init__(self, network: str, fund: Callable[[str, int], tuple], height: Callable[[], int],
                 capacity=200_000, expiry_blocks=1_008, max_price=1_000, max_close_fee=2_000,
                 budget_sats=1_000_000, on_open: Callable = None, on_refund: Callable = None):
        self.network, self.fund, self.height = network, fund, height
        self.capacity, self.expiry_blocks, self.max_price = capacity, expiry_blocks, max_price
        self.max_close_fee, self.budget_sats = max_close_fee, budget_sats
        self.on_open, self.on_refund = on_open, on_refund
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
        secret = secrets.randbelow(ecc.N - 1) + 1
        blocks = min(max(self.expiry_blocks, int(ex["minExpiryBlocks"]) + 6), int(ex["maxExpiryBlocks"]) - 1)
        expiry = self.height() + blocks
        p = ChannelParams.derive(acc["payTo"], ecc.pubkey(secret).hex(), expiry, int(ex["closeFeeSat"]))
        txid, vout = self.fund(segwit_address(self.hrp_for(), p.spk), cap)
        p.funding_txid, p.funding_vout, p.capacity = txid, vout, cap
        self.opened_sats += cap
        ch = ClientChannel(Payer(p, secret), origin, acc, refund_hex=p.refund_tx(secret).hex())
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

    def _payload(self, ch: ClientChannel, price: int) -> dict:
        billing = ch.accepted["extra"].get("billing", "postpay")
        need_msat = ch.spent_msat + (price * 1000 if billing == "prepay" else 0)
        cum = max(-(-need_msat // 1000), ch.payer.signed)
        if 0 < cum < DUST:
            cum = DUST
        ch.seq += 1
        pl = {"chan": ch.payer.params.channel_id, "seq": ch.seq, "cum": str(cum)}
        if cum > ch.payer.signed:
            if cum > ch.payer.params.max_amount:
                raise ChannelError("exhausted", "channel capacity used up: close and reopen")
            pl["sig"] = ch.payer.sign_state(cum).hex()
        return pl

    def request(self, method: str, url: str, body: bytes = b""):
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        ch = self.channels.get(origin)
        hdrs = {}
        if ch:
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": ch.accepted,
                                                  "payload": self._payload(ch, int(ch.accepted["amount"]))})}
        status, rh, out = self.http(method, url, body, hdrs)
        if status == 402:
            pr = unb64json(rh["PAYMENT-REQUIRED"])
            acc = self._pick(pr)
            if not ch:
                ch = self._open(origin, acc)
                self.channels[origin] = ch
            ch.accepted = acc
            if "channel" in pr:   # provider's view: accept at most one extra call beyond our receipts
                claimed = int(pr["channel"]["spentMsat"])
                if claimed - ch.spent_msat > int(acc["amount"]) * 1000:
                    raise ChannelError("bad_offer", "provider claims charges we have no receipts for")
                ch.spent_msat = max(ch.spent_msat, claimed)
            hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc,
                                                  "payload": self._payload(ch, int(acc["amount"]))})}
            status, rh, out = self.http(method, url, body, hdrs)
        if "PAYMENT-RESPONSE" in rh:
            self._receipt(ch, unb64json(rh["PAYMENT-RESPONSE"]), method, path, body)
        return status, rh, out

    def _receipt(self, ch: ClientChannel, r: dict, method, path, body):
        if r["req"] != request_digest(method, path, body):
            raise ChannelError("bad_receipt", "receipt is for another request")
        if not ecc.verify(bytes.fromhex(ch.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        if int(r["cum"]) > ch.payer.signed or int(r["charged"]) > int(ch.accepted["amount"]):
            raise ChannelError("bad_receipt", "provider claims more than we signed or were quoted")
        if int(r["spentMsat"]) - ch.spent_msat > int(ch.accepted["amount"]) * 1000:
            raise ChannelError("bad_receipt", "provider charged more than one call")
        ch.spent_msat = int(r["spentMsat"])
        ch.receipts.append(r)

    def close(self, origin: str) -> dict:
        """Cooperative close; in postpay the final state pays exactly what is owed."""
        ch = self.channels[origin]
        pl = self._payload(ch, 0)
        sig = ecc.sign(ch.payer.secret, close_message(ch.payer.params.channel_id)).hex()
        return self._post(origin + ch.accepted["extra"]["closeUrl"],
                          {"chan": ch.payer.params.channel_id, "sig": sig, "payload": pl})
