"""xbt402 over HTTP: challenge/credential headers, a stdlib server, and a client SDK.

Wire format (spec: Research/P-003/B1 xbt402 HTTP 402 payment channels.md):

  402 Payment Required
  WWW-Authenticate: XBT402 realm="demo", network="xbt-regtest", price_msat="250000",
                    open="/xbt402/open", min_capacity="20000", min_expiry="144",
                    max_expiry="8640", min_conf="1", fee_rate="2"

  Authorization: XBT402 channel="<txid>:<vout>", amount="<cumulative sats>", sig="<hex>"
  (sig optional while the channel has credit)

  XBT402-Receipt: channel="..", amount="..", spent_msat="..", credit_msat="..",
                  expiry="..", req="<sha256 of method|path|body>", sig="<payee sig>"
"""
import hashlib
import json
import os
import re
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

from . import ecc
from .channel import ChannelError, ChannelParams, Payee, Payer
from .funding import FundingPolicy, check_funding
from .tx import tagged_hash

SCHEME = "XBT402"
_PARAM = re.compile(r'([a-z_]+)="([^"]*)"')


def format_params(params: Dict[str, object]) -> str:
    return ", ".join(f'{k}="{v}"' for k, v in params.items())


def parse_params(header: str) -> Dict[str, str]:
    if not header or not header.startswith(SCHEME + " "):
        return {}
    return dict(_PARAM.findall(header[len(SCHEME) + 1:]))


def request_digest(method: str, path: str, body: bytes) -> bytes:
    return hashlib.sha256(method.encode() + b"|" + path.encode() + b"|" + body).digest()


def receipt_message(r: Dict[str, str]) -> bytes:
    fields = "|".join(r[k] for k in ("channel", "amount", "spent_msat", "credit_msat", "req"))
    return tagged_hash("xbt402/receipt", fields.encode())


def close_message(channel: str) -> bytes:
    return tagged_hash("xbt402/close", channel.encode())


# --- server ---------------------------------------------------------------------------------
@dataclass
class ChannelState:
    params: ChannelParams
    payee_secret: int
    best_amount: int = 0
    best_sig: str = ""
    spent_msat: int = 0
    closed_txid: str = ""

    @property
    def credit_msat(self) -> int:
        return self.best_amount * 1000 - self.spent_msat


class Ledger:
    """Channel states, persisted atomically on every change (losing the best state = losing
    revenue). Prototype: one JSON file; production: SQLite/Postgres row per channel with the
    payee key in the B2 signer, not in this file."""

    def __init__(self, path: str):
        self.path, self.lock = path, threading.Lock()
        self.pending: Dict[str, ChannelState] = {}   # keyed by payee_pub, before funding
        self.channels: Dict[str, ChannelState] = {}  # keyed by channel id
        if os.path.exists(path):
            for cid, d in json.load(open(path)).items():
                d["params"] = ChannelParams(**d["params"])
                self.channels[cid] = ChannelState(**d)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({cid: {**s.__dict__, "params": s.params.to_dict()} for cid, s in self.channels.items()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


class Xbt402Server:
    """Payee middleware: wraps a handler `(method, path, body) -> (status, headers, body)` and
    charges `price_msat(method, path)` per request through channels on `rpc`."""

    def __init__(self, rpc, payee_wallet_rpc, ledger_path: str, price_msat: Callable[[str, str], int],
                 handler: Callable, realm="xbt402-demo", network="xbt-regtest", fee_rate=2,
                 policy: FundingPolicy = None, hrp="bcrt"):
        self.rpc, self.wallet, self.hrp = rpc, payee_wallet_rpc, hrp
        self.ledger = Ledger(ledger_path)
        self.price_msat, self.handler = price_msat, handler
        self.realm, self.network, self.fee_rate = realm, network, fee_rate
        self.policy = policy or FundingPolicy()

    def challenge(self, price: int) -> str:
        p = self.policy
        return f"{SCHEME} " + format_params({
            "realm": self.realm, "network": self.network, "price_msat": price, "open": "/xbt402/open",
            "min_capacity": p.min_capacity, "min_expiry": p.min_expiry_blocks,
            "max_expiry": p.max_expiry_blocks, "min_conf": p.min_conf, "fee_rate": self.fee_rate})

    # control endpoints ------------------------------------------------------------------
    def open(self, req: dict) -> dict:
        """Step 1: payer proposes key, change script and expiry; payee answers with a fresh key."""
        from .tx import address_to_spk, segwit_address
        secret = secrets.randbelow(ecc.N - 1) + 1
        p = ChannelParams(payer_pub=req["payer_pub"], payee_pub=ecc.pubkey(secret).hex(),
                          expiry=int(req["expiry"]), payer_spk=req["payer_spk"],
                          payee_spk=address_to_spk(self.wallet.getnewaddress("", "bech32")).hex(),
                          fee_rate=self.fee_rate)
        ecc._decode_pub(bytes.fromhex(p.payer_pub))  # on-curve compressed key
        p.script  # validates expiry encoding
        with self.ledger.lock:
            self.ledger.pending[p.payee_pub] = ChannelState(p, secret)
        return {**p.to_dict(), "address": segwit_address(self.hrp, p.spk), "witness_script": p.script.hex()}

    def fund(self, req: dict) -> dict:
        """Step 2: payer reports the funding outpoint; payee checks it on its own node."""
        with self.ledger.lock:
            st = self.ledger.pending.get(req["payee_pub"])
            if not st:
                raise ChannelError("unknown_open", "call /xbt402/open first")
            p = st.params
            p.funding_txid, p.funding_vout, p.capacity = req["funding_txid"], int(req["funding_vout"]), int(req["capacity"])
            confs = check_funding(self.rpc, p, self.policy)
            del self.ledger.pending[p.payee_pub]
            self.ledger.channels[p.channel_id] = st
            self.ledger.save()
        return {"channel": p.channel_id, "confirmations": confs, "expiry": p.expiry, "max_amount": p.max_amount}

    def close(self, req: dict) -> dict:
        """Cooperative close, requested by the payer (signed so third parties can't force it)."""
        cid = req["channel"]
        with self.ledger.lock:
            st = self.ledger.channels.get(cid)
            if not st:
                raise ChannelError("unknown_channel")
            if not ecc.verify(bytes.fromhex(st.params.payer_pub), close_message(cid), bytes.fromhex(req["sig"])):
                raise ChannelError("bad_sig", "close request not signed by the payer")
            return {"channel": cid, "txid": self._close_locked(st)}

    def _close_locked(self, st: ChannelState) -> str:
        if st.closed_txid:
            return st.closed_txid
        payee = Payee(st.params, st.payee_secret)
        payee.best_amount, payee.best_sig = st.best_amount, bytes.fromhex(st.best_sig)
        st.closed_txid = self.rpc.sendrawtransaction(payee.close_tx().hex())
        self.ledger.save()
        return st.closed_txid

    def close_due(self) -> list:
        """Watcher tick: close every channel within close_margin of expiry (run each block)."""
        h, out = self.rpc.getblockcount(), []
        with self.ledger.lock:
            for st in self.ledger.channels.values():
                if not st.closed_txid and st.best_sig and h >= st.params.expiry - self.policy.close_margin:
                    out.append(self._close_locked(st))
        return out

    # paid requests ----------------------------------------------------------------------
    def serve(self, method: str, path: str, headers: dict, body: bytes):
        if path.startswith("/xbt402/"):
            action = {"/xbt402/open": self.open, "/xbt402/fund": self.fund, "/xbt402/close": self.close}.get(path)
            if not action or method != "POST":
                return 404, {}, b"not found"
            try:
                return 200, {"Content-Type": "application/json"}, json.dumps(action(json.loads(body))).encode()
            except (ChannelError, KeyError, ValueError) as e:
                return 400, {"Content-Type": "application/json"}, json.dumps(
                    {"error": getattr(e, "code", "bad_request"), "detail": str(e)}).encode()
        price = self.price_msat(method, path)
        cred = parse_params(headers.get("Authorization", ""))
        if not cred:
            return self._payment_required(price, "payment_required")
        with self.ledger.lock:
            st = self.ledger.channels.get(cred.get("channel", ""))
            if not st:
                return self._payment_required(price, "unknown_channel")
            if st.closed_txid or self.rpc.getblockcount() >= st.params.expiry - self.policy.close_margin:
                return self._payment_required(price, "channel_closing")
            if "sig" in cred:
                try:
                    payee = Payee(st.params, st.payee_secret)
                    payee.best_amount, payee.best_sig = st.best_amount, bytes.fromhex(st.best_sig)
                    payee.accept(int(cred["amount"]), bytes.fromhex(cred["sig"]))
                    st.best_amount, st.best_sig = payee.best_amount, payee.best_sig.hex()
                except (ChannelError, ValueError) as e:
                    return self._payment_required(price, getattr(e, "code", "bad_credential"), st)
            if st.credit_msat < price:
                return self._payment_required(price, "insufficient_credit", st)
            st.spent_msat += price       # charge before serving; the state is already persisted-safe
            self.ledger.save()
            receipt_state = (st.params.channel_id, st.best_amount, st.spent_msat, st.credit_msat, st.params.expiry)
        status, hdrs, out = self.handler(method, path, body)
        hdrs = dict(hdrs)
        hdrs["XBT402-Receipt"] = self._receipt(*receipt_state, request_digest(method, path, body), st)
        return status, hdrs, out

    def _receipt(self, cid, amount, spent, credit, expiry, digest, st) -> str:
        r = {"channel": cid, "amount": str(amount), "spent_msat": str(spent), "credit_msat": str(credit),
             "expiry": str(expiry), "req": digest.hex()}
        r["sig"] = ecc.sign(st.payee_secret, receipt_message(r)).hex()
        return format_params(r)

    def _payment_required(self, price, code, st: Optional[ChannelState] = None):
        hdrs = {"WWW-Authenticate": self.challenge(price), "Content-Type": "application/json"}
        body = {"error": code, "price_msat": price}
        if st:
            body.update(channel=st.params.channel_id, amount=st.best_amount, spent_msat=st.spent_msat,
                        credit_msat=st.credit_msat)
        return 402, hdrs, json.dumps(body).encode()

    def http_server(self, port: int) -> ThreadingHTTPServer:
        app = self

        class H(BaseHTTPRequestHandler):
            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                status, hdrs, out = app.serve(self.command, self.path, dict(self.headers), self.rfile.read(n))
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


# --- client SDK -----------------------------------------------------------------------------
@dataclass
class OpenChannel:
    payer: Payer
    base: str
    spent_msat: int = 0          # what the client believes it has been charged
    last_price: int = 0          # sign ahead with the last quoted price: one round trip per request
    receipts: list = field(default_factory=list)


class Xbt402Client:
    """Payer SDK. `fund(address, sats) -> (txid, vout)` is the only wallet hook: in production it
    is the B2 agent-wallet MCP (policy-checked), so this SDK never holds the funding keys.
    The per-channel payer key is generated here and never leaves the process."""

    def __init__(self, fund: Callable[[str, int], tuple], change_spk: str, height: Callable[[], int],
                 capacity=100_000, expiry_blocks=1_008, max_price_msat=1_000_000, budget_sats=1_000_000,
                 max_fee_rate=10):
        self.fund, self.change_spk, self.height = fund, change_spk, height
        self.capacity, self.expiry_blocks = capacity, expiry_blocks
        self.max_price_msat, self.budget_sats, self.max_fee_rate = max_price_msat, budget_sats, max_fee_rate
        self.channels: Dict[str, OpenChannel] = {}   # by origin
        self.opened_sats = 0

    @staticmethod
    def _http(method, url, body=b"", headers=None):
        req = urllib.request.Request(url, body or None, headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def _post(self, base, path, obj):
        st, _, out = self._http("POST", base + path, json.dumps(obj).encode(), {"Content-Type": "application/json"})
        data = json.loads(out)
        if st != 200:
            raise ChannelError(data.get("error", "http_error"), data.get("detail", ""))
        return data

    def _open(self, base: str, ch: Dict[str, str]) -> OpenChannel:
        if self.opened_sats + self.capacity > self.budget_sats:
            raise ChannelError("budget", "opening another channel would exceed the budget")
        secret = secrets.randbelow(ecc.N - 1) + 1
        min_exp = int(ch.get("min_expiry", 144))
        expiry = self.height() + max(self.expiry_blocks, min_exp + int(ch.get("close_margin", 36)) + 6)
        offer = self._post(base, ch.get("open", "/xbt402/open"),
                           {"payer_pub": ecc.pubkey(secret).hex(), "payer_spk": self.change_spk, "expiry": expiry})
        params = ChannelParams(**{k: offer[k] for k in ChannelParams.__dataclass_fields__})
        if params.payer_pub != ecc.pubkey(secret).hex() or params.payer_spk != self.change_spk \
                or params.expiry != expiry or offer["witness_script"] != params.script.hex():
            raise ChannelError("bad_offer", "payee altered the channel terms")
        if params.fee_rate > self.max_fee_rate:
            raise ChannelError("bad_offer", "close fee rate above our cap (fee griefing)")
        txid, vout = self.fund(offer["address"], self.capacity)
        params.funding_txid, params.funding_vout, params.capacity = txid, vout, self.capacity
        self.opened_sats += self.capacity
        oc = OpenChannel(Payer(params, secret), base)
        oc.refund_hex = params.refund_tx(secret).hex()   # hand to the wallet: valid at expiry
        oc.fund_request = {"payee_pub": params.payee_pub, "funding_txid": txid,
                           "funding_vout": vout, "capacity": self.capacity}
        return oc

    def activate(self, oc: OpenChannel):
        return self._post(oc.base, "/xbt402/fund", oc.fund_request)

    def request(self, method: str, url: str, body: bytes = b"", on_open=None):
        """Do a request, paying through a channel. `on_open(oc)` runs after funding (e.g. to wait
        for confirmations) before the channel is registered with the payee."""
        base = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        oc = self.channels.get(base)
        headers = {}
        if oc:
            headers = self._credential(oc, oc.last_price or None)
        status, hdrs, out = self._http(method, url, body, headers)
        for _ in range(2):
            if status != 402:
                break
            ch = parse_params(hdrs.get("WWW-Authenticate", ""))
            price = int(ch.get("price_msat", "0"))
            if price > self.max_price_msat:
                raise ChannelError("too_expensive", f"price {price} msat above max {self.max_price_msat}")
            if oc:
                oc.last_price = price
            if not oc:
                oc = self._open(base, ch)
                if on_open:
                    on_open(oc)
                self.activate(oc)
                oc.last_price = price
                self.channels[base] = oc
            headers = self._credential(oc, price)
            status, hdrs, out = self._http(method, url, body, headers)
        if status != 402 and "XBT402-Receipt" in hdrs:
            self._check_receipt(oc, parse_params(SCHEME + " " + hdrs["XBT402-Receipt"]), method, path, body)
        return status, hdrs, out

    def _credential(self, oc: OpenChannel, price: Optional[int]) -> Dict[str, str]:
        p = oc.payer.params
        cred = {"channel": p.channel_id, "amount": oc.payer.signed}
        if price is not None:
            # pay exactly what is needed: cumulative must cover what we've been charged + price
            need_sats = -(-(oc.spent_msat + price) // 1000)
            amount = max(need_sats, oc.payer.signed, 546)
            if amount > p.max_amount:
                raise ChannelError("exhausted", "channel capacity used up: close and reopen")
            if amount > oc.payer.signed:
                cred = {"channel": p.channel_id, "amount": amount, "sig": oc.payer.sign_state(amount).hex()}
        return {"Authorization": f"{SCHEME} " + format_params(cred)}

    def _check_receipt(self, oc: OpenChannel, r: Dict[str, str], method, path, body):
        if r.get("req") != request_digest(method, path, body).hex():
            raise ChannelError("bad_receipt", "receipt is for another request")
        if not ecc.verify(bytes.fromhex(oc.payer.params.payee_pub), receipt_message(r), bytes.fromhex(r["sig"])):
            raise ChannelError("bad_receipt", "receipt not signed by the payee")
        if int(r["amount"]) > oc.payer.signed:
            raise ChannelError("bad_receipt", "payee claims more than we signed")
        oc.spent_msat = int(r["spent_msat"])
        oc.receipts.append(r)

    def close(self, base: str):
        oc = self.channels[base]
        sig = ecc.sign(oc.payer.secret, close_message(oc.payer.params.channel_id)).hex()
        return self._post(base, "/xbt402/close", {"channel": oc.payer.params.channel_id, "sig": sig})
