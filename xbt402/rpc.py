"""Tiny JSON-RPC client for a local Knots node (cookie auth, stdlib only)."""
import base64
import json
import os
import urllib.error
import urllib.request


class RPCError(Exception):
    def __init__(self, err):
        super().__init__(err.get("message", str(err)))
        self.code = err.get("code")


class RPC:
    def __init__(self, port: int, cookie_path: str, wallet: str = ""):
        self.url = f"http://127.0.0.1:{port}/" + (f"wallet/{wallet}" if wallet else "")
        self.cookie_path = cookie_path

    @classmethod
    def from_env(cls, wallet: str = ""):
        dd = os.environ.get("XBT402_DATADIR", os.path.join(os.path.dirname(__file__), "..", ".regtest"))
        return cls(int(os.environ.get("XBT402_RPCPORT", "19543")),
                   os.path.join(dd, "regtest", ".cookie"), wallet)

    def wallet(self, name: str) -> "RPC":
        return RPC(int(self.url.split(":")[2].split("/")[0]), self.cookie_path, name)

    def __getattr__(self, method):
        def call(*params):
            with open(self.cookie_path, "rb") as f:
                auth = base64.b64encode(f.read().strip()).decode()
            req = urllib.request.Request(
                self.url, json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode(),
                {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
            try:
                body = json.load(urllib.request.urlopen(req, timeout=60))
            except urllib.error.HTTPError as e:
                body = json.load(e)
            if body.get("error"):
                raise RPCError(body["error"])
            return body["result"]
        return call
