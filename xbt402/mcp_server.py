"""MCP tools for xbt402. Talks only to a ChannelSigner. The model never sees keys.

Tools: xbt402_pay, xbt_channels, xbt_close, xbt_refunds_due.
Each sign_state goes through the signer's policy hook. Responses are sanitised.
"""
import json
import os
import re
from pathlib import Path

from .channel import ChannelError

MCP_TOOL_NAMES = frozenset({"xbt402_pay", "xbt_channels", "xbt_close", "xbt_refunds_due"})
_KEY_RE = re.compile(r"(secret|privkey|private_key|wif|xprv|mnemonic|seed)", re.I)


def assert_no_key_material(obj) -> None:
    blob = json.dumps(obj, default=str)
    if _KEY_RE.search(blob):
        raise RuntimeError("refusing to return key material to the model")


def sanitize(obj):
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items() if not _KEY_RE.search(str(k))}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    return obj


def xbt402_pay(client, url: str, method: str = "GET", body: bytes = b"", max_sats: int = 1000) -> dict:
    """Pay `url` over xbt-channel. `client` is an XbtChannelClient bound to a signer."""
    if body is None:
        body = b""
    if isinstance(body, str):
        body = body.encode()
    origin = "/".join(url.split("/")[:3])
    price = int((client.channels.get(origin).accepted["amount"]
                 if origin in client.channels else max_sats))
    if price > max_sats:
        raise ChannelError("policy", f"quoted {price} sat > max_sats {max_sats}")
    old = client.max_price
    client.max_price = min(client.max_price, max_sats)
    try:
        status, hdrs, out = client.request(method, url, body)
    finally:
        client.max_price = old
    receipt = None
    if "PAYMENT-RESPONSE" in {k.upper(): v for k, v in hdrs.items()}:
        from .x402_channel import unb64json
        receipt = unb64json(hdrs.get("PAYMENT-RESPONSE") or hdrs.get("payment-response"))
        receipt = {k: receipt[k] for k in receipt if k != "sig"}  # keep receipt facts, drop raw sig
    result = {"status": status, "body": out.decode("utf-8", "replace")[:4000],
              "chan": receipt.get("chan") if receipt else None,
              "charged": receipt.get("charged") if receipt else None,
              "spentMsat": receipt.get("spentMsat") if receipt else None,
              "owedMsat": receipt.get("owedMsat") if receipt else None}
    assert_no_key_material(result)
    return sanitize(result)


def xbt_channels(signer) -> dict:
    result = {"channels": signer.channels()}
    assert_no_key_material(result)
    return sanitize(result)


def xbt_close(client, origin: str) -> dict:
    res = client.close(origin)
    out = {"chan": res.get("chan"), "txid": res.get("txid"), "cum": res.get("cum"),
           "unpaidMsat": res.get("unpaidMsat")}
    assert_no_key_material(out)
    return sanitize(out)


def xbt_refunds_due(client, height: int = None) -> dict:
    custody = getattr(client, "refunds", None)
    if custody is None:
        return {"broadcast": []}
    h = client.height() if height is None else height
    out = {"broadcast": custody.due(h)}
    assert_no_key_material(out)
    return sanitize(out)


def _build_server(client, signer):
    try:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("xbt402")
    except ImportError:
        return None

    @mcp.tool()
    def xbt402_pay_tool(url: str, method: str = "GET", body: str = "", max_sats: int = 1000) -> str:
        """Pay an HTTP URL over xbt-channel. Keys stay in the B2 signer."""
        return json.dumps(xbt402_pay(client, url, method, body.encode(), max_sats), indent=2)

    @mcp.tool()
    def xbt_channels_tool() -> str:
        """List open channels (caps, used, expiry). No keys."""
        return json.dumps(xbt_channels(signer), indent=2)

    @mcp.tool()
    def xbt_close_tool(origin: str) -> str:
        """Cooperative close of the channel to `origin`."""
        return json.dumps(xbt_close(client, origin), indent=2)

    @mcp.tool()
    def xbt_refunds_due_tool() -> str:
        """Broadcast stored refunds whose expiry has been reached."""
        return json.dumps(xbt_refunds_due(client), indent=2)

    return mcp


def handle(client, signer, method: str, params: dict) -> dict:
    """JSON-RPC surface used by tests and by a B2 signer that forwards these methods."""
    if method in ("xbt402_pay", "xbt_pay_402"):
        return xbt402_pay(client, params["url"], params.get("method", "GET"),
                          params.get("body", b""), int(params.get("max_sats", 1000)))
    if method == "xbt_channels":
        return xbt_channels(signer)
    if method == "xbt_close":
        return xbt_close(client, params["origin"])
    if method == "xbt_refunds_due":
        return xbt_refunds_due(client, params.get("height"))
    raise ValueError(f"unknown method {method}")
