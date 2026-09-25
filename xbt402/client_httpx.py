"""httpx scheme handler for `xbt-channel` (one channel per origin)."""
import httpx

from .x402_channel import XbtChannelClient


class Xbt402Transport(httpx.BaseTransport):
    """Sends every request through `XbtChannelClient.request` (open on first 402, pay per call)."""

    def __init__(self, client: XbtChannelClient):
        self.client = client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.content or b""
        status, hdrs, out = self.client.request(request.method, str(request.url), body)
        return httpx.Response(status, headers=hdrs, content=out, request=request)


def xbt402_httpx(client: XbtChannelClient, **kwargs) -> httpx.Client:
    return httpx.Client(transport=Xbt402Transport(client), **kwargs)
