"""Channel-key signer: secrets never leave this object.

XBT-062's B2 policy engine should implement the same method names on its unix-socket
signer (`xbt402_new_key`, `xbt402_sign_state`, `xbt402_sign_close`, `xbt402_sign_refund`,
`xbt402_fund`, and since XBT-061 `xbt402_request_auth`). The MCP tool in `mcp_server.py` talks only to this API.
"""
import secrets
from typing import Callable, Optional

from . import ecc
from .channel import ChannelError, ChannelParams, Payer, channel_auth_key
from .tx import SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED, tagged_hash


def close_message(chan: str) -> bytes:
    return tagged_hash("xbt402/close", chan.encode())


class ChannelSigner:
    """Holds per-channel payer secrets. Optional `policy(origin, sats) -> None` raises to deny."""

    def __init__(self, fund: Callable[[str, int], tuple] = None,
                 policy: Optional[Callable[[str, int], None]] = None):
        self.fund_fn, self.policy = fund, policy
        self._secrets = {}       # chan or pending:<origin> -> int
        self._params = {}        # chan -> ChannelParams
        self._origins = {}       # origin -> chan
        self._signed = {}        # chan -> highest amount

    def new_key(self, origin: str) -> str:
        secret = secrets.randbelow(ecc.N - 1) + 1
        self._secrets[f"pending:{origin}"] = secret
        return ecc.pubkey(secret).hex()

    def attach(self, origin: str, params: ChannelParams) -> str:
        key = f"pending:{origin}"
        if key not in self._secrets:
            raise ChannelError("bad_key", "call new_key before attach")
        secret = self._secrets.pop(key)
        if ecc.pubkey(secret).hex() != params.payer_pub:
            raise ChannelError("bad_key", "attached params do not match issued key")
        self._secrets[params.channel_id] = secret
        self._params[params.channel_id] = params
        self._origins[origin] = params.channel_id
        self._signed[params.channel_id] = 0
        return params.channel_id

    def _secret(self, chan: str) -> int:
        if chan not in self._secrets:
            raise ChannelError("unknown_channel", chan)
        return self._secrets[chan]

    def sign_state(self, chan: str, amount: int) -> str:
        params = self._params[chan]
        if self.policy:
            origin = next((o for o, c in self._origins.items() if c == chan), "")
            self.policy(origin, amount)
        if amount < self._signed.get(chan, 0):
            raise ChannelError("stale_amount", "never sign a lower cumulative amount")
        tx = params.state_tx(amount)
        sig = ecc.sign(self._secret(chan), params.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        self._signed[chan] = amount
        return sig.hex()

    def sign_state_a3(self, chan: str, amount: int) -> str:
        params = self._params[chan]
        if self.policy:
            origin = next((o for o, c in self._origins.items() if c == chan), "")
            self.policy(origin, amount)
        tx = params.state_tx_a3(amount)
        sig = ecc.sign(self._secret(chan), params.sighash_a3(tx)) + bytes([SIGHASH_SINGLE_ACP_UNIFIED])
        return sig.hex()

    def sign_close(self, chan: str) -> str:
        return ecc.sign(self._secret(chan), close_message(chan)).hex()

    def sign_refund(self, chan: str) -> str:
        return self._params[chan].refund_tx(self._secret(chan)).hex()

    def request_auth(self, chan: str, seq: int, cum, sig, req: str) -> str:
        """payload.auth for one paid request (XBT-061 H3). The ECDH key stays in here."""
        from .x402_channel import request_auth
        key = channel_auth_key(self._secret(chan), bytes.fromhex(self._params[chan].payee_pub))
        return request_auth(key, chan, seq, cum, sig, req)

    def sign_conditional(self, chan: str, uncond: int, cond) -> str:
        """`cond` is a ConditionalParams. Policy sees uncond+cond_amount."""
        if self.policy:
            origin = next((o for o, c in self._origins.items() if c == chan), "")
            self.policy(origin, uncond + cond.cond_amount)
        tx = cond.state_tx(uncond)
        sig = ecc.sign(self._secret(chan), cond.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        return sig.hex()

    def fund(self, address: str, sats: int):
        if not self.fund_fn:
            raise ChannelError("no_wallet", "signer has no fund() hook")
        return self.fund_fn(address, sats)

    def channels(self) -> list:
        out = []
        for origin, chan in self._origins.items():
            p = self._params[chan]
            out.append({"origin": origin, "chan": chan, "capacity": p.capacity,
                        "signed": self._signed.get(chan, 0), "expiry": p.expiry,
                        "max": p.max_amount})
        return out

    def has(self, chan: str) -> bool:
        return chan in self._secrets

    def payer_for(self, params: ChannelParams) -> Payer:
        return Payer(params, backend=self)


class SignerSocketAdapter:
    """Talk to a B2-style unix-socket signer that implements the xbt402_* methods."""

    def __init__(self, client):
        """`client` is anything with `.call(method, **params)` (B2 SignerClient)."""
        self.client = client

    def new_key(self, origin: str) -> str:
        return self.client.call("xbt402_new_key", origin=origin)["pubkey"]

    def attach(self, origin: str, params: ChannelParams) -> str:
        return self.client.call("xbt402_attach", origin=origin, params=params.to_dict())["chan"]

    def sign_state(self, chan: str, amount: int) -> str:
        return self.client.call("xbt402_sign_state", chan=chan, amount=amount)["sig"]

    def sign_state_a3(self, chan: str, amount: int) -> str:
        return self.client.call("xbt402_sign_state_a3", chan=chan, amount=amount)["sig"]

    def sign_close(self, chan: str) -> str:
        return self.client.call("xbt402_sign_close", chan=chan)["sig"]

    def sign_refund(self, chan: str) -> str:
        return self.client.call("xbt402_sign_refund", chan=chan)["hex"]

    def request_auth(self, chan: str, seq: int, cum, sig, req: str) -> str:
        return self.client.call("xbt402_request_auth", chan=chan, seq=seq, cum=str(cum), sig=sig or "", req=req)["auth"]

    def fund(self, address: str, sats: int):
        r = self.client.call("xbt402_fund", address=address, sats=sats)
        return r["txid"], r["vout"]

    def channels(self) -> list:
        return self.client.call("xbt402_channels")["channels"]
