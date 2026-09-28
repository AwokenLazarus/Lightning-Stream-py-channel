"""Payee-side funding checks before a channel is credited."""
from dataclasses import dataclass

from .channel import ChannelError, ChannelParams

SAT = 100_000_000


@dataclass
class FundingPolicy:
    min_capacity: int = 20_000
    max_capacity: int = 10_000_000
    min_expiry_blocks: int = 144      # ~1 day left at open
    max_expiry_blocks: int = 8_640    # ~60 days: bounds how long the payee's key is hot
    close_margin: int = 36            # payee closes this many blocks before expiry
    min_conf: int = 1
    zero_conf_max: int = 0            # accept unconfirmed funding up to this capacity (0 = never)
    large_capacity: int = 1_000_000   # above this a funding reorg is worth more to an attacker,
    large_min_conf: int = 3           # so wait for more confirmations

    def conf_for(self, capacity: int) -> int:
        return max(self.min_conf, self.large_min_conf) if capacity > self.large_capacity else self.min_conf


def check_funding(rpc, p: ChannelParams, pol: FundingPolicy) -> int:
    """Raise ChannelError unless the funding output is acceptable; returns its confirmations.

    Refuses coinbase fundings outright: a channel funded by a coinbase output inherits the
    coinbase maturity (6480 blocks while Knots #419 applies), so neither the close nor the
    refund could be mined in time. Any other funding is an ordinary spend.

    Reads the output with `gettxout` (mempool included), which a pruned node without txindex
    answers for any unspent output; `getrawtransaction` would need txindex once the
    funding is in a block. A funding output that is already spent is refused.
    """
    try:
        out = rpc.gettxout(p.funding_txid, p.funding_vout, True)
    except Exception as e:  # noqa: BLE001 - node errors become protocol errors
        raise ChannelError("unknown_funding", str(e))
    if not out:
        raise ChannelError("unknown_funding", "no such unspent output (unknown, or already spent)")
    if out.get("coinbase"):
        raise ChannelError("coinbase_funding", "coinbase outputs cannot fund a channel (maturity)")
    if (out.get("scriptPubKey") or {}).get("hex") != p.spk.hex():
        raise ChannelError("bad_funding", "output is not this channel's script")
    if round(out["value"] * SAT) != p.capacity:
        raise ChannelError("bad_funding", "capacity mismatch")
    if not pol.min_capacity <= p.capacity <= pol.max_capacity:
        raise ChannelError("bad_capacity", f"capacity outside [{pol.min_capacity}, {pol.max_capacity}]")
    left = p.expiry - rpc.getblockcount()
    if not pol.min_expiry_blocks <= left <= pol.max_expiry_blocks:
        raise ChannelError("bad_expiry", f"{left} blocks to expiry, need "
                                         f"[{pol.min_expiry_blocks}, {pol.max_expiry_blocks}]")
    confs = out.get("confirmations", 0)
    need = pol.conf_for(p.capacity)
    if confs < need and p.capacity > pol.zero_conf_max:
        raise ChannelError("unconfirmed", f"{confs} confirmations, need {need}")
    return confs
