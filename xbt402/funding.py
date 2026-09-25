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


def check_funding(rpc, p: ChannelParams, pol: FundingPolicy) -> int:
    """Raise ChannelError unless the funding output is acceptable; returns its confirmations.

    Refuses coinbase fundings outright: a channel funded by a coinbase output inherits the
    coinbase maturity (6480 blocks while Knots #419 applies), so neither the close nor the
    refund could be mined in time. Any other funding is an ordinary spend.
    """
    try:
        raw = rpc.getrawtransaction(p.funding_txid, True)
    except Exception as e:  # noqa: BLE001 - node errors become protocol errors
        raise ChannelError("unknown_funding", str(e))
    if any("coinbase" in vin for vin in raw["vin"]):
        raise ChannelError("coinbase_funding", "coinbase outputs cannot fund a channel (maturity)")
    if p.funding_vout >= len(raw["vout"]):
        raise ChannelError("bad_funding", "no such output")
    out = raw["vout"][p.funding_vout]
    if out["scriptPubKey"]["hex"] != p.spk.hex():
        raise ChannelError("bad_funding", "output is not this channel's script")
    if round(out["value"] * SAT) != p.capacity:
        raise ChannelError("bad_funding", "capacity mismatch")
    if not pol.min_capacity <= p.capacity <= pol.max_capacity:
        raise ChannelError("bad_capacity", f"capacity outside [{pol.min_capacity}, {pol.max_capacity}]")
    left = p.expiry - rpc.getblockcount()
    if not pol.min_expiry_blocks <= left <= pol.max_expiry_blocks:
        raise ChannelError("bad_expiry", f"{left} blocks to expiry, need "
                                         f"[{pol.min_expiry_blocks}, {pol.max_expiry_blocks}]")
    confs = raw.get("confirmations", 0)
    if confs < pol.min_conf and p.capacity > pol.zero_conf_max:
        raise ChannelError("unconfirmed", f"{confs} confirmations, need {pol.min_conf}")
    return confs
