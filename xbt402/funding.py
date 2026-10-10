"""Payee-side funding checks before a channel is credited, and the expiry a payer opens with."""
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


def open_expiry_floor(min_expiry: int, min_conf: int, close_margin: int) -> int:
    """The fewest blocks to expiry a payer asks for when it opens on an offer: `minExpiryBlocks +
    minConf + closeMarginBlocks`, all three from that offer (AGP-076; the same rule as xbt-rs
    `xbt402::funding::open_expiry_floor`).

    check_funding compares the blocks left with min_expiry_blocks at the provider's tip when the
    funded open reaches it, not at the payer's tip when the payer chose the expiry. In between the
    funding has to get `minConf` confirmations, and it may wait for the first one. So the payer adds
    `minConf`, plus the time the provider itself allows a transaction to confirm on this chain:
    `closeMarginBlocks`, how long before expiry it broadcasts its close. A funding that takes longer
    would be refused bad_expiry on every retry, with the coins locked until the refund. No provider
    check reads the margin; it is only the payer's allowance."""
    return min_expiry + min_conf + close_margin


def open_expiry_blocks(want: int, min_expiry: int, max_expiry: int, min_conf: int, close_margin: int) -> int:
    """Blocks to expiry for a new channel: what the payer wants, at least open_expiry_floor, at most
    `maxExpiryBlocks - 1`. An offer whose window is narrower than the floor gets the top of its
    window: the open preflight answers that before anything is funded."""
    return max(0, min(max(want, open_expiry_floor(min_expiry, min_conf, close_margin)), max_expiry - 1))


def _block_count(v):
    """An offer's block count: a non-negative integer, or a string of decimal digits. None otherwise."""
    if isinstance(v, str):
        v = v.strip()
        v = int(v) if v.isascii() and v.isdigit() and len(v) <= 30 else None
    return v if isinstance(v, int) and v >= 0 else None


def offer_expiry_terms(extra: dict) -> tuple:
    """(minExpiryBlocks, maxExpiryBlocks, minConf, closeMarginBlocks) of an offer's `extra`. `minConf`
    absent is 1, as everywhere on this wire; the three others have no default, so an offer without
    one (or with one that is not a block count) is refused bad_offer, before anything is funded."""
    def need(k):
        n = _block_count(extra.get(k))
        if n is None:
            raise ChannelError("bad_offer", f"extra.{k} missing or not a block count")
        return n
    return need("minExpiryBlocks"), need("maxExpiryBlocks"), need("minConf") if "minConf" in extra else 1, \
        need("closeMarginBlocks")


def offer_expiry_blocks(extra: dict, want: int) -> int:
    """open_expiry_blocks for an offer's `extra` (offer_expiry_terms)."""
    min_expiry, max_expiry, min_conf, close_margin = offer_expiry_terms(extra)
    return open_expiry_blocks(want, min_expiry, max_expiry, min_conf, close_margin)
