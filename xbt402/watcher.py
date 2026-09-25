"""close_due() loop plus CPFP from the payee close output."""
import threading
import time

from .channel import ChannelError, cpfp_child, channel_payee_secret
from . import ecc

SAT = 100_000_000


class Watcher:
    """Runs `provider.close_due()` each tick; optionally CPFP-bumps each new close."""

    def __init__(self, provider, interval: float = 2.0, cpfp_fee: int = 0):
        self.provider, self.interval, self.cpfp_fee = provider, interval, cpfp_fee
        self._stop = threading.Event()
        self.closed = []
        self.cpfp_txids = []

    def tick(self) -> list:
        txids = self.provider.close_due()
        for txid in txids:
            self.closed.append(txid)
            if self.cpfp_fee:
                try:
                    child = self.provider.cpfp(txid, self.cpfp_fee)
                    if child:
                        self.cpfp_txids.append(child)
                except (ChannelError, Exception):
                    pass
        return txids

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._loop, daemon=True, name="xbt402-watcher")
        t.start()
        return t

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                pass

    def stop(self):
        self._stop.set()


def cpfp_from_close(rpc, close_txid: str, payee_spk_hex: str, payee_secret: int, fee: int) -> str:
    raw = rpc.getrawtransaction(close_txid, True)
    vout = next(o for o in raw["vout"] if o["scriptPubKey"]["hex"] == payee_spk_hex)
    value = round(vout["value"] * SAT)
    tx = cpfp_child(close_txid, vout["n"], value, bytes.fromhex(payee_spk_hex), payee_secret, fee)
    return rpc.sendrawtransaction(tx.hex())
