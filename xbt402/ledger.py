"""SQLite WAL ledger: one row per channel, fsynced before a call is served."""
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field

from .channel import ChannelParams


@dataclass
class ChannelState:
    params: ChannelParams
    best_cum: int = 0
    best_sig: str = ""
    seq: int = 0
    spent_msat: int = 0
    closed_txid: str = ""
    best_sig_a3: str = ""
    cond_hash: str = ""
    cond_amount: int = 0
    cond_sig: str = ""
    extra: dict = field(default_factory=dict)
    suspended: bool = False     # the watcher saw the funding leave the chain (reorg): serve nothing
    close_error: str = ""       # last watcher error for this channel, retried every tick


COLUMNS = ("chan", "params_json", "best_cum", "best_sig", "seq", "spent_msat", "closed_txid", "best_sig_a3",
           "cond_hash", "cond_amount", "cond_sig", "extra_json", "suspended", "close_error")


class Ledger:
    """Latest state per channel. WAL + FULL so a crash cannot serve a call twice unpaid."""

    def __init__(self, path: str):
        if path.endswith(".json"):
            path = path[:-5] + ".sqlite"
        self.path, self.lock = path, threading.Lock()
        self.channels = {}
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS channels (
                chan TEXT PRIMARY KEY,
                params_json TEXT NOT NULL,
                best_cum INTEGER NOT NULL DEFAULT 0,
                best_sig TEXT NOT NULL DEFAULT '',
                seq INTEGER NOT NULL DEFAULT 0,
                spent_msat INTEGER NOT NULL DEFAULT 0,
                closed_txid TEXT NOT NULL DEFAULT '',
                best_sig_a3 TEXT NOT NULL DEFAULT '',
                cond_hash TEXT NOT NULL DEFAULT '',
                cond_amount INTEGER NOT NULL DEFAULT 0,
                cond_sig TEXT NOT NULL DEFAULT '',
                extra_json TEXT NOT NULL DEFAULT '{}',
                suspended INTEGER NOT NULL DEFAULT 0,
                close_error TEXT NOT NULL DEFAULT ''
            )"""
        )
        have = {r[1] for r in self._db.execute("PRAGMA table_info(channels)")}
        for col, decl in (("suspended", "INTEGER NOT NULL DEFAULT 0"), ("close_error", "TEXT NOT NULL DEFAULT ''")):
            if col not in have:   # a wave-2 ledger from before XBT-061
                self._db.execute(f"ALTER TABLE channels ADD COLUMN {col} {decl}")
        self._load()

    def _load(self):
        for row in self._db.execute(f"SELECT {', '.join(COLUMNS)} FROM channels"):
            (chan, params_json, best_cum, best_sig, seq, spent_msat, closed_txid,
             best_sig_a3, cond_hash, cond_amount, cond_sig, extra_json, suspended, close_error) = row
            st = ChannelState(
                ChannelParams(**json.loads(params_json)), best_cum, best_sig, seq, spent_msat,
                closed_txid, best_sig_a3, cond_hash, cond_amount, cond_sig,
                json.loads(extra_json or "{}"), bool(suspended), close_error,
            )
            self.channels[chan] = st

    def save(self, *states: ChannelState):
        """Upsert the given rows (every row if none are given) and fsync the WAL. A paid call saves
        only its own channel: rewriting all of them made each call O(channels), and channels cost an
        attacker only fees (XBT-061 M5)."""
        rows = [(st.params.channel_id, st) for st in states] if states else list(self.channels.items())
        cur = self._db.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            for chan, st in rows:
                cur.execute(
                    """INSERT INTO channels(chan, params_json, best_cum, best_sig, seq, spent_msat,
                       closed_txid, best_sig_a3, cond_hash, cond_amount, cond_sig, extra_json,
                       suspended, close_error)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(chan) DO UPDATE SET
                         params_json=excluded.params_json, best_cum=excluded.best_cum,
                         best_sig=excluded.best_sig, seq=excluded.seq, spent_msat=excluded.spent_msat,
                         closed_txid=excluded.closed_txid, best_sig_a3=excluded.best_sig_a3,
                         cond_hash=excluded.cond_hash, cond_amount=excluded.cond_amount,
                         cond_sig=excluded.cond_sig, extra_json=excluded.extra_json,
                         suspended=excluded.suspended, close_error=excluded.close_error""",
                    (chan, json.dumps(st.params.to_dict()), st.best_cum, st.best_sig, st.seq,
                     st.spent_msat, st.closed_txid, st.best_sig_a3, st.cond_hash, st.cond_amount,
                     st.cond_sig, json.dumps(st.extra or {}), int(st.suspended), st.close_error),
                )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        self._db.execute("PRAGMA wal_checkpoint(FULL)")
