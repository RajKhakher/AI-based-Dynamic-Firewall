"""
storage.py - the history the dashboard reads from.

We keep three tables in a small SQLite database:

  events  - a record of packet decisions (sampled, so we don't drown in rows)
  alerts  - detector and AI alerts, with the reason
  blocks  - a log of every block and unblock

Writing to SQLite on the packet thread would slow packet handling, so writes go
onto a queue and a single background thread drains it. The web side only reads.
SQLite is run in WAL mode so reads and writes don't block each other.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time

from .config import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "firewall.db")


class Storage:
    def __init__(self, path: str = DB_PATH, keep_events: int = 50000):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.path = path
        self.keep_events = keep_events
        self._q: "queue.Queue" = queue.Queue(maxsize=10000)
        self._stop = threading.Event()
        self._writer = threading.Thread(target=self._run, daemon=True, name="storage-writer")
        self._init_db()
        self._writer.start()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, direction TEXT, proto TEXT,
                    src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
                    length INTEGER, action TEXT, reason TEXT)""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, kind TEXT, src TEXT, severity TEXT,
                    detail TEXT, evidence TEXT, acted TEXT)""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, event TEXT, ip TEXT, reason TEXT, source TEXT)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        conn.close()

    # -- write side (non-blocking) -----------------------------------------
    def log_event(self, pkt, action: str, reason: str = "") -> None:
        row = ("event", (time.time(), pkt.direction, pkt.proto, pkt.src, pkt.sport,
                         pkt.dst, pkt.dport, pkt.length, action, reason))
        try:
            self._q.put_nowait(row)
        except queue.Full:
            pass  # under extreme load we drop history rows, never packets

    def log_alert(self, alert, acted: str = "") -> None:
        row = ("alert", (time.time(), alert.kind, alert.src, alert.severity,
                         alert.detail, json.dumps(alert.evidence), acted))
        try:
            self._q.put_nowait(row)
        except queue.Full:
            pass

    def log_block(self, event: str, ip: str, reason: str, source: str) -> None:
        row = ("block", (time.time(), event, ip, reason, source))
        try:
            self._q.put_nowait(row)
        except queue.Full:
            pass

    def _run(self) -> None:
        conn = self._connect()
        last_trim = time.time()
        while not self._stop.is_set() or not self._q.empty():
            try:
                kind, values = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                with conn:
                    if kind == "event":
                        conn.execute(
                            "INSERT INTO events(ts,direction,proto,src,sport,dst,dport,length,action,reason)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?)", values)
                    elif kind == "alert":
                        conn.execute(
                            "INSERT INTO alerts(ts,kind,src,severity,detail,evidence,acted)"
                            " VALUES(?,?,?,?,?,?,?)", values)
                    elif kind == "block":
                        conn.execute(
                            "INSERT INTO blocks(ts,event,ip,reason,source) VALUES(?,?,?,?,?)",
                            values)
            except Exception:
                pass
            if time.time() - last_trim > 60:
                self._trim(conn)
                last_trim = time.time()
        conn.close()

    def _trim(self, conn) -> None:
        try:
            with conn:
                conn.execute(
                    "DELETE FROM events WHERE id NOT IN "
                    "(SELECT id FROM events ORDER BY id DESC LIMIT ?)", (self.keep_events,))
        except Exception:
            pass

    # -- read side ----------------------------------------------------------
    def recent_events(self, limit: int = 100) -> list[dict]:
        return self._read("SELECT ts,direction,proto,src,sport,dst,dport,length,action,reason"
                          " FROM events ORDER BY id DESC LIMIT ?", (limit,),
                          ["ts", "direction", "proto", "src", "sport", "dst", "dport",
                           "length", "action", "reason"])

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        rows = self._read("SELECT ts,kind,src,severity,detail,evidence,acted FROM alerts"
                          " ORDER BY id DESC LIMIT ?", (limit,),
                          ["ts", "kind", "src", "severity", "detail", "evidence", "acted"])
        for r in rows:
            try:
                r["evidence"] = json.loads(r["evidence"])
            except Exception:
                r["evidence"] = {}
        return rows

    def recent_blocks(self, limit: int = 100) -> list[dict]:
        return self._read("SELECT ts,event,ip,reason,source FROM blocks"
                          " ORDER BY id DESC LIMIT ?", (limit,),
                          ["ts", "event", "ip", "reason", "source"])

    def alert_counts(self) -> dict:
        rows = self._read("SELECT kind, COUNT(*) c FROM alerts GROUP BY kind", (),
                          ["kind", "c"])
        return {r["kind"]: r["c"] for r in rows}

    def _read(self, sql: str, params, cols: list[str]) -> list[dict]:
        conn = self._connect()
        try:
            cur = conn.execute(sql, params)
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except Exception:
            return []
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._writer.join(timeout=3)
