"""
stats.py - fast in-memory counters for the live dashboard.

The packet path must stay quick, so we never touch the database on every packet.
Instead we keep a handful of counters in memory and update them cheaply. The
dashboard reads a snapshot a few times a second. Everything here is guarded by a
lock because the packet thread writes while the web thread reads.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.started = time.time()
        self.total = 0
        self.allowed = 0
        self.denied = 0
        self.by_proto = defaultdict(int)
        self.by_action = defaultdict(int)
        self.top_talkers = defaultdict(int)     # src ip -> packets
        self.top_targets = defaultdict(int)     # dst port -> packets
        self.alerts = 0
        self.ai_flags = 0
        # For a packets-per-second sparkline: one bucket per second, last 60s.
        self._pps = deque(maxlen=60)
        self._cur_sec = int(time.time())
        self._cur_count = 0

    def record(self, pkt, action: str) -> None:
        with self._lock:
            self.total += 1
            self.by_proto[pkt.proto] += 1
            self.by_action[action] += 1
            if action == "allow":
                self.allowed += 1
            else:
                self.denied += 1
            if pkt.src:
                self.top_talkers[pkt.src] += 1
            if pkt.dport:
                self.top_targets[pkt.dport] += 1
            # pps bucket
            sec = int(time.time())
            if sec != self._cur_sec:
                self._pps.append((self._cur_sec, self._cur_count))
                # fill any gap seconds with zeros
                for s in range(self._cur_sec + 1, sec):
                    self._pps.append((s, 0))
                self._cur_sec = sec
                self._cur_count = 0
            self._cur_count += 1

    def record_alert(self) -> None:
        with self._lock:
            self.alerts += 1

    def record_ai_flag(self) -> None:
        with self._lock:
            self.ai_flags += 1

    def snapshot(self) -> dict:
        with self._lock:
            pps = list(self._pps) + [(self._cur_sec, self._cur_count)]
            top_talkers = sorted(self.top_talkers.items(), key=lambda x: -x[1])[:10]
            top_targets = sorted(self.top_targets.items(), key=lambda x: -x[1])[:10]
            return {
                "uptime": round(time.time() - self.started, 1),
                "total": self.total,
                "allowed": self.allowed,
                "denied": self.denied,
                "by_proto": dict(self.by_proto),
                "by_action": dict(self.by_action),
                "alerts": self.alerts,
                "ai_flags": self.ai_flags,
                "top_talkers": [{"ip": ip, "packets": n} for ip, n in top_talkers],
                "top_targets": [{"port": p, "packets": n} for p, n in top_targets],
                "pps": [{"t": t, "n": n} for t, n in pps[-60:]],
            }
