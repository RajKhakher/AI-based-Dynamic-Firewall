"""
detectors.py - recognise unwanted traffic patterns.

These are defensive detectors. Each one watches the stream of real packets and
raises an alert when a source behaves in a way that a normal client never would.
They are deliberately simple and explainable - every alert says exactly which
threshold was crossed, so nothing is a black box.

Detectors implemented:

  PortScanDetector   one source touching many different ports quickly
                     (someone mapping which services you run)
  SynFloodDetector   a burst of half-open TCP connections
                     (a flood aimed at exhausting resources)
  UdpFloodDetector   a burst of UDP packets from one source
  IcmpFloodDetector  a burst of pings from one source
  BruteForceDetector many new connections to a login port (SSH/RDP/...)

Each detector, when it fires, returns an Alert describing what happened and how
long to block the source. The engine decides whether to act on it (in monitor
mode it only logs; in enforce mode it blocks).

The windows use collections.deque and only store timestamps, so memory stays
small even under a real flood.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

from .packet import PacketInfo, INBOUND


@dataclass
class Alert:
    kind: str            # "portscan", "syn_flood", ...
    src: str             # offending source address
    detail: str          # human-readable explanation
    severity: str        # "low" / "medium" / "high"
    block_seconds: int    # recommended block duration (0 = don't block)
    evidence: dict        # the numbers behind the decision


class _SlidingWindow:
    """Remembers events within the last `window` seconds."""

    def __init__(self, window: float):
        self.window = window
        self._events: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, value=None, now: float | None = None) -> deque:
        now = now or time.time()
        dq = self._events[key]
        dq.append((now, value))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return dq

    def values(self, key: str):
        return [v for _, v in self._events.get(key, ())]

    def count(self, key: str) -> int:
        return len(self._events.get(key, ()))

    def gc(self, now: float | None = None) -> None:
        now = now or time.time()
        cutoff = now - self.window
        for key in list(self._events):
            dq = self._events[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self._events[key]


class PortScanDetector:
    """Fires when one source hits more than `ports` distinct dports in `window`."""

    def __init__(self, ports=15, window=10, block_seconds=300):
        self.threshold = ports
        self.window = window
        self.block_seconds = block_seconds
        self._w = _SlidingWindow(window)
        self._fired: dict[str, float] = {}

    def inspect(self, pkt: PacketInfo) -> Alert | None:
        if pkt.direction != INBOUND or pkt.protocol not in (6, 17):
            return None
        now = time.time()
        self._w.add(pkt.src, pkt.dport, now)
        distinct = len(set(self._w.values(pkt.src)))
        if distinct >= self.threshold:
            # Don't spam: one alert per source per window.
            if now - self._fired.get(pkt.src, 0) < self.window:
                return None
            self._fired[pkt.src] = now
            return Alert(
                kind="portscan", src=pkt.src, severity="high",
                detail=f"{distinct} different ports in {self.window}s (limit {self.threshold})",
                block_seconds=self.block_seconds,
                evidence={"distinct_ports": distinct, "window_s": self.window},
            )
        return None


class _FloodDetector:
    kind = "flood"

    def __init__(self, count, window, block_seconds, protocols):
        self.threshold = count
        self.window = window
        self.block_seconds = block_seconds
        self.protocols = protocols
        self._w = _SlidingWindow(window)
        self._fired: dict[str, float] = {}

    def _match(self, pkt: PacketInfo) -> bool:
        return pkt.protocol in self.protocols

    def inspect(self, pkt: PacketInfo) -> Alert | None:
        if pkt.direction != INBOUND or not self._match(pkt):
            return None
        now = time.time()
        self._w.add(pkt.src, 1, now)
        n = self._w.count(pkt.src)
        if n >= self.threshold:
            if now - self._fired.get(pkt.src, 0) < self.window:
                return None
            self._fired[pkt.src] = now
            return Alert(
                kind=self.kind, src=pkt.src, severity="high",
                detail=f"{n} {self.kind.split('_')[0]} packets in {self.window}s (limit {self.threshold})",
                block_seconds=self.block_seconds,
                evidence={"packets": n, "window_s": self.window},
            )
        return None


class SynFloodDetector(_FloodDetector):
    kind = "syn_flood"

    def __init__(self, count=100, window=5, block_seconds=120):
        super().__init__(count, window, block_seconds, protocols={6})

    def _match(self, pkt: PacketInfo) -> bool:
        return pkt.is_syn_only  # only count half-open attempts


class UdpFloodDetector(_FloodDetector):
    kind = "udp_flood"

    def __init__(self, count=300, window=5, block_seconds=120):
        super().__init__(count, window, block_seconds, protocols={17})


class IcmpFloodDetector(_FloodDetector):
    kind = "icmp_flood"

    def __init__(self, count=100, window=5, block_seconds=120):
        super().__init__(count, window, block_seconds, protocols={1, 58})


class BruteForceDetector:
    """Many NEW connections to a login port from one source = likely guessing."""

    def __init__(self, count=10, window=30, ports=(22, 23, 3389, 21, 3306, 5432),
                 block_seconds=300):
        self.threshold = count
        self.window = window
        self.ports = set(ports)
        self.block_seconds = block_seconds
        self._w = _SlidingWindow(window)
        self._fired: dict[str, float] = {}

    def inspect(self, pkt: PacketInfo, is_new: bool = True) -> Alert | None:
        if pkt.direction != INBOUND or not pkt.is_syn_only:
            return None
        if pkt.dport not in self.ports:
            return None
        now = time.time()
        key = f"{pkt.src}->{pkt.dport}"
        self._w.add(key, 1, now)
        n = self._w.count(key)
        if n >= self.threshold:
            if now - self._fired.get(key, 0) < self.window:
                return None
            self._fired[key] = now
            return Alert(
                kind="bruteforce", src=pkt.src, severity="high",
                detail=f"{n} new connections to port {pkt.dport} in {self.window}s (limit {self.threshold})",
                block_seconds=self.block_seconds,
                evidence={"attempts": n, "port": pkt.dport, "window_s": self.window},
            )
        return None


class DetectorSuite:
    """Runs every enabled detector over each packet and collects alerts."""

    def __init__(self, cfg: dict):
        d = cfg.get("detectors", {})
        self.enabled = d.get("enabled", True)
        ps = d.get("portscan", {})
        sf = d.get("syn_flood", {})
        uf = d.get("udp_flood", {})
        icf = d.get("icmp_flood", {})
        bf = d.get("bruteforce", {})
        self.portscan = PortScanDetector(ps.get("ports", 15), ps.get("window", 10),
                                         ps.get("block_seconds", 300))
        self.syn = SynFloodDetector(sf.get("count", 100), sf.get("window", 5),
                                    sf.get("block_seconds", 120))
        self.udp = UdpFloodDetector(uf.get("count", 300), uf.get("window", 5),
                                    uf.get("block_seconds", 120))
        self.icmp = IcmpFloodDetector(icf.get("count", 100), icf.get("window", 5),
                                      icf.get("block_seconds", 120))
        self.brute = BruteForceDetector(bf.get("count", 10), bf.get("window", 30),
                                        tuple(bf.get("ports", [22, 23, 3389, 21, 3306, 5432])),
                                        bf.get("block_seconds", 300))

    def inspect(self, pkt: PacketInfo) -> list[Alert]:
        if not self.enabled:
            return []
        alerts = []
        for det in (self.portscan, self.syn, self.udp, self.icmp, self.brute):
            a = det.inspect(pkt)
            if a:
                alerts.append(a)
        return alerts
