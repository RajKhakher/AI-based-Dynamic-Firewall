"""
conntrack.py - lightweight stateful connection tracking.

A "stateful" firewall remembers conversations. If your machine opens a
connection to a web server, the reply coming back should be allowed even if
there is an inbound "deny" rule, because it is part of a conversation you
started. Without this, a firewall is just a dumb per-packet filter.

We keep a small table keyed by a normalised 5-tuple
(protocol, address A, port A, address B, port B) where A/B are sorted so both
directions of the same flow map to the same key. For each flow we record:

  - state    : NEW, ESTABLISHED
  - who started it (so we know which direction is "reply")
  - last-seen time (entries expire after a timeout)

The engine uses this to let established/return traffic through and to spot
brand-new inbound connections (which is what detectors care about).
"""

from __future__ import annotations

import threading
import time

from .packet import PacketInfo, OUTBOUND, SYN, ACK, RST, FIN

NEW = "new"
ESTABLISHED = "established"

# How long a flow with no packets stays remembered.
TCP_TIMEOUT = 120.0
UDP_TIMEOUT = 60.0
ICMP_TIMEOUT = 30.0


def _flow_key(pkt: PacketInfo):
    """A direction-independent key for the flow this packet belongs to."""
    a = (pkt.src, pkt.sport)
    b = (pkt.dst, pkt.dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (pkt.protocol, lo[0], lo[1], hi[0], hi[1])


class ConnTrack:
    def __init__(self):
        self._flows: dict = {}
        self._lock = threading.Lock()
        self._last_sweep = time.time()

    def _timeout_for(self, proto: int) -> float:
        if proto == 6:
            return TCP_TIMEOUT
        if proto == 17:
            return UDP_TIMEOUT
        return ICMP_TIMEOUT

    def update(self, pkt: PacketInfo) -> str:
        """
        Record this packet and return the flow's state as seen *for this
        packet*: NEW if it starts a flow, ESTABLISHED if it belongs to one we
        already know. Also sets pkt-derived info the engine may want.
        """
        now = time.time()
        key = _flow_key(pkt)
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # Brand new flow.
                self._flows[key] = {
                    "state": NEW,
                    "opener": OUTBOUND if pkt.direction == OUTBOUND else pkt.direction,
                    "opener_src": pkt.src,
                    "created": now,
                    "last": now,
                    "packets": 1,
                }
                state = NEW
            else:
                flow["last"] = now
                flow["packets"] += 1
                # Any second packet (especially the reply) promotes to established.
                if flow["state"] == NEW and pkt.src != flow["opener_src"]:
                    flow["state"] = ESTABLISHED
                state = flow["state"]
                # A TCP reset/fin closes the flow.
                if pkt.is_tcp and (pkt.tcp_flags & (RST | FIN)):
                    self._flows.pop(key, None)
            if now - self._last_sweep > 15:
                self._sweep(now)
            return state

    def is_established(self, pkt: PacketInfo) -> bool:
        with self._lock:
            flow = self._flows.get(_flow_key(pkt))
            return bool(flow and flow["state"] == ESTABLISHED)

    def is_reply_to_us(self, pkt: PacketInfo) -> bool:
        """True if this inbound packet is a reply on a flow WE opened."""
        with self._lock:
            flow = self._flows.get(_flow_key(pkt))
            if not flow:
                return False
            return flow["opener"] == OUTBOUND and pkt.src != flow["opener_src"]

    def _sweep(self, now: float) -> None:
        dead = [k for k, f in self._flows.items()
                if now - f["last"] > self._timeout_for(k[0])]
        for k in dead:
            self._flows.pop(k, None)
        self._last_sweep = now

    def count(self) -> int:
        with self._lock:
            return len(self._flows)

    def snapshot(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = []
            for (proto, sip, sport, dip, dport), f in list(self._flows.items())[:limit]:
                rows.append({
                    "protocol": proto, "a": f"{sip}:{sport}", "b": f"{dip}:{dport}",
                    "state": f["state"], "packets": f["packets"],
                    "age": round(time.time() - f["created"], 1),
                })
            return rows
