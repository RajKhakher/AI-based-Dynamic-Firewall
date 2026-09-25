"""
blocklist.py - the dynamic, self-expiring blocklist with a safety net.

When a detector or the AI decides an address is misbehaving, it asks this module
to block it. A block:

  * is pushed into the kernel (via NetfilterManager) so it takes effect instantly
  * has an optional lifetime, after which it lifts itself automatically
  * is written to history so the dashboard can show why it happened

The safelist is the important safety feature. It guarantees we will never block
loopback, your own machine, the default gateway, or your DNS servers - the
things that, if blocked, would cut you off from your own box. Manual blocks from
the dashboard bypass detectors but still respect the safelist.
"""

from __future__ import annotations

import ipaddress
import threading
import time


def _default_gateways_and_dns() -> set[str]:
    """Best-effort discovery of the gateway and DNS servers, to protect them."""
    keep = set()
    # Default gateway from /proc/net/route (IPv4).
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw = parts[2]
                    # little-endian hex -> dotted quad
                    octets = [str(int(gw[i:i+2], 16)) for i in (6, 4, 2, 0)]
                    keep.add(".".join(octets))
    except Exception:
        pass
    # DNS servers from /etc/resolv.conf.
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    keep.add(line.split()[1].strip())
    except Exception:
        pass
    return {ip for ip in keep if ip}


class DynamicBlocklist:
    def __init__(self, netfilter, safelist=None, keep_gateway=True, on_change=None):
        self._nf = netfilter
        self._lock = threading.Lock()
        self._active: dict[str, dict] = {}     # ip -> {reason, until, created, source}
        self._on_change = on_change
        self._safe = set(safelist or [])
        self._safe |= {"127.0.0.1", "::1", "0.0.0.0"}
        if keep_gateway:
            self._safe |= _default_gateways_and_dns()

    def is_safe(self, ip: str) -> bool:
        if ip in self._safe:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                return True
        except ValueError:
            return True  # not a real address -> don't touch it
        return False

    def block(self, ip: str, seconds: int = 0, reason: str = "", source: str = "auto") -> bool:
        """Block an address. Returns False if it's safelisted or already blocked."""
        if self.is_safe(ip):
            return False
        with self._lock:
            if ip in self._active:
                # Extend the block if the new one lasts longer.
                if seconds and (self._active[ip]["until"] and
                                time.time() + seconds > self._active[ip]["until"]):
                    self._active[ip]["until"] = time.time() + seconds
                return False
            ok = self._nf.block_ip(ip, seconds)
            if not ok:
                return False
            self._active[ip] = {
                "reason": reason,
                "until": (time.time() + seconds) if seconds else 0,
                "created": time.time(),
                "source": source,
            }
        if self._on_change:
            self._on_change("block", ip, reason, source)
        return True

    def unblock(self, ip: str) -> bool:
        with self._lock:
            existed = ip in self._active
            self._nf.unblock_ip(ip)
            self._active.pop(ip, None)
        if existed and self._on_change:
            self._on_change("unblock", ip, "manual/expired", "")
        return existed

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._active

    def sweep(self) -> None:
        """Lift blocks whose lifetime has passed. Call periodically."""
        now = time.time()
        expired = []
        with self._lock:
            for ip, info in list(self._active.items()):
                if info["until"] and now >= info["until"]:
                    expired.append(ip)
        for ip in expired:
            self.unblock(ip)

    def active(self) -> list[dict]:
        with self._lock:
            now = time.time()
            rows = []
            for ip, info in self._active.items():
                rows.append({
                    "ip": ip,
                    "reason": info["reason"],
                    "source": info["source"],
                    "age": round(now - info["created"], 1),
                    "remaining": round(info["until"] - now, 1) if info["until"] else None,
                })
            return sorted(rows, key=lambda r: r["age"])

    def add_safe(self, ip: str) -> None:
        with self._lock:
            self._safe.add(ip)

    def safelist(self) -> list[str]:
        with self._lock:
            return sorted(self._safe)
