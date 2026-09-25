"""
fwcore - core engine for the AI-Based Dynamic Firewall System.

This package contains the real packet-filtering engine. Packets are handed to
us by the Linux kernel through NFQUEUE; every module here works on those real
packets. Nothing in this project fabricates traffic.

Modules
-------
packet      Parse raw packet bytes into a PacketInfo object.
rules       Ordered allow/deny rule engine (first match wins).
conntrack   Lightweight stateful connection tracking.
detectors   Behaviour detectors (port scan, floods, brute force).
blocklist   Dynamic, time-limited blocking with a safelist.
ai          Unsupervised anomaly model that learns *your* normal traffic.
netfilter   Talks to iptables / ip6tables / ipset in the kernel.
storage     SQLite event/alert/block history for the dashboard.
stats       Fast in-memory counters for the live view.
engine      Ties everything together into one decision pipeline.
config      Loads and saves settings.
"""

__version__ = "1.0.0"
__all__ = [
    "packet", "rules", "conntrack", "detectors", "blocklist",
    "ai", "netfilter", "storage", "stats", "engine", "config",
]
