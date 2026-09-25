"""
config.py - load and save the firewall's settings.

Everything the firewall does is driven by a single JSON file (data/config.json).
If it doesn't exist yet, we create it with safe defaults. Keeping it in one
place means the dashboard and the engine always agree on the settings.
"""

from __future__ import annotations

import json
import os
import threading
from copy import deepcopy

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")

# ---------------------------------------------------------------------------
# Default settings. Chosen to be safe on a machine you might be connected to
# over SSH: the firewall starts in "monitor" mode (it watches and logs but does
# not drop anything) and fails open (if the process dies, traffic still flows).
# ---------------------------------------------------------------------------
DEFAULTS = {
    "mode": "monitor",                 # "monitor" = observe only, "enforce" = actually block
    "fail_open": True,                 # if the firewall crashes, let traffic through (safer for remote boxes)

    "default_policy": {
        "in": "allow",                 # default for inbound packets with no matching rule
        "out": "allow",                # default for outbound packets with no matching rule
    },

    # Addresses that must NEVER be blocked, so the firewall can't lock you out.
    # Loopback and link-local are always safe; add your own admin IP here.
    "safelist": [
        "127.0.0.1", "::1",
    ],
    "safelist_keep_gateway": True,     # also never block the default gateway / DNS servers

    "queues": {"in": 0, "out": 1},     # NFQUEUE numbers for inbound / outbound

    # Behaviour detectors (all counts are within the given window in seconds).
    "detectors": {
        "enabled": True,
        "portscan": {"ports": 15, "window": 10, "block_seconds": 300},
        "syn_flood": {"count": 100, "window": 5, "block_seconds": 120},
        "udp_flood": {"count": 300, "window": 5, "block_seconds": 120},
        "icmp_flood": {"count": 100, "window": 5, "block_seconds": 120},
        "bruteforce": {"count": 10, "window": 30, "ports": [22, 23, 3389, 21, 3306, 5432],
                       "block_seconds": 300},
    },

    # Unsupervised AI anomaly detection.
    "ai": {
        "enabled": True,
        "auto_block": False,           # when the AI flags a packet, block automatically?
        "block_seconds": 120,
        "contamination": 0.02,         # expected fraction of odd traffic while learning
        "min_training_rows": 200,      # need at least this many samples before training
        "score_threshold": 0.0,        # <0 = anomaly (IsolationForest convention)
    },

    "web": {
        "host": "127.0.0.1",
        "port": 5000,
        "session_hours": 8,
    },

    "logging": {
        "sample_allowed": 1,           # store 1 in N allowed packets (1 = store all)
        "keep_events": 50000,          # trim the events table beyond this many rows
    },
}

_lock = threading.RLock()
_cache: dict | None = None


def _deep_merge(base: dict, override: dict) -> dict:
    """Return base updated with override, recursively (override wins)."""
    out = deepcopy(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = deepcopy(val)
    return out


def load() -> dict:
    """Load config from disk (creating it with defaults if missing)."""
    global _cache
    with _lock:
        if _cache is not None:
            return deepcopy(_cache)
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as f:
                    on_disk = json.load(f)
                merged = _deep_merge(DEFAULTS, on_disk)
            except Exception:
                merged = deepcopy(DEFAULTS)
        else:
            merged = deepcopy(DEFAULTS)
            with open(CONFIG_PATH, "w") as f:
                json.dump(merged, f, indent=2)
        _cache = merged
        return deepcopy(_cache)


def save(cfg: dict) -> None:
    """Persist a full config dict to disk and refresh the cache."""
    global _cache
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        merged = _deep_merge(DEFAULTS, cfg)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(merged, f, indent=2)
        os.replace(tmp, CONFIG_PATH)
        _cache = merged


def update(path: list[str], value) -> dict:
    """
    Update one nested setting, e.g. update(["mode"], "enforce") or
    update(["ai", "auto_block"], True). Returns the new full config.
    """
    with _lock:
        cfg = load()
        node = cfg
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = value
        save(cfg)
        return cfg
