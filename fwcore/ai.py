"""
ai.py - the "AI" part, done honestly.

The AI here is both real and appropriate for a firewall: an
**unsupervised anomaly detector**.

Why unsupervised?
-----------------
To train a normal (supervised) classifier you need labelled examples of attacks.
We don't have real attacks, and inventing fake ones would just teach the model
those fakes. Instead we learn what *your* normal traffic looks like and then flag
anything that doesn't fit. This needs no attack data at all - only the ordinary
traffic your machine already sees.

How it works
------------
1. LEARN: while you use the machine normally, we turn each packet into a short
   list of numbers (its "features") and collect them.
2. TRAIN: we fit an Isolation Forest on those numbers. An Isolation Forest is a
   model that learns the shape of "normal" and can then score how far any new
   point sits outside it. (Intuition: unusual points are easy to separate from
   the crowd with a few random cuts, so they get isolated quickly.)
3. PROTECT: every new packet is scored. A score below the threshold means
   "this doesn't look like your normal traffic" and raises an alert. We also
   report *which feature* was most unusual, so the alert is explainable rather
   than a black box.

The features are per-source, short-memory summaries so the model can react to
behaviour (bursts, fan-out) and not just single packets.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    _HAVE_SKLEARN = True
except Exception:                       # pragma: no cover
    _HAVE_SKLEARN = False

from .config import DATA_DIR
from .packet import PacketInfo

MODEL_PATH = os.path.join(DATA_DIR, "model.npz")

# Names of the features we compute, in order. Keeping them named makes the
# alerts explainable ("the unusual thing was distinct_dports").
FEATURE_NAMES = [
    "packet_len",          # size of the packet
    "protocol",            # 6=tcp, 17=udp, 1=icmp (as-is; trees handle this fine)
    "dport",               # destination port
    "is_syn",              # 1 if a bare SYN (new connection attempt)
    "pkts_last_5s",        # packets from this source in the last 5 seconds
    "distinct_dports_10s", # distinct destination ports from this source in 10s
    "distinct_dsts_10s",   # distinct destinations from this source in 10s
    "inbound",             # 1 if inbound
]


class _SourceMemory:
    """Short rolling memory per source address, for the behavioural features."""

    def __init__(self):
        self.times = deque()             # packet timestamps (last 5s)
        self.ports = deque()             # (t, dport) last 10s
        self.dsts = deque()              # (t, dst) last 10s

    def update(self, pkt: PacketInfo, now: float):
        self.times.append(now)
        self.ports.append((now, pkt.dport))
        self.dsts.append((now, pkt.dst))
        while self.times and self.times[0] < now - 5:
            self.times.popleft()
        while self.ports and self.ports[0][0] < now - 10:
            self.ports.popleft()
        while self.dsts and self.dsts[0][0] < now - 10:
            self.dsts.popleft()


class AnomalyModel:
    """
    Learns normal traffic and scores new packets. Thread-safe. Degrades
    gracefully: if scikit-learn is missing it simply reports "not ready".
    """

    def __init__(self, cfg: dict):
        ai = cfg.get("ai", {})
        self.contamination = ai.get("contamination", 0.02)
        self.min_rows = ai.get("min_training_rows", 200)
        self.threshold = ai.get("score_threshold", 0.0)
        self._lock = threading.RLock()
        self._model = None
        self._mean = None                # feature means (for explainability)
        self._std = None
        self._mem: dict[str, _SourceMemory] = defaultdict(_SourceMemory)
        self._learning = False
        self._collected: list[list[float]] = []
        self._trained_at = 0.0
        self._trained_rows = 0
        self.load()

    # -- feature extraction -------------------------------------------------
    def features(self, pkt: PacketInfo) -> list[float]:
        now = time.time()
        mem = self._mem[pkt.src]
        mem.update(pkt, now)
        distinct_ports = len({p for _, p in mem.ports})
        distinct_dsts = len({d for _, d in mem.dsts})
        return [
            float(pkt.length),
            float(pkt.protocol),
            float(pkt.dport),
            1.0 if pkt.is_syn_only else 0.0,
            float(len(mem.times)),
            float(distinct_ports),
            float(distinct_dsts),
            1.0 if pkt.direction == "in" else 0.0,
        ]

    # -- learning -----------------------------------------------------------
    def start_learning(self):
        with self._lock:
            self._learning = True
            self._collected = []

    def stop_learning(self):
        with self._lock:
            self._learning = False

    @property
    def learning(self) -> bool:
        return self._learning

    def observe(self, pkt: PacketInfo) -> None:
        """During learning, record this packet's features."""
        if not self._learning:
            return
        feats = self.features(pkt)
        with self._lock:
            if len(self._collected) < 200000:      # cap memory
                self._collected.append(feats)

    def collected_rows(self) -> int:
        with self._lock:
            return len(self._collected)

    def train(self) -> dict:
        """Fit the Isolation Forest on whatever we've collected so far."""
        if not _HAVE_SKLEARN:
            return {"ok": False, "error": "scikit-learn not installed"}
        with self._lock:
            rows = list(self._collected)
        if len(rows) < self.min_rows:
            return {"ok": False, "error": f"need >= {self.min_rows} rows, have {len(rows)}"}
        X = np.array(rows, dtype=float)
        model = IsolationForest(
            n_estimators=120, contamination=self.contamination,
            random_state=42, n_jobs=-1,
        )
        model.fit(X)
        with self._lock:
            self._model = model
            self._mean = X.mean(axis=0)
            # Floor the standard deviation at 1.0 so features that barely vary
            # (like the 0/1 flags) can't produce absurd "1000x off" explanations
            # from a near-zero denominator.
            self._std = np.maximum(X.std(axis=0), 1.0)
            self._trained_at = time.time()
            self._trained_rows = len(rows)
            self._learning = False
        self.save()
        return {"ok": True, "rows": len(rows), "features": len(FEATURE_NAMES)}

    # -- scoring ------------------------------------------------------------
    @property
    def ready(self) -> bool:
        return self._model is not None

    def score(self, pkt: PacketInfo):
        """
        Return (is_anomaly, score, explanation) for a packet.
        score < threshold  => anomaly. explanation names the most unusual feature.
        If the model isn't trained yet, returns (False, None, "").
        """
        if self._model is None:
            return False, None, ""
        feats = self.features(pkt)
        X = np.array([feats], dtype=float)
        with self._lock:
            # decision_function centres the boundary at 0 using the model's
            # contamination setting: >0 means normal, <0 means anomaly. This is
            # the right function to compare against a fixed threshold.
            score = float(self._model.decision_function(X)[0])
            mean, std = self._mean, self._std
        is_anom = score < self.threshold
        explanation = ""
        if is_anom and mean is not None:
            z = np.abs((np.array(feats) - mean) / std)
            idx = int(np.argmax(z))
            multiple = min(z[idx], 999)   # cap so the text stays readable
            explanation = (f"{FEATURE_NAMES[idx]}={feats[idx]:.0f} "
                           f"(normal ~{mean[idx]:.0f}, {multiple:.1f} sigma off)")
        return is_anom, score, explanation

    # -- persistence --------------------------------------------------------
    def save(self) -> None:
        if self._model is None:
            return
        try:
            import joblib
            os.makedirs(DATA_DIR, exist_ok=True)
            joblib.dump(
                {"model": self._model, "mean": self._mean, "std": self._std,
                 "trained_at": self._trained_at, "rows": self._trained_rows},
                MODEL_PATH.replace(".npz", ".pkl"),
            )
        except Exception:
            pass

    def load(self) -> None:
        path = MODEL_PATH.replace(".npz", ".pkl")
        if not os.path.exists(path):
            return
        try:
            import joblib
            data = joblib.load(path)
            with self._lock:
                self._model = data["model"]
                self._mean = data["mean"]
                self._std = data["std"]
                self._trained_at = data.get("trained_at", 0)
                self._trained_rows = data.get("rows", 0)
        except Exception:
            pass

    def status(self) -> dict:
        return {
            "ready": self.ready,
            "learning": self._learning,
            "collected_rows": self.collected_rows(),
            "trained_rows": self._trained_rows,
            "trained_at": self._trained_at,
            "have_sklearn": _HAVE_SKLEARN,
            "features": FEATURE_NAMES,
        }
