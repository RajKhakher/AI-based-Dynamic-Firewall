"""
engine.py - the decision pipeline that ties every part together.

This is the core of the firewall. The kernel sends us every packet through two
NFQUEUE queues (inbound and outbound). For each packet we run one clear pipeline
and then give the kernel a verdict: ACCEPT (let it through) or DROP (stop it).

The pipeline, in order, for one packet:

  1. Parse the raw bytes into a PacketInfo.
  2. Stateful check: is this part of a conversation we already allowed? If it's
     a reply to something we sent, accept it (that's what "stateful" means).
  3. Dynamic blocklist: is the source already blocked? (Belt and braces - the
     kernel ipset usually catches these first, but a just-decided block is
     honoured here immediately.)
  4. Rules: run the ordered rule list. First match wins -> allow / deny / reject.
     If nothing matches, use the default policy for the direction.
  5. Detectors: update the behaviour detectors; if one fires, raise an alert and
     (in enforce mode) block the source.
  6. AI: score the packet against the learned model of normal traffic; if it's
     anomalous, raise an alert and (if auto-block is on) block the source.
  7. Record stats + history, and return the verdict.

Two modes:
  * monitor  - everything runs and is logged, but nothing is ever dropped. Safe
               for watching a live machine without risk of cutting it off.
  * enforce  - deny/reject rules and blocks actually stop packets.

If the firewall is only *observing* (monitor mode) it still calls .accept() so
traffic is never interrupted.
"""

from __future__ import annotations

import socket
import threading
import time

from netfilterqueue import NetfilterQueue

from . import config
from .packet import parse, INBOUND, OUTBOUND
from .rules import RuleSet, ALLOW, DENY, REJECT
from .conntrack import ConnTrack
from .detectors import DetectorSuite
from .blocklist import DynamicBlocklist
from .ai import AnomalyModel
from .netfilter import NetfilterManager
from .storage import Storage
from .stats import Stats


class FirewallEngine:
    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or config.load()
        self.mode = self.cfg.get("mode", "monitor")
        q = self.cfg.get("queues", {"in": 0, "out": 1})

        # Kernel plumbing.
        self.netfilter = NetfilterManager(
            queue_in=q["in"], queue_out=q["out"],
            fail_open=self.cfg.get("fail_open", True),
        )
        # Components.
        self.rules = RuleSet().load()
        self.conntrack = ConnTrack()
        self.detectors = DetectorSuite(self.cfg)
        self.ai = AnomalyModel(self.cfg)
        self.stats = Stats()
        self.storage = Storage(keep_events=self.cfg.get("logging", {}).get("keep_events", 50000))
        self.blocklist = DynamicBlocklist(
            self.netfilter,
            safelist=self.cfg.get("safelist", []),
            keep_gateway=self.cfg.get("safelist_keep_gateway", True),
            on_change=self._on_block_change,
        )

        self._sample = max(1, int(self.cfg.get("logging", {}).get("sample_allowed", 1)))
        self._q_in = None
        self._q_out = None
        self._running = threading.Event()
        self._thread = None
        self._sweeper = None
        self._pkt_counter = 0

    # -- block logging ------------------------------------------------------
    def _on_block_change(self, event, ip, reason, source):
        self.storage.log_block(event, ip, reason, source)

    # -- packet callbacks ---------------------------------------------------
    def _handle(self, nfpacket, direction: str):
        """The heart of the firewall: decide one packet's fate."""
        try:
            pkt = parse(nfpacket.get_payload())
            pkt.direction = direction

            verdict, reason = self._decide(pkt)

            # Apply verdict. In monitor mode we never actually drop.
            if verdict == "drop" and self.mode == "enforce":
                nfpacket.drop()
            else:
                nfpacket.accept()

            # Record (sampled for allowed traffic to keep the DB small).
            action = "allow" if verdict == "accept" else verdict
            self.stats.record(pkt, "allow" if verdict == "accept" else "deny")
            self._pkt_counter += 1
            if verdict != "accept" or self._pkt_counter % self._sample == 0:
                self.storage.log_event(pkt, action, reason)
        except Exception as e:
            # Never let an error stop traffic: accept and move on.
            try:
                nfpacket.accept()
            except Exception:
                pass

    def _decide(self, pkt) -> tuple[str, str]:
        """
        Return (verdict, reason) where verdict is "accept", "drop", or "reject".
        In monitor mode the caller won't act on drop/reject, but we still compute
        and log what *would* have happened.
        """
        # Loopback (127.x / ::1) is the machine talking to itself - inherently
        # trusted. We accept it without running detectors or the AI, so the
        # firewall's own dashboard traffic doesn't drown the analysis in noise.
        if pkt.src.startswith("127.") or pkt.src == "::1" or pkt.dst == "::1":
            return "accept", "loopback (trusted)"

        # 2. Stateful: replies to connections we started are always allowed.
        state = self.conntrack.update(pkt)
        if pkt.direction == INBOUND and self.conntrack.is_reply_to_us(pkt):
            return "accept", "established (reply to outbound)"

        # 3. Already blocked?
        if pkt.direction == INBOUND and self.blocklist.is_blocked(pkt.src):
            return "drop", "source is on the dynamic blocklist"

        # 4. Rules (first match wins).
        action, rule = self.rules.evaluate(pkt)
        if action == "":
            action = self.cfg["default_policy"].get(pkt.direction, "allow")
            reason = f"default policy ({pkt.direction})"
            rule_id = None
        else:
            reason = f"rule #{rule.id}: {rule.comment or rule.action}"
            rule_id = rule.id

        # 5. Detectors (only meaningful for inbound).
        for alert in self.detectors.inspect(pkt):
            self.stats.record_alert()
            acted = ""
            if self.mode == "enforce" and alert.block_seconds:
                if self.blocklist.block(alert.src, alert.block_seconds,
                                        f"{alert.kind}: {alert.detail}", source="detector"):
                    acted = f"blocked {alert.block_seconds}s"
            self.storage.log_alert(alert, acted)
            # A detector firing forces a drop of this packet in enforce mode.
            if action == ALLOW:
                action, reason = DENY, f"detector: {alert.kind}"

        # 6. AI anomaly scoring.
        if self.cfg.get("ai", {}).get("enabled", True):
            if self.ai.learning:
                self.ai.observe(pkt)
            elif self.ai.ready:
                is_anom, score, expl = self.ai.score(pkt)
                if is_anom:
                    self.stats.record_ai_flag()
                    from .detectors import Alert
                    alert = Alert(kind="ai_anomaly", src=pkt.src, severity="medium",
                                  detail=f"unusual traffic: {expl}",
                                  block_seconds=self.cfg["ai"].get("block_seconds", 120),
                                  evidence={"score": round(score, 3), "explain": expl})
                    acted = ""
                    if self.cfg["ai"].get("auto_block") and self.mode == "enforce":
                        if self.blocklist.block(pkt.src, alert.block_seconds,
                                                f"ai_anomaly: {expl}", source="ai"):
                            acted = "blocked"
                            if action == ALLOW:
                                action, reason = DENY, "ai anomaly"
                    self.storage.log_alert(alert, acted)

        # Translate rule action into a queue verdict.
        if action == ALLOW:
            return "accept", reason
        if action == REJECT:
            return "reject", reason
        return "drop", reason

    # -- run / stop ---------------------------------------------------------
    def start(self, background: bool = True):
        """Install kernel hooks and begin processing packets.

        We give the inbound and outbound queues a thread each. Servicing them
        from a single thread let one queue starve the other (an accepted inbound
        request could sit un-replied because the outbound reply was never read),
        so each queue gets its own reader.
        """
        self.netfilter.install()
        self._running.set()
        self._q_in = NetfilterQueue()
        self._q_in.bind(self.cfg["queues"]["in"], lambda p: self._handle(p, INBOUND))
        self._q_out = NetfilterQueue()
        self._q_out.bind(self.cfg["queues"]["out"], lambda p: self._handle(p, OUTBOUND))
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True, name="sweeper")
        self._sweeper.start()

        self._readers = [
            threading.Thread(target=self._queue_loop, args=(self._q_in,),
                             daemon=True, name="fw-in"),
            threading.Thread(target=self._queue_loop, args=(self._q_out,),
                             daemon=True, name="fw-out"),
        ]
        for t in self._readers:
            t.start()
        if not background:
            # Foreground: block until stopped.
            try:
                while self._running.is_set():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass

    def _queue_loop(self, nfq: NetfilterQueue):
        """Read and process one queue until the engine stops.

        The socket has a 1-second timeout so this loop can notice that we've
        been asked to stop and exit cleanly, instead of blocking forever.
        """
        s = socket.fromfd(nfq.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        while self._running.is_set():
            try:
                nfq.run_socket(s)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                if not self._running.is_set():
                    break
        try:
            s.close()
        except Exception:
            pass

    def _sweep_loop(self):
        """Periodic housekeeping: expire dynamic blocks."""
        while self._running.is_set():
            time.sleep(2)
            try:
                self.blocklist.sweep()
            except Exception:
                pass

    def set_mode(self, mode: str):
        assert mode in ("monitor", "enforce")
        self.mode = mode
        self.cfg = config.update(["mode"], mode)

    def stop(self):
        """Stop processing and remove all kernel hooks. Always safe to call."""
        self._running.clear()
        for t in getattr(self, "_readers", []):
            t.join(timeout=3)
        for q in (self._q_in, self._q_out):
            try:
                if q:
                    q.unbind()
            except Exception:
                pass
        try:
            self.netfilter.remove()
        except Exception:
            pass
        try:
            self.storage.close()
        except Exception:
            pass

    # -- dashboard helpers --------------------------------------------------
    def status(self) -> dict:
        return {
            "mode": self.mode,
            "fail_open": self.cfg.get("fail_open", True),
            "rules": len(self.rules),
            "connections": self.conntrack.count(),
            "blocked": len(self.blocklist.active()),
            "ai": self.ai.status(),
            "stats": self.stats.snapshot(),
        }
