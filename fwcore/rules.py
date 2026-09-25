"""
rules.py - the ordered rule list that decides allow / deny / reject.

This is what most people picture when they think "firewall": a list of rules
checked from top to bottom. The FIRST rule that matches a packet wins, and its
action is applied. If no rule matches, the default policy for that direction
(set in config) is used.

A rule can match on:
  - direction : "in", "out", or "any"
  - protocol  : "tcp", "udp", "icmp", "icmpv6", or "any"
  - src / dst : an IP or CIDR block (e.g. 10.0.0.0/8), or "any"
  - ports     : source and/or destination port(s): single, list, or range
  - action    : "allow", "deny" (silently drop), or "reject" (drop + tell sender)

Rules are stored in data/rules.json so they survive restarts and can be edited
from the dashboard.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
from dataclasses import dataclass, field, asdict

from .config import DATA_DIR
from .packet import PacketInfo, INBOUND, OUTBOUND

RULES_PATH = os.path.join(DATA_DIR, "rules.json")

ALLOW = "allow"
DENY = "deny"        # drop silently (attacker learns nothing)
REJECT = "reject"    # drop but send an ICMP/RST so the sender knows

VALID_ACTIONS = (ALLOW, DENY, REJECT)


def _parse_ports(spec) -> list[tuple[int, int]]:
    """
    Turn a port spec into a list of (low, high) ranges.
    Accepts: None/"any" -> [] (matches all), 80, "80", "1000-2000",
    [22, 80, "8000-8100"].
    """
    if spec in (None, "", "any", "*"):
        return []
    if isinstance(spec, int):
        return [(spec, spec)]
    if isinstance(spec, str):
        spec = [spec]
    ranges = []
    for item in spec:
        s = str(item).strip()
        if "-" in s:
            lo, hi = s.split("-", 1)
            ranges.append((int(lo), int(hi)))
        else:
            p = int(s)
            ranges.append((p, p))
    return ranges


def _port_matches(port: int, ranges: list[tuple[int, int]]) -> bool:
    if not ranges:            # empty = match any port
        return True
    for lo, hi in ranges:
        if lo <= port <= hi:
            return True
    return False


@dataclass
class Rule:
    id: int
    action: str = DENY
    direction: str = "any"          # in / out / any
    protocol: str = "any"           # tcp / udp / icmp / icmpv6 / any
    src: str = "any"                # IP or CIDR
    dst: str = "any"                # IP or CIDR
    src_ports: object = "any"       # see _parse_ports
    dst_ports: object = "any"
    log: bool = True
    enabled: bool = True
    comment: str = ""

    # Pre-computed matchers (not serialised).
    _src_net: object = field(default=None, repr=False, compare=False)
    _dst_net: object = field(default=None, repr=False, compare=False)
    _src_port_ranges: list = field(default_factory=list, repr=False, compare=False)
    _dst_port_ranges: list = field(default_factory=list, repr=False, compare=False)

    def compile(self) -> "Rule":
        """Pre-parse CIDRs and ports so matching is fast."""
        self._src_net = None if self.src in ("any", "*", "") else ipaddress.ip_network(self.src, strict=False)
        self._dst_net = None if self.dst in ("any", "*", "") else ipaddress.ip_network(self.dst, strict=False)
        self._src_port_ranges = _parse_ports(self.src_ports)
        self._dst_port_ranges = _parse_ports(self.dst_ports)
        return self

    def matches(self, pkt: PacketInfo) -> bool:
        if not self.enabled:
            return False
        # Direction
        if self.direction != "any" and self.direction != pkt.direction:
            return False
        # Protocol
        if self.protocol != "any" and self.protocol != pkt.proto:
            return False
        # Addresses
        try:
            if self._src_net is not None:
                if ipaddress.ip_address(pkt.src) not in self._src_net:
                    return False
            if self._dst_net is not None:
                if ipaddress.ip_address(pkt.dst) not in self._dst_net:
                    return False
        except ValueError:
            return False
        # Ports only apply to TCP/UDP
        if pkt.protocol in (6, 17):
            if not _port_matches(pkt.sport, self._src_port_ranges):
                return False
            if not _port_matches(pkt.dport, self._dst_port_ranges):
                return False
        elif self._src_port_ranges or self._dst_port_ranges:
            # A port-specific rule can't match a non-port protocol.
            return False
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if not k.startswith("_")}


class RuleSet:
    """An ordered, thread-safe collection of rules with load/save."""

    def __init__(self):
        self._rules: list[Rule] = []
        self._lock = threading.RLock()
        self._next_id = 1

    # -- persistence --------------------------------------------------------
    def load(self) -> "RuleSet":
        with self._lock:
            if os.path.exists(RULES_PATH):
                try:
                    with open(RULES_PATH) as f:
                        raw = json.load(f)
                    self._rules = [Rule(**r).compile() for r in raw]
                    self._next_id = max((r.id for r in self._rules), default=0) + 1
                except Exception:
                    self._rules = []
            if not self._rules:
                self._install_starter_rules()
            return self

    def save(self) -> None:
        with self._lock:
            os.makedirs(DATA_DIR, exist_ok=True)
            tmp = RULES_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump([r.to_dict() for r in self._rules], f, indent=2)
            os.replace(tmp, RULES_PATH)

    def _install_starter_rules(self) -> None:
        """A few sensible example rules so a fresh install isn't empty."""
        examples = [
            Rule(id=0, action=ALLOW, direction="any", protocol="any",
                 src="127.0.0.0/8", log=False, comment="Always allow loopback"),
            Rule(id=0, action=DENY, direction="in", protocol="tcp", dst_ports=23,
                 comment="Block inbound Telnet (insecure)"),
            Rule(id=0, action=REJECT, direction="in", protocol="tcp", dst_ports=445,
                 comment="Reject inbound SMB"),
        ]
        for r in examples:
            self.add(r.to_dict())

    # -- editing ------------------------------------------------------------
    def add(self, data: dict, position: int | None = None) -> Rule:
        with self._lock:
            data = dict(data)
            data.pop("id", None)
            data.pop("_src_net", None)
            data.pop("_dst_net", None)
            for k in ("_src_port_ranges", "_dst_port_ranges"):
                data.pop(k, None)
            action = data.get("action", DENY)
            if action not in VALID_ACTIONS:
                raise ValueError(f"invalid action: {action}")
            rule = Rule(id=self._next_id, **data).compile()
            self._next_id += 1
            if position is None or position >= len(self._rules):
                self._rules.append(rule)
            else:
                self._rules.insert(max(0, position), rule)
            self.save()
            return rule

    def delete(self, rule_id: int) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            changed = len(self._rules) != before
            if changed:
                self.save()
            return changed

    def update(self, rule_id: int, data: dict) -> Rule | None:
        with self._lock:
            for i, r in enumerate(self._rules):
                if r.id == rule_id:
                    merged = r.to_dict()
                    merged.update({k: v for k, v in data.items() if not k.startswith("_")})
                    merged["id"] = rule_id
                    new_rule = Rule(**merged).compile()
                    self._rules[i] = new_rule
                    self.save()
                    return new_rule
            return None

    def move(self, rule_id: int, new_index: int) -> bool:
        with self._lock:
            idx = next((i for i, r in enumerate(self._rules) if r.id == rule_id), None)
            if idx is None:
                return False
            rule = self._rules.pop(idx)
            self._rules.insert(max(0, min(new_index, len(self._rules))), rule)
            self.save()
            return True

    # -- matching -----------------------------------------------------------
    def evaluate(self, pkt: PacketInfo) -> tuple[str, Rule | None]:
        """
        Return (action, matching_rule). If no rule matches, returns
        ("", None) so the engine can apply the default policy.
        """
        with self._lock:
            for rule in self._rules:
                if rule.matches(pkt):
                    return rule.action, rule
        return "", None

    def all(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def __len__(self) -> int:
        return len(self._rules)
