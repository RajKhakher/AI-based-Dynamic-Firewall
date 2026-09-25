"""
Unit tests for the firewall's core logic.

These test the parts that don't need root or the kernel: packet parsing, the
rule engine, connection tracking, the detectors, and the AI model. Run with:

    python3 -m pytest tests/test_core.py -v
or simply:
    python3 tests/test_core.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from fwcore.packet import parse, INBOUND, OUTBOUND, SYN
from fwcore.rules import RuleSet, Rule, ALLOW, DENY, REJECT
from fwcore.conntrack import ConnTrack, NEW, ESTABLISHED
from fwcore.detectors import DetectorSuite
from fwcore.config import DEFAULTS


def _pkt(raw, direction=INBOUND):
    p = parse(raw)
    p.direction = direction
    return p


# -- packet parsing ---------------------------------------------------------
def test_parse_tcp_syn():
    p = parse(bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags="S")))
    assert p.src == "1.2.3.4" and p.dst == "5.6.7.8"
    assert p.proto == "tcp" and p.dport == 80 and p.is_syn_only


def test_parse_udp_and_icmp():
    u = parse(bytes(IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / b"hi"))
    assert u.proto == "udp" and u.dport == 53
    ic = parse(bytes(IP(src="9.9.9.9", dst="8.8.8.8") / ICMP()))
    assert ic.is_icmp


def test_parse_ipv6():
    p = parse(bytes(IPv6(src="::1", dst="::2") / TCP(sport=40000, dport=443, flags="SA")))
    assert p.version == 6 and p.proto == "tcp" and p.dport == 443


def test_parse_malformed():
    assert parse(b"").malformed
    assert parse(b"\x45\x00\x00").malformed


# -- rule engine ------------------------------------------------------------
def test_rule_first_match_wins():
    rs = RuleSet()
    rs._rules = [
        Rule(id=1, action=ALLOW, direction="in", protocol="tcp", dst_ports=22).compile(),
        Rule(id=2, action=DENY, direction="in", protocol="tcp", dst_ports=22).compile(),
    ]
    action, rule = rs.evaluate(_pkt(bytes(IP(src="9.9.9.9", dst="10.0.0.1") / TCP(dport=22, flags="S"))))
    assert action == ALLOW and rule.id == 1


def test_rule_cidr_and_ports():
    rs = RuleSet()
    rs._rules = [Rule(id=1, action=DENY, direction="in", protocol="tcp",
                      src="203.0.113.0/24", dst_ports="8000-8100").compile()]
    hit = _pkt(bytes(IP(src="203.0.113.5", dst="10.0.0.1") / TCP(sport=5, dport=8050, flags="S")))
    miss = _pkt(bytes(IP(src="198.51.100.5", dst="10.0.0.1") / TCP(sport=5, dport=8050, flags="S")))
    assert rs.evaluate(hit)[0] == DENY
    assert rs.evaluate(miss)[0] == ""      # no match -> default


def test_rule_no_match_returns_empty():
    rs = RuleSet()
    rs._rules = [Rule(id=1, action=DENY, direction="in", protocol="tcp", dst_ports=23).compile()]
    assert rs.evaluate(_pkt(bytes(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="S"))))[0] == ""


# -- conntrack --------------------------------------------------------------
def test_conntrack_reply_is_established():
    ct = ConnTrack()
    out = _pkt(bytes(IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=44444, dport=443, flags="S")), OUTBOUND)
    assert ct.update(out) == NEW
    rep = _pkt(bytes(IP(src="1.1.1.1", dst="10.0.0.5") / TCP(sport=443, dport=44444, flags="SA")), INBOUND)
    assert ct.update(rep) == ESTABLISHED
    assert ct.is_reply_to_us(rep)


# -- detectors --------------------------------------------------------------
def test_detector_portscan():
    s = DetectorSuite(DEFAULTS)
    fired = False
    for port in range(1000, 1020):
        for a in s.inspect(_pkt(bytes(IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=5555, dport=port, flags="S")))):
            if a.kind == "portscan":
                fired = True
    assert fired


def test_detector_synflood():
    s = DetectorSuite(DEFAULTS)
    fired = False
    for i in range(120):
        for a in s.inspect(_pkt(bytes(IP(src="203.0.113.10", dst="10.0.0.5") / TCP(sport=6000 + i % 50, dport=80, flags="S")))):
            if a.kind == "syn_flood":
                fired = True
    assert fired


def test_detector_no_false_alarm_on_normal():
    s = DetectorSuite(DEFAULTS)
    any_fire = False
    for i in range(5):
        if s.inspect(_pkt(bytes(IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=8000 + i, dport=443, flags="S")))):
            any_fire = True
    assert not any_fire


# -- AI model ---------------------------------------------------------------
def test_ai_learns_and_flags():
    import fwcore.ai as ai
    clock = {"t": 5000.0}
    real = ai.time.time
    ai.time.time = lambda: clock["t"]
    try:
        m = ai.AnomalyModel(DEFAULTS)
        m.start_learning()
        import random
        random.seed(1)
        for i in range(1500):
            clock["t"] += 0.5
            src = random.choice(["10.0.0.10", "10.0.0.11"])
            dport = random.choice([80, 443, 443, 53])
            p = _pkt(bytes(IP(src=src, dst="10.0.0.5") / TCP(sport=random.randint(30000, 60000), dport=dport, flags="S")))
            m.observe(p)
        assert m.train()["ok"]
        # A heavy fan-out (scan-like) source should be flagged.
        odd = "203.0.113.50"
        for port in range(1, 120):
            clock["t"] += 0.02
            m.score(_pkt(bytes(IP(src=odd, dst="10.0.0.5") / TCP(sport=51000, dport=port, flags="S"))))
        is_anom, score, expl = m.score(_pkt(bytes(IP(src=odd, dst="10.0.0.5") / TCP(sport=51000, dport=31337, flags="S"))))
        # It must be flagged as anomalous, with a non-empty human explanation.
        assert is_anom and expl
    finally:
        ai.time.time = real


def _run_all():
    """Tiny runner so the file works without pytest installed."""
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} unit tests passed")
    return passed == len(fns)


if __name__ == "__main__":
    ok = _run_all()
    sys.exit(0 if ok else 1)
