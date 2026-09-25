#!/usr/bin/env python3
"""
lab.py - see the firewall filter REAL traffic on a single machine.

A firewall is normally tested with two computers: one runs the firewall, the
other sends traffic at it. If you only have one Linux machine, this script
builds that setup *inside* it using two network namespaces (think of them as two
tiny virtual computers joined by a virtual cable):

    lab_client  <---- virtual cable ---->  lab_fw   (runs the firewall)
    10.55.0.1                              10.55.0.2

It then runs the real firewall engine inside lab_fw and sends real traffic from
lab_client:

    1. a normal ping and TCP connection      -> must be ALLOWED
    2. a real nmap port scan                  -> must be DETECTED and BLOCKED
    3. traffic after the block                -> must be STOPPED

Nothing here is simulated inside the app: real packets cross a real (virtual)
link and the kernel enforces the verdicts. This touches only the private lab
namespaces, never your real network.

Usage:
    sudo python3 tools/lab.py            # run the demo
    sudo python3 tools/lab.py --cleanup  # remove the lab namespaces
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

CLIENT = "lab_client"
FW = "lab_fw"
CLIENT_IP = "10.55.0.1"
FW_IP = "10.55.0.2"


def sh(cmd, check=False, ns=None, capture=True):
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.run(cmd, capture_output=capture, text=True,
                          check=check)


def build_lab():
    teardown(quiet=True)
    sh(["ip", "netns", "add", CLIENT], check=True)
    sh(["ip", "netns", "add", FW], check=True)
    sh(["ip", "link", "add", "veth_c", "type", "veth", "peer", "name", "veth_f"], check=True)
    sh(["ip", "link", "set", "veth_c", "netns", CLIENT], check=True)
    sh(["ip", "link", "set", "veth_f", "netns", FW], check=True)
    sh(["ip", "addr", "add", f"{CLIENT_IP}/24", "dev", "veth_c"], ns=CLIENT)
    sh(["ip", "addr", "add", f"{FW_IP}/24", "dev", "veth_f"], ns=FW)
    for ns, dev in ((CLIENT, "veth_c"), (FW, "veth_f")):
        sh(["ip", "link", "set", dev, "up"], ns=ns)
        sh(["ip", "link", "set", "lo", "up"], ns=ns)


def teardown(quiet=False):
    # Best-effort firewall cleanup inside lab_fw before deleting it.
    for ipt in ("iptables", "ip6tables"):
        for chain, hook in (("AIFW_IN", "INPUT"), ("AIFW_OUT", "OUTPUT")):
            for _ in range(20):
                r = sh([ipt, "-D", hook, "-j", chain], ns=FW)
                if r.returncode != 0:
                    break
            sh([ipt, "-F", chain], ns=FW)
            sh([ipt, "-X", chain], ns=FW)
    for s in ("aifw_block4", "aifw_block6"):
        sh(["ipset", "destroy", s], ns=FW)
    sh(["ip", "netns", "del", CLIENT])
    sh(["ip", "netns", "del", FW])
    if not quiet:
        print("Lab removed.")


def ping_ok(count=2):
    r = sh(["ping", "-c", str(count), "-W", "1", FW_IP], ns=CLIENT)
    # Parse the "N received" field rather than the loss string, because
    # "100% packet loss" contains "0% packet loss" as a substring.
    for part in r.stdout.split(","):
        if "received" in part:
            try:
                return int(part.strip().split()[0]) > 0
            except (ValueError, IndexError):
                return False
    return False


def tcp_ok(port=9000):
    # Start a one-shot listener in lab_fw, connect from lab_client.
    sh(["sh", "-c", f"nc -l -p {port} -q1 </dev/null >/dev/null 2>&1 &"], ns=FW, capture=False)
    time.sleep(0.3)
    r = sh(["sh", "-c", f"echo hi | nc -w1 {FW_IP} {port} && echo OK"], ns=CLIENT)
    return "OK" in r.stdout


def run_demo():
    from fwcore import config
    from fwcore.engine import FirewallEngine

    print("Building the lab (two namespaces joined by a virtual cable)...")
    build_lab()

    # Run the engine INSIDE lab_fw by entering its namespace for this process's
    # network view. We do that by re-exec'ing ourselves under `ip netns exec`.
    if os.environ.get("LAB_IN_FW") != "1":
        env = dict(os.environ, LAB_IN_FW="1")
        print("Starting the firewall engine inside lab_fw...\n")
        proc = subprocess.run(
            ["ip", "netns", "exec", FW, sys.executable, __file__, "--inner"],
            env=env)
        teardown()
        sys.exit(proc.returncode)


def run_inner():
    """This half runs *inside* lab_fw's network namespace."""
    from fwcore import config
    from fwcore.engine import FirewallEngine

    cfg = config.load()
    cfg["mode"] = "enforce"
    cfg["queues"] = {"in": 0, "out": 1}
    eng = FirewallEngine(cfg)
    # Add a rule we can demonstrate: deny inbound TCP to port 9001.
    eng.rules.add({"action": "deny", "direction": "in", "protocol": "tcp",
                   "dst_ports": "9001", "comment": "lab demo: deny port 9001"})
    eng.start(background=True)
    time.sleep(1.5)

    results = []

    def check(name, ok):
        results.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")

    print("Running real traffic through the firewall:\n")
    check("normal ping is allowed", ping_ok())
    check("normal TCP connection is allowed (port 9002)", tcp_ok(9002))
    check("connection to a denied port is blocked (rule: deny 9001)", not tcp_ok(9001))

    print("\n  ... launching a real nmap port scan from the client ...")
    sh(["nmap", "-sS", "-p", "1-60", "--max-retries", "1", "-T5", FW_IP], ns=CLIENT)
    time.sleep(2)

    blocked = eng.blocklist.active()
    check("port scan was detected and the scanner blocked",
          any(b["ip"] == CLIENT_IP for b in blocked))
    check("traffic from the blocked scanner is now stopped", not ping_ok())

    alerts = eng.storage.recent_alerts(10)
    scan_alert = next((a for a in alerts if a["kind"] == "portscan"), None)
    if scan_alert:
        print(f"\n  Detector said: \"{scan_alert['detail']}\" -> {scan_alert['acted']}")

    eng.stop()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed.")
    print("The firewall filtered real packets: normal traffic through, the scan blocked.")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This needs root (it creates network namespaces). Try: sudo python3 tools/lab.py")
        sys.exit(1)
    if "--cleanup" in sys.argv:
        teardown()
    elif "--inner" in sys.argv:
        run_inner()
    else:
        run_demo()
