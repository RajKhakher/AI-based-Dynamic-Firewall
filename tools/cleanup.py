#!/usr/bin/env python3
"""
cleanup.py - remove any firewall rules left behind by a crash.

Normally the firewall cleans up after itself when you press Ctrl+C. But if it
was killed hard (kill -9, power loss), its kernel rules can be left in place.
Run this to wipe them and return networking to normal:

    sudo python3 tools/cleanup.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwcore.netfilter import NetfilterManager

if os.geteuid() != 0:
    print("Run with sudo: sudo python3 tools/cleanup.py")
    sys.exit(1)

nm = NetfilterManager()
nm.remove()
print("Firewall rules removed. Networking is back to normal.")
