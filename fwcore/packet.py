"""
packet.py - turn raw packet bytes into a structured object.

The kernel gives us each packet as a block of raw bytes (the IP header, then a
TCP/UDP/ICMP header, then the payload). This module reads those bytes by hand,
field by field, and returns a small PacketInfo object the rest of the engine can
use. Doing it by hand (rather than leaning on a big library in the hot path)
keeps it fast and makes it clear exactly what each byte means.

We parse:
  - IPv4 and IPv6 headers  -> addresses, protocol, length, TTL/hop limit
  - TCP                    -> ports, flags (SYN, ACK, FIN, RST, ...)
  - UDP                    -> ports
  - ICMP / ICMPv6          -> type, code

Everything is defensive: a malformed or truncated packet never raises, it just
comes back with whatever could be read and `malformed=True`.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# Direction of travel relative to THIS machine.
INBOUND = "in"       # someone -> us
OUTBOUND = "out"     # us -> someone

# TCP flag bit masks.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# IP protocol numbers we name explicitly.
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

_PROTO_NAMES = {
    PROTO_ICMP: "icmp",
    PROTO_TCP: "tcp",
    PROTO_UDP: "udp",
    PROTO_ICMPV6: "icmpv6",
}


def proto_name(number: int) -> str:
    """Human-readable protocol name, e.g. 6 -> 'tcp'."""
    return _PROTO_NAMES.get(number, f"proto{number}")


def tcp_flag_string(flags: int) -> str:
    """Render a TCP flags byte as e.g. 'SYN,ACK'. Empty string if none set."""
    names = []
    for bit, name in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"),
                      (RST, "RST"), (PSH, "PSH"), (URG, "URG"),
                      (ECE, "ECE"), (CWR, "CWR")):
        if flags & bit:
            names.append(name)
    return ",".join(names)


@dataclass
class PacketInfo:
    """Everything the engine needs to know about one packet."""

    version: int = 4              # 4 or 6
    src: str = ""                 # source IP as text
    dst: str = ""                 # destination IP as text
    protocol: int = 0             # IP protocol number
    proto: str = ""               # protocol name (tcp/udp/icmp/...)
    length: int = 0               # total packet length in bytes
    ttl: int = 0                  # IPv4 TTL or IPv6 hop limit
    sport: int = 0                # source port (0 if not applicable)
    dport: int = 0                # destination port (0 if not applicable)
    tcp_flags: int = 0            # raw TCP flags byte
    flags_str: str = ""           # readable TCP flags
    icmp_type: int = -1           # ICMP type (-1 if not ICMP)
    icmp_code: int = -1           # ICMP code
    direction: str = INBOUND      # filled in by the engine from the queue
    payload_len: int = 0          # bytes of L4 payload
    malformed: bool = False       # parsing hit a problem
    raw_len: int = 0              # length of the raw buffer we were given

    # Convenience -----------------------------------------------------------
    @property
    def is_tcp(self) -> bool:
        return self.protocol == PROTO_TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == PROTO_UDP

    @property
    def is_icmp(self) -> bool:
        return self.protocol in (PROTO_ICMP, PROTO_ICMPV6)

    @property
    def is_syn_only(self) -> bool:
        """A bare SYN = a brand-new connection attempt."""
        return self.is_tcp and (self.tcp_flags & SYN) and not (self.tcp_flags & ACK)

    def summary(self) -> str:
        base = f"{self.proto} {self.src}"
        if self.sport:
            base += f":{self.sport}"
        base += f" -> {self.dst}"
        if self.dport:
            base += f":{self.dport}"
        if self.flags_str:
            base += f" [{self.flags_str}]"
        return base


def _parse_l4(proto: int, data: bytes, info: PacketInfo) -> None:
    """Parse the transport header (TCP/UDP/ICMP) sitting after the IP header."""
    try:
        if proto == PROTO_TCP and len(data) >= 14:
            sport, dport = struct.unpack("!HH", data[0:4])
            data_offset = (data[12] >> 4) * 4
            flags = data[13]
            info.sport, info.dport = sport, dport
            info.tcp_flags = flags
            info.flags_str = tcp_flag_string(flags)
            info.payload_len = max(0, len(data) - data_offset)
        elif proto == PROTO_UDP and len(data) >= 8:
            sport, dport, ulen, _ = struct.unpack("!HHHH", data[0:8])
            info.sport, info.dport = sport, dport
            info.payload_len = max(0, len(data) - 8)
        elif proto in (PROTO_ICMP, PROTO_ICMPV6) and len(data) >= 2:
            info.icmp_type = data[0]
            info.icmp_code = data[1]
            info.payload_len = max(0, len(data) - 8)
    except Exception:
        info.malformed = True


def parse(raw: bytes) -> PacketInfo:
    """
    Parse a raw IPv4 or IPv6 packet (as delivered by NFQUEUE) into PacketInfo.
    Never raises: on trouble it returns a best-effort object with malformed=True.
    """
    info = PacketInfo()
    info.raw_len = len(raw)
    if not raw:
        info.malformed = True
        return info

    version = raw[0] >> 4
    info.version = version
    try:
        if version == 4:
            if len(raw) < 20:
                info.malformed = True
                return info
            ihl = (raw[0] & 0x0F) * 4
            total_len = struct.unpack("!H", raw[2:4])[0]
            info.ttl = raw[8]
            proto = raw[9]
            info.protocol = proto
            info.proto = proto_name(proto)
            info.src = socket.inet_ntop(socket.AF_INET, raw[12:16])
            info.dst = socket.inet_ntop(socket.AF_INET, raw[16:20])
            info.length = total_len or len(raw)
            _parse_l4(proto, raw[ihl:], info)
        elif version == 6:
            if len(raw) < 40:
                info.malformed = True
                return info
            payload_len = struct.unpack("!H", raw[4:6])[0]
            next_header = raw[6]
            info.ttl = raw[7]  # hop limit
            info.protocol = next_header
            info.proto = proto_name(next_header)
            info.src = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            info.dst = socket.inet_ntop(socket.AF_INET6, raw[24:40])
            info.length = 40 + payload_len
            # Note: IPv6 extension headers are not walked here; the common
            # case (TCP/UDP/ICMPv6 directly after the base header) is handled.
            _parse_l4(next_header, raw[40:], info)
        else:
            info.malformed = True
    except Exception:
        info.malformed = True
    return info
