"""
netfilter.py - the bridge between our Python code and the Linux kernel.

A firewall has to live in the kernel, because that is where packets actually
flow. We use three standard Linux tools:

  * iptables / ip6tables : install the rules that hand packets to our program
  * ipset                : a fast in-kernel list of blocked addresses
  * NFQUEUE              : the mechanism that passes each packet up to Python

How the hooks are laid out
--------------------------
We create our own chains (AIFW_IN, AIFW_OUT) and hook them into the kernel's
INPUT and OUTPUT chains, so we never disturb rules that are already there. Each
of our chains does two things, in order:

  1. If the source/destination is in our "blocked" ipset -> DROP immediately.
     (This is the dynamic blocking. Once an address is blocked, the kernel
     handles it at full speed and the packets never reach Python.)
  2. Otherwise -> send the packet to NFQUEUE, where Python inspects it.

The NFQUEUE rule uses `--queue-bypass` when fail-open is on: if our Python
process is not running, the kernel simply lets the packet through instead of
freezing the network. That keeps you from locking yourself out of a remote box.

Everything here is reversible: `remove()` deletes exactly what `install()`
added and nothing else.
"""

from __future__ import annotations

import shutil
import subprocess
import threading

# Our private chain names (unlikely to clash with anything).
CHAIN_IN = "AIFW_IN"
CHAIN_OUT = "AIFW_OUT"

# ipset names for the dynamic blocklist (v4 and v6).
SET_BLOCK4 = "aifw_block4"
SET_BLOCK6 = "aifw_block6"


class NetfilterError(RuntimeError):
    pass


def _run(cmd: list[str], check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        if not quiet:
            raise NetfilterError(f"command failed: {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc


class NetfilterManager:
    """Installs, tears down and updates the kernel-side firewall plumbing."""

    def __init__(self, queue_in: int = 0, queue_out: int = 1,
                 fail_open: bool = True, enable_ipv6: bool = True):
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.fail_open = fail_open
        self.enable_ipv6 = enable_ipv6
        self._installed = False
        self._lock = threading.RLock()
        self._check_tools()

    def _check_tools(self) -> None:
        for tool in ("iptables", "ipset"):
            if shutil.which(tool) is None:
                raise NetfilterError(
                    f"required tool '{tool}' not found. Install it "
                    f"(e.g. `sudo apt install {'iptables' if tool=='iptables' else 'ipset'}`).")
        self._have_ip6 = shutil.which("ip6tables") is not None
        if self.enable_ipv6 and not self._have_ip6:
            self.enable_ipv6 = False

    # -- lifecycle ----------------------------------------------------------
    def install(self) -> None:
        """Create ipsets and chains, and hook them into INPUT/OUTPUT."""
        with self._lock:
            self.remove(quiet=True)  # start from a clean slate
            self._create_ipsets()
            self._create_chains("iptables", SET_BLOCK4)
            if self.enable_ipv6:
                self._create_chains("ip6tables", SET_BLOCK6)
            self._installed = True

    def _create_ipsets(self) -> None:
        # `timeout 1` makes the set support per-entry timeouts (auto-expiry).
        _run(["ipset", "create", SET_BLOCK4, "hash:ip", "family", "inet",
              "timeout", "0", "-exist"])
        if self.enable_ipv6:
            _run(["ipset", "create", SET_BLOCK6, "hash:ip", "family", "inet6",
                  "timeout", "0", "-exist"])

    def _create_chains(self, ipt: str, setname: str) -> None:
        bypass = ["--queue-bypass"] if self.fail_open else []
        # Fresh chains.
        for chain, hook, direction_q in (
            (CHAIN_IN, "INPUT", self.queue_in),
            (CHAIN_OUT, "OUTPUT", self.queue_out),
        ):
            _run([ipt, "-N", chain], check=False, quiet=True)  # may already exist
            _run([ipt, "-F", chain])
            # Loopback (127.x / ::1, incl. this dashboard) skips the firewall.
            iface_flag = "-i" if chain == CHAIN_IN else "-o"
            _run([ipt, "-A", chain, iface_flag, "lo", "-j", "RETURN"])
            match_dir = "src" if chain == CHAIN_IN else "dst"
            # 1) kernel-level drop for anything already in the blocked set
            _run([ipt, "-A", chain, "-m", "set", "--match-set", setname,
                  match_dir, "-j", "DROP"])
            # 2) everything else goes up to Python for inspection
            _run([ipt, "-A", chain, "-j", "NFQUEUE", "--queue-num",
                  str(direction_q)] + bypass)
            # Hook our chain into the kernel's built-in chain (insert at top).
            # Guard against duplicates by deleting first.
            _run([ipt, "-D", hook, "-j", chain], check=False, quiet=True)
            _run([ipt, "-I", hook, "1", "-j", chain])

    def remove(self, quiet: bool = False) -> None:
        """Undo everything install() did. Safe to call even if not installed.

        A crashed run (killed with -9) can leave several copies of a hook
        stacked in INPUT/OUTPUT, so we delete each hook in a loop until it's
        gone, then flush and drop the chains, and only then destroy the ipsets
        (they can't be destroyed while a rule still references them).
        """
        with self._lock:
            for ipt, setname, have in (
                ("iptables", SET_BLOCK4, True),
                ("ip6tables", SET_BLOCK6, self._have_ip6),
            ):
                if not have:
                    continue
                for chain, hook in ((CHAIN_IN, "INPUT"), (CHAIN_OUT, "OUTPUT")):
                    # Remove every stacked copy of the hook.
                    for _ in range(20):
                        p = _run([ipt, "-D", hook, "-j", chain], check=False, quiet=True)
                        if p.returncode != 0:
                            break
                    _run([ipt, "-F", chain], check=False, quiet=True)
                    _run([ipt, "-X", chain], check=False, quiet=True)
                # ipsets are per-family; destroy the matching one now its rules are gone.
                _run(["ipset", "destroy", setname], check=False, quiet=True)
            self._installed = False

    # -- dynamic blocking ---------------------------------------------------
    def block_ip(self, ip: str, seconds: int = 0) -> bool:
        """
        Add an address to the in-kernel blocked set. `seconds=0` means until
        it is removed or the firewall stops. Returns True on success.
        """
        setname = SET_BLOCK6 if ":" in ip else SET_BLOCK4
        if ":" in ip and not self.enable_ipv6:
            return False
        timeout = ["timeout", str(seconds)] if seconds > 0 else ["timeout", "0"]
        proc = _run(["ipset", "add", setname, ip] + timeout + ["-exist"],
                    check=False, quiet=True)
        return proc.returncode == 0

    def unblock_ip(self, ip: str) -> bool:
        setname = SET_BLOCK6 if ":" in ip else SET_BLOCK4
        proc = _run(["ipset", "del", setname, ip], check=False, quiet=True)
        return proc.returncode == 0

    def list_blocked(self) -> list[str]:
        out = []
        for setname in (SET_BLOCK4, SET_BLOCK6):
            proc = _run(["ipset", "list", setname], check=False, quiet=True)
            if proc.returncode != 0:
                continue
            in_members = False
            for line in proc.stdout.splitlines():
                if line.startswith("Members:"):
                    in_members = True
                    continue
                if in_members and line.strip():
                    out.append(line.split()[0])
        return out

    def counters(self) -> dict:
        """Read packet/byte counters from our chains (handy for the dashboard)."""
        result = {}
        proc = _run(["iptables", "-L", CHAIN_IN, "-v", "-n", "-x"],
                    check=False, quiet=True)
        result["raw_in"] = proc.stdout
        return result

    @property
    def installed(self) -> bool:
        return self._installed
