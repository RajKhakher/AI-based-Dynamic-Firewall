# How it works — every part, in plain language

This document explains the whole firewall from the ground up, in plain terms,
with no assumed background. It's written so you can read it start to finish and
understand *why* each piece exists and *how* it does its job. It's also meant to
be enough to explain and defend the project in a report or viva.

---

## 1. What a firewall actually is

Your computer is constantly sending and receiving small chunks of data called
**packets**. Every time you load a web page, send a message, or a device on the
network tries to reach you, that's packets moving in and out.

A **firewall** is a guard that sits on the path those packets travel. For each
packet it asks a simple question — *"should this be allowed through, or stopped?"*
— and then does one of two things:

- **allow** the packet (let it continue), or
- **block** the packet (throw it away so it never arrives).

That's the whole idea. Everything else — rules, detection, AI — is just
different ways of deciding *which* packets to allow and which to block.

---

## 2. Why the earlier version wasn't a real firewall

The earlier version of this project didn't actually guard the packet path. It
had a function that **made up** fake attacks using a random-number generator:

```python
fake_ip = f"192.168.1.{random.randint(1,255)}"   # a made-up address
threat_score = random.randint(50, 100)            # a made-up score
```

The dashboard then displayed those made-up entries. No real packet was ever
inspected or blocked. It also had a machine-learning model that was "trained" on
eight rows of numbers typed into the code by hand, so it had never seen real
traffic and couldn't meaningfully classify anything.

This version throws all of that away. Here, **real packets from the real network
are inspected and really blocked.** Nothing is invented inside the program.

---

## 3. How our program gets to see real packets

Here's the key question: how can an ordinary Python program get in the way of
packets and decide their fate? The answer is a feature built into the Linux
kernel called **NFQUEUE** ("netfilter queue").

Think of the Linux kernel as the post office that handles all your packets. Linux
has a built-in system for making rules about packets, called **netfilter**; the
command-line tool you use to set those rules is **iptables**. One special rule
you can add says:

> "Instead of deciding this packet yourself, hand it up to a program that's
> waiting, and do whatever that program says."

That "hand it up to a waiting program" instruction is NFQUEUE. Our program is the
waiting program. So the flow is:

1. A packet arrives at the kernel.
2. Our iptables rule tells the kernel: send this packet to queue number 0 (for
   incoming) or 1 (for outgoing).
3. Our Python program is subscribed to those queues. It receives the packet's
   raw bytes.
4. It makes a decision and tells the kernel **accept** or **drop**.
5. The kernel carries out that decision.

Because the kernel genuinely waits for our verdict, this is a true **inline**
firewall — the packet does not proceed until we say so. (This is the same
technique real intrusion-prevention systems use.)

The file that sets up these kernel rules is [`fwcore/netfilter.py`](fwcore/netfilter.py).
The file that receives packets and runs the decision is
[`fwcore/engine.py`](fwcore/engine.py).

### A safety detail: "fail-open"

If our program crashed while it was the gatekeeper, packets could get stuck. To
avoid that, the kernel rule is added with a "bypass" option: if no program is
listening on the queue, the kernel just lets packets through instead of freezing
the network. This means a bug in our code can't lock you out of your own machine.
This is called **failing open**, and it's the safe default here.

---

## 4. Reading a packet: `packet.py`

When we receive a packet, it's just a block of raw bytes. The first job is to
make sense of it. A packet is laid out in a fixed order, like a labelled form:

- The **IP header** comes first. It contains the source address (who sent it),
  the destination address (who it's for), which protocol is inside, and the
  total length.
- After that comes the **transport header**, which depends on the protocol:
  - **TCP** (used by web, SSH, most things) has a source port, a destination
    port, and *flags* — little on/off switches like SYN (start a connection),
    ACK (acknowledge), FIN (finish), RST (reset).
  - **UDP** (used by DNS, video, games) has just source and destination ports.
  - **ICMP** (used by `ping`) has a type and a code.

`packet.py` reads these bytes at their known positions and fills in a small
object with named fields (source, destination, protocol, ports, flags, length).
The rest of the program works with those clean fields instead of raw bytes. It's
written to never crash on a malformed packet — it just marks it as malformed and
moves on.

One field worth knowing: a **"bare SYN"** is a TCP packet with the SYN flag on
and ACK off. That's the very first packet of a new connection — someone knocking
on a door. Counting bare SYNs is how we spot scans and floods later.

---

## 5. The rule list: `rules.py`

This is the classic part of a firewall. You have an **ordered list of rules**,
and each packet is checked against them from the top down. **The first rule that
matches wins**, and its action is applied. If no rule matches, a **default
policy** is used.

Each rule can match on:

- **direction** — is the packet coming in, or going out?
- **protocol** — tcp, udp, icmp, or any
- **source / destination** — a single address or a whole range written as CIDR
  (for example `203.0.113.0/24` means "any address starting with 203.0.113")
- **ports** — a single port like `22`, a list, or a range like `1000-2000`

And each rule has an **action**:

- **allow** — let it through
- **deny** — drop it silently (the sender gets no reply and learns nothing)
- **reject** — drop it but send back a "no entry" message (the sender knows
  immediately instead of waiting)

Example: *"deny any inbound TCP packet to port 23"* blocks people from reaching
the (insecure) Telnet service on your machine.

"First match wins" is important: it lets you put a specific **allow** above a
broad **deny**. For instance, *allow SSH from your own admin network*, then *deny
SSH from everywhere else*.

Rules are saved to `data/rules.json` so they survive restarts, and you can edit
them live from the dashboard.

---

## 6. Being "stateful": `conntrack.py`

Imagine your firewall has a rule: *"deny all inbound traffic."* You then open a
website. Your request goes out fine, but the website's reply is *inbound* — so a
naive firewall would block the reply, and the page would never load. That's
useless.

A **stateful** firewall fixes this by *remembering conversations*. When your
machine starts a connection to a website, the firewall notes it down. When the
reply comes back, it recognises it as part of a conversation you started and
lets it in automatically — even though there's a "deny inbound" rule.

`conntrack.py` (short for "connection tracking") keeps a small table of active
conversations. For each one it remembers who started it and when it was last
active (old entries are forgotten after a timeout). This is what makes the
firewall practical to actually use, rather than just a packet-by-packet filter.

---

## 7. Spotting bad behaviour: `detectors.py`

Rules are good for fixed decisions ("never allow Telnet"). But some threats are
about *behaviour over time*, not a single packet. That's what the detectors
watch for. Each one keeps a short rolling memory of recent packets from each
source and raises an **alert** when a source crosses a threshold.

- **Port scan** — A normal client talks to one or two ports on your machine (say,
  the web port). An attacker mapping your machine touches *many* different ports
  quickly to see what's open. So: if one source hits more than N different ports
  within a few seconds, that's a scan.

- **SYN flood** — Remember the "bare SYN" (a connection attempt)? In a SYN flood,
  an attacker sends a huge number of connection attempts without ever completing
  them, trying to exhaust your machine. So: too many bare SYNs from one source in
  a short window = flood.

- **UDP flood / ICMP flood** — Same idea, but counting UDP packets or pings. A
  sudden burst from one source far above normal = flood.

- **Brute force** — Many *new* connections to a login service (SSH on port 22,
  RDP on 3389, databases, etc.) from one source in a short time looks like
  someone trying password after password. So: too many new connections to a
  login port = brute-force attempt.

Every alert is **explainable** — it records exactly which number crossed which
limit, e.g. *"15 different ports in 10s (limit 15)."* Nothing is a mysterious
black box. The thresholds are all configurable.

When the firewall is *enforcing*, a detector firing also **blocks** the offending
source (see next section). When it's only *monitoring*, it just logs the alert.

### How the memory stays small

Each detector uses a "sliding window": it stores only the timestamps of recent
events and throws away anything older than the window. So even during a massive
flood, memory use stays tiny — old entries are constantly dropped.

---

## 8. Blocking, safely: `blocklist.py` + `ipset`

When something needs to be blocked, we don't want to keep asking Python about
every future packet from that address — that would be slow during a flood.
Instead we push the block *into the kernel* using a feature called **ipset**, which
is a high-speed list of addresses the kernel can check instantly. Our very first
kernel rule says: *"if the source is in the blocked set, drop it immediately."*
So once an address is blocked, its packets are discarded by the kernel at full
speed and never even reach Python.

Blocks can be **temporary**: you can block an address for, say, 300 seconds, and
it lifts itself automatically afterwards. `blocklist.py` tracks each block, why
it happened, and when it expires.

### The safety net: the safelist

The single most important safety feature is the **safelist** — a set of addresses
that can *never* be blocked, no matter what:

- **loopback** (`127.0.0.1`) — your machine talking to itself
- your **default gateway** — the router you reach the network through
- your **DNS servers** — what you use to look up names

If any of these got blocked, you'd cut yourself off from your own network. The
safelist guarantees that can't happen, even if a detector or the AI wanted to
block them, and even if you type one into the manual-block box by mistake.

---

## 9. The AI part, done honestly: `ai.py`

This deserves care, because "AI firewall" is easy to fake (as the old version
did). Here's the honest version and why it's the right design.

### The problem with a normal classifier

The obvious idea is: train a model to tell "attack" from "normal". But to do
that you need lots of **labelled examples of real attacks**, and we don't have
those. Inventing fake attacks (what the old code did) just teaches the model your
fakes — it learns nothing about reality.

### The solution: learn "normal", flag the unusual

So we flip the problem around. We don't try to recognise attacks. Instead we
learn what **your** normal traffic looks like, and then flag anything that
doesn't fit. This is called **unsupervised anomaly detection**, and its big
advantage is that it needs **no attack data at all** — only the ordinary traffic
your machine already produces.

### How the model works (Isolation Forest, in plain terms)

The model we use is an **Isolation Forest**. Here's the intuition without the
maths:

Imagine all your normal traffic plotted as a big cloud of points. To "isolate"
one point, you make random straight cuts through the cloud until that point is
alone in its own little box. A point in the **middle of the crowd** needs *many*
cuts to isolate — it's surrounded. A point **far outside the crowd** (unusual)
gets cut off from everyone after just a **few** cuts, because there's nothing
near it.

So the model measures: *how few cuts does it take to isolate this point?* Few
cuts → it's an outlier → **anomaly**. Many cuts → it's normal. We build lots of
these random-cutting trees (a "forest") and average them, which makes the answer
stable.

### What the model actually looks at (the features)

For each packet we compute a short list of numbers describing it and the recent
behaviour of its source:

1. packet length
2. protocol (tcp/udp/icmp)
3. destination port
4. is it a new-connection attempt (bare SYN)?
5. how many packets this source sent in the last 5 seconds
6. how many *different* ports this source touched in the last 10 seconds
7. how many *different* destinations this source touched in the last 10 seconds
8. is it inbound?

Features 5–7 are what let it notice *behaviour* (bursts and fan-out), not just
single packets.

### The three steps you run

1. **Learn** — turn on learning and use the machine normally. The model collects
   feature rows from real traffic.
2. **Train** — it fits the Isolation Forest on what it collected.
3. **Protect** — every new packet gets an "anomaly score". If it's below the
   threshold, it's flagged (and optionally blocked).

### It explains itself

When the AI flags a packet, it also reports **which feature was most unusual**
compared to what it learned — for example *"distinct_dports=100 (normal ~2)"*.
So even the AI's decisions are readable, not a black box.

### An honest limitation

Anomaly detection flags things that are *unusual*, which is not always the same
as *malicious* — a rare but legitimate burst can be flagged (a "false positive").
That's why auto-blocking from the AI is **off by default**: by default the AI
raises alerts for you to review, and the rule-based detectors (which are precise)
are what block automatically. This is a deliberate, honest design choice.

---

## 10. Putting it together: `engine.py`

For every packet, the engine runs one clear pipeline and then tells the kernel
what to do:

1. **Loopback?** If the machine is talking to itself, allow it (trusted) and stop.
2. **Established?** If it's a reply to a connection we started, allow it (that's
   the stateful check).
3. **Already blocked?** If the source is on the blocklist, drop it.
4. **Rules.** Run the rule list; first match wins. No match → default policy.
5. **Detectors.** Update the behaviour detectors; if one fires, alert and (in
   enforce mode) block the source.
6. **AI.** Score the packet; if it's anomalous, alert and (if auto-block is on)
   block.
7. **Verdict.** Accept or drop, and record it for the dashboard.

Two modes control how far it goes:

- **Monitor** — everything runs and is logged, but **nothing is ever dropped**.
  Perfect for watching a live machine safely.
- **Enforce** — deny/reject rules and blocks actually take effect.

If anything ever goes wrong while handling a packet, the engine's rule is: accept
the packet and move on. It will never let a bug in analysis break your network.

---

## 11. The dashboard: `web/`

The dashboard is how you watch and control the firewall in a browser. It talks to
the running engine and refreshes a few times a second, showing live counts, a
traffic chart, the busiest sources and ports, a live feed of decisions, alerts,
the block list, the rules, and the AI controls.

Security basics the old version lacked are included here:

- **Login required** for every page and API call.
- **Passwords are hashed**, never stored as plain text.
- A **fresh secret key** each run, so old session cookies can't be reused.
- A **CSRF token** on every action that changes something, so another website
  can't trick your browser into changing your firewall.
- The server listens on **127.0.0.1** (your machine only) by default.

The charting library (Chart.js) is bundled locally, so the dashboard works even
on a machine with no internet — useful for an isolated lab VM.

---

## 12. Why this is safe to run on your own machine

- It starts in **monitor mode** (watches only).
- It **fails open** (a crash lets traffic through, doesn't freeze it).
- It **can't block loopback, your gateway, or DNS** (the safelist).
- It **removes every kernel rule** it added when you stop it (and there's a
  `tools/cleanup.py` for the rare case it was killed hard).

---

## 13. How to prove it's real

- Run `sudo python3 tools/lab.py`. It creates two isolated virtual computers,
  runs the real engine on one, and fires a **real `nmap` scan** from the other.
  You'll see the scan detected and the scanner blocked, and traffic from it
  stopped afterwards — all with real packets.
- Or use two real devices (see the README's Demo section) and watch it on the
  dashboard.

That's the whole system. Every layer is doing real work on real packets, and
every decision it makes can be explained.
