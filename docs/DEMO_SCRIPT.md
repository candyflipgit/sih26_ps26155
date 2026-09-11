# Two-minute demo script

**Before recording:** run `python backend/scripts/reset_demo.py`, start both servers, open
http://localhost:5173 on the Analyse tab, and have an Explorer window open on
`backend/data/samples` so you can drag files in. Record at 1440×900 or wider.

The demo has one job: show that the platform handles a vendor it has never seen, *and* that the
security decision is never the model's to make. Everything else is supporting material.

---

### 0:00 – 0:10 · The gap

> "Security frameworks already define what a hardened device looks like. The problem is every vendor
> says it differently, and hard-coded parsers break the moment a new one arrives."

### 0:10 – 0:25 · A whole fleet at once

*Select all six files in `backend/data/samples` and drag them onto the drop zone.*

> "Six devices, one drop. Cisco, Juniper, Fortinet, Palo Alto — and an AWS security group, which isn't
> a CLI at all, it's JSON. Every one identified, every serial number extracted."

*Point at the MikroTik row showing **n/a**.*

> "One device we deliberately have no parser for. It shows n/a, not zero — and it's left out of the
> fleet average, because a device we couldn't judge isn't a failing device."

### 0:25 – 0:45 · Evidence and remediation

*Click the **CORE-SW-01** row → click the **Telnet** finding.*

> "Critical: Telnet is enabled. There are two evidence lines — one VTY range permits Telnet, the other
> doesn't. We resolve toward the risk, because missing a real exposure is worse than a false alarm."

*Scroll to the remediation.*

> "The fix is the real Cisco command sequence, from a curated library, never generated — and chosen
> for this device's exact OS release, because older releases reject the modern syntax."

### 0:45 – 1:00 · The vendor nobody wrote a parser for

*Analyse tab → click **MikroTik RB4011**.*

> "MikroTik RouterOS. No parser. Vendor unknown, every control undetermined. A hard-coded tool stops
> here. This is where ours starts working."

### 1:00 – 1:25 · Teach it once

*Click **Teach AI**. Select the telnet line.*

> "The model reads each command and proposes a mapping with its confidence — a proposal, not a
> decision. Nothing applies until an administrator approves it. And look at what gets learned: not the
> string, the command *shape*. Teach it once and every variant is recognised."

*Click **Save mapping**. Repeat for one or two more, quickly.*

### 1:25 – 1:40 · It learned

*Click **Re-scan with 3 new mappings**.*

> "Same file, no restart, no retraining. A critical Telnet exposure that was invisible a minute ago is
> now detected — deterministically, from the knowledge base. The model isn't in the loop any more."

### 1:40 – 1:50 · Not everything applies everywhere

*Analyse → **AWS Security Group** → **View findings**.*

> "The cloud firewall: Telnet reachable through a port *range*, twenty to twenty-three, which an
> exact-port check would miss. And twenty-one controls marked not applicable — a security group has no
> login banner, so we don't pretend it failed one."

### 1:50 – 2:00 · The point

*Back on the batch view, click **Download 6 PDF reports**.*

> "One report per device, credentials masked. The AI never decided any of this. It interpreted vendor
> syntax. Rules decided compliance. A human approved the new knowledge."

---

## If asked live

**"What if the model is wrong?"** — It marks the control UNKNOWN, not PASS or FAIL. An AI reading only
counts once a human approves it, and at that point it's a deterministic rule. Wrong AI lowers
coverage; it cannot corrupt a verdict.

**"What if the config contains a prompt injection?"** — The config is fenced with a per-request nonce
and every line is marked as data. We probed it with six hostile configs and none worked. But the
stronger answer is structural: the model has no field to put a verdict in.

**"Why not just embed everything and skip the LLM?"** — We measured it. Correct and incorrect
neighbours both scored 0.74–0.80, and retrieval alone got about half right. That measurement is why
the LLM is load-bearing rather than decorative.

**"Does it need internet?"** — No. Point it at a local Ollama and the same pipeline runs on open
weights on your own hardware. With no model at all, everything except the suggestions still works.

**"Can it pull configs from live devices?"** — Yes, over SSH with Netmiko, read-only commands only.
Credentials are used for one session and never stored or logged. It's optional on purpose: an auditor
holding standing credentials to every device would itself be a prime target.

**"How many vendors?"** — Five packs ship, including a cloud firewall that's JSON rather than CLI, and
MikroTik is in the demo to show the path to vendor number fifty. Adding one is a JSON file, not a
release.

**"What about different OS versions?"** — Remediation is chosen for the detected release. A Cisco
device on 15.2 gets `enable secret`; on 17.9 it gets scrypt, because 15.2 rejects the scrypt syntax.
