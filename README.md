# NetBaseline AI

**AI-augmented, vendor-agnostic network security compliance auditor.**
Smart India Hackathon 2026 · Problem Statement **26155** · National Technical Research Organisation (NTRO)

Ingests network device configurations from any vendor — CLI text or structured JSON, one file or a
whole fleet — normalises them into a vendor-neutral security model, evaluates that model against
CIS / NIST SP 800-53 / DISA STIG / ISO 27001, and produces a per-device PDF report with evidence and
remediation chosen for the device's vendor *and* OS release.

**Deliverables:** [Architecture (2 pages)](docs/Architecture.pdf) ·
[Technical presentation (5 slides)](docs/NetBaseline_AI_Technical_Presentation.pptx) ·
[Demo script](docs/DEMO_SCRIPT.md) · [Full design notes](docs/DESIGN_NOTES.md)

---

## The governing principle

> **AI interprets syntax. Rules decide compliance. Humans approve new knowledge.**

The language model never emits a verdict. It proposes `{parameter, value, confidence, evidence}`,
that proposal is schema-validated against a closed vocabulary, and a deterministic engine renders
the result by comparison alone. Every finding traces back to the literal configuration lines that
produced it.

| Concern a security auditor will raise | How the design answers it |
|---|---|
| "What if the model hallucinates?" | It cannot reach a verdict. An unreviewed AI reading marks a control **UNKNOWN**, never PASS or FAIL. |
| "Why did this device pass?" | Every finding cites the config lines, the rule id, and the rule version. The same input always gives the same answer. |
| "What about a vendor you've never seen?" | Nothing breaks. Its commands queue for classification, and one approval teaches the platform permanently. |
| "Does a cloud firewall even have an NTP setting?" | No — so that control reports **NOT APPLICABLE**, not UNKNOWN and not FAIL. |

---

## What it does

- **Ingests** any configuration — `.cfg`, `.conf`, `.txt`, `.rsc`, `.json` — by upload, drag-drop,
  paste, **bulk upload of up to 50 files**, or optional **live SSH collection** via Netmiko.
- **Identifies** the vendor deterministically from weighted signature tokens.
- **Normalises** proprietary syntax into 24 canonical security parameters, each carrying its evidence
  and provenance. Structured input such as a cloud security group is flattened first, then parsed
  exactly like CLI text.
- **Evaluates** 23 controls, each mapped to all four frameworks from a single catalogue entry, with
  four honest outcomes: PASS, FAIL, UNKNOWN, NOT APPLICABLE.
- **Learns** unrecognised commands through a review interface — and learns the command *shape*, so
  teaching `ip ssh version 2` also teaches `ip ssh version 1`.
- **Reports** one PDF per device — identity including serial number, evidence, framework references,
  and curated remediation CLI **selected for the detected OS release** — or a zip of them for a fleet.

### Vendor packs

| Pack | Input | Notes |
|---|---|---|
| Cisco IOS / IOS-XE | CLI | Release-aware remediation (e.g. scrypt secrets need IOS 15.3(3)M+) |
| Juniper Junos | CLI, set format | |
| Fortinet FortiOS | CLI, config/edit blocks | |
| Palo Alto PAN-OS | CLI, set format | |
| AWS VPC Security Group | **JSON** | Judges port *ranges*, so `0-65535` exposes SSH; 21 controls correctly N/A |
| MikroTik RouterOS | CLI | **Deliberately unsupported** — the sample exists to demonstrate teaching a new vendor |

---

## Setup

**Requirements:** Python 3.11–3.13 and Node 18+. No database server, no GPU, no Docker.
You will need **two terminals** — one for the API, one for the UI — and they stay running.

### 1. Clone

```bash
git clone https://github.com/candyflipgit/sih26_ps26155.git netbaseline
```

```bash
cd netbaseline
```

### 2. Backend — terminal one

Create the virtual environment:

```bash
python -m venv .venv
```

Activate it. **Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
source .venv/bin/activate
```

Install dependencies and create your local config:

```bash
pip install -r backend/requirements.txt
```

```bash
cd backend
```

```bash
cp .env.example .env
```

On Windows `cmd.exe` use `copy .env.example .env` instead. PowerShell and Git Bash both accept `cp`.

Now start the API — **you are already inside `backend/`, do not `cd` again**:

```bash
python -m uvicorn app.main:app --reload --port 8077
```

Leave it running. First start takes ~20 seconds: it downloads a ~130 MB embedding model
(`bge-small`, ONNX) into a local cache. Later starts are instant. On Windows you will see a
`huggingface_hub` warning about symlinks — that is expected and harmless.

Wait for `Application startup complete.` before moving on.

### 3. Frontend — terminal two

Open a **new** terminal in the same project folder. The frontend needs no Python environment:

```bash
cd frontend
```

```bash
npm install
```

```bash
npm run dev
```

Open **http://localhost:5173**. Interactive API docs are at **http://localhost:8077/docs**.

### 4. Check it works

Click **Cisco Catalyst 9300** on the Analyse screen. You should get a 41% score, 13 findings, and
serial `FCW2447L0GH`. Then click **AWS Security Group**: 2 failures, 21 controls not applicable.
If both look right, the whole pipeline is working.

To verify from the command line, in a third terminal with the venv activated:

```bash
cd backend && python -m pytest tests/ -q
```

164 tests should pass in well under a minute.

### 5. Inference endpoint (optional)

**The platform runs fully without this.** With no endpoint configured, parsing, compliance
evaluation, reporting and manual classification all work — only the model's *suggestions* are
absent, and unrecognised commands queue for a human instead.

To enable suggestions, put any OpenAI-compatible endpoint in `backend/.env`:

| Host | `LLM_BASE_URL` | Notes |
|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | Free tier, open-weight models, no card |
| OpenRouter | `https://openrouter.ai/api/v1` | Append `:free` to a model id |
| Hugging Face | `https://router.huggingface.co/v1` | Routes to open-weight providers |
| **Ollama (offline)** | `http://localhost:11434/v1` | **No key, nothing leaves your network** |

```bash
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=your-key-here
LLM_MODEL=qwen/qwen3.8-27b
```

The offline row is the deployment story for a national-security operator: the same pipeline runs on
open weights on the operator's own hardware, and no configuration data ever leaves the premises.

**Choosing a model.** Providers retire model ids. If suggestions never appear but the key is valid, a
dead model id is the likely cause — the API falls back to queueing commands for review rather than
erroring. To see what your account can call and benchmark each against a known answer key:

```bash
cd backend && python scripts/bench_models.py
```

### 6. Live SSH collection (optional)

Pull a configuration straight from a device instead of uploading a file:

```bash
pip install -r backend/requirements-collect.txt
```

Then `POST /api/v1/collect` with `host`, `platform` (`cisco_ios`, `juniper_junos`, `fortinet_fortios`,
`paloalto_panos`), `username` and `password`. Only read-only show commands are run. Credentials are
used for that one session and are **never stored, logged, or echoed** — not even in driver error
messages. Uploads remain the primary path on purpose: an auditor holding standing credentials to every
device would itself be a prime target.

### 7. Reset between demos

```bash
cd backend && python scripts/reset_demo.py
```

Removes learned mappings and scan history; leaves the shipped rule packs untouched. Safe to run while
the server is up.

---

## Troubleshooting

Verified against a fresh clone on a clean machine. These are the things that actually go wrong.

**`ModuleNotFoundError: No module named 'fastapi'`** — the virtual environment is not active in that
terminal. Every new terminal needs it activated again; your prompt should show `(.venv)`.

**`can't open file` or `no such file or directory`** — wrong folder. The API runs from `backend/`, the
UI from `frontend/`. After `cd backend` you do **not** `cd backend` again.

**`address already in use`** — an earlier run still holds the port. Stop it, or use `--port 8078` and
update the `proxy` target in `frontend/vite.config.js` to match.

**The UI loads but everything is empty** — the API is not running or is on another port. Check that
http://localhost:8077/api/v1/health returns `{"status":"ok"}`.

**First startup hangs for ~20 seconds** — expected; it is downloading the embedding model once.

**No internet on the machine** — it still runs. Embeddings fall back to offline character n-gram
TF-IDF; parsing, compliance and reporting are unaffected.

**`pip install` fails resolving a version** — the pins were built on Python 3.13 and verified on 3.11+.
Python 3.14 and 3.10 are untested.

**Rate limited on a free inference tier** — expected when scanning several devices quickly. The client
honours `Retry-After` and backs off; if it still cannot get through, those commands queue for review.

---

## Measured, not assumed

Design choices were benchmarked. Each script is reproducible:

```bash
cd backend && python scripts/bench_models.py
```

Scores every available model against an answer key. The 120B model scored *worse* than the 27B ones —
it invented a mapping for a command no parameter covers.

```bash
cd backend && python scripts/bench_context.py
```

Supplying the enclosing configuration block moved accuracy on context-dependent FortiOS lines from
6/10 to 9/10.

```bash
cd backend && python scripts/probe_injection.py
```

Six hostile configurations try to hijack the model. 0 of 6 succeeded — and a verdict has no
representable form in the response schema, so even a successful hijack could not become one.

```bash
cd backend && python scripts/build_architecture_pdf.py
```

Rebuilds the architecture document from live measurements, and fails if it exceeds two pages.

---

## How it works

```
file · bulk upload · paste · SSH · JSON
      │
      ▼
vendor detection ──────────────► weighted signature tokens, deterministic
      │
      ▼
parsing engine  ───────────────► one engine, per-vendor JSON rule packs
      │                          JSON input flattened to lines first
      │                          `ntp server 10.0.0.1` → `ntp server <IP>` + slot
      ├── recognised ──────────► normalised fact + evidence
      ▼
  unrecognised ─► retrieval (precedent only) ─► LLM (closed vocabulary, config
      │           fenced as untrusted data, secrets redacted) ─► validation
      ▼
  administrator review ────────► approve → written to the rule pack
      │                          → recognised deterministically from then on
      ▼
NORMALISED SECURITY MODEL (24 canonical parameters, each with provenance)
      │
      ▼
compliance engine ─────────────► pure comparison, no AI
      │                          PASS / FAIL / UNKNOWN / NOT APPLICABLE
      ├──► findings + evidence
      ├──► remediation (curated, chosen per vendor and OS release)
      └──► per-device PDF, or a zip for a fleet
```

**Adding a vendor** means dropping a JSON rule pack into `backend/data/knowledge/` — no Python, no
redeployment. A mapping taught through the GUI is written into that same file in the same shape, so
learned and shipped knowledge are indistinguishable to the engine.

---

## Project layout

```
backend/
  app/
    schema/        canonical parameter registry + normalised security model
    parsers/       one generic engine, JSON flattening, rule packs as data, detector
    compliance/    deterministic rule engine, catalogue, release-aware remediation
    ai/            canonicalisation, retrieval index, LLM provider, prompts
    core/          settings, secret redaction
    reports/       ReportLab PDF generator
    services/      pipeline orchestration, optional SSH collector
    models/        SQLite persistence, training audit trail
  data/
    knowledge/     vendor rule packs (JSON)  ← add a vendor here
    rules/         control catalogue + remediation templates
    samples/       six device configurations
  scripts/         benchmarks, injection probe, architecture PDF builder, demo reset
  tests/           164 tests
frontend/
  src/components/  Dashboard, Analyse (incl. bulk), Findings, Teach AI, Knowledge
docs/              Architecture.pdf, presentation, demo script, design notes
```

---

## Security notes

- **Configurations are untrusted input.** Each prompt fences the configuration with a per-request
  nonce and marks every line as data; an instruction hidden in a config comment has no effect, and
  could not produce a verdict even if the model obeyed it.
- **Secrets never leave the process.** Hashes, SNMP communities, pre-shared keys and private keys are
  redacted before any prompt is built and before any evidence reaches a report.
- **Conflicts resolve toward risk.** When readings disagree — two VTY ranges, one permitting Telnet —
  the riskier one wins and both lines are cited.
- **Undecidable is not failing.** A device with no judgeable controls shows n/a and is left out of the
  fleet average rather than dragging it down as a false 0%.
- **Remediation is curated, never generated**, and chosen for the device's OS release. Where no
  verified template exists, the report says so instead of inventing a command.

---

## Scope and honesty

Deliberate limits, not oversights:

- The control catalogue is **a curated set of network-hardening controls mapped to CIS / NIST / STIG /
  ISO control families**, not a certified crosswalk, and does not reproduce any benchmark's text.
- STIG references name the requirement family rather than a version-specific V-ID, because those
  identifiers change with every benchmark release.
- Five vendor packs ship; the architecture accepts any vendor, and the MikroTik sample shows the path.
- The AWS pack judges exposure of the management ports SSH, Telnet and RDP; it does not attempt a
  full cloud security posture review.
- Release-aware remediation covers the templates where syntax is known to differ across releases;
  elsewhere, commands are for current releases and the report says so.
- Automatic remediation and model fine-tuning are out of scope by design.
