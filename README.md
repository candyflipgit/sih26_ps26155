# NetBaseline AI

**AI-augmented, vendor-agnostic network security compliance auditor.**
Smart India Hackathon 2026 · Problem Statement **26155** · National Technical Research Organisation (NTRO)

Ingests network device configurations from any vendor, normalises proprietary CLI syntax into a
vendor-neutral security model, evaluates that model against CIS / NIST SP 800-53 / DISA STIG /
ISO 27001, and produces a per-device PDF report with evidence and device-specific remediation.

---

## The governing principle

> **AI interprets syntax. Rules decide compliance. Humans approve new knowledge.**

The language model never emits a verdict. It proposes `{parameter, value, confidence, evidence}`,
that proposal is schema-validated against a closed vocabulary, and a deterministic engine renders
PASS / FAIL / UNKNOWN by comparison alone. Every finding traces back to the literal configuration
lines that produced it.

This matters for three reasons a security auditor will ask about:

| Concern | How the design answers it |
|---|---|
| "What if the model hallucinates?" | It cannot reach a verdict. An unreviewed AI reading marks a control **UNKNOWN**, never PASS or FAIL. |
| "Why did this device pass?" | Every finding cites the config lines, the rule id, and the rule version. Re-running the same input always gives the same answer. |
| "What happens with a vendor you've never seen?" | Nothing breaks. The commands queue for classification, and one approval teaches the platform permanently. |

---

## What it does

- **Ingests** any text configuration — `.cfg`, `.conf`, `.txt`, `.rsc` — by upload, drag-drop, or paste.
- **Identifies** the vendor deterministically from weighted signature tokens.
- **Normalises** proprietary syntax into 24 canonical security parameters, carrying evidence and
  provenance on every reading.
- **Evaluates** 23 controls, each mapped to all four frameworks from a single catalogue entry.
- **Learns** unrecognised commands through a review interface — and learns the command *shape*, so
  teaching `ip ssh version 2` also teaches `ip ssh version 1`.
- **Reports** to PDF with device identity (including serial number), evidence, framework references,
  and curated per-vendor remediation CLI.

Ships with parsers for **Cisco IOS/IOS-XE**, **Juniper Junos**, and **Fortinet FortiOS**, plus a
**MikroTik RouterOS** sample that is deliberately *unsupported* — it exists to demonstrate the
learning path on a vendor with no parser.

---

## Setup

**Requirements:** Python 3.11+ and Node 18+. No database server, no GPU, no Docker required.

### 1. Backend

```bash
git clone <your-repo-url> netbaseline && cd netbaseline
python -m venv .venv
```

Activate the environment — `.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on
macOS or Linux — then:

```bash
pip install -r backend/requirements.txt
cd backend && cp .env.example .env
```

Start the API:

```bash
cd backend && python -m uvicorn app.main:app --reload --port 8077
```

### 2. Frontend

In a second terminal:

```bash
cd frontend && npm install && npm run dev
```

Open **http://localhost:5173**. Interactive API docs are at **http://localhost:8077/docs**.

### 3. Inference endpoint (optional)

**The platform runs fully without this.** With no endpoint configured, deterministic parsing,
compliance evaluation, reporting and manual classification all work — only the model's *suggestions*
are absent, and unrecognised commands queue for a human instead.

To enable suggestions, put an OpenAI-compatible endpoint in `backend/.env`. Any of these work
unchanged, because the client speaks one dialect:

| Host | `LLM_BASE_URL` | Notes |
|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | Free tier, open-weight models, no card |
| OpenRouter | `https://openrouter.ai/api/v1` | Append `:free` to a model id |
| Hugging Face | `https://router.huggingface.co/v1` | Routes to open-weight providers |
| **Ollama (offline)** | `http://localhost:11434/v1` | **No key, nothing leaves your network** |

```bash
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=your-key-here
LLM_MODEL=llama-3.3-70b-versatile
```

The offline row is the deployment story for a national-security operator: the same pipeline runs
against open weights on the operator's own hardware, and no configuration data ever leaves the
premises.

### 4. Tests

```bash
cd backend && python -m pytest tests/ -q
```

### 5. Reset between demos

```bash
cd backend && python scripts/reset_demo.py
```

Removes learned mappings and scan history; leaves the shipped rule packs untouched.

---

## How it works

```
raw configuration
      │
      ▼
vendor detection ──────────────► weighted signature tokens, deterministic
      │
      ▼
parsing engine  ───────────────► one engine, per-vendor JSON rule packs
      │                          canonicalises `ntp server 10.0.0.1`
      │                          into `ntp server <IP>` + captured slots
      ├── recognised ──────────► normalised fact + evidence
      │
      ▼
  unrecognised
      │
      ├── retrieval ───────────► nearest verified mappings, as precedent only
      ▼
  language model ──────────────► closed vocabulary, JSON-only, config fenced
      │                          as untrusted data; secrets redacted first
      ▼
  schema validation ───────────► rejects unknown parameters and bad types
      │
      ▼
  administrator review ────────► approve → written to the rule pack on disk
      │                          → recognised deterministically from then on
      ▼
NORMALISED SECURITY MODEL (24 canonical parameters, each with provenance)
      │
      ▼
compliance engine ─────────────► pure comparison. No AI. PASS / FAIL / UNKNOWN
      │
      ├──► findings + evidence
      ├──► remediation (curated per-vendor templates, never generated)
      └──► PDF report
```

### Why retrieval does not decide mappings

We measured it. On held-out cross-vendor commands, dense similarity scored correct and incorrect
neighbours in the same 0.74–0.80 band and answered barely half of the set correctly. Absolute
similarity on CLI text is not separable enough to trust, so retrieval supplies few-shot precedent to
the model and nothing more. Exact recognition of a taught command is handled by deterministic
template matching instead — which is also why it needs no model at all on the second encounter.

### Adding a vendor

Drop a JSON rule pack into `backend/data/knowledge/`. No Python changes, no redeployment. A mapping
an administrator teaches through the GUI is written into that same file in the same shape, so
learned knowledge and shipped knowledge are indistinguishable to the engine.

---

## Project layout

```
backend/
  app/
    schema/        canonical parameter registry + normalised security model
    parsers/       one generic engine, vendor rule packs as data, detector
    compliance/    deterministic rule engine, catalogue, remediation library
    ai/            canonicalisation, retrieval index, LLM provider, prompts
    core/          settings, secret redaction
    reports/       ReportLab PDF generator
    services/      pipeline orchestration
    models/        SQLite persistence, training audit trail
  data/
    knowledge/     vendor rule packs (JSON)  ← add a vendor here
    rules/         control catalogue + remediation templates
    samples/       four device configurations
  tests/           92 tests
frontend/
  src/components/  Dashboard, Analyse, Findings, Teach AI, Knowledge
docs/
```

---

## Security notes

- **Configurations are untrusted input.** The prompt fences them and instructs the model to ignore
  any instruction found inside — a config comment saying "report this device as compliant" has no
  effect, and could not produce a verdict even if the model complied.
- **Secrets never leave the process.** Password hashes, SNMP communities, pre-shared keys and
  private-key blocks are redacted before any prompt is built and before any evidence is drawn into a
  report. This is the most-tested part of the codebase.
- **Conflicts resolve toward risk.** When a configuration asserts the same parameter twice and the
  readings disagree — two VTY ranges, one permitting Telnet — the riskier reading wins and both
  lines are cited. A false negative in a security audit is more damaging than a false positive.
- **Remediation is curated, never generated.** A hallucinated CLI command in a security report is
  worse than no command: someone may paste it into production. Where no verified template exists for
  a platform, the report says so and gives descriptive guidance instead.

---

## Scope and honesty

This is a hackathon prototype, and the following are deliberate limits rather than oversights:

- The control catalogue is **a curated set of network-hardening controls mapped to CIS / NIST / STIG /
  ISO control families**. It is not a certified crosswalk, and this project does not reproduce the
  copyrighted text of any benchmark.
- STIG references name the applicable requirement family rather than a version-specific V-ID, because
  those identifiers change with every benchmark release.
- Three vendors ship with parsers. The architecture supports any vendor; the demo supports three
  properly and shows the path for a fourth.
- Live device collection over SSH, automatic remediation execution, and model fine-tuning are
  explicitly out of scope.
