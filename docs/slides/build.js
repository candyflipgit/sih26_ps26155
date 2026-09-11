const pptxgen = require('pptxgenjs')

// Palette lifted from the running product, so the deck reads as the same system.
const BG = '0E1520'
const PANEL = '18222E'
const RAISED = '212D3B'
const LINE = '2B3A4C'
const TEXT = 'E9EFF6'
const MUTED = '93A4B8'
const FAINT = '64768C'
const ACCENT = '4C9AFF'
const CRIT = 'FF5A5F'
const WARN = 'FFA23C'
const PASS = '35D0A5'

const HEAD = 'Cambria'
const BODY = 'Calibri'
const MONO = 'Consolas'

const pres = new pptxgen()
pres.layout = 'LAYOUT_WIDE' // 13.33 x 7.5
pres.author = 'Team NetBaseline'
pres.title = 'NetBaseline AI — SIH 2026 PS 26155'

const W = 13.33
const M = 0.62 // page margin

function slide() {
  const s = pres.addSlide()
  s.background = { color: BG }
  return s
}

function title(s, text, sub) {
  s.addText(text, {
    x: M, y: 0.42, w: W - 2 * M, h: 0.68,
    fontFace: HEAD, fontSize: 34, bold: true, color: TEXT,
    isTextBox: true, margin: 0,
  })
  if (sub) {
    s.addText(sub, {
      x: M, y: 1.12, w: W - 2 * M, h: 0.36,
      fontFace: BODY, fontSize: 14, color: MUTED,
      isTextBox: true, margin: 0,
    })
  }
}

function card(s, o) {
  s.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h,
    rectRadius: 0.06,
    fill: { color: o.fill || PANEL },
    line: { color: o.line || LINE, width: 1 },
  })
}

function chip(s, o) {
  s.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h, rectRadius: 0.05,
    fill: { color: o.fill }, line: { type: 'none' },
  })
  s.addText(o.text, {
    x: o.x, y: o.y, w: o.w, h: o.h,
    fontFace: BODY, fontSize: o.size || 10, bold: true, color: o.color,
    align: 'center', valign: 'middle', isTextBox: true, margin: 0,
  })
}

function footer(s, n) {
  s.addText('NetBaseline AI  ·  SIH 2026  ·  PS 26155  ·  NTRO', {
    x: M, y: 6.92, w: 7, h: 0.28,
    fontFace: BODY, fontSize: 9, color: FAINT, isTextBox: true, margin: 0,
  })
  s.addText(String(n), {
    x: W - M - 0.6, y: 6.92, w: 0.6, h: 0.28,
    fontFace: BODY, fontSize: 9, color: FAINT, align: 'right', isTextBox: true, margin: 0,
  })
}

/* ───────────────────────── SLIDE 1 — the gap ───────────────────────── */
{
  const s = slide()
  title(
    s,
    'One security control, three languages',
    'Frameworks already define what "hardened" means. Every vendor says it differently — and hard-coded parsers break the moment a new one arrives.',
  )

  const rows = [
    ['Cisco IOS-XE', 'ip ssh version 2'],
    ['Juniper Junos', 'set system services ssh protocol-version v2'],
    ['Fortinet FortiOS', 'set admin-ssh-v1 disable'],
  ]
  rows.forEach(([vendor, cmd], i) => {
    const y = 1.86 + i * 0.72
    card(s, { x: M, y, w: 6.5, h: 0.58 })
    s.addText(vendor, {
      x: M + 0.2, y, w: 1.8, h: 0.58,
      fontFace: BODY, fontSize: 10.5, color: MUTED, valign: 'middle', isTextBox: true, margin: 0,
    })
    s.addText(cmd, {
      x: M + 1.95, y, w: 4.45, h: 0.58,
      fontFace: MONO, fontSize: 10.5, color: TEXT, valign: 'middle', isTextBox: true, margin: 0,
    })
  })

  s.addText('→', {
    x: M + 6.65, y: 2.28, w: 0.55, h: 0.9,
    fontFace: BODY, fontSize: 30, color: FAINT, align: 'center', valign: 'middle',
    isTextBox: true, margin: 0,
  })

  card(s, { x: M + 7.3, y: 1.86, w: 4.79, h: 2.02, fill: RAISED, line: ACCENT })
  s.addText('One security concept', {
    x: M + 7.5, y: 2.06, w: 4.4, h: 0.3,
    fontFace: BODY, fontSize: 10.5, color: ACCENT, isTextBox: true, margin: 0,
  })
  s.addText('management.ssh.version = 2', {
    x: M + 7.5, y: 2.44, w: 4.4, h: 0.42,
    fontFace: MONO, fontSize: 14, bold: true, color: TEXT, isTextBox: true, margin: 0,
  })
  s.addText(
    'A vendor-neutral security model is the bridge between proprietary syntax and vendor-independent policy.',
    {
      x: M + 7.5, y: 2.94, w: 4.4, h: 0.78,
      fontFace: BODY, fontSize: 11, color: MUTED, isTextBox: true, margin: 0,
    },
  )

  // The consequence, as three stat callouts.
  const stats = [
    ['Manual', 'checklist audits, per device, per vendor'],
    ['Or locked in', 'vendor suites that ignore heterogeneous fleets'],
    ['And brittle', 'a firmware update silently breaks a parser'],
  ]
  stats.forEach(([big, small], i) => {
    const x = M + i * 4.06
    card(s, { x, y: 4.36, w: 3.82, h: 1.28 })
    s.addText(big, {
      x: x + 0.22, y: 4.54, w: 3.4, h: 0.4,
      fontFace: HEAD, fontSize: 19, bold: true, color: i === 2 ? CRIT : TEXT,
      isTextBox: true, margin: 0,
    })
    s.addText(small, {
      x: x + 0.22, y: 4.96, w: 3.4, h: 0.58,
      fontFace: BODY, fontSize: 11, color: MUTED, isTextBox: true, margin: 0,
    })
  })

  s.addText(
    'The gap is not missing standards. It is the absence of a common semantic layer beneath them.',
    {
      x: M, y: 5.92, w: W - 2 * M, h: 0.4,
      fontFace: BODY, fontSize: 13, italic: true, color: ACCENT, isTextBox: true, margin: 0,
    },
  )

  s.addNotes(
    'The problem is not that security standards are missing. CIS, NIST, STIG and ISO all say what a hardened device looks like. The problem is that every vendor expresses those controls in its own syntax, so the industry falls back on manual checklists or vendor-locked suites that cannot span a mixed fleet. And a hard-coded parser fails silently the moment a firmware update or a new vendor arrives.',
  )
  footer(s, 1)
}

/* ──────────────────── SLIDE 2 — architecture ──────────────────── */
{
  const s = slide()
  title(
    s,
    'AI interprets. Rules decide. Humans approve.',
    'The model is confined to answering what a command configures. It has no path to a verdict.',
  )

  const stages = [
    ['Vendor detection', 'weighted signature tokens', 'deterministic', FAINT],
    ['Parsing engine', 'one engine, JSON rule packs · CLI or JSON input', 'deterministic', FAINT],
    ['Semantic layer', 'retrieval → LLM → schema validation', 'AI, constrained', ACCENT],
    ['Security baseline model', '24 canonical parameters + provenance', 'normalised', PASS],
    ['Compliance engine', 'pure comparison · PASS / FAIL / UNKNOWN / N/A', 'no AI, by design', PASS],
  ]

  stages.forEach(([name, detail, tag, tone], i) => {
    const y = 1.72 + i * 0.86
    card(s, { x: M, y, w: 7.5, h: 0.7, line: tone === ACCENT ? ACCENT : LINE })
    s.addText(name, {
      x: M + 0.22, y: y + 0.06, w: 3.1, h: 0.3,
      fontFace: BODY, fontSize: 12.5, bold: true, color: TEXT, isTextBox: true, margin: 0,
    })
    s.addText(detail, {
      x: M + 0.22, y: y + 0.35, w: 4.6, h: 0.28,
      fontFace: BODY, fontSize: 10, color: MUTED, isTextBox: true, margin: 0,
    })
    chip(s, {
      x: M + 5.85, y: y + 0.21, w: 1.45, h: 0.28,
      text: tag, fill: RAISED, color: tone, size: 8.5,
    })
    if (i < stages.length - 1) {
      s.addText('▼', {
        x: M + 0.5, y: y + 0.68, w: 0.3, h: 0.2,
        fontFace: BODY, fontSize: 9, color: LINE, align: 'center', isTextBox: true, margin: 0,
      })
    }
  })

  // Right column: the escape hatch that makes it vendor-agnostic.
  card(s, { x: M + 7.85, y: 1.72, w: 4.24, h: 2.42, fill: RAISED, line: WARN })
  s.addText('Unrecognised command', {
    x: M + 8.05, y: 1.9, w: 3.9, h: 0.3,
    fontFace: BODY, fontSize: 11.5, bold: true, color: WARN, isTextBox: true, margin: 0,
  })
  s.addText(
    [
      { text: 'Model proposes a mapping with its confidence', options: { bullet: true, breakLine: true } },
      { text: 'Administrator approves or corrects it', options: { bullet: true, breakLine: true } },
      { text: 'Written into the vendor rule pack on disk', options: { bullet: true, breakLine: true } },
      { text: 'Recognised deterministically from then on', options: { bullet: true } },
    ],
    {
      x: M + 8.05, y: 2.26, w: 3.9, h: 1.5,
      fontFace: BODY, fontSize: 10.5, color: MUTED,
      paraSpaceAfter: 5, isTextBox: true, margin: 0,
    },
  )
  s.addText('No retraining. No redeployment.', {
    x: M + 8.05, y: 3.78, w: 3.9, h: 0.28,
    fontFace: BODY, fontSize: 10.5, bold: true, italic: true, color: PASS,
    isTextBox: true, margin: 0,
  })

  card(s, { x: M + 7.85, y: 4.34, w: 4.24, h: 1.7 })
  s.addText('Outputs', {
    x: M + 8.05, y: 4.5, w: 3.9, h: 0.28,
    fontFace: BODY, fontSize: 11.5, bold: true, color: TEXT, isTextBox: true, margin: 0,
  })
  s.addText(
    [
      { text: 'Findings with the config lines as evidence', options: { bullet: true, breakLine: true } },
      { text: 'Curated per-vendor remediation CLI', options: { bullet: true, breakLine: true } },
      { text: 'Per-device PDF, bulk zip, credentials masked', options: { bullet: true } },
    ],
    {
      x: M + 8.05, y: 4.84, w: 3.9, h: 1.02,
      fontFace: BODY, fontSize: 10.5, color: MUTED, paraSpaceAfter: 5,
      isTextBox: true, margin: 0,
    },
  )

  s.addText(
    'React + Vite  ·  FastAPI + Pydantic  ·  SQLite  ·  ReportLab  ·  bge-small ONNX (no torch)  ·  any OpenAI-compatible endpoint  ·  Netmiko (optional)',
    {
      x: M, y: 6.18, w: W - 2 * M, h: 0.3,
      fontFace: BODY, fontSize: 10, color: FAINT, isTextBox: true, margin: 0,
    },
  )

  s.addNotes(
    'One engine drives every vendor; vendor knowledge lives in JSON rule packs, not Python. The deterministic stages run first, and the AI layer only sees what they could not resolve. Critically, the compliance engine contains no AI at all — the model decides what a configuration says, never whether that is compliant.',
  )
  footer(s, 2)
}

/* ─────────────── SLIDE 3 — the learning loop + measurement ─────────────── */
{
  const s = slide()
  title(
    s,
    'It learns a command shape, not a string',
    'Teaching one command teaches every variant of it — which is what makes a single approval durable.',
  )

  card(s, { x: M, y: 1.76, w: 7.2, h: 2.5 })
  s.addText('Administrator teaches once', {
    x: M + 0.24, y: 1.94, w: 6.7, h: 0.3,
    fontFace: BODY, fontSize: 11.5, bold: true, color: ACCENT, isTextBox: true, margin: 0,
  })
  const steps = [
    ['/ip service set telnet disabled=no port=23', MONO, TEXT, 11],
    ['canonicalised to a template with typed slots', BODY, FAINT, 10],
    ['/ip service set telnet disabled=no port=<NUM>', MONO, PASS, 11],
    ['so this, never seen before, is also understood', BODY, FAINT, 10],
    ['/ip service set telnet disabled=no port=2323', MONO, PASS, 11],
  ]
  steps.forEach(([t, face, color, size], i) => {
    s.addText(t, {
      x: M + 0.24, y: 2.32 + i * 0.36, w: 6.7, h: 0.32,
      fontFace: face, fontSize: size, color, isTextBox: true, margin: 0,
    })
  })

  // The measurement that justifies the LLM's presence.
  card(s, { x: M + 7.55, y: 1.76, w: 4.54, h: 2.5, fill: RAISED, line: WARN })
  s.addText('Why not just embed and search?', {
    x: M + 7.79, y: 1.94, w: 4.1, h: 0.3,
    fontFace: BODY, fontSize: 11.5, bold: true, color: WARN, isTextBox: true, margin: 0,
  })
  s.addText('We measured it.', {
    x: M + 7.79, y: 2.28, w: 4.1, h: 0.28,
    fontFace: BODY, fontSize: 10.5, italic: true, color: MUTED, isTextBox: true, margin: 0,
  })
  s.addText('~50%', {
    x: M + 7.79, y: 2.6, w: 4.1, h: 0.62,
    fontFace: HEAD, fontSize: 40, bold: true, color: CRIT, isTextBox: true, margin: 0,
  })
  s.addText(
    'retrieval accuracy on held-out cross-vendor commands. Correct and incorrect neighbours both scored 0.74–0.80, so similarity on CLI text is not separable enough to trust.',
    {
      x: M + 7.79, y: 3.26, w: 4.1, h: 0.86,
      fontFace: BODY, fontSize: 10, color: MUTED, isTextBox: true, margin: 0,
    },
  )

  // Consequence row.
  const conseq = [
    ['Retrieval', 'supplies precedent to the model — never decides', FAINT],
    ['The LLM', 'is load-bearing, not decoration', ACCENT],
    ['Taught commands', 'resolve deterministically, with no model at all', PASS],
  ]
  conseq.forEach(([h, d, tone], i) => {
    const x = M + i * 4.06
    card(s, { x, y: 4.5, w: 3.82, h: 1.16 })
    s.addText(h, {
      x: x + 0.22, y: 4.66, w: 3.4, h: 0.3,
      fontFace: BODY, fontSize: 12, bold: true, color: tone, isTextBox: true, margin: 0,
    })
    s.addText(d, {
      x: x + 0.22, y: 4.98, w: 3.4, h: 0.56,
      fontFace: BODY, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0,
    })
  })

  s.addText(
    'A mapping an administrator approves is written into the same rule pack, in the same shape, as one that shipped in the box — learned and built-in knowledge are the same object.',
    {
      x: M, y: 5.94, w: W - 2 * M, h: 0.4,
      fontFace: BODY, fontSize: 12, italic: true, color: ACCENT, isTextBox: true, margin: 0,
    },
  )

  s.addNotes(
    'The differentiator is not that we call a language model. It is that an approval generalises and then leaves the model behind. We also want to be honest about why the LLM is there at all: we tested pure embedding retrieval and it answered about half of a held-out cross-vendor set, with correct and incorrect neighbours indistinguishable by score. If similarity search had worked, the model would be decoration.',
  )
  footer(s, 3)
}

/* ──────────────── SLIDE 4 — assurance / failure behaviour ──────────────── */
{
  const s = slide()
  title(
    s,
    'A model mistake cannot become a compliance result',
    'This is a security tool, so the interesting question is what happens when a component is wrong.',
  )

  const cards = [
    [
      'AI proposal, unreviewed',
      'Control reports UNKNOWN',
      'Never PASS, never FAIL. A wrong reading lowers coverage; it cannot corrupt a verdict.',
      PASS,
    ],
    [
      'Prompt injection in a config',
      'Structurally inert',
      'Config is fenced as untrusted data — and even full compliance yields no verdict, because the model has no path to one.',
      PASS,
    ],
    [
      'Inference endpoint down',
      'Degraded, not stopped',
      'Parsing, compliance, reporting and manual classification all continue. Commands queue for a human.',
      PASS,
    ],
    [
      'Two readings disagree',
      'The riskier one wins',
      'Both lines cited. In an audit, a false negative is more damaging than a false positive.',
      WARN,
    ],
    [
      'Setting cannot be parsed',
      'UNKNOWN, not FAIL',
      'Reporting an unparsed line as a violation would manufacture a false positive and destroy trust in the score.',
      WARN,
    ],
    [
      'No verified remediation',
      'Guidance, not commands',
      'A hallucinated CLI command in a report gets pasted into production. We say so instead.',
      WARN,
    ],
  ]

  cards.forEach(([q, a, why, tone], i) => {
    const col = i % 3
    const row = Math.floor(i / 3)
    const x = M + col * 4.06
    const y = 1.78 + row * 2.16
    card(s, { x, y, w: 3.82, h: 1.98 })
    s.addText(q, {
      x: x + 0.22, y: y + 0.18, w: 3.4, h: 0.3,
      fontFace: BODY, fontSize: 10.5, color: FAINT, isTextBox: true, margin: 0,
    })
    s.addText(a, {
      x: x + 0.22, y: y + 0.48, w: 3.4, h: 0.36,
      fontFace: BODY, fontSize: 13, bold: true, color: tone, isTextBox: true, margin: 0,
    })
    s.addText(why, {
      x: x + 0.22, y: y + 0.9, w: 3.4, h: 0.92,
      fontFace: BODY, fontSize: 10, color: MUTED, isTextBox: true, margin: 0,
    })
  })

  s.addText(
    'Credentials — password hashes, SNMP communities, pre-shared keys, private keys — are redacted before any prompt is built and before any evidence is drawn into a report.',
    {
      x: M, y: 6.18, w: W - 2 * M, h: 0.4,
      fontFace: BODY, fontSize: 11.5, color: MUTED, isTextBox: true, margin: 0,
    },
  )

  s.addNotes(
    'Every finding is reproducible and cites the configuration lines behind it, so a reviewer who disagrees with a verdict can trace it back to the exact text. The redaction path is the most heavily tested part of the codebase, because a report circulates far more widely than the configuration it describes.',
  )
  footer(s, 4)
}

/* ──────────────────────── SLIDE 5 — results ──────────────────────── */
{
  const s = slide()
  title(
    s,
    'Working prototype, measured',
    'Six configurations, five vendor packs, one vendor deliberately left unsupported — and a cloud firewall that is not a CLI at all.',
  )

  const stats = [
    ['23', 'controls', 'each mapped to all four frameworks from one catalogue entry'],
    ['4', 'frameworks', 'CIS · NIST SP 800-53 · DISA STIG · ISO/IEC 27001'],
    ['164', 'tests passing', 'redaction, parsing, verdicts, learning, bulk, SSH'],
    ['≤13 ms', 'per device', 'ingest to verdict, deterministic path'],
  ]
  stats.forEach(([big, label, sub], i) => {
    const x = M + i * 3.05
    card(s, { x, y: 1.78, w: 2.81, h: 1.72 })
    s.addText(big, {
      x: x + 0.2, y: 1.92, w: 2.45, h: 0.62,
      fontFace: HEAD, fontSize: 34, bold: true, color: ACCENT, isTextBox: true, margin: 0,
    })
    s.addText(label, {
      x: x + 0.2, y: 2.54, w: 2.45, h: 0.28,
      fontFace: BODY, fontSize: 11.5, bold: true, color: TEXT, isTextBox: true, margin: 0,
    })
    s.addText(sub, {
      x: x + 0.2, y: 2.82, w: 2.45, h: 0.6,
      fontFace: BODY, fontSize: 9.5, color: MUTED, isTextBox: true, margin: 0,
    })
  })

  const rows = [
    ['Cisco IOS-XE', 'Catalyst 9300', '1.00', '68%', PASS],
    ['Juniper Junos', 'SRX 340', '1.00', '79%', PASS],
    ['Fortinet FortiOS', 'FortiGate 100F', '1.00', '100%', PASS],
    ['Palo Alto PAN-OS', 'PA-3220', '1.00', '94%', PASS],
    ['AWS Security Group', 'JSON, not a CLI', '1.00', '100% · 21 N/A', PASS],
    ['MikroTik RouterOS', 'RB4011 — no parser', 'unknown', '0% → taught', WARN],
  ]

  card(s, { x: M, y: 3.72, w: 7.5, h: 2.32 })
  const heads = ['Vendor', 'Device', 'Detection', 'Coverage']
  const colX = [0.22, 2.3, 4.35, 5.85]
  heads.forEach((h, i) => {
    s.addText(h, {
      x: M + colX[i], y: 3.86, w: 2.0, h: 0.26,
      fontFace: BODY, fontSize: 9, bold: true, color: FAINT, isTextBox: true, margin: 0,
    })
  })
  rows.forEach((r, i) => {
    const y = 4.14 + i * 0.31
    const tone = r[4]
    ;[r[0], r[1], r[2], r[3]].forEach((cell, c) => {
      s.addText(cell, {
        x: M + colX[c], y, w: c === 1 ? 2.0 : 1.9, h: 0.28,
        fontFace: c >= 2 ? MONO : BODY, fontSize: 9.5,
        color: c === 3 ? tone : c === 0 ? TEXT : MUTED,
        valign: 'middle', isTextBox: true, margin: 0,
      })
    })
  })

  card(s, { x: M + 7.85, y: 3.72, w: 4.24, h: 2.32, fill: RAISED, line: ACCENT })
  s.addText('Sovereignty', {
    x: M + 8.07, y: 3.88, w: 3.9, h: 0.3,
    fontFace: BODY, fontSize: 11.5, bold: true, color: ACCENT, isTextBox: true, margin: 0,
  })
  s.addText(
    'The AI layer runs on open weights behind an OpenAI-compatible endpoint. Point it at a local Ollama and the identical pipeline runs on the operator\u2019s own hardware — no configuration data leaves the network.',
    {
      x: M + 8.07, y: 4.22, w: 3.9, h: 1.1,
      fontFace: BODY, fontSize: 10.5, color: MUTED, isTextBox: true, margin: 0,
    },
  )
  s.addText('Adding a vendor is a JSON file, not a release.', {
    x: M + 8.07, y: 5.44, w: 3.9, h: 0.44,
    fontFace: BODY, fontSize: 10.5, bold: true, italic: true, color: PASS,
    isTextBox: true, margin: 0,
  })

  s.addText(
    'AI interprets syntax.  Rules decide compliance.  Humans approve new knowledge.',
    {
      x: M, y: 6.24, w: W - 2 * M, h: 0.4,
      fontFace: HEAD, fontSize: 14, bold: true, color: TEXT, isTextBox: true, margin: 0,
    },
  )

  s.addNotes(
    'The numbers here are measured on the bundled samples, not estimated. Coverage is the share of security-relevant configuration lines the engine interpreted; the Fortinet sample reaches 100 percent, the Cisco one 68 percent, and the remainder is exactly what the training queue exists for. MikroTik is unsupported on purpose — it is how we demonstrate the path to vendor number fifty.',
  )
  footer(s, 5)
}

pres
  .writeFile({ fileName: require('path').join(__dirname, '..', 'NetBaseline_AI_Technical_Presentation.pptx') })
  .then((f) => console.log('wrote', f))
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
