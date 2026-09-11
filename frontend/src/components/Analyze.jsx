import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { Banner, Button, Card, Code, Empty, ScoreRing, SectionTitle, Spinner, Stat } from './ui'

const FRAMEWORKS = [
  { id: 'ALL', label: 'All frameworks' },
  { id: 'CIS', label: 'CIS Controls v8' },
  { id: 'NIST', label: 'NIST SP 800-53' },
  { id: 'STIG', label: 'DISA STIG' },
  { id: 'ISO27001', label: 'ISO/IEC 27001' },
]

const SAMPLE_META = {
  'cisco_core_switch.cfg': { name: 'Cisco Catalyst 9300', role: 'Core switch', glyph: '⬢' },
  'juniper_edge_srx.conf': { name: 'Juniper SRX 340', role: 'Edge firewall', glyph: '⬣' },
  'fortinet_perimeter_fw.conf': { name: 'FortiGate 100F', role: 'Perimeter firewall', glyph: '⬡' },
  'mikrotik_branch_router.rsc': { name: 'MikroTik RB4011', role: 'Unsupported vendor', glyph: '◈', unknown: true },
}

export default function Analyze({ meta, analysis, onAnalysis, goTo, onError }) {
  const [samples, setSamples] = useState([])
  const [framework, setFramework] = useState('ALL')
  const [busy, setBusy] = useState(false)
  const [stages, setStages] = useState([])
  const [pasted, setPasted] = useState('')
  const [dragging, setDragging] = useState(false)
  const fileInput = useRef(null)

  useEffect(() => {
    api.samples().then(setSamples).catch((e) => onError(e.message))
  }, [onError])

  // Stages are revealed one at a time with the timings the run actually
  // measured. Nothing here is simulated -- the numbers come from the backend,
  // the staggering only makes a sub-20ms pipeline legible to a viewer.
  const revealStages = useCallback((result) => {
    const t = result.timings
    const steps = [
      { label: 'Configuration ingested', detail: `${result.normalized.stats.total_lines} lines`, ms: null },
      {
        label: 'Vendor identified',
        detail: `${result.detection.display_name} · ${(result.detection.confidence * 100).toFixed(0)}% match`,
        ms: t.detection_ms,
      },
      {
        label: 'Normalised to security baseline',
        detail: `${result.normalized.facts.length} parameters · ${result.normalized.stats.coverage}% of security lines`,
        ms: t.parsing_ms,
      },
      {
        label: result.ai.llm_available ? 'Semantic layer interpreted unknowns' : 'Semantic layer unavailable',
        detail: result.ai.llm_available
          ? `${result.ai.proposals_accepted} of ${result.ai.commands_considered} proposed`
          : `${result.ai.commands_considered} command(s) queued for review`,
        ms: t.interpretation_ms,
      },
      {
        label: 'Compliance evaluated',
        detail: `${result.scan.summary.passed} pass · ${result.scan.summary.failed} fail · ${result.scan.summary.unknown} undetermined`,
        ms: t.evaluation_ms,
      },
    ]
    setStages([])
    steps.forEach((step, index) => {
      setTimeout(() => setStages((prev) => [...prev, step]), 130 * (index + 1))
    })
  }, [])

  const run = useCallback(
    async (fn) => {
      setBusy(true)
      setStages([])
      onError(null)
      try {
        const result = await fn()
        onAnalysis(result)
        revealStages(result)
      } catch (err) {
        onError(err.message)
      } finally {
        setBusy(false)
      }
    },
    [onAnalysis, onError, revealStages],
  )

  const onDrop = (event) => {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files?.[0]
    if (file) run(() => api.upload(file, framework))
  }

  return (
    <div className="animate-fade-up">
      <header className="mb-5">
        <h1 className="text-[19px] font-semibold">Analyse a configuration</h1>
        <p className="mt-1 text-[13px] text-muted">
          Upload a device configuration from any vendor. Syntax is normalised into a vendor-neutral
          security model, then judged by a deterministic rule engine.
        </p>
      </header>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.13em] text-faint">
          Framework
        </span>
        {FRAMEWORKS.map((f) => (
          <button
            key={f.id}
            onClick={() => setFramework(f.id)}
            className={`rounded-lg px-2.5 py-1.5 text-xs transition-colors ${
              framework === f.id
                ? 'bg-accent/15 text-text ring-1 ring-inset ring-accent/30'
                : 'text-muted hover:bg-raised hover:text-text'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.05fr_0.95fr]">
        <div>
          <SectionTitle hint="bundled, no files needed">Sample devices</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-2">
            {samples.map((s) => {
              const info = SAMPLE_META[s.name] ?? { name: s.name, role: '', glyph: '▸' }
              return (
                <button
                  key={s.name}
                  disabled={busy}
                  onClick={() => run(() => api.analyzeSample(s.name, framework))}
                  className="group flex items-start gap-3 rounded-xl border border-line bg-panel/70 p-3 text-left transition-colors hover:border-accent/40 hover:bg-raised disabled:opacity-50"
                >
                  <span
                    className={`mt-0.5 text-base ${info.unknown ? 'text-medium' : 'text-accent'}`}
                  >
                    {info.glyph}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium">{info.name}</span>
                    <span className="block text-[11px] text-faint">
                      {info.role} · {s.lines} lines
                    </span>
                    {info.unknown ? (
                      <span className="mt-1 inline-block rounded bg-medium/15 px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wider text-medium">
                        no parser exists
                      </span>
                    ) : null}
                  </span>
                </button>
              )
            })}
          </div>

          <div className="mt-4">
            <SectionTitle>Your own configuration</SectionTitle>
            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => fileInput.current?.click()}
              className={`cursor-pointer rounded-xl border border-dashed px-4 py-7 text-center transition-colors ${
                dragging ? 'border-accent bg-accent/8' : 'border-line hover:border-accent/40 hover:bg-raised/50'
              }`}
            >
              <input
                ref={fileInput}
                type="file"
                className="hidden"
                accept=".cfg,.conf,.txt,.rsc,.json,.log"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) run(() => api.upload(file, framework))
                  e.target.value = ''
                }}
              />
              <div className="text-sm text-muted">Drop a configuration file, or click to browse</div>
              <div className="mt-1 text-[11px] text-faint">.cfg · .conf · .txt · .rsc · any vendor</div>
            </div>

            <details className="mt-2 group">
              <summary className="cursor-pointer list-none text-[12px] text-faint hover:text-muted">
                or paste configuration text ▾
              </summary>
              <textarea
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                rows={7}
                spellCheck={false}
                placeholder={'hostname EDGE-RTR-01\nip ssh version 2\nline vty 0 4\n transport input telnet'}
                className="mt-2 w-full rounded-lg border border-line bg-ink/60 p-3 font-mono text-[11.5px] text-text outline-none placeholder:text-faint/60 focus:border-accent/50"
              />
              <Button
                className="mt-2"
                variant="ghost"
                disabled={busy || !pasted.trim()}
                onClick={() => run(() => api.analyzeText(pasted, 'pasted-configuration.cfg', framework))}
              >
                Analyse pasted text
              </Button>
            </details>
          </div>
        </div>

        <div>
          <SectionTitle hint={busy ? 'running' : analysis ? 'complete' : 'idle'}>Pipeline</SectionTitle>
          <Card className="p-4">
            {busy ? (
              <div className="flex items-center gap-2.5 py-8 text-sm text-muted">
                <Spinner /> Analysing configuration…
              </div>
            ) : stages.length === 0 && !analysis ? (
              <Empty
                icon="◇"
                title="No configuration analysed yet"
                hint="Pick a sample device or upload a file. Each stage reports the time it actually took."
              />
            ) : (
              <ol className="space-y-2.5">
                {stages.map((stage, index) => (
                  <li key={index} className="flex animate-fade-up items-start gap-2.5">
                    <span className="mt-[3px] grid h-4 w-4 shrink-0 place-items-center rounded-full bg-pass/15 text-[9px] font-bold text-pass ring-1 ring-inset ring-pass/30">
                      ✓
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-[12.5px] leading-tight">{stage.label}</span>
                      <span className="block text-[11px] text-faint">{stage.detail}</span>
                    </span>
                    {stage.ms !== null ? (
                      <span className="shrink-0 font-mono text-[10.5px] tabular-nums text-faint">
                        {stage.ms.toFixed(1)} ms
                      </span>
                    ) : null}
                  </li>
                ))}
              </ol>
            )}
          </Card>

          {analysis && !busy ? <ResultSummary analysis={analysis} goTo={goTo} /> : null}
        </div>
      </div>
    </div>
  )
}

function ResultSummary({ analysis, goTo }) {
  const summary = analysis.scan.summary
  const device = analysis.normalized.device
  const queue = analysis.normalized.unknown_commands.length
  const unknownVendor = analysis.detection.vendor === 'unknown'

  return (
    <div className="mt-4 animate-fade-up">
      <SectionTitle>Result</SectionTitle>
      <Card className="p-4">
        <div className="flex items-start gap-4">
          <ScoreRing score={summary.score} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[15px] font-semibold">{device.display_name}</div>
            <div className="mt-0.5 text-[12px] text-muted">{analysis.detection.display_name}</div>
            <dl className="mt-2.5 space-y-1 text-[11.5px]">
              {[
                ['Model', device.model],
                ['OS', [device.os_family, device.os_version].filter(Boolean).join(' ')],
                ['Serial', device.serial_number],
              ].map(([k, v]) =>
                v ? (
                  <div key={k} className="flex gap-2">
                    <dt className="w-14 shrink-0 text-faint">{k}</dt>
                    <dd className="truncate font-mono text-muted">{v}</dd>
                  </div>
                ) : null,
              )}
            </dl>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <Stat label="Passed" value={summary.passed} tone="text-pass" />
          <Stat label="Failed" value={summary.failed} tone="text-critical" />
          <Stat label="Undetermined" value={summary.unknown} tone="text-unknown" />
        </div>

        {unknownVendor ? (
          <div className="mt-3">
            <Banner tone="warn">
              <strong>No parser exists for this vendor.</strong> Every control is undetermined
              because nothing in the configuration has been mapped yet. {queue} security-relevant
              command{queue === 1 ? '' : 's'} are waiting in <em>Teach AI</em> — classify them once
              and this device becomes auditable.
            </Banner>
          </div>
        ) : summary.unknown > 0 ? (
          <div className="mt-3">
            <Banner tone="info">
              {summary.unknown} control{summary.unknown === 1 ? ' is' : 's are'} undetermined and
              excluded from the score. Coverage is {summary.coverage}%.
            </Banner>
          </div>
        ) : null}

        <div className="mt-3 flex gap-2">
          <Button onClick={() => goTo('findings')} className="flex-1">
            View {summary.failed} finding{summary.failed === 1 ? '' : 's'}
          </Button>
          {queue > 0 ? (
            <Button variant="ghost" onClick={() => goTo('teach')}>
              Teach {queue}
            </Button>
          ) : null}
        </div>
      </Card>
    </div>
  )
}
