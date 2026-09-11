import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { Banner, Button, Card, Code, ConfidenceBar, Empty, SectionTitle, Spinner, Stat } from './ui'

/** Preview the template a command will be generalised into, before approving.
 *  Mirrors backend canonicalisation so the reviewer can see that they are
 *  teaching a command *shape*, not a literal string. */
function previewTemplate(command) {
  return command
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\/\d{1,2}\b/g, '<CIDR>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<IP>')
    .replace(/"[^"]*"/g, '<QUOTED>')
    .replace(/(?<![\w-])v(?=\d)\d+\b/gi, '<VER>')
    .replace(/(?<![\w.\-])\d+(?![\w.])/g, '<NUM>')
}

export default function Teach({ meta, analysis, onAnalysis, refreshMeta, onError }) {
  const [index, setIndex] = useState(0)
  const [parameter, setParameter] = useState('')
  const [value, setValue] = useState('true')
  const [busy, setBusy] = useState(false)
  const [learned, setLearned] = useState([])
  const [rescanning, setRescanning] = useState(false)
  const [delta, setDelta] = useState(null)

  const queue = analysis?.normalized?.unknown_commands ?? []
  const current = queue[index]
  const parameters = meta?.parameters ?? []
  const spec = parameters.find((p) => p.name === parameter)

  // Pre-fill from the model's proposal so the common path is a single click,
  // while leaving every field editable so the reviewer stays in control.
  useEffect(() => {
    if (!current) return
    setParameter(current.suggested_parameter ?? '')
    setValue(
      current.suggested_value === null || current.suggested_value === undefined
        ? 'true'
        : String(current.suggested_value),
    )
  }, [current])

  const grouped = useMemo(() => {
    const out = {}
    for (const p of parameters) (out[p.category] ??= []).push(p)
    return out
  }, [parameters])

  if (!analysis) {
    return (
      <Empty
        icon="✦"
        title="No analysis loaded"
        hint="Analyse a configuration first. Any command the parser could not interpret arrives here for classification."
      />
    )
  }

  if (queue.length === 0) {
    return (
      <div className="animate-fade-up">
        <header className="mb-4">
          <h1 className="text-[19px] font-semibold">Teach AI</h1>
        </header>
        <Card>
          <Empty
            icon="✓"
            title="Nothing left to classify"
            hint={`Every security-relevant line in ${analysis.normalized.device.display_name} is already mapped to the security baseline.`}
          />
        </Card>
        {learned.length ? <LearnedList learned={learned} /> : null}
      </div>
    )
  }

  const approve = async () => {
    if (!parameter) return
    setBusy(true)
    onError(null)
    try {
      let parsed = value
      if (spec?.value_type === 'boolean') parsed = value === 'true'
      else if (spec?.value_type === 'integer') parsed = Number(value)

      const response = await api.teach({
        command: current.raw,
        parameter,
        value: parsed,
        vendor: analysis.detection.vendor === 'unknown' ? 'generic' : analysis.detection.vendor,
        approved_by: 'netadmin',
        config_id: analysis.config_id,
        ai_parameter: current.suggested_parameter ?? null,
        ai_value: current.suggested_value ?? null,
        ai_confidence: current.suggested_confidence ?? null,
      })

      setLearned((prev) => [...prev, { ...response, command: current.raw }])
      await refreshMeta()
      setIndex((i) => Math.min(i, Math.max(0, queue.length - 2)))
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const rescan = async () => {
    setRescanning(true)
    onError(null)
    try {
      const before = analysis.scan.summary
      const beforeQueue = queue.length
      const result = await api.rescan(analysis.config_id, analysis.framework)
      setDelta({
        beforeScore: before.score,
        afterScore: result.scan.summary.score,
        beforeUnknown: before.unknown,
        afterUnknown: result.scan.summary.unknown,
        beforeQueue,
        afterQueue: result.normalized.unknown_commands.length,
        newFailures: result.scan.summary.failed - before.failed,
      })
      onAnalysis(result)
      setIndex(0)
    } catch (err) {
      onError(err.message)
    } finally {
      setRescanning(false)
    }
  }

  const template = current ? previewTemplate(current.raw) : ''
  const generalises = template !== current?.raw.trim().replace(/\s+/g, ' ')

  return (
    <div className="animate-fade-up">
      <header className="mb-4">
        <h1 className="text-[19px] font-semibold">Teach AI</h1>
        <p className="mt-1 text-[13px] text-muted">
          Commands the parser could not interpret. Classify one and the platform recognises it — and
          every variant of it — on every future scan, with no code change and no restart.
        </p>
      </header>

      {!analysis.ai.llm_available ? (
        <div className="mb-4">
          <Banner tone="warn">
            <strong>No inference endpoint configured.</strong> The platform still works: commands
            queue here for manual classification and the rest of the pipeline is unaffected. Set{' '}
            <code className="font-mono text-[11px]">LLM_API_KEY</code> in{' '}
            <code className="font-mono text-[11px]">backend/.env</code> to have the model propose
            mappings for you.
          </Banner>
        </div>
      ) : null}

      {delta ? (
        <div className="mb-4">
          <Banner tone="good">
            <strong>Re-scan complete.</strong> Unclassified commands {delta.beforeQueue} →{' '}
            {delta.afterQueue}, undetermined controls {delta.beforeUnknown} → {delta.afterUnknown},
            score {delta.beforeScore}% → {delta.afterScore}%
            {delta.newFailures > 0
              ? `. ${delta.newFailures} previously invisible violation${delta.newFailures === 1 ? '' : 's'} are now detected.`
              : '.'}
          </Banner>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,300px)_minmax(0,1fr)]">
        <div>
          <SectionTitle hint={`${queue.length} queued`}>Unclassified</SectionTitle>
          <Card className="max-h-[480px] overflow-y-auto">
            <ul className="divide-y divide-line-soft">
              {queue.map((item, i) => (
                <li key={`${item.line_number}-${i}`}>
                  <button
                    onClick={() => setIndex(i)}
                    className={`w-full px-3 py-2.5 text-left transition-colors hover:bg-raised ${
                      i === index ? 'bg-raised' : ''
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-faint">L{item.line_number}</span>
                      {item.suggested_parameter ? (
                        <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-accent">
                          proposed
                        </span>
                      ) : null}
                    </div>
                    <div className="mt-1 truncate font-mono text-[11.5px] text-text">{item.raw}</div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <div>
          <SectionTitle hint={`${index + 1} of ${queue.length}`}>Classify command</SectionTitle>
          <Card className="p-4">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
              Unrecognised command · line {current.line_number}
            </div>
            <Code>{current.raw}</Code>

            {generalises ? (
              <div className="mt-2 rounded-lg border border-line-soft bg-raised/40 px-3 py-2">
                <div className="text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
                  Will be learned as
                </div>
                <div className="mt-1 font-mono text-[11.5px] text-pass">{template}</div>
                <p className="mt-1 text-[11px] leading-relaxed text-faint">
                  The placeholders make this a command <em>shape</em>, so variants with different
                  values are recognised too — you will not be asked about this command again.
                </p>
              </div>
            ) : null}

            {current.suggested_parameter ? (
              <div className="mt-3 rounded-lg border border-accent/30 bg-accent/8 p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-accent">
                    Model proposal
                  </span>
                  <ConfidenceBar value={current.suggested_confidence} className="w-32" />
                </div>
                <div className="mt-1.5 font-mono text-[12px]">
                  {current.suggested_parameter} = {String(current.suggested_value)}
                </div>
                {current.suggested_rationale ? (
                  <p className="mt-1 text-[11.5px] leading-relaxed text-muted">
                    {current.suggested_rationale}
                  </p>
                ) : null}
                <p className="mt-1.5 text-[11px] text-faint">
                  A proposal, not a decision. Nothing is applied until you approve it.
                </p>
              </div>
            ) : (
              <div className="mt-3">
                <Banner tone="info">
                  No proposal for this command — classify it manually below.
                </Banner>
              </div>
            )}

            <div className="mt-4 grid gap-3 sm:grid-cols-[1.6fr_1fr]">
              <label className="block">
                <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
                  Security parameter
                </span>
                <select
                  value={parameter}
                  onChange={(e) => setParameter(e.target.value)}
                  className="w-full rounded-lg border border-line bg-ink/60 px-2.5 py-2 text-[12.5px] text-text outline-none focus:border-accent/50"
                >
                  <option value="">— select —</option>
                  {Object.entries(grouped).map(([category, items]) => (
                    <optgroup key={category} label={category}>
                      {items.map((p) => (
                        <option key={p.name} value={p.name}>
                          {p.name}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
                  Value {spec ? `(${spec.value_type})` : ''}
                </span>
                {spec?.value_type === 'boolean' ? (
                  <div className="flex gap-1.5">
                    {['true', 'false'].map((v) => (
                      <button
                        key={v}
                        onClick={() => setValue(v)}
                        className={`flex-1 rounded-lg border px-2 py-2 text-[12.5px] transition-colors ${
                          value === v
                            ? 'border-accent/40 bg-accent/15 text-text'
                            : 'border-line text-muted hover:bg-raised'
                        }`}
                      >
                        {v}
                      </button>
                    ))}
                  </div>
                ) : (
                  <input
                    type={spec?.value_type === 'integer' ? 'number' : 'text'}
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    className="w-full rounded-lg border border-line bg-ink/60 px-2.5 py-2 text-[12.5px] text-text outline-none focus:border-accent/50"
                  />
                )}
              </label>
            </div>

            {spec ? (
              <p className="mt-2 text-[11.5px] leading-relaxed text-faint">
                <span className="text-muted">{spec.description}.</span> {spec.guidance}
              </p>
            ) : null}

            <div className="mt-4 flex flex-wrap gap-2">
              <Button onClick={approve} disabled={busy || !parameter}>
                {busy ? <Spinner /> : null}
                {current.suggested_parameter === parameter &&
                String(current.suggested_value) === value
                  ? 'Approve proposal'
                  : 'Save mapping'}
              </Button>
              <Button
                variant="quiet"
                onClick={() => setIndex((i) => Math.min(i + 1, queue.length - 1))}
                disabled={index >= queue.length - 1}
              >
                Skip
              </Button>
              {learned.length > 0 ? (
                <Button variant="ghost" onClick={rescan} disabled={rescanning} className="ml-auto">
                  {rescanning ? <Spinner /> : null} Re-scan with {learned.length} new mapping
                  {learned.length === 1 ? '' : 's'}
                </Button>
              ) : null}
            </div>
          </Card>

          {learned.length ? <LearnedList learned={learned} /> : null}
        </div>
      </div>
    </div>
  )
}

function LearnedList({ learned }) {
  return (
    <div className="mt-4">
      <SectionTitle hint="active immediately, no restart">Learned this session</SectionTitle>
      <Card className="divide-y divide-line-soft">
        {learned.map((item, i) => (
          <div key={i} className="px-3.5 py-2.5">
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-pass">✓</span>
              <span className="font-mono text-[11.5px] text-muted">{item.template}</span>
              {item.accepted_ai_suggestion ? (
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-accent">
                  AI agreed
                </span>
              ) : (
                <span className="rounded bg-medium/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-medium">
                  corrected
                </span>
              )}
            </div>
            <div className="mt-0.5 pl-5 font-mono text-[11px] text-faint">
              → {item.parameter} · {item.value_rule}
            </div>
          </div>
        ))}
      </Card>
    </div>
  )
}
