import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import {
  Banner, Button, Card, Code, Empty, ScoreRing, SectionTitle,
  SeverityPill, Spinner, Stat, StatusPill, SEVERITY_TONE,
} from './ui'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Findings({ analysis, goTo }) {
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('FAIL')
  const [report, setReport] = useState(null)
  const [reporting, setReporting] = useState(false)

  useEffect(() => {
    setSelected(null)
    setReport(null)
  }, [analysis?.config_id])

  const findings = analysis?.scan?.findings ?? []
  const visible = useMemo(
    () => (filter === 'ALL' ? findings : findings.filter((f) => f.status === filter)),
    [findings, filter],
  )

  if (!analysis) {
    return (
      <Empty
        icon="◈"
        title="No analysis loaded"
        hint="Analyse a configuration first — findings, evidence and remediation appear here."
      />
    )
  }

  const summary = analysis.scan.summary
  const device = analysis.normalized.device
  const breakdown = summary.failed_by_severity

  const makeReport = async () => {
    setReporting(true)
    try {
      setReport(await api.generateReport(analysis.config_id))
    } finally {
      setReporting(false)
    }
  }

  return (
    <div className="animate-fade-up">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-[19px] font-semibold">{device.display_name}</h1>
          <p className="mt-0.5 text-[12.5px] text-muted">
            {analysis.detection.display_name}
            {device.serial_number ? ` · serial ${device.serial_number}` : ''} · assessed against{' '}
            {analysis.framework === 'ALL' ? 'all frameworks' : analysis.framework}
          </p>
        </div>
        <div className="flex gap-2">
          {report ? (
            <a href={api.reportUrl(analysis.config_id)} target="_blank" rel="noreferrer">
              <Button>Download PDF ({Math.round(report.size_bytes / 1024)} KB)</Button>
            </a>
          ) : (
            <Button variant="ghost" onClick={makeReport} disabled={reporting}>
              {reporting ? <Spinner /> : null} Generate PDF report
            </Button>
          )}
        </div>
      </header>

      <Card className="mb-4 p-4">
        <div className="flex flex-wrap items-center gap-5">
          <ScoreRing score={summary.score} size={104} />
          <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Passed" value={summary.passed} tone="text-pass" />
            <Stat label="Failed" value={summary.failed} tone="text-critical" />
            <Stat label="Undetermined" value={summary.unknown} tone="text-unknown" />
            <Stat
              label="Coverage"
              value={`${summary.coverage}%`}
              sub="controls the engine could decide"
            />
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((sev) => {
            const count = breakdown[sev.toLowerCase()]
            const tone = SEVERITY_TONE[sev]
            return (
              <div
                key={sev}
                className={`flex items-center gap-2 rounded-lg border border-line-soft px-3 py-1.5 ${count ? tone.bg : ''}`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                  {sev}
                </span>
                <span className={`text-sm font-semibold tabular-nums ${count ? tone.text : 'text-faint'}`}>
                  {count}
                </span>
              </div>
            )
          })}
        </div>
      </Card>

      {summary.unknown > 0 ? (
        <div className="mb-4">
          <Banner tone="info">
            <strong>{summary.unknown} control{summary.unknown === 1 ? '' : 's'} undetermined.</strong>{' '}
            The configuration carried no statement these could be judged on, so they are excluded
            from the score rather than counted as failures — reporting an unparsed setting as a
            violation would manufacture a false positive.{' '}
            {analysis.normalized.unknown_commands.length > 0 ? (
              <button className="text-accent underline underline-offset-2" onClick={() => goTo('teach')}>
                Classify {analysis.normalized.unknown_commands.length} unrecognised command
                {analysis.normalized.unknown_commands.length === 1 ? '' : 's'}
              </button>
            ) : null}
          </Banner>
        </div>
      ) : null}

      {summary.not_applicable > 0 ? (
        <div className="mb-4">
          <Banner tone="info">
            <strong>
              {summary.not_applicable} control{summary.not_applicable === 1 ? ' does' : 's do'} not
              apply to this class of device.
            </strong>{' '}
            A {analysis.detection.display_name} has no login banner, NTP client or local accounts,
            so those controls are reported as not applicable — not as undetermined, and not as
            failures. They are excluded from both the score and the coverage figure.
          </Banner>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
        <div>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {[
              ['FAIL', `Failed (${summary.failed})`],
              ['PASS', `Passed (${summary.passed})`],
              ['UNKNOWN', `Undetermined (${summary.unknown})`],
              ...(summary.not_applicable
                ? [['NOT_APPLICABLE', `Not applicable (${summary.not_applicable})`]]
                : []),
              ['ALL', `All (${findings.length})`],
            ].map(([id, label]) => (
              <button
                key={id}
                onClick={() => setFilter(id)}
                className={`rounded-lg px-2.5 py-1.5 text-xs transition-colors ${
                  filter === id
                    ? 'bg-accent/15 text-text ring-1 ring-inset ring-accent/30'
                    : 'text-muted hover:bg-raised hover:text-text'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <Card className="overflow-hidden">
            {visible.length === 0 ? (
              <Empty icon="✓" title="Nothing in this category" />
            ) : (
              <ul className="divide-y divide-line-soft">
                {visible.map((finding) => (
                  <li key={finding.rule_id}>
                    <button
                      onClick={() => setSelected(finding)}
                      className={`w-full px-3.5 py-2.5 text-left transition-colors hover:bg-raised ${
                        selected?.rule_id === finding.rule_id ? 'bg-raised' : ''
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <StatusPill status={finding.status} />
                        <SeverityPill severity={finding.severity} />
                        <span className="font-mono text-[10.5px] text-faint">{finding.rule_id}</span>
                        {finding.is_ai_assisted ? (
                          <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wider text-accent">
                            AI-read
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-1 text-[13px] leading-snug">{finding.title}</div>
                      {finding.evidence?.[0] ? (
                        <div className="mt-1 truncate font-mono text-[11px] text-faint">
                          {finding.evidence[0].text}
                        </div>
                      ) : (
                        <div className="mt-1 truncate text-[11px] italic text-faint">
                          no matching statement in configuration
                        </div>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <div>
          {selected ? (
            <Detail finding={selected} analysis={analysis} />
          ) : (
            <Card>
              <Empty
                icon="→"
                title="Select a finding"
                hint="Each finding shows the configuration lines it was derived from, the frameworks it maps to, and the exact commands to fix it on this platform."
              />
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

function Detail({ finding, analysis }) {
  const [plan, setPlan] = useState(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    setPlan(null)
    setCopied(false)
    if (finding.status !== 'FAIL' || !finding.remediation_id) return
    setLoading(true)
    api
      .remediation(analysis.config_id, finding.rule_id)
      .then(setPlan)
      .catch(() => setPlan(null))
      .finally(() => setLoading(false))
  }, [finding, analysis.config_id])

  const copy = () => {
    navigator.clipboard?.writeText(plan.commands.join('\n')).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  return (
    <Card className="animate-fade-up p-4">
      <div className="flex items-center gap-2">
        <StatusPill status={finding.status} />
        <SeverityPill severity={finding.severity} />
        <span className="font-mono text-[10.5px] text-faint">
          {finding.rule_id} · v{finding.rule_version}
        </span>
      </div>

      <h3 className="mt-2 text-[15px] font-semibold leading-snug">{finding.title}</h3>
      <p className="mt-1.5 text-[12.5px] leading-relaxed text-muted">{finding.description}</p>

      {finding.impact ? (
        <div className="mt-3 rounded-lg border border-line-soft bg-raised/40 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
            Why this matters
          </div>
          <p className="mt-1 text-[12px] leading-relaxed text-muted">{finding.impact}</p>
        </div>
      ) : null}

      <div className="mt-3 grid grid-cols-2 gap-2 text-[12px]">
        <div className="rounded-lg border border-line-soft px-3 py-2">
          <div className="text-[10px] uppercase tracking-wider text-faint">Expected</div>
          <div className="mt-0.5 font-mono text-pass">
            {finding.operator.replace(/_/g, ' ')} {String(finding.expected)}
          </div>
        </div>
        <div className="rounded-lg border border-line-soft px-3 py-2">
          <div className="text-[10px] uppercase tracking-wider text-faint">Observed</div>
          <div
            className={`mt-0.5 font-mono ${finding.status === 'FAIL' ? 'text-critical' : 'text-text'}`}
          >
            {String(finding.actual)}
          </div>
        </div>
      </div>

      <div className="mt-3">
        <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
          Evidence
        </div>
        {finding.evidence?.length ? (
          <Code>
            {finding.evidence.map((e) => `${String(e.line_number).padStart(4)}  ${e.text}`).join('\n')}
          </Code>
        ) : (
          <p className="text-[12px] italic leading-relaxed text-faint">
            {finding.normalisation_rationale ?? 'No statement found.'}
          </p>
        )}
      </div>

      {finding.is_ai_assisted ? (
        <div className="mt-3 rounded-lg border border-accent/30 bg-accent/8 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.13em] text-accent">
            AI-assisted reading
          </div>
          <p className="mt-1 text-[12px] leading-relaxed text-muted">
            Interpreted by the semantic layer at {Math.round((finding.confidence ?? 0) * 100)}%
            confidence.{finding.normalisation_rationale ? ` ${finding.normalisation_rationale}` : ''}
            {finding.requires_review
              ? ' Pending administrator approval, so this control is reported as undetermined rather than as a pass or a failure.'
              : ''}
          </p>
        </div>
      ) : null}

      {Object.keys(finding.frameworks ?? {}).length ? (
        <div className="mt-3">
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
            Framework mapping
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(finding.frameworks).map(([fw, refs]) => (
              <span
                key={fw}
                className="rounded border border-line-soft bg-raised/50 px-2 py-1 text-[10.5px]"
              >
                <span className="font-semibold text-muted">{fw}</span>{' '}
                <span className="font-mono text-faint">{refs.join(', ')}</span>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {finding.status === 'FAIL' ? (
        <div className="mt-3">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">
              Remediation
            </span>
            {plan?.commands?.length ? (
              <button
                onClick={copy}
                className="text-[11px] text-accent hover:underline underline-offset-2"
              >
                {copied ? 'copied ✓' : 'copy'}
              </button>
            ) : null}
          </div>

          {loading ? (
            <div className="flex items-center gap-2 py-2 text-[12px] text-muted">
              <Spinner /> loading template…
            </div>
          ) : plan?.commands?.length ? (
            <>
              <Code>{plan.commands.join('\n')}</Code>
              {plan.note ? (
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-faint">{plan.note}</p>
              ) : null}
              {plan.version_basis ? (
                <p className="mt-1 text-[11px] leading-relaxed text-accent">{plan.version_basis}</p>
              ) : null}
              <p className="mt-1.5 text-[11px] leading-relaxed text-faint">{plan.warning}</p>
            </>
          ) : plan ? (
            <Banner tone="warn">
              {plan.guidance} No verified command sequence is published for this platform, so
              descriptive guidance is shown rather than commands to paste.
            </Banner>
          ) : null}
        </div>
      ) : null}
    </Card>
  )
}
