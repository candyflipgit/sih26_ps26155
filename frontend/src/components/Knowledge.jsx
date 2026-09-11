import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { Card, Empty, SectionTitle, Spinner, Stat } from './ui'

export default function Knowledge() {
  const [data, setData] = useState(null)
  const [events, setEvents] = useState(null)
  const [vendor, setVendor] = useState(null)
  const [query, setQuery] = useState('')

  useEffect(() => {
    api.knowledge().then((d) => {
      setData(d)
      setVendor((v) => v ?? d.packs[0]?.vendor)
    })
    api.trainingEvents().then(setEvents)
  }, [])

  const pack = data?.packs.find((p) => p.vendor === vendor)

  const rules = useMemo(() => {
    if (!pack) return []
    const needle = query.trim().toLowerCase()
    if (!needle) return pack.rules
    return pack.rules.filter(
      (r) =>
        (r.pattern ?? '').toLowerCase().includes(needle) ||
        r.parameter.toLowerCase().includes(needle) ||
        (r.description ?? '').toLowerCase().includes(needle),
    )
  }, [pack, query])

  if (!data) {
    return (
      <div className="flex items-center gap-2 py-10 text-sm text-muted">
        <Spinner /> Loading knowledge base…
      </div>
    )
  }

  const summary = data.summary
  const stats = events?.stats

  return (
    <div className="animate-fade-up">
      <header className="mb-4">
        <h1 className="text-[19px] font-semibold">Knowledge base</h1>
        <p className="mt-1 text-[13px] text-muted">
          Every mapping the platform knows, as data rather than code. Adding a vendor is a rule pack,
          not a release — which is what makes learned knowledge and shipped knowledge the same thing.
        </p>
      </header>

      <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Mappings" value={summary.total_rules} sub="across all vendors" />
        <Stat
          label="Learned"
          value={summary.total_learned}
          tone="text-pass"
          sub="approved by an administrator"
        />
        <Stat label="Controls" value={summary.controls} sub="mapped to 4 frameworks" />
        <Stat
          label="AI agreement"
          value={stats?.acceptance_rate === null || stats?.acceptance_rate === undefined ? '—' : `${stats.acceptance_rate}%`}
          sub={
            stats?.ai_assisted
              ? `${stats.ai_accepted} accepted, ${stats.ai_corrected} corrected`
              : 'no proposals reviewed yet'
          }
        />
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        {data.packs.map((p) => (
          <button
            key={p.vendor}
            onClick={() => setVendor(p.vendor)}
            className={`rounded-lg px-2.5 py-1.5 text-xs transition-colors ${
              vendor === p.vendor
                ? 'bg-accent/15 text-text ring-1 ring-inset ring-accent/30'
                : 'text-muted hover:bg-raised hover:text-text'
            }`}
          >
            {p.display_name}
            <span className="ml-1.5 tabular-nums text-faint">{p.rules.length}</span>
          </button>
        ))}
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search mappings…"
          className="ml-auto w-48 rounded-lg border border-line bg-ink/60 px-2.5 py-1.5 text-xs text-text outline-none placeholder:text-faint/70 focus:border-accent/50"
        />
      </div>

      {pack ? (
        <Card className="overflow-hidden">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line px-3.5 py-2.5 text-[11px] text-faint">
            <span>
              block style <span className="font-mono text-muted">{pack.block_style}</span>
            </span>
            <span>
              defaults <span className="font-mono text-muted">{pack.defaults.length}</span>
            </span>
            <span>
              learned{' '}
              <span className="font-mono text-pass">
                {pack.rules.filter((r) => r.origin === 'learned').length}
              </span>
            </span>
          </div>

          {rules.length === 0 ? (
            <Empty icon="○" title="No mappings match that search" />
          ) : (
            <ul className="divide-y divide-line-soft">
              {rules.map((rule) => (
                <li key={rule.id} className="px-3.5 py-2.5">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <code className="font-mono text-[11.5px] text-text">{rule.pattern}</code>
                    {rule.origin === 'learned' ? (
                      <span className="rounded bg-pass/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-pass">
                        learned
                      </span>
                    ) : null}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-baseline gap-2 text-[11px]">
                    <span className="text-faint">→</span>
                    <span className="font-mono text-accent">{rule.parameter}</span>
                    <span className="font-mono text-faint">via {rule.value_rule}</span>
                  </div>
                  {rule.description ? (
                    <p className="mt-1 text-[11.5px] leading-relaxed text-muted">{rule.description}</p>
                  ) : null}
                  {rule.approved_by ? (
                    <p className="mt-0.5 text-[10.5px] text-faint">
                      approved by {rule.approved_by}
                      {rule.approved_at ? ` · ${rule.approved_at.slice(0, 19).replace('T', ' ')}` : ''}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>
      ) : null}

      {events?.events?.length ? (
        <div className="mt-5">
          <SectionTitle hint="who approved what, and when">Training audit trail</SectionTitle>
          <Card className="divide-y divide-line-soft">
            {events.events.map((e) => (
              <div key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3.5 py-2 text-[11.5px]">
                <span className="font-mono text-[10.5px] text-faint">
                  {e.created_at.slice(0, 19).replace('T', ' ')}
                </span>
                <span className="text-muted">{e.approved_by}</span>
                <span className="font-mono text-text">{e.template}</span>
                <span className="text-faint">→</span>
                <span className="font-mono text-accent">{e.parameter}</span>
                {e.ai_parameter ? (
                  <span
                    className={`ml-auto rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${
                      e.accepted_ai_suggestion
                        ? 'bg-accent/15 text-accent'
                        : 'bg-medium/15 text-medium'
                    }`}
                  >
                    {e.accepted_ai_suggestion ? 'AI agreed' : 'AI corrected'}
                    {e.ai_confidence ? ` · ${Math.round(e.ai_confidence * 100)}%` : ''}
                  </span>
                ) : (
                  <span className="ml-auto text-[10px] text-faint">manual</span>
                )}
              </div>
            ))}
          </Card>
        </div>
      ) : null}
    </div>
  )
}
