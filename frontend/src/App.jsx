import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Spinner } from './components/ui'
import Dashboard from './components/Dashboard'
import Analyze from './components/Analyze'
import Findings from './components/Findings'
import Teach from './components/Teach'
import Knowledge from './components/Knowledge'

const NAV = [
  { id: 'dashboard', label: 'Dashboard', glyph: '▤' },
  { id: 'analyze', label: 'Analyse', glyph: '▲' },
  { id: 'findings', label: 'Findings', glyph: '◈' },
  { id: 'teach', label: 'Teach AI', glyph: '✦' },
  { id: 'knowledge', label: 'Knowledge', glyph: '❑' },
]

export default function App() {
  const [tab, setTab] = useState('analyze')
  const [meta, setMeta] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState(null)
  const [booting, setBooting] = useState(true)

  const refreshMeta = useCallback(async () => {
    try {
      setMeta(await api.meta())
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    refreshMeta().finally(() => setBooting(false))
  }, [refreshMeta])

  // The teach queue lives on the current analysis, so approving a mapping has
  // to refresh both the analysis and the knowledge counts.
  const onAnalysis = useCallback((result) => {
    setAnalysis(result)
    setError(null)
  }, [])

  const queueSize = analysis?.normalized?.unknown_commands?.length ?? 0

  if (booting) {
    return (
      <div className="flex h-full items-center justify-center gap-3 text-sm text-muted">
        <Spinner /> Loading compliance engine…
      </div>
    )
  }

  return (
    <div className="flex h-full">
      <aside className="flex w-[212px] shrink-0 flex-col border-r border-line bg-surface">
        <div className="border-b border-line px-4 py-4">
          <div className="flex items-center gap-2">
            <div className="grid h-7 w-7 place-items-center rounded-md bg-accent/15 text-[13px] font-bold text-accent ring-1 ring-inset ring-accent/30">
              N
            </div>
            <div className="leading-tight">
              <div className="text-[13px] font-semibold">NetBaseline AI</div>
              <div className="text-[10px] text-faint">Compliance Auditor</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-2">
          {NAV.map((item) => {
            const active = tab === item.id
            const badge = item.id === 'teach' && queueSize > 0 ? queueSize : null
            return (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`mb-0.5 flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-colors ${
                  active
                    ? 'bg-accent/12 text-text ring-1 ring-inset ring-accent/25'
                    : 'text-muted hover:bg-raised hover:text-text'
                }`}
              >
                <span className={`text-[11px] ${active ? 'text-accent' : 'text-faint'}`}>
                  {item.glyph}
                </span>
                <span className="flex-1 text-left">{item.label}</span>
                {badge ? (
                  <span className="rounded bg-medium/20 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-medium">
                    {badge}
                  </span>
                ) : null}
              </button>
            )
          })}
        </nav>

        <div className="border-t border-line px-4 py-3 text-[11px] leading-relaxed">
          <StatusLine
            ok={meta?.knowledge?.llm_available}
            label={meta?.knowledge?.llm_available ? 'Inference online' : 'Retrieval-only mode'}
          />
          <div className="mt-1 text-faint">
            {meta?.knowledge?.total_rules ?? 0} mappings ·{' '}
            {meta?.knowledge?.total_learned ?? 0} learned
          </div>
          <div className="text-faint">{meta?.knowledge?.controls ?? 0} controls · 4 frameworks</div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1180px] px-7 py-6">
          {error ? (
            <div className="mb-4">
              <Banner tone="danger">{error}</Banner>
            </div>
          ) : null}

          {tab === 'dashboard' && <Dashboard meta={meta} onOpen={onAnalysis} goTo={setTab} />}
          {tab === 'analyze' && (
            <Analyze meta={meta} analysis={analysis} onAnalysis={onAnalysis} goTo={setTab} onError={setError} />
          )}
          {tab === 'findings' && <Findings analysis={analysis} goTo={setTab} />}
          {tab === 'teach' && (
            <Teach
              meta={meta}
              analysis={analysis}
              onAnalysis={onAnalysis}
              refreshMeta={refreshMeta}
              onError={setError}
            />
          )}
          {tab === 'knowledge' && <Knowledge />}
        </div>
      </main>
    </div>
  )
}

function StatusLine({ ok, label }) {
  return (
    <div className="flex items-center gap-1.5">
      <span
        className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-pass' : 'bg-medium'}`}
        aria-hidden="true"
      />
      <span className="text-muted">{label}</span>
    </div>
  )
}
