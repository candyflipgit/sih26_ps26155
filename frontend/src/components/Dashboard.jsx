import React, { useEffect, useState } from 'react'
import { BarChart, Bar, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api'
import { Card, Empty, ScoreRing, SectionTitle, Spinner, Stat } from './ui'

const SEVERITY_FILL = {
  CRITICAL: 'var(--color-critical)',
  HIGH: 'var(--color-high)',
  MEDIUM: 'var(--color-medium)',
  LOW: 'var(--color-low)',
}

export default function Dashboard({ meta, onOpen, goTo }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api
      .listAnalyses()
      .then(setData)
      .finally(() => setLoading(false))
  }, [])

  const open = async (configId) => {
    const result = await api.getAnalysis(configId)
    onOpen(result)
    goTo('findings')
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-10 text-sm text-muted">
        <Spinner /> Loading fleet…
      </div>
    )
  }

  const fleet = data?.fleet ?? {}
  const devices = data?.devices ?? []

  if (devices.length === 0) {
    return (
      <div className="animate-fade-up">
        <header className="mb-4">
          <h1 className="text-[19px] font-semibold">Dashboard</h1>
        </header>
        <Card>
          <Empty
            icon="▤"
            title="No devices assessed yet"
            hint="Analyse a configuration and its posture will be tracked here across scans."
          />
        </Card>
      </div>
    )
  }

  const chartData = devices
    .slice()
    .sort((a, b) => a.score - b.score)
    .slice(0, 10)
    .map((d) => ({
      name: d.hostname || d.filename,
      score: d.score,
      fill:
        d.score >= 80
          ? 'var(--color-pass)'
          : d.score >= 50
            ? 'var(--color-medium)'
            : 'var(--color-critical)',
    }))

  return (
    <div className="animate-fade-up">
      <header className="mb-4">
        <h1 className="text-[19px] font-semibold">Fleet posture</h1>
        <p className="mt-1 text-[13px] text-muted">
          Every device assessed, judged against one vendor-neutral security baseline.
        </p>
      </header>

      <div className="mb-4 grid gap-4 lg:grid-cols-[minmax(0,300px)_minmax(0,1fr)]">
        <Card className="flex items-center gap-4 p-4">
          <ScoreRing score={fleet.average_score} size={98} label="fleet avg" />
          <div className="min-w-0 flex-1 space-y-2">
            <Stat label="Devices" value={fleet.devices} />
            <Stat
              label="Critical failures"
              value={fleet.critical_failures}
              tone={fleet.critical_failures > 0 ? 'text-critical' : 'text-pass'}
            />
          </div>
        </Card>

        <Card className="p-4">
          <SectionTitle hint="lowest scoring first">Compliance by device</SectionTitle>
          <ResponsiveContainer width="100%" height={Math.max(140, chartData.length * 34)}>
            <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 26, top: 2, bottom: 2 }}>
              <XAxis
                type="number" domain={[0, 100]} tick={{ fill: 'var(--color-faint)', fontSize: 10 }}
                axisLine={false} tickLine={false} unit="%"
              />
              <YAxis
                type="category" dataKey="name" width={120}
                tick={{ fill: 'var(--color-muted)', fontSize: 11 }}
                axisLine={false} tickLine={false}
              />
              <Tooltip
                cursor={{ fill: 'var(--color-raised)' }}
                contentStyle={{
                  background: 'var(--color-panel)',
                  border: '1px solid var(--color-line)',
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(v) => [`${v}%`, 'compliance']}
              />
              <Bar dataKey="score" radius={[0, 4, 4, 0]} barSize={16}>
                {chartData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <SectionTitle hint={`${devices.length} assessed`}>Devices</SectionTitle>
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead className="border-b border-line text-[10px] uppercase tracking-[0.12em] text-faint">
              <tr>
                {['Device', 'Vendor', 'Serial', 'Score', 'Fail', 'Critical', 'Assessed'].map((h) => (
                  <th key={h} className="px-3.5 py-2 font-semibold">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {devices.map((d) => (
                <tr
                  key={d.config_id}
                  onClick={() => open(d.config_id)}
                  className="cursor-pointer transition-colors hover:bg-raised"
                >
                  <td className="px-3.5 py-2.5">
                    <div className="font-medium">{d.hostname || d.filename}</div>
                    <div className="text-[10.5px] text-faint">{d.model || d.filename}</div>
                  </td>
                  <td className="px-3.5 py-2.5 text-muted">{d.vendor_display}</td>
                  <td className="px-3.5 py-2.5 font-mono text-[11px] text-faint">
                    {d.serial_number || '—'}
                  </td>
                  <td className="px-3.5 py-2.5">
                    <span
                      className={`font-semibold tabular-nums ${
                        d.score >= 80 ? 'text-pass' : d.score >= 50 ? 'text-medium' : 'text-critical'
                      }`}
                    >
                      {d.score}%
                    </span>
                  </td>
                  <td className="px-3.5 py-2.5 tabular-nums text-muted">{d.failed}</td>
                  <td className="px-3.5 py-2.5 tabular-nums">
                    {d.critical_failures > 0 ? (
                      <span className="font-semibold text-critical">{d.critical_failures}</span>
                    ) : (
                      <span className="text-faint">0</span>
                    )}
                  </td>
                  <td className="px-3.5 py-2.5 text-[11px] text-faint">
                    {d.created_at.slice(0, 16).replace('T', ' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {meta?.knowledge?.frameworks?.length ? (
        <div className="mt-5">
          <SectionTitle hint="one control catalogue, four mappings">Frameworks</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-2">
            {meta.knowledge.frameworks.map((f) => (
              <Card key={f.key} className="p-3">
                <div className="text-[12.5px] font-medium">{f.name}</div>
                <div className="text-[11px] text-faint">{f.publisher}</div>
                {f.note ? (
                  <p className="mt-1.5 text-[11px] leading-relaxed text-muted">{f.note}</p>
                ) : null}
              </Card>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}
