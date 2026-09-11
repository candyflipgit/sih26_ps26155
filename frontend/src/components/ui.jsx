import React from 'react'

export const SEVERITY_TONE = {
  CRITICAL: { text: 'text-critical', bg: 'bg-critical/12', ring: 'ring-critical/35', dot: 'bg-critical' },
  HIGH: { text: 'text-high', bg: 'bg-high/12', ring: 'ring-high/35', dot: 'bg-high' },
  MEDIUM: { text: 'text-medium', bg: 'bg-medium/12', ring: 'ring-medium/35', dot: 'bg-medium' },
  LOW: { text: 'text-low', bg: 'bg-low/12', ring: 'ring-low/35', dot: 'bg-low' },
}

export const STATUS_TONE = {
  PASS: { text: 'text-pass', bg: 'bg-pass/12', ring: 'ring-pass/35' },
  FAIL: { text: 'text-critical', bg: 'bg-critical/12', ring: 'ring-critical/35' },
  UNKNOWN: { text: 'text-unknown', bg: 'bg-unknown/12', ring: 'ring-unknown/30' },
  NOT_APPLICABLE: { text: 'text-faint', bg: 'bg-faint/10', ring: 'ring-faint/25' },
}

export function Card({ children, className = '', ...rest }) {
  return (
    <div
      className={`rounded-xl border border-line bg-panel/70 backdrop-blur-[2px] ${className}`}
      {...rest}
    >
      {children}
    </div>
  )
}

export function SectionTitle({ children, hint }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-4">
      <h2 className="text-[13px] font-semibold uppercase tracking-[0.14em] text-muted">{children}</h2>
      {hint ? <span className="text-xs text-faint">{hint}</span> : null}
    </div>
  )
}

export function Pill({ tone, children, className = '' }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ring-1 ring-inset ${tone.bg} ${tone.text} ${tone.ring} ${className}`}
    >
      {children}
    </span>
  )
}

export function SeverityPill({ severity }) {
  const tone = SEVERITY_TONE[severity] ?? STATUS_TONE.UNKNOWN
  return <Pill tone={tone}>{severity}</Pill>
}

export function StatusPill({ status }) {
  const tone = STATUS_TONE[status] ?? STATUS_TONE.UNKNOWN
  return <Pill tone={tone}>{status === 'NOT_APPLICABLE' ? 'N/A' : status}</Pill>
}

export function Button({ children, variant = 'primary', className = '', ...rest }) {
  const variants = {
    primary:
      'bg-accent text-ink hover:bg-[#6aabff] disabled:bg-accent/40 disabled:text-ink/50 font-semibold',
    ghost:
      'bg-raised text-text hover:bg-line border border-line disabled:opacity-45',
    quiet:
      'bg-transparent text-muted hover:text-text hover:bg-raised border border-transparent',
    danger:
      'bg-critical/15 text-critical border border-critical/35 hover:bg-critical/25',
  }
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-[13px] transition-colors disabled:cursor-not-allowed ${variants[variant]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  )
}

export function Stat({ label, value, sub, tone = 'text-text', className = '' }) {
  return (
    <div className={`rounded-lg border border-line-soft bg-raised/50 px-3.5 py-3 ${className}`}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.13em] text-faint">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums leading-none ${tone}`}>{value}</div>
      {sub ? <div className="mt-1.5 text-[11px] leading-snug text-muted">{sub}</div> : null}
    </div>
  )
}

export function ScoreRing({ score, size = 120, stroke = 9, label = 'compliance' }) {
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score ?? 0))
  const tone = clamped >= 80 ? 'var(--color-pass)' : clamped >= 50 ? 'var(--color-medium)' : 'var(--color-critical)'

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="var(--color-line)" strokeWidth={stroke}
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={tone} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - (clamped / 100) * circumference}
          style={{ transition: 'stroke-dashoffset 700ms cubic-bezier(0.2,0.7,0.3,1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[26px] font-semibold tabular-nums leading-none">{clamped.toFixed(0)}%</span>
        <span className="mt-1 text-[9px] font-semibold uppercase tracking-[0.14em] text-faint">{label}</span>
      </div>
    </div>
  )
}

export function ConfidenceBar({ value, className = '' }) {
  const pct = Math.round((value ?? 0) * 100)
  const tone = pct >= 85 ? 'bg-pass' : pct >= 60 ? 'bg-medium' : 'bg-high'
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-line">
        <div className={`h-full rounded-full ${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-9 text-right text-[11px] tabular-nums text-muted">{pct}%</span>
    </div>
  )
}

export function Code({ children, className = '' }) {
  return (
    <code
      className={`block overflow-x-auto whitespace-pre rounded-md border border-line-soft bg-ink/70 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-text ${className}`}
    >
      {children}
    </code>
  )
}

export function Spinner({ className = '' }) {
  return (
    <span
      className={`inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-line border-t-accent ${className}`}
    />
  )
}

export function Empty({ icon = '○', title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-3 text-2xl text-faint">{icon}</div>
      <div className="text-sm font-medium text-muted">{title}</div>
      {hint ? <div className="mt-1.5 max-w-sm text-xs leading-relaxed text-faint">{hint}</div> : null}
    </div>
  )
}

export function Banner({ tone = 'info', children }) {
  const tones = {
    info: 'border-accent/30 bg-accent/8 text-text',
    warn: 'border-medium/35 bg-medium/8 text-text',
    danger: 'border-critical/35 bg-critical/8 text-text',
    good: 'border-pass/30 bg-pass/8 text-text',
  }
  return (
    <div className={`rounded-lg border px-3.5 py-2.5 text-[12.5px] leading-relaxed ${tones[tone]}`}>
      {children}
    </div>
  )
}
