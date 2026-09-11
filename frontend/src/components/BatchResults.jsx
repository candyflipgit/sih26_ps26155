import React, { useState } from 'react'
import { api } from '../api'
import { Banner, Button, Card, SectionTitle, Spinner, Stat } from './ui'

const scoreTone = (score) =>
  score >= 80 ? 'text-pass' : score >= 50 ? 'text-medium' : 'text-critical'

/**
 * Fleet view for a multi-file upload.
 *
 * A device with no decidable controls (an unrecognised vendor, before any
 * teaching) shows n/a rather than 0%, and is left out of the fleet average:
 * its 0 is an artefact of 0/0, and averaging it in would report an
 * undetermined device as a failing one.
 */
export default function BatchResults({ batch, onAnalysis, goTo, onError }) {
  const [downloading, setDownloading] = useState(false)
  const fleet = batch.fleet

  const open = async (configId) => {
    try {
      onAnalysis(await api.getAnalysis(configId))
      goTo('findings')
    } catch (err) {
      onError(err.message)
    }
  }

  const downloadAll = async () => {
    setDownloading(true)
    try {
      const blob = await api.batchReports(batch.results.map((r) => r.config_id))
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `compliance-reports-${batch.results.length}-devices.zip`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      onError(err.message)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="animate-fade-up">
      <SectionTitle hint={`${batch.analysed} analysed`}>Batch result</SectionTitle>
      <Card className="p-4">
        <div className="grid grid-cols-3 gap-2">
          <Stat
            label="Fleet average"
            value={fleet.devices_judged ? `${fleet.average_score}%` : 'n/a'}
            tone={fleet.devices_judged ? scoreTone(fleet.average_score) : 'text-unknown'}
            sub={`over ${fleet.devices_judged} judged device${fleet.devices_judged === 1 ? '' : 's'}`}
          />
          <Stat
            label="With critical"
            value={fleet.devices_with_critical}
            tone={fleet.devices_with_critical ? 'text-critical' : 'text-pass'}
            sub={`${fleet.critical_failures} critical finding${fleet.critical_failures === 1 ? '' : 's'}`}
          />
          <Stat
            label="Unknown vendor"
            value={fleet.unknown_vendors}
            tone={fleet.unknown_vendors ? 'text-medium' : 'text-muted'}
            sub={fleet.unknown_vendors ? 'waiting in Teach AI' : 'all vendors recognised'}
          />
        </div>

        <ul className="mt-3 divide-y divide-line-soft rounded-lg border border-line-soft">
          {batch.results.map((r) => {
            const judged = r.passed + r.failed > 0
            return (
              <li key={r.config_id}>
                <button
                  onClick={() => open(r.config_id)}
                  className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-raised"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12.5px] font-medium">
                      {r.hostname || r.filename}
                    </span>
                    <span className="block truncate text-[10.5px] text-faint">
                      {r.vendor_display}
                      {r.serial_number ? ` · ${r.serial_number}` : ''}
                    </span>
                  </span>
                  {r.critical_failures > 0 ? (
                    <span className="shrink-0 text-[10px] font-semibold text-critical">
                      {r.critical_failures} critical
                    </span>
                  ) : null}
                  {r.queue > 0 ? (
                    <span className="shrink-0 text-[10px] text-medium">{r.queue} to teach</span>
                  ) : null}
                  <span
                    className={`w-12 shrink-0 text-right text-[13px] font-semibold tabular-nums ${
                      judged ? scoreTone(r.score) : 'text-unknown'
                    }`}
                  >
                    {judged ? `${r.score}%` : 'n/a'}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>

        {batch.errors.length ? (
          <div className="mt-3">
            <Banner tone="warn">
              {batch.errors.length} file{batch.errors.length === 1 ? '' : 's'} skipped:{' '}
              {batch.errors.map((e) => `${e.filename} (${e.error})`).join(', ')}. The rest of the
              batch was unaffected.
            </Banner>
          </div>
        ) : null}

        <Button
          className="mt-3 w-full"
          onClick={downloadAll}
          disabled={downloading || batch.results.length === 0}
        >
          {downloading ? <Spinner /> : null} Download {batch.results.length} PDF reports (zip)
        </Button>
        <p className="mt-2 text-[11px] leading-relaxed text-faint">
          One report per device, as the problem statement specifies. Undetermined devices show n/a
          and are left out of the fleet average rather than counted as failing. Click any device
          for its findings.
        </p>
      </Card>
    </div>
  )
}
