const BASE = '/api/v1'

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    headers: options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!response.ok) {
    // FastAPI puts the useful message in `detail`; surface it rather than a
    // bare status code, since most failures here are user-correctable.
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json()
      if (body.detail) message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* response had no JSON body */
    }
    throw new Error(message)
  }
  return response.json()
}

export const api = {
  health: () => request('/health'),
  meta: () => request('/meta'),
  samples: () => request('/samples'),

  analyzeSample: (name, framework = 'ALL') =>
    request(`/samples/${encodeURIComponent(name)}/analyze?framework=${framework}`, { method: 'POST' }),

  analyzeText: (text, filename, framework = 'ALL') =>
    request('/configs/analyze', {
      method: 'POST',
      body: JSON.stringify({ text, filename, framework }),
    }),

  upload: (file, framework = 'ALL') => {
    const form = new FormData()
    form.append('file', file)
    return request(`/configs/upload?framework=${framework}`, { method: 'POST', body: form })
  },

  uploadBatch: (files, framework = 'ALL') => {
    const form = new FormData()
    for (const file of files) form.append('files', file)
    return request(`/configs/upload-batch?framework=${framework}`, { method: 'POST', body: form })
  },

  // Returns a Blob (a zip of one PDF per device), not JSON.
  batchReports: async (configIds) => {
    const response = await fetch(`${BASE}/batch/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config_ids: configIds }),
    })
    if (!response.ok) throw new Error(`Report bundle failed (${response.status})`)
    return response.blob()
  },

  listAnalyses: () => request('/analyses'),
  getAnalysis: (id) => request(`/analyses/${id}`),
  rescan: (id, framework = 'ALL') =>
    request(`/analyses/${id}/rescan?framework=${framework}`, { method: 'POST' }),

  remediation: (configId, ruleId) => request(`/analyses/${configId}/remediation/${ruleId}`),

  teach: (payload) =>
    request('/training/approve', { method: 'POST', body: JSON.stringify(payload) }),
  trainingEvents: () => request('/training/events'),

  knowledge: () => request('/knowledge'),

  generateReport: (id) => request(`/reports/${id}`, { method: 'POST' }),
  reportUrl: (id) => `${BASE}/reports/${id}/download`,
}
