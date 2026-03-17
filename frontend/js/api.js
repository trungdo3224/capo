/**
 * api.js — All fetch() wrappers for C.A.P.O Studio backend.
 */

const BASE = ''  // same-origin

async function _get(url) {
  const r = await fetch(BASE + url)
  if (!r.ok) throw new Error(`${r.status} ${url}`)
  return r.json()
}

async function _post(url, body) {
  const r = await fetch(BASE + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }))
    throw new Error(err.detail ? JSON.stringify(err.detail) : r.statusText)
  }
  return r
}

// ── Cheatsheets ──────────────────────────────────────────────────────────────
export const fetchCheatsheets    = ()           => _get('/api/cheatsheets')
export const getCheatsheet       = (filename)   => _get(`/api/cheatsheets/${filename}`)
export const saveCheatsheet      = (filename, data) => _post(`/api/cheatsheets/${filename}`, data)

// ── Methodologies ────────────────────────────────────────────────────────────
export const fetchMethodologies  = ()           => _get('/api/methodologies')
export const getMethodology      = (filename)   => _get(`/api/methodologies/${filename}`)
export const saveMethodology     = (filename, data) => _post(`/api/methodologies/${filename}`, data)

// ── Engagement ───────────────────────────────────────────────────────────────
export const fetchEngagement     = ()           => _get('/api/engagement/status')

// ── Suggestions + Triggers ───────────────────────────────────────────────────
export const fetchSuggestions    = ()           => _get('/api/suggestions')
export const fetchCustomTriggers = ()           => _get('/api/triggers/custom')
export const saveCustomTriggers  = (data)       => _post('/api/triggers/custom', data)
