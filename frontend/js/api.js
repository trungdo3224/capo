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

async function _postJson(url, body) {
  const r = await _post(url, body)
  if (r.status === 204) return null
  return r.json()
}

async function _put(url, body) {
  const r = await fetch(BASE + url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }))
    throw new Error(err.detail ? JSON.stringify(err.detail) : r.statusText)
  }
  return r.json()
}

async function _delete(url) {
  const r = await fetch(BASE + url, { method: 'DELETE' })
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }))
    throw new Error(err.detail ? JSON.stringify(err.detail) : r.statusText)
  }
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

// ── Sessions ────────────────────────────────────────────────────────────────
export const fetchSessions         = ()               => _get('/api/sessions')
export const createSession         = (data)           => _postJson('/api/sessions', data)
export const getActiveSession      = ()               => _get('/api/sessions/active')
export const activateSession       = (name)           => _postJson(`/api/sessions/${encodeURIComponent(name)}/activate`, {})
export const getSession            = (name)           => _get(`/api/sessions/${encodeURIComponent(name)}`)
export const deleteSession         = (name)           => _delete(`/api/sessions/${encodeURIComponent(name)}`)
export const fetchSessionCommands  = (name, params)   => _get(`/api/sessions/${encodeURIComponent(name)}/commands${params ? '?' + params : ''}`)
export const logManualCommand      = (name, data)     => _postJson(`/api/sessions/${encodeURIComponent(name)}/commands`, data)
export const toggleCommandKey      = (id, isKey)      => _put(`/api/sessions/commands/${id}/key`, { is_key: isKey })
export const fetchSessionFindings  = (name)           => _get(`/api/sessions/${encodeURIComponent(name)}/findings`)
export const createFinding         = (name, data)     => _postJson(`/api/sessions/${encodeURIComponent(name)}/findings`, data)
export const deleteFinding         = (id)             => _delete(`/api/sessions/findings/${id}`)

// ── Knowledge Graph ─────────────────────────────────────────────────────────
export const fetchGraph         = ()              => _get('/api/graph')
export const createGraphNode    = (data)          => _postJson('/api/graph/nodes', data)
export const updateGraphNode    = (id, data)      => _put(`/api/graph/nodes/${id}`, data)
export const deleteGraphNode    = (id)            => _delete(`/api/graph/nodes/${id}`)
export const createGraphEdge    = (data)          => _postJson('/api/graph/edges', data)
export const updateGraphEdge    = (id, data)      => _put(`/api/graph/edges/${id}`, data)
export const deleteGraphEdge    = (id)            => _delete(`/api/graph/edges/${id}`)
export const saveGraphPositions = (positions)     => _post('/api/graph/positions', positions)
export const clearGraph         = ()              => _post('/api/graph/clear', {})
