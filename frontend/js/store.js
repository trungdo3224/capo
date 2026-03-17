/**
 * store.js — Shared reactive state for C.A.P.O Studio
 * Imported by all components that need cross-component data.
 */
import { ref, computed } from 'vue'

// ── Active view ──────────────────────────────────────────────────────────────
export const currentView = ref('cheatsheets')

// ── Suggestions (kept here so Sidebar badge stays updated from any view) ─────
export const suggestions = ref({
  target: null,
  port_triggers: [],
  contextual: [],
  rule_suggestions: [],
})

export const suggestionCount = computed(() => {
  const s = suggestions.value
  return (s.port_triggers?.length || 0) + (s.contextual?.length || 0) + (s.rule_suggestions?.length || 0)
})

// ── Toast ────────────────────────────────────────────────────────────────────
let _toastInstance = null

export function showToast(msg, isSuccess = true) {
  const toastEl  = document.getElementById('statusToast')
  const toastMsg = document.getElementById('toastMessage')
  if (!toastEl || !toastMsg) return
  toastEl.classList.remove('bg-success', 'bg-danger')
  toastEl.classList.add(isSuccess ? 'bg-success' : 'bg-danger')
  toastMsg.innerHTML = isSuccess
    ? `<i class="fa-solid fa-check-circle me-2"></i> ${msg}`
    : `<i class="fa-solid fa-triangle-exclamation me-2"></i> ${msg}`
  if (_toastInstance) _toastInstance.hide()
  _toastInstance = new bootstrap.Toast(toastEl, { delay: 3000 })
  _toastInstance.show()
}

// ── Utilities ────────────────────────────────────────────────────────────────
export function formatTime(iso) {
  if (!iso) return ''
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}

export function copyCmd(cmd) {
  navigator.clipboard?.writeText(cmd)
    .then(() => showToast('Copied to clipboard'))
    .catch(() => showToast('Copy failed', false))
}

export function getIconForFile(filename) {
  const n = filename.toLowerCase()
  if (n.includes('windows') || n.includes('ad_') || n.includes('active_dir')) return 'fa-brands fa-windows'
  if (n.includes('linux'))   return 'fa-brands fa-linux'
  if (n.includes('web') || n.includes('sql'))   return 'fa-solid fa-globe'
  if (n.includes('network') || n.includes('port')) return 'fa-solid fa-network-wired'
  if (n.includes('crack') || n.includes('pass'))   return 'fa-solid fa-key'
  return 'fa-solid fa-file-code'
}
