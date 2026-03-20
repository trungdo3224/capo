import { defineComponent, ref, computed, onMounted, onActivated } from 'vue'
import { showToast, copyCmd } from '../store.js'
import {
  fetchSessions, createSession, activateSession, deleteSession, getSession,
  fetchSessionCommands, logManualCommand, toggleCommandKey,
  fetchSessionFindings, createFinding, deleteFinding,
} from '../api.js'

const SEV_COLORS = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#20c997', info: '#6c757d' }
const CAT_ICONS  = { general: 'fa-circle-info', foothold: 'fa-door-open', privesc: 'fa-arrow-up',
                     credential: 'fa-key', misconfiguration: 'fa-triangle-exclamation', vulnerability: 'fa-bug' }

export default defineComponent({
  name: 'SessionsView',
  setup() {
    const sessions   = ref([])
    const loading    = ref(false)
    const view       = ref('list')    // list | detail | create
    const detail     = ref(null)
    const commands   = ref([])
    const findings   = ref([])
    const activeTab  = ref('commands')
    const keyFilter  = ref(false)
    const toolFilter = ref('')

    // Create form
    const form = ref({ name: '', target_ip: '', domain: '', campaign: '' })

    // Manual log form
    const logForm = ref({ command: '', tool: 'manual' })

    // Finding form
    const findingForm = ref({ title: '', description: '', command_id: null, category: 'general', severity: 'info' })
    const showFindingForm = ref(false)

    async function loadSessions() {
      loading.value = true
      try { sessions.value = await fetchSessions() }
      catch { showToast('Failed to load sessions', false) }
      loading.value = false
    }

    async function onCreateSession() {
      if (!form.value.name || !form.value.target_ip) return showToast('Name and target IP required', false)
      try {
        await createSession(form.value)
        showToast(`Session "${form.value.name}" created`)
        form.value = { name: '', target_ip: '', domain: '', campaign: '' }
        view.value = 'list'
        await loadSessions()
      } catch (e) { showToast(e.message, false) }
    }

    async function onActivate(name) {
      try {
        await activateSession(name)
        showToast(`Switched to "${name}"`)
        await loadSessions()
        if (detail.value && detail.value.name === name) await openDetail(name)
      } catch (e) { showToast(e.message, false) }
    }

    async function onDelete(name) {
      if (!confirm(`Delete session "${name}" and all its data?`)) return
      try {
        await deleteSession(name)
        showToast(`Session "${name}" deleted`)
        if (detail.value && detail.value.name === name) { detail.value = null; view.value = 'list' }
        await loadSessions()
      } catch (e) { showToast(e.message, false) }
    }

    async function openDetail(name) {
      try {
        detail.value = await getSession(name)
        await loadCommands(name)
        await loadFindings(name)
        view.value = 'detail'
      } catch (e) { showToast(e.message, false) }
    }

    async function loadCommands(name) {
      const params = new URLSearchParams()
      if (keyFilter.value) params.set('key_only', 'true')
      if (toolFilter.value) params.set('tool', toolFilter.value)
      try { commands.value = await fetchSessionCommands(name || detail.value.name, params.toString()) }
      catch { commands.value = [] }
    }

    async function loadFindings(name) {
      try { findings.value = await fetchSessionFindings(name || detail.value.name) }
      catch { findings.value = [] }
    }

    async function onToggleKey(cmd) {
      try {
        await toggleCommandKey(cmd.id, cmd.is_key ? false : true)
        cmd.is_key = cmd.is_key ? 0 : 1
      } catch (e) { showToast(e.message, false) }
    }

    async function onLogCommand() {
      if (!logForm.value.command) return
      try {
        await logManualCommand(detail.value.name, logForm.value)
        logForm.value = { command: '', tool: 'manual' }
        showToast('Command logged')
        await loadCommands()
      } catch (e) { showToast(e.message, false) }
    }

    async function onCreateFinding() {
      if (!findingForm.value.title) return
      try {
        await createFinding(detail.value.name, findingForm.value)
        findingForm.value = { title: '', description: '', command_id: null, category: 'general', severity: 'info' }
        showFindingForm.value = false
        showToast('Finding created')
        await loadFindings()
      } catch (e) { showToast(e.message, false) }
    }

    async function onDeleteFinding(id) {
      if (!confirm('Delete this finding?')) return
      try {
        await deleteFinding(id)
        showToast('Finding deleted')
        await loadFindings()
      } catch (e) { showToast(e.message, false) }
    }

    function applyFilters() { loadCommands() }

    const activeSession = computed(() => sessions.value.find(s =>
      s.total_commands !== undefined && sessions.value.length > 0
    ))

    onMounted(loadSessions)
    onActivated(loadSessions)

    return {
      sessions, loading, view, detail, commands, findings, activeTab,
      form, logForm, findingForm, showFindingForm,
      keyFilter, toolFilter, SEV_COLORS, CAT_ICONS,
      onCreateSession, onActivate, onDelete, openDetail,
      loadCommands, loadFindings, onToggleKey, onLogCommand,
      onCreateFinding, onDeleteFinding, applyFilters, copyCmd,
    }
  },
  template: `
    <div class="p-4 p-md-5">

      <!-- ═══ LIST VIEW ═══ -->
      <template v-if="view === 'list'">
        <div class="d-flex justify-content-between align-items-center mb-4">
          <h2 class="fw-bold text-white mb-0">
            <i class="fa-solid fa-folder-open" style="color:var(--accent)"></i> Sessions
          </h2>
          <button class="btn btn-sm btn-outline-success" @click="view = 'create'">
            <i class="fa-solid fa-plus me-1"></i> New Session
          </button>
        </div>

        <div v-if="loading && !sessions.length" class="text-center py-5">
          <div class="spinner-border text-danger" role="status"></div>
        </div>

        <div v-else-if="!sessions.length" class="text-muted text-center py-5">
          No sessions yet. Click <strong>New Session</strong> to get started.
        </div>

        <div v-else class="row g-3">
          <div v-for="s in sessions" :key="s.id" class="col-md-6 col-lg-4">
            <div class="capo-card h-100" style="cursor:pointer" @click="openDetail(s.name)">
              <div class="capo-card-header border-bottom d-flex justify-content-between align-items-center"
                   :style="{ borderColor: s.status === 'active' ? 'var(--accent)' : 'var(--border)' }">
                <h5 class="mb-0 fw-bold text-white capo-font">{{ s.name }}</h5>
                <span class="badge" :class="s.status === 'active' ? 'bg-success' : s.status === 'completed' ? 'bg-secondary' : 'bg-warning'">
                  {{ s.status }}
                </span>
              </div>
              <div class="card-body p-3">
                <div class="text-muted small mb-2">
                  <i class="fa-solid fa-crosshairs me-1"></i> {{ s.target_ip }}
                  <span v-if="s.domain" class="ms-2"><i class="fa-solid fa-globe me-1"></i> {{ s.domain }}</span>
                </div>
                <div class="d-flex gap-3 small">
                  <span><i class="fa-solid fa-terminal me-1"></i> {{ s.total_commands || 0 }} cmds</span>
                  <span><i class="fa-solid fa-star me-1 text-warning"></i> {{ s.key_steps || 0 }} key</span>
                  <span><i class="fa-solid fa-flag me-1 text-danger"></i> {{ s.findings_count || 0 }} findings</span>
                </div>
                <div class="mt-2 d-flex gap-2" @click.stop>
                  <button class="btn btn-sm btn-outline-success" @click="onActivate(s.name)" title="Activate">
                    <i class="fa-solid fa-play"></i>
                  </button>
                  <button class="btn btn-sm btn-outline-danger" @click="onDelete(s.name)" title="Delete">
                    <i class="fa-solid fa-trash"></i>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </template>

      <!-- ═══ CREATE VIEW ═══ -->
      <template v-if="view === 'create'">
        <div class="d-flex align-items-center mb-4">
          <button class="btn btn-sm btn-outline-secondary me-3" @click="view = 'list'">
            <i class="fa-solid fa-arrow-left"></i>
          </button>
          <h2 class="fw-bold text-white mb-0">New Session</h2>
        </div>

        <div class="capo-card" style="max-width:500px">
          <div class="card-body p-4">
            <div class="mb-3">
              <label class="form-label text-muted small">Session Name</label>
              <input v-model="form.name" class="form-control bg-dark text-white border-secondary"
                     placeholder="e.g. Forest" @keyup.enter="onCreateSession">
            </div>
            <div class="mb-3">
              <label class="form-label text-muted small">Target IP</label>
              <input v-model="form.target_ip" class="form-control bg-dark text-white border-secondary"
                     placeholder="e.g. 10.129.95.210" @keyup.enter="onCreateSession">
            </div>
            <div class="mb-3">
              <label class="form-label text-muted small">Domain (optional)</label>
              <input v-model="form.domain" class="form-control bg-dark text-white border-secondary"
                     placeholder="e.g. htb.local" @keyup.enter="onCreateSession">
            </div>
            <div class="mb-3">
              <label class="form-label text-muted small">Campaign (optional)</label>
              <input v-model="form.campaign" class="form-control bg-dark text-white border-secondary"
                     placeholder="e.g. HTB" @keyup.enter="onCreateSession">
            </div>
            <button class="btn btn-success w-100" @click="onCreateSession">
              <i class="fa-solid fa-plus me-1"></i> Create & Activate
            </button>
          </div>
        </div>
      </template>

      <!-- ═══ DETAIL VIEW ═══ -->
      <template v-if="view === 'detail' && detail">
        <div class="d-flex align-items-center mb-4">
          <button class="btn btn-sm btn-outline-secondary me-3" @click="view = 'list'; loadSessions()">
            <i class="fa-solid fa-arrow-left"></i>
          </button>
          <h2 class="fw-bold text-white mb-0 capo-font">{{ detail.name }}</h2>
          <span class="badge ms-2" :class="detail.status === 'active' ? 'bg-success' : 'bg-secondary'">
            {{ detail.status }}
          </span>
          <button class="btn btn-sm btn-outline-success ms-auto" @click="onActivate(detail.name)">
            <i class="fa-solid fa-play me-1"></i> Activate
          </button>
        </div>

        <!-- Summary cards -->
        <div class="row g-3 mb-4">
          <div class="col-6 col-md-3">
            <div class="capo-card text-center p-3">
              <div class="text-muted small">Target</div>
              <div class="text-white fw-bold capo-font">{{ detail.target_ip }}</div>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="capo-card text-center p-3">
              <div class="text-muted small">Commands</div>
              <div class="text-warning fw-bold fs-4">{{ detail.total_commands || 0 }}</div>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="capo-card text-center p-3">
              <div class="text-muted small">Key Steps</div>
              <div class="text-warning fw-bold fs-4">{{ detail.key_steps || 0 }}</div>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="capo-card text-center p-3">
              <div class="text-muted small">Findings</div>
              <div class="text-danger fw-bold fs-4">{{ detail.findings_count || 0 }}</div>
            </div>
          </div>
        </div>

        <!-- Tabs -->
        <ul class="nav nav-tabs mb-3" style="border-color:var(--border)">
          <li class="nav-item">
            <a class="nav-link" :class="{ active: activeTab === 'commands' }"
               style="cursor:pointer;color:var(--text-muted)" @click="activeTab = 'commands'">
              <i class="fa-solid fa-terminal me-1"></i> Commands
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" :class="{ active: activeTab === 'findings' }"
               style="cursor:pointer;color:var(--text-muted)" @click="activeTab = 'findings'">
              <i class="fa-solid fa-flag me-1"></i> Findings
            </a>
          </li>
        </ul>

        <!-- Commands Tab -->
        <div v-if="activeTab === 'commands'">
          <div class="d-flex gap-2 mb-3 align-items-center">
            <div class="form-check form-check-inline">
              <input class="form-check-input" type="checkbox" v-model="keyFilter" @change="applyFilters" id="keyChk">
              <label class="form-check-label text-muted small" for="keyChk">Key only</label>
            </div>
            <input v-model="toolFilter" class="form-control form-control-sm bg-dark text-white border-secondary"
                   style="max-width:150px" placeholder="Filter by tool" @input="applyFilters">
          </div>

          <div class="table-responsive">
            <table class="table table-sm table-dark table-hover align-middle" style="font-size:0.85rem">
              <thead>
                <tr class="text-muted">
                  <th>#</th><th>Tool</th><th>Command</th><th>Dur</th><th>Key</th><th>Src</th><th>Time</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="c in commands" :key="c.id">
                  <td class="text-muted">{{ c.id }}</td>
                  <td><span class="badge bg-secondary">{{ c.tool }}</span></td>
                  <td class="capo-font" style="cursor:pointer;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                      :title="c.command" @click="copyCmd(c.command)">{{ c.command }}</td>
                  <td class="text-warning">{{ c.duration ? c.duration.toFixed(1) + 's' : '' }}</td>
                  <td style="cursor:pointer" @click="onToggleKey(c)">
                    <i class="fa-solid fa-star" :style="{ color: c.is_key ? '#ffc107' : '#444' }"></i>
                  </td>
                  <td class="text-muted">{{ c.source }}</td>
                  <td class="text-muted">{{ (c.created_at || '').slice(0, 19) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="!commands.length" class="text-muted text-center py-3">No commands recorded yet.</div>

          <!-- Manual log -->
          <div class="mt-3 d-flex gap-2">
            <input v-model="logForm.command" class="form-control form-control-sm bg-dark text-white border-secondary"
                   placeholder="Log a manual command..." @keyup.enter="onLogCommand">
            <input v-model="logForm.tool" class="form-control form-control-sm bg-dark text-white border-secondary"
                   style="max-width:120px" placeholder="tool">
            <button class="btn btn-sm btn-outline-info" @click="onLogCommand">
              <i class="fa-solid fa-plus"></i>
            </button>
          </div>
        </div>

        <!-- Findings Tab -->
        <div v-if="activeTab === 'findings'">
          <button class="btn btn-sm btn-outline-danger mb-3" @click="showFindingForm = !showFindingForm">
            <i class="fa-solid fa-plus me-1"></i> Add Finding
          </button>

          <div v-if="showFindingForm" class="capo-card mb-3" style="max-width:500px">
            <div class="card-body p-3">
              <input v-model="findingForm.title" class="form-control form-control-sm bg-dark text-white border-secondary mb-2"
                     placeholder="Finding title">
              <textarea v-model="findingForm.description" class="form-control form-control-sm bg-dark text-white border-secondary mb-2"
                        rows="2" placeholder="Description (optional)"></textarea>
              <div class="d-flex gap-2 mb-2">
                <select v-model="findingForm.category" class="form-select form-select-sm bg-dark text-white border-secondary">
                  <option value="general">General</option>
                  <option value="foothold">Foothold</option>
                  <option value="privesc">Privesc</option>
                  <option value="credential">Credential</option>
                  <option value="misconfiguration">Misconfiguration</option>
                  <option value="vulnerability">Vulnerability</option>
                </select>
                <select v-model="findingForm.severity" class="form-select form-select-sm bg-dark text-white border-secondary">
                  <option value="info">Info</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <input v-model.number="findingForm.command_id" type="number"
                     class="form-control form-control-sm bg-dark text-white border-secondary mb-2"
                     placeholder="Command ID (optional)">
              <button class="btn btn-sm btn-danger" @click="onCreateFinding">Create Finding</button>
            </div>
          </div>

          <div v-for="f in findings" :key="f.id" class="capo-card mb-2">
            <div class="card-body p-3 d-flex justify-content-between align-items-start">
              <div>
                <div class="d-flex align-items-center gap-2 mb-1">
                  <i class="fa-solid" :class="CAT_ICONS[f.category] || 'fa-circle-info'" style="color:var(--accent)"></i>
                  <strong class="text-white">{{ f.title }}</strong>
                  <span class="badge" :style="{ backgroundColor: SEV_COLORS[f.severity] }">{{ f.severity }}</span>
                  <span class="badge bg-secondary">{{ f.category }}</span>
                </div>
                <div v-if="f.description" class="text-muted small">{{ f.description }}</div>
                <div class="text-muted small mt-1">
                  <span v-if="f.command_id">Cmd #{{ f.command_id }} · </span>
                  {{ (f.created_at || '').slice(0, 19) }}
                </div>
              </div>
              <button class="btn btn-sm btn-outline-danger" @click="onDeleteFinding(f.id)">
                <i class="fa-solid fa-trash"></i>
              </button>
            </div>
          </div>
          <div v-if="!findings.length" class="text-muted text-center py-3">No findings yet.</div>
        </div>
      </template>

    </div>
  `,
})
