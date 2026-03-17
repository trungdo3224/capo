import { defineComponent, ref, onMounted, onActivated, onDeactivated } from 'vue'
import { showToast, copyCmd, suggestions } from '../store.js'
import { fetchSuggestions, fetchCustomTriggers, saveCustomTriggers } from '../api.js'
import CommandLine from '../components/CommandLine.js'

export default defineComponent({
  name: 'SuggestionsView',
  components: { CommandLine },
  setup() {
    const customTriggers  = ref({})
    const autoRefresh     = ref(true)
    const lastRefreshed   = ref('')
    const newTriggerPort  = ref('')
    let   timer           = null
    let   errorStreak     = 0   // consecutive failures — backoff

    async function refresh() {
      try {
        suggestions.value = await fetchSuggestions()
        lastRefreshed.value = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        errorStreak = 0
      } catch {
        errorStreak++
        // After 3 consecutive failures, pause auto-refresh and notify once
        if (errorStreak === 3) {
          autoRefresh.value = false
          showToast('API unreachable — auto-refresh paused', false)
        }
      }
    }

    function startTimer() {
      if (timer) clearInterval(timer)
      timer = setInterval(() => { if (autoRefresh.value) refresh() }, 15000)
    }

    function stopTimer() {
      if (timer) { clearInterval(timer); timer = null }
    }

    // Load custom triggers once on first mount (not on every refresh cycle)
    onMounted(async () => {
      try { customTriggers.value = await fetchCustomTriggers() || {} } catch {}
    })

    // KeepAlive hooks: refresh immediately on tab switch, manage timer lifecycle
    onActivated(() => {
      refresh()
      if (autoRefresh.value) startTimer()
    })

    onDeactivated(stopTimer)

    async function saveTriggers() {
      try {
        await saveCustomTriggers(customTriggers.value)
        showToast('Custom triggers saved — active in CLI immediately!')
      } catch { showToast('Failed to save triggers', false) }
    }

    function addNewPort() {
      const port = parseInt(newTriggerPort.value)
      if (!port || port < 1 || port > 65535) { showToast('Enter a valid port (1–65535)', false); return }
      if (customTriggers.value[port]) { showToast(`Port ${port} already exists`, false); return }
      customTriggers.value[port] = [{ title: '', suggestions: [] }]
      newTriggerPort.value = ''
    }

    function removePort(port) {
      const copy = { ...customTriggers.value }
      delete copy[port]
      customTriggers.value = copy
    }

    function toggleRefresh() {
      autoRefresh.value = !autoRefresh.value
      errorStreak = 0
      if (autoRefresh.value) { refresh(); startTimer() }
      else stopTimer()
    }

    const nlJoin  = (arr) => Array.isArray(arr) ? arr.join('\n') : (arr || '')
    const nlSplit = (str) => str.split('\n').filter(x => x.trim())

    return {
      suggestions, customTriggers, autoRefresh, lastRefreshed, newTriggerPort,
      refresh, saveTriggers, addNewPort, removePort, copyCmd, toggleRefresh,
      nlJoin, nlSplit,
    }
  },
  template: `
    <div class="p-4 p-md-5">
      <!-- Header -->
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="fw-bold text-white mb-0">
          <i class="fa-solid fa-lightbulb text-warning"></i> Live Suggestions
        </h2>
        <div class="d-flex gap-2 align-items-center">
          <span class="d-flex align-items-center gap-2 text-muted small">
            <span :class="['pulse-dot', autoRefresh ? '' : 'inactive']"></span>
            <span>{{ autoRefresh ? 'Live' : 'Paused' }}</span>
            <span v-if="lastRefreshed" class="ms-1">· {{ lastRefreshed }}</span>
          </span>
          <button class="btn btn-sm btn-capo-outline" @click="toggleRefresh">
            <i :class="['fa-solid', autoRefresh ? 'fa-pause' : 'fa-play']"></i>
          </button>
          <button class="btn btn-sm btn-capo-outline" @click="refresh">
            <i class="fa-solid fa-rotate-right me-1"></i> Refresh
          </button>
        </div>
      </div>

      <!-- No target -->
      <div v-if="!suggestions.target" class="text-center py-5">
        <i class="fa-solid fa-crosshairs text-muted" style="font-size:3rem;opacity:0.3;"></i>
        <h4 class="mt-3 text-muted">No Active Target</h4>
        <p class="text-muted small">Run <code class="capo-font">capo target set &lt;ip&gt;</code> in the CLI first.</p>
      </div>

      <div v-else>
        <!-- Port Intelligence -->
        <div v-if="suggestions.port_triggers?.length" class="mb-4">
          <h5 class="fw-bold mb-3">
            <i class="fa-solid fa-plug text-info me-2"></i>Port Intelligence
            <span class="badge rounded-pill count-badge ms-2">{{ suggestions.port_triggers.length }}</span>
          </h5>
          <div v-for="(t, i) in suggestions.port_triggers" :key="i" class="suggestion-card priority-port">
            <div class="p-3">
              <div class="d-flex align-items-center gap-2 mb-2">
                <span class="badge capo-font port-badge">:{{ t.port }}</span>
                <span class="fw-bold text-white">{{ t.title }}</span>
              </div>
              <div class="d-flex flex-column gap-1">
                <CommandLine v-for="(cmd, ci) in t.commands" :key="ci" :cmd="cmd" accent-color="var(--accent)" />
              </div>
            </div>
          </div>
        </div>

        <!-- Contextual Alerts -->
        <div v-if="suggestions.contextual?.length" class="mb-4">
          <h5 class="fw-bold mb-3">
            <i class="fa-solid fa-brain me-2" style="color:var(--purple)"></i>Contextual Alerts
            <span class="badge rounded-pill count-badge-purple ms-2">{{ suggestions.contextual.length }}</span>
          </h5>
          <div v-for="(t, i) in suggestions.contextual" :key="i" class="suggestion-card priority-ctx">
            <div class="p-3">
              <div class="fw-bold text-white mb-2">{{ t.title }}</div>
              <div class="d-flex flex-column gap-1">
                <CommandLine v-for="(cmd, ci) in t.commands" :key="ci" :cmd="cmd" accent-color="var(--purple)" />
              </div>
            </div>
          </div>
        </div>

        <!-- Strategic Objectives (daemon rules) -->
        <div v-if="suggestions.rule_suggestions?.length" class="mb-4">
          <h5 class="fw-bold mb-3">
            <i class="fa-solid fa-robot me-2" style="color:var(--red)"></i>Strategic Objectives
            <span class="badge rounded-pill count-badge-red ms-2">{{ suggestions.rule_suggestions.length }}</span>
          </h5>
          <div v-for="(r, i) in suggestions.rule_suggestions" :key="r.id || i"
               :class="['suggestion-card', r.priority === 'P1' ? 'priority-p1' : r.priority === 'P2' ? 'priority-p2' : 'priority-p3']">
            <div class="p-3">
              <div class="d-flex align-items-center gap-2 mb-1">
                <span :class="['badge capo-font', r.priority === 'P1' ? 'badge-p1' : r.priority === 'P2' ? 'badge-p2' : 'badge-p3']">{{ r.priority }}</span>
                <span class="fw-bold text-white">{{ r.name }}</span>
              </div>
              <p v-if="r.description" class="text-muted small mb-2">{{ r.description }}</p>
              <CommandLine :cmd="r.command"
                :accent-color="r.priority === 'P1' ? 'var(--red)' : r.priority === 'P2' ? 'var(--amber)' : 'var(--text-muted)'" />
              <div v-if="r.source" class="mt-2">
                <span class="text-muted" style="font-size:0.72rem;"><i class="fa-solid fa-link me-1"></i>{{ r.source }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Empty state -->
        <div v-if="!suggestions.port_triggers?.length && !suggestions.contextual?.length && !suggestions.rule_suggestions?.length"
             class="text-center py-5">
          <i class="fa-solid fa-magnifying-glass text-muted" style="font-size:2.5rem;opacity:0.3;"></i>
          <h5 class="mt-3 text-muted">No suggestions yet</h5>
          <p class="text-muted small">Run a scan — suggestions appear automatically as findings come in.</p>
        </div>

        <!-- Custom Triggers Editor -->
        <hr class="border-secondary my-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h5 class="fw-bold mb-0">
            <i class="fa-solid fa-sliders text-warning me-2"></i>Custom Port Triggers
          </h5>
          <button class="btn btn-sm btn-capo-outline" @click="saveTriggers">
            <i class="fa-solid fa-floppy-disk me-1"></i> Save Triggers
          </button>
        </div>
        <p class="text-muted small mb-3">Add your own port triggers — they sync with the CLI automatically.</p>

        <div v-for="(entries, port) in customTriggers" :key="port" class="capo-card">
          <div class="capo-card-header">
            <span class="capo-font text-info fw-bold">Port {{ port }}</span>
            <button class="btn btn-sm text-danger" @click="removePort(port)"><i class="fa-solid fa-trash"></i></button>
          </div>
          <div class="card-body p-3">
            <div v-for="(entry, ei) in entries" :key="ei" class="mb-3">
              <div class="row g-2 align-items-start">
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Title</label>
                  <input v-model="entry.title" class="form-control form-control-sm" placeholder="Service detected">
                </div>
                <div class="col-md-7">
                  <label class="form-label text-muted small fw-bold text-uppercase">Commands (one per line)</label>
                  <textarea class="form-control form-control-sm cmd-input" rows="2"
                    :value="nlJoin(entry.suggestions)"
                    @input="entry.suggestions = nlSplit($event.target.value)"
                    placeholder="tool --flag {IP}"></textarea>
                </div>
                <div class="col-md-1 d-flex align-items-end">
                  <button class="btn btn-sm text-danger" @click="entries.splice(ei, 1)"><i class="fa-solid fa-minus"></i></button>
                </div>
              </div>
            </div>
            <button class="btn btn-sm btn-capo-outline" @click="entries.push({title:'', suggestions:[]})">
              <i class="fa-solid fa-plus me-1"></i> Add Entry
            </button>
          </div>
        </div>

        <!-- Add new port -->
        <div class="capo-card">
          <div class="card-body p-3 d-flex gap-2 align-items-center">
            <input v-model="newTriggerPort" class="form-control form-control-sm capo-font" style="width:120px;"
                   type="number" placeholder="Port #" min="1" max="65535">
            <button class="btn btn-sm btn-capo" @click="addNewPort">
              <i class="fa-solid fa-plus me-1"></i> Add Port
            </button>
            <span class="text-muted small">Variables: <code class="capo-font">{IP} {DOMAIN} {USER} {PASS} {USERFILE} {PASSFILE}</code></span>
          </div>
        </div>
      </div>
    </div>
  `,
})
