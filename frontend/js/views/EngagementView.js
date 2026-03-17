import { defineComponent, ref, computed, onMounted, onActivated, onDeactivated } from 'vue'
import { showToast, formatTime } from '../store.js'
import { fetchEngagement } from '../api.js'

// Known array/object keys that are displayed in dedicated sections above
const ARRAY_KEYS = new Set(['ports', 'users', 'credentials', 'scan_history', 'groups', 'shares'])

export default defineComponent({
  name: 'EngagementView',
  setup() {
    const engagementData = ref(null)
    const loading        = ref(false)
    const showRawState   = ref(false)
    let   timer          = null

    async function load() {
      loading.value = true
      try { engagementData.value = await fetchEngagement() }
      catch { showToast('Failed to load engagement state', false) }
      loading.value = false
    }

    function startTimer() {
      if (timer) clearInterval(timer)
      timer = setInterval(load, 5000)
    }

    function stopTimer() {
      if (timer) { clearInterval(timer); timer = null }
    }

    // Scalar fields from state (everything that isn't a known array/object section)
    const stateScalars = computed(() => {
      const s = engagementData.value?.state
      if (!s) return []
      return Object.entries(s)
        .filter(([k, v]) => !ARRAY_KEYS.has(k) && v !== null && v !== undefined && v !== '' && !Array.isArray(v) && typeof v !== 'object')
        .map(([k, v]) => ({ key: k.replace(/_/g, ' '), raw: k, value: String(v) }))
    })

    // Extra array fields not handled in dedicated sections (groups, shares, etc.)
    const stateExtraArrays = computed(() => {
      const s = engagementData.value?.state
      if (!s) return []
      return Object.entries(s)
        .filter(([k, v]) => !['ports','users','credentials','scan_history'].includes(k) && Array.isArray(v) && v.length > 0)
        .map(([k, v]) => ({ key: k.replace(/_/g, ' '), raw: k, items: v }))
    })

    onMounted(load)
    onActivated(() => { load(); startTimer() })
    onDeactivated(stopTimer)

    return { engagementData, loading, showRawState, stateScalars, stateExtraArrays, formatTime }
  },
  template: `
    <div class="p-4 p-md-5">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="fw-bold text-white mb-0">
          <i class="fa-solid fa-crosshairs text-danger"></i> Active Engagement
        </h2>
      </div>

      <div v-if="loading && !engagementData" class="text-center py-5">
        <div class="spinner-border text-danger" role="status"></div>
      </div>

      <div v-else-if="engagementData" class="row g-4 pt-2">
        <div class="col-12">
          <div class="capo-card border-danger">
            <div class="capo-card-header bg-danger bg-opacity-10 border-danger border-bottom">
              <h4 class="mb-0 text-white fw-bold">
                <i class="fa-solid fa-crosshairs me-2"></i> Active Target:
                <span class="text-danger capo-font">{{ engagementData.target || 'No Target Selected' }}</span>
              </h4>
            </div>
            <div class="card-body p-4">
              <h5 class="fw-bold mb-3">
                <i class="fa-solid fa-flag text-warning me-2"></i>
                Campaign: {{ engagementData.campaign || 'No Active Campaign' }}
              </h5>

              <div v-if="!engagementData.target" class="text-muted fst-italic">
                No target selected. Run <code class="capo-font">capo target set &lt;ip&gt;</code> in the CLI.
              </div>

              <template v-else>

                <!-- ── State Overview (scalar fields) ── -->
                <div v-if="stateScalars.length" class="mb-4">
                  <h6 class="fw-bold text-info mb-2"><i class="fa-solid fa-circle-info me-2"></i>Host Info</h6>
                  <div class="rounded border" style="border-color:var(--border)!important;overflow:hidden;">
                    <table class="table table-sm mb-0" style="background:transparent;">
                      <tbody>
                        <tr v-for="row in stateScalars" :key="row.raw"
                            style="border-color:var(--border-dim);">
                          <td class="text-muted capo-font py-1 px-3"
                              style="width:9rem;font-size:0.72rem;letter-spacing:0.06em;text-transform:uppercase;white-space:nowrap;border-color:var(--border-dim);">
                            {{ row.key }}
                          </td>
                          <td class="text-white py-1 px-3 capo-font"
                              style="font-size:0.8rem;border-color:var(--border-dim);">
                            {{ row.value }}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <!-- ── Open Ports ── -->
                <div v-if="engagementData.state?.ports?.length" class="mb-4">
                  <h6 class="fw-bold text-info mb-2"><i class="fa-solid fa-network-wired me-2"></i>Open Ports</h6>
                  <div class="rounded border" style="border-color:var(--border)!important;overflow:hidden;">
                    <table class="table table-sm mb-0" style="background:transparent;">
                      <thead>
                        <tr style="border-color:var(--border-dim);">
                          <th class="text-muted py-1 px-3" style="font-size:0.7rem;letter-spacing:0.08em;text-transform:uppercase;font-weight:500;border-color:var(--border);">Port</th>
                          <th class="text-muted py-1 px-3" style="font-size:0.7rem;letter-spacing:0.08em;text-transform:uppercase;font-weight:500;border-color:var(--border);">Proto</th>
                          <th class="text-muted py-1 px-3" style="font-size:0.7rem;letter-spacing:0.08em;text-transform:uppercase;font-weight:500;border-color:var(--border);">Service</th>
                          <th class="text-muted py-1 px-3" style="font-size:0.7rem;letter-spacing:0.08em;text-transform:uppercase;font-weight:500;border-color:var(--border);">Version</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="p in engagementData.state.ports" :key="p.port + p.protocol"
                            style="border-color:var(--border-dim);">
                          <td class="capo-font py-1 px-3" style="color:var(--accent);font-size:0.8rem;border-color:var(--border-dim);">{{ p.port }}</td>
                          <td class="text-muted capo-font py-1 px-3" style="font-size:0.78rem;border-color:var(--border-dim);">{{ p.protocol }}</td>
                          <td class="text-white py-1 px-3" style="font-size:0.8rem;border-color:var(--border-dim);">{{ p.service || '—' }}</td>
                          <td class="text-muted py-1 px-3" style="font-size:0.78rem;border-color:var(--border-dim);">{{ p.version || '—' }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <!-- ── Users / Credentials ── -->
                <div v-if="engagementData.state?.users?.length || engagementData.state?.credentials?.length" class="mb-4 row g-3">
                  <div v-if="engagementData.state.users?.length" class="col-md-6">
                    <h6 class="fw-bold mb-2" style="color:var(--amber)"><i class="fa-solid fa-users me-1"></i>Users</h6>
                    <div class="d-flex flex-wrap gap-1">
                      <span v-for="u in engagementData.state.users.slice(0,12)" :key="u"
                            class="badge bg-dark border border-secondary text-muted capo-font">{{ u }}</span>
                      <span v-if="engagementData.state.users.length > 12" class="text-muted small">
                        +{{ engagementData.state.users.length - 12 }} more
                      </span>
                    </div>
                  </div>
                  <div v-if="engagementData.state.credentials?.length" class="col-md-6">
                    <h6 class="fw-bold mb-2" style="color:var(--green)"><i class="fa-solid fa-key me-1"></i>Credentials</h6>
                    <div class="d-flex flex-wrap gap-1">
                      <span v-for="c in engagementData.state.credentials.slice(0,6)" :key="c.username + c.service"
                            class="badge capo-font badge-green">
                        {{ c.username }}{{ c.service ? ':' + c.service : '' }}
                      </span>
                    </div>
                  </div>
                </div>

                <!-- ── Extra arrays (groups, shares, etc.) ── -->
                <div v-for="arr in stateExtraArrays" :key="arr.raw" class="mb-3">
                  <h6 class="fw-bold text-info mb-2 text-capitalize">
                    <i class="fa-solid fa-list me-2"></i>{{ arr.key }}
                  </h6>
                  <div class="d-flex flex-wrap gap-1">
                    <span v-for="(item, i) in arr.items.slice(0,20)" :key="i"
                          class="badge bg-dark border border-secondary text-muted capo-font" style="font-size:0.75rem;">
                      {{ typeof item === 'object' ? JSON.stringify(item) : item }}
                    </span>
                    <span v-if="arr.items.length > 20" class="text-muted small">+{{ arr.items.length - 20 }} more</span>
                  </div>
                </div>

                <!-- ── Scan History ── -->
                <div v-if="engagementData.state?.scan_history?.length" class="mb-4">
                  <hr class="border-secondary">
                  <h6 class="fw-bold text-info mb-2"><i class="fa-solid fa-clock-rotate-left me-2"></i>Scan History</h6>
                  <div style="max-height:220px;overflow-y:auto;">
                    <div v-for="(scan, i) in [...engagementData.state.scan_history].reverse().slice(0,20)" :key="i" class="history-row">
                      <span class="history-tool">{{ scan.tool }}</span>
                      <span class="history-cmd">{{ scan.command }}</span>
                      <span class="history-time">{{ formatTime(scan.timestamp) }}</span>
                    </div>
                  </div>
                </div>

                <!-- ── Full State (collapsible) ── -->
                <hr class="border-secondary">
                <div class="d-flex justify-content-between align-items-center" style="cursor:pointer;" @click="showRawState = !showRawState">
                  <h6 class="fw-bold text-info mb-0"><i class="fa-solid fa-database me-2"></i>Full State</h6>
                  <i class="fa-solid text-muted" :class="showRawState ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size:0.75rem;"></i>
                </div>
                <div v-if="showRawState" class="bg-dark p-3 mt-2 rounded border border-secondary" style="max-height:400px;overflow-y:auto;">
                  <pre class="text-success capo-font mb-0" style="font-size:0.82rem;">{{ JSON.stringify(engagementData.state, null, 2) }}</pre>
                </div>

              </template>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
})
