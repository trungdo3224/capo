import { defineComponent, ref } from 'vue'
import { showToast, getIconForFile } from '../store.js'
import { fetchMethodologies, getMethodology, saveMethodology } from '../api.js'
import FileCard from '../components/FileCard.js'

export default defineComponent({
  name: 'MethodologyView',
  components: { FileCard },
  setup() {
    const filesList    = ref([])
    const selectedFile = ref('')
    const currentData  = ref(null)
    const loading      = ref(false)

    async function loadList() {
      loading.value = true
      try { filesList.value = await fetchMethodologies() }
      catch { showToast('Failed to load methodologies', false) }
      loading.value = false
    }

    async function loadFile(filename) {
      selectedFile.value = filename
      loading.value = true
      try { currentData.value = await getMethodology(filename) }
      catch { showToast('Error parsing file', false); selectedFile.value = '' }
      loading.value = false
    }

    function closeFile() {
      selectedFile.value = ''
      currentData.value  = null
    }

    async function save() {
      try {
        const payload = JSON.parse(JSON.stringify(currentData.value))
        payload.steps?.forEach(s => {
          if (typeof s.commands === 'string')
            s.commands = s.commands.split('\n').map(x => x.trim()).filter(Boolean)
        })
        await saveMethodology(selectedFile.value, payload)
        showToast('Saved successfully to disk!')
      } catch (e) { showToast('Save error: ' + e.message, false) }
    }

    function addStep() {
      if (!currentData.value.steps) currentData.value.steps = []
      currentData.value.steps.push({ id: 'new-step', name: 'New Step', phase: 'recon', description: '', commands: [] })
    }

    function moveStepUp(idx) {
      if (idx === 0) return
      const s = currentData.value.steps;
      [s[idx - 1], s[idx]] = [s[idx], s[idx - 1]]
    }

    function moveStepDown(idx) {
      const s = currentData.value.steps
      if (idx === s.length - 1) return;
      [s[idx + 1], s[idx]] = [s[idx], s[idx + 1]]
    }

    loadList()

    const nlJoin  = (arr) => Array.isArray(arr) ? arr.join('\n') : (arr || '')
    const nlSplit = (str) => str.split('\n')

    return {
      filesList, selectedFile, currentData, loading,
      loadFile, closeFile, save, addStep, moveStepUp, moveStepDown, getIconForFile,
      nlJoin, nlSplit,
    }
  },
  template: `
    <div class="p-4 p-md-5">
      <!-- Header -->
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 class="fw-bold text-white mb-1">
            <i class="fa-solid fa-code-branch text-warning"></i> Attack Methodologies
          </h2>
          <nav aria-label="breadcrumb">
            <ol class="breadcrumb mb-0">
              <li class="breadcrumb-item">
                <a href="#" @click.prevent="closeFile" class="text-decoration-none" style="color:var(--accent);">Library</a>
              </li>
              <li v-if="selectedFile" class="breadcrumb-item active text-muted" aria-current="page">{{ selectedFile }}</li>
            </ol>
          </nav>
        </div>
        <div v-if="selectedFile && currentData" class="d-flex gap-2">
          <button class="btn btn-outline-secondary" @click="closeFile">
            <i class="fa-solid fa-arrow-left me-1"></i> Back
          </button>
          <button class="btn btn-capo" @click="save">
            <i class="fa-solid fa-floppy-disk me-1"></i> Save Changes
          </button>
        </div>
      </div>

      <!-- List view -->
      <div v-if="!selectedFile" class="row g-4 pt-2">
        <div v-if="loading" class="col-12 text-center py-5">
          <div class="spinner-border text-info" role="status"></div>
        </div>
        <div v-else-if="filesList.length === 0" class="col-12 text-center py-5">
          <i class="fa-solid fa-folder-open text-muted" style="font-size:4rem;opacity:0.3;"></i>
          <h4 class="mt-3 text-muted">No methodologies found</h4>
        </div>
        <FileCard v-for="f in filesList" :key="f" :filename="f" :icon="getIconForFile(f)" @select="loadFile" />
      </div>

      <!-- Editor view -->
      <div v-else class="detail-editor">
        <div v-if="loading" class="text-center py-5">
          <div class="spinner-border text-info" role="status"></div>
          <div class="mt-2 text-muted">Loading {{ selectedFile }}...</div>
        </div>

        <div v-else-if="currentData">
          <!-- Profile -->
          <div class="capo-card mb-4">
            <div class="capo-card-header">
              <h5 class="mb-0 fw-bold"><i class="fa-solid fa-list-check me-2"></i> Methodology Profile</h5>
            </div>
            <div class="card-body p-4">
              <div class="row g-3">
                <div class="col-md-6">
                  <label class="form-label text-muted small fw-bold text-uppercase">ID Name</label>
                  <input v-model="currentData.name" class="form-control">
                </div>
                <div class="col-md-6">
                  <label class="form-label text-muted small fw-bold text-uppercase">Display Name</label>
                  <input v-model="currentData.display_name" class="form-control">
                </div>
                <div class="col-12">
                  <label class="form-label text-muted small fw-bold text-uppercase">Description</label>
                  <textarea v-model="currentData.description" class="form-control" rows="2"></textarea>
                </div>
              </div>
            </div>
          </div>

          <!-- Steps -->
          <div class="d-flex justify-content-between align-items-center mb-3 mt-5">
            <div>
              <h4 class="fw-bold mb-0"><i class="fa-solid fa-shoe-prints me-2"></i> Execution Steps</h4>
              <span class="text-muted small">{{ currentData.steps ? currentData.steps.length : 0 }} phases</span>
            </div>
            <button class="btn btn-sm btn-capo-outline" @click="addStep">
              <i class="fa-solid fa-plus me-1"></i> Add Step
            </button>
          </div>

          <div v-for="(step, idx) in currentData.steps" :key="idx" class="capo-card">
            <div class="capo-card-header py-2" style="background-color:rgba(0,0,0,0.2);">
              <div class="fw-bold text-white">
                <span class="text-muted pe-2">Step {{ idx + 1 }}</span> {{ step.name || 'Untitled Step' }}
              </div>
              <div>
                <button class="btn btn-sm text-secondary me-1" @click="moveStepUp(idx)" :disabled="idx === 0">
                  <i class="fa-solid fa-arrow-up"></i>
                </button>
                <button class="btn btn-sm text-secondary me-3" @click="moveStepDown(idx)" :disabled="idx === currentData.steps.length - 1">
                  <i class="fa-solid fa-arrow-down"></i>
                </button>
                <button class="btn btn-sm text-danger" @click="currentData.steps.splice(idx, 1)">
                  <i class="fa-solid fa-trash"></i>
                </button>
              </div>
            </div>
            <div class="card-body p-3 p-md-4">
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Step ID</label>
                  <input v-model="step.id" class="form-control form-control-sm">
                </div>
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Step Name</label>
                  <input v-model="step.name" class="form-control form-control-sm">
                </div>
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Phase</label>
                  <input v-model="step.phase" class="form-control form-control-sm" placeholder="e.g. recon, exploit">
                </div>
                <div class="col-12">
                  <label class="form-label text-muted small fw-bold text-uppercase">Description</label>
                  <input v-model="step.description" class="form-control form-control-sm">
                </div>
                <div class="col-12 mt-3">
                  <label class="form-label text-muted small fw-bold text-uppercase text-info mb-1">Commands (one per line)</label>
                  <textarea class="form-control cmd-input" rows="3"
                    :value="nlJoin(step.commands)"
                    @input="step.commands = nlSplit($event.target.value)"></textarea>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
})
