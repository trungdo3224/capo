import { defineComponent, ref } from 'vue'
import { showToast, getIconForFile } from '../store.js'
import { fetchCheatsheets, getCheatsheet, saveCheatsheet } from '../api.js'
import FileCard from '../components/FileCard.js'

export default defineComponent({
  name: 'CheatsheetView',
  components: { FileCard },
  setup() {
    const filesList    = ref([])
    const selectedFile = ref('')
    const currentData  = ref(null)
    const loading      = ref(false)

    async function loadList() {
      loading.value = true
      try { filesList.value = await fetchCheatsheets() }
      catch { showToast('Failed to load cheatsheets', false) }
      loading.value = false
    }

    async function loadFile(filename) {
      selectedFile.value = filename
      loading.value = true
      try { currentData.value = await getCheatsheet(filename) }
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
        payload.commands?.forEach(c => {
          if (typeof c.tags === 'string') c.tags = c.tags.split(',').map(x => x.trim()).filter(Boolean)
          if (typeof c.exam === 'string') c.exam = c.exam.split(',').map(x => x.trim()).filter(Boolean)
        })
        await saveCheatsheet(selectedFile.value, payload)
        showToast('Saved successfully to disk!')
      } catch (e) { showToast('Save error: ' + e.message, false) }
    }

    function addCommand() {
      currentData.value.commands.unshift({
        name: 'new-command', description: '', command: '', tool: '', tags: [], os: '', exam: []
      })
    }

    loadList()

    return {
      filesList, selectedFile, currentData, loading,
      loadFile, closeFile, save, addCommand, getIconForFile,
    }
  },
  template: `
    <div class="p-4 p-md-5">
      <!-- Header -->
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 class="fw-bold text-white mb-1">
            <i class="fa-solid fa-book-open text-primary"></i> Cheatsheet Intelligence
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
          <h4 class="mt-3 text-muted">No cheatsheets found</h4>
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
          <!-- Metadata -->
          <div class="capo-card mb-4">
            <div class="capo-card-header">
              <h5 class="mb-0 fw-bold"><i class="fa-solid fa-cog me-2"></i> Document Metadata</h5>
            </div>
            <div class="card-body p-4">
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Category</label>
                  <input v-model="currentData.category" class="form-control" placeholder="e.g. active-directory">
                </div>
                <div class="col-md-8">
                  <label class="form-label text-muted small fw-bold text-uppercase">Description</label>
                  <input v-model="currentData.description" class="form-control" placeholder="What is this cheatsheet for?">
                </div>
              </div>
            </div>
          </div>

          <!-- Commands -->
          <div class="d-flex justify-content-between align-items-center mb-3 mt-5">
            <div>
              <h4 class="fw-bold mb-0"><i class="fa-solid fa-terminal me-2"></i> Commands Bank</h4>
              <span class="text-muted small">{{ currentData.commands ? currentData.commands.length : 0 }} entries</span>
            </div>
            <button class="btn btn-sm btn-capo-outline" @click="addCommand">
              <i class="fa-solid fa-plus me-1"></i> Add Command
            </button>
          </div>

          <div v-for="(cmd, idx) in currentData.commands" :key="idx" class="capo-card">
            <div class="capo-card-header py-2" style="background-color:rgba(0,0,0,0.2);">
              <div class="fw-bold text-white">
                <span class="text-muted pe-2">#{{ idx + 1 }}</span> {{ cmd.name || 'Untitled Node' }}
              </div>
              <button class="btn btn-sm text-danger" @click="currentData.commands.splice(idx, 1)" title="Delete">
                <i class="fa-solid fa-trash"></i>
              </button>
            </div>
            <div class="card-body p-3 p-md-4">
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Reference ID</label>
                  <input v-model="cmd.name" class="form-control form-control-sm" placeholder="asrep-roast">
                </div>
                <div class="col-md-4">
                  <label class="form-label text-muted small fw-bold text-uppercase">Tool Executable</label>
                  <input v-model="cmd.tool" class="form-control form-control-sm" placeholder="impacket">
                </div>
                <div class="col-md-2">
                  <label class="form-label text-muted small fw-bold text-uppercase">Target OS</label>
                  <select v-model="cmd.os" class="form-select form-select-sm">
                    <option value="">Any</option>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                  </select>
                </div>
                <div class="col-md-12">
                  <label class="form-label text-muted small fw-bold text-uppercase">Description</label>
                  <input v-model="cmd.description" class="form-control form-control-sm" placeholder="What does this do?">
                </div>
                <div class="col-md-12">
                  <label class="form-label text-muted small fw-bold text-uppercase text-info">Syntax Template</label>
                  <div class="input-group input-group-sm">
                    <span class="input-group-text bg-dark border-secondary text-muted"><i class="fa-solid fa-angle-right"></i></span>
                    <input v-model="cmd.command" class="form-control cmd-input form-control-sm" placeholder="tool -u {USER} -p {PASS} {IP}">
                  </div>
                </div>
                <div class="col-md-6">
                  <label class="form-label text-muted small fw-bold text-uppercase">Tags (comma separated)</label>
                  <input type="text" class="form-control form-control-sm"
                    :value="Array.isArray(cmd.tags) ? cmd.tags.join(', ') : cmd.tags"
                    @input="cmd.tags = $event.target.value"
                    placeholder="ad, kerberos, enum">
                </div>
                <div class="col-md-6">
                  <label class="form-label text-muted small fw-bold text-uppercase">Exam Applicability</label>
                  <input type="text" class="form-control form-control-sm"
                    :value="Array.isArray(cmd.exam) ? cmd.exam.join(', ') : cmd.exam"
                    @input="cmd.exam = $event.target.value"
                    placeholder="oscp, cpts">
                </div>
                <div v-if="cmd.notes" class="col-12">
                  <label class="form-label text-muted small fw-bold text-uppercase">Notes</label>
                  <textarea v-model="cmd.notes" class="form-control form-control-sm" rows="2"></textarea>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
})
