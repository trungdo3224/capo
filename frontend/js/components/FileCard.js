import { defineComponent } from 'vue'

export default defineComponent({
  name: 'FileCard',
  props: {
    filename: { type: String, required: true },
    icon:     { type: String, default: 'fa-solid fa-file-code' },
  },
  emits: ['select'],
  template: `
    <div class="col-md-4 col-lg-3">
      <div class="file-card" @click="$emit('select', filename)">
        <div class="d-flex flex-column align-items-center text-center">
          <i class="fa-solid file-icon" :class="icon"></i>
          <h5 class="fw-bold mb-1 w-100 text-truncate" :title="filename">{{ filename.replace('.yaml', '') }}</h5>
          <span class="badge bg-dark border border-secondary text-muted mt-2">YAML</span>
        </div>
      </div>
    </div>
  `,
})
