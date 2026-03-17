import { defineComponent } from 'vue'
import { copyCmd } from '../store.js'

export default defineComponent({
  name: 'CommandLine',
  props: {
    cmd:         { type: String, required: true },
    accentColor: { type: String, default: 'var(--accent)' },
  },
  setup() {
    return { copyCmd }
  },
  template: `
    <div class="cmd-line" @click="copyCmd(cmd)" title="Click to copy">
      <i class="fa-solid fa-angle-right" :style="{ color: accentColor, fontSize: '0.7rem' }"></i>
      <span class="flex-1">{{ cmd }}</span>
      <i class="fa-regular fa-copy copy-icon"></i>
    </div>
  `,
})
