import { defineComponent } from 'vue'
import { currentView, suggestionCount, currentTheme, setTheme } from '../store.js'

export default defineComponent({
  name: 'Sidebar',
  setup() {
    const navItems = [
      { view: 'cheatsheets',  icon: 'fa-book-open',       label: 'Cheatsheets' },
      { view: 'methodologies',icon: 'fa-code-branch',      label: 'Methodologies' },
      { view: 'engagement',   icon: 'fa-crosshairs',       label: 'Active Engagement' },
      { view: 'graph',        icon: 'fa-diagram-project',  label: 'Knowledge Graph' },
      { view: 'sessions',     icon: 'fa-folder-open',       label: 'Sessions' },
      { view: 'suggestions',  icon: 'fa-lightbulb',        label: 'Suggestions' },
    ]

    const themes = [
      { key: 'dark',  icon: 'fa-moon',           tip: 'Dark' },
      { key: 'dim',   icon: 'fa-cloud-moon',     tip: 'Dim' },
      { key: 'light', icon: 'fa-sun',            tip: 'Light' },
    ]

    function switchView(view) {
      currentView.value = view
    }

    return { currentView, suggestionCount, navItems, switchView, currentTheme, setTheme, themes }
  },
  template: `
    <div class="col-md-2 sidebar d-flex flex-column">
      <div class="logo-container d-flex align-items-center gap-2" @click="switchView('cheatsheets')">
        <i class="fa-solid fa-terminal" style="color:var(--accent);font-size:1.5rem;"></i>
        <span class="logo-text">C.A.P.O<small>STUDIO</small></span>
      </div>

      <ul class="nav nav-pills flex-column mb-auto">
        <li v-for="item in navItems" :key="item.view" class="nav-item">
          <a class="nav-link" :class="{ active: currentView === item.view }" @click="switchView(item.view)">
            <i class="fa-solid ms-1 me-2" :class="item.icon"></i>
            {{ item.label }}
            <span
              v-if="item.view === 'suggestions' && suggestionCount > 0"
              class="badge rounded-pill nav-badge ms-1"
            >{{ suggestionCount }}</span>
          </a>
        </li>
      </ul>

      <div class="mt-auto pt-3 border-top" style="border-color:var(--border)!important;">
        <div class="d-flex justify-content-center mb-2">
          <div class="theme-switcher">
            <button
              v-for="t in themes" :key="t.key"
              class="theme-btn"
              :class="{ active: currentTheme === t.key }"
              :title="t.tip"
              @click="setTheme(t.key)"
            ><i class="fa-solid" :class="t.icon"></i></button>
          </div>
        </div>
        <div class="text-muted small text-center">
          <i class="fa-solid fa-shield-halved"></i> Active Directory · OSCP · CPTS
        </div>
      </div>
    </div>
  `,
})
