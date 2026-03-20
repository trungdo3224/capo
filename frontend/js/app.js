import { createApp, computed } from 'vue'

import { currentView } from './store.js'

import Sidebar         from './components/Sidebar.js'
import Toast           from './components/Toast.js'
import CheatsheetView  from './views/CheatsheetView.js'
import MethodologyView from './views/MethodologyView.js'
import EngagementView  from './views/EngagementView.js'
import GraphView       from './views/GraphView.js'
import SuggestionsView from './views/SuggestionsView.js'
import SessionsView    from './views/SessionsView.js'

const viewMap = {
  cheatsheets:   CheatsheetView,
  methodologies: MethodologyView,
  engagement:    EngagementView,
  graph:         GraphView,
  sessions:      SessionsView,
  suggestions:   SuggestionsView,
}

const App = {
  components: { Sidebar, Toast, CheatsheetView, MethodologyView, EngagementView, GraphView, SessionsView, SuggestionsView },

  setup() {
    const activeComponent = computed(() => viewMap[currentView.value])
    return { currentView, activeComponent }
  },

  // KeepAlive keeps all views alive between tab switches:
  // - no repeated API fetches on every click
  // - scroll position is preserved
  // - views use onActivated for refresh-on-revisit instead of onMounted
  template: `
    <div class="container-fluid p-0">
      <div class="row g-0">
        <Sidebar />
        <div class="col-md-10" style="height:100vh;overflow-y:auto;">
          <KeepAlive>
            <component :is="activeComponent" :key="currentView" />
          </KeepAlive>
        </div>
      </div>
      <Toast />
    </div>
  `,
}

createApp(App).mount('#app')
