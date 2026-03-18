import { defineComponent, ref, computed, onMounted, onActivated, onDeactivated, onBeforeUnmount, watch, nextTick } from 'vue'
import { showToast } from '../store.js'
import {
  fetchGraph, createGraphNode, updateGraphNode, deleteGraphNode,
  createGraphEdge, updateGraphEdge, deleteGraphEdge, saveGraphPositions, clearGraph,
} from '../api.js'

// ── Node type config ────────────────────────────────────────────────────────
const NODE_TYPES = [
  { value: 'target',     label: 'Target',     color: '#f87171', icon: 'fa-crosshairs' },
  { value: 'service',    label: 'Service',    color: '#22d3ee', icon: 'fa-server' },
  { value: 'user',       label: 'User',       color: '#fbbf24', icon: 'fa-user' },
  { value: 'credential', label: 'Credential', color: '#34d399', icon: 'fa-key' },
  { value: 'hash',       label: 'Hash',       color: '#fb923c', icon: 'fa-hashtag' },
  { value: 'domain',     label: 'Domain',     color: '#22d3ee', icon: 'fa-globe' },
  { value: 'dc',         label: 'Domain Ctrl', color: '#e879f9', icon: 'fa-building-columns' },
  { value: 'vhost',      label: 'VHost',      color: '#38bdf8', icon: 'fa-at' },
  { value: 'directory',  label: 'Directory',  color: '#94a3b8', icon: 'fa-folder-tree' },
  { value: 'share',      label: 'Share',      color: '#a78bfa', icon: 'fa-folder-open' },
  { value: 'finding',    label: 'Finding',    color: '#a78bfa', icon: 'fa-bug' },
  { value: 'note',       label: 'Note',       color: '#5e5e72', icon: 'fa-sticky-note' },
  { value: 'custom',     label: 'Custom',     color: '#dcdce6', icon: 'fa-circle' },
]
const typeColorMap = Object.fromEntries(NODE_TYPES.map(t => [t.value, t.color]))
const RELATIONSHIP_TYPES = [
  'has_service', 'connects_to', 'authenticates_as', 'owns_credential',
  'has_hash', 'pass_the_hash', 'member_of', 'admin_of', 'trusts',
  'runs_on', 'leads_to', 'exploits', 'exposes', 'found_on',
  'resolves_to', 'related_to',
]

export default defineComponent({
  name: 'GraphView',
  setup() {
    // ── Reactive state ────────────────────────────────────────────────────
    const canvasRef = ref(null)
    const graphData = ref({ nodes: [], edges: [] })
    const loading = ref(false)
    const selectedNode = ref(null)
    const selectedEdge = ref(null)
    const mode = ref('select')          // 'select' | 'connect'
    const connectSource = ref(null)
    const showLabels = ref(true)
    const physicsOn = ref(false)
    const nodeCount = computed(() => graphData.value.nodes.length)
    const edgeCount = computed(() => graphData.value.edges.length)

    // ── Search & filter ────────────────────────────────────────────────────
    const searchQuery = ref('')
    const hiddenTypes = ref(new Set())

    function toggleType(type) {
      const s = new Set(hiddenTypes.value)
      if (s.has(type)) s.delete(type); else s.add(type)
      hiddenTypes.value = s
    }

    function isNodeVisible(n) {
      if (hiddenTypes.value.has(n.type)) return false
      return true
    }

    function isNodeHighlighted(n) {
      if (!searchQuery.value) return true
      const q = searchQuery.value.toLowerCase()
      return n.label.toLowerCase().includes(q) || n.type.toLowerCase().includes(q)
    }

    const matchCount = computed(() => {
      if (!searchQuery.value) return -1
      const q = searchQuery.value.toLowerCase()
      return graphData.value.nodes.filter(n =>
        isNodeVisible(n) && (n.label.toLowerCase().includes(q) || n.type.toLowerCase().includes(q))
      ).length
    })

    // ── New node form ─────────────────────────────────────────────────────
    const newNodeType = ref('finding')
    const newNodeLabel = ref('')

    // ── New edge form ─────────────────────────────────────────────────────
    const newEdgeRelationship = ref('related_to')
    const newEdgeLabel = ref('')

    // ── Edit forms ────────────────────────────────────────────────────────
    const editLabel = ref('')
    const editType = ref('')
    const editRelationship = ref('')
    const editEdgeLabel = ref('')

    // ── Theme-aware canvas colors (read from CSS variables) ────────────
    let themeColors = { text: [220,220,230], textMuted: [142,142,162], edge: [88,166,255], highlight: [255,255,255] }
    function readThemeColors() {
      const s = getComputedStyle(document.documentElement)
      const parse = (v) => {
        const hex = (s.getPropertyValue(v) || '').trim().replace('#', '')
        if (hex.length === 6) return [parseInt(hex.substring(0,2),16), parseInt(hex.substring(2,4),16), parseInt(hex.substring(4,6),16)]
        return null
      }
      themeColors.text = parse('--text') || [220,220,230]
      themeColors.textMuted = parse('--text-muted') || [142,142,162]
      themeColors.accent = parse('--accent') || [34,211,238]
      // highlight: use text color for selected/hovered borders (visible on any bg)
      themeColors.highlight = themeColors.text
    }

    // ── Camera ────────────────────────────────────────────────────────────
    let camX = 0, camY = 0, camZoom = 1
    let canvasW = 0, canvasH = 0
    let animId = null
    let ctx = null

    // ── Interaction state ─────────────────────────────────────────────────
    let dragNode = null, isDragging = false
    let isPanning = false, panStartX = 0, panStartY = 0
    let hoveredNode = null
    let mouseX = 0, mouseY = 0
    let connectLine = null   // { sx, sy } world coords of source during connect drag
    let positionsDirty = false
    let positionTimer = null

    // ── Coordinate transforms ─────────────────────────────────────────────
    function toScreen(wx, wy) {
      return [(wx - camX) * camZoom + canvasW / 2, (wy - camY) * camZoom + canvasH / 2]
    }
    function toWorld(sx, sy) {
      return [(sx - canvasW / 2) / camZoom + camX, (sy - canvasH / 2) / camZoom + camY]
    }

    // ── Node hit-test ─────────────────────────────────────────────────────
    function nodeAt(sx, sy) {
      const [wx, wy] = toWorld(sx, sy)
      const nodes = graphData.value.nodes
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i]
        if (!isNodeVisible(n)) continue
        const nx = n.x ?? 0, ny = n.y ?? 0
        const r = nodeRadius(n) / camZoom
        if ((wx - nx) ** 2 + (wy - ny) ** 2 < r ** 2) return n
      }
      return null
    }

    function edgeAt(sx, sy) {
      const [wx, wy] = toWorld(sx, sy)
      const edges = graphData.value.edges
      const nodes = graphData.value.nodes
      const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]))
      const threshold = 8 / camZoom
      for (const e of edges) {
        const s = nodeMap[e.source], t = nodeMap[e.target]
        if (!s || !t) continue
        const dist = pointToSegmentDist(wx, wy, s.x ?? 0, s.y ?? 0, t.x ?? 0, t.y ?? 0)
        if (dist < threshold) return e
      }
      return null
    }

    function pointToSegmentDist(px, py, ax, ay, bx, by) {
      const dx = bx - ax, dy = by - ay
      const lenSq = dx * dx + dy * dy
      if (lenSq === 0) return Math.hypot(px - ax, py - ay)
      let t = ((px - ax) * dx + (py - ay) * dy) / lenSq
      t = Math.max(0, Math.min(1, t))
      return Math.hypot(px - (ax + t * dx), py - (ay + t * dy))
    }

    // Cached edge-count map — rebuilt when edges change (not per frame)
    let edgeCountMap = {}
    function rebuildEdgeCounts() {
      const map = {}
      for (const e of graphData.value.edges) {
        map[e.source] = (map[e.source] || 0) + 1
        map[e.target] = (map[e.target] || 0) + 1
      }
      edgeCountMap = map
    }
    watch(() => graphData.value.edges.length, rebuildEdgeCounts, { immediate: true })

    function nodeRadius(n) {
      const conns = edgeCountMap[n.id] || 0
      return (6 + Math.min(conns * 1.5, 10)) * camZoom
    }

    // ── Physics (simple force-directed) ───────────────────────────────────
    function simulate() {
      if (!physicsOn.value) return
      const nodes = graphData.value.nodes
      const edges = graphData.value.edges
      const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]))
      const damping = 0.85

      for (const n of nodes) {
        if (!n._vx) n._vx = 0
        if (!n._vy) n._vy = 0
        if (n === dragNode) continue

        let fx = 0, fy = 0
        // Repulsion
        for (const m of nodes) {
          if (m === n) continue
          const dx = (n.x ?? 0) - (m.x ?? 0), dy = (n.y ?? 0) - (m.y ?? 0)
          const dist = Math.max(Math.hypot(dx, dy), 1)
          const force = 800 / (dist * dist)
          fx += (dx / dist) * force
          fy += (dy / dist) * force
        }
        // Spring attraction
        for (const e of edges) {
          let other = null
          if (e.source === n.id) other = nodeMap[e.target]
          else if (e.target === n.id) other = nodeMap[e.source]
          if (!other) continue
          const dx = (other.x ?? 0) - (n.x ?? 0), dy = (other.y ?? 0) - (n.y ?? 0)
          const dist = Math.hypot(dx, dy)
          const force = (dist - 120) * 0.01
          fx += (dx / Math.max(dist, 1)) * force
          fy += (dy / Math.max(dist, 1)) * force
        }

        n._vx = (n._vx + fx) * damping
        n._vy = (n._vy + fy) * damping
        n.x = (n.x ?? 0) + n._vx
        n.y = (n.y ?? 0) + n._vy
      }
      positionsDirty = true
    }

    // ── Drawing ───────────────────────────────────────────────────────────
    function draw() {
      if (!ctx) return
      simulate()
      readThemeColors()
      ctx.clearRect(0, 0, canvasW, canvasH)

      const nodes = graphData.value.nodes
      const edges = graphData.value.edges
      const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]))
      const sel = selectedNode.value
      const selEdge = selectedEdge.value
      const hov = hoveredNode
      const hovConnected = new Set()
      if (hov) {
        for (const e of edges) {
          if (e.source === hov.id || e.target === hov.id) {
            hovConnected.add(e.source)
            hovConnected.add(e.target)
          }
        }
      }

      // Build visibility set for filtering
      const visibleIds = new Set()
      const searchHighlighted = new Set()
      const hasSearch = !!searchQuery.value
      for (const n of nodes) {
        if (isNodeVisible(n)) visibleIds.add(n.id)
        if (hasSearch && isNodeHighlighted(n)) searchHighlighted.add(n.id)
      }

      // Draw edges
      for (const e of edges) {
        const s = nodeMap[e.source], t = nodeMap[e.target]
        if (!s || !t) continue
        if (!visibleIds.has(s.id) || !visibleIds.has(t.id)) continue
        const [sx, sy] = toScreen(s.x ?? 0, s.y ?? 0)
        const [tx, ty] = toScreen(t.x ?? 0, t.y ?? 0)

        let alpha = 0.35
        let lineW = 1
        if (hov) {
          alpha = (e.source === hov.id || e.target === hov.id) ? 0.9 : 0.08
          lineW = (e.source === hov.id || e.target === hov.id) ? 2 : 0.5
        }
        if (hasSearch && !searchHighlighted.has(s.id) && !searchHighlighted.has(t.id)) {
          alpha *= 0.15
        }
        if (selEdge && e.id === selEdge.id) { alpha = 1; lineW = 2.5 }

        const [er, eg, eb] = themeColors.accent
        ctx.strokeStyle = `rgba(${er},${eg},${eb},${alpha})`
        ctx.lineWidth = lineW
        ctx.beginPath()
        ctx.moveTo(sx, sy)
        ctx.lineTo(tx, ty)
        ctx.stroke()

        // Arrow head
        if (e.directed !== false) {
          const angle = Math.atan2(ty - sy, tx - sx)
          const r = nodeRadius(t)
          const ax = tx - Math.cos(angle) * r
          const ay = ty - Math.sin(angle) * r
          const aSize = 6 + lineW
          ctx.fillStyle = `rgba(${er},${eg},${eb},${alpha})`
          ctx.beginPath()
          ctx.moveTo(ax, ay)
          ctx.lineTo(ax - aSize * Math.cos(angle - 0.4), ay - aSize * Math.sin(angle - 0.4))
          ctx.lineTo(ax - aSize * Math.cos(angle + 0.4), ay - aSize * Math.sin(angle + 0.4))
          ctx.closePath()
          ctx.fill()
        }

        // Edge label
        if (showLabels.value && e.label && camZoom > 0.5) {
          const mx = (sx + tx) / 2, my = (sy + ty) / 2
          ctx.font = `${Math.max(9, 10 * camZoom)}px 'JetBrains Mono', monospace`
          const [mr, mg, mb] = themeColors.textMuted
          ctx.fillStyle = `rgba(${mr},${mg},${mb},${alpha})`
          ctx.textAlign = 'center'
          ctx.fillText(e.label, mx, my - 4)
        }
      }

      // Connect-mode dashed line
      if (connectLine) {
        const [sx, sy] = toScreen(connectLine.sx, connectLine.sy)
        ctx.setLineDash([6, 4])
        const [cr, cg, ccb] = themeColors.accent
        ctx.strokeStyle = `rgba(${cr},${cg},${ccb},0.7)`
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.moveTo(sx, sy)
        ctx.lineTo(mouseX, mouseY)
        ctx.stroke()
        ctx.setLineDash([])
      }

      // Draw nodes
      for (const n of nodes) {
        if (!visibleIds.has(n.id)) continue
        const [sx, sy] = toScreen(n.x ?? 0, n.y ?? 0)
        const r = nodeRadius(n)
        const color = typeColorMap[n.type] || '#dcdce6'
        let alpha = 1
        if (hov && hov !== n && !hovConnected.has(n.id)) alpha = 0.15
        if (hasSearch && !searchHighlighted.has(n.id)) alpha *= 0.12

        // Node circle
        ctx.beginPath()
        ctx.arc(sx, sy, r, 0, Math.PI * 2)
        ctx.fillStyle = color.replace(')', `, ${alpha * 0.85})`).replace('rgb', 'rgba')
        // Convert hex to rgba
        const rgba = hexToRgba(color, alpha * 0.85)
        ctx.fillStyle = rgba
        ctx.fill()

        // Border
        const isSelected = sel && sel.id === n.id
        const isHovered = hov && hov.id === n.id
        const [hr, hg, hb] = themeColors.highlight
        const highlightC = `rgba(${hr},${hg},${hb},${alpha})`
        ctx.strokeStyle = isSelected ? highlightC : isHovered ? highlightC : hexToRgba(color, alpha * 0.4)
        ctx.lineWidth = isSelected ? 2.5 : isHovered ? 2 : 1
        ctx.stroke()

        // State node indicator (double border)
        if (n.source === 'state') {
          ctx.beginPath()
          ctx.arc(sx, sy, r + 3, 0, Math.PI * 2)
          ctx.strokeStyle = hexToRgba(color, alpha * 0.3)
          ctx.lineWidth = 1
          ctx.stroke()
        }

        // Connect source glow
        if (connectSource.value && connectSource.value.id === n.id) {
          ctx.beginPath()
          ctx.arc(sx, sy, r + 6, 0, Math.PI * 2)
          const [gr, gg, gb] = themeColors.accent
          ctx.strokeStyle = `rgba(${gr},${gg},${gb},0.6)`
          ctx.lineWidth = 2
          ctx.stroke()
        }

        // Label
        if (showLabels.value && camZoom > 0.4) {
          const fontSize = Math.max(9, 11 * camZoom)
          ctx.font = `500 ${fontSize}px 'DM Sans', sans-serif`
          const [tr, tg, tb] = themeColors.text
          ctx.fillStyle = `rgba(${tr},${tg},${tb},${alpha})`
          ctx.textAlign = 'center'
          ctx.fillText(n.label, sx, sy - r - 4)
        }
      }

      animId = requestAnimationFrame(draw)
    }

    function hexToRgba(hex, a) {
      const h = hex.replace('#', '')
      const r = parseInt(h.substring(0, 2), 16)
      const g = parseInt(h.substring(2, 4), 16)
      const b = parseInt(h.substring(4, 6), 16)
      return `rgba(${r},${g},${b},${a})`
    }

    // ── Canvas sizing ─────────────────────────────────────────────────────
    function resizeCanvas() {
      const canvas = canvasRef.value
      if (!canvas) return
      const parent = canvas.parentElement
      canvasW = parent.clientWidth
      canvasH = parent.clientHeight
      canvas.width = canvasW
      canvas.height = canvasH
    }

    // ── Mouse handlers ────────────────────────────────────────────────────
    function onMouseDown(e) {
      const rect = canvasRef.value.getBoundingClientRect()
      const sx = e.clientX - rect.left, sy = e.clientY - rect.top
      const hit = nodeAt(sx, sy)

      if (mode.value === 'connect' || e.shiftKey) {
        if (hit) {
          if (!connectSource.value) {
            connectSource.value = hit
            connectLine = { sx: hit.x ?? 0, sy: hit.y ?? 0 }
          } else if (hit.id !== connectSource.value.id) {
            doCreateEdge(connectSource.value.id, hit.id)
            connectSource.value = null
            connectLine = null
          }
        }
        return
      }

      if (hit) {
        dragNode = hit
        isDragging = false
        selectedEdge.value = null
      } else {
        isPanning = true
        panStartX = e.clientX
        panStartY = e.clientY
        // Check edge hit
        const edgeHit = edgeAt(sx, sy)
        if (edgeHit) {
          selectedEdge.value = edgeHit
          selectedNode.value = null
          editEdgeLabel.value = edgeHit.label || ''
          editRelationship.value = edgeHit.relationship || 'related_to'
        } else {
          selectedNode.value = null
          selectedEdge.value = null
        }
      }
    }

    function onMouseMove(e) {
      const rect = canvasRef.value.getBoundingClientRect()
      mouseX = e.clientX - rect.left
      mouseY = e.clientY - rect.top

      if (dragNode) {
        isDragging = true
        const [wx, wy] = toWorld(mouseX, mouseY)
        dragNode.x = wx
        dragNode.y = wy
        positionsDirty = true
      } else if (isPanning) {
        const dx = e.clientX - panStartX, dy = e.clientY - panStartY
        camX -= dx / camZoom
        camY -= dy / camZoom
        panStartX = e.clientX
        panStartY = e.clientY
      } else {
        hoveredNode = nodeAt(mouseX, mouseY)
        canvasRef.value.style.cursor = hoveredNode ? 'pointer' : (connectSource.value ? 'crosshair' : 'grab')
      }
    }

    function onMouseUp() {
      if (dragNode) {
        if (!isDragging) {
          // Click (not drag) — select
          selectedNode.value = dragNode
          selectedEdge.value = null
          editLabel.value = dragNode.label || ''
          editType.value = dragNode.type || 'custom'
        } else {
          scheduleSavePositions()
        }
        dragNode = null
        isDragging = false
      }
      isPanning = false
    }

    function onWheel(e) {
      e.preventDefault()
      const factor = e.deltaY > 0 ? 0.9 : 1.1
      const newZoom = Math.max(0.1, Math.min(5, camZoom * factor))
      // Zoom toward mouse
      const [wx, wy] = toWorld(mouseX, mouseY)
      camZoom = newZoom
      camX = wx - (mouseX - canvasW / 2) / camZoom
      camY = wy - (mouseY - canvasH / 2) / camZoom
    }

    function onDblClick(e) {
      const rect = canvasRef.value.getBoundingClientRect()
      const sx = e.clientX - rect.left, sy = e.clientY - rect.top
      const hit = nodeAt(sx, sy)
      if (hit) {
        selectedNode.value = hit
        selectedEdge.value = null
        editLabel.value = hit.label || ''
        editType.value = hit.type || 'custom'
        return
      }
      // Double-click on empty canvas — create node at position
      const [wx, wy] = toWorld(sx, sy)
      doAddNodeAt(wx, wy)
    }

    function onKeyDown(e) {
      if (e.key === 'Delete' || e.key === 'Backspace') {
        // Don't intercept if user is typing in an input
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return
        if (selectedNode.value && selectedNode.value.source !== 'state') {
          doDeleteNode(selectedNode.value.id)
        } else if (selectedEdge.value) {
          doDeleteEdge(selectedEdge.value.id)
        }
      }
      if (e.key === 'Escape') {
        connectSource.value = null
        connectLine = null
        selectedNode.value = null
        selectedEdge.value = null
      }
    }

    // ── API actions ───────────────────────────────────────────────────────
    async function loadGraph() {
      loading.value = true
      try {
        graphData.value = await fetchGraph()
        // Assign random positions to nodes missing x/y
        for (const n of graphData.value.nodes) {
          if (n.x == null) n.x = (Math.random() - 0.5) * 400
          if (n.y == null) n.y = (Math.random() - 0.5) * 400
        }
      } catch (err) {
        if (!String(err).includes('400')) showToast('Failed to load graph: ' + err.message, false)
      }
      loading.value = false
    }

    async function doAddNode() {
      if (!newNodeLabel.value.trim()) return
      try {
        const node = await createGraphNode({
          type: newNodeType.value,
          label: newNodeLabel.value.trim(),
        })
        node.x = (Math.random() - 0.5) * 200
        node.y = (Math.random() - 0.5) * 200
        graphData.value.nodes.push(node)
        newNodeLabel.value = ''
        showToast('Node created')
      } catch (err) { showToast(err.message, false) }
    }

    async function doAddNodeAt(wx, wy) {
      const label = newNodeLabel.value.trim() || 'New node'
      try {
        const node = await createGraphNode({
          type: newNodeType.value,
          label,
          x: wx, y: wy,
        })
        node.x = wx
        node.y = wy
        graphData.value.nodes.push(node)
        selectedNode.value = node
        editLabel.value = node.label
        editType.value = node.type
        showToast('Node created')
      } catch (err) { showToast(err.message, false) }
    }

    async function doCreateEdge(sourceId, targetId) {
      try {
        const edge = await createGraphEdge({
          source: sourceId,
          target: targetId,
          relationship: newEdgeRelationship.value,
          label: newEdgeLabel.value,
        })
        graphData.value.edges.push(edge)
        newEdgeLabel.value = ''
        showToast('Edge created')
      } catch (err) { showToast(err.message, false) }
    }

    async function doUpdateNode() {
      if (!selectedNode.value) return
      try {
        const updates = { label: editLabel.value }
        if (selectedNode.value.source !== 'state') updates.type = editType.value
        const updated = await updateGraphNode(selectedNode.value.id, updates)
        Object.assign(selectedNode.value, updated)
        showToast('Node updated')
      } catch (err) { showToast(err.message, false) }
    }

    async function doUpdateEdge() {
      if (!selectedEdge.value) return
      try {
        const updated = await updateGraphEdge(selectedEdge.value.id, {
          label: editEdgeLabel.value,
          relationship: editRelationship.value,
        })
        Object.assign(selectedEdge.value, updated)
        showToast('Edge updated')
      } catch (err) { showToast(err.message, false) }
    }

    async function doDeleteNode(id) {
      try {
        await deleteGraphNode(id)
        graphData.value.nodes = graphData.value.nodes.filter(n => n.id !== id)
        graphData.value.edges = graphData.value.edges.filter(e => e.source !== id && e.target !== id)
        selectedNode.value = null
        showToast('Node deleted')
      } catch (err) { showToast(err.message, false) }
    }

    async function doDeleteEdge(id) {
      try {
        await deleteGraphEdge(id)
        graphData.value.edges = graphData.value.edges.filter(e => e.id !== id)
        selectedEdge.value = null
        showToast('Edge deleted')
      } catch (err) { showToast(err.message, false) }
    }

    async function doClearGraph() {
      try {
        await clearGraph()
        await loadGraph()
        showToast('Manual nodes cleared')
      } catch (err) { showToast(err.message, false) }
    }

    function scheduleSavePositions() {
      if (positionTimer) clearTimeout(positionTimer)
      positionTimer = setTimeout(async () => {
        if (!positionsDirty) return
        const positions = graphData.value.nodes.map(n => ({ id: n.id, x: n.x ?? 0, y: n.y ?? 0 }))
        try { await saveGraphPositions(positions) } catch {}
        positionsDirty = false
      }, 500)
    }

    function fitView() {
      const nodes = graphData.value.nodes
      if (!nodes.length) { camX = 0; camY = 0; camZoom = 1; return }
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      for (const n of nodes) {
        const x = n.x ?? 0, y = n.y ?? 0
        if (x < minX) minX = x; if (x > maxX) maxX = x
        if (y < minY) minY = y; if (y > maxY) maxY = y
      }
      camX = (minX + maxX) / 2
      camY = (minY + maxY) / 2
      const padded = Math.max(maxX - minX + 100, maxY - minY + 100, 200)
      camZoom = Math.min(canvasW, canvasH) / padded
      camZoom = Math.max(0.2, Math.min(camZoom, 2))
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────
    let resizeObs = null

    onMounted(async () => {
      await nextTick()
      const canvas = canvasRef.value
      if (!canvas) return
      ctx = canvas.getContext('2d')
      resizeCanvas()
      resizeObs = new ResizeObserver(resizeCanvas)
      resizeObs.observe(canvas.parentElement)
      canvas.addEventListener('mousedown', onMouseDown)
      canvas.addEventListener('mousemove', onMouseMove)
      canvas.addEventListener('mouseup', onMouseUp)
      canvas.addEventListener('mouseleave', onMouseUp)
      canvas.addEventListener('wheel', onWheel, { passive: false })
      canvas.addEventListener('dblclick', onDblClick)
      window.addEventListener('keydown', onKeyDown)
      await loadGraph()
      fitView()
      animId = requestAnimationFrame(draw)
    })

    onActivated(async () => {
      await loadGraph()
      resizeCanvas()
      if (!animId) animId = requestAnimationFrame(draw)
    })

    onDeactivated(() => {
      if (animId) { cancelAnimationFrame(animId); animId = null }
      if (positionsDirty) scheduleSavePositions()
    })

    onBeforeUnmount(() => {
      if (animId) { cancelAnimationFrame(animId); animId = null }
      window.removeEventListener('keydown', onKeyDown)
      if (resizeObs) { resizeObs.disconnect(); resizeObs = null }
      if (positionTimer) { clearTimeout(positionTimer); positionTimer = null }
      const canvas = canvasRef.value
      if (canvas) {
        canvas.removeEventListener('mousedown', onMouseDown)
        canvas.removeEventListener('mousemove', onMouseMove)
        canvas.removeEventListener('mouseup', onMouseUp)
        canvas.removeEventListener('mouseleave', onMouseUp)
        canvas.removeEventListener('wheel', onWheel)
        canvas.removeEventListener('dblclick', onDblClick)
      }
    })

    return {
      canvasRef, graphData, loading, mode, showLabels, physicsOn,
      selectedNode, selectedEdge, connectSource,
      newNodeType, newNodeLabel, newEdgeRelationship, newEdgeLabel,
      editLabel, editType, editRelationship, editEdgeLabel,
      nodeCount, edgeCount,
      searchQuery, hiddenTypes, matchCount, toggleType,
      NODE_TYPES, RELATIONSHIP_TYPES,
      doAddNode, doUpdateNode, doDeleteNode, doUpdateEdge, doDeleteEdge,
      doClearGraph, loadGraph, fitView,
    }
  },

  template: `
    <div class="graph-container">
      <!-- Canvas area -->
      <div class="graph-canvas-area">
        <canvas ref="canvasRef"></canvas>

        <!-- Toolbar -->
        <div class="graph-toolbar">
          <button class="btn btn-sm" :class="mode === 'select' ? 'btn-capo' : 'btn-capo-outline'"
            @click="mode = 'select'" title="Select mode">
            <i class="fa-solid fa-arrow-pointer"></i>
          </button>
          <button class="btn btn-sm" :class="mode === 'connect' ? 'btn-capo' : 'btn-capo-outline'"
            @click="mode = 'connect'; connectSource = null" title="Connect mode (or hold Shift)">
            <i class="fa-solid fa-link"></i>
          </button>
          <button class="btn btn-sm" :class="showLabels ? 'btn-capo' : 'btn-capo-outline'"
            @click="showLabels = !showLabels" title="Toggle labels">
            <i class="fa-solid fa-font"></i>
          </button>
          <button class="btn btn-sm" :class="physicsOn ? 'btn-capo' : 'btn-capo-outline'"
            @click="physicsOn = !physicsOn" title="Toggle physics">
            <i class="fa-solid fa-atom"></i>
          </button>
          <button class="btn btn-sm btn-capo-outline" @click="fitView()" title="Fit to view">
            <i class="fa-solid fa-expand"></i>
          </button>
          <button class="btn btn-sm btn-capo-outline" @click="loadGraph()" title="Refresh from state">
            <i class="fa-solid fa-rotate"></i>
          </button>
        </div>

        <!-- Connect mode hint -->
        <div v-if="connectSource" class="graph-hint">
          Click target node to connect — Esc to cancel
        </div>

        <!-- No target message -->
        <div v-if="!loading && nodeCount === 0" class="graph-empty">
          <i class="fa-solid fa-diagram-project" style="font-size:2rem;color:var(--text-dim);"></i>
          <p style="color:var(--text-muted);margin-top:0.5rem;">No target set or empty graph</p>
          <p style="color:var(--text-dim);font-size:0.75rem;">Set a target with <code>capo target set &lt;IP&gt;</code></p>
        </div>
      </div>

      <!-- Right panel -->
      <div class="graph-panel">
        <!-- Search & Filter -->
        <div class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-search me-1"></i> Search
          </h6>
          <input v-model="searchQuery" class="form-control form-control-sm mb-1"
            placeholder="Filter nodes..." style="font-size:0.75rem;" />
          <small v-if="matchCount >= 0" style="color:var(--text-dim);font-size:0.65rem;">
            {{ matchCount }} match{{ matchCount !== 1 ? 'es' : '' }}
          </small>
        </div>

        <div class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-filter me-1"></i> Type Filter
          </h6>
          <div style="display:flex;flex-wrap:wrap;gap:4px;">
            <button v-for="t in NODE_TYPES" :key="t.value"
              class="btn btn-sm"
              :style="{
                background: hiddenTypes.has(t.value) ? 'var(--bg)' : t.color + '22',
                color: hiddenTypes.has(t.value) ? 'var(--text-dim)' : t.color,
                border: '1px solid ' + (hiddenTypes.has(t.value) ? 'var(--border)' : t.color + '44'),
                fontSize: '0.62rem',
                padding: '2px 6px',
                textDecoration: hiddenTypes.has(t.value) ? 'line-through' : 'none',
                opacity: hiddenTypes.has(t.value) ? 0.5 : 1,
              }"
              @click="toggleType(t.value)"
              :title="(hiddenTypes.has(t.value) ? 'Show ' : 'Hide ') + t.label + ' nodes'"
            >{{ t.label }}</button>
          </div>
        </div>

        <hr style="border-color:var(--border);" />

        <!-- Add Node section -->
        <div class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-plus me-1"></i> Add Node
          </h6>
          <select v-model="newNodeType" class="form-select form-select-sm mb-2">
            <option v-for="t in NODE_TYPES" :key="t.value" :value="t.value">
              {{ t.label }}
            </option>
          </select>
          <div class="input-group input-group-sm">
            <input v-model="newNodeLabel" class="form-control" placeholder="Label..."
              @keyup.enter="doAddNode()" />
            <button class="btn btn-capo" @click="doAddNode()" :disabled="!newNodeLabel.trim()">
              Add
            </button>
          </div>
          <small class="text-muted" style="font-size:0.65rem;">Or double-click canvas to place</small>
        </div>

        <!-- Connect settings -->
        <div class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-link me-1"></i> Edge Settings
          </h6>
          <select v-model="newEdgeRelationship" class="form-select form-select-sm mb-1">
            <option v-for="r in RELATIONSHIP_TYPES" :key="r" :value="r">{{ r }}</option>
          </select>
          <input v-model="newEdgeLabel" class="form-control form-control-sm" placeholder="Edge label (optional)" />
        </div>

        <hr style="border-color:var(--border);" />

        <!-- Selected Node -->
        <div v-if="selectedNode" class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-circle-info me-1"></i> Selected Node
          </h6>
          <span v-if="selectedNode.source === 'state'" class="badge bg-secondary mb-2" style="font-size:0.6rem;">
            <i class="fa-solid fa-lock me-1"></i> Auto-synced from state
          </span>
          <div class="mb-2">
            <label class="form-label" style="font-size:0.7rem;color:var(--text-muted);">Label</label>
            <input v-model="editLabel" class="form-control form-control-sm" @blur="doUpdateNode()" @keyup.enter="doUpdateNode()" />
          </div>
          <div v-if="selectedNode.source !== 'state'" class="mb-2">
            <label class="form-label" style="font-size:0.7rem;color:var(--text-muted);">Type</label>
            <select v-model="editType" class="form-select form-select-sm" @change="doUpdateNode()">
              <option v-for="t in NODE_TYPES" :key="t.value" :value="t.value">{{ t.label }}</option>
            </select>
          </div>
          <div v-if="selectedNode.properties && Object.keys(selectedNode.properties).length" class="mb-2">
            <label class="form-label" style="font-size:0.7rem;color:var(--text-muted);">Properties</label>
            <div v-for="(val, key) in selectedNode.properties" :key="key" style="font-size:0.72rem;color:var(--text-dim);">
              <span style="color:var(--accent);">{{ key }}:</span> {{ val }}
            </div>
          </div>
          <button v-if="selectedNode.source !== 'state'" class="btn btn-sm btn-outline-danger w-100 mt-1"
            @click="doDeleteNode(selectedNode.id)">
            <i class="fa-solid fa-trash me-1"></i> Delete Node
          </button>
        </div>

        <!-- Selected Edge -->
        <div v-if="selectedEdge && !selectedNode" class="mb-3">
          <h6 class="text-muted mb-2" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-link me-1"></i> Selected Edge
          </h6>
          <div class="mb-2">
            <label class="form-label" style="font-size:0.7rem;color:var(--text-muted);">Relationship</label>
            <select v-model="editRelationship" class="form-select form-select-sm" @change="doUpdateEdge()">
              <option v-for="r in RELATIONSHIP_TYPES" :key="r" :value="r">{{ r }}</option>
            </select>
          </div>
          <div class="mb-2">
            <label class="form-label" style="font-size:0.7rem;color:var(--text-muted);">Label</label>
            <input v-model="editEdgeLabel" class="form-control form-control-sm" @blur="doUpdateEdge()" @keyup.enter="doUpdateEdge()" />
          </div>
          <button class="btn btn-sm btn-outline-danger w-100 mt-1" @click="doDeleteEdge(selectedEdge.id)">
            <i class="fa-solid fa-trash me-1"></i> Delete Edge
          </button>
        </div>

        <!-- No selection placeholder -->
        <div v-if="!selectedNode && !selectedEdge" class="mb-3" style="color:var(--text-dim);font-size:0.72rem;">
          Click a node or edge to inspect and edit.
        </div>

        <hr style="border-color:var(--border);" />

        <!-- Stats -->
        <div class="graph-stats mb-3">
          <h6 class="text-muted mb-1" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-chart-simple me-1"></i> Graph Stats
          </h6>
          <div>Nodes: <strong>{{ nodeCount }}</strong></div>
          <div>Edges: <strong>{{ edgeCount }}</strong></div>
        </div>

        <!-- Legend -->
        <div class="mb-3">
          <h6 class="text-muted mb-1" style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;">
            <i class="fa-solid fa-palette me-1"></i> Legend
          </h6>
          <div v-for="t in NODE_TYPES" :key="t.value"
            style="display:flex;align-items:center;gap:6px;font-size:0.72rem;margin:2px 0;">
            <span :style="{background:t.color,width:'10px',height:'10px',borderRadius:'50%',display:'inline-block'}"></span>
            <span style="color:var(--text-muted);">{{ t.label }}</span>
          </div>
        </div>

        <!-- Actions -->
        <button class="btn btn-sm btn-capo-outline w-100 mb-2" @click="doClearGraph()">
          <i class="fa-solid fa-eraser me-1"></i> Clear Manual Nodes
        </button>
      </div>
    </div>
  `,
})
