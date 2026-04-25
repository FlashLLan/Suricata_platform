import { useParams, useNavigate } from 'react-router-dom'
import { useEffect, useState, useCallback, useRef, useLayoutEffect } from 'react'
import {
  ReactFlow, Background, Controls, MiniMap,
  addEdge, useNodesState, useEdgesState, SelectionMode,
  type Connection, type Node, type Edge,
  type NodeTypes, type EdgeTypes, type NodeChange, type EdgeChange,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowLeft, Save, Play, ChevronDown, ChevronUp, AlertTriangle, Download, FileSearch } from 'lucide-react'

import { getProject, updateProject, type Project } from '../api/projects'
import { useAuthStore } from '../store/authStore'
import { getEdgeKind, type EdgeKind } from '../utils/edgeSemantics'

import DeviceNode from '../components/lab/DeviceNode'
import DevicePalette from '../components/lab/DevicePalette'
import DeviceConfigPanel from '../components/lab/DeviceConfigPanel'
import RuleLibraryPanel from '../components/lab/RuleLibraryPanel'
import SimulationModal from '../components/lab/SimulationModal'
import ExportModal from '../components/lab/ExportModal'
import PcapImportModal from '../components/lab/PcapImportModal'
import AnimatedPacketEdge from '../components/lab/AnimatedPacketEdge'

import type { DeviceData, DeviceType, ActiveRule, RuleEntry, SimulationRun } from '../types/lab'
import { PREDEFINED_RULES } from '../data/rules'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Snapshot {
  nodes: Node[]
  edges: Edge[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

const NODE_TYPES: NodeTypes = { device: DeviceNode }
const EDGE_TYPES: EdgeTypes = { 'animated-packet': AnimatedPacketEdge as never }

const EDGE_STYLES: Record<EdgeKind, Pick<Edge, 'style' | 'animated' | 'labelStyle' | 'labelBgStyle'> & { labelBgPadding?: [number, number] }> = {
  'same-zone':  { style: { stroke: '#6366f1', strokeWidth: 2 }, animated: false },
  'cross-zone': { style: { stroke: '#f59e0b', strokeWidth: 2 }, animated: false, labelStyle: { fill: '#f59e0b', fontSize: 10, fontWeight: 600 }, labelBgStyle: { fill: '#1f1200', fillOpacity: 0.8 }, labelBgPadding: [4, 2] },
  'attack':     { style: { stroke: '#ef4444', strokeWidth: 2, strokeDasharray: '6 3' }, animated: true,  labelStyle: { fill: '#ef4444', fontSize: 10, fontWeight: 600 }, labelBgStyle: { fill: '#1f0000', fillOpacity: 0.8 }, labelBgPadding: [4, 2] },
  'monitoring': { style: { stroke: '#a855f7', strokeWidth: 1.5, strokeDasharray: '6 3' }, animated: true },
  'blocked':    { style: { stroke: '#dc2626', strokeWidth: 1, strokeDasharray: '4 4' }, animated: false },
  'no-route':   { style: { stroke: '#06b6d4', strokeWidth: 1.5, strokeDasharray: '3 5' }, animated: false, labelStyle: { fill: '#06b6d4', fontSize: 10, fontWeight: 600 }, labelBgStyle: { fill: '#001a1f', fillOpacity: 0.85 }, labelBgPadding: [4, 2] },
}

// ─── Default topology ─────────────────────────────────────────────────────────

function makeDeviceNode(deviceType: DeviceType, position: { x: number; y: number }, id: string): Node {
  const defaults: Record<DeviceType, Partial<DeviceData>> = {
    workstation:  { label: 'Workstation',  ip: '192.168.1.10', zone: 'internal',   ports: '22,3389' },
    server:       { label: 'Server',       ip: '192.168.1.20', zone: 'internal',   ports: '22,80' },
    'web-server': { label: 'Web Server',   ip: '192.168.1.30', zone: 'dmz',        ports: '80,443' },
    database:     { label: 'Database',     ip: '192.168.1.40', zone: 'internal',   ports: '3306,5432' },
    router:       { label: 'Router',       ip: '192.168.1.1',  zone: 'internal',   ports: '' },
    firewall:     { label: 'Firewall',     ip: '192.168.1.2',  zone: 'management', ports: '' },
    attacker:     { label: 'Attacker',     ip: '203.0.113.10', zone: 'external',   ports: '' },
    'dns-server': { label: 'DNS Server',   ip: '192.168.1.53', zone: 'internal',   ports: '53' },
    'mail-server':{ label: 'Mail Server',  ip: '192.168.1.25', zone: 'dmz',        ports: '25,465,993' },
    ids:          { label: 'Suricata IDS', ip: '192.168.1.5',  zone: 'management', ports: '' },
  }
  const data: DeviceData = {
    label: '', deviceType, ip: '', ipClass: 'C', subnet: '192.168.1.0/24',
    ports: '', os: '', zone: 'internal', notes: '',
    selectedAttacks: [], customAttackCommands: '',
    noDefense: false, enabledDefenses: [], customDefenseConfig: '',
    selectedRuleIds: [],
    customRules: [],
    ...defaults[deviceType],
  }
  return { id, type: 'device', position, data: data as unknown as Record<string, unknown> }
}

const INITIAL_NODES: Node[] = [
  makeDeviceNode('workstation',  { x: 150, y: 160 }, 'node-1'),
  makeDeviceNode('web-server',   { x: 420, y: 80  }, 'node-2'),
  makeDeviceNode('ids',          { x: 420, y: 280 }, 'node-3'),
  makeDeviceNode('router',       { x: 680, y: 160 }, 'node-4'),
]

const INITIAL_EDGES: Edge[] = [
  { id: 'e1-3', source: 'node-1', target: 'node-3', ...EDGE_STYLES['monitoring'],
    data: { edgeKind: 'monitoring', monitoringOnly: true,  communicationAllowed: false, crossZone: false } },
  { id: 'e2-3', source: 'node-2', target: 'node-3', ...EDGE_STYLES['monitoring'],
    data: { edgeKind: 'monitoring', monitoringOnly: true,  communicationAllowed: false, crossZone: false } },
  { id: 'e3-4', source: 'node-3', target: 'node-4', ...EDGE_STYLES['cross-zone'], label: 'internal → management',
    data: { edgeKind: 'cross-zone', monitoringOnly: false, communicationAllowed: true,  crossZone: true  } },
]

let nodeIdCounter = 100

// ─── Component ────────────────────────────────────────────────────────────────

export default function LabPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { logout } = useAuthStore()

  const [project, setProject] = useState<Project | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<string | null>(null)
  const [isDirty, setIsDirty] = useState(false)
  const isLoaded = useRef(false)   // true once the project data has been restored into state
  const autosaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ── Inline project rename ────────────────────────────────────────────────
  const [isEditingName, setIsEditingName] = useState(false)
  const [editName, setEditName] = useState('')
  const nameInputRef = useRef<HTMLInputElement>(null)

  const [nodes, setNodes, onNodesChange] = useNodesState(INITIAL_NODES)
  const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES)
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)

  const [activeRules, setActiveRules] = useState<ActiveRule[]>([])
  const [rulesOpen, setRulesOpen] = useState(true)
  const [showSim, setShowSim] = useState(false)
  const [showPcap, setShowPcap] = useState(false)
  const [simHistory, setSimHistory] = useState<SimulationRun[]>([])
  const simHistoryRef = useRef<SimulationRun[]>([])
  const [showExport, setShowExport] = useState(false)
  const [connectionWarning, setConnectionWarning] = useState<string | null>(null)
  const [isPanning, setIsPanning] = useState(false)
  // Edge IDs that are animating during simulation (to restore them afterward)
  const animatingEdgeIds = useRef<string[]>([])

  // ── Rules panel resize ────────────────────────────────────────────────────
  const [rulesPanelH, setRulesPanelH] = useState(240)
  const rulesDrag = useRef<{ startY: number; startH: number } | null>(null)

  useLayoutEffect(() => {
    function onMove(e: MouseEvent) {
      if (!rulesDrag.current) return
      const delta = rulesDrag.current.startY - e.clientY
      setRulesPanelH(Math.max(120, Math.min(560, rulesDrag.current.startH + delta)))
    }
    function onUp() { rulesDrag.current = null }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [])

  function onRulesHandleMouseDown(e: React.MouseEvent) {
    e.preventDefault()
    rulesDrag.current = { startY: e.clientY, startH: rulesPanelH }
  }

  // ── Undo history ──────────────────────────────────────────────────────────
  const history = useRef<Snapshot[]>([{ nodes: INITIAL_NODES, edges: INITIAL_EDGES }])
  const historyPtr = useRef(0)

  // Always-current refs so saveSnapshot doesn't capture stale closures
  const nodesRef = useRef<Node[]>(INITIAL_NODES)
  const edgesRef = useRef<Edge[]>(INITIAL_EDGES)
  useEffect(() => { nodesRef.current = nodes }, [nodes])
  useEffect(() => { edgesRef.current = edges }, [edges])

  const saveSnapshot = useCallback(() => {
    const snapshot: Snapshot = {
      nodes: nodesRef.current.map(n => ({ ...n })),
      edges: edgesRef.current.map(e => ({ ...e })),
    }
    // Truncate any redo future
    history.current = history.current.slice(0, historyPtr.current + 1)
    history.current.push(snapshot)
    historyPtr.current = history.current.length - 1
  }, [])

  const undo = useCallback(() => {
    if (historyPtr.current <= 0) return
    historyPtr.current--
    const snap = history.current[historyPtr.current]
    setNodes(snap.nodes)
    setEdges(snap.edges)
    setSelectedNode(null)
  }, [setNodes, setEdges])

  // Ctrl+Z listener
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
        e.preventDefault()
        undo()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [undo])

  // Intercept remove changes to save snapshot before deleting
  const handleNodesChange = useCallback((changes: NodeChange[]) => {
    if (changes.some(c => c.type === 'remove')) saveSnapshot()
    onNodesChange(changes)
  }, [onNodesChange, saveSnapshot])

  const handleEdgesChange = useCallback((changes: EdgeChange[]) => {
    if (changes.some(c => c.type === 'remove')) saveSnapshot()
    onEdgesChange(changes)
  }, [onEdgesChange, saveSnapshot])

  // ── React Flow wiring ─────────────────────────────────────────────────────
  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [rfInstance, setRfInstance] = useState<{
    screenToFlowPosition: (p: { x: number; y: number }) => { x: number; y: number }
  } | null>(null)

  // Validate connection while user is dragging (shows green/red handle)
  const isValidConnection = useCallback((conn: Connection) => {
    if (conn.source === conn.target) return false
    const src = nodesRef.current.find(n => n.id === conn.source)
    const tgt = nodesRef.current.find(n => n.id === conn.target)
    if (!src || !tgt) return false
    const { kind } = getEdgeKind(
      src.data as unknown as DeviceData,
      tgt.data as unknown as DeviceData,
    )
    return kind !== 'blocked'
  }, [])

  const onConnect = useCallback((connection: Connection) => {
    const src = nodesRef.current.find(n => n.id === connection.source)
    const tgt = nodesRef.current.find(n => n.id === connection.target)
    if (!src || !tgt) return

    const { kind, label, warning, monitoringOnly, communicationAllowed, crossZone } = getEdgeKind(
      src.data as unknown as DeviceData,
      tgt.data as unknown as DeviceData,
    )

    if (kind === 'blocked') {
      setConnectionWarning((tgt.data as unknown as DeviceData).deviceType === 'database'
        ? 'Blocked: Database must not be directly exposed to the external zone.'
        : 'Connection blocked by topology rules.')
      setTimeout(() => setConnectionWarning(null), 4000)
      return
    }

    if (warning) {
      setConnectionWarning(warning)
      setTimeout(() => setConnectionWarning(null), 5000)
    }

    saveSnapshot()

    const edgeStyle = EDGE_STYLES[kind]
    setEdges(eds => addEdge({
      ...connection,
      ...edgeStyle,
      ...(label ? { label } : {}),
      data: {
        edgeKind: kind,
        monitoringOnly,
        communicationAllowed,
        crossZone,
      },
    }, eds))
  }, [saveSnapshot, setEdges])

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    const deviceType = e.dataTransfer.getData('application/device-type') as DeviceType
    if (!deviceType || !rfInstance || !reactFlowWrapper.current) return

    const bounds = reactFlowWrapper.current.getBoundingClientRect()
    const position = rfInstance.screenToFlowPosition({
      x: e.clientX - bounds.left,
      y: e.clientY - bounds.top,
    })

    saveSnapshot()
    nodeIdCounter++
    setNodes(nds => [...nds, makeDeviceNode(deviceType, position, `node-${nodeIdCounter}`)])
  }, [rfInstance, setNodes, saveSnapshot])

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
  }, [])

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node)
  }, [])

  const onPaneClick = useCallback(() => setSelectedNode(null), [])

  // ── Dirty tracking — mark unsaved after any canvas / rule change ─────────
  useEffect(() => {
    if (!isLoaded.current) return   // ignore state changes during initial restore
    setIsDirty(true)
    // Debounced autosave: 4 s after last change
    if (autosaveTimer.current) clearTimeout(autosaveTimer.current)
    autosaveTimer.current = setTimeout(() => {
      autosaveTimer.current = null
      // handleSave reads project, nodes, edges, activeRules via closure — but those
      // close over stale values in a plain function. We use refs to stay current.
      doSave()
    }, 4000)
    return () => {
      if (autosaveTimer.current) clearTimeout(autosaveTimer.current)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, activeRules])

  // ── Save on browser/tab close ─────────────────────────────────────────────
  useEffect(() => {
    function onBeforeUnload(e: BeforeUnloadEvent) {
      if (!isDirty) return
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [isDirty])

  // ── Project load ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (!id) return
    getProject(Number(id))
      .then((p) => {
        setProject(p)
        try {
          const topo = JSON.parse(p.topology_json || '{}')
          if (topo.nodes?.length) { setNodes(topo.nodes); nodesRef.current = topo.nodes }
          if (topo.edges?.length) {
            // Re-apply edge styles from node data so stale saved styles are corrected.
            const nodeMap = new Map((topo.nodes ?? []).map((n: Node) => [n.id, n]))
            const reStyled = (topo.edges as Edge[]).map(e => {
              const src = nodeMap.get(e.source)
              const tgt = nodeMap.get(e.target)
              if (!src || !tgt) return e
              const { kind, label, monitoringOnly, communicationAllowed, crossZone } =
                getEdgeKind(src.data as unknown as DeviceData, tgt.data as unknown as DeviceData)
              return {
                ...e,
                ...EDGE_STYLES[kind],
                ...(label ? { label } : {}),
                data: { edgeKind: kind, monitoringOnly, communicationAllowed, crossZone },
              }
            })
            setEdges(reStyled); edgesRef.current = reStyled
          }
          history.current = [{ nodes: topo.nodes ?? INITIAL_NODES, edges: topo.edges ?? INITIAL_EDGES }]
          historyPtr.current = 0
        } catch { /* use defaults */ }
        try {
          const rules = JSON.parse(p.rules_json || '[]') as string[]
          if (rules.length) {
            const loaded: ActiveRule[] = rules
              .map((sid) => PREDEFINED_RULES.find(r => r.sid === sid))
              .filter(Boolean)
              .map(entry => ({ entry: entry! }))
            setActiveRules(loaded)
          }
        } catch { /* ignore */ }
        try {
          const sim = JSON.parse(p.simulation_json || '{}')
          if (Array.isArray(sim.runs)) {
            setSimHistory(sim.runs)
            simHistoryRef.current = sim.runs
          }
        } catch { /* ignore */ }
        // Mark load complete — dirty tracking starts from here
        setTimeout(() => { isLoaded.current = true }, 0)
      })
      .catch(() => navigate('/dashboard'))
      .finally(() => setLoading(false))
  }, [id, navigate, setEdges, setNodes])

  // ── Save ──────────────────────────────────────────────────────────────────
  // Refs so autosave callback always reads the latest values
  const projectRef = useRef<typeof project>(null)
  const activeRulesRef = useRef(activeRules)
  useEffect(() => { projectRef.current = project }, [project])
  useEffect(() => { activeRulesRef.current = activeRules }, [activeRules])
  useEffect(() => { simHistoryRef.current = simHistory }, [simHistory])

  async function doSave() {
    const p = projectRef.current
    if (!p) return
    setSaving(true)
    try {
      await updateProject(p.id, {
        topology_json: JSON.stringify({ nodes: nodesRef.current, edges: edgesRef.current }),
        rules_json: JSON.stringify(activeRulesRef.current.map(r => r.entry.sid)),
      })
      setSavedAt(new Date().toLocaleTimeString())
      setIsDirty(false)
    } finally {
      setSaving(false)
    }
  }

  async function handleSave() {
    if (autosaveTimer.current) { clearTimeout(autosaveTimer.current); autosaveTimer.current = null }
    await doSave()
  }

  // ── PCAP topology import ──────────────────────────────────────────────────
  function handleLoadTopology(topology: { nodes: object[]; edges: object[] }) {
    const importedNodes = (topology.nodes as Node[])
    const importedEdges = (topology.edges as Edge[]).map(e => {
      const src = importedNodes.find(n => n.id === e.source)
      const tgt = importedNodes.find(n => n.id === e.target)
      if (!src || !tgt) return e
      const { kind, label, monitoringOnly, communicationAllowed, crossZone } =
        getEdgeKind(src.data as unknown as DeviceData, tgt.data as unknown as DeviceData)
      return {
        ...e,
        ...EDGE_STYLES[kind],
        ...(label ? { label } : {}),
        data: { edgeKind: kind, monitoringOnly, communicationAllowed, crossZone },
      }
    })
    saveSnapshot()
    setNodes(importedNodes)
    setEdges(importedEdges)
    nodesRef.current = importedNodes
    edgesRef.current = importedEdges
  }

  const handleRunSaved = useCallback(async (run: SimulationRun) => {
    const updated = [run, ...simHistoryRef.current].slice(0, 50)
    setSimHistory(updated)
    simHistoryRef.current = updated
    if (projectRef.current) {
      await updateProject(projectRef.current.id, {
        simulation_json: JSON.stringify({ runs: updated }),
      }).catch(() => {})
    }
  }, [])

  // ── Rename project ────────────────────────────────────────────────────────
  function startRename() {
    if (!project) return
    setEditName(project.name)
    setIsEditingName(true)
    setTimeout(() => nameInputRef.current?.select(), 0)
  }

  async function commitRename() {
    const trimmed = editName.trim()
    setIsEditingName(false)
    if (!trimmed || !project || trimmed === project.name) return
    const updated = await updateProject(project.id, { name: trimmed })
    setProject(updated)
  }

  // ── Node config update ────────────────────────────────────────────────────
  function updateNodeData(nodeId: string, data: DeviceData) {
    saveSnapshot()
    setNodes(nds => nds.map(n =>
      n.id === nodeId ? { ...n, data: data as unknown as Record<string, unknown> } : n
    ))
    setSelectedNode(prev =>
      prev?.id === nodeId ? { ...prev, data: data as unknown as Record<string, unknown> } : prev
    )
  }

  // ── Rule management ───────────────────────────────────────────────────────
  function addRule(entry: RuleEntry) {
    if (activeRules.some(r => r.entry.id === entry.id)) return
    setActiveRules(prev => [...prev, { entry }])
  }

  function removeRule(ruleId: string) {
    setActiveRules(prev => prev.filter(r => r.entry.id !== ruleId))
  }

  function addCustomRule(text: string) {
    const customEntry: RuleEntry = {
      id: `custom-${Date.now()}`,
      sid: '9999999',
      category: 'custom',
      difficulty: 'intermediate',
      msg: 'Custom Rule',
      rule: text,
      explanation: 'User-defined custom Suricata rule.',
    }
    setActiveRules(prev => [...prev, { entry: customEntry, customText: text }])
  }

  // ── Simulation animation ──────────────────────────────────────────────────

  /**
   * Called when the simulation result arrives.
   * Finds edges along the attack path and switches them to the animated-packet type.
   */
  function handleSimulationStart(packetRate: number, attackPath: string[][], nftablesBlockedAt?: string) {
    // Build a reverse map: ip → node id
    const ipToNodeId: Record<string, string> = {}
    for (const node of nodesRef.current) {
      const ip = (node.data as unknown as DeviceData).ip
      if (ip) ipToNodeId[ip] = node.id
    }

    // Flash the firewall node red when it blocked the attack
    if (nftablesBlockedAt) {
      const fwNodeId = ipToNodeId[nftablesBlockedAt]
      if (fwNodeId) {
        setNodes(nds => nds.map(n =>
          n.id === fwNodeId ? { ...n, data: { ...n.data, flashBlocked: true } } : n
        ))
        setTimeout(() => {
          setNodes(nds => nds.map(n =>
            n.id === fwNodeId ? { ...n, data: { ...n.data, flashBlocked: false } } : n
          ))
        }, 2500)
      }
    }

    // Attack path edges — animated red packets
    const attackEdgeIds = new Set<string>()
    // Collect all node IDs on the attack path (to find connected IDS monitoring edges)
    const pathNodeIds = new Set<string>()

    for (const [srcIp, dstIp] of attackPath) {
      const srcId = ipToNodeId[srcIp]
      const dstId = ipToNodeId[dstIp]
      if (srcId) pathNodeIds.add(srcId)
      if (dstId) pathNodeIds.add(dstId)
      if (!srcId || !dstId) continue
      for (const edge of edgesRef.current) {
        if (
          (edge.source === srcId && edge.target === dstId) ||
          (edge.source === dstId && edge.target === srcId)
        ) {
          attackEdgeIds.add(edge.id)
        }
      }
    }

    if (attackEdgeIds.size === 0) return

    // IDS monitoring edges connected to any node on the attack path — pulse purple
    const monitorEdgeIds = new Set<string>()
    for (const edge of edgesRef.current) {
      if (edge.data?.edgeKind === 'monitoring' &&
          (pathNodeIds.has(edge.source) || pathNodeIds.has(edge.target))) {
        monitorEdgeIds.add(edge.id)
      }
    }

    animatingEdgeIds.current = [...attackEdgeIds, ...monitorEdgeIds]

    setEdges(eds => eds.map(e => {
      if (attackEdgeIds.has(e.id)) {
        return { ...e, type: 'animated-packet', data: { ...(e.data ?? {}), packetRate, active: true } }
      }
      if (monitorEdgeIds.has(e.id)) {
        // Keep monitoring style but mark active so the edge knows simulation is running
        return { ...e, data: { ...(e.data ?? {}), active: true, packetRate: Math.max(1, Math.round(packetRate / 3)) } }
      }
      return e
    }))
  }

  /** Called when the simulation modal closes — restore edges to normal. */
  function handleSimulationEnd() {
    const ids = new Set(animatingEdgeIds.current)
    if (ids.size === 0) return
    animatingEdgeIds.current = []

    setEdges(eds => eds.map(e => {
      if (!ids.has(e.id)) return e
      // Restore to the edge's original kind style (stored in edge.data.edgeKind)
      const edgeKind = (e.data?.edgeKind as EdgeKind | undefined) ?? 'attack'
      const originalStyle = EDGE_STYLES[edgeKind] ?? EDGE_STYLES['attack']
      return {
        ...e,
        type: undefined,
        data: { ...(e.data ?? {}), active: false },
        ...originalStyle,
      }
    }))
  }

  // ─────────────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400 text-sm">
        Loading lab…
      </div>
    )
  }

  const RULE_PANEL_H = rulesOpen ? rulesPanelH : 36

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-white overflow-hidden">

      {/* ── Top bar ── */}
      <header className="flex-shrink-0 h-11 bg-gray-900 border-b border-gray-800 flex items-center px-3 gap-3">
        <button
          onClick={() => {
            if (isDirty && !window.confirm('You have unsaved changes. Leave without saving?')) return
            navigate('/dashboard')
          }}
          className="text-gray-400 hover:text-white transition p-1"
        >
          <ArrowLeft size={16} />
        </button>
        <div className="w-px h-5 bg-gray-700" />
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-indigo-600 flex items-center justify-center flex-shrink-0">
            <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          {isEditingName ? (
            <input
              ref={nameInputRef}
              value={editName}
              onChange={e => setEditName(e.target.value)}
              onBlur={commitRename}
              onKeyDown={e => {
                if (e.key === 'Enter') { e.currentTarget.blur() }
                if (e.key === 'Escape') { setIsEditingName(false) }
              }}
              className="bg-gray-800 border border-indigo-600 rounded px-2 py-0.5 text-sm font-semibold text-white focus:outline-none w-48"
            />
          ) : (
            <button
              onClick={startRename}
              title="Click to rename"
              className="text-sm font-semibold text-white truncate max-w-[200px] hover:text-indigo-300 transition text-left"
            >
              {project?.name}
            </button>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {isDirty
            ? <span className="text-xs text-amber-500/80 hidden sm:block">Unsaved changes</span>
            : savedAt
              ? <span className="text-xs text-gray-600 hidden sm:block">Saved {savedAt}</span>
              : null
          }
          <button
            onClick={handleSave}
            disabled={saving}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition disabled:opacity-50 ${
              isDirty
                ? 'bg-indigo-700 hover:bg-indigo-600 border-indigo-600 text-white'
                : 'bg-gray-800 hover:bg-gray-700 border-gray-700 text-gray-300'
            }`}
          >
            <Save size={13} />
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={() => setShowPcap(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 hover:text-white text-xs font-medium rounded-lg transition"
            title="Import and analyze a .pcap file"
          >
            <FileSearch size={13} />
            Import PCAP
          </button>
          <button
            onClick={() => setShowSim(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
          >
            <Play size={13} />
            Run Simulation
          </button>
          <button
            onClick={() => { logout(); navigate('/login') }}
            className="text-xs text-gray-600 hover:text-gray-400 transition hidden sm:block"
          >
            Sign out
          </button>
        </div>
      </header>

      {/* ── Main area ── */}
      <div
        className="flex-1 flex overflow-hidden"
        style={{ height: `calc(100vh - 44px - ${RULE_PANEL_H}px)` }}
      >
        {/* Left: device palette */}
        <aside className="w-44 flex-shrink-0 bg-gray-900 border-r border-gray-800 overflow-y-auto">
          <DevicePalette />
        </aside>

        {/* Canvas */}
        <div
          ref={reactFlowWrapper}
          className="flex-1 relative"
          onDrop={onDrop}
          onDragOver={onDragOver}
          onMouseDown={(e) => { if (e.button === 2) setIsPanning(true) }}
          onMouseUp={() => setIsPanning(false)}
          onMouseLeave={() => setIsPanning(false)}
        >
          {isPanning && (
            <style>{'.react-flow__pane { cursor: grabbing !important; }'}</style>
          )}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={handleNodesChange}
            onEdgesChange={handleEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onInit={setRfInstance as never}
            isValidConnection={isValidConnection}
            nodeTypes={NODE_TYPES}
            edgeTypes={EDGE_TYPES}
            fitView
            deleteKeyCode="Delete"
            panOnDrag={[2]}
            selectionOnDrag
            selectionMode={SelectionMode.Partial}
            onContextMenu={(e) => e.preventDefault()}
            style={{ background: '#0a0b0f' }}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1a1f2e" gap={24} size={1} />
            <Controls className="[&>button]:bg-gray-800 [&>button]:border-gray-700 [&>button]:text-gray-300 !bottom-8" />
            <MiniMap
              nodeColor="#6366f1"
              maskColor="rgba(0,0,0,0.7)"
              style={{ background: '#111827', border: '1px solid #1f2937' }}
            />
          </ReactFlow>

          {/* Connection warning toast */}
          {connectionWarning && (
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-2 bg-yellow-900/90 border border-yellow-700 text-yellow-200 text-xs rounded-xl px-4 py-2.5 shadow-xl max-w-sm text-center backdrop-blur-sm z-10">
              <AlertTriangle size={14} className="flex-shrink-0 text-yellow-400" />
              {connectionWarning}
            </div>
          )}

          {/* Hint bar */}
          <div className="absolute bottom-0 left-0 right-0 flex items-center gap-4 px-3 py-1 bg-gray-900/80 border-t border-gray-800/60 text-[10px] text-gray-600">
            <span>Drag from palette to add · Left-drag to select area · Right-drag to pan · Click node to configure · Delete removes selection · <kbd className="bg-gray-800 px-1 rounded">Ctrl+Z</kbd> to undo</span>
            <span className="ml-auto flex items-center gap-3">
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-indigo-500 inline-block" /> same zone</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-amber-500 inline-block" /> cross-zone</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-red-500 inline-block" /> attack path</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-purple-500 inline-block" style={{ borderTop: '1px dashed #a855f7' }} /> monitor</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-cyan-500 inline-block" style={{ borderTop: '1px dashed #06b6d4' }} /> no route</span>
            </span>
          </div>
        </div>

        {/* Right: device config */}
        {selectedNode && (
          <DeviceConfigPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            onUpdate={updateNodeData}
          />
        )}
      </div>

      {/* ── Bottom: Rule panel ── */}
      <div className="flex-shrink-0 border-t border-gray-800" style={{ height: RULE_PANEL_H }}>
        {/* Resize handle — drag up/down to resize the panel */}
        {rulesOpen && (
          <div
            className="h-1.5 cursor-ns-resize flex items-center justify-center group bg-gray-900 hover:bg-indigo-950/40 transition-colors border-b border-gray-800/60"
            onMouseDown={onRulesHandleMouseDown}
          >
            <div className="w-8 h-0.5 rounded-full bg-gray-700 group-hover:bg-indigo-500 transition-colors" />
          </div>
        )}

        <div
          className="w-full flex items-center justify-between px-4 bg-gray-900 hover:bg-gray-800 transition border-b border-gray-800 text-xs text-gray-400 cursor-pointer select-none"
          style={{ height: 30 }}
          onClick={() => setRulesOpen(!rulesOpen)}
        >
          <span className="font-medium">
            Rules
            {activeRules.length > 0 && (
              <span className="ml-2 px-1.5 py-0.5 bg-indigo-900/60 text-indigo-300 rounded text-[10px]">
                {activeRules.length} active
              </span>
            )}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={e => { e.stopPropagation(); setShowExport(true) }}
              className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-gray-400 hover:text-indigo-300 hover:bg-indigo-950/40 border border-transparent hover:border-indigo-800/40 transition"
              title="Export rules and environment config"
            >
              <Download size={10} />
              Export
            </button>
            {rulesOpen ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
          </div>
        </div>

        {rulesOpen && (
          <div style={{ height: RULE_PANEL_H - 36 }} className="overflow-hidden">
            <RuleLibraryPanel
              activeRules={activeRules}
              onAdd={addRule}
              onRemove={removeRule}
              onAddCustom={addCustomRule}
            />
          </div>
        )}
      </div>

      {/* Export modal */}
      {showExport && project && (
        <ExportModal
          projectName={project.name}
          activeRules={activeRules}
          nodes={nodes}
          edges={edges}
          onClose={() => setShowExport(false)}
        />
      )}

      {/* PCAP import modal */}
      {showPcap && (
        <PcapImportModal
          activeRules={activeRules}
          onClose={() => setShowPcap(false)}
          onLoadTopology={handleLoadTopology}
        />
      )}

      {/* Simulation modal */}
      {showSim && project && (
        <SimulationModal
          projectId={project.id}
          activeRules={activeRules}
          nodes={nodes}
          edges={edges}
          onClose={() => setShowSim(false)}
          onSimulationStart={handleSimulationStart}
          onSimulationEnd={handleSimulationEnd}
          simHistory={simHistory}
          onRunSaved={handleRunSaved}
        />
      )}
    </div>
  )
}
