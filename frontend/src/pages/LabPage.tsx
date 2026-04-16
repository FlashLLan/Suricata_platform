import { useParams, useNavigate } from 'react-router-dom'
import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ReactFlow, Background, Controls, MiniMap,
  addEdge, useNodesState, useEdgesState,
  type Connection, type Node, type NodeTypes,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowLeft, Save, Play, ChevronDown, ChevronUp } from 'lucide-react'

import { getProject, updateProject, type Project } from '../api/projects'
import { useAuthStore } from '../store/authStore'

import DeviceNode from '../components/lab/DeviceNode'
import DevicePalette from '../components/lab/DevicePalette'
import DeviceConfigPanel from '../components/lab/DeviceConfigPanel'
import RuleLibraryPanel from '../components/lab/RuleLibraryPanel'
import SimulationModal from '../components/lab/SimulationModal'

import type { DeviceData, DeviceType, ActiveRule, RuleEntry } from '../types/lab'
import { PREDEFINED_RULES } from '../data/rules'

// Register custom node type
const NODE_TYPES: NodeTypes = { device: DeviceNode }

function makeDeviceNode(deviceType: DeviceType, position: { x: number; y: number }, id: string): Node {
  const defaults: Record<DeviceType, Partial<DeviceData>> = {
    workstation:  { label: 'Workstation',  ip: '192.168.1.10', zone: 'internal', ports: '22,3389' },
    server:       { label: 'Server',       ip: '192.168.1.20', zone: 'internal', ports: '22,80' },
    'web-server': { label: 'Web Server',   ip: '192.168.1.30', zone: 'dmz',      ports: '80,443' },
    database:     { label: 'Database',     ip: '192.168.1.40', zone: 'internal', ports: '3306,5432' },
    router:       { label: 'Router',       ip: '192.168.1.1',  zone: 'internal', ports: '' },
    firewall:     { label: 'Firewall',     ip: '192.168.1.2',  zone: 'management', ports: '' },
    attacker:     { label: 'Attacker',     ip: '203.0.113.10', zone: 'external', ports: '' },
    'dns-server': { label: 'DNS Server',   ip: '192.168.1.53', zone: 'internal', ports: '53' },
    'mail-server':{ label: 'Mail Server',  ip: '192.168.1.25', zone: 'dmz',      ports: '25,465,993' },
    ids:          { label: 'Suricata IDS', ip: '192.168.1.5',  zone: 'management', ports: '' },
  }

  const data: DeviceData = {
    label: '', deviceType, ip: '', subnet: '192.168.1.0/24',
    ports: '', os: '', zone: 'internal', notes: '',
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

const INITIAL_EDGES = [
  { id: 'e1-3', source: 'node-1', target: 'node-3', animated: true, style: { stroke: '#6366f1' } },
  { id: 'e2-3', source: 'node-2', target: 'node-3', animated: true, style: { stroke: '#6366f1' } },
  { id: 'e3-4', source: 'node-3', target: 'node-4' },
]

let nodeIdCounter = 100

export default function LabPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { logout } = useAuthStore()

  const [project, setProject] = useState<Project | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<string | null>(null)

  const [nodes, setNodes, onNodesChange] = useNodesState(INITIAL_NODES)
  const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES)
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)

  const [activeRules, setActiveRules] = useState<ActiveRule[]>([])
  const [rulesOpen, setRulesOpen] = useState(true)
  const [showSim, setShowSim] = useState(false)

  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [rfInstance, setRfInstance] = useState<{ screenToFlowPosition: (p: { x: number; y: number }) => { x: number; y: number } } | null>(null)

  const onConnect = useCallback((connection: Connection) => {
    setEdges((eds) => addEdge({ ...connection, animated: false }, eds))
  }, [setEdges])

  // Load project
  useEffect(() => {
    if (!id) return
    getProject(Number(id))
      .then((p) => {
        setProject(p)
        try {
          const topo = JSON.parse(p.topology_json || '{}')
          if (topo.nodes?.length) setNodes(topo.nodes)
          if (topo.edges?.length) setEdges(topo.edges)
        } catch { /* use defaults */ }
        try {
          const rules = JSON.parse(p.rules_json || '[]') as string[]
          if (rules.length) {
            const loaded: ActiveRule[] = rules.map((sid) => {
              const entry = PREDEFINED_RULES.find((r) => r.sid === sid)
              return entry ? { entry } : null
            }).filter(Boolean) as ActiveRule[]
            setActiveRules(loaded)
          }
        } catch { /* ignore */ }
      })
      .catch(() => navigate('/dashboard'))
      .finally(() => setLoading(false))
  }, [id, navigate, setEdges, setNodes])

  async function handleSave() {
    if (!project) return
    setSaving(true)
    try {
      await updateProject(project.id, {
        topology_json: JSON.stringify({ nodes, edges }),
        rules_json: JSON.stringify(activeRules.map((r) => r.entry.sid)),
      })
      setSavedAt(new Date().toLocaleTimeString())
    } finally {
      setSaving(false)
    }
  }

  // Drag-to-canvas
  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    const deviceType = e.dataTransfer.getData('application/device-type') as DeviceType
    if (!deviceType || !rfInstance || !reactFlowWrapper.current) return

    const bounds = reactFlowWrapper.current.getBoundingClientRect()
    const position = rfInstance.screenToFlowPosition({
      x: e.clientX - bounds.left,
      y: e.clientY - bounds.top,
    })

    nodeIdCounter++
    const newNode = makeDeviceNode(deviceType, position, `node-${nodeIdCounter}`)
    setNodes((nds) => [...nds, newNode])
  }, [rfInstance, setNodes])

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
  }, [])

  // Node click → open config
  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node)
  }, [])

  const onPaneClick = useCallback(() => {
    setSelectedNode(null)
  }, [])

  function updateNodeData(nodeId: string, data: DeviceData) {
    setNodes((nds) =>
      nds.map((n) =>
        n.id === nodeId ? { ...n, data: data as unknown as Record<string, unknown> } : n
      )
    )
    setSelectedNode((prev) =>
      prev?.id === nodeId ? { ...prev, data: data as unknown as Record<string, unknown> } : prev
    )
  }

  // Rule management
  function addRule(entry: RuleEntry) {
    if (activeRules.some((r) => r.entry.id === entry.id)) return
    setActiveRules((prev) => [...prev, { entry }])
  }

  function removeRule(ruleId: string) {
    setActiveRules((prev) => prev.filter((r) => r.entry.id !== ruleId))
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
    setActiveRules((prev) => [...prev, { entry: customEntry, customText: text }])
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400 text-sm">
        Loading lab…
      </div>
    )
  }

  const RULE_PANEL_H = rulesOpen ? 240 : 36

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-white overflow-hidden">
      {/* ── Top bar ── */}
      <header className="flex-shrink-0 h-11 bg-gray-900 border-b border-gray-800 flex items-center px-3 gap-3">
        <button onClick={() => navigate('/dashboard')} className="text-gray-400 hover:text-white transition p-1">
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
          <span className="text-sm font-semibold text-white truncate max-w-[200px]">{project?.name}</span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {savedAt && <span className="text-xs text-gray-600 hidden sm:block">Saved {savedAt}</span>}
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-300 text-xs font-medium rounded-lg border border-gray-700 transition"
          >
            <Save size={13} />
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={() => setShowSim(true)}
            disabled={activeRules.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-xs font-semibold rounded-lg transition"
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
      <div className="flex-1 flex overflow-hidden" style={{ height: `calc(100vh - 44px - ${RULE_PANEL_H}px)` }}>
        {/* Left sidebar: device palette */}
        <aside className="w-44 flex-shrink-0 bg-gray-900 border-r border-gray-800 overflow-y-auto">
          <DevicePalette />
        </aside>

        {/* Canvas */}
        <div ref={reactFlowWrapper} className="flex-1 relative" onDrop={onDrop} onDragOver={onDragOver}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onInit={setRfInstance as never}
            nodeTypes={NODE_TYPES}
            fitView
            style={{ background: '#0a0b0f' }}
            deleteKeyCode="Delete"
          >
            <Background color="#1a1f2e" gap={24} size={1} />
            <Controls className="[&>button]:bg-gray-800 [&>button]:border-gray-700 [&>button]:text-gray-300" />
            <MiniMap
              nodeColor="#6366f1"
              maskColor="rgba(0,0,0,0.7)"
              style={{ background: '#111827', border: '1px solid #1f2937' }}
            />
          </ReactFlow>
        </div>

        {/* Right sidebar: device config */}
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
        {/* Collapse toggle */}
        <button
          onClick={() => setRulesOpen(!rulesOpen)}
          className="w-full flex items-center justify-between px-4 py-1.5 bg-gray-900 hover:bg-gray-800 transition border-b border-gray-800 text-xs text-gray-400"
        >
          <span className="font-medium">
            Rules
            {activeRules.length > 0 && (
              <span className="ml-2 px-1.5 py-0.5 bg-indigo-900/60 text-indigo-300 rounded text-[10px]">
                {activeRules.length} active
              </span>
            )}
          </span>
          {rulesOpen ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
        </button>

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

      {/* Simulation modal */}
      {showSim && project && (
        <SimulationModal
          projectId={project.id}
          activeRules={activeRules}
          onClose={() => setShowSim(false)}
        />
      )}
    </div>
  )
}
