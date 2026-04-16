import { useParams, useNavigate } from 'react-router-dom'
import { useEffect, useState, useCallback } from 'react'
import { ReactFlow, Background, Controls, MiniMap, addEdge, useNodesState, useEdgesState, type Connection } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { getProject, updateProject, type Project } from '../api/projects'
import { useAuthStore } from '../store/authStore'

const DEFAULT_NODES = [
  {
    id: '1',
    type: 'default',
    position: { x: 250, y: 150 },
    data: { label: 'Workstation\n192.168.1.10' },
  },
  {
    id: '2',
    type: 'default',
    position: { x: 550, y: 150 },
    data: { label: 'Web Server\n192.168.1.20' },
  },
  {
    id: '3',
    type: 'default',
    position: { x: 400, y: 300 },
    data: { label: 'Suricata IDS\n(monitoring)' },
  },
]

const DEFAULT_EDGES = [
  { id: 'e1-2', source: '1', target: '2', animated: false },
  { id: 'e1-3', source: '1', target: '3', animated: true, style: { stroke: '#6366f1' } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#6366f1' } },
]

export default function LabPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { logout } = useAuthStore()

  const [project, setProject] = useState<Project | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<string | null>(null)

  const [nodes, setNodes, onNodesChange] = useNodesState(DEFAULT_NODES)
  const [edges, setEdges, onEdgesChange] = useEdgesState(DEFAULT_EDGES)

  const onConnect = useCallback((connection: Connection) => {
    setEdges((eds) => addEdge(connection, eds))
  }, [setEdges])

  useEffect(() => {
    if (!id) return
    getProject(Number(id))
      .then((p) => {
        setProject(p)
        if (p.topology_json) {
          try {
            const topo = JSON.parse(p.topology_json)
            if (topo.nodes?.length) setNodes(topo.nodes)
            if (topo.edges?.length) setEdges(topo.edges)
          } catch {
            // use defaults
          }
        }
      })
      .catch(() => navigate('/dashboard'))
      .finally(() => setLoading(false))
  }, [id, navigate, setEdges, setNodes])

  async function handleSave() {
    if (!project) return
    setSaving(true)
    try {
      const topology_json = JSON.stringify({ nodes, edges })
      await updateProject(project.id, { topology_json })
      setSavedAt(new Date().toLocaleTimeString())
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400">
        Loading lab…
      </div>
    )
  }

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-white">
      {/* Top bar */}
      <header className="flex-shrink-0 h-12 bg-gray-900 border-b border-gray-800 flex items-center px-4 gap-4">
        <button
          onClick={() => navigate('/dashboard')}
          className="text-gray-400 hover:text-white transition"
          title="Back to projects"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
        </button>

        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-indigo-600 flex items-center justify-center">
            <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <span className="text-sm font-semibold text-white">{project?.name}</span>
        </div>

        <div className="ml-auto flex items-center gap-3">
          {savedAt && (
            <span className="text-xs text-gray-500">Saved at {savedAt}</span>
          )}
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={() => { logout(); navigate('/login') }}
            className="text-xs text-gray-500 hover:text-gray-300 transition"
          >
            Sign out
          </button>
        </div>
      </header>

      {/* Canvas */}
      <div className="flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
          style={{ background: '#0f1117' }}
        >
          <Background color="#1f2937" gap={20} />
          <Controls />
          <MiniMap
            nodeColor="#6366f1"
            maskColor="rgba(0,0,0,0.6)"
            style={{ background: '#1f2937' }}
          />
        </ReactFlow>
      </div>

      {/* Bottom hint bar */}
      <div className="flex-shrink-0 h-8 bg-gray-900 border-t border-gray-800 flex items-center px-4 gap-6 text-xs text-gray-600">
        <span>Drag to move nodes</span>
        <span>Connect ports to create network links</span>
        <span>Right-click node to configure device <span className="text-indigo-500">(coming soon)</span></span>
      </div>
    </div>
  )
}
