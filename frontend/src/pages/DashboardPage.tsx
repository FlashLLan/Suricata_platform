import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listProjects, createProject, deleteProject, updateProject, type ProjectSummary } from '../api/projects'
import { useAuthStore } from '../store/authStore'
import { LAB_TEMPLATES, type LabTemplate } from '../data/templates'
import PcapImportModal from '../components/lab/PcapImportModal'
import { timeAgo } from '../utils/timeAgo'

export default function DashboardPage() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const [projects, setProjects] = useState<ProjectSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [modalStep, setModalStep] = useState<'template' | 'details'>('template')
  const [selectedTemplate, setSelectedTemplate] = useState<LabTemplate>(LAB_TEMPLATES[0])
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [showPcap, setShowPcap] = useState(false)
  const [deleteId, setDeleteId] = useState<number | null>(null)
  const [renameId, setRenameId] = useState<number | null>(null)
  const [renameName, setRenameName] = useState('')

  useEffect(() => {
    listProjects()
      .then(setProjects)
      .finally(() => setLoading(false))
  }, [])

  function openNewProjectModal() {
    setModalStep('template')
    setSelectedTemplate(LAB_TEMPLATES[0])
    setNewName('')
    setNewDesc('')
    setCreateError(null)
    setShowModal(true)
  }

  function handleSelectTemplate(tpl: LabTemplate) {
    setSelectedTemplate(tpl)
    setNewName(tpl.id === 'blank' ? '' : tpl.name)
    setCreateError(null)
    setModalStep('details')
  }

  async function handleCreate() {
    if (!newName.trim()) return
    setCreating(true)
    setCreateError(null)
    try {
      const tpl = selectedTemplate
      const topology_json = tpl.topology ? JSON.stringify(tpl.topology) : undefined
      const rules_json = tpl.ruleSids.length ? JSON.stringify(tpl.ruleSids) : undefined
      const p = await createProject(newName.trim(), newDesc.trim() || undefined, topology_json, rules_json)
      setProjects((prev) => [p, ...prev])
      setShowModal(false)
      navigate(`/lab/${p.id}`)
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setCreateError(detail ?? 'Failed to create project. Please try again.')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(id: number) {
    await deleteProject(id)
    setProjects((prev) => prev.filter((p) => p.id !== id))
    setDeleteId(null)
  }

  async function handleRename() {
    if (!renameId || !renameName.trim()) return
    const updated = await updateProject(renameId, { name: renameName.trim() })
    setProjects(prev => prev.map(p => p.id === renameId ? { ...p, name: updated.name } : p))
    setRenameId(null)
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Top nav */}
      <header className="border-b border-gray-800 bg-gray-900/60 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center">
              <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="font-semibold text-white">Suricata Lab</span>
          </div>

          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-400">{user?.email}</span>
            <button
              onClick={() => { logout(); navigate('/login') }}
              className="text-sm text-gray-400 hover:text-white transition"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-6xl mx-auto px-6 py-10">
        {/* Header row */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">My Projects</h1>
            <p className="text-gray-400 text-sm mt-0.5">
              Each project is a saved Suricata simulation lab.
            </p>
          </div>
          <button
            onClick={openNewProjectModal}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-lg transition"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New project
          </button>
        </div>

        {/* Projects grid */}
        {loading ? (
          <div className="text-gray-500 text-sm">Loading…</div>
        ) : projects.length === 0 ? (
          <div className="border border-dashed border-gray-700 rounded-2xl p-16 text-center">
            <div className="w-14 h-14 rounded-2xl bg-gray-800 flex items-center justify-center mx-auto mb-4">
              <svg className="w-7 h-7 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                  d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            </div>
            <p className="text-white font-medium mb-1">No projects yet</p>
            <p className="text-gray-400 text-sm mb-5">Create your first simulation lab to get started.</p>
            <button
              onClick={openNewProjectModal}
              className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-lg transition"
            >
              Create project
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((p) => (
              <div
                key={p.id}
                className="group bg-gray-900 border border-gray-800 hover:border-indigo-500/50 rounded-2xl p-5 cursor-pointer transition-all"
                onClick={() => navigate(`/lab/${p.id}`)}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-9 h-9 rounded-xl bg-indigo-900/50 border border-indigo-700/30 flex items-center justify-center flex-shrink-0">
                    <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                        d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                  </div>
                  <div className="opacity-0 group-hover:opacity-100 flex items-center gap-0.5 transition">
                    <button
                      onClick={(e) => { e.stopPropagation(); setRenameName(p.name); setRenameId(p.id) }}
                      className="p-1 text-gray-500 hover:text-indigo-400 transition"
                      title="Rename"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); setDeleteId(p.id) }}
                      className="p-1 text-gray-500 hover:text-red-400 transition"
                      title="Delete"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
                <h3 className="font-semibold text-white text-sm mb-1 truncate">{p.name}</h3>
                {p.description && (
                  <p className="text-gray-400 text-xs mb-3 line-clamp-2">{p.description}</p>
                )}
                <p className="text-gray-600 text-xs mt-auto">
                  Updated {timeAgo(p.updated_at)}
                </p>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Create modal — 2-step: template picker → project details */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4">
          {modalStep === 'template' ? (
            /* ── Step 1: Template picker ─────────────────────────────────── */
            <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
              <div className="flex items-center justify-between mb-5 flex-shrink-0">
                <div>
                  <h2 className="text-lg font-bold text-white">New project</h2>
                  <p className="text-gray-400 text-sm mt-0.5">Choose a template to get started</p>
                </div>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-500 hover:text-gray-300 transition p-1"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 overflow-y-auto pr-1">
                {/* Import PCAP option */}
                <button
                  onClick={() => { setShowModal(false); setShowPcap(true) }}
                  className="text-left p-4 bg-indigo-950/40 hover:bg-indigo-950/70 border border-indigo-700/50 hover:border-indigo-500 rounded-xl transition-all group"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                  </div>
                  <p className="text-sm font-semibold text-indigo-300 group-hover:text-indigo-200 transition leading-tight mb-1.5">
                    Import PCAP
                  </p>
                  <p className="text-[11px] text-indigo-400/70 leading-relaxed">
                    Upload a .pcap capture — topology and scenario are reconstructed automatically.
                  </p>
                </button>

                {LAB_TEMPLATES.map((tpl) => (
                  <button
                    key={tpl.id}
                    onClick={() => handleSelectTemplate(tpl)}
                    className="text-left p-4 bg-gray-800 hover:bg-gray-700/80 border border-gray-700 hover:border-indigo-500/60 rounded-xl transition-all group"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {tpl.id === 'blank' ? (
                        <span className="text-base">✦</span>
                      ) : (
                        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                          tpl.difficulty === 'beginner'
                            ? 'bg-green-900/40 text-green-400 border border-green-700/40'
                            : tpl.difficulty === 'intermediate'
                            ? 'bg-amber-900/40 text-amber-400 border border-amber-700/40'
                            : 'bg-red-900/40 text-red-400 border border-red-700/40'
                        }`}>
                          {tpl.difficulty}
                        </span>
                      )}
                    </div>
                    <p className="text-sm font-semibold text-white group-hover:text-indigo-300 transition leading-tight mb-1.5">
                      {tpl.name}
                    </p>
                    <p className="text-[11px] text-gray-400 leading-relaxed line-clamp-3">
                      {tpl.description}
                    </p>
                    {tpl.ruleSids.length > 0 && (
                      <p className="text-[10px] text-indigo-400/70 mt-2">
                        {tpl.ruleSids.length} rule{tpl.ruleSids.length !== 1 ? 's' : ''} pre-loaded
                      </p>
                    )}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* ── Step 2: Project details ─────────────────────────────────── */
            <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-md shadow-2xl">
              <div className="flex items-center gap-3 mb-5">
                <button
                  onClick={() => setModalStep('template')}
                  className="text-gray-500 hover:text-gray-300 transition p-1 -ml-1"
                  title="Back to templates"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                  </svg>
                </button>
                <div>
                  <h2 className="text-lg font-bold text-white leading-none">New project</h2>
                  {selectedTemplate.id !== 'blank' && (
                    <p className="text-xs text-indigo-400 mt-0.5">Template: {selectedTemplate.name}</p>
                  )}
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">Name</label>
                  <input
                    autoFocus
                    value={newName}
                    onChange={(e) => { setNewName(e.target.value); setCreateError(null) }}
                    onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                    className={`w-full px-4 py-2.5 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 transition ${
                      createError ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-indigo-500'
                    }`}
                    placeholder="My first lab"
                  />
                  {createError && (
                    <p className="mt-1.5 text-xs text-red-400">{createError}</p>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">
                    Description <span className="text-gray-500">(optional)</span>
                  </label>
                  <textarea
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    rows={3}
                    className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition resize-none"
                    placeholder="What are you experimenting with?"
                  />
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreate}
                  disabled={creating || !newName.trim()}
                  className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition"
                >
                  {creating ? 'Creating…' : 'Create'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Rename modal */}
      {renameId !== null && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-sm shadow-2xl">
            <h2 className="text-lg font-bold text-white mb-4">Rename project</h2>
            <input
              autoFocus
              value={renameName}
              onChange={e => setRenameName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleRename(); if (e.key === 'Escape') setRenameId(null) }}
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition mb-5"
            />
            <div className="flex gap-3">
              <button
                onClick={() => setRenameId(null)}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleRename}
                disabled={!renameName.trim()}
                className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition"
              >
                Rename
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PCAP import modal */}
      {showPcap && (
        <PcapImportModal
          activeRules={[]}
          onClose={() => setShowPcap(false)}
          onProjectCreated={(p) => setProjects(prev => [p, ...prev])}
        />
      )}

      {/* Delete confirm modal */}
      {deleteId !== null && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-sm shadow-2xl">
            <h2 className="text-lg font-bold text-white mb-2">Delete project?</h2>
            <p className="text-gray-400 text-sm mb-6">This cannot be undone. All saved lab data will be lost.</p>
            <div className="flex gap-3">
              <button
                onClick={() => setDeleteId(null)}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteId)}
                className="flex-1 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-semibold rounded-lg transition"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
