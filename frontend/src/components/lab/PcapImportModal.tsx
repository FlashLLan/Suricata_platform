import { useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  X, Upload, FileText, AlertTriangle, CheckCircle, XCircle,
  FlaskConical, Server, Shield, Activity, FolderPlus, ExternalLink,
} from 'lucide-react'
import { analyzePcap, type PcapAnalysisResult, type PcapRuleResult } from '../../api/pcap'
import { createProject, type Project } from '../../api/projects'
import type { ActiveRule } from '../../types/lab'
import { SCENARIO_RULES } from '../../data/scenarioRules'

interface Props {
  activeRules: ActiveRule[]
  onClose: () => void
  /** If omitted the "Load to Canvas" button is hidden (e.g. when called from the dashboard) */
  onLoadTopology?: (topology: { nodes: object[]; edges: object[] }) => void
  /** Called after a project is successfully created — lets the dashboard update its list */
  onProjectCreated?: (project: Project) => void
}

type Tab = 'overview' | 'topology' | 'detection'
type SimMode = 'python' | 'suricata'

const CONFIDENCE_COLOR = (c: number) =>
  c >= 0.7 ? 'text-green-400' : c >= 0.4 ? 'text-amber-400' : 'text-gray-400'

const PROTOCOL_COLOR: Record<string, string> = {
  tcp:  'bg-blue-900/50 text-blue-300',
  udp:  'bg-purple-900/50 text-purple-300',
  icmp: 'bg-orange-900/50 text-orange-300',
  dns:  'bg-teal-900/50 text-teal-300',
  http: 'bg-green-900/50 text-green-300',
}

const DEVICE_ICON: Record<string, string> = {
  attacker:    '⚔️',
  'web-server':'🌐',
  database:    '🗄️',
  'dns-server':'🔍',
  'mail-server':'✉️',
  server:      '🖥️',
  workstation: '💻',
  router:      '🔀',
  firewall:    '🛡️',
  ids:         '👁️',
}

export default function PcapImportModal({ activeRules, onClose, onLoadTopology, onProjectCreated }: Props) {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [file, setFile]         = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult]     = useState<PcapAnalysisResult | null>(null)
  const [error, setError]       = useState<string | null>(null)
  const [tab, setTab]           = useState<Tab>('overview')
  const [simMode, setSimMode]   = useState<SimMode>('python')

  // ── Save as Project ─────────────────────────────────────────────────────────
  const [showSaveForm, setShowSaveForm] = useState(false)
  const [saveName, setSaveName]         = useState('')
  const [saving, setSaving]             = useState(false)
  const [saveError, setSaveError]       = useState<string | null>(null)
  const [savedProject, setSavedProject] = useState<Project | null>(null)

  // Lab context = onLoadTopology provided; dashboard context = it's absent
  const isLabContext = !!onLoadTopology

  async function handleSaveProject() {
    if (!result || !saveName.trim()) return
    setSaving(true)
    setSaveError(null)
    try {
      const topology_json = JSON.stringify({
        nodes: result.topology.nodes,
        edges: result.topology.edges,
      })
      // Pre-populate rules matched to the detected scenario
      const scenarioSids = SCENARIO_RULES[result.scenario.scenario_id] ?? []
      const rules_json = scenarioSids.length ? JSON.stringify(scenarioSids) : undefined

      const project = await createProject(
        saveName.trim(),
        `Imported from ${result.filename} — ${result.scenario.name}`,
        topology_json,
        rules_json,
      )
      onProjectCreated?.(project)
      setSavedProject(project)
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setSaveError(detail ?? 'Failed to save project. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  // ── File selection ──────────────────────────────────────────────────────────
  function selectFile(f: File) {
    if (!f.name.match(/\.(pcap|pcapng|cap)$/i)) {
      setError('Please select a .pcap or .pcapng file.')
      return
    }
    if (f.size > 20 * 1024 * 1024) {
      setError('File too large. Maximum size is 20 MB.')
      return
    }
    setFile(f)
    setError(null)
    setResult(null)
  }

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) selectFile(f)
  }, [])

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(true)
  }, [])

  const onDragLeave = useCallback(() => setDragging(false), [])

  // ── Analyze ─────────────────────────────────────────────────────────────────
  async function handleAnalyze() {
    if (!file) return
    setAnalyzing(true)
    setError(null)
    setResult(null)
    try {
      const ruleTexts = activeRules.map(r => r.customText ?? r.entry.rule)
      const data = await analyzePcap(file, ruleTexts, simMode)
      setResult(data)
      setTab('overview')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? 'Analysis failed. Make sure the file is a valid pcap.'
      setError(msg)
    } finally {
      setAnalyzing(false)
    }
  }

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileText size={18} className="text-indigo-400" />
            <span className="font-semibold text-white text-sm">Import &amp; Analyze PCAP</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition">
            <X size={18} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">

          {/* ── Upload section ──────────────────────────────────────────────── */}
          <div className="px-5 pt-4 pb-3 space-y-4">

            {/* Drop zone */}
            <div
              className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
                dragging
                  ? 'border-indigo-500 bg-indigo-950/30'
                  : file
                    ? 'border-green-700 bg-green-950/20'
                    : 'border-gray-700 hover:border-gray-600 bg-gray-800/40'
              }`}
              onClick={() => fileInputRef.current?.click()}
              onDrop={onDrop}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                onChange={e => { const f = e.target.files?.[0]; if (f) selectFile(f) }}
              />
              {file ? (
                <div className="flex flex-col items-center gap-1">
                  <CheckCircle size={28} className="text-green-400" />
                  <p className="text-sm font-medium text-white mt-1">{file.name}</p>
                  <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB · Click to change</p>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-2 text-gray-400">
                  <Upload size={28} />
                  <p className="text-sm font-medium text-white">Drop a .pcap file here</p>
                  <p className="text-xs">or click to browse · max 20 MB</p>
                </div>
              )}
            </div>

            {/* Mode toggle */}
            <div>
              <p className="text-xs text-gray-500 mb-2 uppercase tracking-wide font-medium">Analysis engine</p>
              <div className="grid grid-cols-2 gap-2">
                {(['python', 'suricata'] as SimMode[]).map(m => (
                  <button
                    key={m}
                    onClick={() => setSimMode(m)}
                    className={`flex items-center gap-2.5 px-3 py-2.5 rounded-xl border text-left transition ${
                      simMode === m
                        ? 'border-indigo-500 bg-indigo-950/50 text-white'
                        : 'border-gray-700 bg-gray-800/50 text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    {m === 'python'
                      ? <FlaskConical size={15} className={simMode === m ? 'text-indigo-400' : 'text-gray-500'} />
                      : <Server size={15} className={simMode === m ? 'text-indigo-400' : 'text-gray-500'} />
                    }
                    <div>
                      <p className="text-xs font-semibold leading-tight">
                        {m === 'python' ? 'Educational Sim' : 'Real Suricata'}
                      </p>
                      <p className="text-[10px] text-gray-500 leading-tight">
                        {m === 'python' ? 'Fast · detailed diagnostics' : 'Production-accurate · Docker'}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Rule count info */}
            {activeRules.length === 0 && (
              <div className="flex items-start gap-2 bg-gray-800/60 border border-gray-700/50 rounded-lg px-3 py-2.5 text-xs text-gray-400">
                <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-gray-500" />
                {isLabContext
                  ? 'No rules loaded — topology and scenario will be extracted, but no rule matching will run. Add rules to the panel first to test detection.'
                  : 'Topology and scenario will be extracted automatically. Detection rules can be added after the project is created.'}
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="flex items-start gap-2 bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2.5 text-xs text-red-300">
                <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
                {error}
              </div>
            )}

            {/* Analyze button */}
            <button
              onClick={handleAnalyze}
              disabled={!file || analyzing}
              className="w-full flex items-center justify-center gap-2 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-xl transition"
            >
              {analyzing ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                  </svg>
                  Analyzing…
                </>
              ) : (
                <>
                  <Activity size={15} />
                  Analyze PCAP
                </>
              )}
            </button>
          </div>

          {/* ── Results ─────────────────────────────────────────────────────── */}
          {result && (
            <>
              <div className="border-t border-gray-800 mx-5" />

              {/* Tabs */}
              <div className="flex gap-0 px-5 pt-3">
                {(['overview', 'topology', 'detection'] as Tab[]).map(t => (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-t-lg border-b-2 transition capitalize ${
                      tab === t
                        ? 'border-indigo-500 text-indigo-300'
                        : 'border-transparent text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {t}
                    {t === 'detection' && result.results.length > 0 && (
                      <span className={`ml-1.5 px-1.5 py-0.5 rounded text-[10px] ${
                        result.triggered_count > 0 ? 'bg-red-900/60 text-red-300' : 'bg-gray-800 text-gray-400'
                      }`}>
                        {result.triggered_count}/{result.results.length}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <div className="px-5 pb-5 pt-3 space-y-3">

                {/* ── Overview tab ─────────────────────────────────────────── */}
                {tab === 'overview' && (
                  <>
                    {/* Fallback warning */}
                    {result.suricata_fallback && (
                      <div className="flex items-start gap-2 bg-amber-900/20 border border-amber-700/50 rounded-xl px-3 py-2.5 text-xs text-amber-300">
                        <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold">Docker unavailable — approximate results.</span>
                          {' '}Results are from the Educational Simulation engine.
                        </div>
                      </div>
                    )}

                    {/* Scenario card */}
                    <div className="bg-gray-800/60 border border-gray-700/60 rounded-xl p-4 space-y-2">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-[10px] text-gray-500 uppercase tracking-wide mb-1">Detected scenario</p>
                          <p className="text-sm font-semibold text-white">{result.scenario.name}</p>
                          <p className="text-xs text-gray-400 mt-1">{result.scenario.description}</p>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <p className={`text-lg font-bold ${CONFIDENCE_COLOR(result.scenario.confidence)}`}>
                            {Math.round(result.scenario.confidence * 100)}%
                          </p>
                          <p className="text-[10px] text-gray-500">confidence</p>
                        </div>
                      </div>

                      {/* Confidence bar */}
                      <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            result.scenario.confidence >= 0.7 ? 'bg-green-500' :
                            result.scenario.confidence >= 0.4 ? 'bg-amber-500' : 'bg-gray-500'
                          }`}
                          style={{ width: `${result.scenario.confidence * 100}%` }}
                        />
                      </div>

                      {/* Attacker / target */}
                      {(result.scenario.attacker_ip || result.scenario.target_ip) && (
                        <div className="flex gap-4 pt-1 text-xs">
                          {result.scenario.attacker_ip && (
                            <div>
                              <span className="text-gray-500">Attacker </span>
                              <span className="text-red-400 font-mono">{result.scenario.attacker_ip}</span>
                            </div>
                          )}
                          {result.scenario.target_ip && (
                            <div>
                              <span className="text-gray-500">Target </span>
                              <span className="text-indigo-400 font-mono">{result.scenario.target_ip}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Stats grid */}
                    <div className="grid grid-cols-3 gap-2">
                      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center">
                        <p className="text-lg font-bold text-white">{result.stats.total_packets.toLocaleString()}</p>
                        <p className="text-[10px] text-gray-500 mt-0.5">packets</p>
                      </div>
                      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center">
                        <p className="text-lg font-bold text-white">{result.stats.unique_ips}</p>
                        <p className="text-[10px] text-gray-500 mt-0.5">unique IPs</p>
                      </div>
                      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center">
                        <p className="text-lg font-bold text-white">{result.stats.duration_seconds}s</p>
                        <p className="text-[10px] text-gray-500 mt-0.5">duration</p>
                      </div>
                    </div>

                    {/* Protocol breakdown */}
                    {Object.keys(result.stats.protocol_counts).length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(result.stats.protocol_counts)
                          .sort(([, a], [, b]) => b - a)
                          .map(([proto, count]) => (
                            <span
                              key={proto}
                              className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                                PROTOCOL_COLOR[proto] ?? 'bg-gray-800 text-gray-300'
                              }`}
                            >
                              {proto.toUpperCase()} {count.toLocaleString()}
                            </span>
                          ))}
                      </div>
                    )}

                    {/* Summary */}
                    <p className="text-xs text-gray-400 bg-gray-800/40 border border-gray-700/40 rounded-lg px-3 py-2.5 leading-relaxed">
                      {result.summary}
                    </p>

                    {/* Save as Project */}
                    {savedProject ? (
                      /* ── Success state ── */
                      <div className="bg-green-950/30 border border-green-800/50 rounded-xl p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <CheckCircle size={16} className="text-green-400 flex-shrink-0" />
                          <div>
                            <p className="text-sm font-semibold text-white">Project saved!</p>
                            <p className="text-xs text-gray-400 mt-0.5 truncate max-w-[260px]">{savedProject.name}</p>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          {isLabContext ? (
                            <button
                              onClick={() => window.open(`/lab/${savedProject.id}`, '_blank')}
                              className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
                            >
                              <ExternalLink size={12} />
                              Open in new tab
                            </button>
                          ) : (
                            <button
                              onClick={() => navigate(`/lab/${savedProject.id}`)}
                              className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
                            >
                              Open project
                            </button>
                          )}
                          <button
                            onClick={onClose}
                            className="px-3 py-2 border border-gray-700 hover:border-gray-500 text-gray-400 text-xs font-medium rounded-lg transition"
                          >
                            {isLabContext ? 'Close' : 'Stay here'}
                          </button>
                        </div>
                      </div>
                    ) : !showSaveForm ? (
                      <button
                        onClick={() => {
                          setSaveName(result.filename.replace(/\.(pcap|pcapng|cap)$/i, ''))
                          setSaveError(null)
                          setShowSaveForm(true)
                        }}
                        className="w-full flex items-center justify-center gap-2 py-2.5 border border-indigo-700 hover:border-indigo-500 hover:bg-indigo-950/30 text-indigo-300 text-sm font-semibold rounded-xl transition"
                      >
                        <FolderPlus size={15} />
                        Save as Project
                      </button>
                    ) : (
                      <div className="bg-gray-800/60 border border-gray-700/60 rounded-xl p-3 space-y-2">
                        <p className="text-xs text-gray-400 font-medium">Project name</p>
                        <input
                          autoFocus
                          type="text"
                          value={saveName}
                          onChange={e => { setSaveName(e.target.value); setSaveError(null) }}
                          onKeyDown={e => { if (e.key === 'Enter') handleSaveProject(); if (e.key === 'Escape') setShowSaveForm(false) }}
                          placeholder="e.g. Port scan investigation"
                          className={`w-full bg-gray-900 border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none transition ${
                            saveError ? 'border-red-500 focus:border-red-400' : 'border-gray-700 focus:border-indigo-500'
                          }`}
                        />
                        {saveError && (
                          <p className="text-xs text-red-400">{saveError}</p>
                        )}
                        <div className="flex gap-2 pt-1">
                          <button
                            onClick={handleSaveProject}
                            disabled={!saveName.trim() || saving}
                            className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg transition"
                          >
                            {saving ? (
                              <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                              </svg>
                            ) : (
                              <FolderPlus size={13} />
                            )}
                            {saving ? 'Saving…' : 'Save'}
                          </button>
                          <button
                            onClick={() => setShowSaveForm(false)}
                            className="px-3 py-2 border border-gray-700 hover:border-gray-500 text-gray-400 text-xs font-medium rounded-lg transition"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Engine badge */}
                    <div className="flex items-center gap-1.5 text-[10px] text-gray-500">
                      {result.mode === 'suricata'
                        ? <><Server size={11} className="text-green-400" /><span className="text-green-400">Real Suricata</span></>
                        : <><FlaskConical size={11} className="text-indigo-400" /><span className="text-indigo-400">Educational Sim</span></>
                      }
                      <span>·</span>
                      <span>{file?.name}</span>
                    </div>
                  </>
                )}

                {/* ── Topology tab ─────────────────────────────────────────── */}
                {tab === 'topology' && (
                  <>
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-gray-400">
                        {result.topology.nodes.length} device{result.topology.nodes.length !== 1 ? 's' : ''} reconstructed from the capture
                      </p>
                      {onLoadTopology && (
                        <button
                          onClick={() => { onLoadTopology(result.topology); onClose() }}
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
                        >
                          <Shield size={12} />
                          Load to Canvas
                        </button>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      {(result.topology.nodes as {
                        id: string
                        data: { label: string; deviceType: string; ip: string; zone: string; ports: string }
                      }[]).map(node => (
                        <div
                          key={node.id}
                          className="flex items-center gap-3 bg-gray-800/50 border border-gray-700/40 rounded-lg px-3 py-2"
                        >
                          <span className="text-base flex-shrink-0">
                            {DEVICE_ICON[node.data.deviceType] ?? '📦'}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-white truncate">{node.data.label}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium flex-shrink-0 ${
                                node.data.zone === 'internal' ? 'bg-blue-900/40 text-blue-300' :
                                node.data.zone === 'external' ? 'bg-red-900/40 text-red-300' :
                                'bg-gray-700 text-gray-400'
                              }`}>
                                {node.data.zone}
                              </span>
                            </div>
                            {node.data.ports && (
                              <p className="text-[10px] text-gray-500 mt-0.5">ports: {node.data.ports}</p>
                            )}
                          </div>
                          <span className="text-[11px] font-mono text-gray-400 flex-shrink-0">{node.data.ip}</span>
                        </div>
                      ))}
                    </div>

                    <p className="text-[10px] text-gray-600 text-center pt-1">
                      {result.topology.edges.length} connection{result.topology.edges.length !== 1 ? 's' : ''} detected between hosts
                    </p>
                  </>
                )}

                {/* ── Detection tab ────────────────────────────────────────── */}
                {tab === 'detection' && (
                  <>
                    {result.results.length === 0 ? (
                      <div className="text-center py-8 text-gray-500 text-sm">
                        No rules were loaded. Add rules to the IDS node and re-analyze.
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {result.results.map((r: PcapRuleResult) => (
                          <RuleResultCard key={r.rule_sid} result={r} />
                        ))}
                      </div>
                    )}
                  </>
                )}

              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function RuleResultCard({ result }: { result: PcapRuleResult }) {
  const [open, setOpen] = useState(false)

  return (
    <div className={`border rounded-xl overflow-hidden ${
      result.fired ? 'border-red-800/60 bg-red-950/20' : 'border-gray-700/50 bg-gray-800/30'
    }`}>
      <button
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left"
        onClick={() => setOpen(o => !o)}
      >
        {result.fired
          ? <XCircle size={15} className="text-red-400 flex-shrink-0" />
          : <CheckCircle size={15} className="text-gray-600 flex-shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-white truncate">{result.rule_msg || `SID ${result.rule_sid}`}</p>
          <p className="text-[10px] text-gray-500">SID {result.rule_sid}</p>
        </div>
        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold flex-shrink-0 ${
          result.fired ? 'bg-red-900/60 text-red-300' : 'bg-gray-700 text-gray-400'
        }`}>
          {result.fired ? 'FIRED' : 'NO MATCH'}
        </span>
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-gray-700/40 pt-2">
          <p className="text-xs text-gray-300 leading-relaxed">{result.explanation}</p>
          {result.why_not && (
            <p className="text-xs text-amber-300/80 leading-relaxed">{result.why_not}</p>
          )}
          {result.fired && result.matched_packets.length > 0 && (
            <div className="space-y-1 pt-1">
              <p className="text-[10px] text-gray-500 uppercase tracking-wide">Matched packets</p>
              {result.matched_packets.slice(0, 5).map((pkt, i) => (
                <div key={i} className="flex items-center gap-2 bg-gray-900/60 rounded px-2 py-1.5 text-[11px]">
                  <span className="text-gray-500 font-mono">{pkt.protocol.toUpperCase()}</span>
                  <span className="text-gray-300 font-mono">{pkt.src} → {pkt.dst}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
