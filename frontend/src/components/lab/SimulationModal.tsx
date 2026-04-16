import { useState } from 'react'
import {
  X, Play, ChevronDown, ChevronRight, ShieldCheck, ShieldOff,
  Loader2, Shield, AlertTriangle, CheckCircle2, Zap, Minimize2, Maximize2,
} from 'lucide-react'
import { SCENARIOS } from '../../data/rules'
import { runSimulation } from '../../api/simulation'
import type {
  ActiveRule, SimulationResult, RuleMatchResult, DefenseImpact,
} from '../../types/lab'
import type { Node, Edge } from '@xyflow/react'
import type { DeviceData } from '../../types/lab'

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  projectId: number
  activeRules: ActiveRule[]
  nodes: Node[]
  edges: Edge[]
  onClose: () => void
  onSimulationStart: (packetRate: number, attackPath: string[][]) => void
  onSimulationEnd: () => void
}

// ─── Pre-flight topology validation ──────────────────────────────────────────

function validateTopology(nodes: Node[], edges: Edge[]): string | null {
  const attacker = nodes.find(n => (n.data as unknown as DeviceData).deviceType === 'attacker')
  if (!attacker) {
    return 'No Attacker device found. Add an Attacker node to the canvas first.'
  }
  if (!attacker.data || !(attacker.data as unknown as DeviceData).ip) {
    return 'The Attacker device has no IP address. Set one in Device Config.'
  }
  const hasEdge = edges.some(
    e => e.source === attacker.id || e.target === attacker.id,
  )
  if (!hasEdge) {
    return 'The Attacker is not connected to any device. Draw a connection from it to a target.'
  }
  return null
}

// ─── Defense impact card ──────────────────────────────────────────────────────

function DefenseImpactSection({ impacts, blocked }: { impacts: DefenseImpact[]; blocked: boolean }) {
  const [open, setOpen] = useState(true)
  if (!impacts || impacts.length === 0) return null

  return (
    <div className={`rounded-xl border overflow-hidden ${blocked ? 'border-green-700/40 bg-green-950/20' : 'border-gray-700/40 bg-gray-800/20'}`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition"
      >
        <Shield size={16} className={blocked ? 'text-green-400' : 'text-gray-500'} />
        <div className="flex-1">
          <p className={`text-sm font-semibold ${blocked ? 'text-green-300' : 'text-gray-300'}`}>
            Defense Evaluation
          </p>
          <p className="text-[11px] text-gray-500">{impacts.length} defense(s) evaluated</p>
        </div>
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${blocked ? 'bg-green-900/60 text-green-300' : 'bg-gray-700/60 text-gray-400'}`}>
          {blocked ? 'BLOCKED' : 'PASSED THROUGH'}
        </span>
        {open ? <ChevronDown size={14} className="text-gray-500" /> : <ChevronRight size={14} className="text-gray-500" />}
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-2 border-t border-gray-700/30">
          <p className="text-[11px] text-gray-500 mt-3 leading-relaxed">
            Defenses are evaluated <em>before</em> IDS rules — a blocking defense stops the attack
            before Suricata even sees the traffic.
          </p>
          {impacts.map((impact, i) => (
            <div key={i} className={`flex gap-3 px-3 py-2 rounded-lg border ${impact.blocked ? 'bg-green-950/20 border-green-800/30' : 'bg-gray-800/30 border-gray-700/20'}`}>
              {impact.blocked
                ? <CheckCircle2 size={13} className="text-green-400 mt-0.5 flex-shrink-0" />
                : <ShieldOff size={13} className="text-gray-600 mt-0.5 flex-shrink-0" />
              }
              <div>
                <p className="text-[11px] font-medium text-gray-300">
                  {impact.defense_name}
                  {impact.device_label && (
                    <span className="text-gray-600"> · {impact.device_label}</span>
                  )}
                </p>
                <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{impact.explanation}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Rule result card ─────────────────────────────────────────────────────────

function RuleResultCard({ result }: { result: RuleMatchResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className={`rounded-xl border overflow-hidden ${result.fired ? 'border-red-700/50 bg-red-950/20' : 'border-gray-700/40 bg-gray-800/20'}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition"
      >
        {result.fired
          ? <ShieldOff size={16} className="text-red-400 flex-shrink-0" />
          : <ShieldCheck size={16} className="text-green-500 flex-shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-medium truncate ${result.fired ? 'text-red-300' : 'text-gray-300'}`}>
            {result.rule_msg || `SID ${result.rule_sid}`}
          </p>
          <p className="text-[11px] text-gray-500">SID {result.rule_sid}</p>
        </div>
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${result.fired ? 'bg-red-900/60 text-red-300' : 'bg-gray-700/60 text-gray-400'}`}>
          {result.fired ? 'FIRED' : 'NO MATCH'}
        </span>
        {expanded ? <ChevronDown size={14} className="text-gray-500 flex-shrink-0" /> : <ChevronRight size={14} className="text-gray-500 flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-gray-700/30">
          <div className="mt-3">
            <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wide mb-1">
              {result.fired ? 'Why it fired' : 'Why it did not fire'}
            </p>
            <p className="text-xs text-gray-300 leading-relaxed">
              {result.fired ? result.explanation : result.why_not || result.explanation}
            </p>
          </div>

          {result.fired && result.matched_packets.length > 0 && (
            <div>
              <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wide mb-2">
                Matched packets ({result.matched_packets.length})
              </p>
              <div className="space-y-1.5">
                {result.matched_packets.slice(0, 5).map((pkt, i) => (
                  <div key={i} className="bg-gray-900/60 rounded-lg px-3 py-2">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-mono text-indigo-400 bg-indigo-900/30 px-1.5 py-0.5 rounded">
                        {pkt.protocol.toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono text-gray-400">
                        {pkt.src} → {pkt.dst}
                      </span>
                    </div>
                    <p className="text-[10px] text-gray-500">{pkt.description}</p>
                    {pkt.payload_preview && (
                      <pre className="text-[10px] text-gray-600 font-mono mt-1 truncate">
                        {pkt.payload_preview.slice(0, 80)}
                      </pre>
                    )}
                  </div>
                ))}
                {result.matched_packets.length > 5 && (
                  <p className="text-[10px] text-gray-600">…and {result.matched_packets.length - 5} more packets</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Main modal ───────────────────────────────────────────────────────────────

export default function SimulationModal({
  projectId,
  activeRules,
  nodes,
  edges,
  onClose,
  onSimulationStart,
  onSimulationEnd,
}: Props) {
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id)
  const [packetRate, setPacketRate] = useState(5)
  const [result, setResult] = useState<SimulationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [minimized, setMinimized] = useState(false)

  const selectedScenario = SCENARIOS.find((s) => s.id === scenarioId)!
  const topologyError = validateTopology(nodes, edges)

  async function handleRun() {
    if (topologyError) return
    setError('')
    setLoading(true)
    setResult(null)

    try {
      const ruleTexts = activeRules.map((r) => r.customText ?? r.entry.rule)
      const topology = { nodes, edges }
      const res = await runSimulation(projectId, scenarioId, ruleTexts, topology)
      setResult(res)

      // Kick off edge animation on the canvas
      if (res.attack_path && res.attack_path.length > 0) {
        onSimulationStart(packetRate, res.attack_path)
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Simulation failed. Check that the backend is running.')
    } finally {
      setLoading(false)
    }
  }

  function handleClose() {
    onSimulationEnd()
    onClose()
  }

  // ── Minimized pill ────────────────────────────────────────────────────────
  if (minimized) {
    return (
      <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-gray-900 border border-gray-700 rounded-2xl px-4 py-3 shadow-2xl">
        {loading && <Loader2 size={14} className="text-indigo-400 animate-spin" />}
        {result && !loading && (
          result.attack_blocked
            ? <CheckCircle2 size={14} className="text-green-400" />
            : <ShieldOff size={14} className="text-red-400" />
        )}
        {!result && !loading && <Play size={14} className="text-gray-500" />}
        <div>
          <p className="text-xs font-semibold text-white leading-tight">
            {loading ? 'Simulating…' : result ? 'Simulation complete' : 'Simulation'}
          </p>
          <p className="text-[10px] text-gray-500">{selectedScenario.name}</p>
        </div>
        <button
          onClick={() => setMinimized(false)}
          className="ml-2 text-gray-500 hover:text-white transition p-1 rounded-lg hover:bg-gray-800"
          title="Restore"
        >
          <Maximize2 size={14} />
        </button>
        <button
          onClick={handleClose}
          className="text-gray-600 hover:text-white transition p-1 rounded-lg hover:bg-gray-800"
          title="Close"
        >
          <X size={14} />
        </button>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-[2px] flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-lg font-bold text-white">Run Simulation</h2>
            <p className="text-xs text-gray-500 mt-0.5">{activeRules.length} rule(s) loaded</p>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setMinimized(true)}
              className="text-gray-500 hover:text-white transition p-1.5 rounded-lg hover:bg-gray-800"
              title="Minimize — watch the canvas"
            >
              <Minimize2 size={15} />
            </button>
            <button onClick={handleClose} className="text-gray-500 hover:text-white transition p-1.5 rounded-lg hover:bg-gray-800">
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Config section */}
        <div className="px-6 py-4 border-b border-gray-800 space-y-4">

          {/* Topology pre-flight warning */}
          {topologyError && (
            <div className="flex gap-2 px-3 py-2.5 bg-yellow-950/30 border border-yellow-700/40 rounded-xl">
              <AlertTriangle size={15} className="text-yellow-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-300 leading-relaxed">{topologyError}</p>
            </div>
          )}

          {/* Scenario picker */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wide">
              Traffic Scenario
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => { setScenarioId(s.id); setResult(null) }}
                  className={`text-left px-3 py-2.5 rounded-xl border transition ${
                    scenarioId === s.id
                      ? 'border-indigo-500 bg-indigo-900/30 text-white'
                      : 'border-gray-700/50 bg-gray-800/30 text-gray-400 hover:border-gray-600'
                  }`}
                >
                  <p className="text-xs font-semibold">{s.name}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-1">{s.description}</p>
                </button>
              ))}
            </div>
            <div className="bg-gray-800/40 rounded-lg p-3">
              <p className="text-[11px] text-gray-400 leading-relaxed">{selectedScenario.description}</p>
            </div>
          </div>

          {/* Packet rate */}
          <div className="space-y-1.5">
            <label className="flex items-center gap-1.5 text-xs font-semibold text-gray-400 uppercase tracking-wide">
              <Zap size={11} />
              Packet Rate — {packetRate} pps
            </label>
            <input
              type="range"
              min={1}
              max={100}
              value={packetRate}
              onChange={e => setPacketRate(Number(e.target.value))}
              className="w-full accent-indigo-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-gray-600">
              <span>1 pps — slow / stealthy</span>
              <span>100 pps — flood</span>
            </div>
            <p className="text-[10px] text-gray-600">
              Controls the speed of the packet animation on the canvas edges during simulation.
            </p>
          </div>

          {/* Error */}
          {error && (
            <p className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded-lg px-3 py-2">{error}</p>
          )}

          {/* Run button */}
          <button
            onClick={handleRun}
            disabled={loading || !!topologyError}
            className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-xl transition"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {loading ? 'Simulating…' : 'Run simulation'}
          </button>

          {activeRules.length === 0 && !topologyError && (
            <p className="text-xs text-yellow-500">
              No Suricata rules loaded — the simulation will run but nothing will be detected.
            </p>
          )}
        </div>

        {/* Results */}
        {result && (
          <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">

            {/* Attack outcome banner */}
            <div className={`rounded-xl border p-4 ${result.attack_blocked ? 'border-green-700/40 bg-green-950/20' : 'border-red-700/40 bg-red-950/20'}`}>
              <div className="flex items-start gap-3">
                {result.attack_blocked
                  ? <CheckCircle2 size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  : <ShieldOff size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                }
                <div className="flex-1">
                  <p className={`text-sm font-bold ${result.attack_blocked ? 'text-green-300' : 'text-red-300'}`}>
                    {result.attack_blocked
                      ? 'Attack blocked by defenses'
                      : result.attack_reached_target
                        ? 'Attack reached the target'
                        : 'Attack result unknown'
                    }
                  </p>
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">{result.summary}</p>

                  {/* Attack path */}
                  {result.attack_path && result.attack_path.length > 0 && (
                    <div className="mt-2 flex items-center gap-1 flex-wrap">
                      {result.attack_path.map(([src, dst], i) => (
                        <span key={i} className="flex items-center gap-1 text-[10px]">
                          <span className="font-mono text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded">{src}</span>
                          <span className="text-gray-600">→</span>
                          <span className="font-mono text-gray-300 bg-gray-800/60 px-1.5 py-0.5 rounded">{dst}</span>
                          {i < result.attack_path!.length - 1 && <span className="text-gray-700">·</span>}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Summary bar */}
            <div className="bg-gray-800/60 rounded-xl p-4 grid grid-cols-4 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{result.triggered_count}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">Rules fired</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-400">{result.results.length - result.triggered_count}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">No match</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-400">{result.total_packets}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">Packets</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-400">{packetRate}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">pps</p>
              </div>
            </div>

            {/* Defense impacts */}
            {result.defense_impacts && (
              <DefenseImpactSection
                impacts={result.defense_impacts}
                blocked={result.attack_blocked ?? false}
              />
            )}

            {/* Per-rule results */}
            {result.results.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">IDS Rule Results</p>
                {[...result.results]
                  .sort((a, b) => (b.fired ? 1 : 0) - (a.fired ? 1 : 0))
                  .map((r, i) => (
                    <RuleResultCard key={i} result={r} />
                  ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
