import { useState } from 'react'
import { X, Play, ChevronDown, ChevronRight, ShieldCheck, ShieldOff, Loader2 } from 'lucide-react'
import { SCENARIOS } from '../../data/rules'
import { runSimulation } from '../../api/simulation'
import type { ActiveRule, SimulationResult, RuleMatchResult } from '../../types/lab'

interface Props {
  projectId: number
  activeRules: ActiveRule[]
  onClose: () => void
}

function RuleResultCard({ result }: { result: RuleMatchResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className={`rounded-xl border overflow-hidden ${result.fired ? 'border-red-700/50 bg-red-950/20' : 'border-gray-700/40 bg-gray-800/20'}`}>
      {/* Header */}
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

      {/* Expanded detail */}
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

export default function SimulationModal({ projectId, activeRules, onClose }: Props) {
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id)
  const [result, setResult] = useState<SimulationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const selectedScenario = SCENARIOS.find((s) => s.id === scenarioId)!

  async function handleRun() {
    setError('')
    setLoading(true)
    setResult(null)
    try {
      const ruleTexts = activeRules.map((r) => r.customText ?? r.entry.rule)
      const res = await runSimulation(projectId, scenarioId, ruleTexts)
      setResult(res)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Simulation failed. Check that the backend is running.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-lg font-bold text-white">Run Simulation</h2>
            <p className="text-xs text-gray-500 mt-0.5">{activeRules.length} rule(s) loaded</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition">
            <X size={18} />
          </button>
        </div>

        {/* Scenario picker */}
        <div className="px-6 py-4 border-b border-gray-800 space-y-3">
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

          {error && (
            <p className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded-lg px-3 py-2">{error}</p>
          )}

          <button
            onClick={handleRun}
            disabled={loading || activeRules.length === 0}
            className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold rounded-xl transition"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {loading ? 'Simulating…' : 'Run simulation'}
          </button>

          {activeRules.length === 0 && (
            <p className="text-xs text-yellow-500">Add rules in the Rule Library before running.</p>
          )}
        </div>

        {/* Results */}
        {result && (
          <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
            {/* Summary bar */}
            <div className="bg-gray-800/60 rounded-xl p-4 flex items-center gap-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{result.triggered_count}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">Triggered</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-400">{result.results.length - result.triggered_count}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">No match</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-400">{result.total_packets}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide">Packets</p>
              </div>
              <div className="flex-1 text-right">
                <p className="text-xs text-gray-400 leading-relaxed">{result.summary}</p>
                <p className="text-[10px] text-gray-600 mt-1">HOME_NET: {result.home_net}</p>
              </div>
            </div>

            {/* Per-rule results */}
            <div className="space-y-2">
              {/* Fired first */}
              {[...result.results]
                .sort((a, b) => (b.fired ? 1 : 0) - (a.fired ? 1 : 0))
                .map((r, i) => (
                  <RuleResultCard key={i} result={r} />
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
