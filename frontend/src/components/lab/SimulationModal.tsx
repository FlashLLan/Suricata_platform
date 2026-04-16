import { useState, useRef, useLayoutEffect } from 'react'
import {
  X, Play, ChevronDown, ChevronRight, ShieldCheck, ShieldOff,
  Loader2, Shield, AlertTriangle, CheckCircle2, Zap, Minimize2, Maximize2,
  Eye, EyeOff, Network, Activity, Target, ArrowRight, Circle,
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

type ResultTab = 'overview' | 'path' | 'defenses' | 'detection'

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

// ─── Tab bar ──────────────────────────────────────────────────────────────────

function ResultTabBar({ active, onChange, result }: {
  active: ResultTab
  onChange: (tab: ResultTab) => void
  result: SimulationResult
}) {
  const tabs: { id: ResultTab; label: string; Icon: React.ElementType; badge?: number; badgeAlert?: boolean }[] = [
    { id: 'overview', label: 'Overview', Icon: Activity },
    { id: 'path',     label: 'Attack Path', Icon: Network },
    {
      id: 'defenses', label: 'Defenses', Icon: Shield,
      badge: result.defense_impacts?.length ?? 0,
    },
    {
      id: 'detection', label: 'Detection', Icon: Eye,
      badge: result.results.length,
      badgeAlert: result.triggered_count > 0,
    },
  ]

  return (
    <div className="flex border-b border-gray-800 px-2">
      {tabs.map(({ id, label, Icon, badge, badgeAlert }) => (
        <button
          key={id}
          onClick={() => onChange(id)}
          className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-semibold transition border-b-2 -mb-px ${
            active === id
              ? 'text-indigo-300 border-indigo-500'
              : 'text-gray-500 border-transparent hover:text-gray-300'
          }`}
        >
          <Icon size={13} />
          {label}
          {badge !== undefined && badge > 0 && (
            <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
              badgeAlert
                ? 'bg-red-900/60 text-red-300'
                : active === id
                  ? 'bg-indigo-900/60 text-indigo-300'
                  : 'bg-gray-800 text-gray-500'
            }`}>
              {badge}
            </span>
          )}
        </button>
      ))}
    </div>
  )
}

// ─── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({ result, packetRate }: { result: SimulationResult; packetRate: number }) {
  // Determine verdict
  const blocked = result.attack_blocked
  const detected = result.triggered_count > 0
  const idsVisible = result.ids_visible ?? true
  const hasPath = result.attack_path && result.attack_path.length > 0

  const verdictColor = blocked
    ? 'border-green-700/40 bg-green-950/20'
    : detected
      ? 'border-yellow-700/40 bg-yellow-950/10'
      : 'border-red-700/40 bg-red-950/20'

  const verdictIcon = blocked
    ? <CheckCircle2 size={22} className="text-green-400 flex-shrink-0" />
    : detected
      ? <Eye size={22} className="text-yellow-400 flex-shrink-0" />
      : <ShieldOff size={22} className="text-red-400 flex-shrink-0" />

  const verdictTitle = blocked
    ? 'Attack Blocked'
    : detected
      ? 'Attack Detected'
      : 'Attack Undetected'

  const verdictSubtitle = blocked
    ? 'Defenses stopped the attack before it reached the target.'
    : detected
      ? 'The attack reached the target and Suricata triggered an alert.'
      : result.attack_reached_target
        ? 'The attack reached the target without triggering any rules.'
        : 'Attack result could not be fully determined.'

  // Causality chain steps
  type StepStatus = 'ok' | 'warn' | 'fail' | 'neutral'
  const steps: { label: string; detail: string; status: StepStatus }[] = [
    {
      label: 'Attack Origin',
      detail: result.attacker_ip ? `Attacker: ${result.attacker_ip}` : 'Attacker identified',
      status: 'ok',
    },
    {
      label: 'Path to Target',
      detail: hasPath
        ? `${result.attack_path!.length} hop(s) to ${result.target_ips?.join(', ')}`
        : 'No route found',
      status: hasPath ? 'ok' : 'fail',
    },
    {
      label: 'Defenses',
      detail: blocked
        ? 'Traffic blocked before delivery'
        : result.defense_impacts && result.defense_impacts.length > 0
          ? 'Defenses evaluated — traffic passed'
          : 'No defenses configured',
      status: blocked ? 'ok' : result.defense_impacts && result.defense_impacts.length > 0 ? 'warn' : 'neutral',
    },
    {
      label: 'IDS Coverage',
      detail: idsVisible
        ? `Monitored by ${result.ids_node_labels?.join(', ') || 'IDS'}`
        : 'Traffic not visible to any IDS sensor',
      status: idsVisible ? 'ok' : 'warn',
    },
    {
      label: 'Detection',
      detail: blocked
        ? 'No packets reached IDS (blocked)'
        : !idsVisible
          ? 'IDS blind — rules not evaluated'
          : result.results.length === 0
            ? 'No rules loaded'
            : `${result.triggered_count} of ${result.results.length} rule(s) fired`,
      status: blocked
        ? 'neutral'
        : !idsVisible || result.results.length === 0
          ? 'warn'
          : detected
            ? 'ok'
            : 'fail',
    },
  ]

  const stepColor: Record<StepStatus, string> = {
    ok:      'text-green-400',
    warn:    'text-yellow-400',
    fail:    'text-red-400',
    neutral: 'text-gray-500',
  }
  const stepBg: Record<StepStatus, string> = {
    ok:      'border-green-700/30 bg-green-950/20',
    warn:    'border-yellow-700/30 bg-yellow-950/10',
    fail:    'border-red-700/30 bg-red-950/20',
    neutral: 'border-gray-700/30 bg-gray-800/20',
  }

  return (
    <div className="space-y-4">

      {/* Verdict banner */}
      <div className={`rounded-xl border p-4 flex items-start gap-3 ${verdictColor}`}>
        {verdictIcon}
        <div className="flex-1 min-w-0">
          <p className={`text-base font-bold ${blocked ? 'text-green-300' : detected ? 'text-yellow-300' : 'text-red-300'}`}>
            {verdictTitle}
          </p>
          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{verdictSubtitle}</p>
          <p className="text-[11px] text-gray-500 mt-2 leading-relaxed italic">{result.summary}</p>
        </div>
      </div>

      {/* Stats grid */}
      <div className="bg-gray-800/50 rounded-xl p-4 grid grid-cols-4 gap-3 text-center">
        <div>
          <p className="text-2xl font-bold text-white">{result.total_packets}</p>
          <p className="text-[10px] text-gray-500 uppercase tracking-wide mt-0.5">Packets</p>
        </div>
        <div>
          <p className={`text-2xl font-bold ${result.triggered_count > 0 ? 'text-red-400' : 'text-gray-400'}`}>
            {result.triggered_count}
          </p>
          <p className="text-[10px] text-gray-500 uppercase tracking-wide mt-0.5">Rules fired</p>
        </div>
        <div>
          <p className={`text-2xl font-bold ${blocked ? 'text-green-400' : 'text-gray-500'}`}>
            {blocked ? '✓' : '✗'}
          </p>
          <p className="text-[10px] text-gray-500 uppercase tracking-wide mt-0.5">Blocked</p>
        </div>
        <div>
          <p className={`text-2xl font-bold ${idsVisible ? 'text-indigo-400' : 'text-gray-500'}`}>
            {idsVisible ? '✓' : '✗'}
          </p>
          <p className="text-[10px] text-gray-500 uppercase tracking-wide mt-0.5">IDS saw it</p>
        </div>
      </div>

      {/* Causality chain */}
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-2">
          Attack Chain
        </p>
        <div className="space-y-1.5">
          {steps.map((step, i) => (
            <div key={i} className={`flex items-start gap-3 px-3 py-2.5 rounded-lg border ${stepBg[step.status]}`}>
              <div className={`text-[10px] font-bold w-4 text-center mt-0.5 flex-shrink-0 ${stepColor[step.status]}`}>
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-gray-300">{step.label}</p>
                <p className={`text-[11px] mt-0.5 ${stepColor[step.status]}`}>{step.detail}</p>
              </div>
              <Circle
                size={8}
                className={`mt-1.5 flex-shrink-0 fill-current ${stepColor[step.status]}`}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Environment */}
      <div className="bg-gray-800/30 rounded-xl px-4 py-3 grid grid-cols-2 gap-x-6 gap-y-1.5">
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-gray-600 uppercase tracking-wide w-20 flex-shrink-0">HOME_NET</span>
          <span className="text-[11px] font-mono text-gray-400 truncate">{result.home_net || '—'}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-gray-600 uppercase tracking-wide w-20 flex-shrink-0">Rate</span>
          <span className="text-[11px] font-mono text-gray-400">{packetRate} pps</span>
        </div>
        {result.attacker_ip && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-600 uppercase tracking-wide w-20 flex-shrink-0">Attacker</span>
            <span className="text-[11px] font-mono text-red-400">{result.attacker_ip}</span>
          </div>
        )}
        {result.target_ips && result.target_ips.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-600 uppercase tracking-wide w-20 flex-shrink-0">Target(s)</span>
            <span className="text-[11px] font-mono text-blue-400 truncate">{result.target_ips.join(', ')}</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Attack Path tab ──────────────────────────────────────────────────────────

function AttackPathTab({ result }: { result: SimulationResult }) {
  const path = result.attack_path ?? []
  const hasPath = path.length > 0

  // Extract ordered unique IPs in path
  const pathNodes: string[] = []
  for (const [src, dst] of path) {
    if (pathNodes.length === 0) pathNodes.push(src)
    if (!pathNodes.includes(dst)) pathNodes.push(dst)
  }

  const isAttacker = (ip: string) => ip === result.attacker_ip
  const isTarget = (ip: string) => result.target_ips?.includes(ip)

  function nodeStyle(ip: string) {
    if (isAttacker(ip)) return { ring: 'border-red-500 bg-red-950/40', text: 'text-red-300', label: 'ATTACKER' }
    if (isTarget(ip)) return { ring: 'border-blue-500 bg-blue-950/40', text: 'text-blue-300', label: 'TARGET' }
    return { ring: 'border-amber-700/50 bg-amber-950/20', text: 'text-amber-300', label: 'HOP' }
  }

  return (
    <div className="space-y-4">
      {!hasPath ? (
        <div className="flex flex-col items-center justify-center py-10 text-center gap-3">
          <Network size={32} className="text-gray-700" />
          <div>
            <p className="text-sm font-semibold text-gray-400">No Attack Path Found</p>
            <p className="text-xs text-gray-600 mt-1 max-w-xs leading-relaxed">
              The attacker could not reach any target through the current topology. Check
              that communication edges exist between the attacker and target device(s).
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* Path visualization */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-3">
              Route — {pathNodes.length} node(s), {path.length} hop(s)
            </p>
            <div className="flex items-center gap-1 flex-wrap">
              {pathNodes.map((ip, i) => {
                const style = nodeStyle(ip)
                return (
                  <div key={i} className="flex items-center gap-1">
                    <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-xl border ${style.ring}`}>
                      <span className={`text-[9px] font-bold uppercase tracking-wider ${style.text}`}>
                        {style.label}
                      </span>
                      <span className="font-mono text-xs text-white">{ip}</span>
                    </div>
                    {i < pathNodes.length - 1 && (
                      <ArrowRight size={14} className="text-gray-600 flex-shrink-0" />
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Hop table */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-2">
              Hop Detail
            </p>
            <div className="space-y-1">
              {path.map(([src, dst], i) => (
                <div key={i} className="flex items-center gap-3 px-3 py-2 bg-gray-800/40 rounded-lg">
                  <span className="text-[10px] text-gray-600 w-4 text-right">{i + 1}</span>
                  <span className="font-mono text-xs text-gray-300">{src}</span>
                  <ArrowRight size={12} className="text-gray-600 flex-shrink-0" />
                  <span className="font-mono text-xs text-gray-300">{dst}</span>
                  {isAttacker(src) && (
                    <span className="ml-auto text-[9px] text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded">origin</span>
                  )}
                  {isTarget(dst) && (
                    <span className="ml-auto text-[9px] text-blue-400 bg-blue-950/40 px-1.5 py-0.5 rounded">target</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* IDS on path note */}
          {result.ids_node_labels && result.ids_node_labels.length > 0 && (
            <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl border border-indigo-700/30 bg-indigo-950/20">
              <Eye size={13} className="text-indigo-400 mt-0.5 flex-shrink-0" />
              <p className="text-[11px] text-indigo-300 leading-relaxed">
                <span className="font-semibold">{result.ids_node_labels.join(', ')}</span> monitored
                traffic along this path via a monitoring link.
              </p>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ─── Defenses tab ─────────────────────────────────────────────────────────────

function DefensesTab({ result }: { result: SimulationResult }) {
  const [openIdx, setOpenIdx] = useState<number | null>(null)
  const impacts = result.defense_impacts ?? []
  const blocked = result.attack_blocked ?? false

  if (impacts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center gap-3">
        <Shield size={32} className="text-gray-700" />
        <div>
          <p className="text-sm font-semibold text-gray-400">No Defenses Evaluated</p>
          <p className="text-xs text-gray-600 mt-1 max-w-xs leading-relaxed">
            No defense controls were active on the target device(s). Configure defenses in
            the Device Config panel to see how they affect the attack.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Overall verdict */}
      <div className={`rounded-xl border px-4 py-3 flex items-center gap-3 ${
        blocked
          ? 'border-green-700/40 bg-green-950/20'
          : 'border-gray-700/40 bg-gray-800/20'
      }`}>
        <Shield size={16} className={blocked ? 'text-green-400' : 'text-gray-500'} />
        <div className="flex-1">
          <p className={`text-sm font-semibold ${blocked ? 'text-green-300' : 'text-gray-300'}`}>
            {blocked ? 'Defenses stopped the attack' : 'Attack passed through defenses'}
          </p>
          <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">
            Defenses are evaluated <em>before</em> IDS rules — a blocking defense stops
            the attack before Suricata even sees the traffic.
          </p>
        </div>
        <span className={`text-[10px] font-bold px-2 py-1 rounded-full flex-shrink-0 ${
          blocked ? 'bg-green-900/60 text-green-300' : 'bg-gray-700/60 text-gray-400'
        }`}>
          {blocked ? 'BLOCKED' : 'PASSED'}
        </span>
      </div>

      {/* Defense cards */}
      <div className="space-y-1.5">
        {impacts.map((impact, i) => (
          <div
            key={i}
            className={`rounded-xl border overflow-hidden ${
              impact.blocked
                ? 'border-green-800/30 bg-green-950/10'
                : 'border-gray-700/30 bg-gray-800/20'
            }`}
          >
            <button
              onClick={() => setOpenIdx(openIdx === i ? null : i)}
              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition"
            >
              {impact.blocked
                ? <CheckCircle2 size={14} className="text-green-400 flex-shrink-0" />
                : <ShieldOff size={14} className="text-gray-600 flex-shrink-0" />
              }
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-gray-300">
                  {impact.defense_name}
                  {impact.device_label && (
                    <span className="font-normal text-gray-600"> · {impact.device_label}</span>
                  )}
                </p>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 mr-1 ${
                impact.blocked ? 'bg-green-900/60 text-green-400' : 'bg-gray-700/60 text-gray-500'
              }`}>
                {impact.blocked ? 'BLOCKED' : 'PASSED'}
              </span>
              {openIdx === i
                ? <ChevronDown size={13} className="text-gray-600 flex-shrink-0" />
                : <ChevronRight size={13} className="text-gray-600 flex-shrink-0" />
              }
            </button>
            {openIdx === i && (
              <div className="px-4 pb-3 border-t border-gray-700/20">
                <p className="text-xs text-gray-400 mt-3 leading-relaxed">{impact.explanation}</p>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Detection tab ────────────────────────────────────────────────────────────

function DetectionTab({ result }: { result: SimulationResult }) {
  const idsVisible = result.ids_visible ?? true
  const noSensor = !idsVisible && (result.ids_node_labels?.length ?? 0) === 0

  return (
    <div className="space-y-3">
      {/* IDS visibility banner */}
      <div className={`rounded-xl border px-4 py-3 flex items-start gap-3 ${
        idsVisible
          ? 'border-indigo-700/40 bg-indigo-950/20'
          : 'border-yellow-700/40 bg-yellow-950/10'
      }`}>
        {idsVisible
          ? <Eye size={16} className="text-indigo-400 flex-shrink-0 mt-0.5" />
          : <EyeOff size={16} className="text-yellow-400 flex-shrink-0 mt-0.5" />
        }
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold ${idsVisible ? 'text-indigo-300' : 'text-yellow-300'}`}>
            {idsVisible ? 'Traffic Visible to IDS' : 'Traffic Not Visible to IDS'}
          </p>
          {idsVisible ? (
            <p className="text-[11px] text-gray-400 mt-0.5 leading-relaxed">
              {result.ids_node_labels?.join(', ')} {(result.ids_node_labels?.length ?? 0) === 1 ? 'has' : 'have'} a
              monitoring link to a node on the attack path — rule evaluation applies.
            </p>
          ) : noSensor ? (
            <p className="text-[11px] text-yellow-500/80 mt-0.5 leading-relaxed">
              No IDS sensor is deployed in this topology. Add an IDS node and connect it
              with a monitoring link to a device on the attack route.
            </p>
          ) : (
            <p className="text-[11px] text-yellow-500/80 mt-0.5 leading-relaxed">
              An IDS sensor exists but is not connected to any node the attack passes through.
              Move the monitoring link closer to the attacker, a router on the path, or the target.
            </p>
          )}
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${
          idsVisible
            ? 'bg-indigo-900/60 text-indigo-300'
            : 'bg-yellow-900/40 text-yellow-400'
        }`}>
          {idsVisible ? 'VISIBLE' : 'BLIND'}
        </span>
      </div>

      {/* Rules */}
      {result.results.length > 0 ? (
        <div className="space-y-1.5">
          <p className={`text-[10px] font-semibold uppercase tracking-wide ${
            !idsVisible ? 'text-yellow-700' : 'text-gray-500'
          }`}>
            Rule Results ({result.results.length})
            {!idsVisible && (
              <span className="ml-2 normal-case font-normal text-yellow-700">— not evaluated (IDS blind)</span>
            )}
          </p>
          {[...result.results]
            .sort((a, b) => (b.fired ? 1 : 0) - (a.fired ? 1 : 0))
            .map((r, i) => (
              <RuleResultCard key={i} result={r} dimmed={!idsVisible} />
            ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-8 text-center gap-2">
          <Target size={28} className="text-gray-700" />
          <p className="text-xs text-gray-500">No rules loaded — nothing to evaluate.</p>
          <p className="text-[10px] text-gray-600 max-w-xs leading-relaxed">
            Add Suricata rules from the rule library to test detection against this scenario.
          </p>
        </div>
      )}
    </div>
  )
}

// ─── Rule result card ─────────────────────────────────────────────────────────

function RuleResultCard({ result, dimmed = false }: { result: RuleMatchResult; dimmed?: boolean }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className={`rounded-xl border overflow-hidden transition-opacity ${
      dimmed ? 'opacity-50' : ''
    } ${result.fired ? 'border-red-700/50 bg-red-950/20' : 'border-gray-700/40 bg-gray-800/20'}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition"
      >
        {result.fired
          ? <ShieldOff size={16} className="text-red-400 flex-shrink-0" />
          : <ShieldCheck size={16} className="text-green-500 flex-shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <p className={`text-xs font-medium truncate ${result.fired ? 'text-red-300' : 'text-gray-300'}`}>
            {result.rule_msg || `SID ${result.rule_sid}`}
          </p>
          <p className="text-[11px] text-gray-500">SID {result.rule_sid}</p>
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${
          result.fired ? 'bg-red-900/60 text-red-300' : 'bg-gray-700/60 text-gray-400'
        }`}>
          {result.fired ? 'FIRED' : 'NO MATCH'}
        </span>
        {expanded
          ? <ChevronDown size={14} className="text-gray-500 flex-shrink-0" />
          : <ChevronRight size={14} className="text-gray-500 flex-shrink-0" />
        }
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
                        {pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}
                      </span>
                    </div>
                    <p className="text-[10px] text-gray-500">{pkt.description}</p>
                    {pkt.payload && (
                      <pre className="text-[10px] text-gray-600 font-mono mt-1 truncate">
                        {pkt.payload.slice(0, 80)}
                      </pre>
                    )}
                  </div>
                ))}
                {result.matched_packets.length > 5 && (
                  <p className="text-[10px] text-gray-600">
                    …and {result.matched_packets.length - 5} more packets
                  </p>
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
  const [activeTab, setActiveTab] = useState<ResultTab>('overview')

  // ── Modal resize (corner) ────────────────────────────────────────────────
  const [modalW, setModalW] = useState(672)
  const [modalH, setModalH] = useState(680)
  const resizeDrag = useRef<{ startX: number; startY: number; startW: number; startH: number } | null>(null)

  // ── Config / results split resize (horizontal divider) ───────────────────
  // null = natural auto height (before first drag); number = locked pixel height
  const [configH, setConfigH] = useState<number | null>(null)
  const configSectionRef = useRef<HTMLDivElement>(null)
  const splitDrag = useRef<{ startY: number; startH: number } | null>(null)

  useLayoutEffect(() => {
    function onMove(e: MouseEvent) {
      // Corner resize
      if (resizeDrag.current) {
        const dW = e.clientX - resizeDrag.current.startX
        const dH = e.clientY - resizeDrag.current.startY
        setModalW(Math.max(480, Math.min(window.innerWidth  * 0.95, resizeDrag.current.startW + dW)))
        setModalH(Math.max(400, Math.min(window.innerHeight * 0.95, resizeDrag.current.startH + dH)))
      }
      // Horizontal split resize
      if (splitDrag.current) {
        const delta = e.clientY - splitDrag.current.startY
        setConfigH(Math.max(120, Math.min(560, splitDrag.current.startH + delta)))
      }
    }
    function onUp() {
      resizeDrag.current = null
      splitDrag.current = null
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [])

  function onResizeMouseDown(e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    resizeDrag.current = { startX: e.clientX, startY: e.clientY, startW: modalW, startH: modalH }
  }

  function onSplitMouseDown(e: React.MouseEvent) {
    e.preventDefault()
    // If no explicit height yet, snapshot the element's current rendered height
    const currentH = configH ?? configSectionRef.current?.offsetHeight ?? 320
    splitDrag.current = { startY: e.clientY, startH: currentH }
  }

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
      // Lock config section height before results appear so they get the remaining space
      if (configH === null && configSectionRef.current) {
        setConfigH(configSectionRef.current.offsetHeight)
      }
      setResult(res)
      setActiveTab('overview')

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
    setConfigH(null)
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
      <div
        className="bg-gray-900 border border-gray-700 rounded-2xl flex flex-col shadow-2xl relative overflow-hidden"
        style={{ width: modalW, height: modalH, maxWidth: '95vw', maxHeight: '95vh' }}
      >

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

        {/* Config section — natural height until user drags the split handle */}
        <div
          ref={configSectionRef}
          className={`px-6 py-4 space-y-4 flex-shrink-0 ${configH !== null ? 'overflow-y-auto' : ''}`}
          style={configH !== null ? { height: configH } : {}}
        >

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
          </div>

          {error && (
            <p className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded-lg px-3 py-2">{error}</p>
          )}

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

        {/* Horizontal split drag strip — always visible, separates config from results */}
        <div
          className="h-1.5 flex-shrink-0 cursor-ns-resize flex items-center justify-center group bg-gray-800/60 hover:bg-indigo-950/40 transition-colors border-y border-gray-800/80"
          onMouseDown={onSplitMouseDown}
        >
          <div className="w-8 h-0.5 rounded-full bg-gray-700 group-hover:bg-indigo-500 transition-colors" />
        </div>

        {/* Results — tab layout */}
        {result && (
          <>
            <ResultTabBar active={activeTab} onChange={setActiveTab} result={result} />
            <div className="flex-1 overflow-y-auto px-6 py-4">
              {activeTab === 'overview'  && <OverviewTab result={result} packetRate={packetRate} />}
              {activeTab === 'path'      && <AttackPathTab result={result} />}
              {activeTab === 'defenses'  && <DefensesTab result={result} />}
              {activeTab === 'detection' && <DetectionTab result={result} />}
            </div>
          </>
        )}

        {/* Resize handle — bottom-right corner */}
        <div
          className="absolute bottom-0 right-0 w-5 h-5 cursor-se-resize z-10 flex items-end justify-end pb-1 pr-1 opacity-30 hover:opacity-80 transition-opacity"
          onMouseDown={onResizeMouseDown}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor" className="text-gray-400">
            <circle cx="8.5" cy="8.5" r="1.1" />
            <circle cx="8.5" cy="5"   r="1.1" />
            <circle cx="5"   cy="8.5" r="1.1" />
            <circle cx="8.5" cy="1.5" r="1.1" />
            <circle cx="5"   cy="5"   r="1.1" />
            <circle cx="1.5" cy="8.5" r="1.1" />
          </svg>
        </div>
      </div>
    </div>
  )
}
