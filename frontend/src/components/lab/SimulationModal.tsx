import { useState, useRef, useLayoutEffect, useEffect } from 'react'
import {
  X, Play, ChevronDown, ChevronRight, ShieldCheck, ShieldOff,
  Loader2, Shield, AlertTriangle, CheckCircle2, Zap, Minimize2, Maximize2,
  Eye, EyeOff, Network, Activity, Target, ArrowRight, Circle,
  Minus, XCircle, ZapOff, Info, Clock, ArrowLeft, Server, FlaskConical,
} from 'lucide-react'
import { SCENARIOS, PREDEFINED_RULES } from '../../data/rules'
import { runSimulation, checkStatus } from '../../api/simulation'
import type { DockerStatus } from '../../api/simulation'
import type {
  ActiveRule, SimulationResult, RuleMatchResult, DefenseImpact, TimelineEvent, RuleEntry, SimulationRun,
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
  simHistory?: SimulationRun[]
  onRunSaved?: (run: SimulationRun) => void
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

      {/* Fallback warning — shown when Real Suricata was requested but Docker was unavailable */}
      {result.suricata_fallback && (
        <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-xl border border-amber-700/40 bg-amber-950/15">
          <AlertTriangle size={14} className="text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-semibold text-amber-300">Docker unavailable — approximate results</p>
            <p className="text-[11px] text-amber-300/70 mt-0.5 leading-relaxed">
              Real Suricata mode was requested but Docker could not be reached.
              Results below are from the Educational Simulation engine and may differ from real Suricata.
              Start Docker Desktop and re-run for production-accurate detection.
            </p>
          </div>
        </div>
      )}

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
        <div className="flex items-center gap-2 col-span-2">
          <span className="text-[10px] text-gray-600 uppercase tracking-wide w-20 flex-shrink-0">Engine</span>
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
            result.mode === 'suricata' && !result.suricata_fallback
              ? 'bg-green-900/50 text-green-300'
              : result.suricata_fallback
                ? 'bg-amber-900/40 text-amber-300'
                : 'bg-indigo-900/30 text-indigo-300'
          }`}>
            {result.mode === 'suricata' && !result.suricata_fallback
              ? 'Real Suricata'
              : result.suricata_fallback
                ? 'Educational Sim (fallback)'
                : 'Educational Sim'}
          </span>
        </div>
      </div>
    </div>
  )
}

// ─── Timeline event row ───────────────────────────────────────────────────────

type TLMeta = {
  Icon: React.ElementType
  iconClass: string
  rowClass: string
  badge?: string
  badgeClass?: string
}

function timelineMeta(type: TimelineEvent['type']): TLMeta {
  switch (type) {
    case 'hop':
      return { Icon: ArrowRight,    iconClass: 'text-gray-500',   rowClass: 'border-gray-700/30 bg-gray-800/20' }
    case 'defense_blocked':
      return { Icon: ShieldCheck,   iconClass: 'text-green-400',  rowClass: 'border-green-700/30 bg-green-950/20',  badge: 'BLOCKED',  badgeClass: 'bg-green-900/60 text-green-300' }
    case 'defense_passed':
      return { Icon: ShieldOff,     iconClass: 'text-amber-500',  rowClass: 'border-amber-700/20 bg-amber-950/10', badge: 'PASSED',   badgeClass: 'bg-amber-900/50 text-amber-400' }
    case 'no_defense':
      return { Icon: Shield,        iconClass: 'text-gray-600',   rowClass: 'border-gray-700/20 bg-gray-800/20',  badge: 'OPEN',     badgeClass: 'bg-gray-700/60 text-gray-500' }
    case 'ids_observed':
      return { Icon: Eye,           iconClass: 'text-indigo-400', rowClass: 'border-indigo-700/30 bg-indigo-950/20', badge: 'VISIBLE', badgeClass: 'bg-indigo-900/60 text-indigo-300' }
    case 'ids_blind':
      return { Icon: EyeOff,        iconClass: 'text-yellow-400', rowClass: 'border-yellow-700/30 bg-yellow-950/10', badge: 'BLIND', badgeClass: 'bg-yellow-900/40 text-yellow-400' }
    case 'rule_fired':
      return { Icon: Zap,           iconClass: 'text-red-400',    rowClass: 'border-red-700/40 bg-red-950/20',    badge: 'ALERT',    badgeClass: 'bg-red-900/60 text-red-300' }
    case 'rule_missed':
      return { Icon: ZapOff,        iconClass: 'text-gray-600',   rowClass: 'border-gray-700/20 bg-gray-800/10' }
    case 'outcome_blocked':
      return { Icon: CheckCircle2,  iconClass: 'text-green-400',  rowClass: 'border-green-700/40 bg-green-950/20', badge: 'STOPPED',   badgeClass: 'bg-green-900/60 text-green-300' }
    case 'outcome_detected':
      return { Icon: AlertTriangle, iconClass: 'text-yellow-400', rowClass: 'border-yellow-700/30 bg-yellow-950/10', badge: 'DETECTED', badgeClass: 'bg-yellow-900/40 text-yellow-300' }
    case 'outcome_undetected':
      return { Icon: XCircle,       iconClass: 'text-red-500',    rowClass: 'border-red-700/30 bg-red-950/10',    badge: 'MISSED',   badgeClass: 'bg-red-900/50 text-red-400' }
    default:
      return { Icon: Minus,         iconClass: 'text-gray-600',   rowClass: 'border-gray-700/20 bg-gray-800/10' }
  }
}

function TimelineRow({ event, index }: { event: TimelineEvent; index: number }) {
  const [open, setOpen] = useState(false)
  const meta = timelineMeta(event.type)
  const { Icon } = meta

  return (
    <div className={`rounded-xl border overflow-hidden ${meta.rowClass}`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-white/5 transition"
      >
        {/* Step number */}
        <span className="text-[10px] text-gray-600 w-4 text-right flex-shrink-0 font-mono">{index + 1}</span>
        {/* Icon */}
        <Icon size={14} className={`flex-shrink-0 ${meta.iconClass}`} />
        {/* Label */}
        <span className="flex-1 text-xs font-medium text-gray-200 truncate">{event.label}</span>
        {/* SID badge for rules */}
        {event.sid && (
          <span className="text-[9px] font-mono text-gray-600 flex-shrink-0">SID {event.sid}</span>
        )}
        {/* Status badge */}
        {meta.badge && (
          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0 ${meta.badgeClass}`}>
            {meta.badge}
          </span>
        )}
        {open
          ? <ChevronDown size={12} className="text-gray-600 flex-shrink-0" />
          : <ChevronRight size={12} className="text-gray-600 flex-shrink-0" />
        }
      </button>
      {open && (
        <div className="px-10 pb-3 border-t border-gray-700/20">
          <p className="text-[11px] text-gray-400 mt-2 leading-relaxed">{event.detail}</p>
          {/* Show IP hop detail */}
          {event.from_ip && event.to_ip && (
            <div className="flex items-center gap-2 mt-2">
              <span className="font-mono text-[10px] text-red-400 bg-red-950/30 px-1.5 py-0.5 rounded">{event.from_ip}</span>
              <ArrowRight size={10} className="text-gray-600" />
              <span className="font-mono text-[10px] text-gray-300 bg-gray-800/60 px-1.5 py-0.5 rounded">{event.to_ip}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Attack Path tab ──────────────────────────────────────────────────────────

function AttackPathTab({ result }: { result: SimulationResult }) {
  const path = result.attack_path ?? []
  const hasPath = path.length > 0
  const timeline = result.timeline ?? []

  // Build ordered unique IP list for the route visualization
  const pathNodes: string[] = []
  for (const [src, dst] of path) {
    if (pathNodes.length === 0) pathNodes.push(src)
    if (!pathNodes.includes(dst)) pathNodes.push(dst)
  }

  const isAttacker = (ip: string) => ip === result.attacker_ip
  const isTarget   = (ip: string) => result.target_ips?.includes(ip) ?? false

  function nodeStyle(ip: string) {
    if (isAttacker(ip)) return { ring: 'border-red-500 bg-red-950/40',   text: 'text-red-300',   label: 'ATTACKER' }
    if (isTarget(ip))   return { ring: 'border-blue-500 bg-blue-950/40', text: 'text-blue-300',  label: 'TARGET' }
    return                     { ring: 'border-amber-700/50 bg-amber-950/20', text: 'text-amber-300', label: 'HOP' }
  }

  if (!hasPath) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center gap-3">
        <Network size={32} className="text-gray-700" />
        <div>
          <p className="text-sm font-semibold text-gray-400">No Attack Path Found</p>
          <p className="text-xs text-gray-600 mt-1 max-w-xs leading-relaxed">
            The attacker could not reach any target. Check that communication
            edges connect the attacker to a target device.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">

      {/* Route visualization */}
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-3">
          Route — {pathNodes.length} node(s), {path.length} hop(s)
        </p>
        <div className="flex items-center gap-1 flex-wrap">
          {pathNodes.map((ip, i) => {
            const s = nodeStyle(ip)
            return (
              <div key={i} className="flex items-center gap-1">
                <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-xl border ${s.ring}`}>
                  <span className={`text-[9px] font-bold uppercase tracking-wider ${s.text}`}>{s.label}</span>
                  <span className="font-mono text-xs text-white">{ip}</span>
                </div>
                {i < pathNodes.length - 1 && <ArrowRight size={14} className="text-gray-600 flex-shrink-0" />}
              </div>
            )
          })}
        </div>
      </div>

      {/* Event timeline */}
      {timeline.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-2">
            Event Timeline
          </p>
          {timeline.map((event, i) => (
            <TimelineRow key={i} event={event} index={i} />
          ))}
        </div>
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

const LEARNING_DISMISSED_KEY = 'suricata_learning_mode_dismissed'

function DetectionTab({ result }: { result: SimulationResult }) {
  const idsVisible = result.ids_visible ?? true
  const noSensor = !idsVisible && (result.ids_node_labels?.length ?? 0) === 0
  const [learningVisible, setLearningVisible] = useState(
    () => localStorage.getItem(LEARNING_DISMISSED_KEY) !== '1'
  )
  const isSuricata   = result.mode === 'suricata' && !result.suricata_fallback
  const isFallback   = result.suricata_fallback === true

  function dismissLearning() {
    localStorage.setItem(LEARNING_DISMISSED_KEY, '1')
    setLearningVisible(false)
  }

  return (
    <div className="space-y-3">
      {/* Mode badge — changes based on which engine produced the results */}
      {isSuricata ? (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-950/20 border border-green-800/20 text-[11px] text-green-300/80">
          <FlaskConical size={12} className="flex-shrink-0 text-green-400" />
          <span className="flex-1">
            <span className="font-semibold text-green-300">Real Suricata</span>
            {' '}— results come directly from a Suricata process running in Docker.
            These are production-accurate: if a rule fires here, it fires on a real sensor.
          </span>
        </div>
      ) : isFallback ? (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-950/15 border border-amber-800/20 text-[11px] text-amber-300/80">
          <AlertTriangle size={12} className="flex-shrink-0 mt-0.5 text-amber-400" />
          <span className="flex-1">
            <span className="font-semibold text-amber-300">Fell back to Educational Sim</span>
            {' '}— Docker was unavailable when this run executed. Results are approximate.
            Start Docker Desktop and re-run for definitive detection results.
          </span>
        </div>
      ) : learningVisible && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-indigo-950/20 border border-indigo-800/20 text-[11px] text-indigo-300/80">
          <Info size={12} className="flex-shrink-0 mt-0.5 text-indigo-400/70" />
          <span className="flex-1">
            <span className="font-semibold text-indigo-300">Educational Sim</span>
            {' '}— rule evaluation is a simplified simulation. Most keywords are supported,
            but results may differ from real Suricata. Switch to Real Suricata mode for production accuracy.
          </span>
          <button
            onClick={dismissLearning}
            className="flex-shrink-0 text-indigo-600 hover:text-indigo-400 transition-colors ml-1"
            title="Dismiss"
          >
            <X size={12} />
          </button>
        </div>
      )}

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
              <RuleResultCard
                key={i}
                result={r}
                ruleEntry={PREDEFINED_RULES.find(p => p.sid === r.rule_sid)}
                dimmed={!idsVisible}
              />
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

function RuleResultCard({
  result,
  ruleEntry,
  dimmed = false,
}: {
  result: RuleMatchResult
  ruleEntry?: RuleEntry
  dimmed?: boolean
}) {
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

          {/* False positive callout — only shown when the rule fired */}
          {result.fired && ruleEntry?.false_positives && (
            <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg bg-amber-950/20 border border-amber-800/30">
              <AlertTriangle size={12} className="text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-[11px] font-semibold text-amber-400 mb-0.5">Potential False Positives</p>
                <p className="text-[11px] text-amber-300/80 leading-relaxed">{ruleEntry.false_positives}</p>
              </div>
            </div>
          )}

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
                        {(pkt.protocol ?? '?').toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono text-gray-400">
                        {pkt.src ?? `${pkt.src_ip}:${pkt.src_port}`} → {pkt.dst ?? `${pkt.dst_ip}:${pkt.dst_port}`}
                      </span>
                    </div>
                    <p className="text-[10px] text-gray-500">{pkt.description}</p>
                    {(pkt.payload_preview ?? pkt.payload) && (
                      <pre className="text-[10px] text-gray-600 font-mono mt-1 truncate">
                        {(pkt.payload_preview ?? pkt.payload ?? '').slice(0, 80)}
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

// ─── Docker install instructions (collapsible) ────────────────────────────────

function DockerInstallInstructions() {
  const [open, setOpen] = useState(false)
  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 text-[11px] text-amber-400/70 hover:text-amber-300 transition-colors"
      >
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        How to install Docker Desktop
      </button>
      {open && (
        <div className="mt-2 space-y-2 pl-4 border-l border-amber-800/30 text-[11px] text-gray-400 leading-relaxed">
          <p>
            <span className="font-semibold text-gray-300">Windows / macOS — </span>
            Download and install Docker Desktop from{' '}
            <span className="font-mono text-amber-300/80">docker.com/products/docker-desktop</span>,
            then launch it. The Docker icon will appear in your taskbar/menu bar when it's running.
          </p>
          <p>
            <span className="font-semibold text-gray-300">Linux — </span>
            <span className="font-mono text-amber-300/80">sudo apt install docker.io && sudo systemctl start docker</span>
            {' '}(Ubuntu/Debian), or follow the official docs for your distro.
          </p>
          <p className="text-gray-500">
            After Docker is running, you'll also need to pull the Suricata image once:{' '}
            <span className="font-mono text-gray-400">docker pull jasonish/suricata:latest</span>{' '}
            (~250 MB one-time download).
          </p>
        </div>
      )}
    </div>
  )
}

// ─── Docker status panel (shown when Real Suricata is selected but not ready) ─

function DockerStatusPanel({ status, loading }: { status: DockerStatus | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800/40 text-[11px] text-gray-500">
        <Loader2 size={11} className="animate-spin" />
        Checking Docker availability…
      </div>
    )
  }
  if (!status) {
    return (
      <div className="px-3 py-2.5 rounded-lg border border-amber-700/30 bg-amber-950/10 text-[11px] text-amber-300/70 leading-relaxed">
        <span className="font-semibold text-amber-300">Docker status unknown</span> — the backend may not be running.
        Simulation will use Educational (approximate) results as fallback.
      </div>
    )
  }
  if (status.ready) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-green-700/30 bg-green-950/10 text-[11px] text-green-300">
        <CheckCircle2 size={12} className="text-green-400 flex-shrink-0" />
        Docker ready · <span className="font-mono text-green-400/80">{status.image}</span>
      </div>
    )
  }
  // Not ready
  const isNotRunning = status.state === 'docker_unavailable'
  const isNotPulled  = status.state === 'image_not_pulled'
  return (
    <div className="px-3 py-2.5 rounded-xl border border-amber-700/30 bg-amber-950/10 space-y-1.5">
      <div className="flex items-start gap-2">
        <AlertTriangle size={13} className="text-amber-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <p className="text-[11px] font-semibold text-amber-300">
            {isNotRunning ? 'Docker not running' : 'First run will download Suricata (~250 MB)'}
          </p>
          {status.error && (
            <p className="text-[10px] text-amber-300/60 mt-0.5 leading-relaxed">{status.error}</p>
          )}
          {isNotRunning && (
            <p className="text-[10px] text-gray-500 mt-1.5 leading-relaxed">
              Simulation will still run using the Educational (approximate) engine as a fallback.
              Switch to Educational Sim to skip this warning.
            </p>
          )}
        </div>
      </div>
      {isNotRunning && <DockerInstallInstructions />}
    </div>
  )
}

// ─── History helpers ──────────────────────────────────────────────────────────

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function HistoryRunCard({ run, onClick }: { run: SimulationRun; onClick: () => void }) {
  const outcomeStyle =
    run.outcome === 'blocked'
      ? { border: 'border-green-700/40 bg-green-950/20',   badge: 'bg-green-900/60 text-green-300',   label: 'BLOCKED',    Icon: CheckCircle2,  iconClass: 'text-green-400' }
    : run.outcome === 'detected'
      ? { border: 'border-yellow-700/40 bg-yellow-950/10', badge: 'bg-yellow-900/40 text-yellow-300', label: 'DETECTED',   Icon: AlertTriangle, iconClass: 'text-yellow-400' }
      : { border: 'border-red-700/30 bg-red-950/10',       badge: 'bg-red-900/50 text-red-400',       label: 'UNDETECTED', Icon: ShieldOff,     iconClass: 'text-red-400' }

  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl border text-left hover:bg-white/5 transition ${outcomeStyle.border}`}
    >
      <outcomeStyle.Icon size={16} className={`flex-shrink-0 ${outcomeStyle.iconClass}`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-gray-300 truncate">{run.scenario_name}</p>
        <p className="text-[11px] text-gray-500 mt-0.5">
          {run.triggered_count} of {run.rule_count} rule{run.rule_count !== 1 ? 's' : ''} fired · {run.packet_rate} pps
        </p>
      </div>
      <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${outcomeStyle.badge}`}>
          {outcomeStyle.label}
        </span>
        <span className="text-[10px] text-gray-600">{formatTimeAgo(run.timestamp)}</span>
      </div>
    </button>
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
  simHistory,
  onRunSaved,
}: Props) {
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id)
  const [packetRate, setPacketRate] = useState(5)
  const [simMode, setSimMode] = useState<'python' | 'suricata'>('python')
  const [dockerStatus, setDockerStatus] = useState<DockerStatus | null>(null)
  const [dockerStatusLoading, setDockerStatusLoading] = useState(true)
  const [result, setResult] = useState<SimulationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [minimized, setMinimized] = useState(false)
  const [activeTab, setActiveTab] = useState<ResultTab>('overview')
  const [showHistory, setShowHistory] = useState(false)

  // Fetch Docker / Suricata availability on mount
  useEffect(() => {
    setDockerStatusLoading(true)
    checkStatus()
      .then(setDockerStatus)
      .catch(() => setDockerStatus(null))
      .finally(() => setDockerStatusLoading(false))
  }, [])

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
      const res = await runSimulation(projectId, scenarioId, ruleTexts, topology, simMode)
      // Lock config section height before results appear so they get the remaining space
      if (configH === null && configSectionRef.current) {
        setConfigH(configSectionRef.current.offsetHeight)
      }
      setResult(res)
      setActiveTab('overview')

      const run: SimulationRun = {
        id: `run-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: scenarioId,
        scenario_name: selectedScenario.name,
        packet_rate: packetRate,
        rule_count: activeRules.length,
        outcome: res.attack_blocked ? 'blocked' : res.triggered_count > 0 ? 'detected' : 'undetected',
        triggered_count: res.triggered_count,
        result: res,
      }
      onRunSaved?.(run)

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
        style={{ width: modalW, height: result || showHistory ? modalH : 'auto', maxWidth: '95vw', maxHeight: '95vh' }}
      >

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-lg font-bold text-white">Run Simulation</h2>
            <p className="text-xs text-gray-500 mt-0.5">{activeRules.length} rule(s) loaded</p>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setShowHistory(h => !h)}
              className={`relative text-gray-500 hover:text-white transition p-1.5 rounded-lg hover:bg-gray-800 ${showHistory ? 'text-indigo-400 bg-indigo-950/40' : ''}`}
              title="Run history"
            >
              <Clock size={15} />
              {(simHistory?.length ?? 0) > 0 && (
                <span className="absolute -top-0.5 -right-0.5 text-[8px] font-bold bg-indigo-600 text-white rounded-full w-3.5 h-3.5 flex items-center justify-center leading-none">
                  {(simHistory!.length) > 9 ? '9+' : simHistory!.length}
                </span>
              )}
            </button>
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

        {/* History panel — replaces config+results when open */}
        {showHistory && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex items-center gap-3 px-6 py-3 border-b border-gray-800 flex-shrink-0">
              <button
                onClick={() => setShowHistory(false)}
                className="text-gray-500 hover:text-white transition p-1 rounded-lg hover:bg-gray-800"
                title="Back"
              >
                <ArrowLeft size={14} />
              </button>
              <p className="text-sm font-semibold text-white">Run History</p>
              <span className="text-xs text-gray-600">
                {(simHistory?.length ?? 0)} run{(simHistory?.length ?? 0) !== 1 ? 's' : ''}
              </span>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-4 space-y-2">
              {(simHistory?.length ?? 0) === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center gap-3">
                  <Clock size={28} className="text-gray-700" />
                  <div>
                    <p className="text-sm font-semibold text-gray-500">No runs yet</p>
                    <p className="text-[11px] text-gray-600 mt-1 max-w-xs leading-relaxed">
                      Run a simulation and your results will be saved here automatically.
                    </p>
                  </div>
                </div>
              ) : (
                (simHistory ?? []).map(run => (
                  <HistoryRunCard
                    key={run.id}
                    run={run}
                    onClick={() => {
                      setResult(run.result)
                      setActiveTab('overview')
                      setShowHistory(false)
                    }}
                  />
                ))
              )}
            </div>
          </div>
        )}

        {/* Config section — scrollable, capped at 55% of modal height until user drags the split handle */}
        {!showHistory && <div
          ref={configSectionRef}
          className="px-6 py-4 space-y-4 flex-shrink-0 overflow-y-auto"
          style={configH !== null ? { height: configH } : { maxHeight: Math.round(modalH * 0.55) }}
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

          {/* Simulation mode toggle */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wide">
              Simulation Mode
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setSimMode('python')}
                className={`flex-1 flex items-center gap-2 px-3 py-2.5 rounded-xl border text-left transition ${
                  simMode === 'python'
                    ? 'border-indigo-500 bg-indigo-900/30 text-white'
                    : 'border-gray-700/50 bg-gray-800/30 text-gray-400 hover:border-gray-600'
                }`}
              >
                <Shield size={13} className={simMode === 'python' ? 'text-indigo-400' : 'text-gray-600'} />
                <div>
                  <p className="text-xs font-semibold">Educational Sim</p>
                  <p className="text-[10px] text-gray-500 mt-0.5">Approximate · detailed diagnostics</p>
                </div>
              </button>
              <button
                onClick={() => setSimMode('suricata')}
                className={`flex-1 flex items-center gap-2 px-3 py-2.5 rounded-xl border text-left transition ${
                  simMode === 'suricata'
                    ? 'border-green-600/60 bg-green-950/20 text-white'
                    : 'border-gray-700/50 bg-gray-800/30 text-gray-400 hover:border-gray-600'
                }`}
              >
                <FlaskConical size={13} className={simMode === 'suricata' ? 'text-green-400' : 'text-gray-600'} />
                <div>
                  <p className="text-xs font-semibold">Real Suricata</p>
                  <p className="text-[10px] text-gray-500 mt-0.5">Production-accurate · Docker</p>
                </div>
              </button>
            </div>
            {simMode === 'suricata' && (
              <DockerStatusPanel status={dockerStatus} loading={dockerStatusLoading} />
            )}
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
            {loading
              ? simMode === 'suricata' && dockerStatus && !dockerStatus.image_available
                ? 'Pulling Suricata image…'
                : 'Simulating…'
              : 'Run simulation'
            }
          </button>

          {activeRules.length === 0 && !topologyError && (
            <p className="text-xs text-yellow-500">
              No Suricata rules loaded — the simulation will run but nothing will be detected.
            </p>
          )}
        </div>}

        {/* Horizontal split drag strip + results — only shown once results exist */}
        {!showHistory && result && (
          <>
            <div
              className="h-1.5 flex-shrink-0 cursor-ns-resize flex items-center justify-center group bg-gray-800/60 hover:bg-indigo-950/40 transition-colors border-y border-gray-800/80"
              onMouseDown={onSplitMouseDown}
            >
              <div className="w-8 h-0.5 rounded-full bg-gray-700 group-hover:bg-indigo-500 transition-colors" />
            </div>

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
