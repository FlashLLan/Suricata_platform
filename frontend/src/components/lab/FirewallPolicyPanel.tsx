import { useState } from 'react'
import { Shield, Plus, Trash2, ChevronDown, ChevronRight, Info } from 'lucide-react'
import type {
  FirewallPolicy, FirewallRule, FWChain, FWProtocol, FWAction, FWZone,
} from '../../types/lab'

// ── Constants ──────────────────────────────────────────────────────────────────

const CHAINS:    { value: FWChain;    label: string }[] = [
  { value: 'forward', label: 'Forward' },
  { value: 'input',   label: 'Input'   },
  { value: 'output',  label: 'Output'  },
]

const PROTOCOLS: { value: FWProtocol; label: string }[] = [
  { value: 'any',  label: 'Any'  },
  { value: 'tcp',  label: 'TCP'  },
  { value: 'udp',  label: 'UDP'  },
  { value: 'icmp', label: 'ICMP' },
]

const ZONES: { value: FWZone; label: string }[] = [
  { value: 'any',        label: 'Any zone'   },
  { value: 'external',   label: 'External'   },
  { value: 'internal',   label: 'Internal'   },
  { value: 'dmz',        label: 'DMZ'        },
  { value: 'management', label: 'Management' },
]

const ACTIONS: { value: FWAction; label: string; cls: string }[] = [
  { value: 'accept', label: 'Accept', cls: 'bg-green-900/60 text-green-300 border-green-700/40' },
  { value: 'drop',   label: 'Drop',   cls: 'bg-red-900/60   text-red-300   border-red-700/40'   },
  { value: 'reject', label: 'Reject', cls: 'bg-amber-900/60 text-amber-300 border-amber-700/40' },
]

const CHAIN_EXPLANATIONS: Record<FWChain, string> = {
  input:   'Traffic destined FOR the firewall itself (e.g. SSH management access to the firewall).',
  output:  'Traffic ORIGINATING from the firewall (e.g. the firewall polling an update server).',
  forward: 'Traffic PASSING THROUGH the firewall between zones — this is the most important chain for attack scenarios.',
}

// ── Presets ────────────────────────────────────────────────────────────────────

interface Preset {
  id: string
  label: string
  description: string
  policy: FirewallPolicy
}

function makeRule(partial: Partial<FirewallRule> & { chain: FWChain; action: FWAction; description: string }): FirewallRule {
  return {
    id: `preset-${Math.random().toString(36).slice(2, 9)}`,
    enabled: true,
    srcZone: 'any',
    dstZone: 'any',
    protocol: 'any',
    dstPort: '',
    ...partial,
  }
}

const PRESETS: Preset[] = [
  {
    id: 'default-deny-external',
    label: 'Default Deny External',
    description: 'Block all external inbound; allow internal outbound. Baseline hardened stance.',
    policy: {
      defaultInput: 'drop',
      defaultForward: 'drop',
      defaultOutput: 'accept',
      rules: [
        makeRule({ chain: 'forward', srcZone: 'internal',   dstZone: 'any',      action: 'accept', description: 'Internal → anywhere: allowed' }),
        makeRule({ chain: 'forward', srcZone: 'management', dstZone: 'any',      action: 'accept', description: 'Management → anywhere: allowed' }),
        makeRule({ chain: 'forward', srcZone: 'external',   dstZone: 'internal', action: 'drop',   description: 'External → Internal: BLOCKED' }),
      ],
    },
  },
  {
    id: 'public-web-server',
    label: 'Public Web Server',
    description: 'Expose HTTP/HTTPS to DMZ only; block external access to internal network.',
    policy: {
      defaultInput: 'drop',
      defaultForward: 'drop',
      defaultOutput: 'accept',
      rules: [
        makeRule({ chain: 'forward', srcZone: 'external', dstZone: 'dmz',      protocol: 'tcp', dstPort: '80,443', action: 'accept', description: 'External → DMZ web traffic allowed' }),
        makeRule({ chain: 'forward', srcZone: 'internal', dstZone: 'any',      action: 'accept', description: 'Internal outbound: allowed' }),
        makeRule({ chain: 'forward', srcZone: 'external', dstZone: 'internal', action: 'drop',   description: 'External → Internal: BLOCKED' }),
      ],
    },
  },
  {
    id: 'ssh-admin-only',
    label: 'SSH Admin Only',
    description: 'SSH restricted to management zone; external SSH attempts blocked.',
    policy: {
      defaultInput: 'drop',
      defaultForward: 'drop',
      defaultOutput: 'accept',
      rules: [
        makeRule({ chain: 'forward', srcZone: 'management', dstZone: 'any', protocol: 'tcp', dstPort: '22', action: 'accept', description: 'Management SSH: allowed' }),
        makeRule({ chain: 'forward', srcZone: 'external',   dstZone: 'any', protocol: 'tcp', dstPort: '22', action: 'drop',   description: 'External SSH: BLOCKED' }),
        makeRule({ chain: 'forward', srcZone: 'internal',   dstZone: 'any', action: 'accept', description: 'Internal outbound: allowed' }),
      ],
    },
  },
  {
    id: 'brute-force-throttle',
    label: 'Brute-Force Throttle',
    description: 'Rate-limit SSH (5 pps) and HTTP/S (20 pps) from external. Blocks brute-force while allowing legitimate traffic.',
    policy: {
      defaultInput: 'drop',
      defaultForward: 'drop',
      defaultOutput: 'accept',
      rules: [
        makeRule({ chain: 'forward', srcZone: 'external', dstZone: 'any', protocol: 'tcp', dstPort: '22',      action: 'accept', description: 'External SSH: throttled to 5 pps',        rateLimit: { pps: 5, burst: 10 } }),
        makeRule({ chain: 'forward', srcZone: 'external', dstZone: 'any', protocol: 'tcp', dstPort: '80,443',  action: 'accept', description: 'External HTTP/S: throttled to 20 pps',    rateLimit: { pps: 20, burst: 40 } }),
        makeRule({ chain: 'forward', srcZone: 'internal', dstZone: 'any', action: 'accept', description: 'Internal → anywhere: unlimited' }),
      ],
    },
  },
  {
    id: 'open',
    label: 'No Filtering',
    description: 'Default allow on all chains. Open network — educational "worst case".',
    policy: {
      defaultInput: 'accept',
      defaultForward: 'accept',
      defaultOutput: 'accept',
      rules: [],
    },
  },
]

// ── Small helpers ──────────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: FWAction }) {
  const a = ACTIONS.find(x => x.value === action)!
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${a.cls}`}>
      {a.label}
    </span>
  )
}

function chainColor(chain: FWChain) {
  if (chain === 'forward') return 'text-orange-400'
  if (chain === 'input')   return 'text-sky-400'
  return 'text-gray-400'
}

const selectCls = 'w-full px-2 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs focus:outline-none focus:ring-1 focus:ring-orange-500 cursor-pointer'
const inputCls  = 'w-full px-2 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-orange-500'

// ── Default policy row ─────────────────────────────────────────────────────────

function PolicyToggle({
  label, value, onChange,
}: { label: string; value: FWAction; onChange: (v: FWAction) => void }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-[11px] text-gray-400 min-w-[60px]">{label}</span>
      <div className="flex gap-1">
        {ACTIONS.map(a => (
          <button
            key={a.value}
            type="button"
            onClick={() => onChange(a.value)}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold border transition ${
              value === a.value ? a.cls : 'border-gray-700 text-gray-600 hover:text-gray-400'
            }`}
          >
            {a.label}
          </button>
        ))}
      </div>
    </div>
  )
}

// ── Add rule form ──────────────────────────────────────────────────────────────

const BLANK_RULE: Omit<FirewallRule, 'id'> = {
  enabled: true, chain: 'forward', srcZone: 'external', dstZone: 'any',
  protocol: 'any', dstPort: '', action: 'drop', description: '',
}

function AddRuleForm({ onAdd }: { onAdd: (r: FirewallRule) => void }) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState<Omit<FirewallRule, 'id'>>(BLANK_RULE)
  const [rlEnabled, setRlEnabled] = useState(false)
  const [rlPps,     setRlPps]     = useState(5)
  const [rlBurst,   setRlBurst]   = useState(10)

  function set<K extends keyof typeof form>(k: K, v: typeof form[K]) {
    setForm(f => ({ ...f, [k]: v }))
  }

  function handleAdd() {
    onAdd({
      id: `rule-${Date.now()}`,
      ...form,
      rateLimit: (rlEnabled && form.action === 'accept') ? { pps: rlPps, burst: rlBurst } : undefined,
    })
    setForm(BLANK_RULE)
    setRlEnabled(false)
    setRlPps(5)
    setRlBurst(10)
    setOpen(false)
  }

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
      >
        <span className="flex items-center gap-1.5 font-medium text-orange-400/80">
          <Plus size={12} />
          Add rule
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="p-3 border-t border-gray-800 space-y-2.5">
          {/* Chain */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Chain</label>
            <select className={selectCls} value={form.chain} onChange={e => set('chain', e.target.value as FWChain)}>
              {CHAINS.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
            <p className="text-[10px] text-gray-600 mt-1 leading-relaxed">{CHAIN_EXPLANATIONS[form.chain]}</p>
          </div>

          {/* Src → Dst zones */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Source zone</label>
              <select className={selectCls} value={form.srcZone} onChange={e => set('srcZone', e.target.value as FWZone)}>
                {ZONES.map(z => <option key={z.value} value={z.value}>{z.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Dest zone</label>
              <select className={selectCls} value={form.dstZone} onChange={e => set('dstZone', e.target.value as FWZone)}>
                {ZONES.map(z => <option key={z.value} value={z.value}>{z.label}</option>)}
              </select>
            </div>
          </div>

          {/* Protocol + port */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Protocol</label>
              <select className={selectCls} value={form.protocol} onChange={e => set('protocol', e.target.value as FWProtocol)}>
                {PROTOCOLS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Dst port</label>
              <input
                className={inputCls}
                value={form.dstPort}
                onChange={e => set('dstPort', e.target.value)}
                placeholder="80 or 80,443"
                disabled={form.protocol === 'icmp' || form.protocol === 'any'}
              />
            </div>
          </div>

          {/* Action */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Action</label>
            <div className="flex gap-1">
              {ACTIONS.map(a => (
                <button
                  key={a.value}
                  type="button"
                  onClick={() => set('action', a.value)}
                  className={`flex-1 py-1 rounded text-[10px] font-semibold border transition ${
                    form.action === a.value ? a.cls : 'border-gray-700 text-gray-600 hover:text-gray-400'
                  }`}
                >
                  {a.label}
                </button>
              ))}
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Description (optional)</label>
            <input
              className={inputCls}
              value={form.description}
              onChange={e => set('description', e.target.value)}
              placeholder="e.g. Allow public HTTP to DMZ web server"
            />
          </div>

          {/* Rate limiting — only for accept rules */}
          {form.action === 'accept' && (
            <div className="rounded-lg border border-gray-700/60 p-2.5 space-y-2">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="rl-enable"
                  checked={rlEnabled}
                  onChange={e => setRlEnabled(e.target.checked)}
                  className="accent-amber-500 cursor-pointer"
                />
                <label htmlFor="rl-enable" className="text-[11px] text-gray-300 cursor-pointer font-medium">
                  Enable rate limiting
                </label>
              </div>
              {rlEnabled && (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-gray-500 block mb-1">Max packets/sec</label>
                      <input
                        type="number" min={1} max={100000}
                        className={inputCls}
                        value={rlPps}
                        onChange={e => setRlPps(Math.max(1, parseInt(e.target.value) || 1))}
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-gray-500 block mb-1">Burst size (packets)</label>
                      <input
                        type="number" min={1} max={100000}
                        className={inputCls}
                        value={rlBurst}
                        onChange={e => setRlBurst(Math.max(1, parseInt(e.target.value) || 1))}
                      />
                    </div>
                  </div>
                  <p className="text-[10px] text-amber-700/80 leading-relaxed">
                    Bursts up to {rlBurst} packets are admitted; excess packets at &gt;{rlPps}/s are dropped. Effective against brute-force and flood attacks.
                  </p>
                </>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={handleAdd}
            className="w-full py-1.5 bg-orange-700 hover:bg-orange-600 text-white text-xs font-semibold rounded-lg transition"
          >
            Add rule
          </button>
        </div>
      )}
    </div>
  )
}

// ── Rule list row ──────────────────────────────────────────────────────────────

function RuleRow({ rule, onToggle, onRemove }: {
  rule: FirewallRule
  onToggle: () => void
  onRemove: () => void
}) {
  const [showDetail, setShowDetail] = useState(false)
  const portLabel = rule.dstPort ? `:${rule.dstPort}` : ''
  const protoLabel = rule.protocol === 'any' ? 'any' : `${rule.protocol}${portLabel}`

  return (
    <div className={`border-b border-gray-800/50 last:border-0 transition ${rule.enabled ? '' : 'opacity-40'}`}>
      <div className="flex items-center gap-1.5 px-2 py-1.5">
        <input
          type="checkbox"
          checked={rule.enabled}
          onChange={onToggle}
          className="accent-orange-500 flex-shrink-0 cursor-pointer"
        />
        <span className={`text-[10px] font-semibold uppercase w-12 flex-shrink-0 ${chainColor(rule.chain)}`}>
          {rule.chain}
        </span>
        <span className="text-[10px] text-gray-400 flex-1 min-w-0 truncate">
          {rule.srcZone} → {rule.dstZone}
          {protoLabel !== 'any' && <span className="text-gray-600"> ({protoLabel})</span>}
        </span>
        {rule.rateLimit && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-amber-700/50 bg-amber-900/30 text-amber-300 flex-shrink-0 font-semibold">
            {rule.rateLimit.pps}pps
          </span>
        )}
        <ActionBadge action={rule.action} />
        {rule.description && (
          <button onClick={() => setShowDetail(!showDetail)} className="text-gray-600 hover:text-gray-400 flex-shrink-0">
            <Info size={11} />
          </button>
        )}
        <button onClick={onRemove} className="text-gray-600 hover:text-red-400 transition flex-shrink-0">
          <Trash2 size={11} />
        </button>
      </div>
      {showDetail && rule.description && (
        <p className="px-3 pb-2 text-[10px] text-gray-500 leading-relaxed">{rule.description}</p>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

const DEFAULT_POLICY: FirewallPolicy = {
  defaultInput: 'drop',
  defaultForward: 'drop',
  defaultOutput: 'accept',
  rules: [],
}

interface Props {
  policy: FirewallPolicy | undefined
  onChange: (p: FirewallPolicy) => void
}

export default function FirewallPolicyPanel({ policy, onChange }: Props) {
  const p = policy ?? DEFAULT_POLICY
  const [presetsOpen, setPresetsOpen] = useState(false)

  function setPolicy(patch: Partial<FirewallPolicy>) {
    onChange({ ...p, ...patch })
  }

  function addRule(rule: FirewallRule) {
    setPolicy({ rules: [...p.rules, rule] })
  }

  function toggleRule(id: string) {
    setPolicy({ rules: p.rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r) })
  }

  function removeRule(id: string) {
    setPolicy({ rules: p.rules.filter(r => r.id !== id) })
  }

  function applyPreset(preset: Preset) {
    onChange({
      ...preset.policy,
      rules: preset.policy.rules.map(r => ({ ...r, id: `preset-${Date.now()}-${Math.random().toString(36).slice(2,6)}` })),
    })
    setPresetsOpen(false)
  }

  const ruleCount = p.rules.length
  const activeCount = p.rules.filter(r => r.enabled).length

  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className="flex items-center gap-2 pt-1">
        <div className="h-px flex-1 bg-gray-800" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-orange-400 flex items-center gap-1">
          <Shield size={10} />
          Firewall Policy
        </span>
        <div className="h-px flex-1 bg-gray-800" />
      </div>

      <p className="text-[10px] text-gray-500 leading-relaxed">
        Configure nftables-style filtering rules. Rules are evaluated top-to-bottom; first match wins. Use presets as a starting point.
      </p>

      {/* Default policies */}
      <div className="rounded-lg border border-gray-800 p-2.5 space-y-2">
        <p className="text-[10px] font-semibold text-gray-400 mb-1">Default policy (no rule matches)</p>
        <PolicyToggle label="Forward" value={p.defaultForward} onChange={v => setPolicy({ defaultForward: v })} />
        <PolicyToggle label="Input"   value={p.defaultInput}   onChange={v => setPolicy({ defaultInput: v })} />
        <PolicyToggle label="Output"  value={p.defaultOutput}  onChange={v => setPolicy({ defaultOutput: v })} />
      </div>

      {/* Presets */}
      <div className="rounded-lg border border-gray-800 overflow-hidden">
        <button
          type="button"
          onClick={() => setPresetsOpen(!presetsOpen)}
          className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
        >
          <span className="font-medium">Load a preset</span>
          {presetsOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        {presetsOpen && (
          <div className="border-t border-gray-800 divide-y divide-gray-800">
            {PRESETS.map(preset => (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyPreset(preset)}
                className="w-full text-left px-3 py-2 hover:bg-gray-800/40 transition"
              >
                <p className="text-[11px] text-orange-300 font-semibold">{preset.label}</p>
                <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{preset.description}</p>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Rule list */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <p className="text-[10px] font-semibold text-gray-400">
            Rules
            {ruleCount > 0 && (
              <span className="ml-1.5 text-orange-400">{activeCount}/{ruleCount} active</span>
            )}
          </p>
        </div>

        {ruleCount === 0 ? (
          <div className="rounded-lg border border-dashed border-gray-800 px-3 py-4 text-center">
            <p className="text-[10px] text-gray-600">No rules. Default policies apply to all traffic.</p>
          </div>
        ) : (
          <div className="rounded-lg border border-gray-800 overflow-hidden">
            {p.rules.map(rule => (
              <RuleRow
                key={rule.id}
                rule={rule}
                onToggle={() => toggleRule(rule.id)}
                onRemove={() => removeRule(rule.id)}
              />
            ))}
          </div>
        )}
      </div>

      <AddRuleForm onAdd={addRule} />
    </div>
  )
}
