import { useState, useEffect, useRef } from 'react'
import { X, ChevronDown, ChevronRight, Terminal, Plus, CheckCircle2, ShieldCheck, AlertTriangle, Trash2, Pencil } from 'lucide-react'
import type { Node } from '@xyflow/react'
import type { DeviceData, NetworkZone, DeviceType, IPClass, RuleCategory, CustomRuleEntry } from '../../types/lab'
import {
  ATTACK_COMMANDS, ATTACK_CATEGORY_LABELS, ATTACK_CATEGORY_COLORS,
  type AttackCategory,
} from '../../data/attacks'
import { PREDEFINED_RULES, CATEGORY_LABELS, CATEGORY_COLORS } from '../../data/rules'
import AddCustomRuleModal, { getCustomCategoryClasses } from './AddCustomRuleModal'
import DefensePanel from './DefensePanel'
import FirewallPolicyPanel from './FirewallPolicyPanel'

// ─── IP helpers ───────────────────────────────────────────────────────────────

function validateIPv4(ip: string): string | null {
  if (!ip) return null                         // empty = not set yet, no error
  const parts = ip.split('.')
  if (parts.length !== 4)
    return 'Must have exactly 4 octets separated by dots (e.g. 192.168.1.10)'
  for (const part of parts) {
    if (!/^\d+$/.test(part))
      return `"${part}" is not a valid number`
    const n = parseInt(part, 10)
    if (n < 0 || n > 255)
      return `Octet "${part}" must be 0 – 255`
    if (part.length > 1 && part.startsWith('0'))
      return `Leading zeros are not allowed (use "${n}" not "${part}")`
  }
  return null
}

function detectIPClass(ip: string): IPClass | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  const first = parseInt(parts[0], 10)
  if (isNaN(first)) return null
  if (first >= 1   && first <= 126) return 'A'
  if (first >= 128 && first <= 191) return 'B'
  if (first >= 192 && first <= 223) return 'C'
  if (first >= 224 && first <= 239) return 'D'
  return null
}

const CLASS_INFO: Record<IPClass, { range: string; defaultSubnet: string; note: string }> = {
  A: { range: '1.0.0.0 – 126.255.255.255', defaultSubnet: '255.0.0.0 (/8)',    note: 'Large networks — up to 16 million hosts per network' },
  B: { range: '128.0.0.0 – 191.255.255.255', defaultSubnet: '255.255.0.0 (/16)', note: 'Medium networks — up to 65,534 hosts per network' },
  C: { range: '192.0.0.0 – 223.255.255.255', defaultSubnet: '255.255.255.0 (/24)', note: 'Small networks — up to 254 hosts per network (most common in labs)' },
  D: { range: '224.0.0.0 – 239.255.255.255', defaultSubnet: 'N/A (multicast)', note: 'Multicast — no unicast subnet, used for group streaming' },
}

const CLASS_SUBNET_DEFAULT: Record<IPClass, string> = {
  A: '10.0.0.0/8',
  B: '172.16.0.0/16',
  C: '192.168.1.0/24',
  D: '224.0.0.0/4',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-400 mb-1">{label}</label>
      {hint && <p className="text-[10px] text-gray-600 mb-1">{hint}</p>}
      {children}
    </div>
  )
}

const inputCls = 'w-full px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500 transition'
const inputErrCls = 'w-full px-2.5 py-1.5 bg-gray-800 border border-red-600 rounded-lg text-white text-xs placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-red-500 transition'
const selectCls = `${inputCls} cursor-pointer`

// ── IP Class Selector ─────────────────────────────────────────────────────────

function IPClassSelector({ value, onChange }: { value: IPClass; onChange: (c: IPClass) => void }) {
  const classes: IPClass[] = ['A', 'B', 'C', 'D']
  return (
    <div className="flex gap-1">
      {classes.map((c) => (
        <button
          key={c}
          type="button"
          onClick={() => onChange(c)}
          className={`flex-1 py-1 text-xs font-bold rounded-lg border transition ${
            value === c
              ? 'bg-indigo-700 border-indigo-500 text-white'
              : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500 hover:text-gray-200'
          }`}
        >
          {c}
        </button>
      ))}
    </div>
  )
}

// ── Attacker Panel ────────────────────────────────────────────────────────────

function AttackerPanel({
  selected,
  customCommands,
  onToggle,
  onCustomChange,
}: {
  selected: string[]
  customCommands: string
  onToggle: (id: string) => void
  onCustomChange: (v: string) => void
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [customOpen, setCustomOpen] = useState(false)

  const byCategory = ATTACK_COMMANDS.reduce<Record<string, typeof ATTACK_COMMANDS>>((acc, cmd) => {
    if (!acc[cmd.category]) acc[cmd.category] = []
    acc[cmd.category].push(cmd)
    return acc
  }, {})

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 pt-1">
        <div className="h-px flex-1 bg-gray-800" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-red-500 flex items-center gap-1">
          <Terminal size={10} />
          Attack Config
        </span>
        <div className="h-px flex-1 bg-gray-800" />
      </div>

      <p className="text-[10px] text-gray-500 leading-relaxed">
        Select attacks this machine will simulate. Selected attacks are shown in the simulation and linked to matching Suricata rules.
      </p>

      {/* Attack list by category */}
      <div className="space-y-2">
        {(Object.entries(byCategory) as [AttackCategory, typeof ATTACK_COMMANDS][]).map(([cat, cmds]) => (
          <div key={cat} className="rounded-lg border border-gray-800 overflow-hidden">
            <div className={`px-2 py-1 text-[10px] font-semibold border-b border-gray-800 ${ATTACK_CATEGORY_COLORS[cat]}`}>
              {ATTACK_CATEGORY_LABELS[cat]}
            </div>
            {cmds.map((cmd) => {
              const isSelected = selected.includes(cmd.id)
              const isExpanded = expandedId === cmd.id
              return (
                <div key={cmd.id} className={`border-b border-gray-800/50 last:border-0 ${isSelected ? 'bg-red-950/20' : ''}`}>
                  <div className="flex items-center gap-2 px-2 py-1.5">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => onToggle(cmd.id)}
                      className="accent-red-500 flex-shrink-0 cursor-pointer"
                    />
                    <span
                      className="flex-1 text-xs text-gray-300 cursor-pointer hover:text-white"
                      onClick={() => setExpandedId(isExpanded ? null : cmd.id)}
                    >
                      {cmd.name}
                    </span>
                    <span className="text-[10px] text-gray-600 font-mono">{cmd.tool}</span>
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : cmd.id)}
                      className="text-gray-600 hover:text-gray-400"
                    >
                      {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="px-3 pb-3 space-y-2">
                      <pre className="text-[10px] text-green-400 font-mono bg-gray-900/80 rounded-lg p-2 whitespace-pre-wrap break-all leading-relaxed border border-gray-800">
                        {cmd.cmd}
                      </pre>
                      <p className="text-[10px] text-gray-400 leading-relaxed">{cmd.description}</p>
                      {cmd.linkedScenario && (
                        <p className="text-[10px] text-indigo-400">
                          Linked simulation: <span className="font-medium">{cmd.linkedScenario}</span>
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>

      {/* Custom commands */}
      <div className="rounded-lg border border-gray-800 overflow-hidden">
        <button
          type="button"
          onClick={() => setCustomOpen(!customOpen)}
          className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
        >
          <span className="flex items-center gap-1.5 font-medium">
            <Plus size={12} />
            Custom attack commands
          </span>
          {customOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        {customOpen && (
          <div className="p-2 border-t border-gray-800">
            <textarea
              className="w-full px-2.5 py-2 bg-gray-900 border border-gray-700 rounded-lg text-green-400 text-[11px] font-mono placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-red-500 resize-none"
              rows={5}
              value={customCommands}
              onChange={(e) => onCustomChange(e.target.value)}
              placeholder={"# Write your own attack commands\nnmap -sS -p 80,443 192.168.1.0/24\nhydra -l root -P passwords.txt ssh://192.168.1.10"}
            />
          </div>
        )}
      </div>
    </div>
  )
}

// ── IDS Rules Panel ────────────────────────────────────────────────────────────

function IDSRulesPanel({
  selected,
  customRules,
  onToggle,
  onAddCustom,
  onUpdateCustom,
  onRemoveCustom,
}: {
  selected: string[]
  customRules: CustomRuleEntry[]
  onToggle: (id: string) => void
  onAddCustom: (rule: CustomRuleEntry) => void
  onUpdateCustom: (rule: CustomRuleEntry) => void
  onRemoveCustom: (id: string) => void
}) {
  const [search, setSearch] = useState('')
  const [showAddModal, setShowAddModal] = useState(false)
  const [editingRule, setEditingRule] = useState<CustomRuleEntry | null>(null)

  const byCategory = PREDEFINED_RULES.reduce<Record<string, typeof PREDEFINED_RULES>>((acc, r) => {
    if (!acc[r.category]) acc[r.category] = []
    acc[r.category].push(r)
    return acc
  }, {})

  const filtered = PREDEFINED_RULES.filter(r => {
    if (!search) return true
    const q = search.toLowerCase()
    return r.msg.toLowerCase().includes(q) || r.category.includes(q)
  })
  const filteredIds = new Set(filtered.map(r => r.id))

  const totalLoaded = selected.length + customRules.length
  const invalidCount = customRules.filter(r => !r.isValid).length

  // Group custom rules by category for display
  const customByCategory = customRules.reduce<Record<string, CustomRuleEntry[]>>((acc, r) => {
    if (!acc[r.category]) acc[r.category] = []
    acc[r.category].push(r)
    return acc
  }, {})

  return (
    <>
      <div className="space-y-3">
        <div className="flex items-center gap-2 pt-1">
          <div className="h-px flex-1 bg-gray-800" />
          <span className="text-[10px] font-semibold uppercase tracking-widest text-indigo-400 flex items-center gap-1">
            <ShieldCheck size={10} />
            Loaded Rules
          </span>
          <div className="h-px flex-1 bg-gray-800" />
        </div>

        <p className="text-[10px] text-gray-500 leading-relaxed">
          Select predefined rules or add your own. Selected rules appear in the Export.
        </p>

        {totalLoaded > 0 && (
          <div className="flex items-center gap-2">
            <p className="text-[10px] text-indigo-400 font-medium">
              {totalLoaded} rule{totalLoaded !== 1 ? 's' : ''} loaded
            </p>
            {invalidCount > 0 && (
              <span className="flex items-center gap-0.5 text-[10px] text-amber-400">
                <AlertTriangle size={10} />
                {invalidCount} with syntax errors
              </span>
            )}
          </div>
        )}

        <div className="pb-0.5">
          <input
            className="w-full px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="Search rules…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Predefined rules */}
        <div className="space-y-2">
          {(Object.entries(byCategory) as [RuleCategory, typeof PREDEFINED_RULES][]).map(([cat, rules]) => {
            const visibleRules = rules.filter(r => filteredIds.has(r.id))
            if (visibleRules.length === 0) return null
            return (
              <div key={cat} className="rounded-lg border border-gray-800 overflow-hidden">
                <div className={`px-2 py-1 text-[10px] font-semibold border-b border-gray-800 ${CATEGORY_COLORS[cat]}`}>
                  {CATEGORY_LABELS[cat]}
                </div>
                {visibleRules.map(rule => {
                  const isOn = selected.includes(rule.id)
                  return (
                    <label
                      key={rule.id}
                      className={`flex items-start gap-2 px-2 py-1.5 cursor-pointer border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30 transition ${isOn ? 'bg-indigo-950/20' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={isOn}
                        onChange={() => onToggle(rule.id)}
                        className="accent-indigo-500 mt-0.5 flex-shrink-0 cursor-pointer"
                      />
                      <div className="min-w-0">
                        <p className="text-[11px] text-gray-300 leading-snug">{rule.msg}</p>
                        <p className="text-[10px] text-gray-600 font-mono mt-0.5">sid:{rule.sid}</p>
                      </div>
                    </label>
                  )
                })}
              </div>
            )
          })}
        </div>

        {/* Custom rules */}
        {customRules.length > 0 && (
          <div className="space-y-2">
            {Object.entries(customByCategory).map(([cat, rules]) => {
              // Find color class: built-in category color, or custom color from first rule
              const colorClass = CATEGORY_COLORS[cat]
                ?? getCustomCategoryClasses(rules[0]?.categoryColor || 'indigo')
              const catLabel = CATEGORY_LABELS[cat] ?? cat
              return (
                <div key={cat} className="rounded-lg border border-gray-800 overflow-hidden">
                  <div className={`px-2 py-1 text-[10px] font-semibold border-b border-gray-800 ${colorClass}`}>
                    {catLabel}
                    <span className="ml-1 opacity-60 font-normal">(custom)</span>
                  </div>
                  {rules.map(rule => (
                    <div
                      key={rule.id}
                      className="flex items-start gap-2 px-2 py-1.5 border-b border-gray-800/50 last:border-0 bg-indigo-950/10"
                    >
                      <div className="mt-0.5 flex-shrink-0">
                        {rule.isValid
                          ? <ShieldCheck size={11} className="text-indigo-400" />
                          : <AlertTriangle size={11} className="text-amber-400" />}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-[11px] text-gray-300 leading-snug">{rule.msg}</p>
                        <p className="text-[10px] text-gray-600 font-mono mt-0.5">sid:{rule.sid}</p>
                        {!rule.isValid && (
                          <p className="text-[10px] text-amber-500 mt-0.5">syntax error — will be flagged in simulation</p>
                        )}
                      </div>
                      <button
                        onClick={() => { setEditingRule(rule); setShowAddModal(true) }}
                        className="text-gray-600 hover:text-indigo-400 transition flex-shrink-0 p-0.5"
                        title="Edit rule"
                      >
                        <Pencil size={11} />
                      </button>
                      <button
                        onClick={() => onRemoveCustom(rule.id)}
                        className="text-gray-600 hover:text-red-400 transition flex-shrink-0 p-0.5"
                        title="Remove rule"
                      >
                        <Trash2 size={11} />
                      </button>
                    </div>
                  ))}
                </div>
              )
            })}
          </div>
        )}

        {/* Add Rule button */}
        <button
          onClick={() => setShowAddModal(true)}
          className="w-full flex items-center justify-center gap-1.5 py-2 rounded-lg border border-dashed border-gray-700 text-[11px] text-gray-500 hover:text-indigo-400 hover:border-indigo-700 transition"
        >
          <Plus size={12} />
          Add custom rule
        </button>
      </div>

      {showAddModal && (
        <AddCustomRuleModal
          existingCustomRules={customRules}
          initialRule={editingRule ?? undefined}
          onSave={rule => {
            if (editingRule) {
              onUpdateCustom(rule)
            } else {
              onAddCustom(rule)
            }
            setShowAddModal(false)
            setEditingRule(null)
          }}
          onClose={() => { setShowAddModal(false); setEditingRule(null) }}
        />
      )}
    </>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

interface Props {
  node: Node | null
  onClose: () => void
  onUpdate: (nodeId: string, data: DeviceData) => void
}

const DEVICE_TYPES: { value: DeviceType; label: string }[] = [
  { value: 'workstation',  label: 'Workstation' },
  { value: 'server',       label: 'Server' },
  { value: 'web-server',   label: 'Web Server' },
  { value: 'database',     label: 'Database' },
  { value: 'router',       label: 'Router' },
  { value: 'firewall',     label: 'Firewall' },
  { value: 'attacker',     label: 'Attacker' },
  { value: 'dns-server',   label: 'DNS Server' },
  { value: 'mail-server',  label: 'Mail Server' },
  { value: 'ids',          label: 'Suricata IDS' },
]

const ZONES: { value: NetworkZone; label: string }[] = [
  { value: 'internal',   label: 'Internal' },
  { value: 'dmz',        label: 'DMZ' },
  { value: 'external',   label: 'External' },
  { value: 'management', label: 'Management' },
]

const EMPTY: DeviceData = {
  label: '', deviceType: 'workstation', ip: '', ipClass: 'C',
  subnet: '', ports: '', os: '', zone: 'internal', notes: '',
  selectedAttacks: [], customAttackCommands: '',
  noDefense: false, enabledDefenses: [], customDefenseConfig: '',
  selectedRuleIds: [],
  customRules: [],
  firewallPolicy: undefined,
}

export default function DeviceConfigPanel({ node, onClose, onUpdate }: Props) {
  const raw = node?.data as unknown as DeviceData | undefined
  const [form, setForm] = useState<DeviceData>(EMPTY)
  const [ipError, setIpError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const savedTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (raw) {
      setForm({
        ...EMPTY,
        ...raw,
        selectedAttacks: raw.selectedAttacks ?? [],
        customAttackCommands: raw.customAttackCommands ?? '',
        noDefense: raw.noDefense ?? false,
        enabledDefenses: raw.enabledDefenses ?? [],
        customDefenseConfig: raw.customDefenseConfig ?? '',
        selectedRuleIds: raw.selectedRuleIds ?? [],
        customRules: raw.customRules ?? [],
        firewallPolicy: raw.firewallPolicy,
      })
      setIpError(null)
    }
  }, [node?.id])

  if (!node) return null

  function set<K extends keyof DeviceData>(key: K, value: DeviceData[K]) {
    setForm(f => ({ ...f, [key]: value }))
  }

  function handleIPChange(val: string) {
    set('ip', val)
    setIpError(validateIPv4(val))
    // Auto-detect class
    const detected = detectIPClass(val)
    if (detected) set('ipClass', detected)
  }

  function handleClassChange(cls: IPClass) {
    set('ipClass', cls)
    // Auto-fill subnet with a sensible default if empty
    if (!form.subnet) set('subnet', CLASS_SUBNET_DEFAULT[cls])
  }

  function toggleAttack(id: string) {
    const current = form.selectedAttacks
    set('selectedAttacks', current.includes(id) ? current.filter(a => a !== id) : [...current, id])
  }

  function toggleDefense(id: string) {
    const current = form.enabledDefenses
    set('enabledDefenses', current.includes(id) ? current.filter(d => d !== id) : [...current, id])
  }

  function toggleRule(id: string) {
    const current = form.selectedRuleIds
    set('selectedRuleIds', current.includes(id) ? current.filter(r => r !== id) : [...current, id])
  }

  function addCustomRule(rule: CustomRuleEntry) {
    set('customRules', [...form.customRules, rule])
  }

  function updateCustomRule(rule: CustomRuleEntry) {
    set('customRules', form.customRules.map(r => r.id === rule.id ? rule : r))
  }

  function removeCustomRule(id: string) {
    set('customRules', form.customRules.filter(r => r.id !== id))
  }

  function handleSave() {
    if (ipError) return
    onUpdate(node!.id, form)
    setSaved(true)
    if (savedTimer.current) clearTimeout(savedTimer.current)
    savedTimer.current = setTimeout(() => setSaved(false), 2000)
  }

  const info = CLASS_INFO[form.ipClass]

  return (
    <div className="w-72 flex-shrink-0 bg-gray-900 border-l border-gray-800 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 flex-shrink-0">
        <span className="text-sm font-semibold text-white">Device Config</span>
        <button onClick={onClose} className="text-gray-500 hover:text-white transition">
          <X size={16} />
        </button>
      </div>

      {/* Form */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Name */}
        <Field label="Name">
          <input
            className={inputCls}
            value={form.label}
            onChange={e => set('label', e.target.value)}
            placeholder="e.g. Employee Laptop"
          />
        </Field>

        {/* Device type */}
        <Field label="Device Type">
          <select
            className={selectCls}
            value={form.deviceType}
            onChange={e => set('deviceType', e.target.value as DeviceType)}
          >
            {DEVICE_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </Field>

        {/* IP class selector */}
        <Field label="IP Address Class">
          <IPClassSelector value={form.ipClass} onChange={handleClassChange} />
          <div className="mt-1.5 px-2 py-1.5 bg-gray-800/50 rounded-lg border border-gray-700/40">
            <p className="text-[10px] text-gray-400 font-mono">{info.range}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">Default mask: {info.defaultSubnet}</p>
            <p className="text-[10px] text-gray-600 mt-0.5">{info.note}</p>
          </div>
        </Field>

        {/* IP address */}
        <Field label="IP Address" hint="Must be a valid IPv4 address">
          <input
            className={ipError ? inputErrCls : inputCls}
            value={form.ip}
            onChange={e => handleIPChange(e.target.value)}
            placeholder="192.168.1.10"
          />
          {ipError && (
            <p className="text-[10px] text-red-400 mt-1 leading-relaxed">{ipError}</p>
          )}
          {!ipError && form.ip && detectIPClass(form.ip) && (
            <p className="text-[10px] text-green-500 mt-1">
              Valid Class {detectIPClass(form.ip)} address
            </p>
          )}
        </Field>

        {/* Subnet */}
        <Field label="Subnet / CIDR">
          <input
            className={inputCls}
            value={form.subnet}
            onChange={e => set('subnet', e.target.value)}
            placeholder="192.168.1.0/24"
          />
        </Field>

        {/* Ports */}
        <Field label="Open Ports / Services" hint="Comma-separated">
          <input
            className={inputCls}
            value={form.ports}
            onChange={e => set('ports', e.target.value)}
            placeholder="22, 80, 443"
          />
        </Field>

        {/* OS */}
        <Field label="OS / Profile">
          <input
            className={inputCls}
            value={form.os}
            onChange={e => set('os', e.target.value)}
            placeholder="Ubuntu 22.04, Windows 11…"
          />
        </Field>

        {/* Zone */}
        <Field label="Network Zone">
          <select
            className={selectCls}
            value={form.zone}
            onChange={e => set('zone', e.target.value as NetworkZone)}
          >
            {ZONES.map(z => (
              <option key={z.value} value={z.value}>{z.label}</option>
            ))}
          </select>
          <p className="text-[10px] text-gray-600 mt-1">
            Determines ring colour and how $HOME_NET / $EXTERNAL_NET resolve in the simulation.
          </p>
        </Field>

        {/* Notes */}
        <Field label="Notes">
          <textarea
            className={`${inputCls} resize-none`}
            rows={2}
            value={form.notes}
            onChange={e => set('notes', e.target.value)}
            placeholder="Purpose, role, anything relevant…"
          />
        </Field>

        {/* Attacker panel */}
        {form.deviceType === 'attacker' && (
          <AttackerPanel
            selected={form.selectedAttacks}
            customCommands={form.customAttackCommands}
            onToggle={toggleAttack}
            onCustomChange={v => set('customAttackCommands', v)}
          />
        )}

        {/* IDS rules panel — shown only for Suricata IDS nodes */}
        {form.deviceType === 'ids' && (
          <IDSRulesPanel
            selected={form.selectedRuleIds}
            customRules={form.customRules}
            onToggle={toggleRule}
            onAddCustom={addCustomRule}
            onUpdateCustom={updateCustomRule}
            onRemoveCustom={removeCustomRule}
          />
        )}

        {/* Firewall policy panel — only for firewall nodes */}
        {form.deviceType === 'firewall' && (
          <FirewallPolicyPanel
            policy={form.firewallPolicy}
            onChange={p => set('firewallPolicy', p)}
          />
        )}

        {/* Defense panel — non-attacker, non-IDS, non-firewall devices */}
        {form.deviceType !== 'attacker' && form.deviceType !== 'ids' && form.deviceType !== 'firewall' && (
          <DefensePanel
            noDefense={form.noDefense}
            enabled={form.enabledDefenses}
            customConfig={form.customDefenseConfig}
            onNoDefenseToggle={v => set('noDefense', v)}
            onToggle={toggleDefense}
            onCustomChange={v => set('customDefenseConfig', v)}
          />
        )}
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-gray-800 flex-shrink-0 space-y-2">
        {ipError && (
          <p className="text-[10px] text-red-400">Fix the IP address error before saving.</p>
        )}
        <button
          onClick={handleSave}
          disabled={!!ipError}
          className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition"
        >
          Apply changes
        </button>
        {/* Save confirmation */}
        <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-all duration-300 ${
          saved
            ? 'opacity-100 border-green-700/40 bg-green-950/30'
            : 'opacity-0 border-transparent bg-transparent pointer-events-none'
        }`}>
          <CheckCircle2 size={13} className="text-green-400 flex-shrink-0" />
          <p className="text-xs text-green-300 font-medium">Changes applied to canvas</p>
        </div>
      </div>
    </div>
  )
}
