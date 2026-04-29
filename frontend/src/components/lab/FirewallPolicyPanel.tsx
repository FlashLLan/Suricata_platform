import { useState } from 'react'
import { Shield, Plus, Trash2, ChevronDown, ChevronRight, Database, Key, Ban, ArrowRight, ArrowUp, ArrowDown, Pencil } from 'lucide-react'
import type {
  FirewallPolicy, FirewallRule, FirewallIPSet, PortKnockConfig, DynamicBanConfig, NatRule, NatType,
  FWChain, FWProtocol, FWAction, FWZone,
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

// Service quick-fill presets for AddRuleForm
const SERVICE_FILLS: { label: string; protocol: FWProtocol; dstPort: string; description: string }[] = [
  { label: 'HTTP/HTTPS',     protocol: 'tcp',  dstPort: '80,443',       description: 'Allow web traffic (HTTP/HTTPS)' },
  { label: 'SSH',            protocol: 'tcp',  dstPort: '22',           description: 'Allow SSH access' },
  { label: 'DNS',            protocol: 'udp',  dstPort: '53',           description: 'Allow DNS queries' },
  { label: 'SMTP',           protocol: 'tcp',  dstPort: '25,587',       description: 'Allow outbound mail (SMTP/Submission)' },
  { label: 'IMAP/POP3',      protocol: 'tcp',  dstPort: '143,993,110,995', description: 'Allow mail retrieval (IMAP/POP3)' },
  { label: 'MySQL/Postgres', protocol: 'tcp',  dstPort: '3306,5432',   description: 'Allow database access' },
  { label: 'RDP',            protocol: 'tcp',  dstPort: '3389',         description: 'Allow Remote Desktop (RDP)' },
  { label: 'NTP',            protocol: 'udp',  dstPort: '123',          description: 'Allow NTP time synchronisation' },
  { label: 'ICMP Ping',      protocol: 'icmp', dstPort: '',             description: 'Allow ICMP echo (ping)' },
  { label: 'OpenVPN',        protocol: 'udp',  dstPort: '1194',         description: 'Allow OpenVPN tunnel' },
  { label: 'WireGuard',      protocol: 'udp',  dstPort: '51820',        description: 'Allow WireGuard VPN' },
  { label: 'LDAP/LDAPS',     protocol: 'tcp',  dstPort: '389,636',      description: 'Allow LDAP directory access' },
]

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

// ── Validation helpers ─────────────────────────────────────────────────────────

function validatePortInput(value: string): string | null {
  if (!value.trim()) return null
  const parts = value.split(',')
  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) return 'Remove trailing commas'
    const rangeParts = trimmed.split(':')
    if (rangeParts.length > 2) return `Invalid range: "${trimmed}"`
    for (const p of rangeParts) {
      const n = parseInt(p.trim(), 10)
      if (isNaN(n) || n < 1 || n > 65535 || String(n) !== p.trim())
        return `"${p.trim()}" is not a valid port (1–65535)`
    }
  }
  return null
}

function validateIPInput(value: string): string | null {
  if (!value.trim()) return null
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/.exec(value.trim())
  if (!m) return 'Enter a valid IPv4 address (e.g. 10.0.0.5 or 192.168.1.0/24)'
  if ([m[1], m[2], m[3], m[4]].some(o => parseInt(o) > 255)) return 'Each octet must be 0–255'
  if (m[6] !== undefined && parseInt(m[6]) > 32) return 'CIDR prefix must be 0–32'
  return null
}

function validateCidrInput(value: string): string | null {
  if (!value.trim()) return null
  const parts = value.split(',')
  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) return 'Remove trailing commas'
    const err = validateIPInput(trimmed)
    if (err) return err
  }
  return null
}

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

function nftName(name: string) {
  return name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')
}

function Detail({ label, value, mono, wide }: { label: string; value: string; mono?: boolean; wide?: boolean }) {
  return (
    <div className={wide ? 'col-span-2' : ''}>
      <p className="text-[9px] uppercase tracking-wide text-gray-600 mb-0.5">{label}</p>
      <p className={`text-[11px] text-gray-300 ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  )
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

// ── IP Sets panel ──────────────────────────────────────────────────────────────

function IpSetsPanel({
  ipSets,
  onChange,
}: { ipSets: FirewallIPSet[]; onChange: (sets: FirewallIPSet[]) => void }) {
  const [open, setOpen] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newElements, setNewElements] = useState('')  // comma/newline separated
  const [addingElement, setAddingElement] = useState<string | null>(null) // set id
  const [elementInput, setElementInput] = useState('')

  function addSet() {
    const name = newName.trim()
    if (!name) return
    const elements = newElements
      .split(/[\n,]+/)
      .map(e => e.trim())
      .filter(Boolean)
    const set: FirewallIPSet = {
      id: `set-${Date.now()}`,
      name,
      elements,
      description: newDesc.trim() || undefined,
    }
    onChange([...ipSets, set])
    setNewName('')
    setNewDesc('')
    setNewElements('')
  }

  function removeSet(id: string) {
    onChange(ipSets.filter(s => s.id !== id))
  }

  function addElementToSet(id: string) {
    const el = elementInput.trim()
    if (!el) return
    onChange(ipSets.map(s => s.id === id ? { ...s, elements: [...s.elements, el] } : s))
    setElementInput('')
    setAddingElement(null)
  }

  function removeElement(setId: string, idx: number) {
    onChange(ipSets.map(s => s.id === setId ? { ...s, elements: s.elements.filter((_, i) => i !== idx) } : s))
  }

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
      >
        <span className="flex items-center gap-1.5 font-medium text-indigo-400/90">
          <Database size={11} />
          IP Sets / Blocklists
          {ipSets.length > 0 && (
            <span className="ml-1 text-[9px] bg-indigo-900/40 border border-indigo-700/40 text-indigo-300 px-1.5 py-0.5 rounded">
              {ipSets.length}
            </span>
          )}
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="border-t border-gray-800 p-3 space-y-3">
          <p className="text-[10px] text-gray-500 leading-relaxed">
            Named IP sets are referenced in rules as <code className="font-mono text-indigo-300">@NAME</code>.
            Use them for blocklists, trusted-host allowlists, or any group of addresses.
          </p>

          {/* Existing sets */}
          {ipSets.map(s => (
            <div key={s.id} className="rounded-lg border border-indigo-900/40 bg-indigo-950/10 overflow-hidden">
              <div className="flex items-center gap-2 px-2.5 py-1.5">
                <span className="text-[10px] font-mono font-bold text-indigo-300 flex-1">@{nftName(s.name)}</span>
                <span className="text-[10px] text-gray-500">{s.elements.length} element{s.elements.length !== 1 ? 's' : ''}</span>
                <button
                  type="button"
                  onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
                  className="text-gray-600 hover:text-gray-400"
                >
                  {expandedId === s.id ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                </button>
                <button type="button" onClick={() => removeSet(s.id)} className="text-gray-600 hover:text-red-400 transition">
                  <Trash2 size={11} />
                </button>
              </div>

              {expandedId === s.id && (
                <div className="px-2.5 pb-2.5 space-y-1.5 border-t border-indigo-900/30">
                  {s.description && (
                    <p className="text-[10px] text-gray-500 mt-1.5">{s.description}</p>
                  )}
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {s.elements.map((el, i) => (
                      <div key={i} className="flex items-center gap-1 bg-gray-800 rounded px-1.5 py-0.5">
                        <span className="text-[10px] font-mono text-gray-300">{el}</span>
                        <button type="button" onClick={() => removeElement(s.id, i)} className="text-gray-600 hover:text-red-400">
                          <Trash2 size={9} />
                        </button>
                      </div>
                    ))}
                  </div>
                  {addingElement === s.id ? (
                    <div className="flex gap-1 mt-1">
                      <input
                        className={`${inputCls} flex-1`}
                        value={elementInput}
                        onChange={e => setElementInput(e.target.value)}
                        placeholder="1.2.3.4 or 10.0.0.0/8"
                        onKeyDown={e => e.key === 'Enter' && addElementToSet(s.id)}
                      />
                      <button
                        type="button"
                        onClick={() => addElementToSet(s.id)}
                        className="px-2 py-1 bg-indigo-700 hover:bg-indigo-600 text-white text-[10px] rounded-lg"
                      >
                        Add
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => { setAddingElement(s.id); setElementInput('') }}
                      className="text-[10px] text-indigo-400/80 hover:text-indigo-300 flex items-center gap-1 mt-1"
                    >
                      <Plus size={10} /> Add element
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}

          {/* Add new set form */}
          <div className="rounded-lg border border-gray-700/60 p-2.5 space-y-2">
            <p className="text-[10px] font-semibold text-gray-400">New IP set</p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Set name</label>
                <input
                  className={inputCls}
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="BLOCKLIST"
                />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Description</label>
                <input
                  className={inputCls}
                  value={newDesc}
                  onChange={e => setNewDesc(e.target.value)}
                  placeholder="optional"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Elements (comma or newline separated)</label>
              <textarea
                className={`${inputCls} resize-none`}
                rows={2}
                value={newElements}
                onChange={e => setNewElements(e.target.value)}
                placeholder="1.2.3.4, 5.6.7.8, 10.0.0.0/8"
              />
            </div>
            <button
              type="button"
              onClick={addSet}
              disabled={!newName.trim()}
              className="w-full py-1.5 bg-indigo-700 hover:bg-indigo-600 disabled:opacity-40 text-white text-xs font-semibold rounded-lg transition"
            >
              Create set
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Port knocking panel ────────────────────────────────────────────────────────

function PortKnockingPanel({
  config,
  onChange,
}: { config: PortKnockConfig | undefined; onChange: (c: PortKnockConfig | undefined) => void }) {
  const [open, setOpen] = useState(false)
  const enabled = config !== undefined

  const defaults: PortKnockConfig = { knockPort: 7000, targetPort: 22, timeoutSec: 30 }
  const c = config ?? defaults

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
      >
        <span className="flex items-center gap-1.5 font-medium text-violet-400/90">
          <Key size={11} />
          Port Knocking
          {enabled && (
            <span className="ml-1 text-[9px] bg-violet-900/40 border border-violet-700/40 text-violet-300 px-1.5 py-0.5 rounded">
              ON
            </span>
          )}
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="border-t border-gray-800 p-3 space-y-2.5">
          <p className="text-[10px] text-gray-500 leading-relaxed">
            Port knocking keeps a port hidden until the client sends a packet to a secret "knock" port first.
            The firewall uses an nftables set with a timeout to track which source IPs have knocked.
            External attackers who don't know the knock sequence see the target port as closed.
          </p>

          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-gray-300 font-medium">Enable port knocking</span>
            <button
              type="button"
              onClick={() => onChange(enabled ? undefined : defaults)}
              className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors flex-shrink-0 ${
                enabled ? 'bg-violet-600' : 'bg-gray-700'
              }`}
            >
              <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                enabled ? 'translate-x-3.5' : 'translate-x-0.5'
              }`} />
            </button>
          </div>

          {enabled && (
            <>
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Knock port</label>
                  <input
                    type="number" min={1} max={65535}
                    className={inputCls}
                    value={c.knockPort}
                    onChange={e => onChange({ ...c, knockPort: parseInt(e.target.value) || 7000 })}
                  />
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Target port</label>
                  <input
                    type="number" min={1} max={65535}
                    className={inputCls}
                    value={c.targetPort}
                    onChange={e => onChange({ ...c, targetPort: parseInt(e.target.value) || 22 })}
                  />
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Timeout (s)</label>
                  <input
                    type="number" min={1} max={3600}
                    className={inputCls}
                    value={c.timeoutSec}
                    onChange={e => onChange({ ...c, timeoutSec: parseInt(e.target.value) || 30 })}
                  />
                </div>
              </div>
              <p className="text-[10px] text-violet-400/70 leading-relaxed">
                Knock on :{c.knockPort} → :{c.targetPort} unlocks for {c.timeoutSec}s.
                Generated nft: <code className="font-mono">tcp dport {c.knockPort} add @KNOCK_CLIENTS</code> then
                <code className="font-mono"> tcp dport {c.targetPort} ip saddr @KNOCK_CLIENTS accept</code>.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ── Dynamic ban panel ──────────────────────────────────────────────────────────

function DynamicBanPanel({
  config,
  onChange,
}: { config: DynamicBanConfig | undefined; onChange: (c: DynamicBanConfig | undefined) => void }) {
  const [open, setOpen] = useState(false)
  const [portError, setPortError] = useState<string | null>(null)
  const enabled = config !== undefined

  const defaults: DynamicBanConfig = {
    rateThreshold: 5, banDurationSec: 300, targetPort: '22', targetProtocol: 'tcp',
  }
  const c = config ?? defaults

  const portLabel  = c.targetPort ? `:${c.targetPort}` : '(all ports)'
  const protoLabel = c.targetProtocol === 'any' ? '' : `${c.targetProtocol.toUpperCase()} `
  const nftSnippet = `ip saddr @BAN_LIST drop\n${c.targetProtocol === 'any' ? '' : c.targetProtocol + ' '}${c.targetPort ? `dport { ${c.targetPort} } ` : ''}${c.targetProtocol === 'tcp' ? 'ct state new ' : ''}meter BAN_METER { ip saddr limit rate over ${c.rateThreshold}/minute burst ${c.rateThreshold} packets } add @BAN_LIST { ip saddr timeout ${c.banDurationSec}s } drop`

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
      >
        <span className="flex items-center gap-1.5 font-medium text-rose-400/90">
          <Ban size={11} />
          Dynamic Bans
          {enabled && (
            <span className="ml-1 text-[9px] bg-rose-900/40 border border-rose-700/40 text-rose-300 px-1.5 py-0.5 rounded">
              ON
            </span>
          )}
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="border-t border-gray-800 p-3 space-y-2.5">
          <p className="text-[10px] text-gray-500 leading-relaxed">
            Automatically temp-ban source IPs that exceed a connection rate threshold.
            Uses nftables <code className="font-mono text-rose-300/80">meter</code> to track
            connection rate per source IP and adds offenders to a timed <code className="font-mono text-rose-300/80">BAN_LIST</code> set.
            Effective against brute-force attacks and scanners.
          </p>

          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-gray-300 font-medium">Enable dynamic banning</span>
            <button
              type="button"
              onClick={() => onChange(enabled ? undefined : defaults)}
              className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors flex-shrink-0 ${
                enabled ? 'bg-rose-600' : 'bg-gray-700'
              }`}
            >
              <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                enabled ? 'translate-x-3.5' : 'translate-x-0.5'
              }`} />
            </button>
          </div>

          {enabled && (
            <>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Protocol</label>
                  <select
                    className={selectCls}
                    value={c.targetProtocol}
                    onChange={e => onChange({ ...c, targetProtocol: e.target.value as DynamicBanConfig['targetProtocol'] })}
                  >
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="any">Any</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Port(s) to watch</label>
                  <input
                    className={`${inputCls} ${portError ? 'border-red-600' : ''}`}
                    value={c.targetPort}
                    onChange={e => {
                      onChange({ ...c, targetPort: e.target.value })
                      setPortError(validatePortInput(e.target.value))
                    }}
                    placeholder="22  or  22,80  or leave blank"
                    disabled={c.targetProtocol === 'any'}
                  />
                  {portError && <p className="text-[10px] text-red-400 mt-1">{portError}</p>}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Threshold (conn/min)</label>
                  <input
                    type="number" min={1} max={10000}
                    className={inputCls}
                    value={c.rateThreshold}
                    onChange={e => onChange({ ...c, rateThreshold: parseInt(e.target.value) || 5 })}
                  />
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Ban duration (s)</label>
                  <input
                    type="number" min={10} max={86400}
                    className={inputCls}
                    value={c.banDurationSec}
                    onChange={e => onChange({ ...c, banDurationSec: parseInt(e.target.value) || 300 })}
                  />
                </div>
              </div>

              <div className="rounded-lg bg-gray-950 px-3 py-2 space-y-1">
                <p className="text-[9px] text-gray-600 uppercase tracking-wide font-semibold mb-1">nft output (forward chain)</p>
                {nftSnippet.split('\n').map((line, i) => (
                  <p key={i} className="text-[10px] font-mono text-rose-300/70 leading-relaxed">{line}</p>
                ))}
              </div>

              <p className="text-[10px] text-rose-400/60 leading-relaxed">
                Any {protoLabel}source exceeding {c.rateThreshold} new connections/min on {portLabel} is banned for {c.banDurationSec}s.
                Already-banned IPs are dropped before the rule list is evaluated.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ── NAT panel ─────────────────────────────────────────────────────────────────

function NatPanel({
  natRules,
  onChange,
}: { natRules: NatRule[]; onChange: (rules: NatRule[]) => void }) {
  const [open, setOpen] = useState(false)
  const [addingType, setAddingType] = useState<NatType>('dnat')
  const [dnatProto, setDnatProto] = useState<'tcp' | 'udp'>('tcp')
  const [dnatExtPort, setDnatExtPort] = useState('80')
  const [dnatToAddr, setDnatToAddr] = useState('')
  const [dnatToPort, setDnatToPort] = useState('')
  const [dnatDesc, setDnatDesc] = useState('')
  const [masqZone, setMasqZone] = useState<FWZone>('internal')
  const [masqDesc, setMasqDesc] = useState('')
  const [expandedNat, setExpandedNat] = useState<string | null>(null)
  const [extPortError, setExtPortError] = useState<string | null>(null)
  const [toAddrError,  setToAddrError]  = useState<string | null>(null)
  const [toPortError,  setToPortError]  = useState<string | null>(null)

  function addDnat() {
    if (!dnatExtPort.trim() || !dnatToAddr.trim() || extPortError || toAddrError || toPortError) return
    const r: NatRule = {
      id: `nat-${Date.now()}`,
      enabled: true,
      type: 'dnat',
      description: dnatDesc.trim() || `Forward :${dnatExtPort} → ${dnatToAddr}${dnatToPort ? ':' + dnatToPort : ''}`,
      protocol: dnatProto,
      extPort: dnatExtPort.trim(),
      toAddr: dnatToAddr.trim(),
      toPort: dnatToPort.trim(),
    }
    onChange([...natRules, r])
    setDnatExtPort('80')
    setDnatToAddr('')
    setDnatToPort('')
    setDnatDesc('')
    setExtPortError(null)
    setToAddrError(null)
    setToPortError(null)
  }

  function addMasquerade() {
    const r: NatRule = {
      id: `nat-${Date.now()}`,
      enabled: true,
      type: 'masquerade',
      description: masqDesc.trim() || `Masquerade ${masqZone} zone`,
      srcZone: masqZone,
    }
    onChange([...natRules, r])
    setMasqDesc('')
  }

  function removeRule(id: string) {
    onChange(natRules.filter(r => r.id !== id))
  }

  function toggleRule(id: string) {
    onChange(natRules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }

  const activeCount = natRules.filter(r => r.enabled).length

  const dnatNftPreview = dnatExtPort && dnatToAddr
    ? `${dnatProto} dport ${dnatExtPort.includes(',') ? '{ ' + dnatExtPort + ' }' : dnatExtPort} dnat to ${dnatToAddr}${dnatToPort ? ':' + dnatToPort : ''}`
    : null

  const masqNftPreview = masqZone && masqZone !== 'any' && masqZone !== 'external'
    ? `ip saddr @${masqZone.toUpperCase()} masquerade`
    : 'masquerade'

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
      >
        <span className="flex items-center gap-1.5 font-medium text-cyan-400/90">
          <ArrowRight size={11} />
          NAT Rules
          {activeCount > 0 && (
            <span className="ml-1 text-[9px] bg-cyan-900/40 border border-cyan-700/40 text-cyan-300 px-1.5 py-0.5 rounded">
              {activeCount}
            </span>
          )}
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="border-t border-gray-800 p-3 space-y-3">
          <p className="text-[10px] text-gray-500 leading-relaxed">
            <code className="font-mono text-cyan-300/80">dnat</code> (port forwarding) redirects inbound
            traffic on an external port to an internal host. <code className="font-mono text-cyan-300/80">masquerade</code> hides
            internal source IPs behind the firewall's external IP on outbound traffic. Both generate a
            separate <code className="font-mono text-cyan-300/80">table ip nat</code> block.
          </p>

          {/* Existing NAT rules */}
          {natRules.length > 0 && (
            <div className="rounded-lg border border-gray-800 overflow-hidden divide-y divide-gray-800/60">
              {natRules.map(r => (
                <div key={r.id} className={r.enabled ? '' : 'opacity-40'}>
                  {/* Summary row */}
                  <div
                    className="flex items-center gap-2 px-2 py-1.5 cursor-pointer hover:bg-gray-800/30 transition select-none"
                    onClick={() => setExpandedNat(expandedNat === r.id ? null : r.id)}
                  >
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      onChange={e => { e.stopPropagation(); toggleRule(r.id) }}
                      className="accent-cyan-500 cursor-pointer flex-shrink-0"
                    />
                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border flex-shrink-0 ${
                      r.type === 'dnat'
                        ? 'bg-cyan-900/50 text-cyan-300 border-cyan-700/40'
                        : 'bg-teal-900/50 text-teal-300 border-teal-700/40'
                    }`}>{r.type}</span>
                    <span className="text-[10px] text-gray-400 flex-1 min-w-0 truncate">{r.description}</span>
                    <span className="text-gray-600 flex-shrink-0">
                      {expandedNat === r.id ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                    </span>
                    <button
                      type="button"
                      onClick={e => { e.stopPropagation(); removeRule(r.id) }}
                      className="text-gray-600 hover:text-red-400 transition flex-shrink-0"
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>

                  {/* Expanded NAT detail */}
                  {expandedNat === r.id && (
                    <div className="px-3 pt-2 pb-3 bg-gray-900/50 border-t border-gray-800/40">
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                        <Detail label="Type" value={r.type === 'dnat' ? 'DNAT (port forward)' : 'Masquerade'} />
                        {r.type === 'dnat' ? (
                          <>
                            <Detail label="Protocol"     value={(r.protocol ?? 'tcp').toUpperCase()} />
                            <Detail label="External port" value={r.extPort ?? ''} mono />
                            <Detail label="Forward to"   value={`${r.toAddr ?? ''}${r.toPort ? ':' + r.toPort : ''}`} mono />
                          </>
                        ) : (
                          <Detail label="Zone" value={r.srcZone ?? 'any'} />
                        )}
                        {r.description && (
                          <Detail label="Description" value={r.description} wide />
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Add NAT rule form */}
          <div className="rounded-lg border border-gray-700/60 p-2.5 space-y-2">
            <p className="text-[10px] font-semibold text-gray-400">Add NAT rule</p>

            <div className="flex gap-1">
              {(['dnat', 'masquerade'] as NatType[]).map(t => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setAddingType(t)}
                  className={`flex-1 py-1 rounded text-[10px] font-semibold border transition ${
                    addingType === t
                      ? t === 'dnat'
                        ? 'bg-cyan-900/60 text-cyan-300 border-cyan-700/40'
                        : 'bg-teal-900/60 text-teal-300 border-teal-700/40'
                      : 'border-gray-700 text-gray-600 hover:text-gray-400'
                  }`}
                >
                  {t === 'dnat' ? 'DNAT (port forward)' : 'Masquerade'}
                </button>
              ))}
            </div>

            {addingType === 'dnat' ? (
              <>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Protocol</label>
                    <select
                      className={selectCls}
                      value={dnatProto}
                      onChange={e => setDnatProto(e.target.value as 'tcp' | 'udp')}
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">External port(s)</label>
                    <input
                      className={`${inputCls} ${extPortError ? 'border-red-600' : ''}`}
                      value={dnatExtPort}
                      onChange={e => { setDnatExtPort(e.target.value); setExtPortError(validatePortInput(e.target.value)) }}
                      placeholder="80 or 80,8080"
                    />
                    {extPortError && <p className="text-[10px] text-red-400 mt-1">{extPortError}</p>}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Forward to IP</label>
                    <input
                      className={`${inputCls} ${toAddrError ? 'border-red-600' : ''}`}
                      value={dnatToAddr}
                      onChange={e => { setDnatToAddr(e.target.value); setToAddrError(validateIPInput(e.target.value)) }}
                      placeholder="10.0.0.5"
                    />
                    {toAddrError && <p className="text-[10px] text-red-400 mt-1">{toAddrError}</p>}
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Forward to port</label>
                    <input
                      className={`${inputCls} ${toPortError ? 'border-red-600' : ''}`}
                      value={dnatToPort}
                      onChange={e => { setDnatToPort(e.target.value); setToPortError(validatePortInput(e.target.value)) }}
                      placeholder="8080 (blank = same)"
                    />
                    {toPortError && <p className="text-[10px] text-red-400 mt-1">{toPortError}</p>}
                  </div>
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Description</label>
                  <input
                    className={inputCls}
                    value={dnatDesc}
                    onChange={e => setDnatDesc(e.target.value)}
                    placeholder="e.g. Forward public HTTP to internal web server"
                  />
                </div>
                {dnatNftPreview && (
                  <div className="rounded-lg bg-gray-950 px-3 py-2">
                    <p className="text-[9px] text-gray-600 uppercase tracking-wide font-semibold mb-1">nft output (prerouting chain)</p>
                    <p className="text-[10px] font-mono text-cyan-300/70">{dnatNftPreview}</p>
                  </div>
                )}
                <button
                  type="button"
                  onClick={addDnat}
                  disabled={!dnatExtPort.trim() || !dnatToAddr.trim() || !!extPortError || !!toAddrError || !!toPortError}
                  className="w-full py-1.5 bg-cyan-800 hover:bg-cyan-700 disabled:opacity-40 text-white text-xs font-semibold rounded-lg transition"
                >
                  Add port forward
                </button>
              </>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Zone to masquerade</label>
                    <select
                      className={selectCls}
                      value={masqZone}
                      onChange={e => setMasqZone(e.target.value as FWZone)}
                    >
                      {ZONES.map(z => <option key={z.value} value={z.value}>{z.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Description</label>
                    <input
                      className={inputCls}
                      value={masqDesc}
                      onChange={e => setMasqDesc(e.target.value)}
                      placeholder="e.g. Hide internal IPs on exit"
                    />
                  </div>
                </div>
                <div className="rounded-lg bg-gray-950 px-3 py-2">
                  <p className="text-[9px] text-gray-600 uppercase tracking-wide font-semibold mb-1">nft output (postrouting chain)</p>
                  <p className="text-[10px] font-mono text-teal-300/70">{masqNftPreview}</p>
                </div>
                <p className="text-[10px] text-teal-400/60 leading-relaxed">
                  Outbound packets from the {masqZone} zone will have their source IP replaced with
                  the firewall's external IP before leaving. Return traffic is automatically un-NAT'd.
                </p>
                <button
                  type="button"
                  onClick={addMasquerade}
                  className="w-full py-1.5 bg-teal-800 hover:bg-teal-700 text-white text-xs font-semibold rounded-lg transition"
                >
                  Add masquerade rule
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Add rule form ──────────────────────────────────────────────────────────────

const BLANK_RULE: Omit<FirewallRule, 'id'> = {
  enabled: true, chain: 'forward', srcZone: 'external', dstZone: 'any',
  protocol: 'any', dstPort: '', action: 'drop', description: '',
}

function AddRuleForm({ onAdd, ipSets }: { onAdd: (r: FirewallRule) => void; ipSets: FirewallIPSet[] }) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState<Omit<FirewallRule, 'id'>>(BLANK_RULE)
  const [rlEnabled, setRlEnabled] = useState(false)
  const [rlPps,     setRlPps]     = useState(5)
  const [rlBurst,   setRlBurst]   = useState(10)
  const [srcSet,      setSrcSet]      = useState('')
  const [dstSet,      setDstSet]      = useState('')
  const [srcCidr,     setSrcCidr]     = useState('')
  const [portError,   setPortError]   = useState<string | null>(null)
  const [cidrError,   setCidrError]   = useState<string | null>(null)

  function set<K extends keyof typeof form>(k: K, v: typeof form[K]) {
    setForm(f => ({ ...f, [k]: v }))
  }

  function setPort(v: string) {
    set('dstPort', v)
    setPortError(validatePortInput(v))
  }

  function applyServiceFill(label: string) {
    const svc = SERVICE_FILLS.find(s => s.label === label)
    if (!svc) return
    setForm(f => ({
      ...f,
      protocol: svc.protocol,
      dstPort: svc.dstPort,
      description: svc.description,
    }))
  }

  function handleAdd() {
    if (portError || cidrError) return
    onAdd({
      id: `rule-${Date.now()}`,
      ...form,
      srcSet:  srcSet  || undefined,
      dstSet:  dstSet  || undefined,
      srcCidr: srcCidr.trim() || undefined,
      rateLimit: (rlEnabled && form.action === 'accept') ? { pps: rlPps, burst: rlBurst } : undefined,
    })
    setForm(BLANK_RULE)
    setPortError(null)
    setCidrError(null)
    setRlEnabled(false)
    setRlPps(5)
    setRlBurst(10)
    setSrcSet('')
    setDstSet('')
    setSrcCidr('')
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

          {/* Service quick-fill */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Quick service fill</label>
            <select
              className={selectCls}
              value=""
              onChange={e => applyServiceFill(e.target.value)}
            >
              <option value="">— select a service to pre-fill —</option>
              {SERVICE_FILLS.map(s => (
                <option key={s.label} value={s.label}>{s.label}</option>
              ))}
            </select>
          </div>

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

          {/* Source IP/CIDR */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">
              Source IP/CIDR <span className="text-gray-600">(overrides zone — leave blank to use zone)</span>
            </label>
            <input
              className={`${inputCls} ${cidrError ? 'border-red-600' : ''}`}
              value={srcCidr}
              onChange={e => { setSrcCidr(e.target.value); setCidrError(validateCidrInput(e.target.value)) }}
              placeholder="10.0.0.5  or  192.168.1.0/24  or  10.0.0.1, 10.0.0.2"
            />
            {cidrError && <p className="text-[10px] text-red-400 mt-1">{cidrError}</p>}
          </div>

          {/* IP set overrides (only when sets are defined) */}
          {ipSets.length > 0 && (
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">
                  Src IP set <span className="text-indigo-400/70">(overrides zone)</span>
                </label>
                <select className={selectCls} value={srcSet} onChange={e => setSrcSet(e.target.value)}>
                  <option value="">— none —</option>
                  {ipSets.map(s => (
                    <option key={s.id} value={s.name}>@{nftName(s.name)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">
                  Dst IP set <span className="text-indigo-400/70">(overrides zone)</span>
                </label>
                <select className={selectCls} value={dstSet} onChange={e => setDstSet(e.target.value)}>
                  <option value="">— none —</option>
                  {ipSets.map(s => (
                    <option key={s.id} value={s.name}>@{nftName(s.name)}</option>
                  ))}
                </select>
              </div>
            </div>
          )}

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
                className={`${inputCls} ${portError ? 'border-red-600' : ''}`}
                value={form.dstPort}
                onChange={e => setPort(e.target.value)}
                placeholder="80 or 80,443"
                disabled={form.protocol === 'icmp' || form.protocol === 'any'}
              />
              {portError && <p className="text-[10px] text-red-400 mt-1">{portError}</p>}
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
            disabled={!!portError || !!cidrError}
            className="w-full py-1.5 bg-orange-700 hover:bg-orange-600 disabled:opacity-40 text-white text-xs font-semibold rounded-lg transition"
          >
            Add rule
          </button>
        </div>
      )}
    </div>
  )
}

// ── Rule list row ──────────────────────────────────────────────────────────────

function RuleRow({ rule, ipSets, isFirst, isLast, onToggle, onRemove, onEdit, onMoveUp, onMoveDown }: {
  rule: FirewallRule
  ipSets: FirewallIPSet[]
  isFirst: boolean
  isLast: boolean
  onToggle: () => void
  onRemove: () => void
  onEdit: (updated: FirewallRule) => void
  onMoveUp: () => void
  onMoveDown: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [editing,  setEditing]  = useState(false)

  // Edit form state — reset from rule whenever edit starts
  const [eChain,     setEChain]     = useState<FWChain>(rule.chain)
  const [eSrcZone,   setESrcZone]   = useState<FWZone>(rule.srcZone)
  const [eDstZone,   setEDstZone]   = useState<FWZone>(rule.dstZone)
  const [eProtocol,  setEProtocol]  = useState<FWProtocol>(rule.protocol)
  const [eDstPort,   setEDstPort]   = useState(rule.dstPort)
  const [eAction,    setEAction]    = useState<FWAction>(rule.action)
  const [eDesc,      setEDesc]      = useState(rule.description)
  const [eRlEnabled, setERlEnabled] = useState(!!rule.rateLimit)
  const [eRlPps,     setERlPps]     = useState(rule.rateLimit?.pps ?? 5)
  const [eRlBurst,   setERlBurst]   = useState(rule.rateLimit?.burst ?? 10)
  const [eSrcSet,    setESrcSet]    = useState(rule.srcSet  ?? '')
  const [eDstSet,    setEDstSet]    = useState(rule.dstSet  ?? '')
  const [eSrcCidr,   setESrcCidr]  = useState(rule.srcCidr ?? '')
  const [ePortErr,   setEPortErr]   = useState<string | null>(null)
  const [eCidrErr,   setECidrErr]   = useState<string | null>(null)

  function startEdit() {
    setEChain(rule.chain); setESrcZone(rule.srcZone); setEDstZone(rule.dstZone)
    setEProtocol(rule.protocol); setEDstPort(rule.dstPort); setEAction(rule.action)
    setEDesc(rule.description); setERlEnabled(!!rule.rateLimit)
    setERlPps(rule.rateLimit?.pps ?? 5); setERlBurst(rule.rateLimit?.burst ?? 10)
    setESrcSet(rule.srcSet ?? ''); setEDstSet(rule.dstSet ?? '')
    setESrcCidr(rule.srcCidr ?? ''); setEPortErr(null); setECidrErr(null)
    setEditing(true); setExpanded(true)
  }

  function cancelEdit() { setEditing(false); setExpanded(false) }

  function saveEdit() {
    if (ePortErr || eCidrErr) return
    onEdit({
      ...rule,
      chain: eChain, srcZone: eSrcZone, dstZone: eDstZone,
      protocol: eProtocol, dstPort: eDstPort, action: eAction, description: eDesc,
      srcSet:  eSrcSet.trim()  || undefined,
      dstSet:  eDstSet.trim()  || undefined,
      srcCidr: eSrcCidr.trim() || undefined,
      rateLimit: (eRlEnabled && eAction === 'accept') ? { pps: eRlPps, burst: eRlBurst } : undefined,
    })
    setEditing(false); setExpanded(false)
  }

  const portLabel  = rule.dstPort ? `:${rule.dstPort}` : ''
  const protoLabel = rule.protocol === 'any' ? 'any' : `${rule.protocol}${portLabel}`
  const srcLabel   = rule.srcCidr?.trim()
    ? rule.srcCidr.trim()
    : rule.srcSet ? `@${nftName(rule.srcSet)}` : rule.srcZone
  const dstLabel   = rule.dstSet ? `@${nftName(rule.dstSet)}` : rule.dstZone

  return (
    <div className={`border-b border-gray-800/50 last:border-0 transition ${rule.enabled ? '' : 'opacity-40'}`}>
      {/* Summary row */}
      <div
        className={`flex items-center gap-1.5 px-2 py-1.5 select-none transition ${editing ? '' : 'cursor-pointer hover:bg-gray-800/30'}`}
        onClick={() => !editing && setExpanded(e => !e)}
      >
        <input
          type="checkbox"
          checked={rule.enabled}
          onChange={e => { e.stopPropagation(); onToggle() }}
          className="accent-orange-500 flex-shrink-0 cursor-pointer"
        />
        <span className={`text-[10px] font-semibold uppercase w-12 flex-shrink-0 ${chainColor(rule.chain)}`}>
          {rule.chain}
        </span>
        <span className="text-[10px] text-gray-400 flex-1 min-w-0 truncate">
          <span className={rule.srcSet ? 'text-indigo-400' : ''}>{srcLabel}</span>
          {' → '}
          <span className={rule.dstSet ? 'text-indigo-400' : ''}>{dstLabel}</span>
          {protoLabel !== 'any' && <span className="text-gray-600"> ({protoLabel})</span>}
        </span>
        {rule.rateLimit && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-amber-700/50 bg-amber-900/30 text-amber-300 flex-shrink-0 font-semibold">
            {rule.rateLimit.pps}pps
          </span>
        )}
        <ActionBadge action={rule.action} />
        {/* Move up / down */}
        <button
          type="button"
          onClick={e => { e.stopPropagation(); onMoveUp() }}
          disabled={isFirst}
          title="Move up"
          className="text-gray-600 hover:text-gray-300 disabled:opacity-20 disabled:cursor-not-allowed flex-shrink-0 transition"
        >
          <ArrowUp size={11} />
        </button>
        <button
          type="button"
          onClick={e => { e.stopPropagation(); onMoveDown() }}
          disabled={isLast}
          title="Move down"
          className="text-gray-600 hover:text-gray-300 disabled:opacity-20 disabled:cursor-not-allowed flex-shrink-0 transition"
        >
          <ArrowDown size={11} />
        </button>
        {/* Edit toggle */}
        <button
          type="button"
          onClick={e => { e.stopPropagation(); editing ? cancelEdit() : startEdit() }}
          title={editing ? 'Cancel edit' : 'Edit rule'}
          className={`flex-shrink-0 transition ${editing ? 'text-orange-400' : 'text-gray-600 hover:text-gray-300'}`}
        >
          <Pencil size={11} />
        </button>
        {!editing && (
          <span className="text-gray-600 flex-shrink-0">
            {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          </span>
        )}
        <button
          type="button"
          onClick={e => { e.stopPropagation(); onRemove() }}
          className="text-gray-600 hover:text-red-400 transition flex-shrink-0"
        >
          <Trash2 size={11} />
        </button>
      </div>

      {/* Read-only expanded detail */}
      {expanded && !editing && (
        <div className="px-3 pt-2 pb-3 bg-gray-900/50 border-t border-gray-800/40">
          <div className="grid grid-cols-2 gap-x-4 gap-y-2">
            <Detail label="Chain"  value={rule.chain.toUpperCase()} />
            <Detail label="Action" value={rule.action.charAt(0).toUpperCase() + rule.action.slice(1)} />
            <Detail
              label="Source"
              value={rule.srcCidr?.trim() ? rule.srcCidr.trim() : rule.srcSet ? `@${nftName(rule.srcSet)} (IP set)` : rule.srcZone}
              mono={!!rule.srcCidr?.trim()}
            />
            <Detail label="Destination" value={rule.dstSet ? `@${nftName(rule.dstSet)} (IP set)` : rule.dstZone} />
            <Detail label="Protocol" value={rule.protocol.toUpperCase()} />
            <Detail label="Dst port"  value={rule.dstPort || 'any'} mono />
            {rule.rateLimit && (
              <Detail label="Rate limit" value={`${rule.rateLimit.pps} pps, burst ${rule.rateLimit.burst} pkts`} wide />
            )}
            {rule.description && <Detail label="Description" value={rule.description} wide />}
          </div>
        </div>
      )}

      {/* Inline edit form */}
      {editing && (
        <div className="px-3 pt-2.5 pb-3 bg-gray-900/60 border-t border-orange-900/30 space-y-2">
          {/* Chain + Action */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Chain</label>
              <select className={selectCls} value={eChain} onChange={e => setEChain(e.target.value as FWChain)}>
                {CHAINS.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Action</label>
              <div className="flex gap-1">
                {ACTIONS.map(a => (
                  <button
                    key={a.value}
                    type="button"
                    onClick={() => setEAction(a.value)}
                    className={`flex-1 py-1 rounded text-[10px] font-semibold border transition ${
                      eAction === a.value ? a.cls : 'border-gray-700 text-gray-600 hover:text-gray-400'
                    }`}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Zones */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Source zone</label>
              <select className={selectCls} value={eSrcZone} onChange={e => setESrcZone(e.target.value as FWZone)}>
                {ZONES.map(z => <option key={z.value} value={z.value}>{z.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Dest zone</label>
              <select className={selectCls} value={eDstZone} onChange={e => setEDstZone(e.target.value as FWZone)}>
                {ZONES.map(z => <option key={z.value} value={z.value}>{z.label}</option>)}
              </select>
            </div>
          </div>

          {/* Source IP/CIDR */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">
              Source IP/CIDR <span className="text-gray-600">(overrides zone — leave blank to use zone)</span>
            </label>
            <input
              className={`${inputCls} ${eCidrErr ? 'border-red-600' : ''}`}
              value={eSrcCidr}
              onChange={e => { setESrcCidr(e.target.value); setECidrErr(validateCidrInput(e.target.value)) }}
              placeholder="10.0.0.5  or  192.168.1.0/24  or  10.0.0.1, 10.0.0.2"
            />
            {eCidrErr && <p className="text-[10px] text-red-400 mt-1">{eCidrErr}</p>}
          </div>

          {/* IP set overrides */}
          {ipSets.length > 0 && (
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">
                  Src IP set <span className="text-indigo-400/70">(overrides zone)</span>
                </label>
                <select className={selectCls} value={eSrcSet} onChange={e => setESrcSet(e.target.value)}>
                  <option value="">— none —</option>
                  {ipSets.map(s => <option key={s.id} value={s.name}>@{nftName(s.name)}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">
                  Dst IP set <span className="text-indigo-400/70">(overrides zone)</span>
                </label>
                <select className={selectCls} value={eDstSet} onChange={e => setEDstSet(e.target.value)}>
                  <option value="">— none —</option>
                  {ipSets.map(s => <option key={s.id} value={s.name}>@{nftName(s.name)}</option>)}
                </select>
              </div>
            </div>
          )}

          {/* Protocol + port */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Protocol</label>
              <select className={selectCls} value={eProtocol} onChange={e => setEProtocol(e.target.value as FWProtocol)}>
                {PROTOCOLS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Dst port</label>
              <input
                className={`${inputCls} ${ePortErr ? 'border-red-600' : ''}`}
                value={eDstPort}
                onChange={e => { setEDstPort(e.target.value); setEPortErr(validatePortInput(e.target.value)) }}
                placeholder="80 or 80,443"
                disabled={eProtocol === 'icmp' || eProtocol === 'any'}
              />
              {ePortErr && <p className="text-[10px] text-red-400 mt-1">{ePortErr}</p>}
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Description</label>
            <input className={inputCls} value={eDesc} onChange={e => setEDesc(e.target.value)} placeholder="optional" />
          </div>

          {/* Rate limit */}
          {eAction === 'accept' && (
            <div className="rounded-lg border border-gray-700/60 p-2 space-y-2">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={eRlEnabled}
                  onChange={e => setERlEnabled(e.target.checked)}
                  className="accent-amber-500 cursor-pointer"
                />
                <label className="text-[11px] text-gray-300 cursor-pointer">Enable rate limiting</label>
              </div>
              {eRlEnabled && (
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Max packets/sec</label>
                    <input
                      type="number" min={1} max={100000} className={inputCls}
                      value={eRlPps} onChange={e => setERlPps(Math.max(1, parseInt(e.target.value) || 1))}
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 block mb-1">Burst (packets)</label>
                    <input
                      type="number" min={1} max={100000} className={inputCls}
                      value={eRlBurst} onChange={e => setERlBurst(Math.max(1, parseInt(e.target.value) || 1))}
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Save / Cancel */}
          <div className="flex gap-2 pt-0.5">
            <button
              type="button"
              onClick={cancelEdit}
              className="flex-1 py-1.5 border border-gray-700 text-gray-400 hover:text-gray-200 text-xs rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={saveEdit}
              disabled={!!ePortErr || !!eCidrErr}
              className="flex-1 py-1.5 bg-orange-700 hover:bg-orange-600 disabled:opacity-40 text-white text-xs font-semibold rounded-lg transition"
            >
              Save changes
            </button>
          </div>
        </div>
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

  function editRule(id: string, updated: FirewallRule) {
    setPolicy({ rules: p.rules.map(r => r.id === id ? updated : r) })
  }

  function moveRule(idx: number, dir: 'up' | 'down') {
    const rules = [...p.rules]
    const swap = dir === 'up' ? idx - 1 : idx + 1
    ;[rules[idx], rules[swap]] = [rules[swap], rules[idx]]
    setPolicy({ rules })
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
  const ipSets = p.ipSets ?? []

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

        {/* Stateful connection tracking toggle */}
        <div className="pt-2 border-t border-gray-800/60 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-gray-300 font-medium">Stateful tracking (ct state)</span>
            <button
              type="button"
              onClick={() => setPolicy({ ctStateEnabled: !(p.ctStateEnabled ?? true) })}
              className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors flex-shrink-0 ${
                (p.ctStateEnabled ?? true) ? 'bg-green-600' : 'bg-gray-700'
              }`}
            >
              <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                (p.ctStateEnabled ?? true) ? 'translate-x-3.5' : 'translate-x-0.5'
              }`} />
            </button>
          </div>
          {(p.ctStateEnabled ?? true) ? (
            <p className="text-[10px] text-gray-600 leading-relaxed">
              <code className="font-mono">ct state established,related accept</code> is prepended to each chain.
              Return packets from allowed connections bypass the rule list automatically.
            </p>
          ) : (
            <p className="text-[10px] text-amber-600/90 leading-relaxed">
              Stateless mode: return packets from allowed connections are re-evaluated against the default policy and will
              be dropped if defaultForward is drop. TCP connections silently fail — use this to observe the effect.
            </p>
          )}
        </div>
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
            {p.rules.map((rule, idx) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                ipSets={ipSets}
                isFirst={idx === 0}
                isLast={idx === p.rules.length - 1}
                onToggle={() => toggleRule(rule.id)}
                onRemove={() => removeRule(rule.id)}
                onEdit={updated => editRule(rule.id, updated)}
                onMoveUp={() => moveRule(idx, 'up')}
                onMoveDown={() => moveRule(idx, 'down')}
              />
            ))}
          </div>
        )}
      </div>

      <AddRuleForm onAdd={addRule} ipSets={ipSets} />

      {/* IP Sets */}
      <IpSetsPanel
        ipSets={ipSets}
        onChange={sets => setPolicy({ ipSets: sets })}
      />

      {/* Port Knocking */}
      <PortKnockingPanel
        config={p.portKnocking}
        onChange={c => setPolicy({ portKnocking: c })}
      />

      {/* Dynamic Bans */}
      <DynamicBanPanel
        config={p.dynamicBan}
        onChange={c => setPolicy({ dynamicBan: c })}
      />

      {/* NAT Rules */}
      <NatPanel
        natRules={p.natRules ?? []}
        onChange={rules => setPolicy({ natRules: rules })}
      />
    </div>
  )
}
