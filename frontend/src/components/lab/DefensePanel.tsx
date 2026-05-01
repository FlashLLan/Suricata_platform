import { useState } from 'react'
import { Shield, ShieldOff, ChevronDown, ChevronRight, Plus } from 'lucide-react'
import {
  DEFENSE_OPTIONS, DEFENSE_CATEGORY_LABELS, DEFENSE_CATEGORY_COLORS,
  type DefenseCategory,
} from '../../data/defenses'

function validateIPCIDRField(value: string): string | null {
  const lines = value.split('\n').map(l => l.trim()).filter(Boolean)
  for (const line of lines) {
    const parts = line.split('/')
    if (parts.length > 2) return `"${line}": too many slashes`
    const octets = parts[0].split('.')
    if (octets.length !== 4) return `"${line}": must have 4 octets (e.g. 192.168.1.0)`
    for (const oct of octets) {
      if (!/^\d+$/.test(oct)) return `"${line}": "${oct}" is not a valid number`
      const n = parseInt(oct, 10)
      if (n < 0 || n > 255) return `"${line}": octet ${n} out of range (0–255)`
    }
    if (parts.length === 2) {
      if (!/^\d+$/.test(parts[1])) return `"${line}": prefix must be a number`
      const pfx = parseInt(parts[1], 10)
      if (pfx < 0 || pfx > 32) return `"${line}": prefix /${pfx} out of range (0–32)`
    }
  }
  return null
}

interface Props {
  noDefense: boolean
  enabled: string[]
  customConfig: string
  onNoDefenseToggle: (val: boolean) => void
  onToggle: (id: string) => void
  onCustomChange: (val: string) => void
}

export default function DefensePanel({
  noDefense,
  enabled,
  customConfig,
  onNoDefenseToggle,
  onToggle,
  onCustomChange,
}: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [customOpen, setCustomOpen] = useState(false)
  const [ipFieldValues, setIpFieldValues] = useState<Record<string, string>>({})
  const [ipFieldErrors, setIpFieldErrors] = useState<Record<string, string | null>>({})

  const byCategory = DEFENSE_OPTIONS.reduce<Record<string, typeof DEFENSE_OPTIONS>>((acc, d) => {
    if (!acc[d.category]) acc[d.category] = []
    acc[d.category].push(d)
    return acc
  }, {})

  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className="flex items-center gap-2 pt-1">
        <div className="h-px flex-1 bg-gray-800" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-blue-400 flex items-center gap-1">
          <Shield size={10} />
          Defense Config
        </span>
        <div className="h-px flex-1 bg-gray-800" />
      </div>

      <p className="text-[10px] text-gray-500 leading-relaxed">
        Configure what defenses this device has before the simulation runs.
        Defenses block or detect attacks before Suricata IDS rules even apply.
      </p>

      {/* Zero-protection toggle */}
      <button
        type="button"
        onClick={() => onNoDefenseToggle(!noDefense)}
        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition ${
          noDefense
            ? 'bg-red-900/30 border-red-700/50 text-red-300'
            : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-200'
        }`}
      >
        <ShieldOff size={13} className={noDefense ? 'text-red-400' : 'text-gray-600'} />
        <span className="flex-1 text-left">No protection (0 defenses)</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${noDefense ? 'bg-red-800/50 text-red-300' : 'bg-gray-700 text-gray-500'}`}>
          {noDefense ? 'ON' : 'OFF'}
        </span>
      </button>

      {noDefense && (
        <div className="px-3 py-2 rounded-lg bg-red-950/30 border border-red-800/30">
          <p className="text-[10px] text-red-400 leading-relaxed">
            This device has no defenses. The simulation will show every attack reaching it unimpeded —
            useful for testing IDS rules in isolation.
          </p>
        </div>
      )}

      {/* Defense list — greyed out when noDefense is ON */}
      <div className={`space-y-2 transition-opacity ${noDefense ? 'opacity-30 pointer-events-none select-none' : ''}`}>
        {(Object.entries(byCategory) as [DefenseCategory, typeof DEFENSE_OPTIONS][]).map(([cat, defs]) => (
          <div key={cat} className="rounded-lg border border-gray-800 overflow-hidden">
            <div className={`px-2 py-1 text-[10px] font-semibold border-b border-gray-800 ${DEFENSE_CATEGORY_COLORS[cat]}`}>
              {DEFENSE_CATEGORY_LABELS[cat]}
            </div>

            {defs.map((def) => {
              const isEnabled = enabled.includes(def.id)
              const isExpanded = expandedId === def.id
              return (
                <div key={def.id} className={`border-b border-gray-800/50 last:border-0 ${isEnabled ? 'bg-blue-950/20' : ''}`}>
                  <div className="flex items-center gap-2 px-2 py-1.5">
                    <input
                      type="checkbox"
                      checked={isEnabled}
                      onChange={() => onToggle(def.id)}
                      className="accent-blue-500 flex-shrink-0 cursor-pointer"
                    />
                    <span
                      className="flex-1 text-xs text-gray-300 cursor-pointer hover:text-white leading-tight"
                      onClick={() => setExpandedId(isExpanded ? null : def.id)}
                    >
                      {def.name}
                    </span>
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : def.id)}
                      className="text-gray-600 hover:text-gray-400 flex-shrink-0"
                    >
                      {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="px-3 pb-3 space-y-2">
                      <p className="text-[10px] text-gray-400 leading-relaxed">{def.description}</p>

                      <div className="px-2 py-1.5 bg-gray-900/60 rounded-lg border border-gray-700/40">
                        <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wide mb-1">How it works</p>
                        <p className="text-[10px] text-gray-400 leading-relaxed">{def.howItWorks}</p>
                      </div>

                      {def.blocksAttacks.length > 0 && (
                        <div>
                          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wide mb-1">Counters</p>
                          <div className="flex flex-wrap gap-1">
                            {def.blocksAttacks.map(a => (
                              <span key={a} className="text-[10px] px-1.5 py-0.5 bg-green-900/30 border border-green-700/30 text-green-400 rounded font-mono">
                                {a}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="px-2 py-1.5 bg-yellow-950/20 rounded-lg border border-yellow-700/20">
                        <p className="text-[10px] text-yellow-600 font-semibold uppercase tracking-wide mb-1">Weaknesses</p>
                        <p className="text-[10px] text-yellow-700/80 leading-relaxed">{def.weaknesses}</p>
                      </div>

                      {/* Config fields */}
                      {def.configFields && def.configFields.length > 0 && isEnabled && (
                        <div className="space-y-2">
                          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wide">Configuration</p>
                          {def.configFields.map(field => {
                            const stateKey = `${def.id}-${field.key}`
                            if (field.type === 'ip-cidr') {
                              const val = ipFieldValues[stateKey] ?? field.defaultValue
                              const err = ipFieldErrors[stateKey] ?? null
                              return (
                                <div key={field.key}>
                                  <label className="block text-[10px] text-gray-400 mb-1">{field.label}</label>
                                  <textarea
                                    rows={3}
                                    className={`w-full px-2 py-1 bg-gray-800 border ${err ? 'border-red-600' : 'border-gray-700'} rounded text-white text-[11px] font-mono placeholder-gray-600 focus:outline-none focus:ring-1 ${err ? 'focus:ring-red-500' : 'focus:ring-blue-500'} resize-none`}
                                    value={val}
                                    placeholder={field.placeholder}
                                    onChange={e => {
                                      const v = e.target.value
                                      setIpFieldValues(prev => ({ ...prev, [stateKey]: v }))
                                      setIpFieldErrors(prev => ({ ...prev, [stateKey]: validateIPCIDRField(v) }))
                                    }}
                                  />
                                  {err && <p className="text-[10px] text-red-400 mt-1 leading-relaxed">{err}</p>}
                                </div>
                              )
                            }
                            return (
                              <div key={field.key}>
                                <label className="block text-[10px] text-gray-400 mb-1">{field.label}</label>
                                <input
                                  className="w-full px-2 py-1 bg-gray-800 border border-gray-700 rounded text-white text-[11px] font-mono placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                                  defaultValue={field.defaultValue}
                                  placeholder={field.placeholder}
                                />
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>

      {/* Custom defense config */}
      <div className={`rounded-lg border border-gray-800 overflow-hidden ${noDefense ? 'opacity-30 pointer-events-none' : ''}`}>
        <button
          type="button"
          onClick={() => setCustomOpen(!customOpen)}
          className="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-400 hover:bg-gray-800/40 transition"
        >
          <span className="flex items-center gap-1.5 font-medium">
            <Plus size={12} />
            Custom defense configuration
          </span>
          {customOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        {customOpen && (
          <div className="p-2 border-t border-gray-800">
            <p className="text-[10px] text-gray-600 mb-1 leading-relaxed">
              Write custom iptables rules, sysctl settings, or configuration snippets.
              This is for documentation purposes — the simulation uses the checkboxes above.
            </p>
            <textarea
              className="w-full px-2.5 py-2 bg-gray-900 border border-gray-700 rounded-lg text-blue-300 text-[11px] font-mono placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500 resize-none"
              rows={5}
              value={customConfig}
              onChange={e => onCustomChange(e.target.value)}
              placeholder={"# iptables custom rules\niptables -A INPUT -s 203.0.113.0/24 -j DROP\n# sysctl\nnet.ipv4.tcp_syncookies=1"}
            />
          </div>
        )}
      </div>
    </div>
  )
}
