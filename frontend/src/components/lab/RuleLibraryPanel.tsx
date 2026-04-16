import { useState } from 'react'
import { Plus, Trash2, ChevronDown, ChevronRight, BookOpen, ListChecks, TerminalSquare } from 'lucide-react'
import { PREDEFINED_RULES, CATEGORY_LABELS, CATEGORY_COLORS } from '../../data/rules'
import type { RuleEntry, ActiveRule, RuleCategory } from '../../types/lab'

interface Props {
  activeRules: ActiveRule[]
  onAdd: (rule: RuleEntry) => void
  onRemove: (ruleId: string) => void
  onAddCustom: (ruleText: string) => void
}

function CategoryBadge({ category }: { category: RuleCategory }) {
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${CATEGORY_COLORS[category]}`}>
      {CATEGORY_LABELS[category]}
    </span>
  )
}

function DifficultyDot({ level }: { level: string }) {
  const colors = { beginner: 'bg-green-500', intermediate: 'bg-yellow-500', advanced: 'bg-red-500' }
  return (
    <span className={`inline-block w-1.5 h-1.5 rounded-full ${colors[level as keyof typeof colors] ?? 'bg-gray-500'}`} title={level} />
  )
}

function RuleLibrary({ activeRules, onAdd }: { activeRules: ActiveRule[]; onAdd: (r: RuleEntry) => void }) {
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const activeIds = new Set(activeRules.map((r) => r.entry.id))

  const filtered = PREDEFINED_RULES.filter((r) => {
    if (!search) return true
    const q = search.toLowerCase()
    return r.msg.toLowerCase().includes(q) || r.category.includes(q) || r.rule.toLowerCase().includes(q)
  })

  const byCategory = filtered.reduce<Record<string, RuleEntry[]>>((acc, r) => {
    if (!acc[r.category]) acc[r.category] = []
    acc[r.category].push(r)
    return acc
  }, {})

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800">
        <input
          className="w-full px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="Search rules…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="flex-1 overflow-y-auto">
        {Object.entries(byCategory).map(([cat, rules]) => (
          <div key={cat}>
            <div className="px-3 py-1.5 bg-gray-800/40 border-b border-gray-800">
              <CategoryBadge category={cat as RuleCategory} />
            </div>
            {rules.map((rule) => {
              const isExpanded = expandedId === rule.id
              const isActive = activeIds.has(rule.id)
              return (
                <div key={rule.id} className="border-b border-gray-800/50">
                  <div
                    className="flex items-center gap-2 px-3 py-2 hover:bg-gray-800/40 cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : rule.id)}
                  >
                    {isExpanded ? <ChevronDown size={12} className="text-gray-500 flex-shrink-0" /> : <ChevronRight size={12} className="text-gray-500 flex-shrink-0" />}
                    <DifficultyDot level={rule.difficulty} />
                    <span className="text-xs text-gray-300 flex-1 truncate">{rule.msg}</span>
                    <button
                      onClick={(e) => { e.stopPropagation(); if (!isActive) onAdd(rule) }}
                      disabled={isActive}
                      className={`flex-shrink-0 p-1 rounded transition ${isActive ? 'text-green-500 cursor-default' : 'text-gray-500 hover:text-indigo-400 hover:bg-gray-700'}`}
                      title={isActive ? 'Already added' : 'Add to simulation'}
                    >
                      <Plus size={12} />
                    </button>
                  </div>
                  {isExpanded && (
                    <div className="px-4 pb-3 space-y-2">
                      <pre className="text-[10px] text-gray-400 font-mono bg-gray-800/60 rounded p-2 whitespace-pre-wrap break-all leading-relaxed">
                        {rule.rule}
                      </pre>
                      <p className="text-[11px] text-gray-400 leading-relaxed">{rule.explanation}</p>
                      <button
                        onClick={() => { if (!isActive) onAdd(rule) }}
                        disabled={isActive}
                        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium transition ${isActive ? 'bg-green-900/30 text-green-400 cursor-default' : 'bg-indigo-700/40 hover:bg-indigo-600/60 text-indigo-300'}`}
                      >
                        <Plus size={12} />
                        {isActive ? 'Added' : 'Add to simulation'}
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ))}
        {filtered.length === 0 && (
          <p className="text-xs text-gray-600 text-center py-6">No rules match your search.</p>
        )}
      </div>
    </div>
  )
}

function ActiveRules({ activeRules, onRemove }: { activeRules: ActiveRule[]; onRemove: (id: string) => void }) {
  if (activeRules.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center py-8 px-4">
        <ListChecks size={24} className="text-gray-600 mb-2" />
        <p className="text-xs text-gray-500">No rules added yet.</p>
        <p className="text-[11px] text-gray-600 mt-1">Add rules from the Library tab.</p>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {activeRules.map((r) => (
        <div key={r.entry.id} className="flex items-center gap-2 px-3 py-2 border-b border-gray-800/50 hover:bg-gray-800/30">
          <CategoryBadge category={r.entry.category} />
          <span className="text-xs text-gray-300 flex-1 truncate">{r.entry.msg}</span>
          <button
            onClick={() => onRemove(r.entry.id)}
            className="text-gray-600 hover:text-red-400 transition p-1"
          >
            <Trash2 size={12} />
          </button>
        </div>
      ))}
    </div>
  )
}

function CustomRule({ onAddCustom }: { onAddCustom: (text: string) => void }) {
  const [text, setText] = useState('')

  function handle() {
    const trimmed = text.trim()
    if (!trimmed) return
    onAddCustom(trimmed)
    setText('')
  }

  return (
    <div className="p-3 flex flex-col gap-2 h-full">
      <p className="text-[11px] text-gray-500">
        Write any valid Suricata rule. Use <code className="text-indigo-400 bg-gray-800 px-1 rounded">$HOME_NET</code> and <code className="text-indigo-400 bg-gray-800 px-1 rounded">$EXTERNAL_NET</code> — they will be resolved from your topology.
      </p>
      <textarea
        className="flex-1 w-full px-2.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-xs font-mono placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500 resize-none"
        placeholder={`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"My Custom Rule"; flags:S; sid:9999999; rev:1;)`}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button
        onClick={handle}
        disabled={!text.trim()}
        className="w-full py-1.5 bg-indigo-700/50 hover:bg-indigo-600/60 disabled:opacity-40 text-indigo-300 text-xs font-semibold rounded-lg transition"
      >
        Add custom rule
      </button>
    </div>
  )
}

type Tab = 'library' | 'active' | 'custom'

export default function RuleLibraryPanel({ activeRules, onAdd, onRemove, onAddCustom }: Props) {
  const [tab, setTab] = useState<Tab>('library')

  const tabs: { id: Tab; label: string; Icon: React.FC<{ size?: number }> }[] = [
    { id: 'library', label: 'Library', Icon: BookOpen },
    { id: 'active',  label: `Active (${activeRules.length})`, Icon: ListChecks },
    { id: 'custom',  label: 'Custom', Icon: TerminalSquare },
  ]

  return (
    <div className="flex flex-col h-full bg-gray-900 border-t border-gray-800">
      {/* Tabs */}
      <div className="flex border-b border-gray-800 flex-shrink-0">
        {tabs.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition border-b-2 ${
              tab === id
                ? 'border-indigo-500 text-white'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {tab === 'library' && <RuleLibrary activeRules={activeRules} onAdd={onAdd} />}
        {tab === 'active'  && <ActiveRules activeRules={activeRules} onRemove={onRemove} />}
        {tab === 'custom'  && <CustomRule onAddCustom={onAddCustom} />}
      </div>
    </div>
  )
}
