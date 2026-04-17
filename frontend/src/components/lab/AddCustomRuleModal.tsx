import { useState } from 'react'
import { X, AlertTriangle, Check, Wand2, Shield } from 'lucide-react'
import type { CustomRuleEntry } from '../../types/lab'
import { CATEGORY_LABELS, CATEGORY_COLORS } from '../../data/rules'

// ─── Color palette for custom categories ─────────────────────────────────────

export const COLOR_PALETTE: { value: string; classes: string; dot: string }[] = [
  { value: 'indigo',  classes: 'text-indigo-300 bg-indigo-900/50 border-indigo-700',  dot: 'bg-indigo-400'  },
  { value: 'purple',  classes: 'text-purple-300 bg-purple-900/50 border-purple-700',  dot: 'bg-purple-400'  },
  { value: 'pink',    classes: 'text-pink-300   bg-pink-900/50   border-pink-700',    dot: 'bg-pink-400'    },
  { value: 'teal',    classes: 'text-teal-300   bg-teal-900/50   border-teal-700',    dot: 'bg-teal-400'    },
  { value: 'orange',  classes: 'text-orange-300 bg-orange-900/50 border-orange-700',  dot: 'bg-orange-400'  },
  { value: 'red',     classes: 'text-red-300    bg-red-900/50    border-red-700',     dot: 'bg-red-400'     },
  { value: 'amber',   classes: 'text-amber-300  bg-amber-900/50  border-amber-700',   dot: 'bg-amber-400'   },
  { value: 'cyan',    classes: 'text-cyan-300   bg-cyan-900/50   border-cyan-700',    dot: 'bg-cyan-400'    },
  { value: 'green',   classes: 'text-green-300  bg-green-900/50  border-green-700',   dot: 'bg-green-400'   },
  { value: 'sky',     classes: 'text-sky-300    bg-sky-900/50    border-sky-700',     dot: 'bg-sky-400'     },
]

export function getCustomCategoryClasses(color: string): string {
  return COLOR_PALETTE.find(c => c.value === color)?.classes ??
    'text-gray-300 bg-gray-800/50 border-gray-700'
}

// ─── Validation ───────────────────────────────────────────────────────────────

export function validateRuleText(text: string): string[] {
  const t = text.trim()
  if (!t) return ['Rule text is required']

  const errors: string[] = []

  if (!/^(alert|drop|pass|reject)\s/.test(t))
    errors.push('Must start with an action: alert / drop / pass / reject')

  const headerRe = /^(alert|drop|pass|reject)\s+\w+\s+\S+\s+\S+\s+(<>|->|<-)\s+\S+\s+\S+\s*\(/
  if (!headerRe.test(t))
    errors.push('Header format: action proto src_ip src_port -> dst_ip dst_port (…)')

  if (!t.includes(')'))
    errors.push('Options block must be closed with )')

  if (!/\bsid\s*:\s*\d+/.test(t))
    errors.push('Missing sid:NNNNN; in options')

  if (!/\bmsg\s*:\s*"/.test(t))
    errors.push('Missing msg:"…"; in options')

  return errors
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function nextSid(existing: CustomRuleEntry[]): number {
  const sids = existing
    .map(r => parseInt(r.sid, 10))
    .filter(n => !isNaN(n) && n >= 9000000)
  return sids.length === 0 ? 9000001 : Math.max(...sids) + 1
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  existingCustomRules: CustomRuleEntry[]
  initialRule?: CustomRuleEntry   // when set, modal is in edit mode
  onSave: (rule: CustomRuleEntry) => void
  onClose: () => void
}

const EXISTING_CATS = Object.keys(CATEGORY_LABELS) as string[]

export default function AddCustomRuleModal({ existingCustomRules, initialRule, onSave, onClose }: Props) {
  const isEdit = !!initialRule
  const suggestedSid = nextSid(existingCustomRules)

  // Determine initial category mode from the rule being edited
  const initCatMode = initialRule
    ? (EXISTING_CATS.includes(initialRule.category) ? 'existing' : 'new')
    : 'existing'

  const [name,         setName]         = useState(initialRule?.msg ?? '')
  const [sid,          setSid]          = useState(initialRule?.sid ?? String(suggestedSid))
  const [catMode,      setCatMode]      = useState<'existing' | 'new'>(initCatMode)
  const [existingCat,  setExistingCat]  = useState(
    initialRule && EXISTING_CATS.includes(initialRule.category) ? initialRule.category : 'custom'
  )
  const [newCatName,   setNewCatName]   = useState(
    initialRule && !EXISTING_CATS.includes(initialRule.category) ? initialRule.category : ''
  )
  const [newCatColor,  setNewCatColor]  = useState(initialRule?.categoryColor || 'indigo')
  const [ruleText,     setRuleText]     = useState(initialRule?.rule ?? '')

  const errors   = validateRuleText(ruleText)
  const isValid  = errors.length === 0
  const hasText  = ruleText.trim().length > 0

  const category      = catMode === 'existing' ? existingCat : (newCatName.trim() || 'custom')
  const categoryColor = catMode === 'new' ? newCatColor : ''

  function handleGenerateTemplate() {
    const msgVal = name.trim() || 'My Custom Rule'
    const sidVal = sid.trim() || String(suggestedSid)
    setRuleText(
      `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"${msgVal}"; flow:established,to_server; content:"CHANGE_ME"; nocase; sid:${sidVal}; rev:1;)`
    )
  }

  function handleSave() {
    if (!ruleText.trim()) return
    const ruleMsg = ruleText.match(/\bmsg\s*:\s*"([^"]+)"/)?.[1] ?? ''
    onSave({
      id: initialRule?.id ?? `custom-${Date.now()}`,   // preserve id when editing
      sid: sid.trim() || String(suggestedSid),
      category,
      categoryColor,
      msg: name.trim() || ruleMsg || 'Custom Rule',
      rule: ruleText.trim(),
      isValid,
    })
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div
        className="flex flex-col bg-gray-900 border border-gray-700/60 rounded-2xl shadow-2xl overflow-hidden"
        style={{ width: 640, maxHeight: '90vh' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <Shield size={14} className="text-indigo-400" />
            <span className="text-sm font-semibold text-gray-100">
              {isEdit ? 'Edit Custom Rule' : 'Add Custom Rule'}
            </span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4 min-h-0">

          {/* Name + SID */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-1.5">
                Rule Name
              </label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder='e.g. SQL Injection Attempt'
                className="w-full bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-600 transition"
              />
              <p className="text-[10px] text-gray-600 mt-1">Display label in the panel</p>
            </div>
            <div>
              <label className="block text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-1.5">
                SID
              </label>
              <input
                value={sid}
                onChange={e => setSid(e.target.value)}
                placeholder={String(suggestedSid)}
                className="w-full bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 font-mono focus:outline-none focus:border-indigo-600 transition"
              />
              <p className="text-[10px] text-gray-600 mt-1">Custom rules use 9000000+ range</p>
            </div>
          </div>

          {/* Category */}
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-1.5">
              Category
            </label>
            <div className="flex flex-wrap gap-1.5">
              {EXISTING_CATS.map(cat => (
                <button
                  key={cat}
                  onClick={() => { setCatMode('existing'); setExistingCat(cat) }}
                  className={`px-2.5 py-1 rounded-lg text-[11px] border transition ${
                    catMode === 'existing' && existingCat === cat
                      ? (CATEGORY_COLORS[cat] ?? 'text-gray-300 bg-gray-800/40 border-gray-600')
                      : 'bg-gray-800/40 border-gray-700 text-gray-500 hover:text-gray-300 hover:border-gray-600'
                  }`}
                >
                  {CATEGORY_LABELS[cat]}
                </button>
              ))}
              <button
                onClick={() => setCatMode('new')}
                className={`px-2.5 py-1 rounded-lg text-[11px] border transition ${
                  catMode === 'new'
                    ? 'bg-indigo-900/40 border-indigo-600 text-indigo-300'
                    : 'bg-gray-800/40 border-gray-700 text-gray-500 hover:text-gray-300 hover:border-gray-600'
                }`}
              >
                + New category
              </button>
            </div>

            {catMode === 'new' && (
              <div className="flex items-center gap-3 mt-2">
                <input
                  value={newCatName}
                  onChange={e => setNewCatName(e.target.value)}
                  placeholder="Category name"
                  className="flex-1 bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-600 transition"
                />
                <div className="flex gap-1.5 flex-shrink-0">
                  {COLOR_PALETTE.map(c => (
                    <button
                      key={c.value}
                      onClick={() => setNewCatColor(c.value)}
                      title={c.value}
                      className={`w-4 h-4 rounded-full ${c.dot} transition ${
                        newCatColor === c.value
                          ? 'ring-2 ring-white ring-offset-1 ring-offset-gray-900 scale-110'
                          : 'opacity-50 hover:opacity-100'
                      }`}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Rule text */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">
                Rule Text
              </label>
              <button
                onClick={handleGenerateTemplate}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition"
              >
                <Wand2 size={10} />
                Generate template
              </button>
            </div>
            <textarea
              value={ruleText}
              onChange={e => setRuleText(e.target.value)}
              placeholder={`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"${name || 'My Rule'}"; sid:${sid || suggestedSid}; rev:1;)`}
              rows={4}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-[11px] text-green-300 font-mono placeholder-gray-700 focus:outline-none focus:border-indigo-600 transition resize-none leading-relaxed"
            />
            <p className="text-[10px] text-gray-600 mt-1 font-mono">
              action protocol src_ip src_port {'→'} dst_ip dst_port (options;)
            </p>
          </div>

          {/* Validation feedback */}
          {hasText && (
            <div className={`rounded-xl border p-3 ${
              isValid
                ? 'border-green-800/60 bg-green-950/20'
                : 'border-amber-800/60 bg-amber-950/10'
            }`}>
              <div className="flex items-center gap-2 mb-1">
                {isValid
                  ? <Check size={12} className="text-green-400 flex-shrink-0" />
                  : <AlertTriangle size={12} className="text-amber-400 flex-shrink-0" />}
                <span className={`text-[11px] font-semibold ${isValid ? 'text-green-400' : 'text-amber-400'}`}>
                  {isValid ? 'Rule syntax looks valid' : 'Syntax issues detected'}
                </span>
              </div>
              {!isValid && (
                <>
                  <ul className="ml-4 space-y-0.5 mb-1.5">
                    {errors.map((e, i) => (
                      <li key={i} className="text-[10px] text-amber-300/80 list-disc">{e}</li>
                    ))}
                  </ul>
                  <p className="text-[10px] text-gray-600">
                    You can still save — invalid rules are flagged in the panel and reported during simulation.
                  </p>
                </>
              )}
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-gray-800 flex-shrink-0">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs text-gray-500 hover:text-gray-300 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!hasText}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-600 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold transition"
          >
            {hasText && !isValid && <AlertTriangle size={11} className="text-amber-300" />}
            Save Rule
          </button>
        </div>
      </div>
    </div>
  )
}
