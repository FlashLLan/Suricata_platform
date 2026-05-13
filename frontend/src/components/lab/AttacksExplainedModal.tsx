import { useState } from 'react'
import { X, Terminal, ChevronDown, ChevronRight, Info } from 'lucide-react'
import {
  ATTACK_COMMANDS, ATTACK_CATEGORY_LABELS, ATTACK_CATEGORY_COLORS,
  type AttackCategory,
} from '../../data/attacks'

interface Props {
  onClose: () => void
}

export default function AttacksExplainedModal({ onClose }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const byCategory = ATTACK_COMMANDS.reduce<Record<string, typeof ATTACK_COMMANDS>>((acc, cmd) => {
    if (!acc[cmd.category]) acc[cmd.category] = []
    acc[cmd.category].push(cmd)
    return acc
  }, {})

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl max-h-[90vh] flex flex-col bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <Terminal size={16} className="text-red-400" />
            <span className="text-sm font-semibold text-white">Attacks Explained</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition">
            <X size={16} />
          </button>
        </div>

        {/* Notice banner */}
        <div className="mx-4 mt-4 flex-shrink-0 flex items-start gap-2.5 px-3 py-2.5 bg-yellow-950/40 border border-yellow-700/40 rounded-lg">
          <Info size={13} className="text-yellow-500 mt-0.5 flex-shrink-0" />
          <p className="text-[11px] text-yellow-400 leading-relaxed">
            This is a reference guide only. These commands are shown for educational purposes - no commands are executed by this platform. Use them in your own controlled lab environment with proper authorisation.
          </p>
        </div>

        {/* Attack list */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {(Object.entries(byCategory) as [AttackCategory, typeof ATTACK_COMMANDS][]).map(([cat, cmds]) => (
            <div key={cat} className="rounded-xl border border-gray-800 overflow-hidden">
              <div className={`px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide border-b border-gray-800 ${ATTACK_CATEGORY_COLORS[cat]}`}>
                {ATTACK_CATEGORY_LABELS[cat]}
              </div>

              {cmds.map((cmd) => {
                const isExpanded = expandedId === cmd.id
                return (
                  <div key={cmd.id} className="border-b border-gray-800/50 last:border-0">
                    <button
                      type="button"
                      className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-800/40 transition text-left"
                      onClick={() => setExpandedId(isExpanded ? null : cmd.id)}
                    >
                      <span className="flex-1 text-xs text-gray-200 font-medium">{cmd.name}</span>
                      <span className="text-[10px] text-gray-500 font-mono bg-gray-800 px-1.5 py-0.5 rounded">{cmd.tool}</span>
                      {isExpanded ? <ChevronDown size={12} className="text-gray-500 flex-shrink-0" /> : <ChevronRight size={12} className="text-gray-500 flex-shrink-0" />}
                    </button>

                    {isExpanded && (
                      <div className="px-4 pb-4 space-y-3">
                        <p className="text-[11px] text-gray-400 leading-relaxed">{cmd.description}</p>

                        <div>
                          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wide mb-1.5">Command</p>
                          <pre className="text-[11px] text-green-400 font-mono bg-gray-950 border border-gray-800 rounded-lg px-3 py-2.5 whitespace-pre-wrap break-all leading-relaxed">
                            {cmd.cmd}
                          </pre>
                        </div>

                        {cmd.linkedScenario && (
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-gray-500">Simulation scenario:</span>
                            <span className="text-[10px] text-indigo-400 font-mono bg-indigo-900/20 border border-indigo-700/30 px-1.5 py-0.5 rounded">
                              {cmd.linkedScenario}
                            </span>
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

        {/* Footer */}
        <div className="px-5 py-3 border-t border-gray-800 flex-shrink-0">
          <button
            onClick={onClose}
            className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
