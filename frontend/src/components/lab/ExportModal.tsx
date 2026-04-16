import { useState } from 'react'
import { X, Download, Copy, Check, FileText, Settings, Terminal } from 'lucide-react'
import type { Node } from '@xyflow/react'
import type { ActiveRule, DeviceData } from '../../types/lab'

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  projectName: string
  activeRules: ActiveRule[]
  nodes: Node[]
  onClose: () => void
}

type ExportTab = 'rules' | 'env'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDeviceData(n: Node): DeviceData {
  return n.data as unknown as DeviceData
}

function buildRulesFile(projectName: string, activeRules: ActiveRule[], nodes: Node[]): string {
  const date = new Date().toISOString().slice(0, 10)
  const deviceSummary = nodes
    .map(n => getDeviceData(n))
    .filter(d => d.ip && d.label)
    .map(d => `${d.label} (${d.ip})`)
    .join(', ')

  const homeIPs = nodes
    .map(getDeviceData)
    .filter(d => d.ip && ['internal', 'dmz', 'management'].includes(d.zone))
    .map(d => d.ip)

  const lines: string[] = [
    `# Suricata Rules — exported from Suricata Learning Platform`,
    `# Project  : ${projectName}`,
    `# Generated: ${date}`,
    `# Rules    : ${activeRules.length}`,
    `#`,
    deviceSummary ? `# Devices  : ${deviceSummary}` : '# Devices  : (none configured)',
    homeIPs.length ? `# HOME_NET : ${homeIPs.join(', ')}` : '# HOME_NET : (configure in suricata.yaml)',
    `#`,
    `# Drop this file into /etc/suricata/rules/ and add it to rule-files in suricata.yaml`,
    `# See the Environment tab for the matching vars block.`,
    ``,
  ]

  if (activeRules.length === 0) {
    lines.push('# No rules are currently active. Add rules from the Rule Library first.')
  } else {
    for (const ar of activeRules) {
      const ruleText = ar.customText ?? ar.entry.rule
      lines.push(ruleText)
    }
  }

  lines.push('')
  return lines.join('\n')
}

function buildYamlVars(nodes: Node[]): string {
  const devs = nodes.map(getDeviceData)

  const homeIPs = devs
    .filter(d => d.ip && ['internal', 'dmz', 'management'].includes(d.zone))
    .map(d => d.ip)

  const httpServerIPs = devs
    .filter(d => d.ip && ['web-server', 'server'].includes(d.deviceType) && ['internal', 'dmz'].includes(d.zone))
    .map(d => d.ip)

  const dnsServerIPs = devs
    .filter(d => d.ip && d.deviceType === 'dns-server')
    .map(d => d.ip)

  const smtpServerIPs = devs
    .filter(d => d.ip && d.deviceType === 'mail-server')
    .map(d => d.ip)

  const sqlServerIPs = devs
    .filter(d => d.ip && d.deviceType === 'database')
    .map(d => d.ip)

  // Collect HTTP ports from web servers
  const httpPortSet = new Set<string>()
  for (const d of devs) {
    if (['web-server', 'server'].includes(d.deviceType) && d.ports) {
      for (const p of d.ports.split(',')) {
        const port = p.trim()
        if (['80', '443', '8080', '8443', '3000', '5000'].includes(port)) {
          httpPortSet.add(port)
        }
      }
    }
  }
  const httpPorts = httpPortSet.size > 0
    ? (httpPortSet.size === 1 ? [...httpPortSet][0] : `"[${[...httpPortSet].join(',')}]"`)
    : '"80"'

  const fmt = (ips: string[], fallback: string) =>
    ips.length === 0 ? fallback
    : ips.length === 1 ? `"${ips[0]}"`
    : `"[${ips.join(',')}]"`

  const homeNet = homeIPs.length === 0
    ? '"192.168.0.0/16"   # TODO: replace with your actual network'
    : fmt(homeIPs, '"192.168.0.0/16"')

  const lines = [
    `# ─── suricata.yaml — vars section ───────────────────────────────────────────`,
    `# Copy this block into your suricata.yaml, replacing the existing vars: section.`,
    `# Generated from your canvas topology on ${new Date().toISOString().slice(0, 10)}.`,
    ``,
    `vars:`,
    `  address-groups:`,
    `    HOME_NET: ${homeNet}`,
    `    EXTERNAL_NET: "!$HOME_NET"`,
    `    HTTP_SERVERS: ${fmt(httpServerIPs, '"$HOME_NET"')}`,
    `    DNS_SERVERS: ${fmt(dnsServerIPs, '"$HOME_NET"')}`,
    `    SMTP_SERVERS: ${fmt(smtpServerIPs, '"$HOME_NET"')}`,
    `    SQL_SERVERS: ${fmt(sqlServerIPs, '"$HOME_NET"')}`,
    ``,
    `  port-groups:`,
    `    HTTP_PORTS: ${httpPorts}`,
    `    SSH_PORTS: "22"`,
    `    FTP_PORTS: "21"`,
    `    DNS_PORTS: "53"`,
    `    SHELLCODE_PORTS: "!80"`,
    `    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"`,
  ]

  return lines.join('\n')
}

const DEPLOY_STEPS = [
  {
    step: '1',
    title: 'Copy the rules file',
    cmd: 'sudo cp local.rules /etc/suricata/rules/local.rules',
    detail: 'Place it alongside the official rule sets (e.g. next to emerging-threats.rules).',
  },
  {
    step: '2',
    title: 'Register it in suricata.yaml',
    cmd: 'rule-files:\n  - suricata.rules\n  - local.rules      # ← add this',
    detail: 'Under the rule-files: key in suricata.yaml.',
  },
  {
    step: '3',
    title: 'Paste the vars block',
    cmd: null,
    detail: 'Replace (or merge) the vars: section in suricata.yaml with the content from the Environment tab above.',
  },
  {
    step: '4',
    title: 'Test the configuration',
    cmd: 'sudo suricata -T -c /etc/suricata/suricata.yaml',
    detail: 'A clean exit (no errors) means the config and rules are valid.',
  },
  {
    step: '5',
    title: 'Reload rules (no restart needed)',
    cmd: 'sudo kill -USR2 $(pidof suricata)',
    detail: 'Or restart the service: sudo systemctl restart suricata',
  },
  {
    step: '6',
    title: 'Watch for alerts',
    cmd: 'tail -f /var/log/suricata/fast.log',
    detail: 'Each matched rule appears as a line in fast.log. EVE JSON is at /var/log/suricata/eve.json.',
  },
]

// ─── Copy button ──────────────────────────────────────────────────────────────

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 hover:text-white transition"
    >
      {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
      {copied ? 'Copied!' : label}
    </button>
  )
}

// ─── Download helper ──────────────────────────────────────────────────────────

function downloadText(content: string, filename: string) {
  const blob = new Blob([content], { type: 'text/plain' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// ─── Rules tab ────────────────────────────────────────────────────────────────

function RulesTab({
  rulesContent,
  projectName,
}: {
  rulesContent: string
  projectName: string
}) {
  const filename = `${projectName.toLowerCase().replace(/\s+/g, '-') || 'lab'}.rules`

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <p className="text-xs font-semibold text-gray-200">{filename}</p>
          <p className="text-[10px] text-gray-500 mt-0.5">
            Drop this into <code className="bg-gray-800 px-1 rounded">/etc/suricata/rules/</code> and add it to <code className="bg-gray-800 px-1 rounded">rule-files:</code>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <CopyButton text={rulesContent} />
          <button
            onClick={() => downloadText(rulesContent, filename)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-700 hover:bg-indigo-600 border border-indigo-600 text-white transition"
          >
            <Download size={12} />
            Download
          </button>
        </div>
      </div>

      <pre className="flex-1 min-h-0 overflow-auto bg-gray-950 border border-gray-800 rounded-xl p-3 text-[11px] text-green-300 font-mono leading-relaxed whitespace-pre-wrap">
        {rulesContent}
      </pre>
    </div>
  )
}

// ─── Environment tab ──────────────────────────────────────────────────────────

function EnvTab({ yamlContent }: { yamlContent: string }) {
  return (
    <div className="flex flex-col gap-4 h-full overflow-y-auto">
      {/* YAML block */}
      <div className="flex flex-col gap-2 flex-shrink-0">
        <div className="flex items-center justify-between">
          <p className="text-xs font-semibold text-gray-200 flex items-center gap-1.5">
            <Settings size={12} className="text-indigo-400" />
            suricata.yaml — vars block
          </p>
          <div className="flex items-center gap-2">
            <CopyButton text={yamlContent} />
            <button
              onClick={() => downloadText(yamlContent, 'suricata-vars.yaml')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 hover:text-white transition"
            >
              <Download size={12} />
              Download
            </button>
          </div>
        </div>
        <pre className="bg-gray-950 border border-gray-800 rounded-xl p-3 text-[11px] text-amber-300 font-mono leading-relaxed whitespace-pre-wrap overflow-x-auto">
          {yamlContent}
        </pre>
      </div>

      {/* Deployment steps */}
      <div className="flex flex-col gap-2 flex-shrink-0 pb-3">
        <p className="text-xs font-semibold text-gray-200 flex items-center gap-1.5">
          <Terminal size={12} className="text-emerald-400" />
          Deployment steps
        </p>
        <div className="space-y-2">
          {DEPLOY_STEPS.map(s => (
            <div key={s.step} className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
              <div className="flex items-start gap-2.5">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-indigo-900/60 text-indigo-300 text-[10px] font-bold flex items-center justify-center mt-0.5">
                  {s.step}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-gray-200">{s.title}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{s.detail}</p>
                  {s.cmd && (
                    <div className="mt-1.5 flex items-start gap-1.5">
                      <pre className="flex-1 text-[10px] font-mono text-green-300 bg-gray-950 border border-gray-800 rounded-lg px-2.5 py-1.5 whitespace-pre-wrap overflow-x-auto">
                        {s.cmd}
                      </pre>
                      <CopyButton text={s.cmd} label="" />
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Modal ────────────────────────────────────────────────────────────────────

export default function ExportModal({ projectName, activeRules, nodes, onClose }: Props) {
  const [tab, setTab] = useState<ExportTab>('rules')

  const rulesContent = buildRulesFile(projectName, activeRules, nodes)
  const yamlContent  = buildYamlVars(nodes)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="flex flex-col bg-gray-900 border border-gray-700/60 rounded-2xl shadow-2xl overflow-hidden"
        style={{ width: 680, height: 600 }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <FileText size={15} className="text-indigo-400" />
            <span className="text-sm font-semibold text-gray-100">Export</span>
            <span className="text-xs text-gray-500">{projectName}</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X size={16} />
          </button>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 px-5 pt-3 pb-0 border-b border-gray-800 flex-shrink-0">
          {([
            { id: 'rules', label: 'Rules File', badge: activeRules.length > 0 ? String(activeRules.length) : null },
            { id: 'env',   label: 'Environment + Deployment', badge: null },
          ] as const).map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-xs font-medium rounded-t-lg border-b-2 transition flex items-center gap-1.5 ${
                tab === t.id
                  ? 'border-indigo-500 text-indigo-300 bg-indigo-950/30'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              {t.label}
              {t.badge && (
                <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-indigo-900/60 text-indigo-300">
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 min-h-0 px-5 py-4 overflow-hidden flex flex-col">
          {tab === 'rules' && (
            <RulesTab rulesContent={rulesContent} projectName={projectName} />
          )}
          {tab === 'env' && (
            <EnvTab yamlContent={yamlContent} />
          )}
        </div>
      </div>
    </div>
  )
}
