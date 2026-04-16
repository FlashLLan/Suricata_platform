import { useState, useEffect } from 'react'
import { X } from 'lucide-react'
import type { Node } from '@xyflow/react'
import type { DeviceData, NetworkZone, DeviceType } from '../../types/lab'

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

const ZONES: { value: NetworkZone; label: string; color: string }[] = [
  { value: 'internal',   label: 'Internal',   color: 'text-blue-400' },
  { value: 'dmz',        label: 'DMZ',        color: 'text-yellow-400' },
  { value: 'external',   label: 'External',   color: 'text-red-400' },
  { value: 'management', label: 'Management', color: 'text-purple-400' },
]

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
const selectCls = `${inputCls} cursor-pointer`

export default function DeviceConfigPanel({ node, onClose, onUpdate }: Props) {
  const raw = node?.data as unknown as DeviceData | undefined
  const [form, setForm] = useState<DeviceData>({
    label: '', deviceType: 'workstation', ip: '', subnet: '',
    ports: '', os: '', zone: 'internal', notes: '',
  })

  useEffect(() => {
    if (raw) setForm({ ...raw })
  }, [node?.id])

  if (!node) return null

  function set<K extends keyof DeviceData>(key: K, value: DeviceData[K]) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  function handleSave() {
    onUpdate(node!.id, form)
  }

  return (
    <div className="w-72 flex-shrink-0 bg-gray-900 border-l border-gray-800 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <span className="text-sm font-semibold text-white">Device Config</span>
        <button onClick={onClose} className="text-gray-500 hover:text-white transition">
          <X size={16} />
        </button>
      </div>

      {/* Form */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <Field label="Name">
          <input
            className={inputCls}
            value={form.label}
            onChange={(e) => set('label', e.target.value)}
            placeholder="e.g. Employee Laptop"
          />
        </Field>

        <Field label="Device Type">
          <select className={selectCls} value={form.deviceType} onChange={(e) => set('deviceType', e.target.value as DeviceType)}>
            {DEVICE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </Field>

        <Field label="IP Address" hint="Used by simulation to resolve $HOME_NET / $EXTERNAL_NET">
          <input
            className={inputCls}
            value={form.ip}
            onChange={(e) => set('ip', e.target.value)}
            placeholder="192.168.1.10"
          />
        </Field>

        <Field label="Subnet / CIDR">
          <input
            className={inputCls}
            value={form.subnet}
            onChange={(e) => set('subnet', e.target.value)}
            placeholder="192.168.1.0/24"
          />
        </Field>

        <Field label="Open Ports / Services" hint="Comma-separated">
          <input
            className={inputCls}
            value={form.ports}
            onChange={(e) => set('ports', e.target.value)}
            placeholder="22, 80, 443"
          />
        </Field>

        <Field label="OS / Profile">
          <input
            className={inputCls}
            value={form.os}
            onChange={(e) => set('os', e.target.value)}
            placeholder="Ubuntu 22.04, Windows 11…"
          />
        </Field>

        <Field label="Network Zone">
          <select className={selectCls} value={form.zone} onChange={(e) => set('zone', e.target.value as NetworkZone)}>
            {ZONES.map((z) => (
              <option key={z.value} value={z.value}>{z.label}</option>
            ))}
          </select>
          <p className="text-[10px] text-gray-600 mt-1">
            Zone determines ring colour on canvas and affects how rules resolve
            $HOME_NET vs $EXTERNAL_NET.
          </p>
        </Field>

        <Field label="Notes">
          <textarea
            className={`${inputCls} resize-none`}
            rows={3}
            value={form.notes}
            onChange={(e) => set('notes', e.target.value)}
            placeholder="Purpose, role, anything relevant…"
          />
        </Field>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-gray-800">
        <button
          onClick={handleSave}
          className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-lg transition"
        >
          Apply changes
        </button>
      </div>
    </div>
  )
}
