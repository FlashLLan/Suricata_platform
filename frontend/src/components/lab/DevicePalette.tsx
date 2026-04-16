import { Monitor, Server, Globe, Database, Router, Shield, Skull, Mail, Wifi, Eye } from 'lucide-react'
import type { DeviceType } from '../../types/lab'

const PALETTE_ITEMS: { type: DeviceType; label: string; Icon: React.FC<{ size?: number; className?: string }> ; color: string }[] = [
  { type: 'workstation',  label: 'Workstation',   Icon: Monitor,  color: 'text-blue-400' },
  { type: 'server',       label: 'Server',        Icon: Server,   color: 'text-cyan-400' },
  { type: 'web-server',   label: 'Web Server',    Icon: Globe,    color: 'text-emerald-400' },
  { type: 'database',     label: 'Database',      Icon: Database, color: 'text-violet-400' },
  { type: 'router',       label: 'Router',        Icon: Router,   color: 'text-amber-400' },
  { type: 'firewall',     label: 'Firewall',      Icon: Shield,   color: 'text-orange-400' },
  { type: 'attacker',     label: 'Attacker',      Icon: Skull,    color: 'text-red-400' },
  { type: 'dns-server',   label: 'DNS Server',    Icon: Wifi,     color: 'text-sky-400' },
  { type: 'mail-server',  label: 'Mail Server',   Icon: Mail,     color: 'text-pink-400' },
  { type: 'ids',          label: 'Suricata IDS',  Icon: Eye,      color: 'text-indigo-400' },
]

export default function DevicePalette() {
  function onDragStart(e: React.DragEvent, deviceType: DeviceType) {
    e.dataTransfer.setData('application/device-type', deviceType)
    e.dataTransfer.effectAllowed = 'move'
  }

  return (
    <div className="flex flex-col gap-1 p-2">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 px-1 mb-1">
        Drag to canvas
      </p>
      {PALETTE_ITEMS.map(({ type, label, Icon, color }) => (
        <div
          key={type}
          draggable
          onDragStart={(e) => onDragStart(e, type)}
          className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg bg-gray-800/60 hover:bg-gray-700/60 border border-gray-700/40 cursor-grab active:cursor-grabbing transition select-none"
        >
          <Icon size={16} className={color} />
          <span className="text-gray-300 text-xs">{label}</span>
        </div>
      ))}
    </div>
  )
}
