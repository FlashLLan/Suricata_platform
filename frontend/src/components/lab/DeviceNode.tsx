import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import {
  Monitor, Server, Globe, Database, Router, Shield,
  Skull, Mail, Wifi, Eye,
} from 'lucide-react'
import type { DeviceData, DeviceType } from '../../types/lab'

const DEVICE_CONFIG: Record<DeviceType, {
  Icon: React.FC<{ size?: number; className?: string }>
  label: string
  color: string
  bg: string
  border: string
}> = {
  workstation:  { Icon: Monitor,  label: 'Workstation',  color: 'text-blue-400',   bg: 'bg-blue-950/60',   border: 'border-blue-700/60' },
  server:       { Icon: Server,   label: 'Server',       color: 'text-cyan-400',   bg: 'bg-cyan-950/60',   border: 'border-cyan-700/60' },
  'web-server': { Icon: Globe,    label: 'Web Server',   color: 'text-emerald-400',bg: 'bg-emerald-950/60',border: 'border-emerald-700/60' },
  database:     { Icon: Database, label: 'Database',     color: 'text-violet-400', bg: 'bg-violet-950/60', border: 'border-violet-700/60' },
  router:       { Icon: Router,   label: 'Router',       color: 'text-amber-400',  bg: 'bg-amber-950/60',  border: 'border-amber-700/60' },
  firewall:     { Icon: Shield,   label: 'Firewall',     color: 'text-orange-400', bg: 'bg-orange-950/60', border: 'border-orange-700/60' },
  attacker:     { Icon: Skull,    label: 'Attacker',     color: 'text-red-400',    bg: 'bg-red-950/60',    border: 'border-red-700/60' },
  'dns-server': { Icon: Wifi,     label: 'DNS Server',   color: 'text-sky-400',    bg: 'bg-sky-950/60',    border: 'border-sky-700/60' },
  'mail-server':{ Icon: Mail,     label: 'Mail Server',  color: 'text-pink-400',   bg: 'bg-pink-950/60',   border: 'border-pink-700/60' },
  ids:          { Icon: Eye,      label: 'Suricata IDS', color: 'text-indigo-400', bg: 'bg-indigo-950/60', border: 'border-indigo-700/60' },
}

const ZONE_RING: Record<string, string> = {
  internal:   'ring-blue-500/40',
  dmz:        'ring-yellow-500/40',
  external:   'ring-red-500/40',
  management: 'ring-purple-500/40',
}

function DeviceNode({ data, selected }: NodeProps) {
  const d = data as unknown as DeviceData & { flashBlocked?: boolean }
  const cfg = DEVICE_CONFIG[d.deviceType] ?? DEVICE_CONFIG.workstation
  const { Icon } = cfg
  const flash = d.flashBlocked === true

  return (
    <div
      className={`
        relative flex flex-col items-center gap-1 px-3 py-2.5 rounded-xl
        border ${flash ? 'border-red-500' : cfg.border} ${cfg.bg}
        ring-2 ${flash ? 'ring-red-500 animate-pulse' : selected ? 'ring-white/40' : ZONE_RING[d.zone] ?? 'ring-transparent'}
        ${selected && !flash ? 'shadow-lg shadow-white/10' : ''}
        ${flash ? 'shadow-lg shadow-red-500/40' : ''}
        min-w-[90px] cursor-pointer select-none
        transition-all duration-150
      `}
      style={{ backdropFilter: 'blur(4px)' }}
    >
      <Handle type="source" position={Position.Top}    id="top-s"    className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="target" position={Position.Top}    id="top-t"    className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="source" position={Position.Bottom} id="bottom-s" className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="target" position={Position.Bottom} id="bottom-t" className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="source" position={Position.Left}   id="left-s"   className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="target" position={Position.Left}   id="left-t"   className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="source" position={Position.Right}  id="right-s"  className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />
      <Handle type="target" position={Position.Right}  id="right-t"  className="!w-2 !h-2 !bg-gray-500 !border-gray-400" />

      <Icon size={24} className={cfg.color} />

      <div className="text-center leading-tight">
        <div className="text-white text-[11px] font-semibold truncate max-w-[100px]">
          {d.label || cfg.label}
        </div>
        {d.ip && (
          <div className="text-gray-400 text-[10px] font-mono">{d.ip}</div>
        )}
      </div>
    </div>
  )
}

export default memo(DeviceNode)
