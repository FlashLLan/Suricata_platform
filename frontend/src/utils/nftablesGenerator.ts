import type { Node, Edge } from '@xyflow/react'
import type { DeviceData } from '../types/lab'

function getData(n: Node): DeviceData {
  return n.data as unknown as DeviceData
}

function parsePorts(ports: string): number[] {
  return ports
    .split(',')
    .map(p => parseInt(p.trim(), 10))
    .filter(p => !isNaN(p) && p > 0)
}

interface ZoneData {
  ips: string[]
  servers: Array<{ label: string; ports: number[] }>
}

const LINE = '─'.repeat(68)
const THICK = '═'.repeat(72)

export function buildNftablesConfig(
  projectName: string,
  nodes: Node[],
  edges: Edge[],
): string {
  const now = new Date().toISOString().slice(0, 10)

  // ── Collect zone data ──────────────────────────────────────────────────────
  const zones: Record<string, ZoneData> = {
    internal:   { ips: [], servers: [] },
    dmz:        { ips: [], servers: [] },
    management: { ips: [], servers: [] },
    external:   { ips: [], servers: [] },
  }

  const firewalls = nodes.filter(
    n => getData(n).deviceType === 'firewall' && getData(n).ip,
  )

  for (const n of nodes) {
    const d = getData(n)
    if (!d.ip) continue
    if (['firewall', 'router', 'attacker'].includes(d.deviceType)) continue
    const zone = d.zone ?? 'internal'
    if (!(zone in zones)) continue
    zones[zone].ips.push(d.ip)
    const ports = parsePorts(d.ports ?? '')
    if (ports.length > 0) zones[zone].servers.push({ label: d.label, ports })
  }

  const hasInternal   = zones.internal.ips.length > 0
  const hasDmz        = zones.dmz.ips.length > 0
  const hasManagement = zones.management.ips.length > 0

  // Determine which zones each firewall bridges via edges
  const nodeMap = new Map(nodes.map(n => [n.id, getData(n)]))
  const fwZones = new Set<string>()
  for (const fw of firewalls) {
    for (const e of edges) {
      const otherId = e.source === fw.id ? e.target
                    : e.target === fw.id ? e.source
                    : null
      if (!otherId) continue
      const other = nodeMap.get(otherId)
      if (other?.zone) fwZones.add(other.zone)
    }
  }

  // ── Firewall header note ───────────────────────────────────────────────────
  let fwNote: string
  if (firewalls.length === 0) {
    fwNote = [
      '# NOTE: No Firewall device was found in your topology.',
      '#       This is a generic zone-based ruleset.',
      '#       Deploy on the host that routes between your network segments.',
    ].join('\n')
  } else if (firewalls.length === 1) {
    const fw = getData(firewalls[0])
    fwNote = [
      `# Firewall device: ${fw.label}  (${fw.ip})`,
      `# Deploy this file on that host:  sudo nft -f <filename>`,
    ].join('\n')
  } else {
    const list = firewalls.map(f => `${getData(f).label} (${getData(f).ip})`).join(', ')
    fwNote = [
      `# Firewall devices: ${list}`,
      `# Deploy on each firewall host as appropriate for your segment.`,
    ].join('\n')
  }

  const L: string[] = []

  // ── File header ────────────────────────────────────────────────────────────
  L.push(`#!/usr/sbin/nft -f`)
  L.push(`# ${THICK}`)
  L.push(`# Suricata Learning Platform — nftables ruleset`)
  L.push(`# Project:   ${projectName}`)
  L.push(`# Generated: ${now}`)
  L.push(`# ${LINE.slice(0, 72)}`)
  L.push(`# Apply:     sudo nft -f <this-file>`)
  L.push(`# Verify:    sudo nft list ruleset`)
  L.push(`# Flush all: sudo nft flush ruleset`)
  L.push(`# ${LINE.slice(0, 72)}`)
  L.push(fwNote)
  L.push(``)
  L.push(`flush ruleset`)
  L.push(``)
  L.push(`table inet filter {`)
  L.push(``)

  // ── Zone address sets ──────────────────────────────────────────────────────
  const namedZones = ['internal', 'dmz', 'management'] as const
  const setName: Record<string, string> = {
    internal:   'INTERNAL',
    dmz:        'DMZ',
    management: 'MANAGEMENT',
  }

  const activeNamedZones = namedZones.filter(z => zones[z].ips.length > 0)

  if (activeNamedZones.length > 0) {
    L.push(`    # ${LINE}`)
    L.push(`    # Zone address sets`)
    L.push(`    # Edit elements to match your real host IPs or CIDR ranges`)
    L.push(`    # ${LINE}`)
    L.push(``)
    for (const zone of activeNamedZones) {
      const ips = zones[zone].ips
      L.push(`    set ${setName[zone]} {`)
      L.push(`        type ipv4_addr`)
      if (ips.length > 1) L.push(`        flags interval`)
      L.push(`        elements = { ${ips.join(', ')} }`)
      L.push(`    }`)
      L.push(``)
    }
  }

  // ── Input chain ────────────────────────────────────────────────────────────
  L.push(`    # ${LINE}`)
  L.push(`    # Input chain — traffic destined for the firewall itself`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain input {`)
  L.push(`        type filter hook input priority filter; policy drop;`)
  L.push(``)
  L.push(`        ct state invalid drop                          # drop invalid packets`)
  L.push(`        ct state { established, related } accept       # allow established sessions`)
  L.push(`        iif "lo" accept                                # allow loopback`)
  L.push(`        icmp type echo-request accept                  # allow ICMP ping`)
  L.push(`        icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept`)
  L.push(``)

  if (hasManagement) {
    L.push(`        # Management zone → firewall: SSH and HTTPS management access`)
    L.push(`        ip saddr @MANAGEMENT tcp dport { 22, 443 } accept`)
  }
  if (hasInternal) {
    L.push(`        # Internal zone → firewall: SSH admin access`)
    L.push(`        ip saddr @INTERNAL tcp dport 22 accept`)
  }

  L.push(``)
  L.push(`        # All other inbound traffic: drop (default policy)`)
  L.push(`    }`)
  L.push(``)

  // ── Forward chain ──────────────────────────────────────────────────────────
  L.push(`    # ${LINE}`)
  L.push(`    # Forward chain — traffic passing through the firewall between zones`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain forward {`)
  L.push(`        type filter hook forward priority filter; policy drop;`)
  L.push(``)
  L.push(`        ct state invalid drop                          # drop invalid packets`)
  L.push(`        ct state { established, related } accept       # allow established sessions`)
  L.push(``)

  if (hasManagement) {
    L.push(`        # Management → anywhere: full administrative access`)
    L.push(`        ip saddr @MANAGEMENT accept`)
    L.push(``)
  }

  if (hasInternal) {
    if (hasDmz) {
      L.push(`        # Internal → DMZ: allow (clients accessing DMZ-hosted services)`)
      L.push(`        ip saddr @INTERNAL ip daddr @DMZ accept`)
      L.push(``)
    }
    L.push(`        # Internal → External: allow outbound (browsing, updates, DNS)`)
    L.push(`        ip saddr @INTERNAL accept`)
    L.push(``)
  }

  if (hasDmz) {
    L.push(`        # DMZ → External: allow (servers pulling package updates, DNS)`)
    L.push(`        ip saddr @DMZ accept`)
    L.push(``)

    // External → DMZ: only specific service ports configured on DMZ devices
    const dmzServers = zones.dmz.servers
    if (dmzServers.length > 0) {
      L.push(`        # External → DMZ: allow only declared service ports`)
      for (const s of dmzServers) {
        const portExpr = s.ports.length === 1
          ? s.ports[0].toString()
          : `{ ${s.ports.join(', ')} }`
        L.push(`        # ${s.label}`)
        L.push(`        ip daddr @DMZ tcp dport ${portExpr} accept`)
      }
      L.push(``)
    } else {
      L.push(`        # External → DMZ: blocked (configure ports on DMZ devices and regenerate)`)
      L.push(``)
    }

    if (hasInternal) {
      L.push(`        # DMZ → Internal: DROP (DMZ servers must never initiate inward)`)
      L.push(`        ip saddr @DMZ ip daddr @INTERNAL drop`)
      L.push(``)
    }
  }

  if (hasManagement) {
    L.push(`        # External → Management: DROP (management must never be internet-reachable)`)
    L.push(`        ip daddr @MANAGEMENT drop`)
    L.push(``)
  }

  L.push(`        # Everything else: DROP (default policy)`)
  L.push(`    }`)
  L.push(``)

  // ── Output chain ───────────────────────────────────────────────────────────
  L.push(`    # ${LINE}`)
  L.push(`    # Output chain — traffic originating from the firewall itself`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain output {`)
  L.push(`        type filter hook output priority filter; policy accept;`)
  L.push(`        # Firewall-originated traffic is fully trusted`)
  L.push(`    }`)
  L.push(``)
  L.push(`}`)
  L.push(``)

  // ── Optional logging block ─────────────────────────────────────────────────
  L.push(`# ${LINE.slice(0, 72)}`)
  L.push(`# Optional: log dropped forward packets for debugging`)
  L.push(`# Uncomment, reload, then: sudo journalctl -k -f | grep "nft drop"`)
  L.push(`# ${LINE.slice(0, 72)}`)
  L.push(``)
  L.push(`# table inet logging {`)
  L.push(`#     chain forward_log {`)
  L.push(`#         type filter hook forward priority filter - 1; policy accept;`)
  L.push(`#         log prefix "nft drop: " drop`)
  L.push(`#     }`)
  L.push(`# }`)

  return L.join('\n')
}
