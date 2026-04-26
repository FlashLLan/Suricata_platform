import type { Node, Edge } from '@xyflow/react'
import type { DeviceData, FirewallPolicy, FirewallRule } from '../types/lab'

function getData(n: Node): DeviceData {
  return n.data as unknown as DeviceData
}

function parsePorts(ports: string): number[] {
  return ports
    .split(',')
    .map(p => parseInt(p.trim(), 10))
    .filter(p => !isNaN(p) && p > 0)
}

const LINE  = '─'.repeat(68)
const THICK = '═'.repeat(72)

// ── Policy-model path ──────────────────────────────────────────────────────────
// Called when at least one firewall node has a FirewallPolicy configured.

function ruleToNft(rule: FirewallRule): string {
  if (!rule.enabled) return ''

  const parts: string[] = []

  if (rule.srcZone !== 'any') {
    const setMap: Record<string, string> = {
      internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
    }
    if (setMap[rule.srcZone]) {
      parts.push(`ip saddr @${setMap[rule.srcZone]}`)
    }
  }

  if (rule.dstZone !== 'any') {
    const setMap: Record<string, string> = {
      internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
    }
    if (setMap[rule.dstZone]) {
      parts.push(`ip daddr @${setMap[rule.dstZone]}`)
    }
  }

  if (rule.protocol !== 'any') {
    parts.push(rule.protocol)
    if (rule.dstPort && rule.protocol !== 'icmp') {
      const ports = rule.dstPort.split(',').map(p => p.trim()).filter(Boolean)
      if (ports.length === 1) {
        parts.push(`dport ${ports[0]}`)
      } else if (ports.length > 1) {
        parts.push(`dport { ${ports.join(', ')} }`)
      }
    }
  }

  if (rule.rateLimit && rule.action === 'accept') {
    parts.push(`limit rate ${rule.rateLimit.pps}/second burst ${rule.rateLimit.burst} packets`)
  }

  parts.push(rule.action)

  const comment = rule.description ? `   # ${rule.description}` : ''
  return `        ${parts.join(' ')}${comment}`
}

function generateFromPolicy(
  L: string[],
  policy: FirewallPolicy,
  zones: Record<string, { ips: string[] }>,
) {
  // Zone address sets (only for zones referenced in rules or with IPs)
  const referencedZones = new Set<string>()
  for (const r of policy.rules) {
    if (r.srcZone !== 'any' && r.srcZone !== 'external') referencedZones.add(r.srcZone)
    if (r.dstZone !== 'any' && r.dstZone !== 'external') referencedZones.add(r.dstZone)
  }
  ;['internal', 'dmz', 'management'].forEach(z => {
    if (zones[z]?.ips.length > 0) referencedZones.add(z)
  })

  const setName: Record<string, string> = {
    internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
  }

  const activeZones = [...referencedZones].filter(z => zones[z]?.ips.length > 0)
  if (activeZones.length > 0) {
    L.push(`    # ${LINE}`)
    L.push(`    # Zone address sets`)
    L.push(`    # ${LINE}`)
    L.push(``)
    for (const zone of activeZones) {
      const ips = zones[zone].ips
      L.push(`    set ${setName[zone]} {`)
      L.push(`        type ipv4_addr`)
      if (ips.length > 1) L.push(`        flags interval`)
      L.push(`        elements = { ${ips.join(', ')} }`)
      L.push(`    }`)
      L.push(``)
    }
  }

  // Helper: emit a chain
  function emitChain(
    name: string,
    hook: string,
    priority: string,
    defaultPolicy: string,
    preamble: string[],
    rules: FirewallRule[],
    trailerComment: string,
  ) {
    L.push(`    # ${LINE}`)
    L.push(`    # ${name} chain`)
    L.push(`    # ${LINE}`)
    L.push(``)
    L.push(`    chain ${name.toLowerCase()} {`)
    L.push(`        type filter hook ${hook} priority ${priority}; policy ${defaultPolicy};`)
    L.push(``)
    for (const line of preamble) L.push(line)
    const chainRules = rules.filter(r => r.chain === name.toLowerCase() && r.enabled)
    for (const rule of chainRules) {
      const line = ruleToNft(rule)
      if (line) L.push(line)
    }
    L.push(``)
    L.push(`        # ${trailerComment} (default policy)`)
    L.push(`    }`)
    L.push(``)
  }

  emitChain(
    'input', 'input', 'filter', policy.defaultInput,
    [
      `        ct state invalid drop                          # drop invalid packets`,
      `        ct state { established, related } accept       # allow established sessions`,
      `        iif "lo" accept                                # allow loopback`,
      `        icmp type echo-request accept                  # allow ICMP ping`,
      ``,
    ],
    policy.rules,
    policy.defaultInput === 'drop' ? 'All other inbound: drop' : 'All other inbound: accept',
  )

  emitChain(
    'forward', 'forward', 'filter', policy.defaultForward,
    [
      `        ct state invalid drop                          # drop invalid packets`,
      `        ct state { established, related } accept       # allow established sessions`,
      ``,
    ],
    policy.rules,
    policy.defaultForward === 'drop' ? 'Everything else: DROP' : 'Everything else: ACCEPT',
  )

  L.push(`    # ${LINE}`)
  L.push(`    # output chain`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain output {`)
  L.push(`        type filter hook output priority filter; policy ${policy.defaultOutput};`)
  L.push(``)
  const outputRules = policy.rules.filter(r => r.chain === 'output' && r.enabled)
  for (const rule of outputRules) {
    const line = ruleToNft(rule)
    if (line) L.push(line)
  }
  L.push(`        # Firewall-originated traffic`)
  L.push(`    }`)
  L.push(``)
}

// ── Zone-inference path (fallback when no policy is configured) ────────────────

interface ZoneData {
  ips: string[]
  servers: Array<{ label: string; ports: number[] }>
}

function generateFromZones(
  L: string[],
  zones: Record<string, ZoneData>,
) {
  const hasInternal   = zones.internal.ips.length > 0
  const hasDmz        = zones.dmz.ips.length > 0
  const hasManagement = zones.management.ips.length > 0

  const namedZones = ['internal', 'dmz', 'management'] as const
  const setName: Record<string, string> = {
    internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
  }
  const activeNamedZones = namedZones.filter(z => zones[z].ips.length > 0)

  if (activeNamedZones.length > 0) {
    L.push(`    # ${LINE}`)
    L.push(`    # Zone address sets (inferred from topology — configure firewall policy for precise rules)`)
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

  // Input chain
  L.push(`    # ${LINE}`)
  L.push(`    # Input chain`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain input {`)
  L.push(`        type filter hook input priority filter; policy drop;`)
  L.push(``)
  L.push(`        ct state invalid drop`)
  L.push(`        ct state { established, related } accept`)
  L.push(`        iif "lo" accept`)
  L.push(`        icmp type echo-request accept`)
  L.push(``)
  if (hasManagement) L.push(`        ip saddr @MANAGEMENT tcp dport { 22, 443 } accept   # management access`)
  if (hasInternal)   L.push(`        ip saddr @INTERNAL   tcp dport 22 accept             # internal SSH`)
  L.push(`    }`)
  L.push(``)

  // Forward chain
  L.push(`    # ${LINE}`)
  L.push(`    # Forward chain`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain forward {`)
  L.push(`        type filter hook forward priority filter; policy drop;`)
  L.push(``)
  L.push(`        ct state invalid drop`)
  L.push(`        ct state { established, related } accept`)
  L.push(``)
  if (hasManagement) { L.push(`        ip saddr @MANAGEMENT accept                          # management → anywhere`); L.push(``) }
  if (hasInternal) {
    if (hasDmz) { L.push(`        ip saddr @INTERNAL ip daddr @DMZ accept            # internal → DMZ`); L.push(``) }
    L.push(`        ip saddr @INTERNAL accept                           # internal → external`)
    L.push(``)
  }
  if (hasDmz) {
    L.push(`        ip saddr @DMZ accept                                # DMZ → external`)
    L.push(``)
    const dmzServers = zones.dmz.servers
    if (dmzServers.length > 0) {
      L.push(`        # External → DMZ: declared service ports only`)
      for (const s of dmzServers) {
        const portExpr = s.ports.length === 1 ? s.ports[0].toString() : `{ ${s.ports.join(', ')} }`
        L.push(`        # ${s.label}`)
        L.push(`        ip daddr @DMZ tcp dport ${portExpr} accept`)
      }
      L.push(``)
    }
    if (hasInternal) { L.push(`        ip saddr @DMZ ip daddr @INTERNAL drop               # DMZ → internal: BLOCKED`); L.push(``) }
  }
  if (hasManagement) { L.push(`        ip daddr @MANAGEMENT drop                           # external → management: BLOCKED`); L.push(``) }
  L.push(`        # Everything else: DROP`)
  L.push(`    }`)
  L.push(``)

  // Output chain
  L.push(`    # ${LINE}`)
  L.push(`    # Output chain`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain output {`)
  L.push(`        type filter hook output priority filter; policy accept;`)
  L.push(`        # Firewall-originated traffic is fully trusted`)
  L.push(`    }`)
  L.push(``)
}

// ── Policy summary (exported for UI) ──────────────────────────────────────────

export interface NftablesPolicySummary {
  mode: 'policy' | 'inferred'
  firewallLabel: string
  firewallIp: string
  defaultInput: string
  defaultForward: string
  defaultOutput: string
  activeRuleCount: number
  rules: { chain: string; description: string; action: string; rateLimit?: { pps: number; burst: number } }[]
  suricataNote: string
}

export function buildNftablesPolicySummary(nodes: Node[]): NftablesPolicySummary {
  const firewall = nodes.find(n => getData(n).deviceType === 'firewall')
  const fwData   = firewall ? getData(firewall) : null
  const policy   = fwData?.firewallPolicy ?? null

  const idsNodes = nodes.filter(n => getData(n).deviceType === 'ids')
  const suricataNote = idsNodes.length === 0
    ? 'No IDS sensors in topology — traffic blocked here will not be logged by Suricata.'
    : `${idsNodes.length} IDS sensor(s): ${idsNodes.map(n => getData(n).label).join(', ')}. ` +
      `Sensors upstream of this firewall still observe blocked traffic; downstream sensors do not.`

  if (!policy) {
    return {
      mode: 'inferred',
      firewallLabel: fwData?.label ?? '(none)',
      firewallIp:    fwData?.ip   ?? '',
      defaultInput:   'drop',
      defaultForward: 'drop',
      defaultOutput:  'accept',
      activeRuleCount: 0,
      rules: [],
      suricataNote,
    }
  }

  const rules = policy.rules
    .filter(r => r.enabled)
    .map(r => {
      const from  = r.srcZone === 'any' ? 'any' : r.srcZone
      const to    = r.dstZone === 'any' ? 'any' : r.dstZone
      const proto = r.protocol === 'any' ? '' : ` ${r.protocol.toUpperCase()}`
      const port  = r.dstPort ? `:${r.dstPort}` : ''
      const desc  = r.description || `${from} → ${to}${proto}${port}`
      return { chain: r.chain, description: desc, action: r.action, rateLimit: r.rateLimit }
    })

  return {
    mode: 'policy',
    firewallLabel:   fwData.label || 'Firewall',
    firewallIp:      fwData.ip    || '',
    defaultInput:    policy.defaultInput,
    defaultForward:  policy.defaultForward,
    defaultOutput:   policy.defaultOutput,
    activeRuleCount: rules.length,
    rules,
    suricataNote,
  }
}

function _policySummaryLines(s: NftablesPolicySummary): string[] {
  const L: string[] = []
  L.push(`# ${LINE}`)
  L.push(`# Policy summary (human-readable)`)
  L.push(`# ${LINE}`)
  L.push(`# Mode     : ${s.mode === 'policy' ? 'Configured via Firewall Policy panel' : 'Zone-inferred — no explicit policy set on firewall node'}`)
  L.push(`# Firewall : ${s.firewallLabel}${s.firewallIp ? '  (' + s.firewallIp + ')' : ''}`)
  L.push(`#`)
  L.push(`# Chain defaults:`)
  L.push(`#   input   : ${s.defaultInput}`)
  L.push(`#   forward : ${s.defaultForward}`)
  L.push(`#   output  : ${s.defaultOutput}`)
  if (s.rules.length > 0) {
    L.push(`#`)
    L.push(`# Explicit rules (${s.activeRuleCount} enabled):`)
    for (const r of s.rules) {
      const a  = r.action.toUpperCase().padEnd(6)
      const c  = r.chain.padEnd(7)
      const rl = r.rateLimit ? `  [limit ${r.rateLimit.pps}pps burst ${r.rateLimit.burst}]` : ''
      L.push(`#   ${c}  ${a}${rl}  ${r.description}`)
    }
  } else {
    L.push(`#`)
    L.push(`# No explicit rules — chain default policies apply to all traffic.`)
  }
  L.push(`# ${LINE}`)
  L.push(``)
  return L
}

function _deploymentNotesLines(fwIp: string): string[] {
  return [
    ``,
    `# ${LINE}`,
    `# Deployment notes`,
    `# ${LINE}`,
    `# 1. Dry-run (validate syntax, do NOT load):`,
    `#       sudo nft -c -f <this-file>`,
    `#`,
    `# 2. Apply:`,
    `#       sudo nft -f <this-file>`,
    `#`,
    `# 3. Verify loaded ruleset:`,
    `#       sudo nft list ruleset`,
    `#`,
    `# 4. Emergency revert (flush all nftables rules):`,
    `#       sudo nft flush ruleset`,
    `#`,
    `# 5. Persist across reboots (systemd-based distros):`,
    `#       sudo cp <this-file> /etc/nftables.conf`,
    `#       sudo systemctl enable nftables && sudo systemctl start nftables`,
    `#`,
    `# 6. Suricata + nftables placement:`,
    `#       IDS sensors UPSTREAM of this firewall (${fwIp || 'this host'}) see all traffic`,
    `#       before it is filtered — visibility is preserved even for blocked attacks.`,
    `#       Sensors DOWNSTREAM only see forwarded traffic — blocked attacks create a`,
    `#       detection blind spot. Ideal: run Suricata on the firewall host itself,`,
    `#       using AF_PACKET before the nftables FORWARD hook fires.`,
    `# ${LINE}`,
  ]
}

// ── Public entry point ─────────────────────────────────────────────────────────

export function buildNftablesConfig(
  projectName: string,
  nodes: Node[],
  edges: Edge[],
): string {
  void edges  // retained for future zone-connectivity detection
  const now = new Date().toISOString().slice(0, 10)

  const firewalls = nodes.filter(
    n => getData(n).deviceType === 'firewall' && getData(n).ip,
  )

  // Find the first firewall with a configured policy
  const configuredFw = firewalls.find(n => getData(n).firewallPolicy != null)
  const policy: FirewallPolicy | undefined = configuredFw
    ? getData(configuredFw).firewallPolicy
    : undefined

  // Collect zone data (used by both paths)
  const zones: Record<string, ZoneData> = {
    internal: { ips: [], servers: [] }, dmz: { ips: [], servers: [] },
    management: { ips: [], servers: [] }, external: { ips: [], servers: [] },
  }
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

  // ── Firewall header note ──────────────────────────────────────────────────
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
      policy
        ? `# Policy configured via Firewall Policy panel — ${policy.rules.filter(r => r.enabled).length} active rule(s)`
        : `# NOTE: No policy configured yet — output is zone-inferred. Open the firewall`,
      policy
        ? `# Apply this file on that host:  sudo nft -f <filename>`
        : `#       node in the canvas, open "Firewall Policy", configure rules, then re-export.`,
    ].join('\n')
  } else {
    const list = firewalls.map(f => `${getData(f).label} (${getData(f).ip})`).join(', ')
    fwNote = [
      `# Firewall devices: ${list}`,
      configuredFw
        ? `# Using policy from: ${getData(configuredFw).label}`
        : `# NOTE: No policy configured on any firewall — output is zone-inferred.`,
      `# Deploy on each firewall host as appropriate for your segment.`,
    ].join('\n')
  }

  const L: string[] = []

  // File header
  L.push(`#!/usr/sbin/nft -f`)
  L.push(`# ${'═'.repeat(72)}`)
  L.push(`# Suricata Learning Platform — nftables ruleset`)
  L.push(`# Project:   ${projectName}`)
  L.push(`# Generated: ${now}`)
  L.push(`# ${'─'.repeat(72)}`)
  L.push(`# Apply:     sudo nft -f <this-file>`)
  L.push(`# Verify:    sudo nft list ruleset`)
  L.push(`# Flush all: sudo nft flush ruleset`)
  L.push(`# ${'─'.repeat(72)}`)
  L.push(fwNote)
  L.push(``)
  const summary = buildNftablesPolicySummary(nodes)
  for (const line of _policySummaryLines(summary)) L.push(line)
  L.push(`flush ruleset`)
  L.push(``)
  L.push(`table inet filter {`)
  L.push(``)

  if (policy) {
    generateFromPolicy(L, policy, zones)
  } else {
    generateFromZones(L, zones)
  }

  L.push(`}`)
  L.push(``)

  // Optional logging block
  L.push(`# ${'─'.repeat(72)}`)
  L.push(`# Optional: log dropped forward packets for debugging`)
  L.push(`# Uncomment, reload, then: sudo journalctl -k -f | grep "nft drop"`)
  L.push(`# ${'─'.repeat(72)}`)
  L.push(``)
  L.push(`# table inet logging {`)
  L.push(`#     chain forward_log {`)
  L.push(`#         type filter hook forward priority filter - 1; policy accept;`)
  L.push(`#         log prefix "nft drop: " drop`)
  L.push(`#     }`)
  L.push(`# }`)

  for (const line of _deploymentNotesLines(summary.firewallIp)) L.push(line)

  return L.join('\n')
}
