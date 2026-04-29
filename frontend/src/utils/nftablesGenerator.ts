import type { Node, Edge } from '@xyflow/react'
import type { DeviceData, DynamicBanConfig, FirewallPolicy, FirewallRule, NatRule } from '../types/lab'

function nftSetName(name: string): string {
  return name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')
}

function dynBanMeterLine(db: DynamicBanConfig): string {
  const proto = db.targetProtocol === 'any' ? '' : `${db.targetProtocol} `
  const port  = db.targetPort ? `dport { ${db.targetPort.split(',').map(p => p.trim()).join(', ')} } ` : ''
  const ctNew = db.targetProtocol === 'tcp' ? 'ct state new ' : ''
  return `${proto}${port}${ctNew}meter BAN_METER { ip saddr limit rate over ${db.rateThreshold}/minute burst ${db.rateThreshold} packets } add @BAN_LIST { ip saddr timeout ${db.banDurationSec}s } drop`
}

function getData(n: Node): DeviceData {
  return n.data as unknown as DeviceData
}

function parsePorts(ports: string): number[] {
  return ports
    .split(',')
    .map(p => parseInt(p.trim(), 10))
    .filter(p => !isNaN(p) && p > 0)
}

const LINE  = '-'.repeat(68)
const THICK = '='.repeat(72)

// ── Policy-model path ──────────────────────────────────────────────────────────
// Called when at least one firewall node has a FirewallPolicy configured.

function ruleToNft(rule: FirewallRule): string {
  if (!rule.enabled) return ''

  const parts: string[] = []

  // Source: direct CIDR > IP set > zone
  if (rule.srcCidr?.trim()) {
    const addrs = rule.srcCidr.split(',').map(s => s.trim()).filter(Boolean)
    if (addrs.length === 1) {
      parts.push(`ip saddr ${addrs[0]}`)
    } else {
      parts.push(`ip saddr { ${addrs.join(', ')} }`)
    }
  } else if (rule.srcSet) {
    parts.push(`ip saddr @${nftSetName(rule.srcSet)}`)
  } else if (rule.srcZone !== 'any') {
    const setMap: Record<string, string> = {
      internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
    }
    if (setMap[rule.srcZone]) {
      parts.push(`ip saddr @${setMap[rule.srcZone]}`)
    }
  }

  // Destination: IP set takes precedence over zone
  if (rule.dstSet) {
    parts.push(`ip daddr @${nftSetName(rule.dstSet)}`)
  } else if (rule.dstZone !== 'any') {
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
  // ── Custom IP sets (blocklists, allowlists) ─────────────────────────────────
  const customSets = policy.ipSets ?? []
  if (customSets.length > 0) {
    L.push(`    # ${LINE}`)
    L.push(`    # Custom IP sets (blocklists, allowlists, trusted hosts)`)
    L.push(`    # ${LINE}`)
    L.push(``)
    for (const s of customSets) {
      const sName = nftSetName(s.name)
      const hasCidr = s.elements.some(e => e.includes('/'))
      L.push(`    set ${sName} {`)
      L.push(`        type ipv4_addr`)
      if (hasCidr || s.elements.length > 1) L.push(`        flags interval`)
      if (s.description) L.push(`        # ${s.description}`)
      if (s.elements.length > 0) L.push(`        elements = { ${s.elements.join(', ')} }`)
      L.push(`    }`)
      L.push(``)
    }
  }

  // ── Port-knocking set (if configured) ───────────────────────────────────────
  const pk = policy.portKnocking
  if (pk) {
    L.push(`    # ${LINE}`)
    L.push(`    # Port-knocking client tracking set`)
    L.push(`    # Knock on :${pk.knockPort} to unlock :${pk.targetPort} for ${pk.timeoutSec}s`)
    L.push(`    # ${LINE}`)
    L.push(``)
    L.push(`    set KNOCK_CLIENTS {`)
    L.push(`        type ipv4_addr`)
    L.push(`        flags timeout`)
    L.push(`        timeout ${pk.timeoutSec}s`)
    L.push(`    }`)
    L.push(``)
  }

  // ── Dynamic ban set (if configured) ─────────────────────────────────────────
  const db = policy.dynamicBan
  if (db) {
    const protoLabel = db.targetProtocol === 'any' ? 'any protocol' : db.targetProtocol.toUpperCase()
    const portLabel  = db.targetPort ? `:${db.targetPort}` : '(all ports)'
    L.push(`    # ${LINE}`)
    L.push(`    # Dynamic ban - sources exceeding ${db.rateThreshold} connections/min on ${protoLabel}${portLabel}`)
    L.push(`    #               are banned for ${db.banDurationSec}s`)
    L.push(`    # ${LINE}`)
    L.push(``)
    L.push(`    set BAN_LIST {`)
    L.push(`        type ipv4_addr`)
    L.push(`        flags dynamic, timeout`)
    L.push(`        timeout ${db.banDurationSec}s`)
    L.push(`    }`)
    L.push(``)
  }

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
  // nftables only allows 'accept' or 'drop' as chain default policies.
  // If the user chose 'reject', we use 'drop' as the kernel policy and
  // append an explicit `reject` rule so clients still get ICMP unreachable.
  function emitChain(
    name: string,
    hook: string,
    priority: string,
    defaultPolicy: string,
    preamble: string[],
    rules: FirewallRule[],
    trailerComment: string,
  ) {
    const kernelPolicy = defaultPolicy === 'reject' ? 'drop' : defaultPolicy
    L.push(`    # ${LINE}`)
    L.push(`    # ${name} chain`)
    L.push(`    # ${LINE}`)
    L.push(``)
    L.push(`    chain ${name.toLowerCase()} {`)
    L.push(`        type filter hook ${hook} priority ${priority}; policy ${kernelPolicy};`)
    L.push(``)
    for (const line of preamble) L.push(line)
    const chainRules = rules.filter(r => r.chain === name.toLowerCase() && r.enabled)
    for (const rule of chainRules) {
      const line = ruleToNft(rule)
      if (line) L.push(line)
    }
    L.push(``)
    if (defaultPolicy === 'reject') {
      L.push(`        reject                                         # ${trailerComment}`)
    } else {
      L.push(`        # ${trailerComment} (default policy)`)
    }
    L.push(`    }`)
    L.push(``)
  }

  const ctStateful = policy.ctStateEnabled !== false

  emitChain(
    'input', 'input', 'filter', policy.defaultInput,
    ctStateful ? [
      `        ct state invalid drop                          # drop invalid packets`,
      `        ct state { established, related } accept       # allow established sessions`,
      `        iif "lo" accept                                # allow loopback`,
      `        icmp type echo-request accept                  # allow ICMP ping`,
      ``,
    ] : [
      `        # STATELESS MODE: ct state rules omitted - return traffic hits default policy`,
      `        iif "lo" accept                                # allow loopback`,
      `        icmp type echo-request accept                  # allow ICMP ping`,
      ``,
    ],
    policy.rules,
    policy.defaultInput === 'drop' ? 'All other inbound: drop'
    : policy.defaultInput === 'reject' ? 'All other inbound: reject'
    : 'All other inbound: accept',
  )

  const portKnockPreamble: string[] = pk ? [
    `        # -- Port knocking ------------------------------------------------------------------`,
    `        # Track knock: add source to KNOCK_CLIENTS set, then drop the knock packet`,
    `        tcp dport ${pk.knockPort} add @KNOCK_CLIENTS { ip saddr timeout ${pk.timeoutSec}s } drop`,
    `        # Allow target port only for IPs that completed the knock`,
    `        tcp dport ${pk.targetPort} ip saddr @KNOCK_CLIENTS accept`,
    `        # ----------------------------------------------------------------------------------`,
    ``,
  ] : []

  const dynamicBanPreamble: string[] = db ? [
    `        # -- Dynamic ban --------------------------------------------------------------------`,
    `        ip saddr @BAN_LIST drop                            # drop already-banned sources`,
    `        ${dynBanMeterLine(db)}`,
    `        # ----------------------------------------------------------------------------------`,
    ``,
  ] : []

  emitChain(
    'forward', 'forward', 'filter', policy.defaultForward,
    [
      ...(ctStateful ? [
        `        ct state invalid drop                          # drop invalid packets`,
        `        ct state { established, related } accept       # allow established sessions`,
        ``,
      ] : [
        `        # STATELESS MODE: reply packets from allowed connections are NOT auto-accepted`,
        ``,
      ]),
      ...portKnockPreamble,
      ...dynamicBanPreamble,
    ],
    policy.rules,
    policy.defaultForward === 'drop' ? 'Everything else: DROP'
    : policy.defaultForward === 'reject' ? 'Everything else: REJECT'
    : 'Everything else: ACCEPT',
  )

  L.push(`    # ${LINE}`)
  L.push(`    # output chain`)
  L.push(`    # ${LINE}`)
  L.push(``)
  L.push(`    chain output {`)
  const outKernelPolicy = policy.defaultOutput === 'reject' ? 'drop' : policy.defaultOutput
  L.push(`        type filter hook output priority filter; policy ${outKernelPolicy};`)
  L.push(``)
  const outputRules = policy.rules.filter(r => r.chain === 'output' && r.enabled)
  for (const rule of outputRules) {
    const line = ruleToNft(rule)
    if (line) L.push(line)
  }
  if (policy.defaultOutput === 'reject') {
    L.push(`        reject                                         # all other outbound traffic`)
  } else {
    L.push(`        # Firewall-originated traffic`)
  }
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
    L.push(`    # Zone address sets (inferred from topology - configure firewall policy for precise rules)`)
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
  if (hasManagement) { L.push(`        ip saddr @MANAGEMENT accept                          # management -> anywhere`); L.push(``) }
  if (hasInternal) {
    if (hasDmz) { L.push(`        ip saddr @INTERNAL ip daddr @DMZ accept            # internal -> DMZ`); L.push(``) }
    L.push(`        ip saddr @INTERNAL accept                           # internal -> external`)
    L.push(``)
  }
  if (hasDmz) {
    L.push(`        ip saddr @DMZ accept                                # DMZ -> external`)
    L.push(``)
    const dmzServers = zones.dmz.servers
    if (dmzServers.length > 0) {
      L.push(`        # External -> DMZ: declared service ports only`)
      for (const s of dmzServers) {
        const portExpr = s.ports.length === 1 ? s.ports[0].toString() : `{ ${s.ports.join(', ')} }`
        L.push(`        # ${s.label}`)
        L.push(`        ip daddr @DMZ tcp dport ${portExpr} accept`)
      }
      L.push(``)
    }
    if (hasInternal) { L.push(`        ip saddr @DMZ ip daddr @INTERNAL drop               # DMZ -> internal: BLOCKED`); L.push(``) }
  }
  if (hasManagement) { L.push(`        ip daddr @MANAGEMENT drop                           # external -> management: BLOCKED`); L.push(``) }
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

// ── NAT table generation ───────────────────────────────────────────────────────

function generateNatTable(L: string[], natRules: NatRule[]) {
  const enabled = natRules.filter(r => r.enabled)
  if (enabled.length === 0) return

  const dnatRules = enabled.filter(r => r.type === 'dnat')
  const masqRules = enabled.filter(r => r.type === 'masquerade')

  const setMap: Record<string, string> = {
    internal: 'INTERNAL', dmz: 'DMZ', management: 'MANAGEMENT',
  }

  L.push(`table ip nat {`)
  L.push(``)

  if (dnatRules.length > 0) {
    L.push(`    chain prerouting {`)
    L.push(`        type nat hook prerouting priority dstnat; policy accept;`)
    L.push(``)
    for (const r of dnatRules) {
      const proto = r.protocol ?? 'tcp'
      const rawPorts = (r.extPort ?? '').split(',').map(p => p.trim()).filter(Boolean)
      const portExpr = rawPorts.length === 1 ? rawPorts[0] : rawPorts.length > 1 ? `{ ${rawPorts.join(', ')} }` : 'any'
      const toTarget = r.toAddr ? (r.toPort ? `${r.toAddr}:${r.toPort}` : r.toAddr) : '?'
      const comment = r.description ? `   # ${r.description}` : ''
      L.push(`        ${proto} dport ${portExpr} dnat to ${toTarget}${comment}`)
    }
    L.push(`    }`)
    L.push(``)
  }

  if (masqRules.length > 0) {
    L.push(`    chain postrouting {`)
    L.push(`        type nat hook postrouting priority srcnat; policy accept;`)
    L.push(``)
    for (const r of masqRules) {
      const zone = r.srcZone
      const saddr = zone && zone !== 'any' && zone !== 'external' && setMap[zone]
        ? `ip saddr @${setMap[zone]} `
        : ''
      const comment = r.description ? `   # ${r.description}` : ''
      L.push(`        ${saddr}masquerade${comment}`)
    }
    L.push(`    }`)
    L.push(``)
  }

  L.push(`}`)
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
  rules: { chain: string; description: string; action: string; rateLimit?: { pps: number; burst: number }; srcSet?: string; dstSet?: string; srcZone?: string; dstZone?: string }[]
  ipSetCount: number
  ipSetNames: string[]
  portKnocking?: { knockPort: number; targetPort: number; timeoutSec: number }
  dynamicBan?: { rateThreshold: number; banDurationSec: number; targetPort: string; targetProtocol: string }
  natRuleCount: number
  natRules: { type: string; description: string }[]
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
      ipSetCount: 0,
      ipSetNames: [],
      portKnocking: undefined,
      dynamicBan: undefined,
      natRuleCount: 0,
      natRules: [],
      suricataNote,
    }
  }

  const rules = policy.rules
    .filter(r => r.enabled)
    .map(r => {
      const from  = r.srcSet ? `@${r.srcSet}` : (r.srcZone === 'any' ? 'any' : r.srcZone)
      const to    = r.dstSet ? `@${r.dstSet}` : (r.dstZone === 'any' ? 'any' : r.dstZone)
      const proto = r.protocol === 'any' ? '' : ` ${r.protocol.toUpperCase()}`
      const port  = r.dstPort ? `:${r.dstPort}` : ''
      const desc  = r.description || `${from} -> ${to}${proto}${port}`
      return { chain: r.chain, description: desc, action: r.action, rateLimit: r.rateLimit, srcSet: r.srcSet, dstSet: r.dstSet, srcZone: r.srcZone, dstZone: r.dstZone }
    })

  const ipSets = policy.ipSets ?? []
  const natRules = (policy.natRules ?? []).filter(r => r.enabled)

  return {
    mode: 'policy',
    firewallLabel:   fwData.label || 'Firewall',
    firewallIp:      fwData.ip    || '',
    defaultInput:    policy.defaultInput,
    defaultForward:  policy.defaultForward,
    defaultOutput:   policy.defaultOutput,
    activeRuleCount: rules.length,
    rules,
    ipSetCount:   ipSets.length,
    ipSetNames:   ipSets.map(s => nftSetName(s.name)),
    portKnocking: policy.portKnocking,
    dynamicBan:   policy.dynamicBan,
    natRuleCount: natRules.length,
    natRules:     natRules.map(r => ({ type: r.type, description: r.description })),
    suricataNote,
  }
}

function _policySummaryLines(s: NftablesPolicySummary): string[] {
  const L: string[] = []
  L.push(`# ${LINE}`)
  L.push(`# Policy summary (human-readable)`)
  L.push(`# ${LINE}`)
  L.push(`# Mode     : ${s.mode === 'policy' ? 'Configured via Firewall Policy panel' : 'Zone-inferred - no explicit policy set on firewall node'}`)
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
      const a   = r.action.toUpperCase().padEnd(6)
      const c   = r.chain.padEnd(7)
      const rl  = r.rateLimit ? `  [limit ${r.rateLimit.pps}pps burst ${r.rateLimit.burst}]` : ''
      const src = r.srcSet ? `@${r.srcSet.toUpperCase()}` : (r.srcZone ?? 'any')
      const dst = r.dstSet ? `@${r.dstSet.toUpperCase()}` : (r.dstZone ?? 'any')
      L.push(`#   ${c}  ${a}${rl}  ${src}->${dst}  ${r.description}`)
    }
  } else {
    L.push(`#`)
    L.push(`# No explicit rules - chain default policies apply to all traffic.`)
  }
  if (s.ipSetCount > 0) {
    L.push(`#`)
    L.push(`# Custom IP sets: ${s.ipSetCount} defined (${s.ipSetNames.join(', ')})`)
  }
  if (s.portKnocking) {
    L.push(`#`)
    L.push(`# Port knocking: knock :${s.portKnocking.knockPort} -> unlocks :${s.portKnocking.targetPort} for ${s.portKnocking.timeoutSec}s`)
  }
  if (s.dynamicBan) {
    const db = s.dynamicBan
    const portStr = db.targetPort ? `:${db.targetPort}` : '(all ports)'
    L.push(`#`)
    L.push(`# Dynamic ban: ${db.rateThreshold} conn/min on ${db.targetProtocol.toUpperCase()}${portStr} -> ban for ${db.banDurationSec}s`)
  }
  if (s.natRuleCount > 0) {
    L.push(`#`)
    L.push(`# NAT rules (${s.natRuleCount} active):`)
    for (const r of s.natRules) {
      L.push(`#   ${r.type.padEnd(12)}  ${r.description}`)
    }
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
    `#       before it is filtered - visibility is preserved even for blocked attacks.`,
    `#       Sensors DOWNSTREAM only see forwarded traffic - blocked attacks create a`,
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
        ? `# Policy configured via Firewall Policy panel - ${policy.rules.filter(r => r.enabled).length} active rule(s)`
        : `# NOTE: No policy configured yet - output is zone-inferred. Open the firewall`,
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
        : `# NOTE: No policy configured on any firewall - output is zone-inferred.`,
      `# Deploy on each firewall host as appropriate for your segment.`,
    ].join('\n')
  }

  const L: string[] = []

  // File header
  L.push(`#!/usr/sbin/nft -f`)
  L.push(`# ${'='.repeat(72)}`)
  L.push(`# Suricata Learning Platform -- nftables ruleset`)
  L.push(`# Project:   ${projectName}`)
  L.push(`# Generated: ${now}`)
  L.push(`# ${'-'.repeat(72)}`)
  L.push(`# Apply:     sudo nft -f <this-file>`)
  L.push(`# Verify:    sudo nft list ruleset`)
  L.push(`# Flush all: sudo nft flush ruleset`)
  L.push(`# ${'-'.repeat(72)}`)
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

  // NAT table (DNAT + masquerade) — emitted as a separate table ip nat block
  const natRules = policy?.natRules ?? []
  if (natRules.some(r => r.enabled)) {
    generateNatTable(L, natRules)
  }

  // Optional logging block
  L.push(`# ${'-'.repeat(72)}`)
  L.push(`# Optional: log dropped forward packets for debugging`)
  L.push(`# Uncomment, reload, then: sudo journalctl -k -f | grep "nft drop"`)
  L.push(`# ${'-'.repeat(72)}`)
  L.push(``)
  L.push(`# table inet logging {`)
  L.push(`#     chain forward_log {`)
  L.push(`#         type filter hook forward priority filter - 1; policy accept;`)
  L.push(`#         log prefix "nft drop: " drop`)
  L.push(`#     }`)
  L.push(`# }`)

  for (const line of _deploymentNotesLines(summary.firewallIp)) L.push(line)

  return L.join('\n') + '\n'
}
