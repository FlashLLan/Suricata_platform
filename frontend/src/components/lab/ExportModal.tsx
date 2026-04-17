import { useState } from 'react'
import {
  X, Download, Copy, Check, FileText, Settings, Terminal,
  ChevronRight, ChevronLeft, Server, Network, Shield, Monitor,
} from 'lucide-react'
import type { Node } from '@xyflow/react'
import type { ActiveRule, DeviceData } from '../../types/lab'

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  projectName: string
  activeRules: ActiveRule[]
  nodes: Node[]
  onClose: () => void
}

// ─── Environment setup (questionnaire answers) ────────────────────────────────

interface EnvSetup {
  os: 'ubuntu' | 'rhel' | 'other'
  suricataVersion: '6' | '7' | 'other'
  deployMode: 'ids' | 'ips'
  envType: 'test' | 'production'
  interfaces: string       // comma-separated, e.g. "eth0" or "eth0,eth1"
  homeNetOverride: string  // blank = auto from topology
  logDir: string
  monitoredSegment: string
}

const DEFAULT_SETUP: EnvSetup = {
  os: 'ubuntu',
  suricataVersion: '7',
  deployMode: 'ids',
  envType: 'test',
  interfaces: 'eth0',
  homeNetOverride: '',
  logDir: '/var/log/suricata',
  monitoredSegment: '',
}

type ExportTab = 'rules' | 'yaml' | 'inventory' | 'guide'

// ─── Topology helpers ─────────────────────────────────────────────────────────

function getDeviceData(n: Node): DeviceData {
  return n.data as unknown as DeviceData
}

function getHomeIPs(nodes: Node[]): string[] {
  return nodes
    .map(getDeviceData)
    .filter(d => d.ip && ['internal', 'dmz', 'management'].includes(d.zone))
    .map(d => d.ip)
}

function resolveHomeNet(nodes: Node[], override: string): string {
  if (override.trim()) return override.trim()
  const ips = getHomeIPs(nodes)
  if (ips.length === 0) return '192.168.0.0/16'
  if (ips.length === 1) return ips[0]
  return `[${ips.join(',')}]`
}

/** Guess the default gateway from a host IP — assumes .1 of the same /24. */
function guessGateway(ip: string): string {
  const parts = ip.split('.')
  if (parts.length !== 4) return '192.168.1.1'
  return `${parts[0]}.${parts[1]}.${parts[2]}.1`
}

/** Return "/24", "/16" etc. from a subnet field that may be a CIDR network or a netmask. */
function toCidrPrefix(subnet: string): string {
  if (!subnet) return '/24'
  if (subnet.includes('/')) return '/' + subnet.split('/')[1]
  const maskMap: Record<string, string> = {
    '255.255.255.0': '/24', '255.255.0.0': '/16', '255.0.0.0': '/8',
    '255.255.255.128': '/25', '255.255.255.192': '/26', '255.255.255.224': '/27',
  }
  return maskMap[subnet] ?? '/24'
}

/** Build per-device OS-specific network interface config snippets. */
function buildInterfaceConfigs(nodes: Node[], os: EnvSetup['os']): string {
  const devs = nodes
    .map(getDeviceData)
    .filter(d => d.ip && d.label && !['attacker', 'ids'].includes(d.deviceType))

  if (devs.length === 0) return '# No devices with IP addresses configured in the topology.'

  const lines: string[] = [
    `# ── How to read this section ────────────────────────────────────────────────`,
    `# Each block shows how to statically assign the IP from your canvas topology`,
    `# to a real network interface on the host.`,
    `# Replace "eth0" with your actual interface name.`,
    `# Find your interfaces: ip link show   or   ls /sys/class/net/`,
    ``,
  ]

  for (const d of devs) {
    const ip     = d.ip
    const prefix = toCidrPrefix(d.subnet)
    const gw     = guessGateway(ip)
    const iface  = 'eth0'
    const title  = `${d.label} · ${DEVICE_ROLE_LABEL[d.deviceType] ?? d.deviceType} · ${d.zone} zone`

    lines.push(`# ${'─'.repeat(70)}`)
    lines.push(`# ${title}`)
    lines.push(`# IP: ${ip}${prefix}   gateway: ${gw}`)
    lines.push(`# ${'─'.repeat(70)}`)
    lines.push('')

    if (os === 'ubuntu') {
      lines.push(`## Option A — Netplan  (Ubuntu 18.04+ / Debian 10+)`)
      lines.push(`## File: /etc/netplan/01-netcfg.yaml`)
      lines.push(`network:`)
      lines.push(`  version: 2`)
      lines.push(`  ethernets:`)
      lines.push(`    ${iface}:`)
      lines.push(`      addresses:`)
      lines.push(`        - ${ip}${prefix}`)
      lines.push(`      routes:`)
      lines.push(`        - to: default`)
      lines.push(`          via: ${gw}`)
      lines.push(`      nameservers:`)
      lines.push(`        addresses: [8.8.8.8, 1.1.1.1]`)
      lines.push(`## Apply:  sudo netplan apply`)
      lines.push('')
      lines.push(`## Option B — Legacy  (/etc/network/interfaces)`)
      lines.push(`auto ${iface}`)
      lines.push(`iface ${iface} inet static`)
      lines.push(`    address    ${ip}`)
      lines.push(`    netmask    255.255.255.0`)
      lines.push(`    gateway    ${gw}`)
      lines.push(`    dns-nameservers 8.8.8.8`)
      lines.push(`## Apply:  sudo ifdown ${iface} && sudo ifup ${iface}`)
    } else if (os === 'rhel') {
      lines.push(`## Option A — NetworkManager / nmcli  (RHEL 8+ / Fedora)`)
      lines.push(`nmcli con mod "${iface}" ipv4.addresses ${ip}${prefix}`)
      lines.push(`nmcli con mod "${iface}" ipv4.gateway   ${gw}`)
      lines.push(`nmcli con mod "${iface}" ipv4.dns       "8.8.8.8 1.1.1.1"`)
      lines.push(`nmcli con mod "${iface}" ipv4.method    manual`)
      lines.push(`nmcli con up  "${iface}"`)
      lines.push(`## Verify:  ip addr show ${iface}`)
      lines.push('')
      lines.push(`## Option B — Legacy ifcfg  (/etc/sysconfig/network-scripts/ifcfg-${iface})`)
      lines.push(`DEVICE=${iface}`)
      lines.push(`BOOTPROTO=static`)
      lines.push(`ONBOOT=yes`)
      lines.push(`IPADDR=${ip}`)
      lines.push(`PREFIX=${prefix.slice(1)}`)
      lines.push(`GATEWAY=${gw}`)
      lines.push(`DNS1=8.8.8.8`)
      lines.push(`## Apply:  sudo nmcli con reload`)
    } else {
      lines.push(`# Generic — adapt to your distribution`)
      lines.push(`# Assign: ${ip}${prefix}   gateway: ${gw}`)
      lines.push(`# ip addr add ${ip}${prefix} dev ${iface}`)
      lines.push(`# ip route add default via ${gw}`)
      lines.push(`# For persistence, see your distro's network configuration docs.`)
    }

    lines.push('')
    lines.push('')
  }

  return lines.join('\n')
}

// ─── Content generators ───────────────────────────────────────────────────────

function buildRulesFile(
  projectName: string,
  activeRules: ActiveRule[],
  nodes: Node[],
  setup: EnvSetup,
): string {
  const date     = new Date().toISOString().slice(0, 10)
  const homeNet  = resolveHomeNet(nodes, setup.homeNetOverride)
  const devSummary = nodes
    .map(getDeviceData)
    .filter(d => d.ip && d.label)
    .map(d => `${d.label} (${d.ip})`)
    .join(', ')

  const lines: string[] = [
    `# ══════════════════════════════════════════════════════════════════════════════`,
    `#  Suricata Rules — exported from Suricata Learning Platform`,
    `# ══════════════════════════════════════════════════════════════════════════════`,
    `#  Project   : ${projectName}`,
    `#  Generated : ${date}`,
    `#  Rules     : ${activeRules.length}`,
    `#  Mode      : ${setup.deployMode.toUpperCase()} (${setup.deployMode === 'ids' ? 'detection only' : 'inline blocking'})`,
    `#  Env type  : ${setup.envType}`,
    `#`,
    devSummary ? `#  Devices   : ${devSummary}` : `#  Devices   : (none configured)`,
    `#  HOME_NET  : ${homeNet}`,
    `#`,
    `#  Deployment: drop into /etc/suricata/rules/ and add to rule-files: in suricata.yaml`,
    `# ══════════════════════════════════════════════════════════════════════════════`,
    ``,
  ]

  if (activeRules.length === 0) {
    lines.push('# No rules are currently active — add rules from the Rule Library first.')
  } else {
    for (const ar of activeRules) {
      lines.push(ar.customText ?? ar.entry.rule)
    }
  }

  lines.push('')
  return lines.join('\n')
}

function buildYaml(nodes: Node[], setup: EnvSetup): string {
  const homeNet   = resolveHomeNet(nodes, setup.homeNetOverride)
  const devs      = nodes.map(getDeviceData)
  const date      = new Date().toISOString().slice(0, 10)
  const ifaces    = setup.interfaces.split(',').map(s => s.trim()).filter(Boolean)
  const isIps     = setup.deployMode === 'ips'
  const logDir    = setup.logDir || '/var/log/suricata'

  const fmt = (ips: string[], fallback: string) =>
    ips.length === 0 ? fallback
    : ips.length === 1 ? `"${ips[0]}"`
    : `"[${ips.join(',')}]"`

  const httpServerIPs = devs.filter(d => d.ip && ['web-server', 'server'].includes(d.deviceType) && ['internal', 'dmz'].includes(d.zone)).map(d => d.ip)
  const dnsServerIPs  = devs.filter(d => d.ip && d.deviceType === 'dns-server').map(d => d.ip)
  const smtpServerIPs = devs.filter(d => d.ip && d.deviceType === 'mail-server').map(d => d.ip)
  const sqlServerIPs  = devs.filter(d => d.ip && d.deviceType === 'database').map(d => d.ip)

  const httpPortSet = new Set<string>()
  for (const d of devs) {
    if (['web-server', 'server'].includes(d.deviceType) && d.ports) {
      for (const p of d.ports.split(',')) {
        if (['80', '443', '8080', '8443', '3000', '5000'].includes(p.trim())) httpPortSet.add(p.trim())
      }
    }
  }
  const httpPorts = httpPortSet.size > 1 ? `"[${[...httpPortSet].join(',')}]"` : httpPortSet.size === 1 ? `"${[...httpPortSet][0]}"` : '"80"'

  const ifaceBlock = ifaces
    .map(iface => [
      `  - interface: ${iface}`,
      `    cluster-id: 99`,
      `    cluster-type: cluster_flow`,
      `    defrag: yes`,
      `    use-mmap: yes`,
      `    tpacket-v3: yes`,
      isIps ? `    copy-mode: ips\n    copy-iface: ${iface}` : '',
    ].filter(Boolean).join('\n'))
    .join('\n\n')

  const isUbuntu = setup.os === 'ubuntu'
  const isRhel   = setup.os === 'rhel'
  const isProd   = setup.envType === 'production'

  // OS-specific default rule path (where the package installs bundled rules)
  const rulePath = isUbuntu ? '/var/lib/suricata/rules'
    : isRhel ? '/usr/share/suricata/rules'
    : '/etc/suricata/rules'

  const lines: string[] = [
    `# ══════════════════════════════════════════════════════════════════════════════`,
    `#  suricata.yaml — generated vars + interface block`,
    `#  Generated: ${date}`,
    `#  OS       : ${isUbuntu ? 'Ubuntu/Debian' : isRhel ? 'RHEL/CentOS/Fedora' : 'Other Linux'}`,
    `#  Suricata : ${setup.suricataVersion}.x`,
    `#  Mode     : ${isIps ? 'IPS (inline blocking via copy-mode)' : 'IDS (passive detection only)'}`,
    `#  Env      : ${isProd ? 'Production' : 'Test / Lab'}`,
    `# ══════════════════════════════════════════════════════════════════════════════`,
    ``,
    `# ── Interface capture ─────────────────────────────────────────────────────────`,
    `af-packet:`,
    ifaceBlock,
    ``,
    `# ── Address / port variables ──────────────────────────────────────────────────`,
    `vars:`,
    `  address-groups:`,
    `    HOME_NET: "${homeNet}"`,
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
    ``,
    `# ── Logging ───────────────────────────────────────────────────────────────────`,
    `default-log-dir: ${logDir}/`,
    ``,
    `outputs:`,
    `  - fast:`,
    `      enabled: yes`,
    `      filename: fast.log`,
    `      append: yes`,
    `  - eve-log:`,
    `      enabled: yes`,
    `      type: file`,
    `      filename: eve.json`,
    `      types:`,
    `        - alert`,
    `        - flow`,
    `        - stats`,
    `        - http`,
    `        - dns`,
    ``,
    `# ── Rules ─────────────────────────────────────────────────────────────────────`,
    `# Bundled community rules live here (installed by the package):`,
    `default-rule-path: ${rulePath}`,
    `rule-files:`,
    `  - suricata.rules`,
    `  - local.rules    # your exported custom rules`,
  ]

  if (!isProd) {
    lines.push(
      ``,
      `# ── Test / Lab settings ──────────────────────────────────────────────────────`,
      `# VMs and virtual NICs often skip checksum computation — disable validation:`,
      `stream:`,
      `  checksum-validation: no   # set to "yes" in production`,
      ``,
      `# Quick test tip: capture on all interfaces at once (no yaml edit needed):`,
      `#   sudo suricata -c /etc/suricata/suricata.yaml -i any`,
      `# VirtualBox / VMware: enable promiscuous mode on the NIC in VM settings`,
      `# so Suricata can see traffic not addressed to the host MAC.`,
    )
  }

  if (isProd) {
    lines.push(
      ``,
      `# ── Production — stream / memory tuning ─────────────────────────────────────`,
      `stream:`,
      `  memcap: 64mb`,
      `  checksum-validation: yes`,
      `  inline: ${isIps ? 'yes' : 'no'}`,
      `  reassembly:`,
      `    memcap: 256mb`,
      `    depth: 1mb`,
      ``,
      `# ── Production — threading ───────────────────────────────────────────────────`,
      `threading:`,
      `  set-cpu-affinity: no   # set "yes" and pin threads on dedicated hardware`,
      `  detect-thread-ratio: 1.0`,
      ``,
      `# ── Production — stats ───────────────────────────────────────────────────────`,
      `stats:`,
      `  enabled: yes`,
      `  interval: 8    # write stats to eve.json every 8 seconds`,
      ``,
      `# ── Production — packet buffer ───────────────────────────────────────────────`,
      `max-pending-packets: 1024   # increase if you see packet drops`,
    )
  }

  if (isIps) {
    lines.push(
      ``,
      `# ── IPS mode via NFQUEUE (alternative to af-packet copy-mode) ───────────────`,
      `# Uncomment if using NFQUEUE instead:`,
      `# nfq:`,
      `#   mode: accept`,
      `#   fail-open: yes   # allow traffic on Suricata crash`,
      ``,
      `# Then route traffic into Suricata via iptables (see Deployment Guide tab):`,
      `# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0`,
    )
  }

  return lines.join('\n')
}

const DEVICE_ROLE_LABEL: Record<string, string> = {
  workstation: 'Workstation',
  server: 'Server',
  'web-server': 'Web Server',
  database: 'Database',
  router: 'Router',
  firewall: 'Firewall',
  attacker: 'Attacker',
  'dns-server': 'DNS Server',
  'mail-server': 'Mail Server',
  ids: 'IDS / Suricata',
}

function buildInventoryText(
  projectName: string,
  nodes: Node[],
  setup: EnvSetup,
): string {
  const date  = new Date().toISOString().slice(0, 10)
  const devs  = nodes.map(getDeviceData).filter(d => d.label)

  const col = (s: string, w: number) => s.padEnd(w).slice(0, w)

  const W = { label: 18, role: 14, zone: 10, ip: 16, subnet: 18, ports: 14, os: 18 }
  const sep = `${'-'.repeat(W.label + 2)}${'-'.repeat(W.role + 2)}${'-'.repeat(W.zone + 2)}${'-'.repeat(W.ip + 2)}${'-'.repeat(W.subnet + 2)}${'-'.repeat(W.ports + 2)}${'-'.repeat(W.os)}`
  const header = `${col('Device', W.label)}  ${col('Role', W.role)}  ${col('Zone', W.zone)}  ${col('IP Address', W.ip)}  ${col('Subnet', W.subnet)}  ${col('Ports', W.ports)}  ${col('OS', W.os)}`

  const rows = devs.map(d => (
    `${col(d.label, W.label)}  ${col(DEVICE_ROLE_LABEL[d.deviceType] ?? d.deviceType, W.role)}  ${col(d.zone, W.zone)}  ${col(d.ip || '—', W.ip)}  ${col(d.subnet || '—', W.subnet)}  ${col(d.ports || '—', W.ports)}  ${col(d.os || '—', W.os)}`
  ))

  // Zone summaries
  const zones: Record<string, string[]> = {}
  for (const d of devs) {
    if (d.ip) {
      if (!zones[d.zone]) zones[d.zone] = []
      zones[d.zone].push(`${d.ip} (${d.label})`)
    }
  }
  const zoneLines = Object.entries(zones).map(([z, ips]) => `  ${z.padEnd(12)}: ${ips.join(', ')}`)

  const homeNet = resolveHomeNet(nodes, setup.homeNetOverride)
  const segment = setup.monitoredSegment ? `Monitored Segment: ${setup.monitoredSegment}` : ''

  const ifaceConfigs = buildInterfaceConfigs(nodes, setup.os)

  return [
    `Network Inventory`,
    `${'='.repeat(80)}`,
    `Project   : ${projectName}`,
    `Generated : ${date}`,
    segment,
    ``,
    `DEVICES`,
    `${'─'.repeat(80)}`,
    header,
    sep,
    ...rows,
    ``,
    `NETWORK ZONES`,
    `${'─'.repeat(80)}`,
    ...zoneLines.length ? zoneLines : ['  (no IPs configured)'],
    ``,
    `SURICATA VARIABLES`,
    `${'─'.repeat(80)}`,
    `  HOME_NET    : ${homeNet}`,
    `  EXTERNAL_NET: !$HOME_NET`,
    ``,
    ``,
    `INTERFACE CONFIGURATION`,
    `${'='.repeat(80)}`,
    `How to assign each device's IP address to a real network interface.`,
    `OS: ${setup.os === 'ubuntu' ? 'Ubuntu/Debian' : setup.os === 'rhel' ? 'RHEL/CentOS/Fedora' : 'Other Linux'}`,
    ``,
    ifaceConfigs,
  ].filter(l => l !== undefined).join('\n')
}

function buildDeploymentGuide(setup: EnvSetup): string {
  const isUbuntu  = setup.os === 'ubuntu'
  const isRhel    = setup.os === 'rhel'
  const isIps     = setup.deployMode === 'ips'
  const isProd    = setup.envType === 'production'
  const iface     = setup.interfaces.split(',')[0].trim() || 'eth0'
  const logDir    = setup.logDir || '/var/log/suricata'
  const ver       = setup.suricataVersion

  const install = isUbuntu
    ? `# Install Suricata ${ver}.x on Ubuntu/Debian
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y`
    : isRhel
    ? `# Install Suricata ${ver}.x on RHEL/CentOS/Fedora
sudo dnf install epel-release -y
sudo dnf install suricata -y`
    : `# Install Suricata — see https://suricata.io/download/`

  // OS-specific rule path (mirrors what buildYaml uses)
  const rulePath = isUbuntu ? '/var/lib/suricata/rules'
    : isRhel ? '/usr/share/suricata/rules'
    : '/etc/suricata/rules'

  const systemdDefault = isUbuntu
    ? `# Ubuntu/Debian: edit /etc/default/suricata to set IFACE=${iface}, then:
sudo systemctl enable suricata
sudo systemctl start suricata`
    : isRhel
    ? `# RHEL/Fedora: edit /etc/sysconfig/suricata to set OPTIONS="-i ${iface}", then:
sudo systemctl enable suricata
sudo systemctl start suricata`
    : `sudo systemctl enable suricata && sudo systemctl start suricata`

  const ipsNote = isIps ? `
# ── IPS: route traffic into Suricata ─────────────────────────────────────────
# Option A — NFQUEUE (simplest, single-NIC):
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo iptables -I INPUT   -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0
# Persist across reboots: sudo netfilter-persistent save   (Ubuntu)
#                      or: sudo iptables-save > /etc/sysconfig/iptables   (RHEL)

# Option B — af-packet copy-mode (two NICs, bridge):
# Requires separate in/out interfaces. See the YAML tab af-packet section.` : ''

  const testNote = !isProd ? `
# ── Test / Lab tips ───────────────────────────────────────────────────────────
# Capture on ALL interfaces at once (good for quick testing):
sudo suricata -c /etc/suricata/suricata.yaml -i any

# VirtualBox / VMware: in VM network settings, set NIC adapter to
# "Promiscuous Mode: Allow All" so Suricata sees traffic between VMs.

# Checksums: virtual NICs often omit checksums — if alerts are missing, add to yaml:
#   stream:
#     checksum-validation: no

# Generate test traffic to trigger your rules (on another terminal):
curl http://${`<target-ip>`}       # HTTP brute-force / SQLi rules
ssh admin@${`<target-ip>`}        # SSH brute-force rules
ping ${`<target-ip>`}             # ICMP rules` : ''

  const prodChecklist = isProd ? `
# ── Production checklist ──────────────────────────────────────────────────────
# Before going live:
# [ ] Run suricata -T to confirm clean config
# [ ] Review each rule for false positive risk (threshold tuning if needed)
# [ ] Enable logrotate for fast.log and eve.json
#       sudo nano /etc/logrotate.d/suricata
#       /var/log/suricata/*.log { daily rotate 14 compress missingok postrotate
#           kill -HUP $(pidof suricata) endscript }
# [ ] Set up alerting: ship eve.json via Filebeat → Elasticsearch / SIEM
# [ ] Schedule daily rule updates:
#       sudo crontab -e
#       0 3 * * * /usr/bin/suricata-update && kill -USR2 $(pidof suricata)
# [ ] Monitor for packet drops:
#       grep "capture.kernel_drops" ${logDir}/stats.log
# [ ] If drops appear, increase max-pending-packets in suricata.yaml` : ''

  return [
    `# ══════════════════════════════════════════════════════════════════════════════`,
    `#  Deployment Guide`,
    `#  OS: ${isUbuntu ? 'Ubuntu/Debian' : isRhel ? 'RHEL/CentOS/Fedora' : 'Other Linux'}  |  Suricata ${ver}.x  |  Mode: ${isIps ? 'IPS' : 'IDS'}  |  Env: ${isProd ? 'Production' : 'Test/Lab'}`,
    `# ══════════════════════════════════════════════════════════════════════════════`,
    ``,
    `# ── Step 1: Configure network interfaces ────────────────────────────────────`,
    `# Assign each device's IP to the correct interface before Suricata can listen.`,
    `# Full per-device config snippets are in the Network Inventory tab.`,
    `# Quick reference for the Suricata host interface (${iface}):`,
    ...(isUbuntu ? [
      `#   Netplan: sudo nano /etc/netplan/01-netcfg.yaml   then: sudo netplan apply`,
      `#   Legacy:  sudo nano /etc/network/interfaces        then: sudo ifup ${iface}`,
    ] : isRhel ? [
      `#   nmcli:   nmcli con mod "${iface}" ipv4.method manual ipv4.addresses <ip/prefix>`,
      `#   Legacy:  sudo nano /etc/sysconfig/network-scripts/ifcfg-${iface}`,
    ] : [
      `#   ip addr add <ip>/<prefix> dev ${iface}`,
      `#   ip route add default via <gateway>`,
    ]),
    `# Verify: ip addr show ${iface}`,
    ``,
    `# ── Step 2: Install Suricata ─────────────────────────────────────────────────`,
    install,
    ``,
    `# ── Step 3: Place your rules file ────────────────────────────────────────────`,
    `sudo cp local.rules /etc/suricata/rules/local.rules`,
    `sudo chown root:suricata /etc/suricata/rules/local.rules`,
    `# Community rules live in: ${rulePath}`,
    ``,
    `# ── Step 4: Apply the suricata.yaml snippet ──────────────────────────────────`,
    `# Copy the contents of the YAML tab into /etc/suricata/suricata.yaml`,
    `sudo nano /etc/suricata/suricata.yaml`,
    ``,
    `# ── Step 5: Validate config ──────────────────────────────────────────────────`,
    `sudo suricata -T -c /etc/suricata/suricata.yaml --set af-packet.0.interface=${iface}`,
    `# Expect: "Configuration provided was successfully loaded." (exit 0)`,
    ``,
    `# ── Step 6: Start Suricata ───────────────────────────────────────────────────`,
    isIps
      ? `# IPS mode — test manually before enabling as service:`
      : `# IDS mode — passive, listen on ${iface}:`,
    isIps
      ? `sudo suricata --nfq-id 0 -c /etc/suricata/suricata.yaml`
      : `sudo suricata -c /etc/suricata/suricata.yaml -i ${iface}`,
    ``,
    `# Enable as a system service:`,
    systemdDefault,
    ipsNote,
    testNote,
    ``,
    `# ── Step 7: Monitor alerts ───────────────────────────────────────────────────`,
    `# Human-readable line per alert:`,
    `tail -f ${logDir}/fast.log`,
    ``,
    `# Structured JSON — filter to alerts only:`,
    `tail -f ${logDir}/eve.json | jq 'select(.event_type=="alert")'`,
    ``,
    `# Filter by SID:`,
    `grep 'sid:XXXX' ${logDir}/fast.log`,
    ``,
    `# ── Step 8: Reload rules (no restart needed) ─────────────────────────────────`,
    `sudo kill -USR2 $(pidof suricata)`,
    `# Or: sudo suricatasc -c reload-rules`,
    ``,
    `# ── Step 9: Keep community rules up to date ──────────────────────────────────`,
    `sudo pip3 install suricata-update`,
    `sudo suricata-update`,
    `sudo kill -USR2 $(pidof suricata)`,
    prodChecklist,
    ``,
    `# ── EVE JSON fields to watch ─────────────────────────────────────────────────`,
    `# .alert.signature      — rule msg string`,
    `# .alert.signature_id   — rule SID`,
    `# .alert.category       — classtype`,
    `# .src_ip / .dest_ip    — packet endpoints`,
    `# .src_port / .dest_port`,
    `# .proto                — protocol`,
    `# .http.url             — full HTTP URI (http events)`,
    `# .http.http_method     — GET / POST etc.`,
    `# .dns.query[].name     — queried domain (dns events)`,
    ``,
  ].filter(l => l !== undefined).join('\n')
}

// ─── Utility components ───────────────────────────────────────────────────────

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
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 hover:text-white transition flex-shrink-0"
    >
      {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
      {label && (copied ? 'Copied!' : label)}
    </button>
  )
}

function DownloadButton({ content, filename, label = 'Download' }: { content: string; filename: string; label?: string }) {
  function handle() {
    const blob = new Blob([content], { type: 'text/plain' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <button
      onClick={handle}
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-indigo-700 hover:bg-indigo-600 border border-indigo-600 text-white transition flex-shrink-0"
    >
      <Download size={11} />
      {label}
    </button>
  )
}

function CodeBlock({ content, color = 'text-green-300' }: { content: string; color?: string }) {
  return (
    <pre className={`flex-1 min-h-0 overflow-auto bg-gray-950 border border-gray-800 rounded-xl p-3 text-[11px] ${color} font-mono leading-relaxed whitespace-pre-wrap`}>
      {content}
    </pre>
  )
}

// ─── Step 1: Environment questionnaire ───────────────────────────────────────

interface RadioGroupProps<T extends string> {
  label: string
  value: T
  options: { value: T; label: string; hint?: string }[]
  onChange: (v: T) => void
}

function RadioGroup<T extends string>({ label, value, options, onChange }: RadioGroupProps<T>) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-1.5">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {options.map(opt => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            className={`px-3 py-1.5 rounded-lg text-xs border transition text-left ${
              value === opt.value
                ? 'bg-indigo-900/60 border-indigo-600 text-indigo-200'
                : 'bg-gray-800/60 border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300'
            }`}
          >
            <span className="font-medium">{opt.label}</span>
            {opt.hint && <span className="block text-[10px] opacity-60 mt-0.5">{opt.hint}</span>}
          </button>
        ))}
      </div>
    </div>
  )
}

function TextInput({ label, value, onChange, placeholder, hint }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; hint?: string
}) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 mb-1.5">{label}</p>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-600 transition"
      />
      {hint && <p className="text-[10px] text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function SetupStep({
  setup,
  setSetup,
  nodes,
  onNext,
}: {
  setup: EnvSetup
  setSetup: (s: EnvSetup) => void
  nodes: Node[]
  onNext: () => void
}) {
  const autoHomeNet = resolveHomeNet(nodes, '')

  return (
    <div className="flex flex-col gap-4 h-full overflow-y-auto pb-1">
      <div className="flex-shrink-0">
        <p className="text-sm font-semibold text-gray-100">Environment Setup</p>
        <p className="text-[11px] text-gray-500 mt-0.5">
          Tell us about your real Suricata environment so we can generate a tailored export.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-x-5 gap-y-3.5">
        <RadioGroup
          label="Operating System"
          value={setup.os}
          onChange={v => setSetup({ ...setup, os: v })}
          options={[
            { value: 'ubuntu', label: 'Ubuntu / Debian' },
            { value: 'rhel',   label: 'RHEL / CentOS / Fedora' },
            { value: 'other',  label: 'Other Linux' },
          ]}
        />

        <RadioGroup
          label="Suricata Version"
          value={setup.suricataVersion}
          onChange={v => setSetup({ ...setup, suricataVersion: v })}
          options={[
            { value: '7',     label: '7.x', hint: 'latest stable' },
            { value: '6',     label: '6.0.x' },
            { value: 'other', label: 'Other' },
          ]}
        />

        <RadioGroup
          label="Deployment Mode"
          value={setup.deployMode}
          onChange={v => setSetup({ ...setup, deployMode: v })}
          options={[
            { value: 'ids', label: 'IDS', hint: 'passive detection only' },
            { value: 'ips', label: 'IPS', hint: 'inline blocking' },
          ]}
        />

        <RadioGroup
          label="Environment Type"
          value={setup.envType}
          onChange={v => setSetup({ ...setup, envType: v })}
          options={[
            { value: 'test',       label: 'Test / Learning', hint: 'lab or VM' },
            { value: 'production', label: 'Production',      hint: 'real network' },
          ]}
        />

        <TextInput
          label="Network Interface(s)"
          value={setup.interfaces}
          onChange={v => setSetup({ ...setup, interfaces: v })}
          placeholder="eth0"
          hint="Comma-separated for multiple: eth0, eth1"
        />

        <TextInput
          label="HOME_NET override"
          value={setup.homeNetOverride}
          onChange={v => setSetup({ ...setup, homeNetOverride: v })}
          placeholder={`Auto-detected: ${autoHomeNet}`}
          hint="Leave blank to use topology IPs"
        />

        <TextInput
          label="Log Directory"
          value={setup.logDir}
          onChange={v => setSetup({ ...setup, logDir: v })}
          placeholder="/var/log/suricata"
        />

        <TextInput
          label="Monitored Segment (optional)"
          value={setup.monitoredSegment}
          onChange={v => setSetup({ ...setup, monitoredSegment: v })}
          placeholder="e.g. Office LAN, DMZ, Server room"
          hint="For documentation purposes only"
        />
      </div>

      <div className="flex justify-end mt-auto pt-2 flex-shrink-0">
        <button
          onClick={onNext}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-600 text-white text-xs font-semibold transition"
        >
          Generate Export
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  )
}

// ─── Step 2: Output tabs ──────────────────────────────────────────────────────

const TABS: { id: ExportTab; label: string; icon: typeof FileText }[] = [
  { id: 'rules',     label: 'Rules File',    icon: FileText },
  { id: 'yaml',      label: 'suricata.yaml', icon: Settings },
  { id: 'inventory', label: 'Network Inventory', icon: Network },
  { id: 'guide',     label: 'Deployment Guide',  icon: Terminal },
]

function TabBar({ active, onChange, ruleBadge }: {
  active: ExportTab
  onChange: (t: ExportTab) => void
  ruleBadge: number
}) {
  return (
    <div className="flex gap-0.5 border-b border-gray-800 flex-shrink-0 -mx-5 px-5">
      {TABS.map(t => {
        const Icon = t.icon
        const badge = t.id === 'rules' && ruleBadge > 0 ? ruleBadge : null
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-medium rounded-t-lg border-b-2 transition ${
              active === t.id
                ? 'border-indigo-500 text-indigo-300 bg-indigo-950/30'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Icon size={11} />
            {t.label}
            {badge !== null && (
              <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-indigo-900/60 text-indigo-300">
                {badge}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

function OutputStep({
  projectName,
  activeRules,
  nodes,
  setup,
  onBack,
}: {
  projectName: string
  activeRules: ActiveRule[]
  nodes: Node[]
  setup: EnvSetup
  onBack: () => void
}) {
  const [tab, setTab] = useState<ExportTab>('rules')
  const slug = projectName.toLowerCase().replace(/\s+/g, '-') || 'lab'

  const rulesContent    = buildRulesFile(projectName, activeRules, nodes, setup)
  const yamlContent     = buildYaml(nodes, setup)
  const inventoryContent = buildInventoryText(projectName, nodes, setup)
  const guideContent    = buildDeploymentGuide(setup)

  return (
    <div className="flex flex-col h-full gap-3 min-h-0">
      <TabBar active={tab} onChange={setTab} ruleBadge={activeRules.length} />

      {/* Content area */}
      <div className="flex-1 min-h-0 flex flex-col gap-2">
        {(tab === 'rules' || tab === 'yaml' || tab === 'inventory' || tab === 'guide') && (() => {
          const [content, filename, color] =
            tab === 'rules'     ? [rulesContent,     `${slug}.rules`,            'text-green-300']
            : tab === 'yaml'    ? [yamlContent,      'suricata-vars.yaml',        'text-amber-300']
            : tab === 'inventory' ? [inventoryContent, `${slug}-inventory.txt`,   'text-cyan-300']
            :                     [guideContent,     `${slug}-deploy-guide.sh`,  'text-emerald-300']

          return (
            <>
              <div className="flex items-center justify-between flex-shrink-0">
                <p className="text-[10px] text-gray-500 font-mono">{filename}</p>
                <div className="flex items-center gap-2">
                  <CopyButton text={content} />
                  <DownloadButton content={content} filename={filename} />
                </div>
              </div>
              <CodeBlock content={content} color={color} />
            </>
          )
        })()}
      </div>

      {/* Back button */}
      <div className="flex items-center justify-between flex-shrink-0 pt-1 border-t border-gray-800/60">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-gray-500 hover:text-gray-300 transition"
        >
          <ChevronLeft size={12} />
          Back to Setup
        </button>
        <p className="text-[10px] text-gray-600">
          {setup.deployMode.toUpperCase()} · {setup.os === 'ubuntu' ? 'Ubuntu/Debian' : setup.os === 'rhel' ? 'RHEL/Fedora' : 'Linux'} · Suricata {setup.suricataVersion}.x
        </p>
      </div>
    </div>
  )
}

// ─── Modal root ───────────────────────────────────────────────────────────────

export default function ExportModal({ projectName, activeRules, nodes, onClose }: Props) {
  const [step, setStep]     = useState<1 | 2>(1)
  const [setup, setSetup]   = useState<EnvSetup>(DEFAULT_SETUP)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="flex flex-col bg-gray-900 border border-gray-700/60 rounded-2xl shadow-2xl overflow-hidden"
        style={{ width: 720, height: 620 }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <FileText size={15} className="text-indigo-400" />
            <span className="text-sm font-semibold text-gray-100">Export</span>
            <span className="text-xs text-gray-500">{projectName}</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-gray-800 text-gray-500 border border-gray-700">
              Step {step} of 2
            </span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 min-h-0 px-5 py-4 overflow-hidden flex flex-col">
          {step === 1 ? (
            <SetupStep
              setup={setup}
              setSetup={setSetup}
              nodes={nodes}
              onNext={() => setStep(2)}
            />
          ) : (
            <OutputStep
              projectName={projectName}
              activeRules={activeRules}
              nodes={nodes}
              setup={setup}
              onBack={() => setStep(1)}
            />
          )}
        </div>
      </div>
    </div>
  )
}
