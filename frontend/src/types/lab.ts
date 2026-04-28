export type NetworkZone = 'internal' | 'dmz' | 'external' | 'management'

// ── Firewall policy model ──────────────────────────────────────────────────────

export type FWChain    = 'input' | 'forward' | 'output'
export type FWProtocol = 'tcp' | 'udp' | 'icmp' | 'any'
export type FWAction   = 'accept' | 'drop' | 'reject'
export type FWZone     = NetworkZone | 'any'

/** A named nftables IP set (blocklist, allowlist, etc.) */
export interface FirewallIPSet {
  id: string
  name: string        // identifier used in rules, e.g. "BLOCKLIST" → ip saddr @BLOCKLIST
  elements: string[]  // IPs or CIDRs: ["1.2.3.4", "10.0.0.0/8"]
  description?: string
}

/** Port-knocking configuration: client must hit knockPort before targetPort is unlocked */
export interface PortKnockConfig {
  knockPort: number    // secret knock port (e.g. 7000)
  targetPort: number   // port unlocked after knock (e.g. 22)
  timeoutSec: number   // seconds the unlock remains valid (e.g. 30)
}

/** Dynamic ban: auto-temp-block a source IP that exceeds rateThreshold new connections/minute */
export interface DynamicBanConfig {
  rateThreshold: number      // new connections per minute before ban triggers (e.g. 5)
  banDurationSec: number     // seconds the source IP stays banned (e.g. 300)
  targetPort: string         // port(s) to watch, e.g. "22", "" = all ports
  targetProtocol: 'tcp' | 'udp' | 'any'
}

export interface FirewallRule {
  id: string
  enabled: boolean
  chain: FWChain
  srcZone: FWZone
  dstZone: FWZone
  protocol: FWProtocol
  dstPort: string       // e.g. "80" or "80,443" or "" for any
  action: FWAction
  description: string
  rateLimit?: { pps: number; burst: number }  // max packets/sec + burst allowance
  srcSet?: string   // name of a FirewallIPSet; when set, overrides srcZone IP matching
  dstSet?: string   // name of a FirewallIPSet; when set, overrides dstZone IP matching
}

export interface FirewallPolicy {
  defaultInput: FWAction
  defaultForward: FWAction
  defaultOutput: FWAction
  rules: FirewallRule[]
  ctStateEnabled?: boolean       // false = stateless mode (omits ct state established,related accept)
  ipSets?: FirewallIPSet[]        // named IP sets referenced by rules
  portKnocking?: PortKnockConfig  // undefined = disabled
  dynamicBan?: DynamicBanConfig   // undefined = disabled
}

// ── Device types ───────────────────────────────────────────────────────────────

export type DeviceType =
  | 'workstation'
  | 'server'
  | 'web-server'
  | 'database'
  | 'router'
  | 'firewall'
  | 'attacker'
  | 'dns-server'
  | 'mail-server'
  | 'ids'

export type IPClass = 'A' | 'B' | 'C' | 'D'

export interface DeviceData {
  label: string
  deviceType: DeviceType
  ip: string
  ipClass: IPClass
  subnet: string
  ports: string           // comma-separated, e.g. "80,443,22"
  os: string
  zone: NetworkZone
  notes: string
  // Attacker-only
  selectedAttacks: string[]
  customAttackCommands: string
  // Defense configuration (non-attacker devices)
  noDefense: boolean          // explicit "0 protection" mode
  enabledDefenses: string[]   // list of defense IDs from defenses.ts
  customDefenseConfig: string // free-form config text
  // IDS/Suricata-only: which rules are loaded on this sensor
  selectedRuleIds: string[]
  customRules: CustomRuleEntry[]
  // Firewall-only: nftables policy
  firewallPolicy?: FirewallPolicy
}

export type RuleCategory = 'scanning' | 'brute-force' | 'web-attacks' | 'malware' | 'exfiltration' | 'dns' | 'custom'

/** A rule written manually by the user on an IDS node. */
export interface CustomRuleEntry {
  id: string            // unique, e.g. "custom-1234567890"
  sid: string           // SID number string
  category: string      // RuleCategory key or free-form custom name
  categoryColor: string // color key from COLOR_PALETTE ("indigo", "teal" …), empty for built-in categories
  msg: string           // display name shown in the panel
  rule: string          // full Suricata rule text as written by the user
  isValid: boolean      // passed frontend syntax check?
}
export type RuleDifficulty = 'beginner' | 'intermediate' | 'advanced'

export interface RuleEntry {
  id: string
  sid: string
  category: RuleCategory
  msg: string
  rule: string
  explanation: string
  difficulty: RuleDifficulty
  false_positives?: string  // common sources of false alerts for this rule
}

export type ScenarioId =
  | 'normal-browsing'
  | 'nmap-syn-scan'
  | 'ssh-brute-force'
  | 'http-brute-force'
  | 'sql-injection'
  | 'dns-tunneling'
  | 'ping-sweep'
  | 'http-c2-beacon'

export interface Scenario {
  id: ScenarioId
  name: string
  description: string
  attacker_role: boolean   // does it require an attacker device?
  difficulty: RuleDifficulty
}

export interface SimPacket {
  protocol: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  payload: string
  flags: string
  description: string
}

export interface RuleMatchResult {
  rule_sid: string
  rule_msg: string
  fired: boolean
  matched_packets: SimPacket[]
  explanation: string
  why_not?: string
}

export interface DefenseImpact {
  defense_id: string
  defense_name: string
  blocked: boolean          // did this defense stop the attack?
  explanation: string       // what the defense did / why it didn't help
  device_label?: string     // label of the device this defense belongs to
}

export type TimelineEventType =
  | 'hop'
  | 'nftables_blocked'
  | 'nftables_allowed'
  | 'nftables_rate_limited'
  | 'nftables_ct_stateless'
  | 'port_knock_blocked'
  | 'dynamic_ban'
  | 'defense_blocked'
  | 'defense_passed'
  | 'no_defense'
  | 'ids_observed'
  | 'ids_blind'
  | 'rule_fired'
  | 'rule_missed'
  | 'outcome_blocked'
  | 'outcome_detected'
  | 'outcome_undetected'

export interface TimelineEvent {
  type: TimelineEventType
  label: string
  detail: string
  from_ip?: string
  to_ip?: string
  from_label?: string
  to_label?: string
  node_label?: string
  sid?: string
}

export interface NftablesDecision {
  firewall_label: string
  firewall_ip: string
  action: string
  matched_rule_description: string
  blocked: boolean
  explanation: string
  rate_limited?: boolean
  rate_limit_pps?: number
  rate_limit_burst?: number
  ct_stateless_warning?: boolean  // true when stateful tracking is disabled and default-forward is drop
  port_knock_blocked?: boolean    // true when port knocking blocked the attempt
  dynamic_ban_triggered?: boolean // true when dynamic ban fired on this source
  dynamic_ban_after_packets?: number  // how many packets got through before the ban activated
}

export interface EnforcementSuggestion {
  title: string
  explanation: string
  rule: {
    chain: FWChain
    srcZone: FWZone
    dstZone: FWZone
    protocol: FWProtocol
    dstPort: string
    action: FWAction
    description: string
  }
  nft_snippet: string
  triggered_sids: string[]
}

export interface SimulationResult {
  scenario: string
  total_packets: number
  triggered_count: number
  results: RuleMatchResult[]
  summary: string
  home_net: string
  // topology-aware additions
  attacker_ip?: string
  target_ips?: string[]
  attack_path?: string[][]  // list of [src_ip, dst_ip] hops for animation
  defense_impacts?: DefenseImpact[]
  attack_blocked?: boolean  // was the attack stopped (by firewall or host defenses)?
  attack_reached_target?: boolean
  // nftables firewall policy
  nftables_decision?: NftablesDecision
  nftables_blocked?: boolean
  nftables_rate_limited?: boolean
  // IDS visibility
  ids_visible?: boolean           // upstream IDS sensor(s) observed the traffic?
  ids_node_labels?: string[]      // labels of upstream (observing) IDS nodes
  ids_downstream_labels?: string[]  // IDS nodes blind due to firewall block
  // Event timeline
  timeline?: TimelineEvent[]
  // Simulation mode
  mode?: 'python' | 'suricata'
  suricata_fallback?: boolean     // suricata was requested but fell back to python
  // Detection-to-enforcement suggestions
  enforcement_suggestions?: EnforcementSuggestion[]
}

export interface ActiveRule {
  entry: RuleEntry
  customText?: string   // override rule text (for custom rules)
}

export interface SimulationRun {
  id: string
  timestamp: string                             // ISO 8601
  scenario_id: string
  scenario_name: string
  packet_rate: number
  rule_count: number
  outcome: 'blocked' | 'detected' | 'undetected'
  triggered_count: number
  result: SimulationResult
}
