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

export type NetworkZone = 'internal' | 'dmz' | 'external' | 'management'
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
}

export type RuleCategory = 'scanning' | 'brute-force' | 'web-attacks' | 'malware' | 'exfiltration' | 'dns' | 'custom'
export type RuleDifficulty = 'beginner' | 'intermediate' | 'advanced'

export interface RuleEntry {
  id: string
  sid: string
  category: RuleCategory
  msg: string
  rule: string
  explanation: string
  difficulty: RuleDifficulty
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
  attack_blocked?: boolean  // was the attack stopped by defenses before IDS?
  attack_reached_target?: boolean
}

export interface ActiveRule {
  entry: RuleEntry
  customText?: string   // override rule text (for custom rules)
}
