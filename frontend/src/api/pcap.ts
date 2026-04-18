import api from './client'

export interface PcapScenario {
  scenario_id: string
  name: string
  confidence: number
  description: string
  attacker_ip: string | null
  target_ip: string | null
}

export interface PcapStats {
  total_packets: number
  unique_ips: number
  duration_seconds: number
  protocol_counts: Record<string, number>
}

export interface PcapRuleResult {
  rule_sid: string
  rule_msg: string
  fired: boolean
  matched_packets: { protocol: string; src: string; dst: string; description: string; payload_preview?: string }[]
  explanation: string
  why_not: string | null
}

export interface PcapAnalysisResult {
  topology: { nodes: object[]; edges: object[] }
  scenario: PcapScenario
  stats: PcapStats
  results: PcapRuleResult[]
  triggered_count: number
  total_packets: number
  mode: 'python' | 'suricata'
  suricata_fallback: boolean
  summary: string
  filename: string
}

export async function analyzePcap(
  file: File,
  ruleTexts: string[],
  mode: 'python' | 'suricata' = 'python',
): Promise<PcapAnalysisResult> {
  const form = new FormData()
  form.append('file', file)
  form.append('rule_texts', JSON.stringify(ruleTexts))
  form.append('mode', mode)

  const { data } = await api.post<PcapAnalysisResult>('/pcap/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}
