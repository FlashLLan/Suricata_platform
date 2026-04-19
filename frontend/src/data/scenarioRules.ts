/** Rule SIDs that are most relevant for each detected PCAP scenario. */
export const SCENARIO_RULES: Record<string, string[]> = {
  'nmap-syn-scan':    ['1000001', '1000002'],
  'ping-sweep':       ['1000002'],
  'ssh-brute-force':  ['1000010'],
  'http-brute-force': ['1000011'],
  'sql-injection':    ['1000020', '1000021', '1000023'],
  'dns-tunneling':    ['1000030', '1000031'],
  'http-c2-beacon':   ['1000040'],
  'normal-browsing':  [],
}
