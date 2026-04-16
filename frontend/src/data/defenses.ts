export type DefenseCategory =
  | 'network-filtering'
  | 'authentication'
  | 'rate-limiting'
  | 'ids-ips'
  | 'application'
  | 'monitoring'

export interface DefenseConfigField {
  key: string
  label: string
  placeholder: string
  defaultValue: string
}

export interface DefenseOption {
  id: string
  name: string
  category: DefenseCategory
  shortDesc: string           // one-liner shown in list
  description: string         // full explanation shown when expanded
  howItWorks: string          // technical mechanism
  blocksAttacks: string[]     // attack IDs from attacks.ts it counters
  weaknesses: string          // what bypasses it
  configFields?: DefenseConfigField[]
}

export const DEFENSE_OPTIONS: DefenseOption[] = [
  // ── Network Filtering ─────────────────────────────────────────────────────
  {
    id: 'ip-blocklist',
    name: 'IP Blocklist / Allowlist',
    category: 'network-filtering',
    shortDesc: 'Drop traffic from known-bad or unlisted IP addresses.',
    description:
      'Maintains a list of blocked (or allowed) IP addresses at the network or host level. Incoming packets from blocked IPs are silently dropped before any service ever sees them.',
    howItWorks:
      'Implemented via iptables/nftables DROP rules or firewall ACLs. The kernel inspects the source IP of every incoming packet; if it matches the blocklist the packet is discarded without sending a RST or ICMP back (stealth drop).',
    blocksAttacks: ['nmap-syn', 'nmap-os', 'ping-sweep', 'hydra-ssh', 'hydra-http'],
    weaknesses:
      'Attackers can spoof source IPs, use proxies/VPNs, or rotate IPs. Internal attackers are unaffected. Requires constant list maintenance.',
    configFields: [
      { key: 'blocked_ips', label: 'Blocked IP ranges (CIDR, one per line)', placeholder: '192.168.1.0/24\n10.0.0.5', defaultValue: '' },
    ],
  },
  {
    id: 'port-filtering',
    name: 'Port Filtering (Firewall Rules)',
    category: 'network-filtering',
    shortDesc: 'Restrict which TCP/UDP ports are reachable from outside.',
    description:
      'A stateful firewall allows only explicitly whitelisted ports and drops everything else. This limits the attack surface so port scanners and exploit tools can\'t reach closed services.',
    howItWorks:
      'Uses iptables/nftables with a default-DROP policy on FORWARD/INPUT chains. Only ports in the allowlist (e.g., 80, 443, 22) get an ACCEPT rule. All other ports return no response, defeating most scan techniques.',
    blocksAttacks: ['nmap-syn', 'udp-scan', 'msf-handler', 'hydra-ftp', 'medusa-rdp'],
    weaknesses:
      'If a required service runs on an open port the attacker can still target it. Doesn\'t protect against attacks on allowed ports.',
    configFields: [
      { key: 'allowed_ports', label: 'Allowed inbound ports (comma-separated)', placeholder: '22,80,443', defaultValue: '80,443' },
    ],
  },
  {
    id: 'geo-blocking',
    name: 'Geo-Blocking',
    category: 'network-filtering',
    shortDesc: 'Drop traffic originating from specific countries.',
    description:
      'Maps source IPs to their registered country and blocks entire country ranges. Useful for services that only legitimately serve a specific region.',
    howItWorks:
      'Uses a GeoIP database (e.g., MaxMind GeoLite2) loaded into iptables via the `geoip` extension or a firewall like pfSense. Packets from blocked country ASN ranges are dropped at ingress.',
    blocksAttacks: ['nmap-syn', 'hydra-ssh', 'medusa-rdp'],
    weaknesses:
      'Easily bypassed with a VPN or proxy in an allowed country. GeoIP databases have ~1–3% error rates on edge cases.',
    configFields: [
      { key: 'blocked_countries', label: 'Blocked country codes (comma-separated)', placeholder: 'RU,CN,KP', defaultValue: '' },
    ],
  },

  // ── Authentication ────────────────────────────────────────────────────────
  {
    id: 'ssh-key-only',
    name: 'SSH Key-Only Authentication',
    category: 'authentication',
    shortDesc: 'Disable SSH password login; require cryptographic keys.',
    description:
      'Disables password-based SSH login in `sshd_config` so that brute-force dictionary attacks have nothing to guess — a private key that the attacker doesn\'t have is required.',
    howItWorks:
      'Sets `PasswordAuthentication no` and `ChallengeResponseAuthentication no` in `/etc/ssh/sshd_config`. The server will reject any auth attempt that doesn\'t present a valid private key signature.',
    blocksAttacks: ['hydra-ssh'],
    weaknesses:
      'Only protects SSH. If the private key or the user\'s workstation is compromised, access is still possible. Doesn\'t protect other services.',
  },
  {
    id: 'mfa',
    name: 'Multi-Factor Authentication (MFA/2FA)',
    category: 'authentication',
    shortDesc: 'Require a second factor (TOTP, hardware token) on login.',
    description:
      'Even if a password is guessed, MFA forces the attacker to also possess the second factor (e.g., a TOTP app or hardware key). Brute-forced passwords alone become useless.',
    howItWorks:
      'Implemented with PAM modules (libpam-google-authenticator, FIDO2) or application-level TOTP libraries. The login flow demands both the correct password and a time-based one-time code.',
    blocksAttacks: ['hydra-ssh', 'hydra-http', 'hydra-ftp', 'medusa-rdp'],
    weaknesses:
      'Phishing can steal session tokens. SIM-swapping can compromise SMS-based 2FA. Adds friction for legitimate users.',
  },
  {
    id: 'port-knocking',
    name: 'Port Knocking',
    category: 'authentication',
    shortDesc: 'Hide services until a secret knock sequence unlocks the port.',
    description:
      'All services appear closed to scanners. A user must send TCP/UDP packets to a secret sequence of ports in order; only then does the firewall temporarily open the real service port for that IP.',
    howItWorks:
      'Implemented by `knockd` daemon watching firewall logs. When it sees packets arrive at ports in the configured sequence (e.g., 7000, 8000, 9000 within 5 seconds), it runs `iptables -I INPUT -s <src> -p tcp --dport 22 -j ACCEPT`.',
    blocksAttacks: ['nmap-syn', 'hydra-ssh', 'medusa-rdp'],
    weaknesses:
      'The knock sequence can be captured via network sniffing. A replay attack can reuse captured sequences. Not suitable for high-availability services.',
    configFields: [
      { key: 'knock_sequence', label: 'Knock sequence (ports, comma-separated)', placeholder: '7000,8000,9000', defaultValue: '' },
    ],
  },

  // ── Rate Limiting ─────────────────────────────────────────────────────────
  {
    id: 'fail2ban',
    name: 'fail2ban (Login Attempt Limiting)',
    category: 'rate-limiting',
    shortDesc: 'Auto-ban IPs after N failed login attempts.',
    description:
      'Watches authentication logs in real time. After a configurable number of failures within a time window, it inserts a temporary iptables DROP rule for that source IP.',
    howItWorks:
      'fail2ban tails log files like `/var/log/auth.log` using regex filters. When `maxretry` failures are seen within `findtime` seconds, it calls an `action` script (typically `iptables -I INPUT -s <ip> -j DROP`) for `bantime` seconds.',
    blocksAttacks: ['hydra-ssh', 'hydra-http', 'hydra-ftp', 'medusa-rdp'],
    weaknesses:
      'Slow brute-force under `maxretry` threshold slips through. Distributed attacks from many IPs each try only a few passwords. Can be used as a DoS tool by spoofing trusted IPs.',
    configFields: [
      { key: 'maxretry', label: 'Max failed attempts before ban', placeholder: '5', defaultValue: '5' },
      { key: 'bantime', label: 'Ban duration (seconds)', placeholder: '600', defaultValue: '600' },
      { key: 'findtime', label: 'Window to count failures (seconds)', placeholder: '60', defaultValue: '60' },
    ],
  },
  {
    id: 'syn-flood-protection',
    name: 'SYN Flood Protection (SYN Cookies)',
    category: 'rate-limiting',
    shortDesc: 'Defend against TCP SYN flood attacks with SYN cookies.',
    description:
      'When the kernel\'s SYN backlog is full, it activates SYN cookies — encoding connection state into the TCP sequence number so no memory is allocated until the handshake completes. This makes SYN floods ineffective.',
    howItWorks:
      'Enabled via `sysctl net.ipv4.tcp_syncookies=1`. When the half-open connection queue overflows, the kernel generates a cryptographic cookie in the SYN-ACK. Only a legitimate ACK with the right cookie advances the connection.',
    blocksAttacks: ['nmap-syn'],
    weaknesses:
      'Doesn\'t stop the bandwidth consumption of a volumetric flood. Some TCP options are lost when SYN cookies are active. Requires kernel-level configuration.',
  },
  {
    id: 'connection-rate-limit',
    name: 'Connection Rate Limiting',
    category: 'rate-limiting',
    shortDesc: 'Throttle new connections per second from any single IP.',
    description:
      'Limits how many new TCP connections a single source IP can open per second. Scanners and brute-force tools require hundreds of connections per second and are throttled back to uselessness.',
    howItWorks:
      'Uses iptables `hashlimit` or `recent` modules. Example: `iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-above 10/sec --hashlimit-mode srcip -j DROP` caps SYN packets at 10/s per source.',
    blocksAttacks: ['nmap-syn', 'hydra-ssh', 'hydra-http', 'hydra-ftp'],
    weaknesses:
      'Distributed attacks from many IPs each stay under the per-IP limit. Legitimate users on shared NAT (e.g., corporate proxy) may be throttled.',
    configFields: [
      { key: 'max_conn_per_sec', label: 'Max new connections per second per IP', placeholder: '10', defaultValue: '10' },
    ],
  },

  // ── IDS / IPS ─────────────────────────────────────────────────────────────
  {
    id: 'suricata-ips',
    name: 'Suricata IPS Mode (Inline)',
    category: 'ids-ips',
    shortDesc: 'Suricata in inline mode actively drops matched traffic.',
    description:
      'Suricata in IPS (Intrusion Prevention System) mode sits inline in the traffic path using netfilter/NFQUEUE. When a rule fires with `drop` action, the packet is discarded before it reaches the target service.',
    howItWorks:
      'Traffic is redirected to a NFQUEUE via iptables: `iptables -I FORWARD -j NFQUEUE`. Suricata reads each packet via the queue, evaluates rules, and returns ACCEPT or DROP verdicts to the kernel.',
    blocksAttacks: ['nmap-syn', 'sqlmap', 'hydra-ssh', 'dns-tunnel', 'curl-exfil'],
    weaknesses:
      'Only as good as its ruleset. Evasion techniques (fragmentation, encoding, slow-scan) bypass signature rules. Adds latency. Requires tuned rules to avoid false positives blocking legitimate traffic.',
  },
  {
    id: 'waf',
    name: 'Web Application Firewall (WAF)',
    category: 'application',
    shortDesc: 'Inspect and block malicious HTTP requests (SQLi, XSS, LFI).',
    description:
      'A WAF sits in front of web applications and inspects HTTP request bodies, headers, and query strings against a ruleset (e.g., ModSecurity OWASP Core Rule Set). Attacks like SQL injection and XSS are blocked before reaching the app.',
    howItWorks:
      'Deployed as an Nginx/Apache module or reverse proxy. Parses HTTP at L7, runs regex and anomaly scoring against the OWASP CRS ruleset. Requests exceeding the anomaly threshold return 403 or are silently dropped.',
    blocksAttacks: ['sqlmap', 'burp-sqli', 'xss-probe', 'lfi', 'nikto', 'gobuster'],
    weaknesses:
      'Can be bypassed with encoding tricks, HTTP parameter pollution, or obfuscated payloads. High false-positive rate requires careful tuning. Doesn\'t protect non-HTTP services.',
    configFields: [
      { key: 'paranoia_level', label: 'OWASP CRS Paranoia Level (1–4)', placeholder: '2', defaultValue: '2' },
    ],
  },

  // ── Monitoring ────────────────────────────────────────────────────────────
  {
    id: 'network-logging',
    name: 'Full Network Logging (pcap / NetFlow)',
    category: 'monitoring',
    shortDesc: 'Capture all traffic for forensic analysis and anomaly detection.',
    description:
      'Full packet capture (pcap) or flow-level logging (NetFlow/IPFIX) records all traffic passing through the network segment. Doesn\'t block attacks in real time but provides forensic evidence and feeds anomaly detection systems.',
    howItWorks:
      'tcpdump / Zeek / ntopng capture packets on a mirror/span port. NetFlow exporters on routers send flow summaries to a collector. Logs are indexed in a SIEM (Splunk, Graylog) for alerting and retrospective analysis.',
    blocksAttacks: [],
    weaknesses:
      'Passive only — won\'t stop an attack in progress. Storage requirements are enormous for pcap. Encrypted traffic (TLS) hides payload content.',
  },
  {
    id: 'honeypot',
    name: 'Honeypot / Honeytokens',
    category: 'monitoring',
    shortDesc: 'Deploy decoy services that alert when touched.',
    description:
      'A honeypot is a fake service with no legitimate users. Any connection to it is by definition malicious or caused by a misconfigured scanner. Honeytokens are fake credentials/files that alert when used.',
    howItWorks:
      'Tools like OpenCanary or Cowrie listen on ports that real services don\'t use (e.g., a fake SSH on port 2222). Every connection fires an alert to a SIEM. Honeytokens are fake API keys placed in config files that trigger alerts if used.',
    blocksAttacks: ['nmap-syn', 'hydra-ssh'],
    weaknesses:
      'Detection only — no blocking. Sophisticated attackers recognize honeypots via fingerprinting. Only catches attackers who probe the decoy port.',
  },
]

export const DEFENSE_CATEGORY_LABELS: Record<DefenseCategory, string> = {
  'network-filtering': 'Network Filtering',
  'authentication':    'Authentication',
  'rate-limiting':     'Rate Limiting',
  'ids-ips':           'IDS / IPS',
  'application':       'Application Layer',
  'monitoring':        'Monitoring',
}

export const DEFENSE_CATEGORY_COLORS: Record<DefenseCategory, string> = {
  'network-filtering': 'text-blue-400 bg-blue-900/20 border-blue-700/30',
  'authentication':    'text-green-400 bg-green-900/20 border-green-700/30',
  'rate-limiting':     'text-yellow-400 bg-yellow-900/20 border-yellow-700/30',
  'ids-ips':           'text-red-400 bg-red-900/20 border-red-700/30',
  'application':       'text-purple-400 bg-purple-900/20 border-purple-700/30',
  'monitoring':        'text-cyan-400 bg-cyan-900/20 border-cyan-700/30',
}
