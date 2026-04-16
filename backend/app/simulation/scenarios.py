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
        "normal-browsing":  _normal_browsing,
        "nmap-syn-scan":    _nmap_syn_scan,
        "ping-sweep":       _ping_sweep,
        "ssh-brute-force":  _ssh_brute_force,
        "http-brute-force": _http_brute_force,
        "sql-injection":    _sql_injection,
        "dns-tunneling":    _dns_tunneling,
        "http-c2-beacon":   _http_c2_beacon,
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
