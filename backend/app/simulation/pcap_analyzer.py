"""
pcap_analyzer.py — Analyze a real .pcap file to extract topology, detect scenario,
and prepare packets for the simulation engine.

Analysis pipeline
-----------------
1. Parse all IP packets from the pcap using scapy.
2. Build a HostInfo record for every unique IP (server ports, SYN counts, etc.).
3. Infer device types and zones from behavior + IP ranges.
4. Assemble a canvas-compatible topology (nodes + edges).
5. Score each known scenario against observed traffic patterns.
6. Convert scapy packets → SimPacket list for the Python engine fallback.
"""
from __future__ import annotations

import io
import ipaddress
import logging
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# Cap SimPacket conversion — keeps the Python engine fast on large captures.
_MAX_SIM_PACKETS = 500


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HostInfo:
    ip: str
    # Ports this host was seen *serving* (inferred from SYN-ACK sport)
    server_ports: set[int] = field(default_factory=set)
    # {target_ip: {dst_port, ...}} — unique ports scanned per target
    syn_targets: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    # (target_ip, dst_port) → SYN count — needed for brute-force detection
    syn_port_counts: Counter = field(default_factory=Counter)
    # IPs this host sent ICMP echo requests to
    icmp_targets: set[str] = field(default_factory=set)
    # Decoded HTTP payload snippets (first 500 chars, up to 50 per host)
    http_payloads: list[str] = field(default_factory=list)
    # DNS query names sent by this host (up to 200)
    dns_queries: list[str] = field(default_factory=list)
    pkts_sent: int = 0
    pkts_recv: int = 0


@dataclass
class ScenarioDetection:
    scenario_id: str
    name: str
    confidence: float       # 0.0 – 1.0
    description: str
    attacker_ip: Optional[str] = None
    target_ip: Optional[str] = None


@dataclass
class PcapStats:
    total_packets: int
    unique_ips: int
    duration_seconds: float
    protocol_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class PcapAnalysis:
    topology: dict              # canvas-compatible {nodes, edges}
    scenario: ScenarioDetection
    stats: PcapStats
    sim_packets: list           # list[SimPacket] for Python engine fallback


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_bytes: bytes) -> PcapAnalysis:
    """
    Analyze raw pcap bytes.

    Returns PcapAnalysis with reconstructed topology, scenario detection,
    traffic statistics, and SimPackets for the Python engine fallback.

    Raises ValueError for unreadable or empty captures.
    """
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw

    buf = io.BytesIO(pcap_bytes)
    try:
        packets = rdpcap(buf)
    except Exception as exc:
        raise ValueError(f"Could not parse pcap file: {exc}") from exc

    if not packets:
        raise ValueError("The pcap file contains no packets.")

    hosts: dict[str, HostInfo] = {}
    comm_pairs: set[tuple[str, str]] = set()
    proto_counter: Counter = Counter()

    start_ts = float(packets[0].time)
    end_ts   = float(packets[-1].time)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        if src not in hosts:
            hosts[src] = HostInfo(ip=src)
        if dst not in hosts:
            hosts[dst] = HostInfo(ip=dst)

        hosts[src].pkts_sent += 1
        hosts[dst].pkts_recv += 1
        comm_pairs.add((src, dst))

        # ── TCP ──────────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp    = pkt[TCP]
            flags  = int(tcp.flags)
            proto_counter['tcp'] += 1

            # SYN (no ACK) → connection initiation
            if (flags & 0x02) and not (flags & 0x10):
                hosts[src].syn_targets[dst].add(tcp.dport)
                hosts[src].syn_port_counts[(dst, tcp.dport)] += 1

            # SYN-ACK → src is the server responding on tcp.sport
            if (flags & 0x12) == 0x12:
                hosts[src].server_ports.add(tcp.sport)

            # HTTP payload collection
            if pkt.haslayer(Raw):
                is_http_port = tcp.dport in (80, 8080, 8443, 443) or tcp.sport in (80, 8080, 8443, 443)
                if is_http_port:
                    proto_counter['http'] += 1
                    if len(hosts[src].http_payloads) < 50:
                        try:
                            payload_str = pkt[Raw].load.decode('utf-8', errors='replace')
                            hosts[src].http_payloads.append(payload_str[:500])
                        except Exception:
                            pass

        # ── UDP / DNS ─────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto_counter['udp'] += 1

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                proto_counter['dns'] += 1

                # Port-53 responder → mark as DNS server
                if udp.sport == 53:
                    hosts[src].server_ports.add(53)

                # Collect query names (qr == 0 means it's a question)
                if dns.qr == 0 and dns.qdcount > 0:
                    try:
                        qname = dns.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                        if len(hosts[src].dns_queries) < 200:
                            hosts[src].dns_queries.append(qname)
                    except Exception:
                        pass

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            proto_counter['icmp'] += 1
            if icmp.type == 8:  # echo request
                hosts[src].icmp_targets.add(dst)

    topology    = _build_topology(hosts, comm_pairs)
    scenario    = _detect_scenario(hosts, comm_pairs, proto_counter)
    sim_packets = _to_sim_packets(packets, hosts)

    stats = PcapStats(
        total_packets=len(packets),
        unique_ips=len(hosts),
        duration_seconds=round(end_ts - start_ts, 2),
        protocol_counts=dict(proto_counter),
    )

    log.info(
        "PCAP analysis: %d packets, %d hosts, scenario=%s (confidence=%.0f%%)",
        len(packets), len(hosts), scenario.scenario_id, scenario.confidence * 100,
    )

    return PcapAnalysis(
        topology=topology,
        scenario=scenario,
        stats=stats,
        sim_packets=sim_packets,
    )


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------

def _build_topology(
    hosts: dict[str, HostInfo],
    comm_pairs: set[tuple[str, str]],
) -> dict:
    """Build a canvas-compatible topology dict from extracted host data."""
    nodes: list[dict] = []
    edges: list[dict] = []
    ip_to_id: dict[str, str] = {}

    for idx, (ip, host) in enumerate(hosts.items()):
        node_id = f"imported-{idx}"
        ip_to_id[ip] = node_id

        device_type = _infer_device_type(host)
        zone        = _infer_zone(ip)
        label       = _make_label(device_type, ip)
        ports_str   = ",".join(str(p) for p in sorted(host.server_ports)) if host.server_ports else ""

        x, y = _layout_position(idx, len(hosts))

        nodes.append({
            "id":   node_id,
            "type": "device",
            "position": {"x": x, "y": y},
            "data": {
                "label":      label,
                "deviceType": device_type,
                "ip":         ip,
                "ipClass":    _ip_class(ip),
                "subnet":     _default_subnet(ip),
                "ports":      ports_str,
                "os":         "",
                "zone":       zone,
                "notes":      "",
                "selectedAttacks":      [],
                "customAttackCommands": "",
                "noDefense":            True,
                "enabledDefenses":      [],
                "customDefenseConfig":  "",
                "selectedRuleIds":      [],
                "customRules":          [],
            },
        })

    # Deduplicated undirected edges
    seen: set[frozenset] = set()
    edge_idx = 0
    for src_ip, dst_ip in comm_pairs:
        if src_ip not in ip_to_id or dst_ip not in ip_to_id:
            continue
        key = frozenset({src_ip, dst_ip})
        if key in seen:
            continue
        seen.add(key)
        edges.append({
            "id":     f"imported-edge-{edge_idx}",
            "source": ip_to_id[src_ip],
            "target": ip_to_id[dst_ip],
            "data":   {"communicationAllowed": True, "monitoringOnly": False},
        })
        edge_idx += 1

    return {"nodes": nodes, "edges": edges}


def _layout_position(idx: int, total: int) -> tuple[float, float]:
    """Circular layout centred at (500, 300)."""
    if total == 1:
        return 500.0, 300.0
    angle  = (2 * math.pi * idx) / total
    radius = max(200.0, min(350.0, 50.0 * total))
    return round(500 + radius * math.cos(angle), 1), round(300 + radius * math.sin(angle), 1)


def _infer_device_type(host: HostInfo) -> str:
    """Infer canvas device type from observed traffic behaviour."""
    # Port scan: many unique destination ports across a target
    unique_ports_scanned = sum(len(ports) for ports in host.syn_targets.values())
    if unique_ports_scanned > 15:
        return "attacker"

    # ICMP sweep: pinging many distinct hosts
    if len(host.icmp_targets) > 5:
        return "attacker"

    # Brute force: many SYNs to the same (target, port)
    max_syn_to_single_port = max(host.syn_port_counts.values(), default=0)
    if max_syn_to_single_port > 20:
        return "attacker"

    srv = host.server_ports
    if {80, 443} & srv or {8080, 8443} & srv:
        return "web-server"
    if {3306, 5432, 1433, 27017, 6379} & srv:
        return "database"
    if 53 in srv:
        return "dns-server"
    if {25, 587, 465, 993, 995} & srv:
        return "mail-server"
    if {22, 3389, 445} & srv:
        return "server"

    return "workstation"


def _infer_zone(ip: str) -> str:
    try:
        return "internal" if ipaddress.ip_address(ip).is_private else "external"
    except ValueError:
        return "internal"


def _make_label(device_type: str, ip: str) -> str:
    base = {
        "web-server":  "Web Server",
        "database":    "Database",
        "dns-server":  "DNS Server",
        "mail-server": "Mail Server",
        "server":      "Server",
        "attacker":    "Attacker",
        "workstation": "Workstation",
        "router":      "Router",
        "firewall":    "Firewall",
        "ids":         "IDS Sensor",
    }.get(device_type, "Device")
    return f"{base} ({ip})"


def _ip_class(ip: str) -> str:
    try:
        first = int(ip.split(".")[0])
        if first < 128: return "A"
        if first < 192: return "B"
        if first < 224: return "C"
        return "D"
    except (ValueError, IndexError):
        return "C"


def _default_subnet(ip: str) -> str:
    try:
        if ipaddress.ip_address(ip).is_private:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except ValueError:
        pass
    return "0.0.0.0/0"


# ---------------------------------------------------------------------------
# Scenario detector
# ---------------------------------------------------------------------------

_SQL_RE    = re.compile(r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|OR\s+1=1|--)\b', re.IGNORECASE)
_AUTH_RE   = re.compile(r'(POST.*login|password=|passwd=|Authorization:)', re.IGNORECASE)


def _detect_scenario(
    hosts: dict[str, HostInfo],
    comm_pairs: set[tuple[str, str]],
    proto_counts: Counter,
) -> ScenarioDetection:
    """Score traffic patterns against known scenarios; return the best match."""

    scores:      dict[str, float]         = {}
    attacker_ip: Optional[str]            = None
    target_ip:   Optional[str]            = None

    # ── Nmap SYN scan ────────────────────────────────────────────────────────
    # One host sends SYN to many *different* ports on one target.
    best_scan = 0.0
    best_scanner = best_scan_target = None
    for ip, host in hosts.items():
        for tgt, ports in host.syn_targets.items():
            if len(ports) >= 10:
                s = min(1.0, len(ports) / 50)
                if s > best_scan:
                    best_scan, best_scanner, best_scan_target = s, ip, tgt
    scores['nmap-syn-scan'] = best_scan

    # ── Ping sweep ────────────────────────────────────────────────────────────
    best_sweep = 0.0
    best_sweeper = None
    for ip, host in hosts.items():
        if len(host.icmp_targets) >= 3:
            s = min(1.0, len(host.icmp_targets) / 20)
            if s > best_sweep:
                best_sweep, best_sweeper = s, ip
    scores['ping-sweep'] = best_sweep

    # ── SSH brute force ───────────────────────────────────────────────────────
    # Many SYNs to the same (target, 22).
    best_ssh = 0.0
    best_ssh_attacker = best_ssh_target = None
    for ip, host in hosts.items():
        for (tgt, port), count in host.syn_port_counts.items():
            if port == 22 and count > 5:
                s = min(1.0, count / 50)
                if s > best_ssh:
                    best_ssh, best_ssh_attacker, best_ssh_target = s, ip, tgt
    scores['ssh-brute-force'] = best_ssh

    # ── HTTP brute force ──────────────────────────────────────────────────────
    # Many SYNs to HTTP ports, or many HTTP payloads with auth patterns.
    best_http_bf = 0.0
    best_http_attacker = best_http_target = None
    for ip, host in hosts.items():
        # SYN-count signal
        for (tgt, port), count in host.syn_port_counts.items():
            if port in (80, 443, 8080, 8443) and count > 10:
                s = min(0.7, count / 80)
                if s > best_http_bf:
                    best_http_bf, best_http_attacker, best_http_target = s, ip, tgt
        # Payload signal: many POST /login payloads
        auth_hits = sum(1 for p in host.http_payloads if _AUTH_RE.search(p))
        if auth_hits > 3:
            s = min(1.0, auth_hits / 20)
            if s > best_http_bf:
                best_http_bf, best_http_attacker = s, ip
    scores['http-brute-force'] = best_http_bf

    # ── SQL injection ─────────────────────────────────────────────────────────
    best_sql = 0.0
    for ip, host in hosts.items():
        hits = sum(1 for p in host.http_payloads if _SQL_RE.search(p))
        if hits:
            best_sql = min(1.0, best_sql + hits * 0.3)
    scores['sql-injection'] = min(1.0, best_sql)

    # ── DNS tunneling ─────────────────────────────────────────────────────────
    # DNS queries with long, encoded subdomain labels.
    best_dns = 0.0
    for ip, host in hosts.items():
        if not host.dns_queries:
            continue
        encoded = [q for q in host.dns_queries if _looks_encoded(q)]
        long_q  = [q for q in host.dns_queries if len(q) > 30]
        ratio   = len(encoded) / max(1, len(host.dns_queries))
        if ratio > 0.25 or len(long_q) > 5:
            s = min(1.0, ratio * 2 + len(long_q) / 20)
            best_dns = max(best_dns, s)
    scores['dns-tunneling'] = best_dns

    # ── HTTP C2 beacon ────────────────────────────────────────────────────────
    # Internal host making regular HTTP requests to an external IP.
    best_c2 = 0.0
    for ip, host in hosts.items():
        if _infer_zone(ip) != "internal" or not host.http_payloads:
            continue
        external_http = [
            dst for (src2, dst) in comm_pairs
            if src2 == ip and _infer_zone(dst) == "external"
        ]
        if external_http:
            best_c2 = max(best_c2, 0.5)
    scores['http-c2-beacon'] = best_c2

    # ── Normal browsing ───────────────────────────────────────────────────────
    scores['normal-browsing'] = 0.3 if (proto_counts.get('http', 0) > 0 or proto_counts.get('dns', 0) > 0) else 0.1

    # ── Pick winner ───────────────────────────────────────────────────────────
    best_id    = max(scores, key=lambda k: scores[k])
    best_score = scores[best_id]

    if best_score < 0.2:
        best_id    = 'normal-browsing'
        best_score = 0.2

    # Resolve attacker/target for the winning scenario
    if best_id == 'nmap-syn-scan':
        attacker_ip, target_ip = best_scanner, best_scan_target
    elif best_id == 'ping-sweep':
        attacker_ip = best_sweeper
    elif best_id == 'ssh-brute-force':
        attacker_ip, target_ip = best_ssh_attacker, best_ssh_target
    elif best_id in ('http-brute-force', 'sql-injection'):
        attacker_ip, target_ip = best_http_attacker, best_http_target

    # Build a human-readable description
    description = _build_description(best_id, hosts, attacker_ip, target_ip, best_score)

    _NAMES = {
        'normal-browsing':  'Normal Browsing',
        'nmap-syn-scan':    'Nmap SYN Scan',
        'ping-sweep':       'Ping Sweep',
        'ssh-brute-force':  'SSH Brute Force',
        'http-brute-force': 'HTTP Brute Force',
        'sql-injection':    'SQL Injection',
        'dns-tunneling':    'DNS Tunneling',
        'http-c2-beacon':   'HTTP C2 Beacon',
    }

    return ScenarioDetection(
        scenario_id=best_id,
        name=_NAMES.get(best_id, best_id),
        confidence=round(best_score, 2),
        description=description,
        attacker_ip=attacker_ip,
        target_ip=target_ip,
    )


def _build_description(
    scenario_id: str,
    hosts: dict[str, HostInfo],
    attacker_ip: Optional[str],
    target_ip: Optional[str],
    confidence: float,
) -> str:
    host = hosts.get(attacker_ip or "") if attacker_ip else None
    if scenario_id == 'nmap-syn-scan' and host and target_ip:
        port_count = len(host.syn_targets.get(target_ip, set()))
        return (
            f"Port scanning detected — {attacker_ip} sent SYN packets to "
            f"{port_count} port(s) on {target_ip}."
        )
    if scenario_id == 'ping-sweep' and host:
        return (
            f"ICMP echo sweep from {attacker_ip} to "
            f"{len(host.icmp_targets)} host(s)."
        )
    if scenario_id == 'ssh-brute-force' and host and target_ip:
        count = host.syn_port_counts.get((target_ip, 22), 0)
        return (
            f"SSH brute force: {count} connection attempt(s) from "
            f"{attacker_ip} to {target_ip}:22."
        )
    if scenario_id == 'http-brute-force':
        return "Repeated HTTP authentication attempts detected — possible credential stuffing or brute force."
    if scenario_id == 'sql-injection':
        return "SQL keywords found in HTTP payloads — possible SQL injection attack."
    if scenario_id == 'dns-tunneling':
        return "Encoded or unusually long DNS subdomain labels detected — possible DNS tunneling."
    if scenario_id == 'http-c2-beacon':
        return f"Internal host making outbound HTTP requests to external server — possible C2 beacon."
    return "Standard HTTP/DNS traffic — no clear attack pattern detected."


def _looks_encoded(domain: str) -> bool:
    """Heuristic: does a DNS label look base32/base64 encoded?"""
    for part in domain.split('.')[:-2]:   # skip TLD + SLD
        if len(part) < 10:
            continue
        alpha  = sum(1 for c in part if c.isalpha())
        if alpha / max(1, len(part)) < 0.8:
            continue
        vowels = sum(1 for c in part.lower() if c in 'aeiou')
        if vowels / max(1, alpha) < 0.15:
            return True
    return False


# ---------------------------------------------------------------------------
# SimPacket converter
# ---------------------------------------------------------------------------

def _to_sim_packets(packets, hosts: dict[str, HostInfo]) -> list:
    """
    Convert scapy packets to SimPacket objects for the Python engine fallback.
    Capped at _MAX_SIM_PACKETS to keep evaluation fast on large captures.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from app.simulation.scenarios import SimPacket

    result: list[SimPacket] = []

    for pkt in packets:
        if len(result) >= _MAX_SIM_PACKETS:
            break
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        payload = ""

        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='replace')[:300]
            except Exception:
                payload = ""

        if pkt.haslayer(TCP):
            tcp       = pkt[TCP]
            flags_int = int(tcp.flags)
            flags_str = _tcp_flags_str(flags_int)
            flow      = _infer_flow(flags_int, src_ip, dst_ip, hosts)
            proto     = 'http' if tcp.dport in (80, 8080) or tcp.sport in (80, 8080) else 'tcp'
            result.append(SimPacket(
                protocol=proto,
                src_ip=src_ip,
                src_port=tcp.sport,
                dst_ip=dst_ip,
                dst_port=tcp.dport,
                payload=payload,
                flags=flags_str,
                description=f"{proto.upper()} {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport} [{flags_str}]",
                flow=flow,
            ))

        elif pkt.haslayer(UDP):
            udp   = pkt[UDP]
            proto = 'dns' if (udp.dport == 53 or udp.sport == 53) else 'udp'
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
                try:
                    qname   = pkt[DNS].qd.qname.decode('utf-8', errors='replace').rstrip('.')
                    payload = f"{qname} A?"
                except Exception:
                    pass
            result.append(SimPacket(
                protocol=proto,
                src_ip=src_ip,
                src_port=udp.sport,
                dst_ip=dst_ip,
                dst_port=udp.dport,
                payload=payload,
                flags="",
                description=f"{proto.upper()} {src_ip}:{udp.sport} → {dst_ip}:{udp.dport}",
                flow="to_server" if udp.dport == 53 else "established",
            ))

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            if icmp.type == 8:
                result.append(SimPacket(
                    protocol='icmp',
                    src_ip=src_ip,
                    src_port=0,
                    dst_ip=dst_ip,
                    dst_port=0,
                    payload="echo request",
                    flags="",
                    description=f"ICMP Echo Request {src_ip} → {dst_ip}",
                    flow="to_server",
                ))

    log.debug("Converted %d / %d packets to SimPackets", len(result), len(packets))
    return result


def _tcp_flags_str(flags_int: int) -> str:
    parts = []
    if flags_int & 0x01: parts.append('F')
    if flags_int & 0x02: parts.append('S')
    if flags_int & 0x04: parts.append('R')
    if flags_int & 0x08: parts.append('P')
    if flags_int & 0x10: parts.append('A')
    if flags_int & 0x20: parts.append('U')
    return ''.join(parts) or 'none'


def _infer_flow(flags_int: int, src_ip: str, dst_ip: str, hosts: dict) -> str:
    is_syn     = bool(flags_int & 0x02)
    is_ack     = bool(flags_int & 0x10)
    is_syn_ack = is_syn and is_ack

    if is_syn and not is_ack:
        return "to_server"
    if is_syn_ack:
        return "to_client"
    # Data packet: if dst is a known server this is to_server, otherwise established
    dst_host = hosts.get(dst_ip)
    if dst_host and dst_host.server_ports:
        return "to_server"
    return "established"
