"""
Parse user-written attack commands into SimPackets for the custom-commands scenario.

Supported tools: nmap, hydra, sqlmap, curl, gobuster, nikto, medusa, nc/netcat, dnscat2, msfconsole
Unknown tools produce a generic TCP probe packet tagged with the tool name.
"""
import re
import shlex

from app.simulation.scenarios import (
    SimPacket,
    _nmap_syn_scan, _nmap_os_scan, _udp_port_scan, _ping_sweep,
    _ssh_brute_force, _http_brute_force, _ftp_brute_force, _rdp_brute_force,
    _sql_injection, _xss_probe, _lfi_attack, _gobuster_scan, _nikto_scan,
    _dns_tunneling, _metasploit_handler, _reverse_shell,
)

_IP_RE = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
_URL_RE = re.compile(r'https?://([^/:?\s]+)', re.IGNORECASE)


def _extract_target(args: list[str], fallback: str) -> str:
    """Best-effort extraction of a target IP from an args list."""
    for a in args:
        # http(s)://host...
        m = _URL_RE.search(a)
        if m:
            host = m.group(1)
            if _IP_RE.match(host):
                return host
        # bare IP or proto://IP
        clean = re.sub(r'^[a-z]+://', '', a)
        if _IP_RE.fullmatch(clean):
            return clean
    return fallback


def _flag_present(args: list[str], *flags: str) -> bool:
    return any(f in args for f in flags)


def _flag_value(args: list[str], *flags: str) -> str | None:
    for i, a in enumerate(args):
        if a in flags and i + 1 < len(args):
            return args[i + 1]
    return None


# ─── Per-tool handlers ────────────────────────────────────────────────────────

def _handle_nmap(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    # OS / version detection
    if _flag_present(args, '-O', '-sV', '-sC', '-A'):
        return _nmap_os_scan(ext, '', dst)
    # UDP scan
    if _flag_present(args, '-sU'):
        return _udp_port_scan(ext, '', dst)
    # Ping sweep
    if _flag_present(args, '-sn', '-sP'):
        return _ping_sweep(ext, '', dst)
    # Custom port SYN scan
    port_val = _flag_value(args, '-p', '--ports')
    if port_val:
        ports = []
        for part in port_val.replace(' ', '').split(','):
            if part.isdigit():
                ports.append(int(part))
            elif '-' in part:
                lo, hi = part.split('-', 1)
                if lo.isdigit() and hi.isdigit():
                    ports.extend(range(int(lo), min(int(hi) + 1, int(lo) + 30)))
        if ports:
            return [
                SimPacket("tcp", ext, 45000 + i, dst, p, payload="", flags="S",
                          flow="to_server", description=f"SYN probe → port {p}")
                for i, p in enumerate(ports[:40])
            ]
    # Default: SYN scan
    return _nmap_syn_scan(ext, '', dst)


def _handle_hydra(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    combined = ' '.join(args).lower()
    if 'http-post-form' in combined or 'http-get-form' in combined:
        return _http_brute_force(ext, '', dst)
    if 'ftp://' in combined or combined.endswith(' ftp'):
        return _ftp_brute_force(ext, '', dst)
    if 'rdp://' in combined or combined.endswith(' rdp'):
        return _rdp_brute_force(ext, '', dst)
    # Default: SSH
    return _ssh_brute_force(ext, '', dst)


def _handle_medusa(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    module = _flag_value(args, '-M', '-m') or ''
    module = module.lower()
    if module == 'rdp':
        return _rdp_brute_force(ext, '', dst)
    if module == 'ftp':
        return _ftp_brute_force(ext, '', dst)
    if module == 'http':
        return _http_brute_force(ext, '', dst)
    return _ssh_brute_force(ext, '', dst)


def _handle_sqlmap(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    return _sql_injection(ext, '', dst)


def _handle_curl(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    # Collect all string args (URLs, -d values, headers)
    full = ' '.join(args)

    # LFI / path traversal patterns
    if re.search(r'\.\.[/\\]|/etc/passwd|/etc/shadow|php://|proc/self', full, re.IGNORECASE):
        return _lfi_attack(ext, '', dst)

    # XSS patterns
    if re.search(r'<script|onerror|onload|javascript:', full, re.IGNORECASE):
        return _xss_probe(ext, '', dst)

    # SQL injection patterns
    if re.search(r"union\s+select|'\s*or\s*'|--\s|1=1|sqlmap", full, re.IGNORECASE):
        return _sql_injection(ext, '', dst)

    # POST with data — could be brute force or exfil
    if _flag_present(args, '-X') and 'POST' in args:
        method_idx = args.index('-X') + 1 if '-X' in args else -1
        if method_idx != -1 and args[method_idx] == 'POST':
            return _http_brute_force(ext, '', dst)
    if _flag_present(args, '-d', '--data', '-F', '--form'):
        return _http_brute_force(ext, '', dst)

    # Generic HTTP GET
    target = _extract_target(args, dst)
    return [SimPacket(
        "tcp", ext, 52100, target, 80,
        payload=f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: curl/7.88\r\n",
        flags="PA", flow="to_server",
        description="curl HTTP GET request",
    )]


def _handle_gobuster(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    return _gobuster_scan(ext, '', dst)


def _handle_nikto(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    return _nikto_scan(ext, '', dst)


def _handle_dnscat2(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    return _dns_tunneling(ext, ext, dst)


def _handle_msfconsole(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    combined = ' '.join(args).lower()
    if 'reverse' in combined or 'handler' in combined or 'meterpreter' in combined:
        return _metasploit_handler(ext, '', dst)
    return _metasploit_handler(ext, '', dst)


def _handle_nc(args: list[str], ext: str, dst: str) -> list[SimPacket]:
    return _reverse_shell(ext, '', dst)


# ─── Dispatch table ───────────────────────────────────────────────────────────

_HANDLERS = {
    'nmap':       _handle_nmap,
    'hydra':      _handle_hydra,
    'medusa':     _handle_medusa,
    'sqlmap':     _handle_sqlmap,
    'curl':       _handle_curl,
    'gobuster':   _handle_gobuster,
    'nikto':      _handle_nikto,
    'dnscat2':    _handle_dnscat2,
    'msfconsole': _handle_msfconsole,
    'nc':         _handle_nc,
    'netcat':     _handle_nc,
}


def parse_custom_commands(
    commands: str,
    attacker_ip: str,
    target_ip: str,
) -> list[SimPacket]:
    """
    Parse user-written shell commands into SimPackets.
    Lines starting with # are treated as comments and skipped.
    Returns an empty list if no valid commands are found.
    """
    packets: list[SimPacket] = []

    for line in commands.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()

        if not parts:
            continue

        # Normalise: strip path prefix (e.g. /usr/bin/nmap → nmap)
        tool = parts[0].lower().split('/')[-1]
        args = parts[1:]

        handler = _HANDLERS.get(tool)
        if handler:
            packets.extend(handler(args, attacker_ip, target_ip))
        else:
            # Unrecognised tool — emit a generic TCP probe so rules can still match
            packets.append(SimPacket(
                "tcp", attacker_ip, 50000, target_ip, 80,
                payload=f"custom-attack: {tool} {' '.join(args[:4])}",
                flags="PA", flow="to_server",
                description=f"Unknown tool: {tool}",
            ))

    return packets
