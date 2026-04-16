"""
Simplified Suricata rule simulation engine.
Matches parsed rules against simulated traffic packets and returns educational results.
"""
from dataclasses import dataclass, field
from typing import Optional

from app.simulation.rule_parser import ParsedRule, parse_rule
from app.simulation.scenarios import SimPacket, build_scenario


@dataclass
class RuleMatchResult:
    rule_sid: str
    rule_msg: str
    fired: bool
    matched_packets: list[dict] = field(default_factory=list)
    explanation: str = ""
    why_not: Optional[str] = None


@dataclass
class SimulationResult:
    scenario: str
    total_packets: int
    triggered_count: int
    results: list[RuleMatchResult] = field(default_factory=list)
    summary: str = ""
    home_net: str = ""


def run_simulation(
    scenario_id: str,
    rule_texts: list[str],
    topology: dict,
) -> SimulationResult:
    """
    Run the simulation engine.

    topology expected keys:
      nodes: list of { data: { ip, zone, deviceType } }
    """
    # Resolve HOME_NET and EXTERNAL_NET from topology
    home_ips, external_ips = _resolve_networks(topology)
    home_net_str = ", ".join(home_ips) if home_ips else "192.168.1.0/24"

    # Build traffic for this scenario
    packets = build_scenario(scenario_id, home_ips, external_ips)

    # Parse rules
    parsed_rules: list[tuple[str, ParsedRule]] = []
    for raw in rule_texts:
        pr = parse_rule(raw)
        if pr:
            parsed_rules.append((raw, pr))

    results: list[RuleMatchResult] = []
    for raw, pr in parsed_rules:
        result = _evaluate_rule(pr, packets, home_ips, external_ips, scenario_id)
        results.append(result)

    triggered = sum(1 for r in results if r.fired)
    total = len(rule_texts)

    if triggered == 0:
        summary = f"No rules triggered against the {scenario_id.replace('-', ' ')} scenario."
    elif triggered == total:
        summary = f"All {total} rule(s) triggered — good coverage for this scenario."
    else:
        summary = f"{triggered} of {total} rule(s) triggered."

    return SimulationResult(
        scenario=scenario_id,
        total_packets=len(packets),
        triggered_count=triggered,
        results=results,
        summary=summary,
        home_net=home_net_str,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_networks(topology: dict) -> tuple[list[str], list[str]]:
    """Extract internal and external IPs from the topology JSON."""
    home: list[str] = []
    external: list[str] = []

    nodes = topology.get("nodes", [])
    for node in nodes:
        data = node.get("data", {})
        ip = data.get("ip", "").strip()
        zone = data.get("zone", "internal")
        if not ip:
            continue
        if zone in ("internal", "dmz", "management"):
            home.append(ip)
        else:
            external.append(ip)

    if not home:
        home = ["192.168.1.10", "192.168.1.20"]
    if not external:
        external = ["203.0.113.10"]

    return home, external


def _ip_matches(rule_ip: str, packet_ip: str, home_ips: list[str], ext_ips: list[str]) -> bool:
    if rule_ip in ("any", "!any"):
        return True
    if rule_ip == "$HOME_NET":
        return packet_ip in home_ips
    if rule_ip == "$EXTERNAL_NET":
        return packet_ip in ext_ips or packet_ip not in home_ips
    if rule_ip == "any":
        return True
    # Simple CIDR check (first 3 octets)
    if "/" in rule_ip:
        base = ".".join(rule_ip.split(".")[:3])
        return packet_ip.startswith(base)
    return rule_ip == packet_ip


def _port_matches(rule_port: str, packet_port: int) -> bool:
    rule_port = rule_port.strip()
    if rule_port in ("any", "$HTTP_PORTS"):
        if rule_port == "$HTTP_PORTS":
            return packet_port in (80, 8080, 8443, 8888, 3000, 5000)
        return True
    if rule_port.startswith("!"):
        return not _port_matches(rule_port[1:], packet_port)
    if ":" in rule_port:
        lo, hi = rule_port.split(":")
        return int(lo) <= packet_port <= int(hi)
    try:
        return int(rule_port) == packet_port
    except ValueError:
        return True


def _protocol_matches(rule_proto: str, pkt_proto: str) -> bool:
    if rule_proto == "tcp" and pkt_proto in ("tcp", "http", "https"):
        return True
    if rule_proto == "udp" and pkt_proto in ("udp", "dns"):
        return True
    if rule_proto == "icmp" and pkt_proto == "icmp":
        return True
    if rule_proto in ("http", "http2") and pkt_proto in ("tcp", "http"):
        return True
    if rule_proto == "dns" and pkt_proto in ("udp", "dns"):
        return True
    return rule_proto == pkt_proto


def _content_matches(rule: ParsedRule, packet: SimPacket) -> bool:
    """Check if rule content keywords appear in packet payload."""
    payload = packet.payload
    payload_lower = payload.lower()

    for kw in rule.content:
        if kw not in payload:
            return False

    for kw in rule.nocase_content:
        if kw not in payload_lower:
            return False

    return True


def _flow_matches(rule: ParsedRule, packet: SimPacket) -> bool:
    if not rule.flow:
        return True
    flow = rule.flow
    if "established" in flow and packet.flow not in ("established", "to_server", "to_client"):
        return False
    if "to_server" in flow and packet.flow not in ("to_server", "established"):
        return False
    if "to_client" in flow and packet.flow != "to_client":
        return False
    return True


def _evaluate_rule(
    rule: ParsedRule,
    packets: list[SimPacket],
    home_ips: list[str],
    ext_ips: list[str],
    scenario_id: str,
) -> RuleMatchResult:
    matched: list[SimPacket] = []

    for pkt in packets:
        if not _protocol_matches(rule.protocol, pkt.protocol):
            continue

        src_ok = _ip_matches(rule.src_ip, pkt.src_ip, home_ips, ext_ips)
        dst_ok = _ip_matches(rule.dst_ip, pkt.dst_ip, home_ips, ext_ips)
        sport_ok = _port_matches(rule.src_port, pkt.src_port)
        dport_ok = _port_matches(rule.dst_port, pkt.dst_port)

        if not (src_ok and dst_ok and sport_ok and dport_ok):
            continue

        if rule.flags and rule.flags.split(",")[0]:
            flag_chars = rule.flags.split(",")[0].upper()
            # Only check non-modifier flags
            flag_chars = re.sub(r'[^SAFRPUECB]', '', flag_chars)
            if flag_chars and not all(f in pkt.flags.upper() for f in flag_chars):
                continue

        if not _flow_matches(rule, pkt):
            continue

        if not _content_matches(rule, pkt):
            continue

        if rule.dsize_gt is not None and len(pkt.payload) <= rule.dsize_gt:
            continue

        matched.append(pkt)

    # Apply threshold: must have enough matching packets
    threshold = rule.threshold_count or 1
    fired = len(matched) >= threshold

    return RuleMatchResult(
        rule_sid=rule.sid,
        rule_msg=rule.msg,
        fired=fired,
        matched_packets=[
            {
                "protocol": p.protocol,
                "src": f"{p.src_ip}:{p.src_port}",
                "dst": f"{p.dst_ip}:{p.dst_port}",
                "description": p.description,
                "payload_preview": p.payload[:120],
            }
            for p in matched[:10]   # cap at 10 for readability
        ],
        explanation=_build_explanation(rule, matched, fired, scenario_id),
        why_not=_build_why_not(rule, packets, matched, home_ips, ext_ips) if not fired else None,
    )


def _build_explanation(rule: ParsedRule, matched: list[SimPacket], fired: bool, scenario: str) -> str:
    if not fired:
        return f"Rule did not fire in the '{scenario.replace('-', ' ')}' scenario."

    parts = [f"Rule fired — {len(matched)} matching packet(s) detected."]

    if rule.threshold_count and rule.threshold_count > 1:
        parts.append(
            f"Threshold reached: {len(matched)} packets matched (threshold was {rule.threshold_count} "
            f"in {rule.threshold_seconds}s)."
        )

    keywords = rule.nocase_content + rule.content
    if keywords:
        kw_list = ", ".join(f'"{k}"' for k in keywords[:4])
        parts.append(f"Content keywords matched: {kw_list}.")

    if rule.protocol == "icmp":
        parts.append("ICMP type matched (echo request = type 8).")

    if "brute" in rule.msg.lower() or rule.threshold_count:
        parts.append(
            "The high packet count from a single source is the key indicator — "
            "legitimate users don't generate this many connections in such a short window."
        )

    return " ".join(parts)


def _build_why_not(
    rule: ParsedRule,
    all_packets: list[SimPacket],
    matched: list[SimPacket],
    home_ips: list[str],
    ext_ips: list[str],
) -> str:
    reasons: list[str] = []

    proto_match = [p for p in all_packets if _protocol_matches(rule.protocol, p.protocol)]
    if not proto_match:
        reasons.append(
            f"Protocol mismatch: rule expects '{rule.protocol}' but the scenario "
            f"generated {set(p.protocol for p in all_packets)} traffic."
        )
        return " ".join(reasons)

    content_fails = [
        p for p in proto_match
        if not _content_matches(rule, p)
    ]
    if content_fails and len(content_fails) == len(proto_match):
        kws = rule.content + rule.nocase_content
        reasons.append(
            f"Content keywords {kws} were not found in any packet payload for this scenario."
        )

    threshold = rule.threshold_count or 1
    if matched and len(matched) < threshold:
        reasons.append(
            f"Threshold not reached: {len(matched)} packet(s) matched but "
            f"{threshold} are needed within {rule.threshold_seconds}s."
        )

    if not reasons:
        reasons.append(
            "The traffic in this scenario does not match this rule's protocol, "
            "port, IP range, or payload conditions."
        )

    return " ".join(reasons)


# Need re for flags parsing
import re
