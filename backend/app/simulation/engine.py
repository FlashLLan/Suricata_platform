"""
Topology-aware Suricata rule simulation engine.
Extracts attacker + target from canvas edges, evaluates defenses,
matches rules against generated traffic, and returns educational results.
"""
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from app.simulation.rule_parser import ParsedRule, parse_rule
from app.simulation.scenarios import SimPacket, build_scenario
from app.simulation.defenses import evaluate_defenses


class SimulationValidationError(Exception):
    """Raised when the topology fails pre-flight checks."""


# ─── Scenario prerequisites ───────────────────────────────────────────────────
# Maps scenario_id → what the primary target must expose for the attack to make sense.
#   required_ports:  at least one must appear in the target's configured ports
#                    (None = no port requirement)
#   required_types:  target's deviceType must be in this list
#                    (None = any device type)

_SCENARIO_PREREQS: dict[str, dict] = {
    "ssh-brute-force": {
        "required_ports":  [22],
        "required_types":  None,
        "port_label":      "SSH (port 22)",
    },
    "http-brute-force": {
        "required_ports":  [80, 443, 8080],
        "required_types":  None,
        "port_label":      "HTTP or HTTPS (port 80, 443, or 8080)",
    },
    "sql-injection": {
        "required_ports":  [80, 443, 8080],
        "required_types":  ["web-server"],
        "port_label":      "HTTP or HTTPS (port 80, 443, or 8080)",
        "type_label":      "Web Server",
    },
    # Recon / flood — target any reachable host, no specific service needed
    "nmap-syn-scan":   {"required_ports": None, "required_types": None},
    "ping-sweep":      {"required_ports": None, "required_types": None},
    # DNS tunneling traffic goes outbound to an external resolver, not the BFS target
    "dns-tunneling":   {"required_ports": None, "required_types": None},
    # C2 beacon — internal host phones home to attacker; attacker IS the server
    "http-c2-beacon":  {"required_ports": None, "required_types": None},
    "normal-browsing": {"required_ports": None, "required_types": None},
}


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
    # topology-aware additions
    attacker_ip: str = ""
    target_ips: list[str] = field(default_factory=list)
    attack_path: list[list[str]] = field(default_factory=list)   # [[src_ip, dst_ip], ...]
    defense_impacts: list[dict] = field(default_factory=list)
    attack_blocked: bool = False
    attack_reached_target: bool = True
    # IDS visibility
    ids_visible: bool = True          # was any IDS sensor on the attack path?
    ids_node_labels: list[str] = field(default_factory=list)  # labels of observing IDS nodes


def _parse_ports(ports_str: str) -> set[int]:
    """Parse a comma-separated port string (e.g. '22,80,443') into a set of ints."""
    result: set[int] = set()
    for part in ports_str.split(","):
        part = part.strip()
        if part.isdigit():
            result.add(int(part))
    return result


def _check_prerequisites(scenario_id: str, target_nodes: list[dict]) -> None:
    """
    Verify the primary target exposes the service the chosen attack requires.
    Raises SimulationValidationError with an educational explanation on failure.
    """
    prereq = _SCENARIO_PREREQS.get(scenario_id)
    if not prereq or not target_nodes:
        return

    target    = target_nodes[0]
    data      = target.get("data", {})
    label     = data.get("label", "target device")
    dev_type  = data.get("deviceType", "")
    open_ports = _parse_ports(data.get("ports", ""))

    required_types = prereq.get("required_types")
    required_ports = prereq.get("required_ports")
    port_label     = prereq.get("port_label", "the required port")
    type_label     = prereq.get("type_label", "")
    attack_name    = scenario_id.replace("-", " ").title()

    # ── Device-type check ────────────────────────────────────────────────────
    if required_types and dev_type not in required_types:
        expected = f"a {type_label}" if type_label else f"one of: {', '.join(required_types)}"
        raise SimulationValidationError(
            f"{attack_name} targets web applications and requires the target to be {expected}. "
            f"'{label}' is configured as a '{dev_type.replace('-', ' ')}'. "
            f"Change the device type in Device Config to 'Web Server', or pick a different target."
        )

    # ── Port check ───────────────────────────────────────────────────────────
    if required_ports:
        if not open_ports:
            raise SimulationValidationError(
                f"{attack_name} requires {port_label} to be open on the target. "
                f"'{label}' has no ports configured. "
                f"Open Device Config and add the required port to the 'Open Ports' field."
            )
        if not any(p in open_ports for p in required_ports):
            listed = ", ".join(str(p) for p in sorted(open_ports))
            raise SimulationValidationError(
                f"{attack_name} requires {port_label} to be open on the target. "
                f"'{label}' exposes [{listed}] — none match the required service. "
                f"Add the correct port in Device Config, or choose an appropriate target."
            )


def run_simulation(
    scenario_id: str,
    rule_texts: list[str],
    topology: dict,
) -> SimulationResult:
    """
    Run the simulation engine.

    topology expected shape:
      nodes: [{ id, data: { ip, zone, deviceType, label, noDefense, enabledDefenses } }]
      edges: [{ source, target }]

    Raises SimulationValidationError if the topology is invalid for simulation.
    """
    # ── 1. Validate and extract attack path ──────────────────────────────────
    attacker_node = _find_attacker(topology)
    if not attacker_node:
        raise SimulationValidationError(
            "No attacker device found in the topology. "
            "Add an Attacker node to the canvas first."
        )

    target_nodes, attack_path, visited_node_ids = _find_targets(topology, attacker_node)
    if not target_nodes:
        raise SimulationValidationError(
            "The attacker is not connected to any target device. "
            "Draw a connection from the Attacker to at least one other device."
        )

    attacker_ip = attacker_node["data"].get("ip", "203.0.113.10")
    target_ips = [n["data"].get("ip", "") for n in target_nodes if n["data"].get("ip")]
    if not target_ips:
        raise SimulationValidationError(
            "Target device(s) have no IP address set. "
            "Assign an IP to each device before running the simulation."
        )

    # ── 2. Check service / port prerequisites ────────────────────────────────
    _check_prerequisites(scenario_id, target_nodes)

    # ── 3. Resolve HOME_NET / EXTERNAL_NET ───────────────────────────────────
    home_ips, external_ips = _resolve_networks(topology)
    home_net_str = ", ".join(home_ips) if home_ips else "192.168.1.0/24"

    # ── 5. Evaluate defenses ─────────────────────────────────────────────────
    defense_impacts, attack_blocked = evaluate_defenses(scenario_id, target_nodes)

    # ── 6. Build traffic packets ──────────────────────────────────────────────
    primary_target = target_ips[0]
    packets = build_scenario(scenario_id, attacker_ip, primary_target, home_ips, external_ips)

    # ── 7. Check IDS visibility ───────────────────────────────────────────────
    ids_visible, ids_node_labels = _find_ids_visibility(topology, visited_node_ids)

    # ── 8. Parse and evaluate rules (only if IDS can see the traffic) ─────────
    parsed_rules: list[tuple[str, ParsedRule]] = []
    for raw in rule_texts:
        pr = parse_rule(raw)
        if pr:
            parsed_rules.append((raw, pr))

    results: list[RuleMatchResult] = []
    if not ids_visible:
        # IDS not on path — produce blind results so the UI can explain why
        no_ids_in_topology = not any(
            n.get("data", {}).get("deviceType") == "ids"
            for n in topology.get("nodes", [])
        )
        blind_why = (
            "No Suricata IDS sensor is deployed in this topology."
            if no_ids_in_topology
            else
            "The IDS sensor is not connected to any node on the attack path. "
            "Move the IDS monitoring link to a device the attack passes through."
        )
        for _raw, pr in parsed_rules:
            results.append(RuleMatchResult(
                rule_sid=pr.sid,
                rule_msg=pr.msg,
                fired=False,
                explanation="IDS had no visibility into this traffic — rule was not evaluated.",
                why_not=blind_why,
            ))
    else:
        for raw, pr in parsed_rules:
            result = _evaluate_rule(pr, packets, home_ips, external_ips, scenario_id)
            results.append(result)

    triggered = sum(1 for r in results if r.fired)
    total = len(rule_texts)

    # ── 9. Build summary ──────────────────────────────────────────────────────
    if attack_blocked:
        summary = (
            f"Attack blocked by defenses on {', '.join(n['data'].get('label', 'target') for n in target_nodes)}. "
            f"{triggered} of {total} IDS rule(s) also triggered."
        )
    elif not ids_visible:
        no_ids_in_topology = not any(
            n.get("data", {}).get("deviceType") == "ids"
            for n in topology.get("nodes", [])
        )
        if no_ids_in_topology:
            summary = (
                f"No IDS sensor deployed — the {scenario_id.replace('-', ' ')} attack "
                f"reached {primary_target} completely unmonitored."
            )
        else:
            summary = (
                f"IDS sensor is not on the attack path — the {scenario_id.replace('-', ' ')} "
                f"attack reached {primary_target} undetected. Connect the IDS to a node on the route."
            )
    elif triggered == 0:
        summary = (
            f"No IDS rules triggered — the {scenario_id.replace('-', ' ')} attack reached "
            f"{primary_target} undetected despite IDS visibility."
        )
    elif triggered == total:
        summary = (
            f"All {total} rule(s) triggered — {', '.join(ids_node_labels)} detected the "
            f"{scenario_id.replace('-', ' ')} attack."
        )
    else:
        summary = (
            f"{triggered} of {total} rule(s) triggered by {scenario_id.replace('-', ' ')} "
            f"targeting {primary_target}. IDS: {', '.join(ids_node_labels)}."
        )

    return SimulationResult(
        scenario=scenario_id,
        total_packets=len(packets),
        triggered_count=triggered,
        results=results,
        summary=summary,
        home_net=home_net_str,
        attacker_ip=attacker_ip,
        target_ips=target_ips,
        attack_path=attack_path,
        defense_impacts=defense_impacts,
        attack_blocked=attack_blocked,
        attack_reached_target=not attack_blocked,
        ids_visible=ids_visible,
        ids_node_labels=ids_node_labels,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Topology helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_attacker(topology: dict) -> Optional[dict]:
    """Return the first node whose deviceType is 'attacker'."""
    for node in topology.get("nodes", []):
        if node.get("data", {}).get("deviceType") == "attacker":
            return node
    return None


def _find_targets(
    topology: dict,
    attacker_node: dict,
) -> tuple[list[dict], list[list[str]], set[str]]:
    """
    BFS from the attacker node through communication edges only.

    Returns:
        (target_nodes, attack_path, visited_node_ids)

        target_nodes:     all reachable non-attacker nodes
        attack_path:      list of [src_ip, dst_ip] hops for animation
        visited_node_ids: set of all node IDs on the traversed path (used for IDS visibility)
    """
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in topology.get("nodes", [])}
    edges = topology.get("edges", [])

    # Build undirected adjacency — only include edges that represent real communication paths.
    # Monitoring edges (IDS taps) and invalid edges (no-route, blocked) are excluded so the
    # BFS path-finder cannot route traffic through them.
    adj: dict[str, list[str]] = {}
    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if not src or not tgt:
            continue

        edge_data = edge.get("data") or {}

        # Skip IDS monitoring links — they are passive taps, not communication paths
        if edge_data.get("monitoringOnly"):
            continue

        # Skip edges where communication is explicitly disallowed (no-route, blocked).
        # Default True preserves backward compatibility with saves that predate this field.
        if not edge_data.get("communicationAllowed", True):
            continue

        adj.setdefault(src, []).append(tgt)
        adj.setdefault(tgt, []).append(src)

    attacker_id = attacker_node["id"]
    attacker_ip = attacker_node.get("data", {}).get("ip", "")

    visited: set[str] = {attacker_id}
    queue: deque[tuple[str, list[str]]] = deque()  # (node_id, path_of_node_ids)
    queue.append((attacker_id, [attacker_id]))

    target_nodes: list[dict] = []
    attack_path: list[list[str]] = []

    while queue:
        current_id, path = queue.popleft()
        for neighbor_id in adj.get(current_id, []):
            if neighbor_id in visited:
                continue
            visited.add(neighbor_id)

            neighbor_node = nodes_by_id.get(neighbor_id)
            if not neighbor_node:
                continue

            neighbor_ip = neighbor_node.get("data", {}).get("ip", "")
            current_ip = nodes_by_id[current_id].get("data", {}).get("ip", "")

            # Record each hop as [src_ip, dst_ip]
            if current_ip and neighbor_ip:
                attack_path.append([current_ip, neighbor_ip])

            if neighbor_node.get("data", {}).get("deviceType") != "attacker":
                target_nodes.append(neighbor_node)
                queue.append((neighbor_id, path + [neighbor_id]))

    return target_nodes, attack_path, visited


def _find_ids_visibility(
    topology: dict,
    visited_node_ids: set[str],
) -> tuple[bool, list[str]]:
    """
    Check whether any IDS node has a monitoring edge to a node on the attack path.

    An IDS "sees" a flow if it has any edge (monitoring link) to a node that was
    traversed during the BFS — attacker, intermediary infrastructure, or target.

    Returns:
        (ids_visible, ids_node_labels)
    """
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in topology.get("nodes", [])}

    ids_node_ids: set[str] = {
        n["id"] for n in topology.get("nodes", [])
        if n.get("data", {}).get("deviceType") == "ids"
    }

    if not ids_node_ids:
        return False, []

    visible_labels: list[str] = []
    seen_ids: set[str] = set()

    for edge in topology.get("edges", []):
        src = edge.get("source", "")
        tgt = edge.get("target", "")

        # Identify which end is the IDS and which is the monitored node
        if src in ids_node_ids:
            ids_id, monitored_id = src, tgt
        elif tgt in ids_node_ids:
            ids_id, monitored_id = tgt, src
        else:
            continue

        # IDS has visibility if the monitored node was on the attack path
        if monitored_id in visited_node_ids and ids_id not in seen_ids:
            seen_ids.add(ids_id)
            label = nodes_by_id.get(ids_id, {}).get("data", {}).get("label", "Suricata IDS")
            visible_labels.append(label)

    return bool(visible_labels), visible_labels


def _resolve_networks(topology: dict) -> tuple[list[str], list[str]]:
    """Extract internal and external IPs from topology nodes by zone."""
    home: list[str] = []
    external: list[str] = []

    for node in topology.get("nodes", []):
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


# ─────────────────────────────────────────────────────────────────────────────
# Rule matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ip_matches(rule_ip: str, packet_ip: str, home_ips: list[str], ext_ips: list[str]) -> bool:
    if rule_ip in ("any", "!any"):
        return True
    if rule_ip == "$HOME_NET":
        return packet_ip in home_ips
    if rule_ip == "$EXTERNAL_NET":
        return packet_ip in ext_ips or packet_ip not in home_ips
    if "/" in rule_ip:
        base = ".".join(rule_ip.split(".")[:3])
        return packet_ip.startswith(base)
    return rule_ip == packet_ip


def _port_matches(rule_port: str, packet_port: int) -> bool:
    rule_port = rule_port.strip()
    if rule_port == "$HTTP_PORTS":
        return packet_port in (80, 8080, 8443, 8888, 3000, 5000)
    if rule_port == "any":
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
            flag_chars = re.sub(r'[^SAFRPUECB]', '', rule.flags.split(",")[0].upper())
            if flag_chars and not all(f in pkt.flags.upper() for f in flag_chars):
                continue

        if not _flow_matches(rule, pkt):
            continue

        if not _content_matches(rule, pkt):
            continue

        if rule.dsize_gt is not None and len(pkt.payload) <= rule.dsize_gt:
            continue

        matched.append(pkt)

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
            for p in matched[:10]
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
            f"Threshold reached: {len(matched)} packets matched "
            f"(threshold was {rule.threshold_count} in {rule.threshold_seconds}s)."
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
    proto_match = [p for p in all_packets if _protocol_matches(rule.protocol, p.protocol)]
    if not proto_match:
        return (
            f"Protocol mismatch: rule expects '{rule.protocol}' but the scenario "
            f"generated {set(p.protocol for p in all_packets)} traffic."
        )

    content_fails = [p for p in proto_match if not _content_matches(rule, p)]
    if content_fails and len(content_fails) == len(proto_match):
        kws = rule.content + rule.nocase_content
        return (
            f"Content keywords {kws} were not found in any packet payload for this scenario."
        )

    threshold = rule.threshold_count or 1
    if matched and len(matched) < threshold:
        return (
            f"Threshold not reached: {len(matched)} packet(s) matched but "
            f"{threshold} are needed within {rule.threshold_seconds}s."
        )

    return (
        "The traffic in this scenario does not match this rule's protocol, "
        "port, IP range, or payload conditions."
    )
