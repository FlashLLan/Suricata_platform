"""
Topology-aware Suricata rule simulation engine.
Extracts attacker + target from canvas edges, evaluates defenses,
matches rules against generated traffic, and returns educational results.
"""
import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from app.simulation.rule_parser import ParsedRule, parse_rule
from app.simulation.scenarios import SimPacket, build_scenario
from app.simulation.defenses import evaluate_defenses


class SimulationValidationError(Exception):
    """Raised when the topology fails pre-flight checks."""


# ─── Zone policy ─────────────────────────────────────────────────────────────
# Zone pairs that are denied when connected DIRECTLY (without a gateway between them).
# Source: topology.md §6 zone communication baseline table.
_DENIED_DIRECT_ZONE_PAIRS: frozenset[frozenset] = frozenset({
    frozenset({"external", "internal"}),    # external → internal: deny by default
    frozenset({"external", "management"}),  # external → management: deny
})

# Scenarios where the attacker acts as a server (C2, DNS resolver proxy, normal web).
# Traffic is initiated by an internal host, so the external↔internal check doesn't apply.
_SKIP_ZONE_CHECK: set[str] = {"normal-browsing", "http-c2-beacon", "dns-tunneling"}

# Infrastructure device types that are allowed to bridge zones
_GATEWAY_DEVICE_TYPES: set[str] = {"router", "firewall"}

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
    # Event timeline
    timeline: list[dict] = field(default_factory=list)


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


def _check_zone_policy(
    scenario_id: str,
    topology: dict,
    visited_node_ids: set[str],
) -> None:
    """
    Verify that no hop in the attack path crosses a denied zone boundary without
    a gateway (router or firewall) acting as intermediary.

    Skipped for scenarios where traffic is internally initiated (C2 beacon, DNS
    tunneling, normal browsing) since the attacker there acts as a remote server,
    not an external aggressor.

    Raises SimulationValidationError with an educational explanation on violation.
    """
    if scenario_id in _SKIP_ZONE_CHECK:
        return

    nodes_by_id: dict[str, dict] = {
        n["id"]: n.get("data", {}) for n in topology.get("nodes", [])
    }

    for edge in topology.get("edges", []):
        edge_data = edge.get("data") or {}

        # Only inspect communication edges (skip monitoring / blocked / no-route)
        if edge_data.get("monitoringOnly"):
            continue
        if not edge_data.get("communicationAllowed", True):
            continue

        src_id = edge.get("source", "")
        tgt_id = edge.get("target", "")

        # Only edges where both endpoints were traversed by the BFS
        if src_id not in visited_node_ids or tgt_id not in visited_node_ids:
            continue

        src_data = nodes_by_id.get(src_id, {})
        tgt_data = nodes_by_id.get(tgt_id, {})

        src_zone = src_data.get("zone", "internal")
        tgt_zone = tgt_data.get("zone", "internal")
        src_type = src_data.get("deviceType", "")
        tgt_type = tgt_data.get("deviceType", "")

        zone_pair = frozenset({src_zone, tgt_zone})
        if zone_pair not in _DENIED_DIRECT_ZONE_PAIRS:
            continue

        # Allowed if a gateway is one of the endpoints (it bridges the zones)
        if src_type in _GATEWAY_DEVICE_TYPES or tgt_type in _GATEWAY_DEVICE_TYPES:
            continue

        # Direct violation — build a clear educational message
        src_label = src_data.get("label", src_type or src_id)
        tgt_label = tgt_data.get("label", tgt_type or tgt_id)

        if "external" in zone_pair and "internal" in zone_pair:
            raise SimulationValidationError(
                f"Direct connection between external '{src_label}' and internal '{tgt_label}' "
                f"is not allowed — in real networks, external traffic cannot reach internal hosts "
                f"without passing through a Firewall or Router. "
                f"Add a Firewall between them and reconnect through it."
            )
        if "external" in zone_pair and "management" in zone_pair:
            raise SimulationValidationError(
                f"Direct connection from the external zone to management zone '{tgt_label}' "
                f"is denied — management interfaces must never be reachable from external networks. "
                f"Place a Firewall between them."
            )


def _build_timeline(
    attack_path: list[list[str]],
    topology: dict,
    defense_impacts: list[dict],
    attack_blocked: bool,
    ids_visible: bool,
    ids_node_labels: list[str],
    rule_results: list[RuleMatchResult],
) -> list[dict]:
    """Build a step-by-step narrative timeline of the simulation."""

    # IP → human label lookup
    ip_to_label: dict[str, str] = {}
    for node in topology.get("nodes", []):
        ip = node.get("data", {}).get("ip", "")
        label = node.get("data", {}).get("label", "")
        if ip and label:
            ip_to_label[ip] = label

    events: list[dict] = []

    # ── 1. Path hops ──────────────────────────────────────────────────────────
    for from_ip, to_ip in attack_path:
        from_label = ip_to_label.get(from_ip, from_ip)
        to_label   = ip_to_label.get(to_ip,   to_ip)
        events.append({
            "type":       "hop",
            "label":      f"{from_label} → {to_label}",
            "detail":     f"Traffic routed from {from_label} ({from_ip}) to {to_label} ({to_ip})",
            "from_ip":    from_ip,
            "to_ip":      to_ip,
            "from_label": from_label,
            "to_label":   to_label,
        })

    # ── 2. Defense evaluation ─────────────────────────────────────────────────
    if not defense_impacts:
        events.append({
            "type":   "no_defense",
            "label":  "No defenses configured",
            "detail": "Target device has no active defense controls — all traffic permitted.",
        })
    elif attack_blocked:
        for impact in defense_impacts:
            if impact.get("blocked"):
                events.append({
                    "type":       "defense_blocked",
                    "label":      f"Blocked: {impact['defense_name']}",
                    "detail":     impact["explanation"],
                    "node_label": impact.get("device_label", ""),
                })
                break
    else:
        for impact in defense_impacts:
            events.append({
                "type":       "defense_passed",
                "label":      f"Defense evaluated — traffic passed",
                "detail":     impact["explanation"],
                "node_label": impact.get("device_label", ""),
            })

    # ── 3. IDS visibility (skip if attack already blocked) ────────────────────
    if not attack_blocked:
        if ids_visible:
            label_str = ", ".join(ids_node_labels) if ids_node_labels else "IDS"
            events.append({
                "type":       "ids_observed",
                "label":      f"{label_str} observed the traffic",
                "detail":     (
                    f"{label_str} has a monitoring link to a node on the attack path — "
                    "Suricata rule evaluation applies."
                ),
                "node_label": label_str,
            })
        else:
            no_sensor = not ids_node_labels
            events.append({
                "type":   "ids_blind",
                "label":  "IDS did not observe traffic",
                "detail": (
                    "No Suricata IDS sensor is deployed in this topology."
                    if no_sensor else
                    "An IDS sensor exists but is not connected to any node the attack passes through."
                ),
            })

    # ── 4. Rule evaluation (only when IDS visible and attack not blocked) ─────
    if not attack_blocked and ids_visible:
        fired_rules  = [r for r in rule_results if r.fired]
        missed_rules = [r for r in rule_results if not r.fired]
        for r in fired_rules:
            events.append({
                "type":   "rule_fired",
                "label":  f"Alert: {r.rule_msg or f'SID {r.rule_sid}'}",
                "detail": r.explanation,
                "sid":    r.rule_sid,
            })
        for r in missed_rules:
            events.append({
                "type":   "rule_missed",
                "label":  f"No match: {r.rule_msg or f'SID {r.rule_sid}'}",
                "detail": r.why_not or r.explanation,
                "sid":    r.rule_sid,
            })

    # ── 5. Outcome ────────────────────────────────────────────────────────────
    if attack_blocked:
        events.append({
            "type":   "outcome_blocked",
            "label":  "Attack stopped by defenses",
            "detail": "The attack was blocked before reaching its target — no traffic delivered.",
        })
    elif not ids_visible:
        events.append({
            "type":   "outcome_undetected",
            "label":  "Attack reached target — undetected",
            "detail": (
                "Traffic was delivered to the target. No IDS coverage means "
                "no detection was possible regardless of loaded rules."
            ),
        })
    elif sum(1 for r in rule_results if r.fired) > 0:
        alert_count = sum(1 for r in rule_results if r.fired)
        events.append({
            "type":   "outcome_detected",
            "label":  f"Attack reached target — {alert_count} alert(s) generated",
            "detail": (
                f"Traffic was delivered and Suricata generated {alert_count} alert(s). "
                "Detection succeeded but the attack was not blocked."
            ),
        })
    else:
        events.append({
            "type":   "outcome_undetected",
            "label":  "Attack reached target — rules did not fire",
            "detail": (
                "Traffic was delivered to the target but no loaded Suricata rules matched. "
                "Either add more rules or investigate why the existing ones missed."
            ),
        })

    return events


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

    # ── 3. Check zone policy — deny direct external↔internal without gateway ──
    _check_zone_policy(scenario_id, topology, visited_node_ids)

    # ── 4. Resolve HOME_NET / EXTERNAL_NET ───────────────────────────────────
    home_ips, external_ips = _resolve_networks(topology)
    home_net_str = ", ".join(home_ips) if home_ips else "192.168.1.0/24"

    # ── 5. Evaluate defenses ─────────────────────────────────────────────────
    defense_impacts, attack_blocked = evaluate_defenses(scenario_id, target_nodes)

    # ── 6. Build traffic packets ──────────────────────────────────────────────
    primary_target = target_ips[0]
    packets = build_scenario(scenario_id, attacker_ip, primary_target, home_ips, external_ips)

    # ── 7. Check IDS visibility ───────────────────────────────────────────────
    ids_visible, ids_node_labels = _find_ids_visibility(topology, visited_node_ids)

    # ── 8. Parse + evaluate rules (only when IDS can see traffic) ────────────
    parsed_rules: list[tuple[str, ParsedRule]] = []
    parse_errors: list[str] = []
    for raw in rule_texts:
        pr = parse_rule(raw)
        if pr:
            parsed_rules.append((raw, pr))
        else:
            parse_errors.append(raw)

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

    # Append results for rules that couldn't be parsed at all
    for raw in parse_errors:
        # Try to extract a sid/msg hint for display
        sid_hint  = (re.search(r'\bsid\s*:\s*(\d+)', raw) or re.search(r'', '')).group(1) if re.search(r'\bsid\s*:\s*(\d+)', raw) else '?'
        msg_hint  = re.search(r'\bmsg\s*:\s*"([^"]+)"', raw)
        label = msg_hint.group(1) if msg_hint else raw[:60].strip()
        results.append(RuleMatchResult(
            rule_sid=sid_hint,
            rule_msg=label,
            fired=False,
            explanation=(
                "This rule could not be parsed — it contains a syntax error. "
                "Suricata would reject it on startup. "
                "Open the IDS node panel and fix the rule syntax."
            ),
            why_not="Rule syntax is invalid: check action, header format, and that sid/msg keywords are present.",
        ))

    triggered = sum(1 for r in results if r.fired)
    total = len(rule_texts)

    # ── 9. Build event timeline ───────────────────────────────────────────────
    timeline = _build_timeline(
        attack_path=attack_path,
        topology=topology,
        defense_impacts=defense_impacts,
        attack_blocked=attack_blocked,
        ids_visible=ids_visible,
        ids_node_labels=ids_node_labels,
        rule_results=results,
    )

    # ── 10. Build summary ─────────────────────────────────────────────────────
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
        timeline=timeline,
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

# ─────────────────────────────────────────────────────────────────────────────
# Low-level matchers (protocol, IP, port, flow, content, pcre)
# ─────────────────────────────────────────────────────────────────────────────

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


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if *ip* falls inside *cidr* (e.g. '192.168.0.0/16')."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _split_ip_group(group_str: str) -> list[str]:
    """
    Split a comma-separated IP group respecting nested brackets.
    e.g. '$HOME_NET,!192.168.1.1'  →  ['$HOME_NET', '!192.168.1.1']
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in group_str:
        if ch == '[':
            depth += 1
            current.append(ch)
        elif ch == ']':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            p = ''.join(current).strip()
            if p:
                parts.append(p)
            current = []
        else:
            current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _ip_matches(rule_ip: str, packet_ip: str, home_ips: list[str], ext_ips: list[str]) -> bool:
    """
    Match a rule IP spec against a packet IP.

    Handles:
      - any
      - $HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS, $SQL_SERVERS, $DNS_SERVERS
      - negation  !<spec>
      - CIDR      192.168.0.0/16
      - exact     192.168.1.1
      - groups    [spec1,spec2,...]
    """
    rule_ip = rule_ip.strip()

    if rule_ip == "any":
        return True

    # Variables
    _VAR_HOME = {"$HOME_NET", "$HTTP_SERVERS", "$SQL_SERVERS", "$DNS_SERVERS",
                 "$SMTP_SERVERS", "$HTTP_SERVERS"}
    if rule_ip in _VAR_HOME:
        return packet_ip in home_ips
    if rule_ip == "$EXTERNAL_NET":
        return packet_ip not in home_ips

    # Negation
    if rule_ip.startswith("!"):
        return not _ip_matches(rule_ip[1:], packet_ip, home_ips, ext_ips)

    # Group  [a,b,c]
    if rule_ip.startswith("[") and rule_ip.endswith("]"):
        parts = _split_ip_group(rule_ip[1:-1])
        return any(_ip_matches(p, packet_ip, home_ips, ext_ips) for p in parts)

    # CIDR
    if "/" in rule_ip:
        return _ip_in_cidr(packet_ip, rule_ip)

    # Exact
    return rule_ip == packet_ip


def _port_matches(rule_port: str, packet_port: int) -> bool:
    """
    Match a rule port spec against an integer packet port.

    Handles:
      - any
      - $HTTP_PORTS, $SSH_PORTS, $FTP_PORTS, $DNS_PORTS
      - negation  !<spec>
      - groups    [80,443,8080]
      - ranges    1024:65535  |  :1023  |  1024:
      - exact     80
    """
    rule_port = rule_port.strip()

    # Variables
    if rule_port == "$HTTP_PORTS":
        return packet_port in (80, 8080, 8443, 8888, 3000, 5000)
    if rule_port == "$SSH_PORTS":
        return packet_port == 22
    if rule_port == "$FTP_PORTS":
        return packet_port in (20, 21)
    if rule_port == "$DNS_PORTS":
        return packet_port == 53
    if rule_port == "$SHELLCODE_PORTS":
        return packet_port > 1023

    if rule_port == "any":
        return True

    # Negation
    if rule_port.startswith("!"):
        return not _port_matches(rule_port[1:], packet_port)

    # Group  [80,443,8080]
    if rule_port.startswith("[") and rule_port.endswith("]"):
        parts = rule_port[1:-1].split(",")
        return any(_port_matches(p.strip(), packet_port) for p in parts)

    # Range  lo:hi  |  lo:  |  :hi
    if ":" in rule_port:
        lo_s, hi_s = rule_port.split(":", 1)
        lo = int(lo_s) if lo_s.strip() else 0
        hi = int(hi_s) if hi_s.strip() else 65535
        return lo <= packet_port <= hi

    try:
        return int(rule_port) == packet_port
    except ValueError:
        return True   # unknown variable — don't block


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


def _content_matches(rule: ParsedRule, packet: SimPacket) -> bool:
    """
    Check all content keywords against the packet payload.

    Sticky buffer content (http.uri, http.method, http.header) is matched
    against the full payload — our simulated packets embed all HTTP information
    (method, URI, headers) inline in the payload string, so this is accurate
    for educational purposes.
    """
    payload = packet.payload
    payload_lower = payload.lower()

    # Plain content (case-sensitive)
    for kw in rule.content:
        if kw not in payload:
            return False

    # content + nocase (stored lower-cased)
    for kw in rule.nocase_content:
        if kw not in payload_lower:
            return False

    # Sticky buffer content — always compared case-insensitively because HTTP
    # URIs, methods, and headers are treated case-insensitively by convention.
    for kw in rule.http_uri_content:
        if kw.lower() not in payload_lower:
            return False

    for kw in rule.http_method_content:
        if kw.lower() not in payload_lower:
            return False

    for kw in rule.http_header_content:
        if kw.lower() not in payload_lower:
            return False

    return True


def _pcre_matches(rule: ParsedRule, packet: SimPacket) -> bool:
    """
    Evaluate PCRE patterns against the packet payload.
    Supports /i (IGNORECASE), /s (DOTALL), /m (MULTILINE) flags.
    Invalid regex patterns are silently skipped (don't block the match).
    """
    if not rule.pcre:
        return True

    text = packet.payload

    for pattern_str in rule.pcre:
        # Strip Perl-style /pattern/flags wrapper
        pm = re.match(r'^/(.+)/([gimsIxAEGRUPHDCKMSYCBOV]*)$', pattern_str, re.DOTALL)
        if pm:
            pattern   = pm.group(1)
            flags_str = pm.group(2).lower()
            re_flags  = 0
            if 'i' in flags_str:
                re_flags |= re.IGNORECASE
            if 's' in flags_str:
                re_flags |= re.DOTALL
            if 'm' in flags_str:
                re_flags |= re.MULTILINE
            try:
                if not re.search(pattern, text, re_flags):
                    return False
            except re.error:
                pass   # malformed regex — don't penalise
        else:
            # No wrapper — treat as literal substring
            if pattern_str not in text:
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

        if not _pcre_matches(rule, pkt):
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

    keywords = (
        rule.content + rule.nocase_content
        + rule.http_uri_content + rule.http_method_content + rule.http_header_content
    )
    if keywords:
        kw_list = ", ".join(f'"{k}"' for k in keywords[:4])
        parts.append(f"Content keywords matched: {kw_list}.")
    if rule.pcre:
        parts.append(f"PCRE pattern matched: {rule.pcre[0]!r}.")

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
    """
    Walk through each check in order and report the first one that eliminates
    all packets — gives students a precise, actionable explanation.
    """
    # ── Protocol ─────────────────────────────────────────────────────────────
    proto_pass = [p for p in all_packets if _protocol_matches(rule.protocol, p.protocol)]
    if not proto_pass:
        protos = sorted({p.protocol for p in all_packets})
        return (
            f"Protocol mismatch: rule checks '{rule.protocol}' traffic, "
            f"but this scenario only generates {protos} packets. "
            f"Change the rule protocol to match, or pick a scenario that produces "
            f"'{rule.protocol}' traffic."
        )

    # ── IP addresses ──────────────────────────────────────────────────────────
    ip_pass = [
        p for p in proto_pass
        if _ip_matches(rule.src_ip, p.src_ip, home_ips, ext_ips)
        and _ip_matches(rule.dst_ip, p.dst_ip, home_ips, ext_ips)
    ]
    if not ip_pass:
        src_ips = sorted({p.src_ip for p in proto_pass})
        dst_ips = sorted({p.dst_ip for p in proto_pass})
        return (
            f"IP address mismatch: rule expects src={rule.src_ip} → dst={rule.dst_ip}, "
            f"but scenario traffic goes {src_ips} → {dst_ips}. "
            f"Check that $HOME_NET / $EXTERNAL_NET align with your topology zones, "
            f"or adjust the IP fields in your rule."
        )

    # ── Ports ─────────────────────────────────────────────────────────────────
    port_pass = [
        p for p in ip_pass
        if _port_matches(rule.src_port, p.src_port)
        and _port_matches(rule.dst_port, p.dst_port)
    ]
    if not port_pass:
        dst_ports = sorted({p.dst_port for p in ip_pass})
        return (
            f"Port mismatch: rule expects src port {rule.src_port} / "
            f"dst port {rule.dst_port}, but scenario uses destination "
            f"port(s) {dst_ports}. "
            f"Update the port in your rule or verify the target device's open ports."
        )

    # ── TCP flags ─────────────────────────────────────────────────────────────
    flag_pass: list[SimPacket] = []
    if rule.flags:
        flag_chars = re.sub(r'[^SAFRPUECB]', '', rule.flags.split(",")[0].upper())
        for p in port_pass:
            if flag_chars and not all(f in p.flags.upper() for f in flag_chars):
                continue
            flag_pass.append(p)
        if not flag_pass:
            pkt_flags = sorted({p.flags for p in port_pass})
            return (
                f"TCP flags mismatch: rule requires flags='{rule.flags}', "
                f"but packets in this scenario carry flags {pkt_flags}. "
                f"Adjust the flags keyword, or remove it to match any flags."
            )
    else:
        flag_pass = port_pass

    # ── Flow state ────────────────────────────────────────────────────────────
    flow_pass = [p for p in flag_pass if _flow_matches(rule, p)]
    if not flow_pass:
        pkt_flows = sorted({p.flow for p in flag_pass})
        hint = ""
        if "established" in rule.flow:
            hint = (
                " 'flow:established' only matches mid-session packets (data exchange), "
                "not SYN/handshake packets."
            )
        return (
            f"Flow state mismatch: rule requires flow='{rule.flow}', "
            f"but scenario packets are marked as {pkt_flows}.{hint}"
        )

    # ── Content keywords ──────────────────────────────────────────────────────
    content_pass = [p for p in flow_pass if _content_matches(rule, p)]
    if not content_pass:
        all_kws = (
            rule.content
            + rule.nocase_content
            + [k.upper() for k in rule.http_uri_content]    # show original case
            + [k.upper() for k in rule.http_method_content]
            + [k.upper() for k in rule.http_header_content]
        )
        if all_kws:
            kw_list = ", ".join(repr(k) for k in all_kws[:4])
            return (
                f"Content not found: keyword(s) {kw_list} were not present in any "
                f"matching packet's payload for this scenario. "
                f"The scenario may not generate traffic containing these strings."
            )

    # ── PCRE ──────────────────────────────────────────────────────────────────
    pcre_pass = [p for p in (content_pass or flow_pass) if _pcre_matches(rule, p)]
    if rule.pcre and not pcre_pass:
        return (
            f"PCRE pattern(s) {rule.pcre[:2]} did not match any packet payload "
            f"in this scenario. Verify the regex against the expected traffic."
        )

    # ── Threshold ─────────────────────────────────────────────────────────────
    threshold = rule.threshold_count or 1
    if matched and len(matched) < threshold:
        return (
            f"Threshold not reached: {len(matched)} packet(s) matched but "
            f"{threshold} are required within {rule.threshold_seconds}s. "
            f"This scenario may not generate enough repeated packets to cross the threshold."
        )

    return (
        "No packets matched all conditions simultaneously "
        "(protocol + IPs + ports + flags + flow + content). "
        "This rule may be designed for a different traffic pattern than this scenario generates."
    )
