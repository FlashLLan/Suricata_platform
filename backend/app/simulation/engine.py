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

import logging

from app.simulation.rule_parser import ParsedRule, parse_rule
from app.simulation.scenarios import SimPacket, build_scenario
from app.simulation.defenses import evaluate_defenses

log = logging.getLogger(__name__)


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

# ─── Scenario flow info (for nftables evaluation) ────────────────────────────
# Maps scenario_id → primary protocol and dst_port used in the attack flow.
_SCENARIO_FLOW_INFO: dict[str, dict] = {
    "ssh-brute-force":  {"protocol": "tcp",  "dst_port": 22},
    "http-brute-force": {"protocol": "tcp",  "dst_port": 80},
    "sql-injection":    {"protocol": "tcp",  "dst_port": 80},
    "nmap-syn-scan":    {"protocol": "tcp",  "dst_port": None},   # scans many ports
    "ping-sweep":       {"protocol": "icmp", "dst_port": None},
    "dns-tunneling":    {"protocol": "udp",  "dst_port": 53},
    "http-c2-beacon":   {"protocol": "tcp",  "dst_port": 80},
    "normal-browsing":  {"protocol": "tcp",  "dst_port": 80},
}

# ─── Detection-to-enforcement suggestion library ─────────────────────────────
# Maps scenario_id → a structured firewall rule suggestion to show when Suricata
# detects the attack but no nftables policy already blocks it.

_SCENARIO_SUGGESTIONS: dict[str, dict] = {
    "ssh-brute-force": {
        "title": "Block external SSH access",
        "explanation": (
            "SSH brute force succeeded because port 22 is reachable from external sources. "
            "Adding a forward rule to drop external TCP/22 removes the attack surface entirely — "
            "access control is more effective than detection alone for brute-force scenarios."
        ),
        "rule": {
            "chain": "forward", "srcZone": "external", "dstZone": "any",
            "protocol": "tcp", "dstPort": "22", "action": "drop",
            "description": "Block external SSH — prevent brute force",
        },
    },
    "http-brute-force": {
        "title": "Restrict HTTP login endpoints or add rate limiting",
        "explanation": (
            "HTTP brute force succeeded because port 80 is open and connections are unrestricted. "
            "If public web access is required, consider rate-limiting new connections. "
            "If only internal access is needed, block external HTTP entirely."
        ),
        "rule": {
            "chain": "forward", "srcZone": "external", "dstZone": "dmz",
            "protocol": "tcp", "dstPort": "80,443", "action": "accept",
            "description": "Explicitly scope web access to DMZ only — tighten if not public-facing",
        },
    },
    "sql-injection": {
        "title": "Isolate database tier from external access",
        "explanation": (
            "SQL injection reached the database because web traffic flows directly to the DB tier. "
            "The database should only accept connections from the web/app tier, never from external. "
            "Add a forward rule that drops external traffic destined for the internal network."
        ),
        "rule": {
            "chain": "forward", "srcZone": "external", "dstZone": "internal",
            "protocol": "tcp", "dstPort": "3306,5432,1433", "action": "drop",
            "description": "Block external DB access — enforce DMZ segmentation",
        },
    },
    "nmap-syn-scan": {
        "title": "Drop unsolicited inbound connections",
        "explanation": (
            "Port scanning succeeded because the firewall accepts connection attempts to all ports. "
            "Dropping new TCP connections to unexposed ports reduces your visible attack surface "
            "and makes reconnaissance significantly harder."
        ),
        "rule": {
            "chain": "forward", "srcZone": "external", "dstZone": "any",
            "protocol": "tcp", "dstPort": "", "action": "drop",
            "description": "Drop unsolicited external TCP — reduce scan surface",
        },
    },
    "ping-sweep": {
        "title": "Block ICMP echo requests from external sources",
        "explanation": (
            "Ping sweep succeeded because ICMP is allowed inbound from external. "
            "Dropping external ICMP prevents host discovery — attackers cannot easily enumerate "
            "which addresses are live before launching targeted attacks."
        ),
        "rule": {
            "chain": "forward", "srcZone": "external", "dstZone": "any",
            "protocol": "icmp", "dstPort": "", "action": "drop",
            "description": "Block external ICMP — prevent host discovery",
        },
    },
    "dns-tunneling": {
        "title": "Restrict outbound DNS to trusted resolvers only",
        "explanation": (
            "DNS tunneling succeeded because outbound UDP/53 is unrestricted. "
            "Allowing DNS only to known/trusted resolvers prevents arbitrary exfiltration "
            "over DNS. Internal hosts should use a controlled DNS forwarder, not query external "
            "resolvers directly."
        ),
        "rule": {
            "chain": "forward", "srcZone": "internal", "dstZone": "external",
            "protocol": "udp", "dstPort": "53", "action": "drop",
            "description": "Block unrestricted outbound DNS — prevent tunneling",
        },
    },
    "http-c2-beacon": {
        "title": "Block or proxy unrestricted outbound HTTP",
        "explanation": (
            "C2 beaconing succeeded over HTTP because outbound web traffic is unrestricted. "
            "Blocking direct external HTTP/HTTPS forces traffic through a proxy where it can be "
            "inspected, breaking most C2 channels that rely on direct outbound connectivity."
        ),
        "rule": {
            "chain": "forward", "srcZone": "internal", "dstZone": "external",
            "protocol": "tcp", "dstPort": "80,443", "action": "drop",
            "description": "Block unrestricted outbound HTTP — prevent C2 beaconing",
        },
    },
}


def _suggestion_to_nft_snippet(rule: dict) -> str:
    """Convert a suggestion rule dict to a single-line nftables rule string."""
    parts: list[str] = []
    zone_set = {"internal": "@INTERNAL", "dmz": "@DMZ", "management": "@MANAGEMENT"}
    src = rule.get("srcZone", "any")
    dst = rule.get("dstZone", "any")
    if src in zone_set:
        parts.append(f"ip saddr {zone_set[src]}")
    if dst in zone_set:
        parts.append(f"ip daddr {zone_set[dst]}")
    proto = rule.get("protocol", "any")
    if proto != "any":
        parts.append(proto)
        port = rule.get("dstPort", "")
        if port and proto != "icmp":
            ports = [p.strip() for p in port.split(",") if p.strip()]
            if len(ports) == 1:
                parts.append(f"dport {ports[0]}")
            elif len(ports) > 1:
                parts.append(f"dport {{ {', '.join(ports)} }}")
    parts.append(rule.get("action", "drop"))
    desc = rule.get("description", "")
    return "        " + " ".join(parts) + (f"   # {desc}" if desc else "")


def _generate_enforcement_suggestions(
    scenario_id: str,
    rule_results: list["RuleMatchResult"],
    nftables_blocked: bool,
) -> list[dict]:
    """
    When Suricata detected an attack that was NOT blocked by nftables policy,
    return a structured rule suggestion the user can apply to their firewall.

    Returns an empty list when:
    - the attack was already blocked (no suggestion needed)
    - no rules fired (nothing detected to act on)
    - the scenario has no mapping (e.g. normal-browsing)
    """
    if nftables_blocked:
        return []

    fired_sids = [r.rule_sid for r in rule_results if r.fired]
    if not fired_sids:
        return []

    suggestion_template = _SCENARIO_SUGGESTIONS.get(scenario_id)
    if not suggestion_template:
        return []

    rule = suggestion_template["rule"]
    return [{
        "title":        suggestion_template["title"],
        "explanation":  suggestion_template["explanation"],
        "rule":         rule,
        "nft_snippet":  _suggestion_to_nft_snippet(rule),
        "triggered_sids": fired_sids,
    }]


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
    ids_visible: bool = True          # upstream IDS sensor(s) observed the traffic?
    ids_node_labels: list[str] = field(default_factory=list)  # labels of upstream (observing) IDS nodes
    ids_downstream_labels: list[str] = field(default_factory=list)  # IDS nodes blind due to FW block
    # Event timeline
    timeline: list[dict] = field(default_factory=list)
    # nftables firewall policy evaluation
    nftables_decision: Optional[dict] = None   # see _evaluate_nftables_policy
    nftables_blocked: bool = False
    nftables_rate_limited: bool = False
    # Simulation mode metadata
    mode: str = "python"              # "python" | "suricata"
    suricata_fallback: bool = False   # suricata was requested but fell back to python
    # Detection-to-enforcement suggestions
    enforcement_suggestions: list[dict] = field(default_factory=list)
    # NAT evaluation
    nat_decisions: list[dict] = field(default_factory=list)


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

    # Skip infrastructure nodes (firewall/router) — they are intermediaries, not attack targets
    _INFRA_TYPES = {"firewall", "router"}
    endpoint_nodes = [n for n in target_nodes if n.get("data", {}).get("deviceType") not in _INFRA_TYPES]
    if not endpoint_nodes:
        return  # only infrastructure in path — nothing to validate against

    target    = endpoint_nodes[0]
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


def _ip_in_set(ip: str, elements: list[str]) -> bool:
    """Return True if *ip* falls within any element of an nftables IP set (exact IP or CIDR)."""
    for element in elements:
        element = element.strip()
        if not element:
            continue
        if "/" in element:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(element, strict=False):
                    return True
            except ValueError:
                continue
        else:
            if ip == element:
                return True
    return False


def _fw_rule_matches_flow(
    rule: dict,
    src_zone: str,
    dst_zone: str,
    protocol: str,
    dst_port: Optional[int],
    src_ip: str = "",
    dst_ip: str = "",
    ip_sets: Optional[dict] = None,
) -> bool:
    """Return True if a single firewall policy rule applies to this flow."""
    if not rule.get("enabled", True):
        return False
    if rule.get("chain") != "forward":
        return False   # only forward chain matters for pass-through attack traffic

    # Source matching: IP set overrides zone
    src_set_name = rule.get("srcSet")
    if src_set_name:
        elements = (ip_sets or {}).get(src_set_name, [])
        if not _ip_in_set(src_ip, elements):
            return False
    else:
        rule_src = rule.get("srcZone", "any")
        if rule_src != "any" and rule_src != src_zone:
            return False

    # Destination matching: IP set overrides zone
    dst_set_name = rule.get("dstSet")
    if dst_set_name:
        elements = (ip_sets or {}).get(dst_set_name, [])
        if not _ip_in_set(dst_ip, elements):
            return False
    else:
        rule_dst = rule.get("dstZone", "any")
        if rule_dst != "any" and rule_dst != dst_zone:
            return False

    rule_proto = rule.get("protocol", "any")
    if rule_proto != "any" and rule_proto != protocol:
        return False

    rule_port_str = rule.get("dstPort", "")
    if rule_port_str and dst_port is not None:
        rule_ports = {int(p.strip()) for p in rule_port_str.split(",") if p.strip().isdigit()}
        if rule_ports and dst_port not in rule_ports:
            return False

    return True


def _evaluate_nftables_policy(
    scenario_id: str,
    topology: dict,
    visited_node_ids: set[str],
    attacker_node: dict,
    target_nodes: list[dict],
) -> tuple[Optional[dict], bool]:
    """
    Evaluate the nftables FirewallPolicy on each firewall node the attack passes through.

    Returns (decision_dict, blocked).
    decision_dict is None if no configured firewall is on the path.
    """
    # Find firewall nodes on the attack path that have a configured policy
    fw_nodes = [
        n for n in topology.get("nodes", [])
        if n.get("data", {}).get("deviceType") == "firewall"
        and n["id"] in visited_node_ids
        and n.get("data", {}).get("firewallPolicy")
    ]
    if not fw_nodes:
        return None, False

    flow = _SCENARIO_FLOW_INFO.get(scenario_id, {"protocol": "tcp", "dst_port": None})
    attack_protocol = flow["protocol"]
    attack_dst_port = flow["dst_port"]

    attacker_zone  = attacker_node.get("data", {}).get("zone", "external")
    attacker_ip    = attacker_node.get("data", {}).get("ip", "")
    primary_target = target_nodes[0] if target_nodes else None
    target_zone    = primary_target.get("data", {}).get("zone", "internal") if primary_target else "internal"
    target_ip      = primary_target.get("data", {}).get("ip", "") if primary_target else ""
    target_label   = primary_target.get("data", {}).get("label", "target") if primary_target else "target"

    port_str = f"/{attack_dst_port}" if attack_dst_port else ""
    flow_desc = f"{attacker_zone} → {target_zone} ({attack_protocol}{port_str})"

    last_allow_decision: Optional[dict] = None

    for fw_node in fw_nodes:
        fw_data = fw_node.get("data", {})
        policy  = fw_data.get("firewallPolicy", {})
        fw_label = fw_data.get("label", "Firewall")
        fw_ip    = fw_data.get("ip", "")

        rules           = policy.get("rules", [])
        default_forward = policy.get("defaultForward", "drop")
        ct_state_enabled = policy.get("ctStateEnabled", True)

        # Build IP-set lookup: name → list of elements
        ip_sets: dict[str, list[str]] = {}
        for s in policy.get("ipSets", []):
            ip_sets[s.get("name", "")] = s.get("elements", [])

        # ── Port knocking check ───────────────────────────────────────────────
        # External attackers never know the knock sequence — if port knocking
        # is enabled for the attack's target port, the port appears closed.
        port_knocking = policy.get("portKnocking")
        if (
            port_knocking
            and isinstance(port_knocking, dict)
            and attack_dst_port is not None
            and port_knocking.get("targetPort") == attack_dst_port
            and attacker_zone == "external"
        ):
            knock_port   = port_knocking.get("knockPort", "?")
            target_port  = port_knocking.get("targetPort")
            timeout_sec  = port_knocking.get("timeoutSec", 30)
            knock_decision = {
                "firewall_label": fw_label,
                "firewall_ip": fw_ip,
                "action": "drop",
                "matched_rule_description": (
                    f"Port knocking: port {target_port} locked "
                    f"(must knock on :{knock_port} within {timeout_sec}s first)"
                ),
                "blocked": True,
                "rate_limited": False,
                "rate_limit_pps": 0,
                "rate_limit_burst": 0,
                "ct_stateless_warning": False,
                "port_knock_blocked": True,
                "explanation": (
                    f"Firewall '{fw_label}' protects port {target_port} with port knocking. "
                    f"A client must first send a packet to the secret knock port :{knock_port} — "
                    f"the firewall then adds the client IP to a timed set for {timeout_sec} seconds, "
                    f"during which :{target_port} is allowed. "
                    f"External attackers who do not know the knock port see :{target_port} as closed. "
                    f"Generated nft rule: "
                    f"tcp dport {knock_port} add @KNOCK_CLIENTS {{ ip saddr timeout {timeout_sec}s }} drop; "
                    f"tcp dport {target_port} ip saddr @KNOCK_CLIENTS accept"
                ),
            }
            return knock_decision, True

        # ── Dynamic ban check ─────────────────────────────────────────────────
        # Brute-force scenarios generate many new connections. If the policy has
        # a dynamicBan configured for the attack port/protocol, the source IP
        # would be banned after rateThreshold connection attempts.
        dynamic_ban = policy.get("dynamicBan")
        if dynamic_ban and isinstance(dynamic_ban, dict):
            db_proto    = dynamic_ban.get("targetProtocol", "tcp")
            db_port_str = dynamic_ban.get("targetPort", "")
            db_threshold = dynamic_ban.get("rateThreshold", 5)
            db_duration  = dynamic_ban.get("banDurationSec", 300)

            # Determine if this attack's protocol/port falls under the ban scope
            proto_match = db_proto == "any" or db_proto == attack_protocol
            if db_port_str:
                watched_ports = {int(p.strip()) for p in db_port_str.split(",") if p.strip().isdigit()}
                port_match = attack_dst_port is not None and attack_dst_port in watched_ports
            else:
                port_match = True  # empty = watch all ports

            # Brute-force scenarios generate many repeated connection attempts
            _is_bruteforce = scenario_id in ("ssh-brute-force", "http-brute-force")

            if proto_match and port_match and _is_bruteforce:
                db_decision = {
                    "firewall_label": fw_label,
                    "firewall_ip": fw_ip,
                    "action": "drop",
                    "matched_rule_description": (
                        f"Dynamic ban: source exceeded {db_threshold} connections/min — "
                        f"banned for {db_duration}s"
                    ),
                    "blocked": True,
                    "rate_limited": False,
                    "rate_limit_pps": 0,
                    "rate_limit_burst": 0,
                    "ct_stateless_warning": False,
                    "port_knock_blocked": False,
                    "dynamic_ban_triggered": True,
                    "dynamic_ban_after_packets": db_threshold,
                    "explanation": (
                        f"Firewall '{fw_label}' dynamic ban triggered. "
                        f"The attacker's repeated connection attempts on "
                        f"{db_proto.upper()} port {attack_dst_port} exceeded the threshold of "
                        f"{db_threshold} new connections/minute. "
                        f"After packet #{db_threshold}, the source IP ({attacker_ip}) was added to "
                        f"the BAN_LIST set — all subsequent traffic from that source is dropped "
                        f"for the next {db_duration} seconds. "
                        f"Generated nft rule: "
                        f"meter BAN_METER {{ ip saddr limit rate over {db_threshold}/minute "
                        f"burst {db_threshold} packets }} add @BAN_LIST {{ ip saddr timeout {db_duration}s }} drop"
                    ),
                }
                return db_decision, True

        matched_rule: Optional[dict] = None
        action = default_forward
        rate_limited = False
        rate_limit_pps = 0
        rate_limit_burst = 0

        for rule in rules:
            if _fw_rule_matches_flow(
                rule, attacker_zone, target_zone, attack_protocol, attack_dst_port,
                src_ip=attacker_ip, dst_ip=target_ip, ip_sets=ip_sets,
            ):
                matched_rule = rule
                action = rule.get("action", "drop")
                rl = rule.get("rateLimit")
                if rl and isinstance(rl, dict) and action == "accept":
                    pps = rl.get("pps", 0)
                    if pps > 0:
                        rate_limited = True
                        rate_limit_pps = pps
                        rate_limit_burst = rl.get("burst", 0)
                break

        rule_desc = ""
        if matched_rule:
            rule_desc = matched_rule.get("description", "") or (
                f"{matched_rule.get('srcZone','any')} → {matched_rule.get('dstZone','any')} "
                f"{matched_rule.get('protocol','any')}"
            )
        else:
            rule_desc = f"default forward policy: {default_forward}"

        blocked = action in ("drop", "reject")

        if rate_limited:
            rl_note = (
                f" Traffic throttled to {rate_limit_pps} packet(s)/second"
                f" (burst: {rate_limit_burst})."
            )
            if scenario_id in ("ssh-brute-force", "http-brute-force"):
                mins = max(1, 1000 // max(1, rate_limit_pps) // 60)
                rl_note += (
                    f" At this rate, a 1 000-password brute-force attempt would require"
                    f" ≥{mins} minute(s) — vastly increasing detection likelihood"
                    f" and triggering account lockouts."
                )
        else:
            rl_note = ""

        # Warn when stateless mode + default-drop: return traffic from allowed connections
        # would also be dropped, silently breaking TCP handshakes and UDP exchanges.
        ct_stateless_warning = (
            not ct_state_enabled
            and default_forward == "drop"
            and not blocked
        )

        decision = {
            "firewall_label": fw_label,
            "firewall_ip": fw_ip,
            "action": action,
            "matched_rule_description": rule_desc,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "rate_limit_pps": rate_limit_pps,
            "rate_limit_burst": rate_limit_burst,
            "ct_stateless_warning": ct_stateless_warning,
            "explanation": (
                f"Firewall '{fw_label}' "
                f"{'BLOCKED' if blocked else ('RATE-LIMITED' if rate_limited else 'allowed')}"
                f" this traffic. "
                f"Flow: {flow_desc}. "
                f"Matching rule: \"{rule_desc}\"."
                + rl_note
                + (
                    f" The attack was stopped — {target_label} never received this traffic."
                    if blocked
                    else (
                        f" Traffic throttled — reduced volume delivered to {target_label}."
                        if rate_limited
                        else f" Traffic continued towards {target_label}."
                    )
                )
            ),
        }

        if blocked:
            return decision, True

        last_allow_decision = decision

    return last_allow_decision, False


def _evaluate_nat_rules(
    scenario_id: str,
    topology: dict,
    visited_node_ids: set[str],
    attacker_node: dict,
) -> list[dict]:
    """
    Detect NAT rules (DNAT / masquerade) on firewall nodes along the attack path
    and return a list of educational NAT decision dicts.

    NAT does not block traffic — it describes how addresses are translated.
    DNAT fires when the attack port matches a forwarding rule.
    Masquerade fires for outbound flows (internal → external scenarios).
    """
    fw_nodes = [
        n for n in topology.get("nodes", [])
        if n.get("data", {}).get("deviceType") == "firewall"
        and n["id"] in visited_node_ids
        and n.get("data", {}).get("firewallPolicy")
    ]
    if not fw_nodes:
        return []

    flow = _SCENARIO_FLOW_INFO.get(scenario_id, {"protocol": "tcp", "dst_port": None})
    attack_protocol = flow["protocol"]
    attack_dst_port = flow["dst_port"]
    attacker_zone = attacker_node.get("data", {}).get("zone", "external")

    # Scenarios where traffic flows internal → external (masquerade applies)
    _OUTBOUND_SCENARIOS = {"dns-tunneling", "http-c2-beacon", "normal-browsing"}

    decisions: list[dict] = []

    for fw_node in fw_nodes:
        policy = fw_node.get("data", {}).get("firewallPolicy", {})
        nat_rules = policy.get("natRules", [])
        if not nat_rules:
            continue
        fw_label = fw_node.get("data", {}).get("label", "Firewall")

        for rule in nat_rules:
            if not rule.get("enabled", True):
                continue
            nat_type = rule.get("type", "")

            if nat_type == "dnat":
                # Check protocol match
                rule_proto = rule.get("protocol", "tcp")
                if rule_proto != attack_protocol:
                    continue
                # Check port match
                ext_port_str = rule.get("extPort", "")
                if ext_port_str and attack_dst_port is not None:
                    rule_ports = {
                        int(p.strip()) for p in ext_port_str.split(",")
                        if p.strip().isdigit()
                    }
                    if attack_dst_port not in rule_ports:
                        continue
                to_addr = rule.get("toAddr", "")
                to_port = rule.get("toPort", "") or ext_port_str
                redirected_to = f"{to_addr}:{to_port}" if to_addr and to_port else to_addr
                decisions.append({
                    "type": "dnat",
                    "description": (
                        f"Firewall '{fw_label}' DNAT: inbound {rule_proto.upper()}:{ext_port_str} "
                        f"is forwarded to {redirected_to}. "
                        f"External traffic targeting the firewall's public IP on port {ext_port_str} "
                        f"is transparently redirected to the internal host without the client being aware. "
                        + (f"Rule note: {rule.get('description')}" if rule.get("description") else "")
                    ),
                    "redirected_to": redirected_to,
                    "ext_port": ext_port_str,
                })

            elif nat_type == "masquerade":
                # Only fires for outbound (internal-initiated) scenarios
                if scenario_id not in _OUTBOUND_SCENARIOS:
                    # Also fires when attacker zone matches srcZone
                    src_zone = rule.get("srcZone", "internal")
                    if src_zone != "any" and src_zone != attacker_zone:
                        continue
                src_zone = rule.get("srcZone", "internal")
                decisions.append({
                    "type": "masquerade",
                    "description": (
                        f"Firewall '{fw_label}' masquerade: outbound traffic from the "
                        f"'{src_zone}' zone has its source IP replaced with the firewall's "
                        f"external IP. The remote server sees the firewall's IP as the source, "
                        f"not the internal host's private address. "
                        f"Return traffic is automatically un-NAT'd by the firewall's conntrack. "
                        + (f"Rule note: {rule.get('description')}" if rule.get("description") else "")
                    ),
                    "masked_zone": src_zone,
                })

    return decisions


def _build_timeline(
    attack_path: list[list[str]],
    topology: dict,
    defense_impacts: list[dict],
    attack_blocked: bool,
    nftables_decision: Optional[dict],
    nftables_blocked: bool,
    ids_visible: bool,
    ids_node_labels: list[str],
    ids_downstream_labels: list[str],
    rule_results: list[RuleMatchResult],
    nat_decisions: list[dict] | None = None,
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

    # ── 1b. NAT events (DNAT / masquerade) ───────────────────────────────────
    for nat in (nat_decisions or []):
        if nat["type"] == "dnat":
            events.append({
                "type":   "nat_dnat",
                "label":  f"Port Forward: external:{nat.get('ext_port', '?')} → {nat.get('redirected_to', '?')}",
                "detail": nat["description"],
            })
        elif nat["type"] == "masquerade":
            events.append({
                "type":   "nat_masquerade",
                "label":  f"Masquerade: {nat.get('masked_zone', 'internal')} → external (src IP hidden)",
                "detail": nat["description"],
            })

    # ── 2. nftables firewall policy evaluation ───────────────────────────────
    if nftables_decision:
        _is_pk  = nftables_decision.get("port_knock_blocked", False)
        _is_db  = nftables_decision.get("dynamic_ban_triggered", False)
        _is_rl  = nftables_decision.get("rate_limited", False)
        _rl_pps = nftables_decision.get("rate_limit_pps", 0)
        _db_n   = nftables_decision.get("dynamic_ban_after_packets", 0)
        if _is_pk:
            _ev_type  = "port_knock_blocked"
            _ev_label = f"Firewall '{nftables_decision['firewall_label']}': PORT KNOCK required"
        elif _is_db:
            _ev_type  = "dynamic_ban"
            _ev_label = f"Firewall '{nftables_decision['firewall_label']}': DYNAMIC BAN (after {_db_n} connections)"
        elif nftables_blocked:
            _ev_type  = "nftables_blocked"
            _ev_label = f"Firewall '{nftables_decision['firewall_label']}': BLOCKED"
        elif _is_rl:
            _ev_type  = "nftables_rate_limited"
            _ev_label = f"Firewall '{nftables_decision['firewall_label']}': RATE-LIMITED ({_rl_pps} pps)"
        else:
            _ev_type  = "nftables_allowed"
            _ev_label = f"Firewall '{nftables_decision['firewall_label']}': allowed"
        events.append({
            "type":       _ev_type,
            "label":      _ev_label,
            "detail":     nftables_decision["explanation"],
            "node_label": nftables_decision["firewall_label"],
        })

    # ── 2b. Stateless warning (emitted after the firewall pass event) ────────
    if nftables_decision and nftables_decision.get("ct_stateless_warning"):
        events.append({
            "type":       "nftables_ct_stateless",
            "label":      f"Stateless firewall — return traffic also dropped",
            "detail":     (
                f"Firewall '{nftables_decision['firewall_label']}' has stateful tracking disabled "
                "(ct state established,related accept is absent). "
                "In a real deployment, reply packets (TCP SYN-ACK, data responses) from this "
                "allowed flow would hit the default-drop policy and be silently discarded — "
                "connections time out from the client's perspective. "
                "Enable stateful tracking to allow established session packets automatically."
            ),
            "node_label": nftables_decision.get("firewall_label", "Firewall"),
        })

    # ── 3. Defense evaluation (only when nftables didn't block) ──────────────
    if nftables_blocked:
        pass  # skip host defense evaluation — attack already stopped
    elif not defense_impacts:
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

    # ── 3. IDS visibility ─────────────────────────────────────────────────────
    # Upstream IDS sensors observed the traffic before the firewall acted on it.
    # Downstream IDS sensors are blind when the firewall blocked — traffic never arrived.
    if ids_visible:  # upstream IDS present
        label_str = ", ".join(ids_node_labels)
        if nftables_blocked:
            detail = (
                f"{label_str} is positioned before the blocking firewall and captured "
                "the attack flow. Suricata rule evaluation applies for this sensor."
            )
        else:
            detail = (
                f"{label_str} has a monitoring link to a node on the attack path — "
                "Suricata rule evaluation applies."
            )
        events.append({
            "type":       "ids_observed",
            "label":      f"{label_str} observed the traffic",
            "detail":     detail,
            "node_label": label_str,
        })
    elif not ids_downstream_labels:
        # No IDS anywhere on path
        no_sensor = not any(
            n.get("data", {}).get("deviceType") == "ids"
            for n in topology.get("nodes", [])
        )
        events.append({
            "type":   "ids_blind",
            "label":  "IDS did not observe traffic",
            "detail": (
                "No Suricata IDS sensor is deployed in this topology."
                if no_sensor else
                "An IDS sensor exists but is not connected to any node the attack passes through."
            ),
        })

    if ids_downstream_labels and nftables_blocked:
        label_str = ", ".join(ids_downstream_labels)
        events.append({
            "type":       "ids_blind",
            "label":      f"{label_str} had no visibility — downstream of firewall",
            "detail":     (
                f"{label_str} is positioned after the blocking firewall. "
                "The attack was dropped before traffic could reach this sensor's segment."
            ),
            "node_label": label_str,
        })

    # ── 4. Rule evaluation (when upstream IDS observed the traffic) ───────────
    if ids_visible:
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
    _outcome_rl     = nftables_decision.get("rate_limited", False) if nftables_decision else False
    _outcome_rl_pps = nftables_decision.get("rate_limit_pps", 0)   if nftables_decision else 0
    if attack_blocked:
        upstream_fired = ids_visible and any(r.fired for r in rule_results)
        if nftables_blocked and upstream_fired:
            fired_count = sum(1 for r in rule_results if r.fired)
            events.append({
                "type":   "outcome_blocked",
                "label":  f"Attack blocked — upstream IDS also alerted ({fired_count} rule(s))",
                "detail": (
                    "The firewall stopped the attack before it reached the target. "
                    f"Additionally, {fired_count} IDS rule(s) fired on the traffic observed "
                    "upstream of the firewall — providing forensic evidence of the attempt."
                ),
            })
        else:
            events.append({
                "type":   "outcome_blocked",
                "label":  "Attack stopped",
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
        rl_prefix = f"Attack throttled to {_outcome_rl_pps} pps — " if _outcome_rl else ""
        events.append({
            "type":   "outcome_detected",
            "label":  f"{rl_prefix}{alert_count} alert(s) generated",
            "detail": (
                f"Traffic was delivered{f' at reduced volume ({_outcome_rl_pps} pps)' if _outcome_rl else ''} "
                f"and Suricata generated {alert_count} alert(s). "
                + ("Rate limiting significantly reduces brute-force effectiveness. " if _outcome_rl else "")
                + "Detection succeeded but the attack was not blocked."
            ),
        })
    else:
        rl_label = f"Attack throttled to {_outcome_rl_pps} pps — no IDS rules fired" if _outcome_rl else "Attack reached target — rules did not fire"
        events.append({
            "type":   "outcome_undetected",
            "label":  rl_label,
            "detail": (
                "Traffic was delivered to the target but no loaded Suricata rules matched. "
                + ("Rate limiting reduces attack volume but does not eliminate it without IDS detection. " if _outcome_rl else "")
                + "Either add more rules or investigate why the existing ones missed."
            ),
        })

    return events


def run_simulation(
    scenario_id: str,
    rule_texts: list[str],
    topology: dict,
    mode: str = "python",
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

    # ── 5. Evaluate nftables firewall policy ─────────────────────────────────
    nftables_decision, nftables_blocked = _evaluate_nftables_policy(
        scenario_id, topology, visited_node_ids, attacker_node, target_nodes
    )

    nftables_rate_limited = (
        bool(nftables_decision.get("rate_limited")) if nftables_decision else False
    )

    # Save full path for IDS position analysis, then truncate for animation
    attack_path_full = attack_path
    if nftables_blocked and nftables_decision:
        fw_ip = nftables_decision.get("firewall_ip")
        if fw_ip:
            truncated: list[list[str]] = []
            for hop in attack_path:
                truncated.append(hop)
                if hop[1] == fw_ip:
                    break
            attack_path = truncated

    # ── 6. Evaluate host defenses ─────────────────────────────────────────────
    defense_impacts, defense_blocked = evaluate_defenses(scenario_id, target_nodes)
    attack_blocked = nftables_blocked or defense_blocked

    # ── 7. Build traffic packets ──────────────────────────────────────────────
    primary_target = target_ips[0]
    packets = build_scenario(scenario_id, attacker_ip, primary_target, home_ips, external_ips)

    # ── 8. Check IDS visibility (upstream vs downstream of firewall) ─────────
    _fw_ip_for_ids = (
        nftables_decision.get("firewall_ip")
        if nftables_blocked and nftables_decision else None
    )
    ids_visible, ids_node_labels, ids_downstream_labels = _find_ids_visibility(
        topology, visited_node_ids, attack_path_full, _fw_ip_for_ids
    )

    # ── 9. Parse rules ────────────────────────────────────────────────────────
    parsed_rules: list[tuple[str, ParsedRule]] = []
    parse_errors: list[str] = []
    for raw in rule_texts:
        pr = parse_rule(raw)
        if pr:
            parsed_rules.append((raw, pr))
        else:
            parse_errors.append(raw)

    results: list[RuleMatchResult] = []
    actual_mode = mode
    suricata_fallback = False

    if not ids_visible:
        # IDS not on path — produce blind results regardless of mode
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
        # parse errors still get reported
        results.extend(_parse_error_results(parse_errors))

    elif mode == "suricata":
        # ── Real Suricata via Docker ──────────────────────────────────────────
        try:
            from app.simulation.pcap_builder import build_pcap
            from app.simulation.suricata_runner import run_suricata
            from app.simulation.suricata_mapper import map_alerts

            pcap_bytes = build_pcap(packets)
            alerts = run_suricata(pcap_bytes, rule_texts)
            # map_alerts handles both fired rules and parse errors in one pass
            results = map_alerts(alerts, rule_texts)
        except Exception as exc:
            log.warning("Suricata mode failed (%s); falling back to Python engine", exc)
            suricata_fallback = True
            actual_mode = "python"
            results = _python_evaluate(
                parsed_rules, parse_errors, packets, home_ips, external_ips, scenario_id
            )

    else:
        # ── Educational simulation (Python engine) ────────────────────────────
        results = _python_evaluate(
            parsed_rules, parse_errors, packets, home_ips, external_ips, scenario_id
        )

    triggered = sum(1 for r in results if r.fired)
    total = len(rule_texts)

    # ── 10. Detection-to-enforcement suggestions ──────────────────────────────
    enforcement_suggestions = _generate_enforcement_suggestions(
        scenario_id, results, nftables_blocked
    )

    # ── 11. Evaluate NAT rules ────────────────────────────────────────────────
    nat_decisions = _evaluate_nat_rules(
        scenario_id, topology, visited_node_ids, attacker_node
    )

    # ── 12. Build event timeline ──────────────────────────────────────────────
    timeline = _build_timeline(
        attack_path=attack_path,
        topology=topology,
        defense_impacts=defense_impacts,
        attack_blocked=attack_blocked,
        nftables_decision=nftables_decision,
        nftables_blocked=nftables_blocked,
        ids_visible=ids_visible,
        ids_node_labels=ids_node_labels,
        ids_downstream_labels=ids_downstream_labels,
        rule_results=results,
        nat_decisions=nat_decisions,
    )

    # ── 13. Build summary ─────────────────────────────────────────────────────
    if nftables_blocked and nftables_decision:
        summary = (
            f"Attack blocked by firewall '{nftables_decision['firewall_label']}' policy. "
            f"Rule: \"{nftables_decision['matched_rule_description']}\". "
            f"Traffic never reached {', '.join(n['data'].get('label', 'target') for n in target_nodes)}."
        )
        if ids_visible and triggered > 0:
            summary += (
                f" Upstream IDS ({', '.join(ids_node_labels)}) still alerted on "
                f"{triggered} rule(s) — forensic evidence of the blocked attempt."
            )
        if ids_downstream_labels:
            summary += (
                f" Downstream IDS ({', '.join(ids_downstream_labels)}) had no visibility "
                "— traffic was dropped before reaching their segment."
            )
    elif nftables_rate_limited and nftables_decision:
        pps   = nftables_decision.get("rate_limit_pps", 0)
        burst = nftables_decision.get("rate_limit_burst", 0)
        tgts  = ', '.join(n['data'].get('label', 'target') for n in target_nodes)
        summary = (
            f"Firewall '{nftables_decision['firewall_label']}' rate-limited traffic to {pps} pps"
            f" (burst {burst}). Attack reached {tgts} at reduced volume — "
            "brute-force attacks at this rate take far longer and will likely trigger lockouts."
        )
        if triggered > 0:
            summary += (
                f" IDS ({', '.join(ids_node_labels)}) detected {triggered} rule(s)"
                " on the throttled traffic."
            )
    elif attack_blocked:
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

    if suricata_fallback:
        summary = (
            "[Fallback: Docker unavailable — results from Educational Simulation] " + summary
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
        nftables_decision=nftables_decision,
        nftables_blocked=nftables_blocked,
        nftables_rate_limited=nftables_rate_limited,
        ids_visible=ids_visible,
        ids_node_labels=ids_node_labels,
        ids_downstream_labels=ids_downstream_labels,
        timeline=timeline,
        mode=actual_mode,
        suricata_fallback=suricata_fallback,
        enforcement_suggestions=enforcement_suggestions,
        nat_decisions=nat_decisions,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Rule evaluation helpers (shared by both modes)
# ─────────────────────────────────────────────────────────────────────────────

def run_rules_on_packets(
    rule_texts: list[str],
    packets: list[SimPacket],
    home_ips: list[str],
    ext_ips: list[str],
    scenario_id: str = "pcap-import",
) -> list[RuleMatchResult]:
    """
    Public helper: evaluate *rule_texts* against *packets* using the Python engine.

    Used by the PCAP import endpoint, which has packets but no canvas topology.
    Returns one RuleMatchResult per rule (fired or not), same as run_simulation().
    """
    parsed_rules: list[tuple[str, ParsedRule]] = []
    parse_errors: list[str] = []
    for raw in rule_texts:
        pr = parse_rule(raw)
        if pr:
            parsed_rules.append((raw, pr))
        else:
            parse_errors.append(raw)
    return _python_evaluate(parsed_rules, parse_errors, packets, home_ips, ext_ips, scenario_id)


def _python_evaluate(
    parsed_rules: list[tuple[str, ParsedRule]],
    parse_errors: list[str],
    packets: list[SimPacket],
    home_ips: list[str],
    ext_ips: list[str],
    scenario_id: str,
) -> list[RuleMatchResult]:
    """Run the Python-based rule evaluation and return results for all rules."""
    results: list[RuleMatchResult] = []
    for raw, pr in parsed_rules:
        results.append(_evaluate_rule(pr, packets, home_ips, ext_ips, scenario_id))
    results.extend(_parse_error_results(parse_errors))
    return results


def _parse_error_results(parse_errors: list[str]) -> list[RuleMatchResult]:
    """Build RuleMatchResult entries for rules that failed to parse."""
    results: list[RuleMatchResult] = []
    for raw in parse_errors:
        sid_hint = re.search(r'\bsid\s*:\s*(\d+)', raw)
        msg_hint = re.search(r'\bmsg\s*:\s*"([^"]+)"', raw)
        results.append(RuleMatchResult(
            rule_sid=sid_hint.group(1) if sid_hint else "?",
            rule_msg=msg_hint.group(1) if msg_hint else raw[:60].strip(),
            fired=False,
            explanation=(
                "This rule could not be parsed — it contains a syntax error. "
                "Suricata would reject it on startup. "
                "Open the IDS node panel and fix the rule syntax."
            ),
            why_not=(
                "Rule syntax is invalid: check action, header format, "
                "and that sid/msg keywords are present."
            ),
        ))
    return results


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
    attack_path_full: list[list[str]],
    firewall_ip: Optional[str] = None,
) -> tuple[bool, list[str], list[str]]:
    """
    Determine which IDS sensors can observe the attack flow, and whether each sits
    upstream or downstream of the blocking firewall.

    An IDS "sees" a flow if it has a monitoring edge to any node traversed during
    the BFS.  When a firewall blocked the traffic, the IDS position in the path
    determines actual visibility:
      - upstream (at or before the firewall): saw the traffic before the drop
      - downstream (after the firewall):      traffic never arrived — blind

    When no firewall blocked, all on-path IDS sensors are treated as upstream.

    Returns:
        (upstream_visible, upstream_labels, downstream_labels)
    """
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in topology.get("nodes", [])}

    ids_node_ids: set[str] = {
        n["id"] for n in topology.get("nodes", [])
        if n.get("data", {}).get("deviceType") == "ids"
    }

    if not ids_node_ids:
        return False, [], []

    # Build an ordered IP sequence from the untruncated attack path so we can
    # compare positions of the firewall and monitored nodes.
    ip_position: dict[str, int] = {}
    if attack_path_full:
        ordered: list[str] = []
        seen_ips: set[str] = set()
        first_src = attack_path_full[0][0]
        if first_src not in seen_ips:
            ordered.append(first_src)
            seen_ips.add(first_src)
        for _src, dst in attack_path_full:
            if dst not in seen_ips:
                ordered.append(dst)
                seen_ips.add(dst)
        ip_position = {ip: i for i, ip in enumerate(ordered)}

    fw_position: Optional[int] = ip_position.get(firewall_ip) if firewall_ip else None

    upstream_labels: list[str] = []
    downstream_labels: list[str] = []
    seen_ids: set[str] = set()

    for edge in topology.get("edges", []):
        src = edge.get("source", "")
        tgt = edge.get("target", "")

        if src in ids_node_ids:
            ids_id, monitored_id = src, tgt
        elif tgt in ids_node_ids:
            ids_id, monitored_id = tgt, src
        else:
            continue

        if monitored_id not in visited_node_ids or ids_id in seen_ids:
            continue
        seen_ids.add(ids_id)

        label = nodes_by_id.get(ids_id, {}).get("data", {}).get("label", "Suricata IDS")

        if fw_position is not None:
            # Compare the monitored node's path position to the firewall's position
            monitored_ip = nodes_by_id.get(monitored_id, {}).get("data", {}).get("ip", "")
            monitored_pos = ip_position.get(monitored_ip)
            if monitored_pos is not None and monitored_pos > fw_position:
                downstream_labels.append(label)
            else:
                upstream_labels.append(label)
        else:
            upstream_labels.append(label)

    return bool(upstream_labels), upstream_labels, downstream_labels


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
