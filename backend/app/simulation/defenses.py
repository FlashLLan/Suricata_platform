"""
Defense evaluation module.
Maps scenario IDs → the attack IDs they represent, then checks which
enabled defenses on target devices would block those attacks.
"""

# Maps scenario_id → list of attack IDs (from frontend/src/data/attacks.ts)
# that the scenario exercises.
SCENARIO_ATTACK_IDS: dict[str, list[str]] = {
    "nmap-syn-scan":    ["nmap-syn"],
    "ping-sweep":       ["ping-sweep"],
    "ssh-brute-force":  ["hydra-ssh"],
    "http-brute-force": ["hydra-http"],
    "sql-injection":    ["sqlmap", "burp-sqli"],
    "dns-tunneling":    ["dns-tunnel"],
    "http-c2-beacon":   ["curl-exfil"],
    "normal-browsing":  [],
}

# Maps defense_id → (display_name, attack IDs it counters, description of what it does)
DEFENSE_INFO: dict[str, tuple[str, list[str], str]] = {
    "ip-blocklist": (
        "IP Blocklist",
        ["nmap-syn", "nmap-os", "ping-sweep", "hydra-ssh", "hydra-http"],
        "Drops packets from the attacker's IP before they reach any service.",
    ),
    "port-filtering": (
        "Port Filtering",
        ["nmap-syn", "udp-scan", "msf-handler", "hydra-ftp", "medusa-rdp"],
        "Firewall closes all non-whitelisted ports; the attack can't reach the target service.",
    ),
    "geo-blocking": (
        "Geo-Blocking",
        ["nmap-syn", "hydra-ssh", "medusa-rdp"],
        "The attacker's IP is registered in a blocked country — traffic is dropped at ingress.",
    ),
    "ssh-key-only": (
        "SSH Key-Only Auth",
        ["hydra-ssh"],
        "Password authentication is disabled on SSH — dictionary attack has nothing to guess.",
    ),
    "mfa": (
        "Multi-Factor Authentication",
        ["hydra-ssh", "hydra-http", "hydra-ftp", "medusa-rdp"],
        "Even a guessed password is useless without the second factor.",
    ),
    "port-knocking": (
        "Port Knocking",
        ["nmap-syn", "hydra-ssh", "medusa-rdp"],
        "The target service is hidden until the correct knock sequence is sent — the attacker sees a closed port.",
    ),
    "fail2ban": (
        "fail2ban",
        ["hydra-ssh", "hydra-http", "hydra-ftp", "medusa-rdp"],
        "The attacker's IP is auto-banned after exceeding the failed-login threshold.",
    ),
    "syn-flood-protection": (
        "SYN Flood Protection",
        ["nmap-syn"],
        "SYN cookies absorb the scan's half-open connections without exhausting resources.",
    ),
    "connection-rate-limit": (
        "Connection Rate Limiting",
        ["nmap-syn", "hydra-ssh", "hydra-http", "hydra-ftp"],
        "The per-IP connection rate limit throttles the scan/brute-force to near uselessness.",
    ),
    "suricata-ips": (
        "Suricata IPS (Inline)",
        ["nmap-syn", "sqlmap", "hydra-ssh", "dns-tunnel", "curl-exfil"],
        "Suricata in inline mode drops matching packets before they reach the target.",
    ),
    "waf": (
        "Web Application Firewall",
        ["sqlmap", "burp-sqli", "xss-probe", "lfi", "nikto", "gobuster"],
        "WAF inspects HTTP payloads and blocks injection/traversal patterns before the app sees them.",
    ),
    "network-logging": (
        "Network Logging",
        [],   # passive only — never blocks
        "Passive capture only — the attack is logged but not blocked.",
    ),
    "honeypot": (
        "Honeypot",
        ["nmap-syn", "hydra-ssh"],
        "Attacker touches the honeypot service, generating an alert — but the attack is not stopped.",
    ),
}


def _scenario_attacks(scenario_id: str) -> list[str]:
    return SCENARIO_ATTACK_IDS.get(scenario_id, [])


def evaluate_defenses(
    scenario_id: str,
    target_nodes: list[dict],
) -> tuple[list[dict], bool]:
    """
    Evaluate all defenses across all target nodes for the given scenario.

    Returns:
        (defense_impacts, attack_blocked)

        defense_impacts: list of dicts with keys
            defense_id, defense_name, blocked, explanation, device_label

        attack_blocked: True if ANY target's defense blocks the attack
    """
    attacks = _scenario_attacks(scenario_id)
    impacts: list[dict] = []
    attack_blocked = False

    for node in target_nodes:
        data = node.get("data", {})
        device_label = data.get("label", "Unknown device")
        no_defense = data.get("noDefense", False)
        enabled = data.get("enabledDefenses", [])

        if no_defense or not enabled:
            impacts.append({
                "defense_id": "none",
                "defense_name": "No Defense",
                "blocked": False,
                "device_label": device_label,
                "explanation": (
                    f"{device_label} has no defenses configured — "
                    "the attack reaches this device unimpeded."
                ),
            })
            continue

        for def_id in enabled:
            info = DEFENSE_INFO.get(def_id)
            if not info:
                continue
            name, countered_attacks, desc = info

            # Does this defense counter any attack in the scenario?
            blocks = bool(attacks) and any(a in countered_attacks for a in attacks)

            if blocks:
                attack_blocked = True
                explanation = (
                    f"{device_label} — {name}: {desc}"
                )
            else:
                if not attacks:
                    explanation = f"{device_label} — {name}: No relevant attack traffic in this scenario."
                elif not countered_attacks:
                    explanation = (
                        f"{device_label} — {name}: This is a passive/monitoring defense that doesn't block traffic."
                    )
                else:
                    explanation = (
                        f"{device_label} — {name}: This defense does not counter the attack type "
                        f"used in the '{scenario_id.replace('-', ' ')}' scenario."
                    )

            impacts.append({
                "defense_id": def_id,
                "defense_name": name,
                "blocked": blocks,
                "device_label": device_label,
                "explanation": explanation,
            })

    return impacts, attack_blocked
