"""
suricata_mapper.py — Map eve.json alert dicts → list[RuleMatchResult].

The mapper bridges the gap between what Suricata returns (a flat list of
alert events keyed by signature_id) and what the rest of the engine expects
(one RuleMatchResult per loaded rule, whether fired or not).

Workflow
--------
1. Parse each raw rule text with rule_parser.parse_rule() to extract its SID.
2. Build a SID → [eve_alert, …] index from the Suricata output.
3. For every rule:
   - Fired (SID present in index):  build RuleMatchResult with matched_packets
     reconstructed from eve.json fields.
   - Not fired (SID absent):  build RuleMatchResult(fired=False) with a
     Suricata-mode why_not message that nudges users toward Python mode for
     the detailed per-keyword diagnosis.
4. Rules whose text cannot be parsed (syntax error) get a dedicated result
   identical to the Python engine's parse-error handling.

Note on explicitness:  Suricata mode cannot tell WHY a rule didn't fire —
it only tells us with certainty THAT it didn't.  The why_not messages here
intentionally reflect that distinction and encourage switching to Educational
Simulation mode for learning.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from app.simulation.rule_parser import parse_rule
from app.simulation.engine import RuleMatchResult


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_alerts(
    alerts: list[dict],
    rule_texts: list[str],
) -> list[RuleMatchResult]:
    """
    Convert Suricata eve.json alert dicts into a ``RuleMatchResult`` per rule.

    Parameters
    ----------
    alerts:      list of alert dicts from suricata_runner.run_suricata()
                 (already filtered to event_type == "alert").
    rule_texts:  the same rule strings that were passed to run_suricata(),
                 in the same order.

    Returns
    -------
    One RuleMatchResult per element of *rule_texts*, preserving order.
    """
    # ── Index alerts by SID (integer key for reliable matching) ───────────────
    by_sid: dict[int, list[dict]] = defaultdict(list)
    for alert in alerts:
        sid = _extract_sid(alert)
        if sid is not None:
            by_sid[sid].append(alert)

    # ── One result per rule text ──────────────────────────────────────────────
    results: list[RuleMatchResult] = []
    for raw in rule_texts:
        parsed = parse_rule(raw)

        if parsed is None:
            # Un-parseable rule — same treatment as Python engine
            sid_hint = _hint_sid(raw)
            msg_hint = _hint_msg(raw)
            results.append(RuleMatchResult(
                rule_sid=sid_hint,
                rule_msg=msg_hint,
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
            continue

        try:
            rule_sid_int = int(parsed.sid)
        except (ValueError, TypeError):
            rule_sid_int = None

        fired_alerts = by_sid.get(rule_sid_int, []) if rule_sid_int is not None else []
        fired = len(fired_alerts) > 0

        if fired:
            results.append(_build_fired_result(parsed.sid, parsed.msg, fired_alerts))
        else:
            results.append(_build_missed_result(parsed.sid, parsed.msg))

    return results


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _build_fired_result(
    sid: str,
    msg: str,
    fired_alerts: list[dict],
) -> RuleMatchResult:
    """Build a RuleMatchResult for a rule that Suricata did fire."""
    matched_packets = [_eve_to_packet(a) for a in fired_alerts[:10]]

    count = len(fired_alerts)
    sources = _distinct(a.get("src_ip", "?") for a in fired_alerts)
    dests   = _distinct(
        f"{a.get('dest_ip', '?')}:{a.get('dest_port', '?')}"
        for a in fired_alerts
    )

    explanation_parts = [
        f"[Real Suricata] Rule fired — {count} alert(s) generated.",
        f"Traffic: {', '.join(sources)} → {', '.join(dests)}.",
    ]

    # Pull severity / category from the first alert's nested alert block
    first_alert_block = fired_alerts[0].get("alert", {})
    category = first_alert_block.get("category", "")
    severity = first_alert_block.get("severity")
    if category:
        explanation_parts.append(f"Classtype: {category}.")
    if severity is not None:
        explanation_parts.append(f"Severity: {severity}.")

    explanation_parts.append(
        "This result comes directly from a real Suricata process — "
        "it reflects true production rule behaviour."
    )

    return RuleMatchResult(
        rule_sid=sid,
        rule_msg=msg,
        fired=True,
        matched_packets=matched_packets,
        explanation=" ".join(explanation_parts),
    )


def _build_missed_result(sid: str, msg: str) -> RuleMatchResult:
    """Build a RuleMatchResult for a rule that Suricata did NOT fire."""
    return RuleMatchResult(
        rule_sid=sid,
        rule_msg=msg,
        fired=False,
        explanation=f"[Real Suricata] Rule SID {sid} did not fire on the generated traffic.",
        why_not=(
            "Suricata processed the traffic and produced no alert for this rule. "
            "This is a definitive result — the rule genuinely did not match. "
            "Possible reasons: wrong protocol/port, payload not matching content keywords, "
            "flow state mismatch, or threshold not reached. "
            "Switch to Educational Simulation mode for a step-by-step breakdown "
            "of exactly which condition failed."
        ),
    )


# ---------------------------------------------------------------------------
# eve.json helpers
# ---------------------------------------------------------------------------

def _extract_sid(alert: dict) -> Optional[int]:
    """Extract the integer SID from an eve.json alert dict."""
    try:
        return int(alert["alert"]["signature_id"])
    except (KeyError, TypeError, ValueError):
        return None


def _eve_to_packet(alert: dict) -> dict:
    """
    Convert one eve.json alert dict into the matched_packet shape that the
    frontend's Detection tab expects (same keys as Python engine output).
    """
    proto = alert.get("proto", "?").lower()
    src_ip   = alert.get("src_ip",   "?")
    src_port = alert.get("src_port", "?")
    dst_ip   = alert.get("dest_ip",  "?")
    dst_port = alert.get("dest_port","?")

    # payload_printable is present only when payload logging is enabled
    payload_preview = (
        alert.get("payload_printable")
        or alert.get("payload", "")
    )
    if isinstance(payload_preview, str):
        payload_preview = payload_preview[:120]
    else:
        payload_preview = ""

    sig = alert.get("alert", {}).get("signature", "")

    return {
        "protocol": proto,
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "description": f"[Suricata] {sig}" if sig else f"[Suricata] SID alert",
        "payload_preview": payload_preview,
    }


# ---------------------------------------------------------------------------
# Fallback hint extraction (for un-parseable rules)
# ---------------------------------------------------------------------------

def _hint_sid(raw: str) -> str:
    m = re.search(r'\bsid\s*:\s*(\d+)', raw)
    return m.group(1) if m else "?"


def _hint_msg(raw: str) -> str:
    m = re.search(r'\bmsg\s*:\s*"([^"]+)"', raw)
    if m:
        return m.group(1)
    return raw[:60].strip()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _distinct(iterable) -> list[str]:
    """Return a deduplicated list preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in iterable:
        s = str(item)
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result
