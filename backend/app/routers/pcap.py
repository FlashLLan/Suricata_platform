"""
pcap.py — PCAP upload and analysis endpoint.

POST /api/pcap/analyze
  Accepts a real .pcap file plus a list of Suricata rule strings.
  Returns reconstructed topology, detected scenario, traffic stats,
  and rule match results (via Real Suricata or Python fallback).
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app import auth, models
from app.simulation.pcap_analyzer import analyze_pcap
from app.simulation.suricata_runner import run_suricata, get_status as _get_docker_status
from app.simulation.suricata_mapper import map_alerts
from app.simulation.engine import run_rules_on_packets

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pcap", tags=["pcap"])

# 20 MB hard limit — real captures rarely exceed this for lab use.
_MAX_PCAP_BYTES = 20 * 1024 * 1024


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(..., description="A .pcap or .pcapng capture file"),
    rule_texts: str  = Form("[]",  description="JSON-encoded list of Suricata rule strings"),
    mode: str        = Form("python", description="'python' or 'suricata'"),
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Analyze an uploaded pcap file and evaluate Suricata rules against its traffic.

    Returns:
      topology        — canvas-ready nodes + edges reconstructed from the capture
      scenario        — best-match scenario with confidence score
      stats           — packet counts, unique IPs, duration, protocol breakdown
      results         — per-rule fired/missed results (same shape as /simulate)
      triggered_count — number of rules that fired
      total_packets   — total packets in the capture
      mode            — 'python' or 'suricata'
      suricata_fallback — true if suricata was requested but fell back to python
      summary         — human-readable result sentence
    """
    # ── Read and validate upload ──────────────────────────────────────────────
    pcap_bytes = await file.read()
    if len(pcap_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(pcap_bytes) > _MAX_PCAP_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(pcap_bytes) // 1024} KB). Maximum is 20 MB.",
        )

    # ── Parse rule_texts ──────────────────────────────────────────────────────
    try:
        rules: list[str] = json.loads(rule_texts)
        if not isinstance(rules, list):
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="rule_texts must be a JSON array of strings.")

    # ── Analyze pcap ──────────────────────────────────────────────────────────
    try:
        analysis = analyze_pcap(pcap_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        log.exception("Unexpected error during pcap analysis")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")

    # ── Extract home / external IPs from reconstructed topology ──────────────
    home_ips: list[str] = []
    ext_ips:  list[str] = []
    for node in analysis.topology.get("nodes", []):
        ip   = node.get("data", {}).get("ip", "")
        zone = node.get("data", {}).get("zone", "internal")
        if not ip:
            continue
        if zone in ("internal", "dmz", "management"):
            home_ips.append(ip)
        else:
            ext_ips.append(ip)

    if not home_ips:
        home_ips = ["192.168.1.0/24"]

    # ── Rule evaluation ───────────────────────────────────────────────────────
    actual_mode      = mode
    suricata_fallback = False
    results          = []

    if not rules:
        # No rules loaded — still return topology + scenario, just empty results
        results = []
    elif mode == "suricata":
        try:
            alerts  = run_suricata(pcap_bytes, rules)
            results = map_alerts(alerts, rules)
            actual_mode = "suricata"
        except Exception as exc:
            log.warning("Suricata mode failed for pcap import (%s); falling back to Python", exc)
            suricata_fallback = True
            actual_mode       = "python"
            results = run_rules_on_packets(
                rules,
                analysis.sim_packets,
                home_ips,
                ext_ips,
                scenario_id=analysis.scenario.scenario_id,
            )
    else:
        results = run_rules_on_packets(
            rules,
            analysis.sim_packets,
            home_ips,
            ext_ips,
            scenario_id=analysis.scenario.scenario_id,
        )

    triggered = sum(1 for r in results if r.fired)

    # ── Build summary ─────────────────────────────────────────────────────────
    scenario_name = analysis.scenario.name
    if not rules:
        summary = (
            f"Imported {analysis.stats.total_packets} packets from '{file.filename}'. "
            f"Detected scenario: {scenario_name} "
            f"(confidence {int(analysis.scenario.confidence * 100)}%). "
            f"No rules loaded — add rules to the IDS node and re-run."
        )
    elif triggered == 0:
        summary = (
            f"No rules fired against '{file.filename}' ({analysis.stats.total_packets} packets). "
            f"Detected scenario: {scenario_name}. "
            f"Either the traffic doesn't match your rules, or the rules need adjustment."
        )
    elif triggered == len(rules):
        summary = (
            f"All {len(rules)} rule(s) fired against '{file.filename}' "
            f"({analysis.stats.total_packets} packets). "
            f"Detected scenario: {scenario_name}."
        )
    else:
        summary = (
            f"{triggered} of {len(rules)} rule(s) fired against '{file.filename}' "
            f"({analysis.stats.total_packets} packets). "
            f"Detected scenario: {scenario_name}."
        )

    if suricata_fallback:
        summary = "[Fallback: Docker unavailable — results from Educational Simulation] " + summary

    # ── Response ──────────────────────────────────────────────────────────────
    return {
        "topology": analysis.topology,
        "scenario": {
            "scenario_id":  analysis.scenario.scenario_id,
            "name":         analysis.scenario.name,
            "confidence":   analysis.scenario.confidence,
            "description":  analysis.scenario.description,
            "attacker_ip":  analysis.scenario.attacker_ip,
            "target_ip":    analysis.scenario.target_ip,
        },
        "stats": {
            "total_packets":    analysis.stats.total_packets,
            "unique_ips":       analysis.stats.unique_ips,
            "duration_seconds": analysis.stats.duration_seconds,
            "protocol_counts":  analysis.stats.protocol_counts,
        },
        "results": [
            {
                "rule_sid":        r.rule_sid,
                "rule_msg":        r.rule_msg,
                "fired":           r.fired,
                "matched_packets": r.matched_packets,
                "explanation":     r.explanation,
                "why_not":         r.why_not,
            }
            for r in results
        ],
        "triggered_count":   triggered,
        "total_packets":     analysis.stats.total_packets,
        "mode":              actual_mode,
        "suricata_fallback": suricata_fallback,
        "summary":           summary,
        "filename":          file.filename or "upload.pcap",
    }
