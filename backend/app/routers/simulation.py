import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import models, auth
from app.database import get_db
from app.simulation.engine import run_simulation, SimulationValidationError
from app.simulation.suricata_runner import get_status as _get_docker_status

router = APIRouter(prefix="/api/simulate", tags=["simulation"])


class SimulateRequest(BaseModel):
    project_id: int
    scenario_id: str
    rule_texts: list[str]
    topology: Optional[dict[str, Any]] = None   # current canvas state (preferred)
    mode: str = "python"                         # "python" | "suricata"
    custom_commands: Optional[str] = None        # used when scenario_id == "custom-commands"


@router.post("")
def simulate(
    req: SimulateRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    # Prefer topology sent directly from the frontend (current canvas state);
    # fall back to the saved DB version only if the client didn't send one.
    if req.topology is not None:
        topology = req.topology
    else:
        project = db.query(models.Project).filter(
            models.Project.id == req.project_id,
            models.Project.user_id == current_user.id,
        ).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")
        try:
            topology = json.loads(project.topology_json or "{}")
        except json.JSONDecodeError:
            topology = {}

    try:
        result = run_simulation(req.scenario_id, req.rule_texts, topology, mode=req.mode, custom_commands=req.custom_commands)
    except SimulationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "scenario": result.scenario,
        "total_packets": result.total_packets,
        "triggered_count": result.triggered_count,
        "summary": result.summary,
        "home_net": result.home_net,
        "attacker_ip": result.attacker_ip,
        "target_ips": result.target_ips,
        "attack_path": result.attack_path,
        "attack_blocked": result.attack_blocked,
        "attack_reached_target": result.attack_reached_target,
        "defense_impacts": result.defense_impacts,
        "ids_visible": result.ids_visible,
        "ids_node_labels": result.ids_node_labels,
        "timeline": result.timeline,
        "mode": result.mode,
        "suricata_fallback": result.suricata_fallback,
        "results": [
            {
                "rule_sid": r.rule_sid,
                "rule_msg": r.rule_msg,
                "fired": r.fired,
                "matched_packets": r.matched_packets,
                "explanation": r.explanation,
                "why_not": r.why_not,
            }
            for r in result.results
        ],
    }


@router.get("/status")
def simulation_status(
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Return Docker + Suricata image availability for the current host.

    States returned in ``state``:
      "docker_unavailable"  — Docker daemon not running
      "image_not_pulled"    — Docker up, jasonish/suricata not downloaded yet
      "ready"               — Real Suricata mode fully available
    """
    return _get_docker_status().as_dict()
