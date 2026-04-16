import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import models, auth
from app.database import get_db
from app.simulation.engine import run_simulation, SimulationValidationError

router = APIRouter(prefix="/api/simulate", tags=["simulation"])


class SimulateRequest(BaseModel):
    project_id: int
    scenario_id: str
    rule_texts: list[str]
    topology: Optional[dict[str, Any]] = None   # current canvas state (preferred)


@router.post("")
def simulate(
    req: SimulateRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if not req.rule_texts and req.scenario_id != "normal-browsing":
        raise HTTPException(
            status_code=400,
            detail="Add at least one Suricata rule before running the simulation.",
        )

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
        result = run_simulation(req.scenario_id, req.rule_texts, topology)
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
