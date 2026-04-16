import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models, auth
from app.database import get_db
from app.simulation.engine import run_simulation

router = APIRouter(prefix="/api/simulate", tags=["simulation"])


class SimulateRequest(BaseModel):
    project_id: int
    scenario_id: str
    rule_texts: list[str]


@router.post("")
def simulate(
    req: SimulateRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if not req.rule_texts:
        raise HTTPException(status_code=400, detail="Add at least one rule before running the simulation.")

    # Load project topology to resolve HOME_NET / EXTERNAL_NET
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

    result = run_simulation(req.scenario_id, req.rule_texts, topology)

    return {
        "scenario": result.scenario,
        "total_packets": result.total_packets,
        "triggered_count": result.triggered_count,
        "summary": result.summary,
        "home_net": result.home_net,
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
