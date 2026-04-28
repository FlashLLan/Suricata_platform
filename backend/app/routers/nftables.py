from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app import models, auth
from app.simulation.nftables_validator import validate_nftables_config, get_status

router = APIRouter(prefix="/api/nftables", tags=["nftables"])


class ValidateRequest(BaseModel):
    config: str


@router.post("/validate")
def validate(
    req: ValidateRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Validate an nftables config string using `nft --check` inside Docker.
    Returns { valid, errors, raw_output, docker_available }.
    """
    return validate_nftables_config(req.config)


@router.get("/status")
def nft_status(
    current_user: models.User = Depends(auth.get_current_user),
):
    """Return the Docker + nftables validator image availability status."""
    return get_status().as_dict()
