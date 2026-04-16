from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=List[schemas.ProjectSummary])
def list_projects(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Project)
        .filter(models.Project.user_id == current_user.id)
        .order_by(models.Project.updated_at.desc())
        .all()
    )


@router.post("", response_model=schemas.ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(
    project_in: schemas.ProjectCreate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    project = models.Project(
        user_id=current_user.id,
        name=project_in.name,
        description=project_in.description,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/{project_id}", response_model=schemas.ProjectRead)
def get_project(
    project_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    project = _get_owned_project(project_id, current_user.id, db)
    project.last_opened_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(project)
    return project


@router.patch("/{project_id}", response_model=schemas.ProjectRead)
def update_project(
    project_id: int,
    project_in: schemas.ProjectUpdate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    project = _get_owned_project(project_id, current_user.id, db)
    for field, value in project_in.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    project.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    project = _get_owned_project(project_id, current_user.id, db)
    db.delete(project)
    db.commit()


def _get_owned_project(project_id: int, user_id: int, db: Session) -> models.Project:
    project = db.query(models.Project).filter(
        models.Project.id == project_id,
        models.Project.user_id == user_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
