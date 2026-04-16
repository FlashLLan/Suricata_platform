from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


# --- Auth ---

class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserRead(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: Optional[int] = None


# --- Projects ---

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    topology_json: Optional[str] = None
    rules_json: Optional[str] = None
    simulation_json: Optional[str] = None
    export_json: Optional[str] = None


class ProjectRead(BaseModel):
    id: int
    user_id: int
    name: str
    description: Optional[str]
    topology_json: Optional[str]
    rules_json: Optional[str]
    simulation_json: Optional[str]
    export_json: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_opened_at: datetime

    class Config:
        from_attributes = True


class ProjectSummary(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_opened_at: datetime

    class Config:
        from_attributes = True
