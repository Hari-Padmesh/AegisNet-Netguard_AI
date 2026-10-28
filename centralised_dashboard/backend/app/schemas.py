from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints
from typing_extensions import Annotated

Password = Annotated[str, StringConstraints(min_length=12, max_length=256)]


class SignupBody(BaseModel):
    email: EmailStr
    password: Password
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)]


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class ProjectCreate(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    framework: str = "FastAPI"


class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_id: str
    timestamp: str | None = None
    severity: str = "LOW"
    label: str = "Security event"
    confidence: float | None = None
    client_ip: str | None = None
    path: str | None = None
    method: str | None = None
    rule_id: str | None = None
    flow_summary: str | None = None
    detection_source: str | None = None


class IngestTelemetry(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_id: str
    stats: dict[str, Any] = Field(default_factory=dict)
