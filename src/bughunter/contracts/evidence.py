from __future__ import annotations

from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .enums import HttpMethod, RiskLevel


class ObservationState(StrEnum):
    RAW = "raw"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class RequestIntent(BaseModel):
    url: str
    method: HttpMethod = HttpMethod.GET
    module_id: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    purpose: str = ""
    source_artifact_id: UUID | None = None
    expected_side_effect: Literal["none", "bounded", "unknown"] = "none"
    auth_context_ref: str | None = None
    correlation_id: UUID = Field(default_factory=uuid4)


class ObservationDraft(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    state: ObservationState = ObservationState.RAW
    module_id: str = ""
    title: str = ""
    description: str = ""
    evidence_refs: tuple[UUID, ...] = ()
    metadata: dict[str, str] = Field(default_factory=dict)


class ValidationAttemptDraft(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    observation_id: UUID
    positive_result: bool = False
    negative_controls_passed: bool = False
    repeatability_confirmed: bool = False
    side_effect_observed: str = "none"
    details: str = ""
