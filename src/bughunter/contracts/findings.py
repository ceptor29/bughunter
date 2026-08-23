from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingState(StrEnum):
    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    ACCEPTED_RISK = "accepted_risk"


class FindingRelation(BaseModel):
    from_finding: UUID
    to_finding: UUID
    relation: str  # "duplicate", "supersedes", "grouped_with", "caused_by"


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    stable_fingerprint: str = ""
    state: FindingState = FindingState.OBSERVATION
    title: str = ""
    affected_asset_ids: tuple[UUID, ...] = ()
    security_invariant: str = ""
    technical_impact: str = ""
    business_impact: str | None = None
    confidence: Decimal = Decimal("0.0")
    severity_label: str | None = None
    cvss_v4_vector: str | None = None
    cvss_v4_score: Decimal | None = None
    evidence_refs: tuple[UUID, ...] = ()
    validation_attempt_ids: tuple[UUID, ...] = ()
    remediation: str = ""
    review_status: str = "pending"
    module_id: str = ""
    scan_id: UUID = Field(default_factory=uuid4)
    metadata: dict[str, str] = Field(default_factory=dict)
