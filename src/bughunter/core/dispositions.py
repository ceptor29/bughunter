from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DispositionKind(StrEnum):
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    OPEN = "open"


class Disposition(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    kind: DispositionKind
    reason: str = ""
    operator: str = "system"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    related_finding_id: UUID | None = None  # for DUPLICATE links


class DispositionTracker:
    def __init__(self) -> None:
        self._dispositions: dict[UUID, list[Disposition]] = {}

    def set(
        self,
        finding_id: UUID,
        kind: DispositionKind,
        reason: str = "",
        operator: str = "system",
        related_finding_id: UUID | None = None,
    ) -> Disposition:
        disp = Disposition(
            finding_id=finding_id,
            kind=kind,
            reason=reason,
            operator=operator,
            related_finding_id=related_finding_id,
        )
        self._dispositions.setdefault(finding_id, []).append(disp)
        return disp

    def get_latest(self, finding_id: UUID) -> Disposition | None:
        disps = self._dispositions.get(finding_id, [])
        return disps[-1] if disps else None

    def get_all(self, finding_id: UUID) -> list[Disposition]:
        return list(self._dispositions.get(finding_id, []))

    def is_false_positive(self, finding_id: UUID) -> bool:
        latest = self.get_latest(finding_id)
        return latest.kind == DispositionKind.FALSE_POSITIVE if latest else False

    def is_fixed(self, finding_id: UUID) -> bool:
        latest = self.get_latest(finding_id)
        return latest.kind == DispositionKind.FIXED if latest else False
