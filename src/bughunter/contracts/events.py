from __future__ import annotations

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditEventKind(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_CANCELLED = "scan_cancelled"
    SCAN_COMPLETED = "scan_completed"
    TASK_LEASED = "task_leased"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    TASK_SKIPPED = "task_skipped"
    MANIFEST_LOADED = "manifest_loaded"
    MANIFEST_EXPIRED = "manifest_expired"
    SCOPE_DENIED = "scope_denied"
    SCOPE_ALLOWED = "scope_allowed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REDACTION_APPLIED = "redaction_applied"
    FINDING_PROMOTED = "finding_promoted"
    FINDING_DISMISSED = "finding_dismissed"
    CONFIG_LOADED = "config_loaded"
    CONFIG_REJECTED = "config_rejected"


class AuditEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: AuditEventKind
    scan_id: UUID = Field(default_factory=uuid4)
    task_id: str | None = None
    module_id: str | None = None
    details: dict[str, str] = Field(default_factory=dict)
    timestamp_ns: int = 0

    def model_post_init(self, __context) -> None:
        if not self.timestamp_ns:
            import time
            self.timestamp_ns = int(time.time_ns())
