from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .enums import RiskLevel


class TaskState(StrEnum):
    PENDING = "pending"
    PLANNED = "planned"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class TaskBudget(BaseModel):
    max_requests: int = 100
    max_runtime_seconds: float = 60.0
    max_response_bytes: int = 1_048_576
    max_redirects: int = 3
    max_retries: int = 1
    max_oob_callbacks: int = 0
    max_state_changes: int = 0

    def is_exhausted(self, consumed: TaskMetrics) -> bool:
        return (
            consumed.requests >= self.max_requests
            or consumed.runtime_seconds >= self.max_runtime_seconds
            or consumed.response_bytes >= self.max_response_bytes
        )

    def remaining(self, consumed: TaskMetrics) -> TaskBudget:
        return TaskBudget(
            max_requests=max(0, self.max_requests - consumed.requests),
            max_runtime_seconds=max(0.0, self.max_runtime_seconds - consumed.runtime_seconds),
            max_response_bytes=max(0, self.max_response_bytes - consumed.response_bytes),
            max_redirects=self.max_redirects - consumed.redirects,
            max_retries=self.max_retries - consumed.retries,
            max_oob_callbacks=self.max_oob_callbacks - consumed.oob_callbacks,
            max_state_changes=self.max_state_changes - consumed.state_changes,
        )


class TaskMetrics(BaseModel):
    requests: int = 0
    runtime_seconds: float = 0.0
    response_bytes: int = 0
    redirects: int = 0
    retries: int = 0
    oob_callbacks: int = 0
    state_changes: int = 0


class TaskSpec(BaseModel):
    id: str = ""
    scan_id: UUID = Field(default_factory=uuid4)
    module_id: str
    module_version: str = "0.1.0"
    input_artifact_ids: tuple[UUID, ...] = ()
    request_intents: tuple[UUID, ...] = ()
    policy_hash: str = ""
    budget: TaskBudget = Field(default_factory=TaskBudget)
    risk_level: RiskLevel = RiskLevel.SAFE
    depends_on: tuple[str, ...] = ()
    params: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            content = f"{self.scan_id}:{self.module_id}:{self.module_version}:{self.params}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]
