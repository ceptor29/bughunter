from __future__ import annotations

from dataclasses import dataclass, field

from bughunter.contracts.tasks import TaskBudget, TaskMetrics


@dataclass
class PhaseBudget:
    name: str
    max_requests: int
    max_runtime_seconds: float = 3600.0
    consumed: TaskMetrics = field(default_factory=TaskMetrics)

    def check(self) -> bool:
        if self.consumed.requests >= self.max_requests:
            return False
        if self.consumed.runtime_seconds >= self.max_runtime_seconds:
            return False
        return True

    def record(self, requests: int = 0, runtime: float = 0.0) -> None:
        self.consumed.requests += requests
        self.consumed.runtime_seconds += runtime


class BudgetManager:
    def __init__(self, global_budget: TaskBudget | None = None) -> None:
        self._global = global_budget or TaskBudget(
            max_requests=5000, max_runtime_seconds=3600, max_response_bytes=50_000_000
        )
        self._consumed = TaskMetrics()
        self._phases: dict[str, PhaseBudget] = {}

    def register_phase(self, name: str, max_requests: int, max_runtime: float = 3600.0) -> PhaseBudget:
        phase = PhaseBudget(name=name, max_requests=max_requests, max_runtime_seconds=max_runtime)
        self._phases[name] = phase
        return phase

    def check(self, task_budget: TaskBudget | None = None, phase: str | None = None) -> bool:
        if self._consumed.requests >= self._global.max_requests:
            return False
        if self._consumed.runtime_seconds >= self._global.max_runtime_seconds:
            return False
        if task_budget and task_budget.is_exhausted(self._consumed):
            return False
        if phase and phase in self._phases:
            if not self._phases[phase].check():
                return False
        return True

    def record(self, requests: int = 0, runtime: float = 0.0, response_bytes: int = 0, phase: str | None = None) -> None:
        self._consumed.requests += requests
        self._consumed.runtime_seconds += runtime
        self._consumed.response_bytes += response_bytes
        if phase and phase in self._phases:
            self._phases[phase].record(requests=requests, runtime=runtime)

    @property
    def consumed(self) -> TaskMetrics:
        return self._consumed.model_copy()

    @property
    def remaining(self) -> TaskBudget:
        return self._global.remaining(self._consumed)

    def phase_summary(self) -> dict[str, dict[str, int]]:
        return {
            name: {"max": p.max_requests, "consumed": p.consumed.requests}
            for name, p in self._phases.items()
        }
