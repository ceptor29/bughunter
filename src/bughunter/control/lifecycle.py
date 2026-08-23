from __future__ import annotations

from uuid import UUID, uuid4

from bughunter.contracts.tasks import TaskSpec, TaskState


class ScanLifecycle:
    def __init__(self, scan_id: UUID | None = None) -> None:
        self.scan_id = scan_id or uuid4()
        self._tasks: dict[str, TaskState] = {}
        self._metrics: dict[str, dict] = {}

    def register_task(self, task: TaskSpec) -> None:
        self._tasks[task.id] = TaskState.PENDING

    def update_state(self, task_id: str, state: TaskState) -> None:
        if task_id in self._tasks:
            self._tasks[task_id] = state

    def get_state(self, task_id: str) -> TaskState:
        return self._tasks.get(task_id, TaskState.PENDING)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for state in self._tasks.values():
            counts[state.value] = counts.get(state.value, 0) + 1
        return counts

    @property
    def is_complete(self) -> bool:
        terminal = {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED, TaskState.SKIPPED}
        return all(s in terminal for s in self._tasks.values()) if self._tasks else True
