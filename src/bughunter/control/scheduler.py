from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from bughunter.contracts.enums import SkipReason
from bughunter.contracts.tasks import TaskSpec, TaskState, TaskMetrics


class Scheduler:
    def __init__(self, max_concurrency: int = 20) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._running: dict[str, asyncio.Task] = {}
        self._cancelled: set[str] = set()

    async def lease_and_run(
        self,
        task: TaskSpec,
        executor: Callable[[TaskSpec], Coroutine[Any, Any, Any]],
    ) -> TaskState:
        if task.id in self._cancelled:
            return TaskState.CANCELLED

        async with self._semaphore:
            if task.id in self._cancelled:
                return TaskState.CANCELLED
            try:
                await executor(task)
                return TaskState.COMPLETED
            except asyncio.CancelledError:
                return TaskState.CANCELLED
            except Exception:
                return TaskState.FAILED

    def cancel_task(self, task_id: str) -> None:
        self._cancelled.add(task_id)
        if task_id in self._running:
            self._running[task_id].cancel()

    def cancel_all(self) -> None:
        for tid in list(self._running):
            self.cancel_task(tid)

    @property
    def active_count(self) -> int:
        return len(self._running)
