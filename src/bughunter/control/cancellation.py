from __future__ import annotations

import asyncio


class CancellationManager:
    def __init__(self) -> None:
        self._cancelled: asyncio.Event = asyncio.Event()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def reset(self) -> None:
        self._cancelled.clear()

    async def wait(self, timeout: float | None = None) -> bool:
        try:
            await asyncio.wait_for(self._cancelled.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def check(self) -> None:
        if self._cancelled.is_set():
            raise asyncio.CancelledError("Scan cancelled by operator")
