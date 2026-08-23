from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, rps: float = 10.0, burst: int = 20) -> None:
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._semaphore = asyncio.Semaphore(burst)
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._semaphore:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_request
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)
                self._last_request = time.monotonic()
