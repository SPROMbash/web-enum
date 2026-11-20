"""One limiter for the whole scan: concurrency + requests/second + request budget.

* **Concurrency**: a semaphore; at most ``concurrency`` requests in flight.
* **Rate**: requests are spaced ``1 / rate`` seconds apart. Each request books
  the next free time slot *before* waiting, so concurrent tasks never pick the
  same slot (no bursts).
* **Budget**: every request sent (retries included) consumes one unit of
  ``max_requests``; once exhausted, :class:`BudgetExhaustedError` is raised.
* **Back-pressure**: :meth:`penalize` pushes the next slot later (Retry-After,
  backoff) and :meth:`slow_down` halves the rate when the server answers 429.
  Both act on *every* task, because the server is the same for all of them.

The clock and ``sleep`` are injectable, so tests run instantly and deterministically.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from types import TracebackType

from web_enum.errors import BudgetExhaustedError

MAX_INTERVAL = 5.0  # slow_down never goes slower than one request every 5 s


class RateLimiter:
    def __init__(
        self,
        *,
        rate: float,
        concurrency: int,
        max_requests: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rate <= 0 or concurrency < 1 or max_requests < 1:
            raise ValueError("rate, concurrency and max_requests must be positive")
        self.interval = 1.0 / rate
        self.concurrency = concurrency
        self.max_requests = max_requests
        self.used = 0
        self._clock = clock
        self._sleep = sleep
        self._semaphore = asyncio.Semaphore(concurrency)
        self._next_slot = 0.0

    @property
    def rate(self) -> float:
        """Current requests/second (lower than configured after slow_down)."""
        return 1.0 / self.interval

    @property
    def remaining(self) -> int:
        return self.max_requests - self.used

    async def __aenter__(self) -> RateLimiter:
        await self._semaphore.acquire()
        try:
            await self._wait_turn()
        except BaseException:
            self._semaphore.release()  # cancelled or over budget: free the slot
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._semaphore.release()

    async def _wait_turn(self) -> None:
        if self.used >= self.max_requests:
            raise BudgetExhaustedError(
                f"Request budget exhausted ({self.max_requests} requests, limits.max_requests)"
            )
        self.used += 1
        # No await between reading and booking the slot: atomic under asyncio.
        now = self._clock()
        slot = max(now, self._next_slot)
        self._next_slot = slot + self.interval
        if slot > now:
            await self._sleep(slot - now)

    def reserve(self, wanted: int) -> int:
        """Book up to ``wanted`` requests sent by an external tool; returns how many.

        ffuf / feroxbuster do not go through this limiter, so their requests are
        booked up front and the job is sized (and time-capped) to fit.
        """
        granted = max(0, min(wanted, self.remaining))
        self.used += granted
        return granted

    def penalize(self, seconds: float) -> None:
        """Nobody sends anything for at least ``seconds`` from now."""
        if seconds > 0:
            self._next_slot = max(self._next_slot, self._clock() + seconds)

    def slow_down(self) -> float:
        """Halve the rate (down to one request every MAX_INTERVAL s); returns the new rate."""
        self.interval = min(self.interval * 2, MAX_INTERVAL)
        return self.rate
