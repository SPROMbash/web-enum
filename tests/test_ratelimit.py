"""RateLimiter: spacing, concurrency, budget, back-pressure."""

from __future__ import annotations

import asyncio

import pytest

from tests.fakes import FakeClock
from web_enum.errors import BudgetExhaustedError
from web_enum.ratelimit import MAX_INTERVAL, RateLimiter


def make(
    clock: FakeClock, *, rate: float = 2, concurrency: int = 5, budget: int = 100
) -> RateLimiter:
    return RateLimiter(
        rate=rate, concurrency=concurrency, max_requests=budget, clock=clock, sleep=clock.sleep
    )


async def test_sequential_requests_are_spaced() -> None:
    clock = FakeClock()
    limiter = make(clock, rate=2)
    for _ in range(3):
        async with limiter:
            pass
    assert clock.sleeps == [0.5, 0.5]  # first goes immediately, then 1/rate apart
    assert limiter.used == 3 and limiter.remaining == 97


async def test_concurrent_requests_book_distinct_slots() -> None:
    clock = FakeClock(advance=False)  # all tasks arrive at t=0
    limiter = make(clock, rate=4)

    async def one() -> None:
        async with limiter:
            pass

    await asyncio.gather(*(one() for _ in range(4)))
    assert sorted(clock.sleeps) == [0.25, 0.5, 0.75]  # no two requests share a slot


async def test_concurrency_is_capped() -> None:
    limiter = RateLimiter(rate=1000, concurrency=3, max_requests=100)
    in_flight = peak = 0

    async def one() -> None:
        nonlocal in_flight, peak
        async with limiter:
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.001)
            in_flight -= 1

    await asyncio.gather(*(one() for _ in range(12)))
    assert peak == 3


async def test_budget_is_enforced() -> None:
    limiter = make(FakeClock(), budget=2)
    for _ in range(2):
        async with limiter:
            pass
    with pytest.raises(BudgetExhaustedError, match="2 requests"):
        async with limiter:
            pass  # pragma: no cover - never reached
    assert limiter.remaining == 0


async def test_semaphore_released_when_cancelled_while_waiting() -> None:
    clock = FakeClock()
    limiter = make(clock, concurrency=1)

    async def cancelled_sleep(_: float) -> None:
        raise asyncio.CancelledError

    limiter._sleep = cancelled_sleep
    async with limiter:  # first request: no wait, so no cancellation
        pass
    with pytest.raises(asyncio.CancelledError):
        async with limiter:  # second has to wait -> cancelled
            pass  # pragma: no cover
    limiter._sleep = clock.sleep

    async def acquire() -> None:
        async with limiter:
            pass

    await asyncio.wait_for(acquire(), timeout=1)  # would hang forever if the slot had leaked


async def test_penalize_delays_everybody() -> None:
    clock = FakeClock()
    limiter = make(clock, rate=10)
    limiter.penalize(7)
    limiter.penalize(2)  # a shorter penalty never shortens a longer one
    limiter.penalize(0)
    async with limiter:
        pass
    assert clock.sleeps == [7.0]


async def test_slow_down_halves_rate_until_floor() -> None:
    clock = FakeClock()
    limiter = make(clock, rate=2)
    assert limiter.slow_down() == 1.0
    async with limiter:
        pass
    async with limiter:
        pass
    assert clock.sleeps == [1.0]
    for _ in range(10):
        limiter.slow_down()
    assert limiter.interval == MAX_INTERVAL


@pytest.mark.parametrize(
    "kwargs",
    [{"rate": 0, "concurrency": 1, "max_requests": 1},
     {"rate": 1, "concurrency": 0, "max_requests": 1},
     {"rate": 1, "concurrency": 1, "max_requests": 0}],
)
def test_invalid_parameters(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        RateLimiter(**kwargs)  # type: ignore[arg-type]
