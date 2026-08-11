"""Shared test fixtures.

pytest-asyncio (auto mode) runs each test in a fresh event loop, but the app's
async engine is a module-global bound to whichever loop created it first — so
after the first DB-touching test, asyncpg connections belong to a dead loop and
every later DB test would fail to connect (and skip itself as "DB not reachable").

This autouse fixture rebinds a fresh engine to each test's own loop and disposes
it afterwards, so every DB-integration test runs reliably and connections don't
leak between loops.
"""

from __future__ import annotations

import warnings

import pytest

from dripstack.api.ratelimit import limiter
from dripstack.db import session as dbsession


@pytest.fixture(autouse=True)
async def _engine_per_test():
    dbsession._engine = None
    dbsession._sessionmaker = None
    yield
    engine = dbsession._engine
    if engine is not None:
        await engine.dispose()
    dbsession._engine = None
    dbsession._sessionmaker = None


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the in-memory rate-limit counters between tests.

    The limiter keys on client IP, and every test hits the app from the same
    one. Without this, the login throttle (10/minute) starts rejecting later
    tests in the file purely because earlier tests logged in — a real limit
    turning into a flaky suite. Tests that assert throttling still exercise it
    fully, because each gets a clean slate and trips the limit on its own.
    """
    limiter.reset()
    yield


@pytest.fixture
async def cleanup():
    """Remove rows a test created, even when the test fails.

    Deletes straight through the ORM rather than the API, deliberately. An
    earlier version registered `lambda: c.delete(...)` closures over the test's
    httpx client — but `async with AsyncClient(...)` closes that client when the
    test body exits, which is BEFORE fixture teardown, so every delete threw and
    the suppression below hid it. Going via the database has no such lifecycle.

        src = (await c.post("/api/v1/event-sources", ...)).json()["eventSource"]
        cleanup(EventSource, src["id"])

    Teardown runs in reverse order so children go before parents. Failures are
    reported, not silently swallowed — a cleanup that quietly stops working is
    exactly how the orphans accumulated in the first place.
    """
    planned: list[tuple[type, str]] = []

    def register(model, pk: str):
        planned.append((model, pk))
        return pk

    yield register

    if not planned:
        return
    from dripstack.db.session import session_scope

    failures = []
    for model, pk in reversed(planned):
        try:
            async with session_scope() as s:
                row = await s.get(model, pk)
                if row is not None:
                    await s.delete(row)
        except Exception as err:  # noqa: BLE001
            failures.append(f"{model.__name__}({pk}): {err}")
    if failures:
        warnings.warn("test cleanup failed, rows may be orphaned: " + "; ".join(failures), stacklevel=1)
