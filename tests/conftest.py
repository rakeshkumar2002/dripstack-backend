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

import pytest

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
