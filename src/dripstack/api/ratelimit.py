"""Shared slowapi limiter (in-memory) — replaces @fastify/rate-limit.

Global default mirrors the TS 1000/min; the ingest route overrides to 120/min.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["1000/minute"])
