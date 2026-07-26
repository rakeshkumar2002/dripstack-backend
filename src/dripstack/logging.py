"""Structured logger (replaces packages/core/src/logger.ts pino).

Use `log = logger.bind(run_id=..., org_id=...)` to add correlation context, the
structlog equivalent of pino's `.child({...})`.
"""

from __future__ import annotations

import logging
import sys

import structlog

from .config import settings

_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    level = getattr(logging, settings().LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        cache_logger_on_first_use=True,
    )
    _configured = True


_configure()

logger = structlog.get_logger("dripstack")
