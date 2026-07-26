"""Uvicorn entrypoint for the API (`uv run api`)."""

from __future__ import annotations

import uvicorn

from ..config import settings


def main() -> None:
    uvicorn.run(
        "dripstack.api.main:app",
        host="0.0.0.0",
        port=settings().API_PORT,
        log_level=settings().LOG_LEVEL.lower(),
        # Behind a TLS-terminating proxy, honour X-Forwarded-{For,Proto} so
        # request.url and the client IP are real. slowapi keys its rate limits on
        # the client IP and the audit log records it, so both are wrong without this.
        proxy_headers=True,
        forwarded_allow_ips=settings().FORWARDED_ALLOW_IPS,
    )


if __name__ == "__main__":
    main()
