"""FastAPI app factory (port of apps/api/src/server.ts + main.ts).

CORS for the dashboard, in-memory rate limiting, health/ready probes, and the
route modules. Inbound-webhook HMAC reads the raw request body inside the route
(`await request.body()`), replacing Fastify's raw-body content-type parser.
"""

from __future__ import annotations

from datetime import UTC

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from ..config import assert_production_secrets, settings
from .ratelimit import limiter
from .routes import admin, auth, dashboard, dev, ingest, platform, sso, tracking


def _security_headers(response, *, production: bool) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    if production:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
        )


def create_app() -> FastAPI:
    # Fail fast before binding the port if production is misconfigured.
    assert_production_secrets()

    app = FastAPI(title="DripStack API", version="0.1.0")

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        _security_headers(response, production=settings().is_production)
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings().cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        from datetime import datetime

        return {"status": "ok", "ts": datetime.now(UTC).isoformat()}

    @app.get("/ready")
    async def ready():
        """Readiness probe: verifies the database is reachable. Returns 503 if not,
        so an orchestrator (k8s/ECS) holds traffic until dependencies are up."""
        from fastapi.responses import JSONResponse
        from sqlalchemy import text

        from ..db.session import session_scope

        checks: dict[str, str] = {}
        ok = True
        try:
            async with session_scope() as session:
                await session.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as err:  # noqa: BLE001
            checks["database"] = f"error: {err}"
            ok = False
        return JSONResponse({"ready": ok, "checks": checks}, status_code=200 if ok else 503)

    app.include_router(auth.router)
    app.include_router(sso.router)
    app.include_router(ingest.router)
    app.include_router(tracking.router)
    app.include_router(admin.router)
    app.include_router(platform.router)
    app.include_router(dashboard.router)
    # /dev/emails renders stored email HTML unauthenticated — never mount it on a
    # public production origin. Mount-gated rather than auth-gated on purpose: the
    # dashboard links to it with a plain <a>, and the JWT lives in localStorage,
    # so a bearer dependency would turn every "view email" link into a 401.
    if not settings().is_production or settings().ENABLE_DEV_EMAIL_PREVIEW:
        app.include_router(dev.router)
    return app


app = create_app()
