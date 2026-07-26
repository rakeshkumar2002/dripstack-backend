"""Centralised, validated environment access (replaces packages/core/src/env.ts).

Mirrors the TS `bootstrapDotenv()` walk-up: in this repo nothing auto-loads the
root `.env` into the environment, and the backend may run from any cwd, so we
locate the nearest `.env` by walking up before constructing Settings.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_dotenv() -> Path | None:
    """Walk up from cwd looking for the repo-root `.env`."""
    here = Path.cwd()
    for parent in [here, *here.parents][:8]:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate
    return None


_dotenv = _find_dotenv()
if _dotenv is not None:
    load_dotenv(_dotenv)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True, extra="ignore")

    NODE_ENV: str = "development"
    APP_BASE_URL: str = "http://localhost:4000"
    DASHBOARD_URL: str = "http://localhost:3000"
    # Extra browser origins allowed by CORS (preview/staging deploys), comma
    # separated. DASHBOARD_URL stays the single canonical origin used for the
    # SSO/notification redirects, which must stay deterministic.
    CORS_ALLOWED_ORIGINS: str = ""

    DATABASE_URL: str | None = None

    # Queue (RabbitMQ).
    RABBITMQ_URL: str = "amqp://dripstack:dripstack@localhost:5672/"

    TEMPORAL_ADDRESS: str = "localhost:7233"
    TEMPORAL_NAMESPACE: str = "default"
    TEMPORAL_TASK_QUEUE: str = "dripstack-sequences"

    JWT_ACCESS_SECRET: str = "dev-access-secret-change-me"
    JWT_REFRESH_SECRET: str = "dev-refresh-secret-change-me"
    JWT_ACCESS_TTL: str = "15m"
    JWT_REFRESH_TTL: str = "7d"
    LINK_SIGNING_SECRET: str = "dev-link-signing-secret-change-me"

    EMAIL_PROVIDER: str = "log"  # log | resend | ses
    EMAIL_FROM_DEFAULT: str = "DripStack <alerts@dripstack.dev>"
    RESEND_API_KEY: str | None = None

    # AWS SES (used when EMAIL_PROVIDER=ses). Credentials come from the standard
    # boto3 chain (env / shared config / IAM role); only the region is required.
    AWS_REGION: str = "us-east-1"
    SES_CONFIGURATION_SET: str | None = None

    AI_PROVIDER: str = "fallback"  # anthropic | fallback
    ANTHROPIC_API_KEY: str | None = None
    AI_MODEL: str = "claude-sonnet-4-6"

    SLACK_BOT_TOKEN: str | None = None
    TEAMS_WEBHOOK_URL: str | None = None

    API_PORT: int = 4000
    LOG_LEVEL: str = "info"

    # Trusted proxy hops for X-Forwarded-For / X-Forwarded-Proto. Behind the
    # compose Caddy this should be the bridge subnet (or "*" when the API port
    # is only reachable on the compose network) — slowapi rate-limits per client
    # IP, so trusting an untrusted hop makes the limit spoofable.
    FORWARDED_ALLOW_IPS: str = "127.0.0.1"

    # /dev/emails renders stored email HTML with no auth. Off in production.
    ENABLE_DEV_EMAIL_PREVIEW: bool = False

    @property
    def is_production(self) -> bool:
        return self.NODE_ENV.lower() in ("production", "prod")

    @property
    def cors_origins(self) -> list[str]:
        """Browser origins allowed by CORS: DASHBOARD_URL plus any extras.

        An `Origin` header never carries a trailing slash, so a DASHBOARD_URL of
        "https://x.com/" would silently match nothing and 403 every browser
        request. Normalise here; link building keeps its own rstrip.
        """
        out: list[str] = []
        for raw in [self.DASHBOARD_URL, *self.CORS_ALLOWED_ORIGINS.split(",")]:
            origin = raw.strip().rstrip("/")
            if origin and origin not in out:
                out.append(origin)
        return out

    @property
    def sqlalchemy_url(self) -> str:
        """Translate the Prisma-style DATABASE_URL into an asyncpg SQLAlchemy URL.

        Prisma uses `postgresql://...?schema=public`; asyncpg does not understand
        the `schema` query param, so we strip it and switch the driver.
        """
        url = self.DATABASE_URL or "postgresql://dripstack:dripstack@localhost:5432/dripstack"
        # Drop query string (e.g. ?schema=public) which asyncpg rejects.
        url = url.split("?", 1)[0]
        if url.startswith("postgresql+"):
            return url
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url

    @property
    def alembic_url(self) -> str:
        """Sync (psycopg/asyncpg via run_sync) URL used by Alembic env."""
        return self.sqlalchemy_url


@lru_cache
def settings() -> Settings:
    return Settings()


# Secrets that ship as insecure dev defaults; refusing to boot production with
# any of these unchanged prevents the classic "deployed with the demo secret"
# class of incident (forgeable JWTs / tamperable tracked links).
_INSECURE_DEFAULTS = {
    "JWT_ACCESS_SECRET": "dev-access-secret-change-me",
    "JWT_REFRESH_SECRET": "dev-refresh-secret-change-me",
    "LINK_SIGNING_SECRET": "dev-link-signing-secret-change-me",
}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def assert_production_secrets(s: Settings | None = None) -> None:
    """Fail fast if production is running with dev secrets. No-op outside prod.

    Called at API and worker startup. Raises RuntimeError listing every secret
    that is still a default or too short (< 32 bytes for HS256/HMAC).
    """
    s = s or settings()
    if not s.is_production:
        return
    problems: list[str] = []
    for name, insecure in _INSECURE_DEFAULTS.items():
        value = getattr(s, name) or ""
        if value == insecure:
            problems.append(f"{name} is still the insecure dev default")
        elif len(value) < 32:
            problems.append(f"{name} must be at least 32 chars (got {len(value)})")
    if s.DATABASE_URL is None:
        problems.append("DATABASE_URL must be set in production")
    # Without these, production boots fine and then 403s every browser request
    # (CORS origin mismatch) and mails un-clickable localhost tracked links.
    for name in ("APP_BASE_URL", "DASHBOARD_URL"):
        value = (getattr(s, name) or "").strip()
        if not value:
            problems.append(f"{name} must be set in production")
            continue
        parsed = urlparse(value)
        if parsed.scheme != "https":
            problems.append(f"{name} must be an https:// URL in production (got {value!r})")
        if (parsed.hostname or "") in _LOCAL_HOSTS:
            problems.append(f"{name} still points at localhost ({value!r})")
        if value.endswith("/"):
            problems.append(f"{name} must not end in '/' (breaks CORS origin matching)")
    if problems:
        raise RuntimeError(
            "Refusing to start in production with insecure configuration:\n  - "
            + "\n  - ".join(problems)
            + "\nGenerate strong secrets, e.g.  openssl rand -hex 32"
        )
