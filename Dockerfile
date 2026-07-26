# syntax=docker/dockerfile:1.7
#
# One image, three entrypoints: `api`, `worker`, `seed` (plus `alembic`).
#
# The API and worker share the entire dependency closure and bind the same
# SQLAlchemy models, and the API's tracking routes signal workflows the worker
# executes — version skew between them is an outage. One image, one digest,
# guaranteed parity across a migration boundary. Pick the process at run time:
#
#   docker run --env-file .env dripstack-backend                    # api
#   docker run --env-file .env dripstack-backend worker
#   docker run --env-file .env dripstack-backend alembic upgrade head

# ─── builder ─────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder

# Copied from a pinned image rather than curl-installed, so builds are reproducible.
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependency layer, invalidated only by pyproject.toml / uv.lock. --all-extras
# pulls in [ses] (aioboto3) so one image supports EMAIL_PROVIDER=ses without an
# ImportError at the first send.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --frozen --no-install-project --no-dev --all-extras

# Project layer. uv installs the project editable via a .pth file holding an
# ABSOLUTE path, so the runtime stage must use this same /app WORKDIR — a
# mismatch fails at container start with no build-time signal.
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-extras

# ─── runtime ─────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd --system --gid 1001 dripstack \
 && useradd  --system --uid 1001 --gid dripstack --create-home dripstack

WORKDIR /app

COPY --from=builder --chown=dripstack:dripstack /app/.venv      /app/.venv
COPY --from=builder --chown=dripstack:dripstack /app/src        /app/src
COPY --from=builder --chown=dripstack:dripstack /app/alembic    /app/alembic
COPY --from=builder --chown=dripstack:dripstack /app/alembic.ini /app/pyproject.toml /app/

USER dripstack
EXPOSE 4000

# python:slim ships no curl — probe with the stdlib. API-only: the worker serves
# no HTTP, so disable this on that service or it reports permanently unhealthy.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('API_PORT','4000')+'/health',timeout=2).status==200 else 1)"

CMD ["api"]
