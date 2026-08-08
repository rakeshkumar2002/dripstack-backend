# DripStack — Backend (API + worker)

DripStack sends automated, event-triggered **technical** drip sequences to
technicians during incident resolution and onboarding: syntax-highlighted code,
pretty-printed JSON, collapsible logs, and AI plain-language explanations of
errors — delivered over email (and, behind a stub interface, Slack/Teams).

This repository is the **MVP vertical slice**: the single core scenario running
end-to-end. A Metasys building-automation API error is ingested, matched to a
sequence, and a durable Temporal workflow drives a branching, multi-step
conversation with the technician. Everything runs **with no external API keys** —
email renders to a local preview route and AI degrades to a graceful fallback.

This repo is the **Python / FastAPI backend**: the API, the Temporal worker, the
RabbitMQ consumers, and the migrations. The dashboard lives in a separate repo,
**`dripstack-dashboard`**, deployed to its own server — it talks to this API
cross-origin over an absolute URL. See [`CONTRACT.md`](CONTRACT.md) for
everything that spans the two.

**Production-ready integrations:** real email (Resend + AWS SES), native
Slack/Teams delivery (incoming webhooks), signed outbound webhooks, OIDC
single sign-on, RBAC + multi-tenancy, and an append-only audit trail.

> 📚 **Full documentation site:** served by the dashboard at `/docs` (source in
> `dripstack-dashboard/public/docs/`) — architecture, configuration, integration,
> API, security, and deployment guides.
>
> Deferred behind clean extension points: SAML (OIDC SSO is built), real RAG, and
> native Slack/Teams *interactive* actions (delivery is live).

---

## Architecture

```mermaid
flowchart LR
  subgraph Customer
    SRC[Metasys / Sentry / API]
  end
  SRC -->|"POST /api/v1/ingest/:id (HMAC)"| API
  subgraph DripStack
    API[FastAPI]
    MQ[(RabbitMQ)]
    WORKER[Worker process]
    TEMPORAL[(Temporal)]
    PG[(Postgres / SQLAlchemy)]
    DASH[Next.js dashboard]
  end
  API -->|buffer ingest| MQ
  MQ -->|normalize + match| WORKER
  WORKER -->|start workflow| TEMPORAL
  TEMPORAL -->|activities: render + send| WORKER
  WORKER -->|MessageLog / runs| PG
  API --> PG
  DASH --> API
  WORKER -->|render email| RENDER[Jinja2 + Pygments]
  RENDER -->|log provider| PREVIEW[/dev/emails]
  TECH[Technician] -->|click action link| API
  API -->|signal actionReceived| TEMPORAL
  WORKER -->|run.escalated/resolved| OUT[Outbound webhook]
```

| Layer | Choice |
|-------|--------|
| Backend | **Python 3.12 / FastAPI** (uv-managed, this repo) |
| Workflow engine | **Temporal** (`temporalio`) — one workflow per sequence run |
| Database | **Postgres 16 + SQLAlchemy 2.0 (async)**, multi-tenant via a `for_org` scope; analytics as raw SQL |
| Migrations | **Alembic** |
| Queue | **RabbitMQ** (`aio-pika`) — ingest buffering + outbound-webhook retries via a dead-letter exchange |
| Email render | **Jinja2 + Pygments** (server-side, Outlook/Gmail-safe) |
| AI | **Anthropic SDK** (`claude-sonnet-4-6`) with Pydantic validation + fallback |
| Dashboard | **Next.js 14 (App Router)** + Tailwind + TanStack Query + Recharts |

Package layout (`src/dripstack/`): `db` (models + `for_org`
tenant guard + analytics) · `shared` (types, JSONPath, crypto, trigger matching)
· `render` (email engine) · `providers` (email/AI/channels) · `queue` (RabbitMQ)
· `temporal` (client) · `api` (FastAPI app + routes) · `worker` (workflow,
activities, processors).

---

## Quick start

Prerequisites: **Docker Desktop** and **[uv](https://docs.astral.sh/uv/)**
(`curl -LsSf https://astral.sh/uv/install.sh | sh`).

```bash
cp .env.example .env

# 1. Start infra (Postgres, RabbitMQ + UI :15672, Temporal dev server + UI :8233)
docker compose up -d

# 2. Create the schema and seed the demo org + Metasys sequence
uv sync
uv run alembic upgrade head
uv run seed            # prints demo login + writes scripts/.demo-env

# 3. Run the backend (two shells)
uv run api             # FastAPI on :4000
uv run worker          # Temporal worker + RabbitMQ consumers
```

For the UI, clone **`dripstack-dashboard`** and run it with
`DASHBOARD_API_URL=http://localhost:4000` — see that repo's README. The default
`DASHBOARD_URL=http://localhost:3000` here already allows its origin through CORS.

Then, in another terminal:

```bash
# 5. Fire the sample Metasys API-error event (signed HMAC)
./scripts/fire-demo-event.sh
```

### Watch it flow
- **Rendered email:** http://localhost:4000/dev/emails — open the Step-1 email:
  highlighted JSON, the AI explanation (or fallback), the collapsed log with a
  "view full log" link, and **Mark as resolved / I need help** buttons.
- **Click an action** → the run branches: *resolve* ends it `resolved`; *I need
  help* (or the `waitForAction` timeout) advances to the follow-up, then to the
  Slack escalation step, ending `escalated` and firing an outbound webhook.
- **Dashboard:** http://localhost:3000 (login is prefilled) — Runs, the per-run
  timeline, Events, and live Analytics.
- **Temporal Web UI:** http://localhost:8233 — see the durable timers + signals.

> The seed sets a short `waitForAction` timeout (~3 min) so the
> timeout→escalation branch is observable quickly. Override with
> `DEMO_TIMEOUT_HOURS`. To send real email instead of the preview, set
> `EMAIL_PROVIDER=resend` + `RESEND_API_KEY`. For real AI, set
> `AI_PROVIDER=anthropic` + `ANTHROPIC_API_KEY`.

---

## How the Temporal workflow works

Each sequence run is exactly one execution of `SequenceRunWorkflow`
(`src/dripstack/worker/workflows.py`). The workflow is **deterministic**:
it performs no I/O directly. All side effects (DB, rendering, email send,
webhooks) live in **activities**
(`src/dripstack/worker/activities.py`).

For each step the workflow:
1. records the current step,
2. `workflow.sleep(delay)` — a **durable timer** that survives restarts,
3. runs the `render_and_send_step` activity (render for the channel + deliver +
   write a `MessageLog`),
4. if the step `waitForAction`, it `workflow.wait_condition(...)` racing a
   **signal** against a durable timeout:
   - a `resolve` signal → finalize `resolved` (records time-to-resolution),
   - an `escalate` signal or a `next_step` timeout → continue to the next step,
   - an `end` timeout → finalize `escalated`.

Signals are buffered in a queue and consumed one per wait, so a click that lands
while earlier activities are still running is queued (not lost) and one click
never satisfies two waits. Action-button clicks hit the API's signed tracking
route (`/r/:runId/action/:action`), which records an `ActionClick` and delivers
the `actionReceived` signal to the workflow by its `temporalWorkflowId`. Reaching
the end of an action-bearing sequence without a resolve finalizes `escalated` and
publishes outbound webhooks for delivery with retries.

The branching is covered by a time-skipping test
(`tests/test_workflow.py`) that fast-forwards the 4-hour timeout.

---

## Tests & lint

```bash
uv run pytest        # all suites
uv run ruff check src tests
uv lock --check      # the image builds --frozen; catch lock drift here
```

- `test_jsonpath` / `test_trigger` — JSONPath + trigger-matching operators
- `test_crypto` — HMAC (openssl-compatible) + signed link-token round-trip
- `test_render` — Outlook table-wrapped code, 90KB Gmail-clip guard, AI fallback
- `test_ai` — AI prompt construction + keyless fallback
- `test_workflow` — time-skipping Temporal branch test *(downloads a test server
  on first run — needs network)*
- `test_tenant` — cross-org tenant isolation *(needs a running Postgres)*

---

## Integrations

| Integration | How it works | Configure |
|-------------|--------------|-----------|
| **Email — Resend** | HTTPS API; real delivery | `EMAIL_PROVIDER=resend` + `RESEND_API_KEY`, or per-org on the Email page |
| **Email — AWS SES** | SESv2 via `aioboto3`; creds from the boto3 chain / IAM role | `pip install '.[ses]'`, `EMAIL_PROVIDER=ses`, `AWS_REGION` |
| **Email — log** | Renders to `/dev/emails`; keyless default | `EMAIL_PROVIDER=log` |
| **Slack / Teams** | Per-org **incoming webhook** (Block Kit / Adaptive Card) | Integrations page → Connect → `PUT /api/v1/channels/{slack,teams}` |
| **Outbound webhooks** | Signed (`x-dripstack-signature`) run-lifecycle events with DLX retries | Integrations page → `POST /api/v1/outbound-webhooks` |
| **SSO (OIDC)** | Authorization-code flow; per-org issuer/client; optional auto-provision + domain allow-list | `PUT /api/v1/sso`; sign in via `/api/v1/auth/sso/{org}/start` |

Slack/Teams/SES/SSO all **degrade gracefully** when unconfigured (stub senders +
log email), so the demo runs keyless. See the docs site at `/docs/integrations.html`.

## Security

- **Inbound webhooks** are HMAC-verified against the raw request bytes; ingest is
  rate-limited and **idempotent** (payload-hash dedupe within 5 minutes).
- **Tracked links** are HMAC-signed and tamper-proof. **Action links require a
  POST**: a GET renders a confirmation interstitial, so email/AV link-scanners
  and client prefetch (which issue GETs) can't silently resolve/escalate an
  incident. Redirect links **bind the destination URL** into the signature
  (no open-redirect).
- **Auth**: bcrypt passwords, short-lived access JWTs + refresh tokens, RBAC
  permission gates, strict per-org tenant isolation, and an append-only
  **audit log** (`/api/v1/audit-logs`).
- **Transport/headers**: CORS locked to `DASHBOARD_URL` (plus any
  `CORS_ALLOWED_ORIGINS`); every response carries `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` (and HSTS in
  production).
- **Fail-fast**: in `NODE_ENV=production` the API and worker refuse to start with
  default or weak (`< 32` char) `JWT_*`/`LINK_SIGNING_SECRET` secrets, **or** with
  an `APP_BASE_URL`/`DASHBOARD_URL` that is non-https, still localhost, or ends in
  a slash (a trailing slash breaks CORS origin matching and nothing else, so it is
  otherwise invisible until every browser request 403s).
- **`/dev/emails` is not mounted in production.** It renders stored email HTML
  with no auth; set `ENABLE_DEV_EMAIL_PREVIEW=true` to force it on in a locked-down
  staging environment, and put a network-level allow-list in front of it.
- Secrets come from env only; channel/SSO credentials live in dedicated tables
  and are never serialized to clients (the API returns masked views).

## Configuration

Copy `.env.example` → `.env`. Key variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `NODE_ENV` | `development` \| `production` (enables the secret guard + HSTS) | `development` |
| `APP_BASE_URL` | Public URL for tracked links + the SSO callback | `http://localhost:4000` |
| `DASHBOARD_URL` | Dashboard origin (CORS + UI links) | `http://localhost:3000` |
| `DATABASE_URL` | Postgres connection string | local compose |
| `RABBITMQ_URL` / `TEMPORAL_ADDRESS` | Queue + workflow engine | local compose |
| `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` / `LINK_SIGNING_SECRET` | **set strong (≥32 char) values in prod** — `openssl rand -hex 32` | dev defaults |
| `EMAIL_PROVIDER` + `RESEND_API_KEY` / `AWS_REGION` | ESP selection | `log` |
| `AI_PROVIDER` + `ANTHROPIC_API_KEY` / `OPENROUTER_API_KEY` | `anthropic` \| `openrouter` \| `fallback` | `fallback` |
| `CORS_ALLOWED_ORIGINS` | Extra browser origins (previews), comma separated | empty |
| `FORWARDED_ALLOW_IPS` | Trusted proxy hops for `X-Forwarded-For` | `127.0.0.1` |
| `ENABLE_DEV_EMAIL_PREVIEW` | Force-mount `/dev/emails` in production | `false` |
| `DRIPSTACK_DEMO_DIR` | Override where `seed` writes the demo files | `./scripts` |

## Docker

One image, three entrypoints. The API and worker share the whole dependency
closure and bind the same models, and the API's tracking routes signal workflows
the worker executes — **version skew between them is an outage**, so they ship as
one digest and the process is chosen at run time.

```bash
docker build -t dripstack-backend .

docker run --env-file .env -p 4000:4000 dripstack-backend          # api (default)
docker run --env-file .env dripstack-backend worker
docker run --env-file .env dripstack-backend alembic upgrade head
docker run --env-file .env dripstack-backend seed
```

The image's `HEALTHCHECK` probes `/health` and is **API-only** — disable it on the
worker service (`healthcheck: {disable: true}`) or the worker reports permanently
unhealthy. `scripts/` is excluded from the image; use `DRIPSTACK_DEMO_DIR` if you
need `seed` to write its demo files inside a container.

### The whole stack in one command

`../docker-compose.deploy.yml` (in the parent directory, so it can reach both
repos as build contexts) runs everything — Postgres, RabbitMQ, Temporal, the API,
the worker and the dashboard — on one machine:

```bash
cd ..                                # the directory holding both repos
cp .env.deploy.example .env          # fill in RESEND_API_KEY / OPENROUTER_API_KEY
docker compose -f docker-compose.deploy.yml up -d --build
docker compose -f docker-compose.deploy.yml run --rm seed
dripstack-backend/scripts/fire-demo-event.sh
```

Dashboard on `:3000`, API on `:4000`, Temporal UI on `:8233`, RabbitMQ UI on
`:15672`. It runs with `NODE_ENV=development` — the production secret guard
rejects the `http://localhost` URLs a laptop has to use. **Not a production
topology:** the Temporal dev server keeps history in SQLite inside its container,
so `docker compose down` loses in-flight runs. See below for the real thing.

### The same stack on AWS free tier

`../docker-compose.aws.yml` runs it on one **`t4g.small`** (2 vCPU / 2 GB ARM
Graviton2) — free under the [EC2 T4g trial][t4g], 750 hrs/month **through
31 Dec 2026**, for new and existing accounts alike. A `t3.micro` will not do: the
six containers need ~1.4 GB and 1 GB OOMs.

```bash
# once, on a fresh Amazon Linux 2023 (arm64) instance
scp -i key.pem bootstrap-ec2.sh ec2-user@$EIP:~/
ssh -i key.pem ec2-user@$EIP 'bash bootstrap-ec2.sh'   # docker, compose, 2 GB swap

# from your machine, each deploy
EIP=$EIP KEY=key.pem ./deploy-aws.sh
```

Two things that setup depends on:

- **Images are built locally and streamed over SSH**, never built on the box —
  the dashboard's `pnpm build` needs more than 2 GB. `deploy-aws.sh` asserts the
  images are `arm64` before shipping, since an amd64 image will not run on
  Graviton.
- **Restrict ports 3000/4000 to your own IP** in the security group.
  `ENABLE_DEV_EMAIL_PREVIEW=true` serves `/dev/emails` with no authentication.
  The Temporal and RabbitMQ UIs are bound to loopback and reached over an SSH
  tunnel.

Costs outside the trial: ~20 GB gp3 and one public IPv4, roughly $5.50/month.

[t4g]: https://aws.amazon.com/ec2/instance-types/t4/

## Production deployment

1. Provision managed **Postgres**, **RabbitMQ**, and a **Temporal** cluster
   (Temporal Cloud or self-hosted); point the env vars at them. Do **not** promote
   the dev compose `temporal` service — it is `start-dev`, in-memory/SQLite, and
   loses every durable timer and in-flight sequence on restart.
2. Set `NODE_ENV=production`, strong secrets, and real https
   `APP_BASE_URL`/`DASHBOARD_URL` (the app won't boot otherwise).
3. Put `.env` beside `docker-compose.prod.yml`, set `APP_DOMAIN`, then:

```bash
docker compose -f docker-compose.prod.yml run --rm migrate
docker compose -f docker-compose.prod.yml up -d
```

   `api` and `worker` both wait on the `migrate` one-shot and share a single
   `env_file` — the worker independently needs `DASHBOARD_URL` for the run
   deep-links it posts to Slack/Teams, and splitting the config is exactly how
   that silently regresses to localhost.
4. Caddy terminates TLS and sets `X-Forwarded-*`; set `FORWARDED_ALLOW_IPS` to the
   compose bridge subnet so the rate limiter and audit log see real client IPs.
5. Health: `GET /health` (liveness) and `GET /ready` (readiness — 503 until the
   DB is reachable).

See the docs site at `/docs/deployment.html` for the full checklist.

## Multi-tenancy (detail)

Every table carries `organization_id`. `for_org(session, org_id)`
(`src/dripstack/db/tenant.py`) returns a `TenantSession` whose read/write
helpers inject the tenant scope into every query — cross-org reads return nothing
and writes are stamped with the caller's org. Proven by `tests/test_tenant.py`.
