# DripStack backend — agent guide

Read this before changing anything. It records the invariants, the conventions,
and the mistakes already made here, so you don't rediscover them.

## What this service is

A customer's product POSTs an error. DripStack matches it to a sequence, emails
the **field technician** — a plain-English explanation plus concrete fix steps —
waits for them to resolve or ask for help, escalates on silence, and calls the
customer's system back.

**DripStack detects nothing.** It's a push target, downstream of the customer's
own monitoring. Don't add polling or log ingestion; that's not the product.

The recipient is explicitly *not an engineer* (`providers/ai.py` prompt: "a field
technician with NO programming background"). That framing drives most product
decisions — if a change makes output more technical, it's probably wrong.

## Layout

`src/dripstack/` — one image, three entrypoints (`api`, `worker`, `alembic`):

| Package | Holds |
|---|---|
| `api/` | FastAPI app, routes, auth, rate limiting, serializers |
| `db/` | SQLAlchemy models, the tenant guard, raw-SQL analytics |
| `worker/` | Temporal workflow + activities, RabbitMQ processors |
| `render/` | Jinja2 + Pygments email rendering |
| `providers/` | Email (log/Resend/SES), AI (Anthropic/OpenRouter/fallback), channels |
| `shared/` | Crypto, JSONPath, trigger matching, SSRF guard |
| `queue/`, `temporal/` | Transport clients |

17 models; the ones that matter: `Organization` (tenant root) · `User` ·
`SequenceRun` (one incident) · `MessageLog` · `EventSource` (ingest creds) ·
`OutboundWebhook` · `SsoConnection` · `AuditLog`.

## Invariants — do not break these

**1 · Tenant isolation is enforced, not conventional.** `db/tenant.py`
`for_org()` returns a `TenantSession` whose helpers always inject
`organization_id`. Route handlers take `db: TenantSession = Depends(tenant_db)`.
Reaching for `db.session` directly bypasses the guard — if you must, scope by
hand and say why in a comment. Cross-org reads return 404, and there are tests.

**2 · Permissions come from RBAC, never from the token's role string.** Gate with
`Depends(require_permission("thing.write"))`. `auth_context_for()` puts the RBAC
*slug* (`customer-admin`) in `ctx.role`; the legacy `Role` enum is only a
fallback for users with no `role_id`. Comparing `auth.role != "admin"` is a bug —
it shipped once and 403'd every real admin.

Permissions: `analytics.read`, `customers.{read,write,delete}`, `email.write`,
`integrations.{read,write}`, `sequences.{read,write}`, `technicians.{read,write}`,
`users.{read,write,delete}`. Roles: `integration-admin` (platform),
`customer-admin`, `customer-member`.

**3 · Signatures cover raw bytes.** Inbound ingest verifies HMAC against the body
read *before* JSON parsing. Outbound signs the exact string it sends. Never
re-serialise between hashing and sending.

**4 · Any server-side fetch of a customer-supplied URL goes through
`shared/net.py::assert_safe_outbound_url`.** Outbound webhooks, Slack/Teams URLs,
the OIDC issuer, and every URL from a discovery document. Applied at save time
*and* fetch time, because DNS moves and discovery hands us URLs we didn't write.

**5 · GET never changes state.** Tracked action links render a confirmation page;
only POST resolves or escalates. Mail scanners and prefetch would otherwise close
incidents on the technician's behalf.

**6 · A failed send must not stall a sequence.** `worker/activities.py` catches
delivery errors, writes a `failed` MessageLog, and lets the workflow continue.

## Conventions

- **Comments explain *why*, not what.** The existing code does this consistently;
  match it. Load-bearing comments (e.g. why `NODE_ENV=development` locally) are
  there to stop someone "tidying" a deliberate choice.
- Async everywhere. `session_scope()` for standalone DB work.
- Responses are camelCase via `api/serialize.py`; models are snake_case.
- Secrets are write-only in the API — reads return a masked view.
- New env vars go in `config.py` with a comment on what unset means.
- `uv` manages deps. The Dockerfile uses `--frozen`, so **run `uv lock` after
  touching `pyproject.toml`** or the image build fails and CI's `uv lock --check`
  catches it.

## Running and testing

```bash
uv sync                      # deps
uv run alembic upgrade head  # schema
uv run seed                  # demo org, user, sequence
uv run api                   # :4000
uv run worker                # separate process
uv run pytest -q             # 106 tests
uv run ruff check src tests
```

Most DB tests self-skip when Postgres is unreachable, so **a green run does not
mean they ran** — check the skip count. The full stack lives in the deploy repo
(`docker-compose.deploy.yml`); Postgres isn't published to the host there, so to
run DB tests against it you need a forwarder:

```bash
docker run -d --rm --name pgfwd --network dripstack_default -p 15432:5432 \
  alpine/socat tcp-listen:5432,fork,reuseaddr tcp-connect:postgres:5432
DATABASE_URL="postgresql://dripstack:dripstack@localhost:15432/dripstack" uv run pytest -q
```

**Register cleanup with the `cleanup` fixture** (`tests/conftest.py`), not inline
at the end of a test — see Gotchas.

## Gotchas — real bugs, already paid for

| Symptom | Cause |
|---|---|
| Org admin gets 403 on `PATCH /settings` | Legacy `auth.role != "admin"` compare. Use `require_permission`. |
| `EMAIL_PROVIDER` env change does nothing | Per-org `settings.emailProvider` **wins over env** (`providers/email.py`). Change it on the organization. |
| Second device's fault produces no run | Dedupe keys on **sequence + contact**, not your entity. Plus a 5-minute payload-hash dedupe. |
| "I need help" doesn't close the run | By design — escalate *advances* the sequence; only resolve finalises. The callback fires when steps run out. |
| AI explanations vanish | OpenRouter free models get delisted or rate-limited. Degrades to written fallback by design; swap `AI_MODEL`. |
| Test suite trips its own rate limit | `conftest.py` resets the limiter per test. Login is 10/min, register 5/hour. |
| Orphan rows after a failed test | Inline cleanup at the end of a test body never runs on failure. Use the `cleanup` fixture, which deletes via the ORM — closures over the httpx client don't work, the client is closed before fixture teardown. |
| Transient send failure loses a message | Known gap: the activity catches everything, so Temporal never retries. Permanent and transient errors are treated alike. |

## Known weaknesses (don't "discover" these as new)

- No PKCE, and the OIDC `id_token` signature isn't verified — identity comes from
  the userinfo endpoint. `state` isn't bound to the browser session.
- Attacker payload reaches `{{ b.html | safe }}` through markdown with raw-HTML
  passthrough. Contained only because `/dev/emails` is off in production.
- `pydantic-settings 2.14.1` has GHSA-4xgf-cpjx-pc3j (fixed in 2.14.2).
- Account enumeration via the 409 on register.
- Dedupe has no error fingerprinting.

## Deployment

CI builds an **arm64** image (the target is Graviton — amd64 fails at container
start with a bare `exec format error`) and deploys over SSM. Push to `main` is
live in ~4 minutes. Infra and runbooks live in the `dripstack-deploy` repo.
