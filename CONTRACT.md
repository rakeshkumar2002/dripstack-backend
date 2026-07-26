# Cross-repo contract

DripStack is two repos deployed to two servers:

| Repo | Runs | Public origin |
|---|---|---|
| [`dripstack-backend`](../dripstack-backend) | FastAPI API + Temporal worker | `APP_BASE_URL` |
| [`dripstack-dashboard`](../dripstack-dashboard) | Next.js SPA | `DASHBOARD_URL` |

Nothing here is enforced by a compiler or a shared package. **A change to any row
below is a two-PR change.** This file is duplicated verbatim in both repos; edit
both.

## Configuration

| Contract | Backend side | Dashboard side |
|---|---|---|
| API origin | `APP_BASE_URL` | `DASHBOARD_API_URL` |
| Dashboard origin | `DASHBOARD_URL` (+ `CORS_ALLOWED_ORIGINS` for previews) | the app's own public URL |
| Auth | JWT via `Authorization: Bearer`, **no cookies anywhere** | `localStorage` key `ds_token` |

`APP_BASE_URL` and `DASHBOARD_API_URL` must be the **same string**. So must
`DASHBOARD_URL` and the dashboard's real origin — exactly, with no trailing
slash. An `Origin` header never carries one, so a trailing slash 403s every
browser request while remaining invisible everywhere else.

## Routes the backend redirects into

The backend hardcodes these dashboard paths. Renaming or deleting one breaks SSO
or notification links with **no compile error on either side** — the dashboard CI
asserts they still exist.

| Backend | Target | Dashboard file |
|---|---|---|
| `api/routes/sso.py` | `{DASHBOARD_URL}/sso/callback#accessToken=…&refreshToken=…` | `app/sso/callback/page.tsx` |
| `api/routes/sso.py` | `{DASHBOARD_URL}/login?sso_error=…` | `app/login/page.tsx` |
| `api/routes/admin.py` | `{DASHBOARD_URL}/integrations` | `app/integrations/page.tsx` |
| `worker/activities.py` | `{DASHBOARD_URL}/runs/{run_id}` | `app/runs/[id]/page.tsx` |

The **worker** builds that last one, so `DASHBOARD_URL` must be set on the worker
process too, not just the API. The shared `env_file` anchor in
`docker-compose.prod.yml` is what keeps them from drifting apart.

## Endpoints the dashboard depends on

- Everything under `/api/v1/*`, returning camelCase JSON with ISO-Z datetimes
  (`api/serialize.py`).
- FastAPI's `{"detail": …}` error shape — parsed in `app/lib/api.ts`.
- `GET /api/v1/auth/sso/{org}/start` — a top-level browser navigation from
  `app/login/page.tsx`, not a fetch.
- `{APP_BASE_URL}/api/v1/ingest/{event_source_id}` — displayed to users.
- `{APP_BASE_URL}/dev/emails/{id}` — **not mounted in production** (see
  `ENABLE_DEV_EMAIL_PREVIEW`); the dashboard link degrades to a 404 there.

Backend response types are **hand-mirrored** in the dashboard (e.g. the
`Principal` interface in `app/lib/principal.ts`). Deliberate decoupling, with a
real maintenance cost: changing a response shape means editing both repos.

## OIDC / SSO

The IdP redirect URI points at the **backend**, not the dashboard:

```
{APP_BASE_URL}/api/v1/auth/sso/callback
```

The dashboard's SSO settings page renders that string from its *own*
`DASHBOARD_API_URL`. If the two disagree, admins paste a redirect URI the backend
never uses and every SSO login fails at the IdP. Moving the backend to a new
origin means re-registering the redirect URI with every configured IdP.
