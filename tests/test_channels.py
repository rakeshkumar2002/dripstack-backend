"""Native Slack/Teams channel senders + config endpoints.

Pure-unit covers the sender payloads, the >=300 raise, and the stub fallback;
an in-process app test (skipped when DB is down) covers config upsert/masking,
the test endpoint, and the integrations.write 403 path.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import text

from dripstack.db.session import session_scope
from dripstack.providers.channels import (
    SlackStubSender,
    SlackWebhookSender,
    TeamsWebhookSender,
    get_channel_sender,
)

# ── Pure unit: senders ────────────────────────────────────────────────────────


def test_slack_payload_shape():
    p = SlackWebhookSender("https://hooks.slack.com/services/x").build_payload(
        subject="DB down", text="connection refused", link="https://app/runs/1"
    )
    assert p["text"] == "DB down"
    assert p["blocks"][0]["type"] == "header"
    assert "runs/1" in p["blocks"][-1]["elements"][0]["text"]


def test_teams_payload_shape():
    p = TeamsWebhookSender("https://x").build_payload(subject="DB down", text="oops", link="https://app/runs/1")
    assert p["@type"] == "MessageCard"
    assert p["title"] == "DB down"
    assert p["potentialAction"][0]["targets"][0]["uri"].endswith("runs/1")


def test_get_channel_sender_falls_back_to_stub():
    # No integration → stub.
    assert isinstance(get_channel_sender("slack", None), SlackStubSender)
    # Disabled integration → stub.
    disabled = SimpleNamespace(enabled=False, webhook_url="https://x")
    assert isinstance(get_channel_sender("slack", disabled), SlackStubSender)
    # Enabled + URL → real sender.
    on = SimpleNamespace(enabled=True, webhook_url="https://hooks.slack.com/services/x")
    assert isinstance(get_channel_sender("slack", on), SlackWebhookSender)


async def test_slack_sender_raises_on_http_error(monkeypatch):
    class FakeResp:
        status_code = 404
        text = "no_service"

    class FakeClient:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    with pytest.raises(RuntimeError) as exc:
        await SlackWebhookSender("https://hooks.slack.com/x").send(to="t", subject="s", html="", text="t")
    assert "slack: 404" in str(exc.value)


async def test_slack_sender_posts_payload(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        text = "ok"

    class FakeClient:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, **k):
            captured["url"] = url
            captured["json"] = json
            return FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    res = await SlackWebhookSender("https://hooks.slack.com/x").send(to="t", subject="Hi", html="", text="body")
    assert captured["url"] == "https://hooks.slack.com/x"
    assert captured["json"]["blocks"][0]["text"]["text"] == "Hi"
    assert res.id.startswith("slack_")


# ── In-process app (skippable) ────────────────────────────────────────────────


async def _db_up() -> bool:
    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


async def test_channel_config_and_member_403():
    if not await _db_up():
        pytest.skip("DB not reachable — skipping channel config app test")

    from dripstack.api.main import create_app

    async with httpx.AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        tok = (
            await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
        ).json()["accessToken"]
        admin = {"authorization": f"Bearer {tok}"}

        # Non-https rejected.
        assert (await c.put("/api/v1/channels/slack", headers=admin, json={"webhookUrl": "http://x"})).status_code == 400
        # Unknown channel rejected.
        assert (await c.put("/api/v1/channels/sms", headers=admin, json={"webhookUrl": "https://x"})).status_code == 400

        # Connect Slack → GET shows connected + masked target (raw URL never returned).
        raw = "https://hooks.slack.com/services/T123/B456/SECRETTOKENVALUE"
        up = await c.put("/api/v1/channels/slack", headers=admin, json={"webhookUrl": raw})
        assert up.status_code == 200
        ch = {x["channel"]: x for x in (await c.get("/api/v1/channels", headers=admin)).json()["channels"]}
        assert ch["slack"]["connected"] is True
        assert raw not in str(ch["slack"]) and ch["slack"]["target"].startswith("https://hooks.slack.com/")
        assert ch["teams"]["connected"] is False

        # Member is read-only on integrations.write.
        email = f"member-{uuid.uuid4().hex[:6]}@x.dev"
        await c.post("/api/v1/users", headers=admin, json={"email": email, "password": "abcd1234", "roleSlug": "customer-member"})
        mtok = (await c.post("/api/v1/auth/login", json={"email": email, "password": "abcd1234"})).json()["accessToken"]
        member = {"authorization": f"Bearer {mtok}"}
        assert (await c.get("/api/v1/channels", headers=member)).status_code == 200
        assert (await c.put("/api/v1/channels/slack", headers=member, json={"webhookUrl": "https://x"})).status_code == 403
        assert (await c.post("/api/v1/channels/slack/test", headers=member)).status_code == 403

        # Cleanup.
        await c.delete("/api/v1/channels/slack", headers=admin)
        me = (await c.get("/api/v1/users", headers=admin)).json()["users"]
        for u in me:
            if u["email"] == email:
                await c.delete(f"/api/v1/users/{u['id']}", headers=admin)
