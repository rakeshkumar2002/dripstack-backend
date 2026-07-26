"""AWS SES email provider: selection, request construction, and the missing-dep
error path. `aioboto3` is faked so the test needs no AWS credentials or network."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from dripstack.providers.email import SendArgs, SesEmailProvider, get_email_provider


def test_get_email_provider_selects_ses():
    p = get_email_provider({"emailProvider": "ses"})
    assert isinstance(p, SesEmailProvider)


def test_get_email_provider_log_when_requested():
    from dripstack.providers.email import LogEmailProvider

    # An explicit per-org "log" choice always yields the preview provider,
    # regardless of the env default.
    assert isinstance(get_email_provider({"emailProvider": "log"}), LogEmailProvider)


async def test_ses_missing_dependency(monkeypatch):
    # Simulate aioboto3 not installed.
    monkeypatch.setitem(sys.modules, "aioboto3", None)
    with pytest.raises(RuntimeError) as exc:
        await SesEmailProvider("us-east-1").send(
            SendArgs(to="t@x.com", from_="f@x.com", subject="s", html="<b>h</b>", text="h")
        )
    assert "aioboto3" in str(exc.value)


async def test_ses_send_builds_request(monkeypatch):
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def send_email(self, **kwargs):
            captured.update(kwargs)
            return {"MessageId": "ses-msg-1"}

    class FakeSession:
        def client(self, service, region_name=None):
            captured["service"] = service
            captured["region"] = region_name
            return FakeClient()

    fake_module = SimpleNamespace(Session=lambda: FakeSession())
    monkeypatch.setitem(sys.modules, "aioboto3", fake_module)

    res = await SesEmailProvider("eu-west-1", "my-config-set").send(
        SendArgs(to="to@x.com", from_="DripStack <from@x.com>", subject="Subj", html="<b>H</b>", text="H")
    )
    assert res.provider == "ses" and res.provider_message_id == "ses-msg-1"
    assert captured["service"] == "sesv2" and captured["region"] == "eu-west-1"
    assert captured["FromEmailAddress"] == "DripStack <from@x.com>"
    assert captured["Destination"]["ToAddresses"] == ["to@x.com"]
    assert captured["Content"]["Simple"]["Subject"]["Data"] == "Subj"
    assert captured["ConfigurationSetName"] == "my-config-set"
