from dripstack.render import render_email_message
from dripstack.render.context import RenderInput
from dripstack.shared.types import Step


class _Links:
    def action_url(self, a):
        return f"https://app.test/r/run1/action/{a}?token=t"

    def block_url(self, b):
        return f"https://app.test/r/run1/log/{b}?token=t"

    def pixel_url(self):
        return "https://app.test/r/run1/pixel.gif?token=t"

    def track_link(self, url, ref):
        return f"https://app.test/r/run1/link/{ref}?u={url}"


payload = {
    "error": {"status": 409, "code": "OBJECT_OVERRIDDEN", "object": "AV-2-RoomTemp"},
    "rawLog": "\n".join(f"2026-06-13T09:14:{i} ERROR line {i}" for i in range(40)),
}


def _step(blocks) -> Step:
    return Step.model_validate(
        {
            "id": "s1",
            "order": 0,
            "channel": "email",
            "delay": {"amount": 0, "unit": "seconds"},
            "template": {"subject": "Error {{ $.error.code }} on {{ $.error.object }}", "blocks": blocks},
        }
    )


async def test_interpolates_highlights_and_wraps_code_in_padded_cell():
    out = await render_email_message(
        RenderInput(
            step=_step(
                [
                    {"type": "text", "markdown": "Hi **there**, an error occurred."},
                    {"type": "json", "source": "event_path", "path": "$.error"},
                    {
                        "type": "actions",
                        "buttons": [
                            {"label": "Mark resolved", "action": "resolve"},
                            {"label": "I need help", "action": "escalate"},
                        ],
                    },
                ]
            ),
            payload=payload,
            contact={"email": "tech@example.com", "name": "Alex"},
            links=_Links(),
        )
    )

    assert out.subject == "Error OBJECT_OVERRIDDEN on AV-2-RoomTemp"
    assert 'style="color:' in out.html  # Pygments inline-styled span
    import re

    assert re.search(r"<td[^>]*padding", out.html, re.IGNORECASE)  # Outlook-safe code frame
    assert "/r/run1/action/resolve" in out.html
    assert "Mark resolved:" in out.text
    assert "```" in out.text


async def test_truncates_oversized_content_and_links_out():
    huge = "x" * 200_000
    out = await render_email_message(
        RenderInput(
            step=_step([{"type": "code", "language": "text", "source": "static", "value": huge}]),
            payload=payload,
            contact={"email": "tech@example.com"},
            links=_Links(),
        )
    )
    assert out.truncated is True
    assert "View full content" in out.html
    assert len(out.html) < 120_000


async def test_renders_graceful_fallback_when_ai_returns_none():
    async def resolve_ai(input_path, doc_context):
        return None

    out = await render_email_message(
        RenderInput(
            step=_step([{"type": "ai_explanation", "inputPath": "$.error"}]),
            payload=payload,
            contact={"email": "tech@example.com"},
            links=_Links(),
            resolve_ai=resolve_ai,
        )
    )
    assert "support team has been notified" in out.html
