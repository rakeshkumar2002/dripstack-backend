import json

import httpx

from dripstack.providers.ai import AiExplainerService, ExplainInput, build_explainer_prompt

error_payload = {
    "status": 409,
    "code": "OBJECT_OVERRIDDEN",
    "message": "Write to presentValue rejected",
}


def test_prompt_frames_senior_support_engineer_role():
    system = build_explainer_prompt(ExplainInput(error_payload=error_payload))["system"]
    assert "senior support engineer" in system
    assert "NO programming background" in system
    assert "confidence" in system


def test_prompt_embeds_payload_and_doc_context():
    user = build_explainer_prompt(
        ExplainInput(
            error_payload=error_payload,
            product_doc_context="OBJECT_OVERRIDDEN means a higher-priority write holds the point.",
        )
    )["user"]
    assert "OBJECT_OVERRIDDEN" in user
    assert "higher-priority write" in user


def test_prompt_caps_doc_context_length():
    user = build_explainer_prompt(ExplainInput(error_payload=error_payload, product_doc_context="a" * 50_000))["user"]
    assert len(user) < 25_000


async def test_fallback_mode_returns_none_without_key():
    svc = AiExplainerService(provider="fallback", api_key=None, model="claude-sonnet-4-6")
    assert await svc.explain(ExplainInput(error_payload=error_payload)) is None


async def test_openrouter_mode_returns_none_without_key():
    svc = AiExplainerService(provider="openrouter", api_key=None, model="some/model:free")
    assert await svc.explain(ExplainInput(error_payload=error_payload)) is None


async def test_openrouter_sends_chat_completion_and_parses_fenced_json():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        # Free models routinely wrap the JSON in a code fence — _extract_json
        # is what keeps that from becoming a parse failure.
        content = (
            "```json\n"
            + json.dumps(
                {
                    "explanation": "A higher-priority command is holding the setpoint.",
                    "fixSteps": ["Open the point", "Release the override", "Retry the write"],
                    "confidence": "high",
                }
            )
            + "\n```"
        )
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})

    svc = AiExplainerService(
        provider="openrouter",
        api_key="sk-or-test",
        model="inclusionai/ling-3.0-flash:free",
        base_url="https://openrouter.ai/api/v1",
        transport=httpx.MockTransport(handler),
    )
    out = await svc.explain(ExplainInput(error_payload=error_payload))

    assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-or-test"
    assert seen["body"]["model"] == "inclusionai/ling-3.0-flash:free"
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
    assert "OBJECT_OVERRIDDEN" in seen["body"]["messages"][1]["content"]

    assert out is not None
    assert out.confidence == "high"
    assert len(out.fix_steps) == 3


async def test_openrouter_http_error_degrades_to_fallback():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    svc = AiExplainerService(
        provider="openrouter",
        api_key="sk-or-test",
        model="inclusionai/ling-3.0-flash:free",
        transport=httpx.MockTransport(handler),
    )
    assert await svc.explain(ExplainInput(error_payload=error_payload)) is None
