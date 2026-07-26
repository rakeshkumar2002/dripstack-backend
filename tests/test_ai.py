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
