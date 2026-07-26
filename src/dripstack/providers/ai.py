"""AI explainer service (port of packages/core/src/ai/explainer.ts).

Returns a validated explanation, or None to signal the caller should render the
graceful fallback (no key, error, or low confidence).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from ..config import settings
from ..logging import logger
from ..shared.crypto import canonical_json, sha256_hex
from ..shared.types import AiExplanation, pretty_json


@dataclass
class ExplainInput:
    error_payload: Any
    product_doc_context: str | None = None


def build_explainer_prompt(inp: ExplainInput) -> dict[str, str]:
    """Pure prompt builder — unit-testable without an API call."""
    system = "\n".join(
        [
            "You are a senior support engineer at an industrial-software company.",
            "Your audience is a field technician with NO programming background.",
            "Given a raw technical error payload, you must return ONLY a JSON object:",
            '{ "explanation": string, "fixSteps": string[], "confidence": "high"|"medium"|"low" }',
            '- "explanation": ONE short paragraph in plain English. No jargon, no code.',
            '- "fixSteps": 3 to 5 concrete, numbered actions the technician can take.',
            '- "confidence": your confidence the explanation is correct for THIS payload.',
            'If the payload is ambiguous or you are unsure, set confidence to "low" and',
            "advise escalating to support. Never invent device behaviour you cannot infer.",
            "Output JSON only — no markdown, no prose around it.",
        ]
    )
    docs = ""
    if inp.product_doc_context and inp.product_doc_context.strip():
        docs = "\n\nProduct documentation / error reference (authoritative):\n" + inp.product_doc_context[:20_000]
    user = f"Error payload:\n{pretty_json(inp.error_payload)}{docs}"
    return {"system": system, "user": user}


def _cache_key(inp: ExplainInput) -> str:
    return sha256_hex(canonical_json(inp.error_payload) + "|" + (inp.product_doc_context or ""))


def _extract_json(text: str) -> str:
    """Tolerate models that wrap JSON in prose/code fences."""
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fenced and fenced.group(1):
        return fenced.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    return text[start : end + 1] if start >= 0 and end > start else text


class AiExplainerService:
    def __init__(self, provider: str, api_key: str | None, model: str) -> None:
        self.provider = provider
        self.model = model
        self._cache: dict[str, AiExplanation | None] = {}
        self._client = None
        if provider == "anthropic" and api_key:
            import anthropic  # imported lazily so fallback mode needs no SDK

            self._client = anthropic.AsyncAnthropic(api_key=api_key)

    @classmethod
    def from_settings(cls) -> AiExplainerService:
        s = settings()
        return cls(provider=s.AI_PROVIDER, api_key=s.ANTHROPIC_API_KEY, model=s.AI_MODEL)

    async def explain(self, inp: ExplainInput) -> AiExplanation | None:
        if self._client is None:
            return None  # fallback mode — keyless demo path

        key = _cache_key(inp)
        if key in self._cache:
            return self._cache[key]

        prompt = build_explainer_prompt(inp)
        try:
            res = await self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.2,
                system=prompt["system"],
                messages=[{"role": "user", "content": prompt["user"]}],
            )
            text = next((c.text for c in res.content if getattr(c, "type", None) == "text"), "")
            data = json.loads(_extract_json(text))
            parsed = AiExplanation.model_validate(data)
        except (ValidationError, json.JSONDecodeError) as err:
            logger.warning("AI explanation failed validation — using fallback", err=str(err))
            self._cache[key] = None
            return None
        except Exception as err:  # noqa: BLE001 - any API failure → graceful fallback
            logger.error("AI explainer call failed — using fallback", err=str(err))
            return None

        # Low confidence → prefer the honest fallback over a shaky suggestion.
        value = None if parsed.confidence == "low" else parsed
        self._cache[key] = value
        return value
