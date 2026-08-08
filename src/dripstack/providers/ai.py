"""AI explainer service (port of packages/core/src/ai/explainer.ts).

Returns a validated explanation, or None to signal the caller should render the
graceful fallback (no key, error, or low confidence).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx
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
    def __init__(
        self,
        provider: str,
        api_key: str | None,
        model: str,
        base_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self._cache: dict[str, AiExplanation | None] = {}
        self._api_key = api_key
        self._base_url = (base_url or "https://openrouter.ai/api/v1").rstrip("/")
        self._transport = transport  # tests inject a MockTransport here
        self._client = None
        if provider == "anthropic" and api_key:
            import anthropic  # imported lazily so fallback mode needs no SDK

            self._client = anthropic.AsyncAnthropic(api_key=api_key)
        # One gate for both providers: no key (or provider=fallback) means the
        # caller renders the graceful non-AI fallback instead.
        self._enabled = self._client is not None or (provider == "openrouter" and bool(api_key))

    @classmethod
    def from_settings(cls) -> AiExplainerService:
        s = settings()
        key = s.OPENROUTER_API_KEY if s.AI_PROVIDER == "openrouter" else s.ANTHROPIC_API_KEY
        return cls(provider=s.AI_PROVIDER, api_key=key, model=s.AI_MODEL, base_url=s.OPENROUTER_BASE_URL)

    async def _complete(self, prompt: dict[str, str]) -> str:
        """Provider-specific call. Returns the raw assistant text."""
        if self._client is not None:
            res = await self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.2,
                system=prompt["system"],
                messages=[{"role": "user", "content": prompt["user"]}],
            )
            return next((c.text for c in res.content if getattr(c, "type", None) == "text"), "")

        # OpenRouter speaks the OpenAI chat-completions schema — there is no
        # Anthropic-native /v1/messages to point the SDK at. httpx is already a
        # dependency, so this needs no addition to the (frozen) uv.lock.
        #
        # Free-tier models are slow: 60s, not the 15s the email provider uses.
        async with httpx.AsyncClient(timeout=60, transport=self._transport) as client:
            res = await client.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "HTTP-Referer": "https://dripstack.dev",
                    "X-Title": "DripStack",
                },
                json={
                    "model": self.model,
                    "max_tokens": 1024,
                    "temperature": 0.2,
                    "messages": [
                        {"role": "system", "content": prompt["system"]},
                        {"role": "user", "content": prompt["user"]},
                    ],
                },
            )
        if res.status_code >= 300:
            raise RuntimeError(f"openrouter: {res.status_code} {res.text}")
        return res.json()["choices"][0]["message"]["content"] or ""

    async def explain(self, inp: ExplainInput) -> AiExplanation | None:
        if not self._enabled:
            return None  # fallback mode — keyless demo path

        key = _cache_key(inp)
        if key in self._cache:
            return self._cache[key]

        prompt = build_explainer_prompt(inp)
        try:
            text = await self._complete(prompt)
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
