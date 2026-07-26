"""Canonical Pydantic schemas for the technical-content model (port of types.ts).

JSON authored in seeds/DB uses camelCase keys (collapsedLines, inputPath,
eventType, …); these models accept camelCase via an alias generator while code
reads snake_case attributes.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from pydantic.alias_generators import to_camel

ValueSource = Literal["static", "event_path"]


class _Model(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


# ── Content blocks ───────────────────────────────────────────────────────────


class TextBlock(_Model):
    type: Literal["text"]
    markdown: str


class CodeBlock(_Model):
    type: Literal["code"]
    language: str = "json"
    source: ValueSource
    value: str


class JsonBlock(_Model):
    type: Literal["json"]
    source: ValueSource
    path: str | None = None
    value: Any | None = None


class LogBlock(_Model):
    type: Literal["log"]
    source: ValueSource
    path: str | None = None
    value: str | None = None
    collapsed_lines: int = 12


class AiExplanationBlock(_Model):
    type: Literal["ai_explanation"]
    input_path: str
    doc_context: str | None = None


class ActionButton(_Model):
    label: str
    action: Literal["resolve", "escalate", "link"]
    url: str | None = None


class ActionsBlock(_Model):
    type: Literal["actions"]
    buttons: list[ActionButton] = Field(min_length=1)


ContentBlock = Annotated[
    TextBlock | CodeBlock | JsonBlock | LogBlock | AiExplanationBlock | ActionsBlock,
    Field(discriminator="type"),
]


# ── Steps ────────────────────────────────────────────────────────────────────

Channel = Literal["email", "slack", "teams"]


class Delay(_Model):
    amount: int
    unit: Literal["seconds", "minutes", "hours", "days"]


class WaitForAction(_Model):
    timeout_hours: float
    on_timeout: Literal["next_step", "end"]


class StepTemplate(_Model):
    subject: str | None = None
    blocks: list[ContentBlock]


class Step(_Model):
    id: str
    order: int
    channel: Channel
    delay: Delay
    wait_for_action: WaitForAction | None = None
    template: StepTemplate


# ── Trigger rules ─────────────────────────────────────────────────────────────

ConditionOp = Literal["eq", "neq", "contains", "gt", "lt", "exists"]


class Condition(_Model):
    path: str
    op: ConditionOp
    value: Any | None = None


class TriggerRule(_Model):
    event_type: str
    conditions: list[Condition] = Field(default_factory=list)


# ── AI explainer output ───────────────────────────────────────────────────────


class AiExplanation(_Model):
    explanation: str
    fix_steps: list[str] = Field(min_length=1, max_length=8)
    confidence: Literal["high", "medium", "low"]


_STEPS_ADAPTER = TypeAdapter(list[Step])
_TRIGGER_ADAPTER = TypeAdapter(TriggerRule)


def parse_steps(raw: Any) -> list[Step]:
    return _STEPS_ADAPTER.validate_python(raw)


def parse_trigger(raw: Any) -> TriggerRule:
    return _TRIGGER_ADAPTER.validate_python(raw)


# ── Convenience helpers ────────────────────────────────────────────────────────

_UNIT_MS = {"seconds": 1_000, "minutes": 60_000, "hours": 3_600_000, "days": 86_400_000}


def delay_to_ms(d: Delay) -> int:
    return d.amount * _UNIT_MS[d.unit]


def pretty_json(value: Any) -> str:
    """Pretty-print a value as 2-space-indented JSON (≈ JSON.stringify(v, null, 2))."""
    return json.dumps(value, indent=2, ensure_ascii=False)
