"""Render inputs/outputs (port of render/src/context.ts).

Everything the render engine needs beyond the step template: the event payload,
recipient, tracked-link builder, and an async resolver for AI explanation blocks.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..shared.types import AiExplanation, Step

# Gmail clips messages above ~102KB; stay comfortably under.
HTML_SIZE_BUDGET = 90_000


class LinkBuilder(Protocol):
    def action_url(self, action: str) -> str: ...
    def block_url(self, block_id: str) -> str: ...
    def pixel_url(self) -> str: ...
    def track_link(self, url: str, ref: str) -> str: ...


ResolveAi = Callable[[str, str | None], Awaitable["AiExplanation | None"]]


@dataclass
class RenderInput:
    step: Step
    payload: Any
    contact: dict[str, Any]
    links: LinkBuilder
    resolve_ai: ResolveAi | None = None
    brand: dict[str, Any] = field(default_factory=dict)


@dataclass
class RenderedMessage:
    subject: str
    html: str
    text: str
    truncated: bool
