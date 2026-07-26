"""Render a step template into an email (port of render/src/renderEmail.ts).

Pygments-highlighted, Outlook-safe (code padding lives on a `<td>`), Gmail-clip
guarded (~90KB) HTML plus a plaintext alternative.

NOTE: `{{ $.path }}` event interpolation is a SEPARATE regex pass over the
authored strings, done BEFORE Jinja2 lays out the email — Jinja2 shares the
`{{ }}` delimiters, so the two must not be conflated.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..shared.jsonpath import get_by_path
from ..shared.types import pretty_json
from .context import HTML_SIZE_BUDGET, RenderedMessage, RenderInput
from .highlight import highlight_to_html
from .markdown import markdown_to_html, markdown_to_text

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
)
_template = _env.get_template("email.html.j2")

_INTERP = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def _interpolate(tpl: str, payload: Any) -> str:
    """`{{ $.error.code }}` style interpolation against the event payload."""

    def repl(m: re.Match[str]) -> str:
        v = get_by_path(payload, m.group(1))
        return "" if v is None else _scalar(v)

    return _INTERP.sub(repl, tpl)


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _as_string(v: Any) -> str:
    if v is None:
        return ""
    return v if isinstance(v, str) else pretty_json(v)


async def _prepare_block(
    block: Any, index: int, inp: RenderInput, remaining_budget: int
) -> tuple[dict[str, Any], bool]:
    payload = inp.payload
    links = inp.links
    block_id = f"b{index}"
    t = block.type

    if t == "text":
        html = markdown_to_html(_interpolate(block.markdown, payload))
        return {"kind": "text", "html": html, "text": markdown_to_text(block.markdown)}, False

    if t in ("code", "json"):
        if t == "json":
            val = get_by_path(payload, block.path or "$") if block.source == "event_path" else block.value
            raw = pretty_json(val if val is not None else None)
            lang = "json"
        else:
            raw = _as_string(get_by_path(payload, block.value)) if block.source == "event_path" else block.value
            lang = block.language or "text"

        truncated = False
        view_url = None
        if len(raw) > remaining_budget:
            keep = max(400, remaining_budget - 200)
            raw = raw[:keep] + "\n… (truncated)"
            truncated = True
            view_url = links.block_url(block_id)

        html = highlight_to_html(raw, lang)
        return (
            {"kind": "code", "html": html, "raw": raw, "truncated": truncated, "view_url": view_url},
            truncated,
        )

    if t == "log":
        full = (
            _as_string(get_by_path(payload, block.path or "$")) if block.source == "event_path" else (block.value or "")
        )
        lines = full.split("\n")
        shown = min(block.collapsed_lines, len(lines))
        preview = "\n".join(lines[:shown])
        html = highlight_to_html(preview, "log")
        truncated = len(lines) > shown
        return (
            {
                "kind": "log",
                "html": html,
                "raw": full,
                "shown": shown,
                "total": len(lines),
                "view_url": links.block_url(block_id),
                "truncated": truncated,
            },
            truncated,
        )

    if t == "ai_explanation":
        data = None
        if inp.resolve_ai is not None:
            data = await inp.resolve_ai(block.input_path, block.doc_context)
        return {"kind": "ai", "data": data}, False

    if t == "actions":
        buttons = []
        for i, btn in enumerate(block.buttons):
            if btn.action == "resolve":
                buttons.append({"label": btn.label, "href": links.action_url("resolve"), "variant": "primary"})
            elif btn.action == "escalate":
                buttons.append({"label": btn.label, "href": links.action_url("escalate"), "variant": "secondary"})
            else:
                href = links.track_link(btn.url, f"{block_id}-{i}") if btn.url else "#"
                buttons.append({"label": btn.label, "href": href, "variant": "link"})
        return {"kind": "actions", "buttons": buttons}, False

    return {"kind": "text", "html": "", "text": ""}, False


def _estimate_size(b: dict[str, Any]) -> int:
    kind = b["kind"]
    if kind == "text":
        return len(b["html"])
    if kind in ("code", "log"):
        return len(b["html"])
    if kind == "ai":
        data = b["data"]
        if data:
            return len(data.explanation) + len("".join(data.fix_steps)) + 400
        return 200
    if kind == "actions":
        return len(b["buttons"]) * 200
    return 0


def _to_plain_text(subject: str, blocks: list[dict[str, Any]]) -> str:
    parts: list[str] = [subject, ""]
    for b in blocks:
        kind = b["kind"]
        if kind == "text":
            parts += [b["text"], ""]
        elif kind == "code":
            parts += [
                "```",
                b["raw"],
                "```",
                f"Full content: {b['view_url']}" if b["truncated"] and b["view_url"] else "",
                "",
            ]
        elif kind == "log":
            preview = "\n".join(b["raw"].split("\n")[: b["shown"]])
            parts += [
                f"--- log ({b['shown']}/{b['total']} lines) ---",
                preview,
                f"Full log: {b['view_url']}",
                "",
            ]
        elif kind == "ai":
            data = b["data"]
            if data:
                parts += ["AI EXPLANATION:", data.explanation, "", "Suggested steps:"]
                for i, s in enumerate(data.fix_steps):
                    parts.append(f"  {i + 1}. {s}")
                parts += [
                    f"Confidence: {data.confidence} — verify before acting on live systems.",
                    "",
                ]
            else:
                parts += ["Our support team has been notified and will follow up.", ""]
        elif kind == "actions":
            for btn in b["buttons"]:
                parts.append(f"{btn['label']}: {btn['href']}")
            parts.append("")
    return "\n".join(parts)


async def render_email_message(inp: RenderInput) -> RenderedMessage:
    subject = _interpolate(inp.step.template.subject or "Update", inp.payload)
    brand_name = (inp.brand or {}).get("name") or "DripStack"

    prepared: list[dict[str, Any]] = []
    used = 5_000  # base layout overhead estimate
    any_truncated = False

    for idx, block in enumerate(inp.step.template.blocks):
        remaining = max(600, HTML_SIZE_BUDGET - used)
        p, truncated_out = await _prepare_block(block, idx, inp, remaining)
        prepared.append(p)
        any_truncated = any_truncated or truncated_out
        used += _estimate_size(p)

    first_text = next((b for b in prepared if b["kind"] == "text"), None)
    preview = (first_text["text"][:140] if first_text else subject) or subject

    html = _template.render(
        subject=subject,
        preview=preview,
        brand_name=brand_name,
        blocks=prepared,
        pixel_url=inp.links.pixel_url(),
    )
    text = _to_plain_text(subject, prepared)
    return RenderedMessage(subject=subject, html=html, text=text, truncated=any_truncated)
