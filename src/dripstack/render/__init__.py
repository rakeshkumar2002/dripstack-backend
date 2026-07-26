"""Email render engine (Jinja2 + Pygments) — port of packages/render."""

from .context import HTML_SIZE_BUDGET, LinkBuilder, RenderedMessage, RenderInput
from .email import render_email_message
from .highlight import escape_html, highlight_to_html
from .markdown import markdown_to_html, markdown_to_text

__all__ = [
    "render_email_message",
    "highlight_to_html",
    "escape_html",
    "markdown_to_html",
    "markdown_to_text",
    "HTML_SIZE_BUDGET",
    "LinkBuilder",
    "RenderInput",
    "RenderedMessage",
]
