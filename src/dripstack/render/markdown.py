"""Markdown helpers (port of render/src/markdown.ts).

`text` content blocks are a trusted authoring context.
"""

from __future__ import annotations

import re

import markdown as _md


def markdown_to_html(text: str) -> str:
    # nl2br ≈ marked `breaks: true`; extra/sane_lists ≈ gfm-ish.
    return _md.markdown(text, extensions=["extra", "nl2br", "sane_lists"])


def markdown_to_text(md: str) -> str:
    """Crude markdown → plaintext for the text/plain alternative part."""
    out = re.sub(r"`{1,3}([^`]*)`{1,3}", r"\1", md)
    out = re.sub(r"\*\*([^*]+)\*\*", r"\1", out)
    out = re.sub(r"\*([^*]+)\*", r"\1", out)
    out = re.sub(r"^#{1,6}\s+", "", out, flags=re.MULTILINE)
    out = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", out)
    return out.strip()
