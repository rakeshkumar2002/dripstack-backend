"""Server-side syntax highlighting for email (port of render/src/highlight.ts).

We use Pygments with `noclasses=True` so every token carries an inline
`style="color: …"` — exactly what email needs (no external CSS, no JS). A single
light theme renders well across mail clients. The caller wraps the returned
`<pre>` in a padded `<td>` (Outlook strips padding off `<pre>` itself).
"""

from __future__ import annotations

from pygments import highlight as _pyg_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from pygments.util import ClassNotFound

# Light, email-friendly token colours (≈ Shiki github-light).
_FORMATTER = HtmlFormatter(noclasses=True, nowrap=True, style="default")

_ALIASES = {
    "js": "javascript",
    "ts": "typescript",
    "sh": "bash",
    "zsh": "bash",
    "shell": "bash",
    "log": "text",
    "txt": "text",
}


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def highlight_to_html(code: str, lang: str) -> str:
    language = _ALIASES.get(lang.lower(), lang.lower())
    if language == "text":
        return f'<pre style="margin:0">{escape_html(code)}</pre>'
    try:
        lexer = get_lexer_by_name(language)
    except ClassNotFound:
        return f'<pre style="margin:0">{escape_html(code)}</pre>'
    inner = _pyg_highlight(code, lexer, _FORMATTER)
    return f'<pre style="margin:0">{inner}</pre>'
