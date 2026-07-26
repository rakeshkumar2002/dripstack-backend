"""Tracking routes (port of apps/api/src/routes/tracking.ts).

Signed, tamper-proof links: each token is an HMAC over (runId, scope, ref),
verified before recording a click/open, signalling the workflow, or redirecting.
"""

from __future__ import annotations

import base64
from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select

from ...config import settings
from ...db import ActionClick, Event, MessageLog, MessageStatus, Sequence, SequenceRun
from ...db.session import session_scope
from ...render import highlight_to_html
from ...shared import get_by_path, sha256_hex, verify_link_token
from ...shared.types import parse_steps, pretty_json
from ...temporal.client import signal_action

router = APIRouter()

_TRANSPARENT_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def _secret() -> str:
    return settings().LINK_SIGNING_SECRET


def _page(title: str, body_html: str) -> str:
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>body{{font-family:ui-sans-serif,system-ui,-apple-system,"
        "sans-serif;background:#f3f4f6;color:#1f2328;display:flex;min-height:100vh;align-items:"
        "center;justify-content:center;margin:0}.card{background:#fff;border:1px solid #d0d7de;"
        "border-radius:12px;padding:32px 40px;max-width:520px;box-shadow:0 1px 3px rgba(0,0,0,.06)}"
        "h1{font-size:18px;margin:0 0 8px}p{color:#656d76;line-height:1.6;margin:0}pre{background:"
        "#f6f8fa;border:1px solid #d0d7de;border-radius:6px;padding:14px;overflow:auto;font-size:"
        f'13px}}</style></head><body><div class="card">{body_html}</div></body></html>'
    )


_ACTION_LABELS = {
    "resolve": ("✅ Mark this incident as resolved", "Mark as resolved"),
    "escalate": ("🆘 Escalate this incident for help", "Escalate / I need help"),
}


@router.get("/r/{run_id}/action/{action}")
async def action_confirm(run_id: str, action: str, token: str | None = None):
    """Confirmation interstitial. State-changing work happens on POST, never GET —
    so email/AV link-scanners and client prefetch (which issue GETs) can't silently
    resolve or escalate an incident. The user clicks the button to POST."""
    if action not in _ACTION_LABELS:
        return HTMLResponse(_page("Invalid", "<h1>Invalid action</h1>"), status_code=400)
    if not token or not verify_link_token(_secret(), run_id, "action", action, token):
        return HTMLResponse(_page("Forbidden", "<h1>Link expired or invalid</h1>"), status_code=403)
    heading, button = _ACTION_LABELS[action]
    body = (
        f"<h1>{heading}</h1>"
        "<p>Please confirm this action.</p>"
        f'<form method="post" action="/r/{run_id}/action/{action}?token={token}" style="margin-top:20px">'
        f'<button type="submit" style="background:#2f5fd0;color:#fff;border:0;border-radius:8px;'
        'padding:12px 20px;font-size:15px;font-weight:600;cursor:pointer">'
        f"{button}</button></form>"
    )
    return HTMLResponse(_page("Confirm action", body))


@router.post("/r/{run_id}/action/{action}")
async def action(run_id: str, action: str, request: Request, token: str | None = None):
    if action not in _ACTION_LABELS:
        return HTMLResponse(_page("Invalid", "<h1>Invalid action</h1>"), status_code=400)
    if not token or not verify_link_token(_secret(), run_id, "action", action, token):
        return HTMLResponse(_page("Forbidden", "<h1>Link expired or invalid</h1>"), status_code=403)

    async with session_scope() as session:
        run = await session.get(SequenceRun, run_id)
        if run is None:
            return HTMLResponse(_page("Not found", "<h1>Run not found</h1>"), status_code=404)
        ip = request.client.host if request.client else ""
        session.add(
            ActionClick(
                organization_id=run.organization_id,
                run_id=run_id,
                action=action,
                ip_hash=sha256_hex(ip),
            )
        )
        for m in run.message_logs:
            m.status = MessageStatus.clicked
        workflow_id = run.temporal_workflow_id

    await signal_action(workflow_id, action)

    if action == "resolve":
        msg = (
            "<h1>✅ Marked as resolved</h1><p>Thanks — this incident is now closed. You can safely close this tab.</p>"
        )
    else:
        msg = (
            "<h1>🆘 Help is on the way</h1><p>We've escalated this to the support team. They'll follow up shortly.</p>"
        )
    return HTMLResponse(_page("DripStack", msg))


@router.get("/r/{run_id}/pixel.gif")
async def pixel(run_id: str, token: str | None = None):
    if token and verify_link_token(_secret(), run_id, "pixel", "open", token):
        async with session_scope() as session:
            run = await session.get(SequenceRun, run_id)
            if run is not None:
                last = (
                    (
                        await session.execute(
                            select(MessageLog)
                            .where(
                                MessageLog.organization_id == run.organization_id,
                                MessageLog.run_id == run_id,
                                MessageLog.status == MessageStatus.sent,
                            )
                            .order_by(MessageLog.created_at.desc())
                        )
                    )
                    .scalars()
                    .first()
                )
                if last is not None:
                    last.status = MessageStatus.opened
    return Response(content=_TRANSPARENT_GIF, media_type="image/gif", headers={"Cache-Control": "no-store"})


@router.get("/r/{run_id}/link/{ref}")
async def link(run_id: str, ref: str, token: str | None = None, u: str | None = None):
    dest = unquote(u) if u else ""
    # The token is bound to the destination URL, so `u` can't be swapped for a
    # phishing target (open-redirect). Also hard-require an http(s) scheme.
    if (
        not dest
        or not token
        or not verify_link_token(_secret(), run_id, "link", ref, token, extra=dest)
        or not dest.lower().startswith(("http://", "https://"))
    ):
        return Response(content="invalid link", status_code=403)
    async with session_scope() as session:
        run = await session.get(SequenceRun, run_id)
        if run is not None:
            for m in run.message_logs:
                m.status = MessageStatus.clicked
    return RedirectResponse(url=dest)


@router.get("/r/{run_id}/log/{block_id}")
async def log_page(run_id: str, block_id: str, token: str | None = None):
    if not token or not verify_link_token(_secret(), run_id, "log", block_id, token):
        return HTMLResponse(_page("Forbidden", "<h1>Link expired or invalid</h1>"), status_code=403)

    async with session_scope() as session:
        run = await session.get(SequenceRun, run_id)
        if run is None:
            return HTMLResponse(_page("Not found", "<h1>Run not found</h1>"), status_code=404)
        seq = await session.get(Sequence, run.sequence_id)
        event = await session.get(Event, run.event_id) if run.event_id else None
        steps = parse_steps(seq.steps)
        payload = (event.payload if event else {}) or {}

    idx = int(block_id.lstrip("b"))
    all_blocks = [b for s in steps for b in s.template.blocks]
    block = all_blocks[idx] if 0 <= idx < len(all_blocks) else None

    raw = "(content unavailable)"
    lang = "text"
    if block is not None:
        if block.type == "log":
            raw = (
                str(get_by_path(payload, block.path or "$") or "")
                if block.source == "event_path"
                else (block.value or "")
            )
        elif block.type == "json":
            val = get_by_path(payload, block.path or "$") if block.source == "event_path" else block.value
            raw = pretty_json(val)
            lang = "json"
        elif block.type == "code":
            raw = str(get_by_path(payload, block.value) or "") if block.source == "event_path" else block.value
            lang = block.language

    html = highlight_to_html(raw, lang)
    return HTMLResponse(_page("Full content", f"<h1>Full content</h1>{html}"))
