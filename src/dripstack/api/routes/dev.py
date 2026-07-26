"""Local email preview (port of apps/api/src/routes/dev.ts).

When EMAIL_PROVIDER=log (the keyless default) no real email is sent — the
rendered HTML is stored on MessageLog and shown here, so the whole demo is
observable end-to-end without an ESP account.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ...db import Channel, MessageLog
from ...db.session import session_scope

router = APIRouter()


@router.get("/dev/emails")
async def list_emails(org: str | None = None):
    async with session_scope() as session:
        stmt = (
            select(MessageLog)
            .options(selectinload(MessageLog.run))
            .where(MessageLog.channel == Channel.email)
            .order_by(MessageLog.created_at.desc())
            .limit(50)
        )
        # This route bypasses the `for_org` tenant guard by design (it is
        # unauthenticated), so a shared dev/staging DB with more than one tenant
        # would otherwise mix orgs' email bodies together. Scope it when asked.
        if org:
            stmt = stmt.where(MessageLog.organization_id == org)
        logs = (await session.execute(stmt)).scalars().all()

        rows = "".join(
            f"""<tr>
          <td><a href="/dev/emails/{m.id}">{m.run.sequence.name}</a></td>
          <td>{m.run.contact.email}</td>
          <td><span class="badge {m.status.value}">{m.status.value}</span></td>
          <td>{m.created_at.isoformat(sep=" ")[:19]}</td>
        </tr>"""
            for m in logs
        )

    table = (
        "<table><thead><tr><th>Sequence</th><th>To</th><th>Status</th><th>Rendered at</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
        if logs
        else '<p class="empty">No emails yet. Run the demo: <code>scripts/fire-demo-event.sh</code></p>'
    )
    html = (
        '<!doctype html><html><head><meta charset="utf-8"><title>DripStack · Email preview</title>'
        "<style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#f6f8fa;margin:0;"
        "padding:32px;color:#1f2328}h1{font-size:20px}table{width:100%;border-collapse:collapse;"
        "background:#fff;border:1px solid #d0d7de;border-radius:8px;overflow:hidden}th,td{text-align:"
        "left;padding:10px 14px;border-bottom:1px solid #eaeef2;font-size:14px}th{background:#f6f8fa;"
        "color:#656d76}a{color:#0969da;text-decoration:none}.badge{font-size:12px;padding:2px 8px;"
        "border-radius:999px;background:#dafbe1;color:#1a7f37}.badge.failed{background:#ffebe9;"
        "color:#cf222e}.empty{color:#656d76;padding:24px}</style></head>"
        "<body><h1>📧 Rendered emails (log provider)</h1>"
        f"{table}</body></html>"
    )
    return HTMLResponse(html)


@router.get("/dev/emails/{message_id}")
async def get_email(message_id: str):
    async with session_scope() as session:
        log = await session.get(MessageLog, message_id)
    if log is None or not log.rendered_html:
        return HTMLResponse("<p>Not found or not rendered.</p>", status_code=404)
    return HTMLResponse(log.rendered_html)
