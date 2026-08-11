"""Analytics aggregations as raw SQL (the heavy lifting the DB does well).

Returns the exact shape the dashboard's /api/v1/analytics consumer expects.
All queries are scoped to one organization.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def compute_analytics(session: AsyncSession, org_id: str) -> dict[str, Any]:
    by_status_rows = (
        await session.execute(
            text(
                "SELECT status::text AS status, count(*) AS n "
                'FROM "SequenceRun" WHERE organization_id = :org GROUP BY status'
            ),
            {"org": org_id},
        )
    ).all()
    counts = {row.status: row.n for row in by_status_rows}

    avg_resolution = (
        await session.execute(
            text(
                "SELECT avg(resolution_time_seconds) AS avg "
                "FROM \"SequenceRun\" WHERE organization_id = :org AND status = 'resolved'"
            ),
            {"org": org_id},
        )
    ).scalar()

    msg_rows = (
        await session.execute(
            text(
                "SELECT status::text AS status, count(*) AS n "
                'FROM "MessageLog" WHERE organization_id = :org GROUP BY status'
            ),
            {"org": org_id},
        )
    ).all()
    message_status = {row.status: row.n for row in msg_rows}

    per_day_rows = (
        await session.execute(
            text(
                "SELECT to_char(date_trunc('day', started_at), 'YYYY-MM-DD') AS date, "
                'count(*) AS n FROM "SequenceRun" WHERE organization_id = :org '
                "GROUP BY 1 ORDER BY 1"
            ),
            {"org": org_id},
        )
    ).all()
    runs_over_time = [{"date": row.date, "count": row.n} for row in per_day_rows]

    # Today's runs, for the sidebar's "absorbed today" card. Counted by when the
    # run STARTED, so a long-running incident still belongs to the day it came
    # in — otherwise the denominator moves under you as runs finish.
    today_rows = (
        await session.execute(
            text(
                "SELECT status::text AS status, count(*) AS n "
                'FROM "SequenceRun" WHERE organization_id = :org '
                "AND started_at >= date_trunc('day', now()) "
                "GROUP BY status"
            ),
            {"org": org_id},
        )
    ).all()
    today_counts = {row.status: row.n for row in today_rows}
    t_resolved = today_counts.get("resolved", 0)
    t_terminal = t_resolved + today_counts.get("escalated", 0) + today_counts.get("completed", 0)

    total = sum(counts.values())
    resolved = counts.get("resolved", 0)
    escalated = counts.get("escalated", 0)
    terminal = resolved + escalated + counts.get("completed", 0)

    return {
        "totalRuns": total,
        "byStatus": counts,
        "resolutionRate": (resolved / terminal) if terminal else 0,
        "escalationRate": (escalated / terminal) if terminal else 0,
        "avgResolutionSeconds": float(avg_resolution) if avg_resolution is not None else None,
        "messageStatus": message_status,
        "runsOverTime": runs_over_time,
        "today": {
            "total": sum(today_counts.values()),
            "resolved": t_resolved,
            # Runs that reached an end today. The rate is deliberately null
            # rather than 0 when nothing has finished — "0%" reads as failure,
            # "no data yet" is the truth.
            "terminal": t_terminal,
            "absorbedRate": (t_resolved / t_terminal) if t_terminal else None,
        },
    }
