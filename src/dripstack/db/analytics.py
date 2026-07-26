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
    }
