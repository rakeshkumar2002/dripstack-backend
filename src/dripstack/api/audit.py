"""Audit logging helper.

`record_audit` appends an AuditLog row. It opens its own short transaction so a
failure to write the audit trail never rolls back (or blocks) the action being
audited — auditing is best-effort and must not break the primary operation.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from ..db import AuditLog
from ..db.session import session_scope
from ..logging import logger
from ..shared import sha256_hex


def _client_ip_hash(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return sha256_hex(request.client.host)


async def record_audit(
    *,
    organization_id: str,
    action: str,
    actor_id: str | None = None,
    actor_label: str | None = None,
    target: str | None = None,
    meta: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    try:
        async with session_scope() as session:
            session.add(
                AuditLog(
                    organization_id=organization_id,
                    actor_id=actor_id,
                    actor_label=actor_label,
                    action=action,
                    target=target,
                    ip_hash=_client_ip_hash(request),
                    meta=meta or {},
                )
            )
    except Exception as err:  # noqa: BLE001 - auditing must never break the request
        logger.warning("failed to write audit log", action=action, err=str(err))
