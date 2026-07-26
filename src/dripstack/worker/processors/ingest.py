"""Normalize one buffered inbound event (port of processors/ingest.ts).

1. idempotent dedupe (same org + payload hash within 5 min),
2. resolve + auto-create the contact,
3. persist the Event,
4. evaluate active sequences and start a Temporal workflow per match
   (deduping concurrent runs for the same sequence+contact).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from ...config import settings
from ...db import Contact, Event, EventSource, EventStatus, Sequence, SequenceRun, SequenceStatus
from ...db.session import session_scope
from ...logging import logger
from ...shared import canonical_json, event_matches_trigger, get_by_path, sha256_hex
from ...shared.types import parse_trigger
from ...temporal.client import get_temporal_client

DEDUPE_WINDOW = timedelta(minutes=5)


def _resolve_contact_email(payload: Any, configured_path: str | None) -> str | None:
    candidates = [
        *([configured_path] if configured_path else []),
        "$.technician.email",
        "$.contactEmail",
        "$.contact.email",
        "$.user.email",
    ]
    for path in candidates:
        v = get_by_path(payload, path)
        if isinstance(v, str) and "@" in v:
            return v
    return None


async def process_ingest_job(job: dict[str, Any]) -> None:
    org_id = job["organization_id"]
    job_type = job["type"]
    event_source_id = job.get("event_source_id")
    payload = job["payload"]
    log = logger.bind(org_id=org_id, type=job_type)
    payload_hash = sha256_hex(canonical_json(payload))

    async with session_scope() as session:
        recent = (
            (
                await session.execute(
                    select(Event).where(
                        Event.organization_id == org_id,
                        Event.payload_hash == payload_hash,
                        Event.received_at >= datetime.now(UTC) - DEDUPE_WINDOW,
                    )
                )
            )
            .scalars()
            .first()
        )
        if recent is not None:
            log.info("duplicate event ignored (dedupe window)", payload_hash=payload_hash)
            return

        source = None
        if event_source_id:
            source = await session.get(EventSource, event_source_id)
        contact_email = _resolve_contact_email(payload, source.contact_email_path if source else None)

        event = Event(
            organization_id=org_id,
            event_source_id=event_source_id,
            type=job_type,
            payload=payload,
            contact_email=contact_email,
            payload_hash=payload_hash,
            status=EventStatus.received,
        )
        session.add(event)
        await session.flush()

        if not contact_email:
            event.status = EventStatus.ignored
            log.warning("no contact email resolved from payload — event ignored")
            return

        contact = (
            (
                await session.execute(
                    select(Contact).where(Contact.organization_id == org_id, Contact.email == contact_email)
                )
            )
            .scalars()
            .first()
        )
        if contact is None:
            contact = Contact(
                organization_id=org_id,
                email=contact_email,
                name=get_by_path(payload, "$.technician.name"),
            )
            session.add(contact)
            await session.flush()

        sequences = (
            (
                await session.execute(
                    select(Sequence).where(
                        Sequence.organization_id == org_id,
                        Sequence.status == SequenceStatus.active,
                    )
                )
            )
            .scalars()
            .all()
        )

        matched = 0
        runs_to_start: list[dict[str, str]] = []
        for seq in sequences:
            try:
                rule = parse_trigger(seq.trigger_rule)
            except Exception:  # noqa: BLE001
                continue
            if not event_matches_trigger({"type": job_type, "payload": payload}, rule):
                continue

            matched += 1

            existing = (
                (
                    await session.execute(
                        select(SequenceRun).where(
                            SequenceRun.organization_id == org_id,
                            SequenceRun.sequence_id == seq.id,
                            SequenceRun.contact_id == contact.id,
                            SequenceRun.status == "running",
                        )
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                log.info("active run exists — skipping new run", sequence_id=seq.id, run_id=existing.id)
                continue

            workflow_id = f"seqrun-{event.id}-{seq.id}"
            run = SequenceRun(
                organization_id=org_id,
                sequence_id=seq.id,
                contact_id=contact.id,
                event_id=event.id,
                temporal_workflow_id=workflow_id,
                status="running",
            )
            session.add(run)
            await session.flush()
            runs_to_start.append({"run_id": run.id, "workflow_id": workflow_id})

        event.status = EventStatus.matched if matched > 0 else EventStatus.ignored
        log.info("event processed", matched=matched)

    # Start workflows after the transaction commits so the run rows are visible.
    for r in runs_to_start:
        await _start_workflow(org_id, r["run_id"], r["workflow_id"])


async def _start_workflow(org_id: str, run_id: str, workflow_id: str) -> None:
    from ..workflows import SequenceRunWorkflow

    client = await get_temporal_client()
    await client.start_workflow(
        SequenceRunWorkflow.run,
        {"run_id": run_id, "organization_id": org_id},
        id=workflow_id,
        task_queue=settings().TEMPORAL_TASK_QUEUE,
    )
    logger.bind(org_id=org_id).info("sequence run started", run_id=run_id, workflow_id=workflow_id)
