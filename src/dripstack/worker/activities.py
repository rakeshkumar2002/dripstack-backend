"""Temporal activities (port of apps/worker/src/activities.ts).

Activities run outside the deterministic workflow sandbox and own all I/O:
DB reads/writes, rendering, email/stub delivery, and outbound-webhook fan-out.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from temporalio import activity

from ..config import settings
from ..db import ChannelIntegration, MessageLog, MessageStatus, Organization, RunStatus, SequenceRun
from ..db.session import session_scope
from ..links import make_link_builder
from ..logging import logger
from ..providers.ai import AiExplainerService, ExplainInput
from ..providers.channels import get_channel_sender
from ..providers.email import SendArgs, get_email_provider
from ..queue import publish_outbound
from ..render import RenderInput, render_email_message
from ..shared import delay_to_ms, get_by_path, parse_steps

_ai = AiExplainerService.from_settings()


async def _load_run(session, run_id: str) -> SequenceRun:
    run = await session.get(SequenceRun, run_id)
    if run is None:
        raise RuntimeError(f"run {run_id} not found")
    return run


@activity.defn(name="loadRunPlan")
async def load_run_plan(run_id: str) -> dict[str, Any]:
    """Only the timing metadata the deterministic workflow needs."""
    async with session_scope() as session:
        run = await _load_run(session, run_id)
        steps = parse_steps(run.sequence.steps)
        plan_steps = []
        had_wait = False
        for s in steps:
            if s.wait_for_action:
                had_wait = True
            plan_steps.append(
                {
                    "delay_ms": delay_to_ms(s.delay),
                    "wait_for_action": (
                        {
                            "timeout_ms": round(s.wait_for_action.timeout_hours * 3_600_000),
                            "on_timeout": s.wait_for_action.on_timeout,
                        }
                        if s.wait_for_action
                        else None
                    ),
                }
            )
        return {"had_wait": had_wait, "steps": plan_steps}


@activity.defn(name="recordCurrentStep")
async def record_current_step(run_id: str, step_index: int) -> None:
    async with session_scope() as session:
        run = await _load_run(session, run_id)
        run.current_step = step_index


@activity.defn(name="renderAndSendStep")
async def render_and_send_step(run_id: str, step_index: int) -> None:
    async with session_scope() as session:
        run = await _load_run(session, run_id)
        org = await session.get(Organization, run.organization_id)
        steps = parse_steps(run.sequence.steps)
        if step_index >= len(steps):
            raise RuntimeError(f"step {step_index} missing on run {run_id}")
        step = steps[step_index]

        log = logger.bind(run_id=run_id, org_id=run.organization_id, step=step_index, channel=step.channel)
        org_settings: dict[str, Any] = (org.settings if org else {}) or {}
        payload = (run.event.payload if run.event else {}) or {}

        async def resolve_ai(input_path: str, doc_context: str | None):
            return await _ai.explain(
                ExplainInput(
                    error_payload=get_by_path(payload, input_path),
                    product_doc_context=doc_context or org_settings.get("productDocContext"),
                )
            )

        try:
            rendered = await render_email_message(
                RenderInput(
                    step=step,
                    payload=payload,
                    contact={"email": run.contact.email, "name": run.contact.name},
                    links=make_link_builder(run_id),
                    brand={"name": org.name if org else "DripStack"},
                    resolve_ai=resolve_ai,
                )
            )

            if step.channel == "email":
                provider = get_email_provider(org_settings)
                res = await provider.send(
                    SendArgs(
                        to=run.contact.email,
                        from_=org_settings.get("fromAddress") or settings().EMAIL_FROM_DEFAULT,
                        subject=rendered.subject,
                        html=rendered.html,
                        text=rendered.text,
                    )
                )
                provider_message_id = res.provider_message_id
            else:
                integration = (
                    await session.execute(
                        select(ChannelIntegration).where(
                            ChannelIntegration.organization_id == run.organization_id,
                            ChannelIntegration.channel == step.channel,
                        )
                    )
                ).scalars().first()
                link = f"{settings().DASHBOARD_URL}/runs/{run_id}"
                res = await get_channel_sender(step.channel, integration).send(
                    to=run.contact.slack_user_id or run.contact.email,
                    subject=rendered.subject,
                    html=rendered.html,
                    text=rendered.text,
                    link=link,
                )
                provider_message_id = res.id

            session.add(
                MessageLog(
                    organization_id=run.organization_id,
                    run_id=run_id,
                    step_id=step.id,
                    channel=step.channel,
                    status=MessageStatus.sent,
                    provider_message_id=provider_message_id,
                    rendered_html=rendered.html,
                    rendered_text=rendered.text,
                    sent_at=datetime.now(UTC),
                )
            )
            log.info("step delivered", provider_message_id=provider_message_id, truncated=rendered.truncated)
        except Exception as err:  # noqa: BLE001 - a failed send must not stall the sequence
            log.error("step delivery failed", err=str(err))
            session.add(
                MessageLog(
                    organization_id=run.organization_id,
                    run_id=run_id,
                    step_id=step.id,
                    channel=step.channel,
                    status=MessageStatus.failed,
                    error=str(err),
                )
            )


@activity.defn(name="finalizeRun")
async def finalize_run(run_id: str, status: str) -> None:
    """Terminal: set run status, timing, and fan out matching outbound webhooks."""
    publish_jobs: list[dict[str, Any]] = []
    async with session_scope() as session:
        run = await _load_run(session, run_id)
        if run.status != RunStatus.running:
            return  # idempotent guard against double-finalize

        ended_at = datetime.now(UTC)
        resolution_time_seconds = None
        if status == "resolved":
            started = run.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            resolution_time_seconds = round((ended_at - started).total_seconds())

        run.status = RunStatus(status)
        run.ended_at = ended_at
        run.resolution_time_seconds = resolution_time_seconds

        event_name = f"run.{status}"
        from sqlalchemy import select

        from ..db import OutboundWebhook

        hooks = (
            (
                await session.execute(
                    select(OutboundWebhook).where(
                        OutboundWebhook.organization_id == run.organization_id,
                        OutboundWebhook.events.contains([event_name]),
                    )
                )
            )
            .scalars()
            .all()
        )

        for h in hooks:
            publish_jobs.append(
                {
                    "organization_id": run.organization_id,
                    "webhook_id": h.id,
                    "url": h.url,
                    "secret": h.secret,
                    "event": event_name,
                    "data": {
                        "runId": run_id,
                        "status": status,
                        "sequenceId": run.sequence_id,
                        "contactEmail": run.contact.email,
                        "resolutionTimeSeconds": resolution_time_seconds,
                        "occurredAt": ended_at.isoformat(),
                    },
                }
            )

    for job in publish_jobs:
        await publish_outbound(job)
    logger.bind(run_id=run_id).info("run finalized", status=status)
