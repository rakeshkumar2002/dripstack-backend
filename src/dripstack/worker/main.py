"""Worker entrypoint (port of apps/worker/src/main.ts).

Runs three things side by side:
  1. Temporal worker  — executes sequenceRunWorkflow + its activities,
  2. RabbitMQ ingest consumer  — normalizes buffered inbound events,
  3. RabbitMQ outbound consumer — delivers outbound webhooks with retries.
"""

from __future__ import annotations

import asyncio
import json

from aio_pika.abc import AbstractIncomingMessage
from temporalio.worker import Worker

from ..config import assert_production_secrets, settings
from ..logging import logger
from ..queue import (
    OUTBOUND_MAX_ATTEMPTS,
    QUEUE_INGEST,
    QUEUE_OUTBOUND,
    death_count,
    declare_topology,
    get_channel,
)
from ..temporal.client import get_temporal_client
from .activities import finalize_run, load_run_plan, record_current_step, render_and_send_step
from .processors.ingest import process_ingest_job
from .processors.outbound import process_outbound_job
from .workflows import SequenceRunWorkflow


async def _on_ingest(message: AbstractIncomingMessage) -> None:
    try:
        await process_ingest_job(json.loads(message.body))
    except Exception as err:  # noqa: BLE001 - best-effort, mirror BullMQ ingest worker
        logger.error("ingest job failed", err=str(err))
    finally:
        await message.ack()


async def _on_outbound(message: AbstractIncomingMessage) -> None:
    try:
        await process_outbound_job(json.loads(message.body))
        await message.ack()
    except Exception as err:  # noqa: BLE001
        attempts = death_count(message) + 1
        if attempts >= OUTBOUND_MAX_ATTEMPTS:
            logger.error("outbound job giving up", attempts=attempts, err=str(err))
            await message.ack()  # stop the retry loop
        else:
            logger.warning("outbound attempt failed — retrying", attempts=attempts, err=str(err))
            await message.reject(requeue=False)  # → DLX → retry queue → back to outbound


async def _amain() -> None:
    assert_production_secrets()
    client = await get_temporal_client()
    worker = Worker(
        client,
        task_queue=settings().TEMPORAL_TASK_QUEUE,
        workflows=[SequenceRunWorkflow],
        activities=[load_run_plan, record_current_step, render_and_send_step, finalize_run],
    )

    channel = await get_channel()
    await declare_topology(channel)
    ingest_q = await channel.get_queue(QUEUE_INGEST)
    outbound_q = await channel.get_queue(QUEUE_OUTBOUND)
    await ingest_q.consume(_on_ingest)
    await outbound_q.consume(_on_outbound)

    logger.info(
        "worker started (temporal + ingest + outbound)",
        task_queue=settings().TEMPORAL_TASK_QUEUE,
        temporal=settings().TEMPORAL_ADDRESS,
    )
    await worker.run()


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        logger.info("worker shutting down")


if __name__ == "__main__":
    main()
