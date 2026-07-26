"""RabbitMQ wiring with aio-pika (replaces packages/core/src/queues.ts BullMQ).

Two durable queues buffer the work where retries/backoff add real value:
  - `ingest`   — bursty inbound-event normalization (best-effort, no retry),
  - `outbound` — outbound webhook delivery with dead-letter-based retry/backoff.

Outbound retry topology (AMQP equivalent of BullMQ's exponential backoff):
  outbound  --(nack/reject)-->  DLX  -->  outbound.retry (TTL)  --expire-->  outbound
A message's redelivery count is read from the `x-death` header; after
OUTBOUND_MAX_ATTEMPTS the consumer acks (gives up) instead of looping forever.
"""

from __future__ import annotations

import json
from typing import Any

import aio_pika
from aio_pika.abc import AbstractRobustChannel, AbstractRobustConnection

from ..config import settings

QUEUE_INGEST = "ingest"
QUEUE_OUTBOUND = "outbound"
QUEUE_OUTBOUND_RETRY = "outbound.retry"
OUTBOUND_RETRY_TTL_MS = 2_000
OUTBOUND_MAX_ATTEMPTS = 3

_connection: AbstractRobustConnection | None = None
_channel: AbstractRobustChannel | None = None


async def get_connection() -> AbstractRobustConnection:
    global _connection
    if _connection is None or _connection.is_closed:
        _connection = await aio_pika.connect_robust(settings().RABBITMQ_URL)
    return _connection


async def get_channel() -> AbstractRobustChannel:
    global _channel
    if _channel is None or _channel.is_closed:
        conn = await get_connection()
        _channel = await conn.channel()
        await _channel.set_qos(prefetch_count=8)
    return _channel


async def declare_topology(channel: AbstractRobustChannel) -> None:
    """Idempotently declare all queues + the outbound retry dead-letter chain."""
    await channel.declare_queue(QUEUE_INGEST, durable=True)
    await channel.declare_queue(
        QUEUE_OUTBOUND,
        durable=True,
        arguments={
            "x-dead-letter-exchange": "",
            "x-dead-letter-routing-key": QUEUE_OUTBOUND_RETRY,
        },
    )
    await channel.declare_queue(
        QUEUE_OUTBOUND_RETRY,
        durable=True,
        arguments={
            "x-message-ttl": OUTBOUND_RETRY_TTL_MS,
            "x-dead-letter-exchange": "",
            "x-dead-letter-routing-key": QUEUE_OUTBOUND,
        },
    )


async def _publish(routing_key: str, payload: dict[str, Any]) -> None:
    channel = await get_channel()
    await declare_topology(channel)
    body = json.dumps(payload).encode("utf-8")
    await channel.default_exchange.publish(
        aio_pika.Message(body, delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
        routing_key=routing_key,
    )


async def publish_ingest(job: dict[str, Any]) -> None:
    await _publish(QUEUE_INGEST, job)


async def publish_outbound(job: dict[str, Any]) -> None:
    await _publish(QUEUE_OUTBOUND, job)


def death_count(message: aio_pika.abc.AbstractIncomingMessage) -> int:
    """How many times this message has already been dead-lettered (retried)."""
    x_death = message.headers.get("x-death") if message.headers else None
    if isinstance(x_death, list) and x_death:
        try:
            return int(x_death[0].get("count", 0))
        except (AttributeError, TypeError, ValueError):
            return 0
    return 0
