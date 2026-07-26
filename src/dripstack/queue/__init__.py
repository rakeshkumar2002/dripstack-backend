"""RabbitMQ queue layer (aio-pika) — replaces the BullMQ/Redis wiring."""

from .rabbit import (
    OUTBOUND_MAX_ATTEMPTS,
    QUEUE_INGEST,
    QUEUE_OUTBOUND,
    QUEUE_OUTBOUND_RETRY,
    death_count,
    declare_topology,
    get_channel,
    get_connection,
    publish_ingest,
    publish_outbound,
)

__all__ = [
    "QUEUE_INGEST",
    "QUEUE_OUTBOUND",
    "QUEUE_OUTBOUND_RETRY",
    "OUTBOUND_MAX_ATTEMPTS",
    "death_count",
    "declare_topology",
    "get_channel",
    "get_connection",
    "publish_ingest",
    "publish_outbound",
]
