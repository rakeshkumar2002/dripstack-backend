"""Temporal client singleton (port of packages/core/src/temporal.ts).

Used by the worker's ingest processor to start `sequence_run_workflow` and by
the API tracking routes to deliver action signals.
"""

from __future__ import annotations

from temporalio.client import Client

from ..config import settings
from ..logging import logger

ACTION_RECEIVED_SIGNAL = "actionReceived"

_client: Client | None = None


async def get_temporal_client() -> Client:
    global _client
    if _client is None:
        _client = await Client.connect(settings().TEMPORAL_ADDRESS, namespace=settings().TEMPORAL_NAMESPACE)
    return _client


async def signal_action(workflow_id: str, action: str) -> None:
    """Deliver an actionReceived signal; tolerate a workflow that already ended."""
    try:
        client = await get_temporal_client()
        handle = client.get_workflow_handle(workflow_id)
        await handle.signal(ACTION_RECEIVED_SIGNAL, {"action": action})
    except Exception as err:  # noqa: BLE001
        logger.warning(
            "could not signal workflow (may have ended)",
            workflow_id=workflow_id,
            err=str(err),
        )
