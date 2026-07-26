"""Time-skipping test of the durable branching engine (port of workflows.test.ts).

Activities are mocked so the test exercises ONLY workflow logic (timers +
signals + branch decisions); the waitForAction timeout is fast-forwarded.

NOTE: on first run temporalio downloads a local test-server binary (needs
network). If it can't start, the suite is skipped so offline unit runs stay green.
"""

from __future__ import annotations

import uuid

import pytest
from temporalio import activity
from temporalio.worker import Worker

from dripstack.worker.workflows import SequenceRunWorkflow

TASK_QUEUE = "test-sequences"


@activity.defn(name="loadRunPlan")
async def mock_load_run_plan(run_id: str) -> dict:
    return {
        "had_wait": True,
        "steps": [{"delay_ms": 0, "wait_for_action": {"timeout_ms": 4 * 3_600_000, "on_timeout": "end"}}],
    }


@activity.defn(name="recordCurrentStep")
async def mock_record_current_step(run_id: str, step_index: int) -> None:
    return None


@activity.defn(name="renderAndSendStep")
async def mock_render_and_send_step(run_id: str, step_index: int) -> None:
    return None


@activity.defn(name="finalizeRun")
async def mock_finalize_run(run_id: str, status: str) -> None:
    return None


_MOCKS = [
    mock_load_run_plan,
    mock_record_current_step,
    mock_render_and_send_step,
    mock_finalize_run,
]


async def _make_env():
    from temporalio.testing import WorkflowEnvironment

    try:
        return await WorkflowEnvironment.start_time_skipping()
    except Exception as err:  # noqa: BLE001 - no network / binary → skip
        pytest.skip(f"temporal test server unavailable: {err}")


async def test_ends_resolved_when_resolve_signal_arrives_before_timeout():
    env = await _make_env()
    async with env:
        async with Worker(env.client, task_queue=TASK_QUEUE, workflows=[SequenceRunWorkflow], activities=_MOCKS):
            handle = await env.client.start_workflow(
                SequenceRunWorkflow.run,
                {"run_id": "run-1", "organization_id": "org-1"},
                id=f"wf-resolve-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            await handle.signal(SequenceRunWorkflow.action_received, {"action": "resolve"})
            assert await handle.result() == "resolved"


async def test_ends_escalated_when_wait_times_out():
    env = await _make_env()
    async with env:
        async with Worker(env.client, task_queue=TASK_QUEUE, workflows=[SequenceRunWorkflow], activities=_MOCKS):
            handle = await env.client.start_workflow(
                SequenceRunWorkflow.run,
                {"run_id": "run-2", "organization_id": "org-1"},
                id=f"wf-timeout-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            assert await handle.result() == "escalated"
