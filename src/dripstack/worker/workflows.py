"""The durable sequence engine (port of apps/worker/src/workflows.ts).

One workflow execution == one SequenceRun. Drip delays are durable timers
(`workflow.sleep`); branching is driven by the `actionReceived` SIGNAL raced
against a durable timeout. The workflow stays deterministic — all I/O lives in
activities.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from ..temporal.client import ACTION_RECEIVED_SIGNAL
    from .activities import finalize_run, load_run_plan, record_current_step, render_and_send_step

_ACT_OPTS: dict[str, Any] = {
    "start_to_close_timeout": timedelta(minutes=2),
    "retry_policy": RetryPolicy(maximum_attempts=3),
}


@workflow.defn(name="sequenceRunWorkflow")
class SequenceRunWorkflow:
    def __init__(self) -> None:
        # Buffer signals in a queue and consume one per wait. Robust against a
        # click that lands while earlier activities run (queued, not lost),
        # without letting one click satisfy multiple waits.
        self._signals: list[dict[str, Any]] = []

    @workflow.signal(name=ACTION_RECEIVED_SIGNAL)
    def action_received(self, payload: dict[str, Any]) -> None:
        self._signals.append(payload)

    @workflow.run
    async def run(self, inp: dict[str, Any]) -> str:
        run_id = inp["run_id"]
        plan = await workflow.execute_activity(load_run_plan, run_id, **_ACT_OPTS)
        steps = plan["steps"]

        for i, step in enumerate(steps):
            await workflow.execute_activity(record_current_step, args=[run_id, i], **_ACT_OPTS)

            if step["delay_ms"] > 0:
                await workflow.sleep(timedelta(milliseconds=step["delay_ms"]))

            await workflow.execute_activity(render_and_send_step, args=[run_id, i], **_ACT_OPTS)

            wfa = step.get("wait_for_action")
            if wfa:
                acted = True
                try:
                    await workflow.wait_condition(
                        lambda: len(self._signals) > 0,
                        timeout=timedelta(milliseconds=wfa["timeout_ms"]),
                    )
                except TimeoutError:
                    acted = False

                sig = self._signals.pop(0) if (acted and self._signals) else None

                if sig and sig.get("action") == "resolve":
                    await workflow.execute_activity(finalize_run, args=[run_id, "resolved"], **_ACT_OPTS)
                    return "resolved"
                if not acted and wfa["on_timeout"] == "end":
                    await workflow.execute_activity(finalize_run, args=[run_id, "escalated"], **_ACT_OPTS)
                    return "escalated"
                # 'escalate' signal OR (timeout with on_timeout='next_step') → continue.

        # Reached the end without an explicit resolve: an incident sequence
        # escalates; a purely informational one simply completes.
        terminal = "escalated" if plan["had_wait"] else "completed"
        await workflow.execute_activity(finalize_run, args=[run_id, terminal], **_ACT_OPTS)
        return terminal
