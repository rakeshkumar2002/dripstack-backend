"""Pure trigger matching (port of packages/shared/src/trigger.ts).

eventType must match exactly; every condition must pass (AND semantics).
"""

from __future__ import annotations

import math
from typing import Any

from .jsonpath import get_by_path, path_exists
from .types import Condition, TriggerRule


def event_matches_trigger(event: dict[str, Any], rule: TriggerRule) -> bool:
    """event = {"type": str, "payload": Any}."""
    if rule.event_type != event.get("type"):
        return False
    return all(eval_condition(event.get("payload"), c) for c in rule.conditions)


def eval_condition(payload: Any, c: Condition) -> bool:
    if c.op == "exists":
        return path_exists(payload, c.path)

    actual = get_by_path(payload, c.path)

    if c.op == "eq":
        return _loose_eq(actual, c.value)
    if c.op == "neq":
        return not _loose_eq(actual, c.value)
    if c.op == "contains":
        return _contains(actual, c.value)
    if c.op == "gt":
        return _to_num(actual) > _to_num(c.value)
    if c.op == "lt":
        return _to_num(actual) < _to_num(c.value)
    return False


def _loose_eq(a: Any, b: Any) -> bool:
    if a is b or a == b:
        return True
    # Numeric/string coercion so `"409" eq 409` matches across JSON sources.
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        return _stringify(a) == _stringify(b)
    return False


def _contains(actual: Any, needle: Any) -> bool:
    if isinstance(actual, (list, tuple)):
        return any(_loose_eq(x, needle) for x in actual)
    if isinstance(actual, str):
        return _stringify(needle) in actual
    return False


def _to_num(v: Any) -> float:
    if isinstance(v, bool):
        return math.nan
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v.strip() != "":
        try:
            return float(v)
        except ValueError:
            return math.nan
    return math.nan


def _stringify(v: Any) -> str:
    """Match JS String(v) for the values relevant to coercion (numbers/strings)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if v is None:
        return "null"
    return str(v)
