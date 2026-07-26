from dripstack.shared.trigger import eval_condition, event_matches_trigger
from dripstack.shared.types import Condition, TriggerRule

payload = {
    "error": {"status": 409, "code": "OBJECT_OVERRIDDEN", "message": "Write to presentValue rejected"},
    "technician": {"email": "tech@example.com"},
}


def _c(**kw) -> Condition:
    return Condition.model_validate(kw)


def test_eq_with_numeric_coercion():
    assert eval_condition(payload, _c(path="$.error.status", op="eq", value=409)) is True
    assert eval_condition(payload, _c(path="$.error.status", op="eq", value="409")) is True
    assert eval_condition(payload, _c(path="$.error.status", op="eq", value=500)) is False


def test_neq_contains_gt_lt_exists():
    assert eval_condition(payload, _c(path="$.error.code", op="neq", value="OK")) is True
    assert eval_condition(payload, _c(path="$.error.message", op="contains", value="rejected")) is True
    assert eval_condition(payload, _c(path="$.error.status", op="gt", value=400)) is True
    assert eval_condition(payload, _c(path="$.error.status", op="lt", value=400)) is False
    assert eval_condition(payload, _c(path="$.technician.email", op="exists")) is True
    assert eval_condition(payload, _c(path="$.technician.phone", op="exists")) is False


_rule = TriggerRule.model_validate(
    {
        "eventType": "metasys.api_error",
        "conditions": [
            {"path": "$.error.status", "op": "gt", "value": 400},
            {"path": "$.error.code", "op": "exists"},
        ],
    }
)


def test_matches_when_type_and_all_conditions_pass():
    assert event_matches_trigger({"type": "metasys.api_error", "payload": payload}, _rule) is True


def test_fails_on_type_mismatch():
    assert event_matches_trigger({"type": "other.event", "payload": payload}, _rule) is False


def test_fails_when_a_condition_fails():
    bad = {"type": "metasys.api_error", "payload": {"error": {"status": 200, "code": "OK"}}}
    assert event_matches_trigger(bad, _rule) is False
