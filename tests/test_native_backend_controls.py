"""Use actual attempt receipts for timed-out control runs."""
from scripts.compare_native_backends import stage_details


def event(attempt, name, **fields):
    return {"event": "attempt_event", "attempt": attempt, "payload": {"event": name, **fields}}


def test_partial_fallback_is_visible_without_a_final_policy_choice():
    row = {"query_entered": 10.0, "backend": "concrete_enumeration", "events": [
        event("frozen_symbolic", "operation_opened", time=10.01),
        event("frozen_symbolic", "producer_started"),
        event("concrete_enumeration", "producer_started"),
    ]}
    detail = stage_details(row)
    assert detail["last_started_backend"] == "concrete_enumeration"
    assert detail["fallback_started"] and detail["fallback_unfinished"]
    assert abs(detail["pre_operation_seconds"] - 0.01) < 1e-10


def test_parent_backend_default_is_not_evidence_that_concrete_execution_started():
    row = {"query_entered": 10.0, "backend": "concrete_enumeration", "events": [
        event("frozen_symbolic", "operation_opened", time=11.9),
        event("frozen_symbolic", "producer_started"),
    ]}
    detail = stage_details(row)
    assert detail["last_started_backend"] == "frozen_symbolic"
    assert not detail["fallback_started"]
    assert abs(detail["pre_operation_seconds"] - 1.9) < 1e-10
