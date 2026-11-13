"""Synthetic immutable v15 ledgers; no model, runtime or measurement executes."""

from copy import deepcopy
import importlib.util
import math
from pathlib import Path
import sys

import pytest

from src.selective_analysis import cascade_evaluation
from src.selective_analysis import trace_headroom


# Reuse the fabricated ledger builders by explicit path; tests is not required
# to be an importable package.  Loading this module only defines unit helpers.
_spec = importlib.util.spec_from_file_location("cascade_fixture_helpers", Path(__file__).with_name("test_cascade_evaluation.py"))
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)


@pytest.fixture
def panel():
    return _fixtures.panel()


def find_row(records, query_id="readonly_chain", method="fixed_cascade", repetition=0):
    return next(row for row in records if row["query_id"] == query_id and row["method"] == method
                and row["repetition"] == repetition)


def test_complete_matrix_produces_nine_trace_deletions_without_freeing_parent_overhead(panel):
    records, references, gold = panel
    report = trace_headroom.summarize_trace_headroom(records, references, gold)
    assert report["schema"] == "symbai.trace_headroom.v1"
    assert report["unique_queries"] == report["repetitions"] == 3
    assert report["cascade_trials"] == 9 and report["validated_trial_records"] == 18
    assert report["separate_reference_records"] == 3
    assert len(report["traces"]) == 9 and len({trace["trial_id"] for trace in report["traces"]}) == 9
    per_query = {row["query_id"]: row for row in report["per_query"]}
    assert per_query["scalar_span"]["optimistic_deletable_attempt_seconds"] == [0.0] * 3
    assert per_query["scalar_span"]["deleted_operations"] == [[], [], []]
    assert per_query["readonly_chain"]["deleted_operations"] == [["interval"]] * 3
    assert per_query["readonly_chain_outside"]["deleted_operations"] == [["interval", "finite_readonly"]] * 3
    assert per_query["readonly_chain"]["optimistic_deletable_attempt_seconds"] == pytest.approx([0.1] * 3)
    assert per_query["readonly_chain_outside"]["optimistic_deletable_attempt_seconds"] == pytest.approx([0.2] * 3)
    assert report["aggregate"]["parent_charged_seconds"]["total_seconds"] == 27
    assert report["aggregate"]["optimistic_deletable_attempt_seconds"]["total_seconds"] == pytest.approx(0.9)
    assert report["aggregate"]["retained_charge_seconds"]["total_seconds"] == pytest.approx(26.1)
    for trace in report["traces"]:
        source = find_row(records, trace["query_id"], repetition=trace["repetition"])
        assert trace["query_hash"] == source["query_hash"] and trace["binary_sha256"] == source["binary_sha256"]
        assert trace["parent_charged_seconds"] == source["parent_receipt"]["charged_seconds"]
        assert trace["retained_charge_seconds"] == pytest.approx(
            trace["parent_charged_seconds"] - trace["optimistic_deletable_attempt_seconds"])
        assert trace["frame_model"] == "delete_unknown_attempts_hold_other_costs_fixed"
        assert trace["retained_charge_seconds"] > source["attempts"][-1]["elapsed_seconds"]


def test_first_repetition_and_variation_remain_in_vectors_and_statistics(panel):
    records, references, gold = panel
    row = find_row(records)
    row["attempts"][0]["elapsed_seconds"] = 0.8
    row["worker_elapsed_seconds"] = 2.0
    _fixtures.seal(row, charged=9.0)
    report = trace_headroom.summarize_trace_headroom(records, references, gold)
    query = next(row for row in report["per_query"] if row["query_id"] == "readonly_chain")
    assert query["repetitions"] == [0, 1, 2]
    assert query["optimistic_deletable_attempt_seconds"] == [0.8, 0.1, 0.1]
    stats = query["statistics"]["optimistic_deletable_attempt_seconds"]
    assert stats == {"count": 3, "total_seconds": 1.0, "median_seconds": 0.1,
                     "minimum_seconds": 0.1, "maximum_seconds": 0.8}
    assert report["aggregate"]["optimistic_deletable_attempt_seconds"]["maximum_seconds"] == 0.8


def test_decisive_operation_and_deleted_prefix_come_from_ledger_not_case_name(panel):
    records, references, gold = panel
    row = find_row(records, query_id="scalar_span")
    final = _fixtures.result("scalar_span", operation="expanded")
    row["attempts"] = [_fixtures.attempt(operation, _fixtures.result("scalar_span", status="unknown"))
                       for operation in ("interval", "finite_readonly")]
    row["attempts"].append(_fixtures.attempt("expanded", final))
    row["result"] = row["worker_result"] = deepcopy(final)
    _fixtures.seal(row)
    report = trace_headroom.summarize_trace_headroom(records, references, gold)
    trace = next(trace for trace in report["traces"] if trace["query_id"] == "scalar_span" and trace["repetition"] == 0)
    assert trace["decisive_operation"] == "expanded"
    assert trace["deleted_operations"] == ["interval", "finite_readonly"]
    assert trace["optimistic_deletable_attempt_seconds"] == pytest.approx(0.2)


def test_zero_unknown_attempt_time_is_valid_and_never_creates_a_speedup(panel):
    records, references, gold = panel
    for row in records:
        if row["method"] == "fixed_cascade":
            for attempt in row["attempts"][:-1]:
                attempt["elapsed_seconds"] = 0.0
                attempt["costs_seconds"] = {"preparation": 0.0, "execution": 0.0, "validation": 0.0}
            _fixtures.seal(row)
    report = trace_headroom.summarize_trace_headroom(records, references, gold)
    assert report["aggregate"]["optimistic_deletable_attempt_seconds"]["total_seconds"] == 0
    assert report["aggregate"]["parent_charged_seconds"] == report["aggregate"]["retained_charge_seconds"]
    assert report["counterfactual_only"] is True
    for name in ("actual_speedup_measured", "neural_benefit_measured", "neural_acquisition_cost_measured",
                 "static_baseline_competition_measured", "real_runtime_upper_bound_claimed", "held_out_evaluation"):
        assert report[name] is False
    assert any("initialization" in text for text in report["limitations"])
    assert any("Static load/cardinality" in text for text in report["limitations"])


def test_function_is_pure_and_order_of_input_records_does_not_change_report(panel):
    records, references, gold = panel
    before = deepcopy(panel)
    modules = set(sys.modules)
    report = trace_headroom.summarize_trace_headroom(records, references, gold)
    assert panel == before
    assert report == trace_headroom.summarize_trace_headroom(list(reversed(records)), list(reversed(references)), gold)
    assert not [name for name in set(sys.modules) - modules if name.split(".")[0] in ("angr", "claripy", "z3", "torch")]
    with pytest.raises(TypeError):
        trace_headroom.summarize_trace_headroom(records, references, gold, model_cost_seconds=0)


def test_original_v15_evaluator_is_called_first_without_replacing_its_checks(monkeypatch):
    class StrictValidationError(ValueError):
        pass
    calls = []
    def reject(*args):
        calls.append(args)
        raise StrictValidationError("original v15 validation rejects matrix")
    monkeypatch.setattr(cascade_evaluation, "evaluate", reject)
    with pytest.raises(StrictValidationError, match="original v15"):
        trace_headroom.summarize_trace_headroom(None, None, None)
    assert calls == [(None, None, None)]


@pytest.mark.parametrize("clock", [True, False, -0.1, math.nan, math.inf, -math.inf, "0.1"])
@pytest.mark.parametrize("field", ["elapsed", "phase", "parent"])
def test_invalid_clocks_never_supply_trace_estimates(panel, clock, field):
    records, references, gold = panel
    row = find_row(records)
    if field == "elapsed": row["attempts"][0]["elapsed_seconds"] = clock
    elif field == "phase": row["attempts"][0]["costs_seconds"]["preparation"] = clock
    else: row["parent_receipt"]["charged_seconds"] = clock
    if field != "parent": _fixtures.seal(row)
    with pytest.raises(ValueError):
        trace_headroom.summarize_trace_headroom(records, references, gold)


def test_phase_overlap_inside_old_v15_tolerance_is_still_rejected(panel):
    records, references, gold = panel
    row = find_row(records)
    row["attempts"][0]["costs_seconds"] = {"preparation": 0.04, "execution": 0.04, "validation": 0.0205}
    _fixtures.seal(row)
    assert cascade_evaluation.evaluate(records, references, gold)["interpretation_allowed"] is True
    with pytest.raises(ValueError, match="phase costs exceed"):
        trace_headroom.summarize_trace_headroom(records, references, gold)


def test_sum_of_attempt_elapsed_must_fit_parent_even_inside_v15_tolerance(panel):
    records, references, gold = panel
    row = find_row(records, query_id="scalar_span")
    row["worker_elapsed_seconds"] = 0.0996
    row["worker_costs_seconds"] = {"preparation": 0.0, "execution": 0.0, "validation": 0.0}
    _fixtures.seal(row, charged=0.0996)
    assert cascade_evaluation.evaluate(records, references, gold)["interpretation_allowed"] is True
    with pytest.raises(ValueError, match="exceed the complete parent"):
        trace_headroom.summarize_trace_headroom(records, references, gold)


def test_floating_point_roundoff_at_equal_phase_boundary_is_not_an_overlap(panel):
    records, references, gold = panel
    row = find_row(records)
    row["attempts"][0]["elapsed_seconds"] = 0.3
    row["attempts"][0]["costs_seconds"] = {"preparation": 0.1, "execution": 0.1, "validation": 0.1}
    _fixtures.seal(row)
    assert trace_headroom.summarize_trace_headroom(records, references, gold)["cascade_trials"] == 9


@pytest.mark.parametrize("change", ["wrong", "late", "nonzero", "timeout", "missing_worker_metadata",
                                    "unresolved_reference", "incomplete_cascade", "missing_trial", "duplicate_trial",
                                    "changed_hash", "changed_payload", "changed_stage_sequence"])
def test_incomplete_or_blocked_data_cannot_produce_headroom(panel, change):
    records, references, gold = panel
    row = find_row(records)
    if change == "missing_trial": records.pop()
    elif change == "duplicate_trial": records[0] = deepcopy(records[1])
    elif change == "changed_hash": row["query_hash"] = "f" * 64; _fixtures.seal(row)
    elif change == "changed_payload": row["worker_elapsed_seconds"] = 3  # No reseal.
    elif change == "changed_stage_sequence": row["attempts"][0]["operation"] = "expanded"; _fixtures.seal(row)
    elif change == "unresolved_reference":
        reference = references[0]
        reference["result"] = reference["worker_result"] = {"status": "unknown", "reason": "unresolved"}
        reference["reference"]["result"] = deepcopy(reference["result"])
        _fixtures.seal(reference)
    elif change == "wrong":
        row = find_row(records, query_id="scalar_span", method="expanded_only")
        wrong = _fixtures.result("scalar_span", status="violation")
        row["attempts"] = [_fixtures.attempt("expanded", wrong)]
        row["result"] = row["worker_result"] = deepcopy(wrong)
        _fixtures.seal(row)
    elif change == "incomplete_cascade":
        unknown = _fixtures.result("readonly_chain", status="unknown")
        row["attempts"] = [_fixtures.attempt(operation, deepcopy(unknown)) for operation in ("interval", "finite_readonly", "expanded")]
        row["result"] = row["worker_result"] = deepcopy(unknown)
        _fixtures.seal(row)
    else:
        # Failures in either control, not only selected cascade traces, must be
        # rejected before any optimistic arithmetic is reported.
        row = find_row(records, query_id="scalar_span", method="expanded_only")
        row["result"] = {"status": "unknown", "reason": "failure or late parent"}
        if change == "missing_worker_metadata":
            row.update(runtime_versions={"availability": "unavailable"}, worker_costs_seconds=None,
                       worker_elapsed_seconds=None, cost_measurement_complete=False)
        _fixtures.seal(row, charged=30.1 if change == "late" else 3,
                       late=change in ("late", "timeout"), returncode=1 if change == "nonzero" else 0,
                       timed_out=change == "timeout")
    with pytest.raises(ValueError):
        trace_headroom.summarize_trace_headroom(records, references, gold)
