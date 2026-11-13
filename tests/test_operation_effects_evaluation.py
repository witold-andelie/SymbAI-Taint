"""Fabricated evaluator fixtures only: these rows are not experimental evidence."""

from copy import deepcopy
import json
from pathlib import Path
import uuid

import pytest

from src.selective_analysis.contracts import Checkpoint
from src.selective_analysis.operation_effects_evaluation import (
    PANEL, PROBES, evaluate_effects,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    """Keep even pure-evaluator serialization checks on the repository's D: drive."""
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("effects-evaluation-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


@pytest.fixture
def fabricated_panel():
    """Twelve named synthetic records, never results from executing the mechanisms."""
    gold = {"schema": "symbai.gold.v1", "panel": PANEL, "labels": []}
    rows = []
    for number in range(1, 13):
        query_id = f"m{number:02d}"
        binary_sha256 = f"{number:064x}"
        query_hash = f"{100 + number:064x}"
        expected = "excluded_within_scope"
        gold["labels"].append({"query_id": query_id, "binary_sha256": binary_sha256, "expected": expected})
        for probe in PROBES:
            for repetition in range(3):
                work = {"preparation_steps": 0, "execution_steps": 4, "validation_steps": 4,
                        "total_executed_steps": 8, "reused_prefix_steps": 0,
                        "measurement_complete": True}
                effects = {"query_decision_progress": True, "planning_artifacts": {}, "prefix_work": work}
                result = {"status": expected, "validation": "fresh_state_complete_scope_recheck",
                          "validation_reused_prefix_steps": 0}
                if probe == "local_bounds":
                    work.update({key: 0 for key in work if key != "measurement_complete"})
                    effects.update(abstract_instruction_steps=7, validation_abstract_instruction_steps=7)
                    result = {"status": expected, "validation": "fresh_byte_decoded_abstract_recheck"}
                if probe in ("definitions_then_expanded", "direct_prefix_then_expanded"):
                    work.update(preparation_steps=4, execution_steps=0, reused_prefix_steps=4)
                    effects["planning_artifacts"] = {"graph_nodes": 100, "snapshots": 5}
                elapsed = {"bounded_paths": 1.0, "expanded_paths": 3.0,
                           "definitions_then_expanded": 4.0, "direct_prefix_then_expanded": 2.0,
                           "local_bounds": 0.5}[probe] + 0.01 * repetition
                rows.append({
                    "schema": "symbai.operation_effect_trial.v1", "query_id": query_id,
                    "query_hash": query_hash, "binary_sha256": binary_sha256,
                    "checkpoint_id": Checkpoint(query_hash).checkpoint_id,
                    "repetition": repetition, "probe_id": probe, "result": result,
                    "effects": effects, "initial_features": {"available": True, "entry_instruction_count": 5},
                    "costs_seconds": {"setup": 0.1, "preparation": 0.1, "execution": 0.1,
                                      "validation": 0.1, "recording": 0.01},
                    "probe_elapsed_seconds": elapsed, "cost_measurement_complete": True,
                    "availability": "available", "fixture_provenance": "fabricated_unit_test_only",
                })
    return rows, gold


def select(rows, query="m01", probe="bounded_paths", repetition=None):
    return [row for row in rows if row["query_id"] == query and row["probe_id"] == probe
            and (repetition is None or row["repetition"] == repetition)]


def make_unknown(row, reason):
    row["result"] = {"status": "unknown", "reason": reason, "validation": "no_decisive_evidence"}
    row["effects"]["query_decision_progress"] = False


def test_complete_panel_counts_costs_and_descriptive_separations(fabricated_panel, tmp_path):
    rows, gold = fabricated_panel
    before = deepcopy((rows, gold))
    report = evaluate_effects(iter(rows), gold)
    assert (rows, gold) == before
    assert report["trials_count"] == 180 and report["queries_count"] == 12
    for probe in PROBES:
        summary = report["probes"][probe]
        assert summary["trial_counts"] == {"total": 36, "resolved": 36, "correct": 36, "wrong": 0, "unknown": 0}
        assert summary["unique_query_counts"] == {"total": 12, "resolved": 12, "correct": 12, "wrong": 0, "unknown": 0}
        assert summary["stable_query_counts"] == summary["unique_query_counts"]
        assert summary["cost_observation_count"] == 36
    bounded = report["queries"][0]["probes"]["bounded_paths"]
    assert bounded["stable_correct"]
    assert bounded["probe_elapsed_seconds"] == {"min": 1.0, "max": 1.02, "median": 1.01}
    assert report["probes"]["bounded_paths"]["median_probe_elapsed_seconds"] == 1.01
    comparisons = report["comparisons"]
    assert comparisons["bounded_vs_expanded"]["same_work_pairs"] == 36
    assert all(pair["interpretation"] == "cap_redundancy_not_speed_evidence"
               for pair in comparisons["bounded_vs_expanded"]["shared_decisive_pairs"])
    assert len(comparisons["composites_vs_expanded"]["definitions_then_expanded"]) == 36
    composite = comparisons["composites_vs_expanded"]["definitions_then_expanded"][0]
    assert composite["left_prefix_work"]["total_executed_steps"] == 8
    assert composite["left_prefix_work"]["preparation_steps"] == 4
    assert composite["left_prefix_work"]["execution_steps"] == 0
    assert composite["left_probe_elapsed_seconds"] == 4.0
    cheaper = comparisons["cheaper_alternatives"]
    assert len(cheaper["pairs"]) == 36
    assert {pair["probe_id"] for pair in cheaper["pairs"]} == {
        "bounded_paths", "direct_prefix_then_expanded", "local_bounds"}
    assert cheaper["label"] == "empirical_separation_not_statistical_significance"
    assert report["interpretation"]["status"] == "descriptive_operation_effects_only"
    output = tmp_path / "fabricated-evaluation.json"
    output.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
    assert json.loads(output.read_text(encoding="utf-8"))["trials_count"] == 180


def test_unknown_categories_and_unstable_correctness_preserve_denominator(fabricated_panel):
    rows, gold = fabricated_panel
    for query, reason in (("m01", "unsupported_instruction:call"),
                          ("m02", "interval_precision_insufficient"),
                          ("m03", "instruction_step_limit"),
                          ("m04", "worker_deadline_exceeded")):
        for row in select(rows, query):
            make_unknown(row, reason)
    make_unknown(select(rows, "m05", repetition=1)[0], "incomplete_exploration")
    report = evaluate_effects(rows, gold)
    bounded = report["probes"]["bounded_paths"]
    assert bounded["trial_counts"] == {"total": 36, "resolved": 23, "correct": 23, "wrong": 0, "unknown": 13}
    assert bounded["unknown_categories"] == {
        "unsupported": 3, "insufficient_precision": 4, "work_limit": 3, "deadline_or_failure": 3}
    assert bounded["unique_query_counts"]["correct"] == 8
    assert bounded["unique_query_counts"]["unknown"] == 5
    assert bounded["stable_query_counts"]["correct"] == 7
    assert bounded["stable_query_counts"]["unknown"] == 4
    assert bounded["unstable_queries"] == 1
    assert not any(pair["query_id"] == "m05" and pair["probe_id"] == "bounded_paths"
                   for pair in report["comparisons"]["cheaper_alternatives"]["pairs"])
    assert report["queries"][4]["probes"]["bounded_paths"]["stable_status"] is None


@pytest.mark.parametrize("reason, category", [
    ("memory_read_outside_subset", "unsupported"),
    ("UnsupportedBounds: instruction_decode_failed", "unsupported"),
    ("write_interval_not_proved_inside_object", "insufficient_precision"),
    ("cycle_without_termination_proof", "insufficient_precision"),
    ("abstract_instruction_limit", "work_limit"),
    ("ValueError: witness validation failed", "deadline_or_failure"),
])
def test_runtime_unknown_reasons_keep_unsupported_separate_from_precision(fabricated_panel, reason, category):
    rows, gold = fabricated_panel
    row = select(rows, probe="local_bounds", repetition=0)[0]
    make_unknown(row, reason)
    row["effects"]["planning_artifacts"] = {"graph_nodes": 100000, "snapshots": 100000}
    report = evaluate_effects(rows, gold)
    assert report["probes"]["local_bounds"]["unknown_categories"][category] == 1
    assert report["probes"]["local_bounds"]["trial_counts"]["correct"] == 35


def test_wrong_validated_answers_remain_counted_and_block_interpretation(fabricated_panel):
    rows, gold = fabricated_panel
    for row in select(rows, probe="expanded_paths"):
        row["result"].update(status="violation", validation="concrete_input_modeled_reexecution")
    report = evaluate_effects(rows, gold)
    assert report["probes"]["expanded_paths"]["trial_counts"]["wrong"] == 3
    assert report["probes"]["expanded_paths"]["stable_query_counts"]["wrong"] == 1
    assert report["correctness_review"]["required"]
    assert len(report["correctness_review"]["wrong_validated_trials"]) == 3
    assert report["correctness_review"]["disagreeing_decisive_statuses"] == [
        {"query_id": "m01", "decisive_statuses": ["excluded_within_scope", "violation"]}]
    assert report["interpretation"]["status"] == "blocked_for_correctness_review"
    assert report["comparisons"]["cheaper_alternatives"]["interpretation_blocked"]


def test_wrong_unanimous_decisions_also_require_review(fabricated_panel):
    rows, gold = fabricated_panel
    gold["labels"][0]["expected"] = "violation"
    report = evaluate_effects(rows, gold)
    assert len(report["correctness_review"]["wrong_validated_trials"]) == 15
    assert report["correctness_review"]["disagreeing_decisive_statuses"] == []
    assert report["correctness_review"]["required"]


def test_missing_features_are_reported_and_available_capture_still_matches(fabricated_panel):
    rows, gold = fabricated_panel
    rows[0]["initial_features"] = {"available": False, "reason": "capture_failed"}
    rows[1]["initial_features"] = {"available": False, "reason": "not_started"}
    report = evaluate_effects(rows, gold)
    assert report["trials_count"] == 180
    assert report["queries"][0]["missing_initial_features_trials"] == 2
    assert report["probes"]["bounded_paths"]["missing_initial_features_trials"] == 2
    select(rows, probe="expanded_paths", repetition=2)[0]["initial_features"]["entry_instruction_count"] = 6
    with pytest.raises(ValueError, match="Available initial features"):
        evaluate_effects(rows, gold)


def test_incomplete_cost_and_work_do_not_become_free_measurements(fabricated_panel):
    rows, gold = fabricated_panel
    for row in select(rows):
        make_unknown(row, "worker_timeout")
        row["availability"] = "not_completed"
        row["cost_measurement_complete"] = False
        row["costs_seconds"] = dict.fromkeys(row["costs_seconds"], 0.0)
        row["probe_elapsed_seconds"] = 0.0
        row["effects"]["prefix_work"].update(
            dict.fromkeys(("preparation_steps", "execution_steps", "validation_steps",
                           "total_executed_steps", "reused_prefix_steps"), 0))
        row["effects"]["prefix_work"]["measurement_complete"] = False
    composite = select(rows, probe="definitions_then_expanded", repetition=0)[0]
    composite["effects"]["prefix_work"]["measurement_complete"] = False
    report = evaluate_effects(rows, gold)
    bounded = report["probes"]["bounded_paths"]
    assert bounded["cost_observation_count"] == 33
    assert bounded["median_probe_elapsed_seconds"] == 1.01
    query = report["queries"][0]["probes"]["bounded_paths"]
    assert query["cost_observation_count"] == 0
    assert query["probe_elapsed_seconds"] is None
    assert all(value is None for value in query["prefix_work"].values())
    pair = report["comparisons"]["composites_vs_expanded"]["definitions_then_expanded"][0]
    assert not pair["work_measurement_complete"]
    assert pair["left_prefix_work"] is None and pair["total_executed_steps_delta"] is None


def test_cost_separation_requires_all_three_complete_costs_and_strict_gap(fabricated_panel):
    rows, gold = fabricated_panel
    select(rows, repetition=2)[0]["probe_elapsed_seconds"] = 3.0
    select(rows, "m02", repetition=1)[0]["cost_measurement_complete"] = False
    report = evaluate_effects(rows, gold)
    alternatives = report["comparisons"]["cheaper_alternatives"]["pairs"]
    assert not any(pair["query_id"] in ("m01", "m02") and pair["probe_id"] == "bounded_paths"
                   for pair in alternatives)
    assert report["queries"][1]["probes"]["bounded_paths"]["cost_observation_count"] == 2


def test_local_abstract_work_is_not_compared_as_symbolic_work(fabricated_panel):
    rows, gold = fabricated_panel
    report = evaluate_effects(rows, gold)
    local = report["queries"][0]["probes"]["local_bounds"]
    assert local["prefix_work"]["total_executed_steps"]["max"] == 0
    assert local["abstract_work"]["abstract_instruction_steps"]["median"] == 7
    rows[-1]["effects"]["prefix_work"].update(execution_steps=7, total_executed_steps=7)
    with pytest.raises(ValueError, match="abstract work"):
        evaluate_effects(rows, gold)


@pytest.mark.parametrize("alteration, message", [
    ("missing_trial", "coverage"), ("duplicate_trial", "Duplicate query"),
    ("unknown_query", "Unmatched"), ("wrong_binary", "Unmatched"),
    ("unknown_probe", "probe_id"), ("bad_rep", "repetition"), ("bool_rep", "repetition"),
    ("wrong_checkpoint", "fresh-entry"), ("changed_hash", "fresh checkpoint"),
    ("unvalidated", "fresh validation"), ("reused_validation", "without prefix reuse"),
    ("unknown_progress", "query_decision_progress"), ("no_progress", "query_decision_progress"),
    ("gold_in_row", "offline gold"), ("neural_features", "type-blind"),
    ("bad_total_work", "must sum"), ("negative_steps", "nonnegative integer"),
    ("bool_steps", "nonnegative integer"), ("bad_abstract_steps", "nonnegative integer"),
    ("unfinished_costs", "cost measurement incomplete"),
])
def test_malformed_trials_rejected(fabricated_panel, alteration, message):
    rows, gold = fabricated_panel
    row = rows[0]
    if alteration == "missing_trial":
        rows.pop()
    elif alteration == "duplicate_trial":
        rows.append(deepcopy(row))
    elif alteration == "unknown_query":
        row["query_id"] = "compiled_case"
    elif alteration == "wrong_binary":
        row["binary_sha256"] = "f" * 64
    elif alteration == "unknown_probe":
        row["probe_id"] = "learned_selector"
    elif alteration == "bad_rep":
        row["repetition"] = 3
    elif alteration == "bool_rep":
        row["repetition"] = True
    elif alteration == "wrong_checkpoint":
        row["checkpoint_id"] = Checkpoint(row["query_hash"], ("definitions",)).checkpoint_id
    elif alteration == "changed_hash":
        row["query_hash"] = "d" * 64
        row["checkpoint_id"] = Checkpoint(row["query_hash"]).checkpoint_id
    elif alteration == "unvalidated":
        row["result"]["validation"] = "graph_nodes_observed"
    elif alteration == "reused_validation":
        row["result"]["validation_reused_prefix_steps"] = 4
    elif alteration == "unknown_progress":
        row["result"] = {"status": "unknown", "reason": "planning_artifacts_only"}
    elif alteration == "no_progress":
        row["effects"]["query_decision_progress"] = False
    elif alteration == "gold_in_row":
        row["result"]["expected"] = "excluded_within_scope"
    elif alteration == "neural_features":
        row["initial_features"]["type_features"] = {"types": ["int"]}
    elif alteration == "bad_total_work":
        row["effects"]["prefix_work"]["total_executed_steps"] = 4
    elif alteration in ("negative_steps", "bool_steps"):
        row["effects"]["prefix_work"]["preparation_steps"] = -1 if alteration == "negative_steps" else True
    elif alteration == "bad_abstract_steps":
        rows[-1]["effects"]["abstract_instruction_steps"] = 0.5
    elif alteration == "unfinished_costs":
        row["availability"] = "not_completed"
    with pytest.raises(ValueError, match=message):
        evaluate_effects(rows, gold)


@pytest.mark.parametrize("field", ("setup", "preparation", "execution", "validation", "recording", "elapsed"))
@pytest.mark.parametrize("value", (-0.1, float("nan"), float("inf"), True, "0.1", None))
def test_malformed_timings_rejected(fabricated_panel, field, value):
    rows, gold = fabricated_panel
    if field == "elapsed":
        rows[0]["probe_elapsed_seconds"] = value
    else:
        rows[0]["costs_seconds"][field] = value
    with pytest.raises(ValueError, match="finite nonnegative"):
        evaluate_effects(rows, gold)


@pytest.mark.parametrize("alteration", ("missing_panel", "compiled_panel", "extra_label", "missing_label",
                                       "duplicate_label", "unknown_label", "nondecisive_label", "bad_schema"))
def test_panel_cannot_pool_compiled_audit_or_change_denominator(fabricated_panel, alteration):
    rows, gold = fabricated_panel
    if alteration == "missing_panel":
        gold.pop("panel")
    elif alteration == "compiled_panel":
        gold["panel"] = "compiled_mapping_proof_audit"
    elif alteration == "extra_label":
        gold["labels"].append({"query_id": "compiled_case", "binary_sha256": "a" * 64, "expected": "violation"})
    elif alteration == "missing_label":
        gold["labels"].pop()
    elif alteration == "duplicate_label":
        gold["labels"][-1] = deepcopy(gold["labels"][0])
    elif alteration == "unknown_label":
        gold["labels"][0]["query_id"] = "new_mechanism"
    elif alteration == "nondecisive_label":
        gold["labels"][0]["expected"] = "unknown"
    elif alteration == "bad_schema":
        gold["schema"] = "another.gold.v1"
    with pytest.raises(ValueError):
        evaluate_effects(rows, gold)
