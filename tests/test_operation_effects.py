"""Real operation effects on existing mechanisms; never new research cases."""

from copy import deepcopy
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import make_mechanisms
from scripts.run_operation_effects import finish_records, run_isolated
from src.selective_analysis.contracts import Checkpoint, Query
from src.selective_analysis.operation_effects import (PROBES, initial_features, missing_probe,
    prepare_direct_prefix, probe_operation, structural_first_hint)
from src.selective_analysis.operations import BinaryChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def cases():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("operation-effects-" + uuid.uuid4().hex[:12])
    manifest = make_mechanisms(folder)
    queries = [Query.from_dict(q, folder) for q in json.loads(manifest.read_text())["queries"]]
    gold = json.loads((folder / "gold.json").read_text())
    return folder, queries, {r["query_id"]: r["expected"] for r in gold["labels"]}


@pytest.fixture(scope="module")
def observations(cases):
    _, queries, _ = cases
    rows = {}
    for query in queries:
        features = initial_features(query)
        for probe in PROBES:
            rows[query.query_id, probe] = probe_operation(query, probe, 0, features, time.monotonic() + 10)
    return rows


@pytest.mark.parametrize("index", range(12))
def test_every_recorded_decision_is_validated_and_correct(cases, observations, index):
    _, queries, gold = cases
    query = queries[index]
    for probe in PROBES:
        row = observations[query.query_id, probe]
        assert row["checkpoint_id"] == Checkpoint(query.contract_hash).checkpoint_id
        assert row["cost_measurement_complete"] is True
        assert sum(row["costs_seconds"].values()) <= row["probe_elapsed_seconds"] + 1e-6
        if row["result"]["status"] != "unknown":
            assert row["result"]["status"] == gold[query.query_id]
            assert row["effects"]["query_decision_progress"] is True
            if probe != "local_bounds":
                assert row["result"]["validation_reused_prefix_steps"] == 0
        else:
            assert row["effects"]["query_decision_progress"] is False
    for full in ("expanded_paths", "definitions_then_expanded", "direct_prefix_then_expanded"):
        assert observations[query.query_id, full]["result"]["status"] == gold[query.query_id]


def test_direct_prefix_is_paid_exact_execution_and_same_total_work(cases, observations):
    _, queries, _ = cases
    query = queries[6]  # Existing long straight-line register alias.
    full, direct = (observations[query.query_id, p] for p in ("expanded_paths", "direct_prefix_then_expanded"))
    work = direct["effects"]["prefix_work"]
    assert direct["effects"]["planning_artifacts"]["backend"] == "direct_entry_prefix_without_rda"
    assert work["preparation_steps"] == work["reused_prefix_steps"] > 8
    assert work["total_executed_steps"] == full["effects"]["prefix_work"]["total_executed_steps"]
    assert direct["costs_seconds"]["preparation"] > 0


def test_dependency_graph_is_planning_not_standalone_decision(cases, observations):
    query = cases[1][0]
    row = observations[query.query_id, "definitions_then_expanded"]
    assert row["effects"]["planning_artifacts"]["definition_count"] > 0
    assert row["effects"]["planning_artifacts"]["completeness"] == "local_approximation_not_a_relevance_proof"
    assert row["result"]["validation"] == "concrete_input_modeled_reexecution"


def test_failed_dependency_preparation_retains_cost_and_full_result(cases, monkeypatch):
    def broken(*args):
        raise ValueError("unit preparation failed")
    monkeypatch.setattr(BinaryChecker, "prepare_dependencies", broken)
    query = cases[1][0]
    row = probe_operation(query, "definitions_then_expanded", 0, initial_features(query), time.monotonic() + 5)
    assert row["result"]["status"] == "violation"
    assert "unit preparation failed" in row["effects"]["planning_artifacts"]["error"]
    assert row["effects"]["prefix_work"]["measurement_complete"] is False
    assert row["costs_seconds"]["preparation"] > 0


def test_direct_preparation_never_claims_a_branching_prefix(cases):
    checker = BinaryChecker(cases[1][1])
    assert prepare_direct_prefix(checker, time.monotonic() + 5)["status"] == "not_prepared"
    assert checker._prepared_prefix is None
    with pytest.raises(TimeoutError):
        prepare_direct_prefix(BinaryChecker(cases[1][0]), time.monotonic() - 1)


def test_abstract_counts_stay_separate_from_symbolic_work(observations):
    row = observations["m06", "local_bounds"]
    assert row["result"]["status"] == "excluded_within_scope"
    assert row["effects"]["abstract_instruction_steps"] > 0
    assert row["effects"]["validation_abstract_instruction_steps"] == row["effects"]["abstract_instruction_steps"]
    assert row["effects"]["prefix_work"]["total_executed_steps"] == 0


def test_structural_hints_use_only_predeclared_inputs(cases):
    features = initial_features(cases[1][5])
    assert structural_first_hint(features) == "local_bounds"
    assert features["entry_immediate_and_masks"] == [7]
    assert structural_first_hint(initial_features(cases[1][0])) == "bounded_paths"
    assert structural_first_hint(initial_features(cases[1][6])) == "expanded_paths"
    assert structural_first_hint({"available": False}) == "expanded_paths"


def test_missing_or_late_records_preserve_denominator_and_evidence(cases, observations):
    query = cases[1][0]
    source = deepcopy(observations[query.query_id, "expanded_paths"])
    events = [{"event": "probe_finished", "query_hash": query.contract_hash, "repetition": 0, "record": source}]
    original = deepcopy(events)
    rows = finish_records(query, 0, PROBES, None, events, {"returncode": -1, "timed_out": True}, 21, 20)
    assert len(rows) == 5 and all(r["result"]["status"] == "unknown" for r in rows)
    late = next(r for r in rows if r["probe_id"] == "expanded_paths")
    assert late["late_candidate_result"]["status"] == "violation"
    assert late["effects"]["query_decision_progress"] is False
    assert events == original
    missing = missing_probe(query, "bounded_paths", 0, {"available": False}, "unstarted")
    assert missing["cost_measurement_complete"] is False


def test_real_worker_cli_emits_five_fresh_records(cases):
    folder, queries, _ = cases
    rows, receipt = run_isolated(queries[0], 0, PROBES, folder / "worker-cli", budget=10)
    assert len(rows) == receipt["record_count"] == 5
    assert all(r["result"]["status"] == ("unknown" if r["probe_id"] == "local_bounds" else "violation") for r in rows)
    assert receipt["process"]["returncode"] == 0
    assert receipt["parent_worker_seconds"] >= sum(r["probe_elapsed_seconds"] for r in rows)


def test_actual_runtime_payload_matches_offline_schema(cases, observations):
    from src.selective_analysis.operation_effects_evaluation import evaluate_effects
    # Repeated records here are fabricated only to test the three-repetition schema.
    # They are not independent timings and never enter empirical output directories.
    rows = []
    for repetition in range(3):
        for row in observations.values():
            copied = deepcopy(row)
            copied["repetition"] = repetition
            rows.append(copied)
    folder, _, _ = cases
    gold = json.loads((folder / "gold.json").read_text())
    gold["panel"] = "primary_existing_12_mechanisms"
    result = evaluate_effects(rows, gold)
    assert result["correctness_review"]["required"] is False
