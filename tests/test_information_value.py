"""Diagnostic isolation checks. Fabricated type fixtures are never empirical model evidence."""

import importlib.util
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import make_mechanisms
from src.selective_analysis.contracts import Query, file_hash
from src.selective_analysis.information_value import choose_operation, run_information_query
from src.selective_analysis.types import TypeView

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("information-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


@pytest.fixture(scope="module")
def safe_query():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("information-cases-" + uuid.uuid4().hex[:12])
    manifest = make_mechanisms(path)
    return Query.from_dict(json.loads(manifest.read_text())["queries"][1], manifest.parent)


def controlled_inputs(path, query):
    """A structurally valid raw/mapping fixture, not output from real trained weights."""
    script = load_script("run_information_value")
    mapper = load_script("map_tygr_candidates")
    location = {"low_pc": query.entry_rva, "high_pc": query.write_rva + 8,
                "location_class": "CfaLocation", "location_register": None, "location_argument": -24}
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256, "acquisition_id": "controlled-test",
           "provenance": {"source": "tygr_glowgnn", "model_sha256": script.MODEL_HASH,
                          "decoder": "independent", "ground_truth_labels_supplied_to_model": False},
           "records": [{"prediction_id": "fixture", "function_address": query.entry_rva, "locations": [location],
                        "score_kind": "raw_logits", "candidates": [
                            {"label": "f32", "rank": 1, "raw_score": 2.0},
                            {"label": "struct*", "rank": 2, "raw_score": 1.0}]}]}
    mapping = {"mappings": [{"prediction_id": "fixture", "use_site_id": query.use_site_id,
        "reviewed_by": "controlled fixture only", "evidence": "no empirical correspondence is claimed",
        "expected_identity": {"function_address": query.entry_rva, "locations": [location]}}]}
    raw_path, types_path, review_path = (path / name for name in ("raw.json", "mapped.json", "review.json"))
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    review_path.write_text(json.dumps(mapping), encoding="utf-8")
    mapped = mapper.map_candidates(raw, [query], mapping)
    mapped.update(raw_artifact_sha256=file_hash(raw_path), acquisition_id=raw["acquisition_id"])
    types_path.write_text(json.dumps(mapped), encoding="utf-8")
    receipt = {"model_sha256": script.MODEL_HASH, "acquisition_id": raw["acquisition_id"],
               "raw_artifact_sha256": file_hash(raw_path), "mapped_artifact_sha256": file_hash(types_path)}
    return raw_path, types_path, review_path, receipt


def test_frozen_input_gate_requires_raw_remapping_even_when_receipt_hash_is_updated(tmp_path, safe_query):
    script = load_script("run_information_value")
    raw, mapped, review, receipt = controlled_inputs(tmp_path, safe_query)
    assert script.validate_frozen_inputs(safe_query, raw, mapped, review, receipt)["reviewed_use_sites"] == 1
    data = json.loads(mapped.read_text())
    data["records"][0]["candidates"][0]["raw_score"] = 0.9
    mapped.write_text(json.dumps(data), encoding="utf-8")
    receipt["mapped_artifact_sha256"] = file_hash(mapped)
    with pytest.raises(ValueError, match="remapping"):
        script.validate_frozen_inputs(safe_query, raw, mapped, review, receipt)


def test_frozen_input_gate_rejects_a_different_acquisition(tmp_path, safe_query):
    script = load_script("run_information_value")
    raw, mapped, review, receipt = controlled_inputs(tmp_path, safe_query)
    receipt["acquisition_id"] = "another-acquisition"
    with pytest.raises(ValueError, match="identities"):
        script.validate_frozen_inputs(safe_query, raw, mapped, review, receipt)


def test_type_views_cannot_change_symbolic_facts_or_common_initialization(tmp_path, safe_query):
    _, types, _, _ = controlled_inputs(tmp_path, safe_query)
    rows = [run_information_query(safe_query, method, 5, types) for method in ("info_B", "info_C", "info_D")]
    assert len({row["policy_hash"] for row in rows}) == 1
    assert all(row["result"]["status"] == "excluded_within_scope" for row in rows)
    assert all(row["result"]["validation"] == "fresh_state_complete_scope_recheck" for row in rows)
    starts = [next(e for e in row["ledger"] if e["event"] == "information_budget_started") for row in rows]
    assert all(e["initial_checkpoint"] == starts[0]["initial_checkpoint"] for e in starts)
    assert all(e["structural_features"] == starts[0]["structural_features"] for e in starts)
    assert all(e["common_checkers"] == ["symbolic", "local_bounds"] and e["initial_prefix_cache"] == "empty" for e in starts)
    features = [next(e for e in row["ledger"] if e["event"] == "action_selected")["type_features"] for row in rows]
    assert not features[0]["available"] and not features[1]["raw_scores"] and features[2]["raw_scores"]
    assert all(not any(e["event"] == "type_export_started" for e in row["ledger"]) for row in rows)
    assert all(sum(row["costs_seconds"].values()) <= row["elapsed_wall_seconds"] + 0.001 for row in rows)


@pytest.mark.parametrize("method", ("info_B", "info_expanded_only", "info_bounds_then_expanded"))
def test_no_type_methods_do_not_read_candidate_files(method, tmp_path, safe_query):
    unreadable_types = tmp_path / "invalid-types.json"
    unreadable_types.write_text("not JSON", encoding="utf-8")
    row = run_information_query(safe_query, method, 5, unreadable_types)
    assert row["result"]["status"] == "excluded_within_scope"
    assert row["type_identity"] == {}
    if method == "info_bounds_then_expanded":
        assert row["result"]["validation"] == "fresh_byte_decoded_abstract_recheck"
    else:
        assert row["result"]["validation"] == "fresh_state_complete_scope_recheck"


def test_synthetic_types_and_late_selection_remain_unknown(tmp_path, safe_query, monkeypatch):
    from src.selective_analysis import information_value
    path = tmp_path / "synthetic.json"
    path.write_text(json.dumps({"schema": "symbai.mapped_types.v1", "provenance": {"source": "synthetic_test"}}), encoding="utf-8")
    row = run_information_query(safe_query, "info_C", 1, path)
    assert row["availability"] == "type_information_unavailable" and row["result"]["status"] == "unknown"
    assert not any(e["event"] == "action_selected" for e in row["ledger"])
    original = information_value.choose_operation
    def delayed(*args):
        time.sleep(0.04)
        return original(*args)
    monkeypatch.setattr(information_value, "choose_operation", delayed)
    row = run_information_query(safe_query, "info_B", 0.02)
    assert row["result"]["status"] == "unknown"
    assert "budget" in row["result"]["reason"].lower()


def test_fixed_information_control_rejects_type_features(safe_query):
    from src.selective_analysis.contracts import Checkpoint
    with pytest.raises(ValueError, match="no type"):
        choose_operation("info_expanded_only", Checkpoint(safe_query.contract_hash), TypeView(("char*",)), {})


def test_information_worker_keeps_preparation_outside_information_budget(tmp_path, safe_query):
    script = load_script("run_selective_pilot")
    # This is an accounting integration test, not a subsecond latency guarantee.
    # Keep finalization charged, with enough budget for a slower Windows filesystem.
    row = script.run_isolated(safe_query, "info_B", 5, "information_only", tmp_path)
    assert row["result"]["status"] == "excluded_within_scope"
    assert row["regime"] == "information_only"
    assert row["accounting_unit"] == "prepared_single_query_information_budget"
    assert row["process_wall_seconds"] > row["charged_seconds"]
    prepared = next(e for e in row["ledger"] if e["event"] == "information_budget_started")
    assert prepared["preparation_charged"] is False
    assert "online_inference" in row["excluded_costs"]
