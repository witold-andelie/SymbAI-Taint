"""Operand identities and real program relations; fabricated candidates are unit fixtures only."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.operand_mapping import (
    CLAIMS, make_probe_plan, operand_id, verify_operand_plan, validate_operand_evidence,
    operand_program_facts, map_operand_candidates, load_operand_views)
from src.selective_analysis.types import TypeInformationUnavailable, load_type_view

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("operands-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


@pytest.fixture(scope="module")
def case():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("operand-case-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    code = Code()
    code.emit("55 48 89 e5 48 89 7d e8")  # Push RBP; frame; index at CFA-40.
    code.lea()
    code.emit("48 89 45 f8 48 8b 55 f8 48 8b 45 e8 48 01 d0")  # Base at CFA-24; address=base+index.
    code.write_offset = len(code.data)
    code.emit("c6 00 41 c3")
    binary = folder / "unit-operands.elf"
    binary.write_bytes(elf_bytes(code.finish()))
    query = Query("unit-operands", str(binary), file_hash(binary), TEXT - BASE,
                  TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", 0, 15),))
    entries, records = [], []
    for role, offset, prediction, labels in (("base_pointer", -24, "base-fixture", ("char*", "void*")),
                                              ("index", -40, "index-fixture", ("u64", "i64"))):
        location = {"low_pc": TEXT, "high_pc": TEXT + len(code.data), "location_class": "CfaLocation",
                    "location_register": None, "location_argument": offset}
        entries.append({"role": role, "operand_id": operand_id(query, role), "prediction_id": prediction,
            "expected_identity": {"function_address": TEXT, "locations": [location]},
            "storage": {"kind": "cfa_relative", "cfa_offset": offset, "size_bytes": 8},
            "anchor": {"kind": "object_base"} if role == "base_pointer" else {"kind": "entry_input", "register": "rdi"},
            "reviewed_by": "unit fixture only", "evidence": "Explicit machine bytes; synthetic candidates are not model evidence."})
        records.append({"prediction_id": prediction, "function_address": TEXT, "locations": [location],
            "score_kind": "raw_logits", "candidates": [
                {"label": labels[0], "rank": 1, "raw_score": 2.0 if role == "base_pointer" else 0.4},
                {"label": labels[1], "rank": 2, "raw_score": 1.0 if role == "base_pointer" else 0.3}]})
    plan = {"schema": "symbai.operand_plan.v1", "query_hash": query.contract_hash,
        "binary_sha256": query.binary_sha256, "use_site_id": query.use_site_id, "address_space": "elf_linked_vaddr",
        "relation": "base_plus_index", "index_scale": 1, "write_length_bytes": 1,
        "cfa_rule": "entry_rsp_plus_8", "operands": entries, "review_source_sha256": "0" * 64}
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256, "acquisition_id": "fixture-only",
        "provenance": {"source": "tygr_glowgnn", "model_sha256": "f" * 64, "decoder": "independent",
                       "ground_truth_labels_supplied_to_model": False}, "records": records}
    first = verify_operand_plan(query, plan, time.monotonic() + 5)
    assert first["status"] == "verified", first
    checked = validate_operand_evidence(query, plan, first, time.monotonic() + 5)
    return query, raw, plan, first, checked


def write_bundle(tmp_path, query, raw, plan, checked):
    path = tmp_path / "operand-types.json"
    path.write_text(json.dumps(map_operand_candidates(query, raw, plan, checked)), encoding="utf-8")
    return path


def test_independent_operand_views_preserve_scores_and_hide_top1_uncertainty(case, tmp_path):
    query, raw, plan, first, checked = case
    assert all(first["checks"][name] is True for name in CLAIMS)
    assert checked["validation"] == "fresh_symbolic_recheck" and checked["verification_passes"] == 2
    path = write_bundle(tmp_path, query, raw, plan, checked)
    c, d = load_operand_views(path, query, "C"), load_operand_views(path, query, "D")
    assert [v.role for v in c] == ["base_pointer", "index"]
    assert len({v.operand_id for v in c}) == 2 and len({v.prediction_id for v in c}) == 2
    assert c[0].view.labels == ("char*",) and c[1].view.labels == ("u64",)
    assert all(not v.view.raw_scores and not v.view.weights for v in c)
    assert d[0].view.raw_scores == (2.0, 1.0) and d[1].view.raw_scores == (0.4, 0.3)
    assert all(sum(v.view.weights) == pytest.approx(1) for v in d)
    assert d[0].view.weights != d[1].view.weights
    assert json.loads(path.read_text())["raw_export"] == raw


def test_legacy_loader_cannot_silently_treat_a_bundle_as_one_variable(case, tmp_path):
    query, raw, plan, _, checked = case
    path = write_bundle(tmp_path, query, raw, plan, checked)
    with pytest.raises(TypeInformationUnavailable, match="schema"):
        load_type_view(path, query, "C")
    assert load_operand_views(tmp_path / "absent", query, "A") == ()
    assert load_operand_views(tmp_path / "absent", query, "B") == ()


def test_common_program_facts_expose_roles_but_no_neural_candidates(case):
    query, _, plan, _, checked = case
    facts = operand_program_facts(query, plan, checked)
    assert [e["role"] for e in facts["operands"]] == ["base_pointer", "index"]
    assert facts["relation"] == "base_plus_index" and facts["write_length_bytes"] == 1
    assert all(set(e) == {"role", "operand_id", "storage", "anchor"} for e in facts["operands"])
    assert all("prediction_id" not in e for e in facts["operands"])
    # A caller cannot mutate the validated plan through this shared-facts export.
    facts["operands"][0]["storage"]["cfa_offset"] = -40
    assert plan["operands"][0]["storage"]["cfa_offset"] == -24


def test_swapped_physical_slots_are_rejected_by_program_evidence(case):
    query, _, plan, _, _ = case
    wrong = deepcopy(plan)
    left, right = wrong["operands"]
    left["storage"], right["storage"] = right["storage"], left["storage"]
    left["expected_identity"], right["expected_identity"] = right["expected_identity"], left["expected_identity"]
    result = verify_operand_plan(query, wrong, time.monotonic() + 5)
    assert result["status"] == "rejected"
    assert result["checks"]["base_slot_equals_object_base"] is False


@pytest.mark.parametrize("change", ("duplicate_role", "duplicate_prediction", "missing_role", "candidate_in_plan"))
def test_malformed_or_score_bearing_plans_cannot_enter_the_verifier(case, change):
    query, _, plan, _, _ = case
    bad = deepcopy(plan)
    if change == "duplicate_role":
        bad["operands"][1]["role"] = "base_pointer"
    elif change == "duplicate_prediction":
        bad["operands"][1]["prediction_id"] = bad["operands"][0]["prediction_id"]
    elif change == "missing_role":
        bad["operands"].pop()
    else:
        bad["operands"][0]["candidate_type"] = "char*"
    with pytest.raises(ValueError):
        verify_operand_plan(query, bad, time.monotonic() + 5)


@pytest.mark.parametrize("change", ("range", "function", "duplicate_raw", "binary"))
def test_raw_locator_and_binary_must_match_verified_plan(case, change):
    query, raw, plan, _, checked = case
    wrong = deepcopy(raw)
    if change == "range":
        wrong["records"][1]["locations"][0]["low_pc"] += 1
    elif change == "function":
        wrong["records"][1]["function_address"] += 1
    elif change == "duplicate_raw":
        wrong["records"].append(deepcopy(wrong["records"][0]))
    else:
        wrong["binary_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        map_operand_candidates(query, wrong, plan, checked)


@pytest.mark.parametrize("change", ("partial", "not_rechecked", "trace", "other_query"))
def test_partial_stale_or_tampered_evidence_cannot_bind_predictions(case, change):
    query, raw, plan, first, checked = case
    wrong = deepcopy(checked)
    if change == "partial":
        del wrong["checks"]["write_length_equals_one"]
    elif change == "not_rechecked":
        wrong = deepcopy(first)
    elif change == "trace":
        wrong["prefix_trace"][0]["bytes"] = "90"
    else:
        wrong["query_hash"] = "other"
    with pytest.raises(ValueError):
        map_operand_candidates(query, raw, plan, wrong)


@pytest.mark.parametrize("change", ("missing_index", "mixed_predictions"))
def test_bundle_loader_rejects_role_loss_even_after_outer_hash_update(case, tmp_path, change):
    query, raw, plan, _, checked = case
    bundle = map_operand_candidates(query, raw, plan, checked)
    if change == "missing_index":
        bundle["bindings"].pop()
    else:
        bundle["bindings"][1]["prediction_id"] = bundle["bindings"][0]["prediction_id"]
        bundle["bindings"][1]["raw_record_fingerprint"] = bundle["bindings"][0]["raw_record_fingerprint"]
    bundle["bundle_fingerprint"] = fingerprint({k: v for k, v in bundle.items() if k != "bundle_fingerprint"})
    path = tmp_path / "bad-bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(TypeInformationUnavailable, match="bindings"):
        load_operand_views(path, query, "D")


def test_deadline_work_limit_and_changed_binary_remain_unverified(case, tmp_path):
    query, _, plan, _, _ = case
    expired = verify_operand_plan(query, plan, time.monotonic() - 1)
    limited = verify_operand_plan(query, plan, time.monotonic() + 5, max_steps=1)
    assert expired["status"] == limited["status"] == "unknown"
    with pytest.raises(ValueError, match="verified"):
        validate_operand_evidence(query, plan, expired, time.monotonic() + 5)
    altered = tmp_path / "changed.elf"
    altered.write_bytes(Path(query.binary).read_bytes() + b"changed")
    same_contract_new_path = replace(query, binary=str(altered))
    assert same_contract_new_path.contract_hash == query.contract_hash
    result = verify_operand_plan(same_contract_new_path, plan, time.monotonic() + 5)
    assert result["status"] == "unknown" and "binary differs" in result["reason"]


def test_probe_proposal_uses_only_physical_metadata_not_names_or_candidates():
    query = Query("compiled-direct-index", "not_loaded_by_factory", "0fb55db6be585f4c71134f6a9483828292f5a73f529420bc21a753a62a7c81a5",
                  0x1129, 0x114b, 0x4018, 8, (InputRange("rdi", 0, 15),))
    raw = {"records": []}
    for offset, prediction in ((-40, "index-id"), (-24, "base-id")):
        raw["records"].append({"prediction_id": prediction, "function_address": 0x1129,
            "locator_variable_name": "misleading-name", "candidates": [{"label": "wrong-test-type"}],
            "locations": [{"low_pc": 0x1129, "high_pc": 0x1151, "location_class": "CfaLocation",
                           "location_register": None, "location_argument": offset}]})
    first = make_probe_plan(query, raw, "0" * 64)
    for record in raw["records"]:
        record["locator_variable_name"] = "another-name"
        record["candidates"] = [{"label": "another-type", "raw_score": 99.0}]
    assert make_probe_plan(query, raw, "0" * 64) == first
    assert [e["prediction_id"] for e in first["operands"]] == ["base-id", "index-id"]
