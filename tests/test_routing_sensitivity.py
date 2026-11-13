"""Fabricated routing unit inputs; no retained exports or property executions."""

from copy import deepcopy
from dataclasses import replace
import math
from pathlib import Path
import sys
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, DATA, TEXT, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis import routing_sensitivity as routing
from src.selective_analysis.types import TypeView, project_type_candidates


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def make_query():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("routing-unit-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)

    def make(mask=False, extra="", query_id="unit-routing", name="unit.elf"):
        code = Code()
        code.emit("55 48 89 e5 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + ("48 83 65 e8 07 " if mask else "") + extra)
        code.emit("48 8b 55 f8 48 8b 45 e8 48 01 d0")
        code.write_offset = len(code.data)
        code.emit("c6 00 41 c3")
        path = folder / name
        path.write_bytes(elf_bytes(code.finish()))
        return Query(query_id, str(path), file_hash(path), TEXT - BASE,
                     TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", 0, 15),))

    return make


def features(mask=False, available=True):
    return {"schema": "symbai.routing_features.v1", "query_hash": "a" * 64, "binary_sha256": "b" * 64,
            "available": available, "reason": None if available else "unsupported_instruction:jmp",
            "instruction_count": 10, "address_load_count": 2 if available else None,
            "has_immediate_mask": mask if available else None}


def dview(labels, logits):
    return project_type_candidates([{"label": label, "rank": index + 1, "raw_score": score}
                                    for index, (label, score) in enumerate(zip(labels, logits))],
                                   "raw_logits", "D", "tygr_glowgnn", "c" * 64, "d" * 64)


def cviews():
    return {"load-pointer": TypeView(("i64 *",)), "load-integer": TypeView(("i64",))}


def dviews(logit=math.log(3)):
    return {"load-pointer": dview(("i64 *", "float", "struct x"), (logit, 0, 0)),
            "load-integer": dview(("i64", "float", "struct x"), (logit, 0, 0))}


def case_rows(case_id, structural=None):
    structural = structural or features()
    return {"case_id": case_id, "routing_records": [routing.routing_record(
        structural, group, {} if group == "B" else cviews() if group == "C" else dviews(), weight)
        for group in ("B", "C", "D") for weight in routing.WEIGHTS]}


def test_static_features_use_authored_bytes_and_never_import_property_engines(make_query):
    before = set(sys.modules)
    unmasked = routing.static_routing_features(make_query())
    masked = routing.static_routing_features(make_query(mask=True, name="masked.elf"))
    assert set(unmasked) == set(masked) == routing.FEATURE_FIELDS
    assert unmasked["available"] is masked["available"] is True
    assert unmasked["address_load_count"] == masked["address_load_count"] == 2
    assert unmasked["has_immediate_mask"] is False and masked["has_immediate_mask"] is True
    assert masked["instruction_count"] == unmasked["instruction_count"] + 1
    forbidden = ("angr", "claripy", "z3", "src.selective_analysis.operations",
                 "src.selective_analysis.operand_mapping", "src.selective_analysis.compiled_fact_audit",
                 "src.selective_analysis.frame_bounds", "src.selective_analysis.local_bounds")
    assert not [name for name in set(sys.modules) - before if any(
        name == prefix or name.startswith(prefix + ".") for prefix in forbidden)]


def test_query_ids_source_names_and_property_bounds_do_not_determine_scores(make_query):
    query = make_query()
    renamed = replace(query, query_id="expected-violation-never-read", capacity=1)
    relocated = Path(query.binary).with_name("excluded_within_scope-source-name.elf")
    relocated.write_bytes(Path(query.binary).read_bytes())
    first = routing.static_routing_features(query)
    moved = routing.static_routing_features(replace(query, binary=str(relocated)))
    altered = routing.static_routing_features(renamed)
    assert moved == first
    assert "query_id" not in first and "binary" not in first and "capacity" not in first
    assert first["query_hash"] != altered["query_hash"]
    assert routing.select_order(first, "B", {})["scores"] == routing.select_order(altered, "B", {})["scores"]
    assert routing.select_order(first, "B", {})["order"] == routing.select_order(altered, "B", {})["order"]


@pytest.mark.parametrize("extra", ["eb 00", "48 83 ec 08", "89 f8"])
def test_unsupported_static_syntax_retains_unknown_features(make_query, extra):
    result = routing.static_routing_features(make_query(extra=extra))
    assert result["available"] is False and result["reason"]
    assert result["has_immediate_mask"] is result["address_load_count"] is None
    assert result["instruction_count"] > 0
    assert routing.select_order(result, "B", {})["order"] == ["expanded_paths", "frame_bounds"]


@pytest.mark.parametrize("label,kind", [("i64 *", "pointer"), (" U32 * ", "pointer"), ("void **", "pointer"),
                                      ("i64", "integer"), ("u32", "integer"), ("bool", "integer"),
                                      ("char", "integer"), ("int", "integer"), ("size_t", "integer"),
                                      ("array", "other"), ("struct x", "other"), ("float", "other"),
                                      ("pointer", "other"), ("i64[8]", "other")])
def test_pointer_and_integer_label_families_are_disjoint(label, kind):
    assert routing.label_kind(label) == kind


@pytest.mark.parametrize("label", [None, 1, "", "   "])
def test_invalid_candidate_labels_are_rejected(label):
    with pytest.raises(ValueError):
        routing.label_kind(label)


def test_mixture_uses_maximum_of_distinct_occurrence_pairs_not_one_occurrence():
    first = dview(("i64 *", "i64"), (math.log(3), math.log(2)))
    second = dview(("i64", "i64 *"), (math.log(4), 0))
    signal, support = routing.contributor_support({"one": first}, "D")
    assert signal == 0 and support["one"] == pytest.approx({"pointer": 0.6, "integer": 0.4})
    signal, support = routing.contributor_support({"one": first, "two": second}, "D")
    assert signal == pytest.approx(0.6)
    assert support["two"] == pytest.approx({"pointer": 0.2, "integer": 0.8})
    assert routing.contributor_support({"two": second, "one": first}, "D")[0] == signal
    assert routing.contributor_support({"one": TypeView(("i64 *",)), "two": TypeView(("u64 *",))}, "C")[0] == 0


def test_b_has_no_type_input_and_c_hides_all_scores():
    assert routing.contributor_support({}, "B") == (0.0, {})
    with pytest.raises(ValueError, match="B cannot"):
        routing.contributor_support({"anything": object()}, "B")
    assert routing.contributor_support(cviews(), "C")[0] == 1
    for view in (TypeView(("i64", "float")), TypeView(("i64",), (1.0,)), TypeView(("i64",), raw_scores=(2.0,))):
        with pytest.raises(ValueError, match="C requires"):
            routing.contributor_support({"one": view}, "C")


@pytest.mark.parametrize("bad", [TypeView(("i64",)), TypeView(("i64", "float"), (0.5, 0.5)),
                                 TypeView(("i64", "float"), (0.8, 0.8), raw_scores=(1, 0)),
                                 TypeView(("i64", "float"), (-0.1, 1.1), raw_scores=(1, 0)),
                                 TypeView(("i64", "float"), (0.5, 0.5), raw_scores=(math.inf, 0)),
                                 TypeView(("i64", "float"), (0.9, 0.1), raw_scores=(0, 0)),
                                 TypeView(("i64", "float"), (0.25, 0.75), raw_scores=(0, math.log(3))),
                                 TypeView(("i64", "i64"), (0.5, 0.5), raw_scores=(0, 0))])
def test_d_requires_genuine_ranked_conditional_scores_not_arbitrary_weights(bad):
    with pytest.raises(ValueError):
        routing.contributor_support({"bad": bad}, "D")


def test_structural_mask_is_strong_b_baseline_and_shared_policy_is_identical():
    structural = features(mask=True)
    for weight in routing.WEIGHTS:
        rows = [routing.select_order(structural, group, {} if group == "B" else cviews() if group == "C" else dviews(), weight)
                for group in ("B", "C", "D")]
        assert all(row["order"] == ["frame_bounds", "expanded_paths"] for row in rows)
        for key in ("features_hash", "policy_hash", "policy_and_weight_hash", "operation_catalog_hash"):
            assert len({row[key] for row in rows}) == 1
        assert rows[0]["frame_structural_score"] == rows[1]["frame_structural_score"] == rows[2]["frame_structural_score"] == 1.25
        assert rows[0]["type_signal"] == 0
        assert all(row["score_geometry"]["strict_switch_threshold"] is None for row in rows)


@pytest.mark.parametrize("weight,first", [(0, "expanded_paths"), (0.25, "expanded_paths"),
                                         (0.250001, "frame_bounds"), (0.5, "frame_bounds")])
def test_unmasked_threshold_is_strict_and_ties_use_operation_id(weight, first):
    row = routing.select_order(features(), "C", cviews(), weight)
    assert row["order"][0] == first and set(row["order"]) == set(routing.OPERATIONS)
    assert row["score_geometry"]["strict_switch_threshold"] == 0.25
    assert row["scores"]["expanded_paths"] == 1


def test_real_conditional_score_changes_can_alter_unmasked_routing_with_fixed_labels():
    low, high = dviews(logit=0.1), dviews(logit=2.0)
    assert {key: view.labels for key, view in low.items()} == {key: view.labels for key, view in high.items()}
    low_row, high_row = [routing.select_order(features(), "D", views) for views in (low, high)]
    assert low_row["type_signal"] < 0.5 < high_row["type_signal"]
    assert low_row["order"] == ["expanded_paths", "frame_bounds"]
    assert high_row["order"] == ["frame_bounds", "expanded_paths"]
    assert routing.select_order(features(), "B", {})["order"] == low_row["order"]


def test_top_one_label_changes_can_alter_choice_without_any_score_input():
    mixed = cviews()
    pointers_only = {key: TypeView(("i64 *",)) for key in mixed}
    first = routing.select_order(features(), "C", mixed)
    second = routing.select_order(features(), "C", pointers_only)
    assert first["type_signal"] == 1 and second["type_signal"] == 0
    assert first["order"] == ["frame_bounds", "expanded_paths"]
    assert second["order"] == ["expanded_paths", "frame_bounds"]
    assert first["features_hash"] == second["features_hash"]
    assert first["policy_and_weight_hash"] == second["policy_and_weight_hash"]


@pytest.mark.parametrize("group,views", [("A", {}), ("C", {}), ("D", {}), ("C", None), ("D", {"one": object()})])
def test_unknown_groups_and_missing_type_arms_are_rejected_not_replaced_with_b(group, views):
    with pytest.raises(ValueError):
        routing.select_order(features(), group, views)


@pytest.mark.parametrize("key", ["query_id", "expected", "gold", "proof", "prior_result", "type_view"])
def test_extra_property_or_type_inputs_cannot_enter_structural_features(key):
    value = features()
    value[key] = "forbidden"
    with pytest.raises(ValueError, match="features"):
        routing.select_order(value, "B", {})


@pytest.mark.parametrize("weight", [-1, float("nan"), float("inf"), True, "0.5"])
@pytest.mark.parametrize("error", [None, "mapping unavailable"])
def test_invalid_weights_are_rejected_even_for_unavailable_rows(weight, error):
    with pytest.raises(ValueError):
        routing.routing_record(features(), "B", {}, weight, error=error)


def test_routing_records_keep_unavailable_arms_and_zero_signal_geometry():
    row = routing.routing_record(features(), "C", None, 0.5, error="missing correspondence")
    assert row["status"] == "unavailable" and row["order"] is None
    assert row["reason"] == "missing correspondence"
    baseline = routing.routing_record(features(), "B", {}, 0.5)
    assert row["features_hash"] == baseline["features_hash"]
    assert row["policy_and_weight_hash"] == baseline["policy_and_weight_hash"]
    assert baseline["score_geometry"]["basis"] == "zero_signal_full_first_for_all_finite_nonnegative_weights"
    with pytest.raises(ValueError):
        routing.routing_record(features(), "unknown", {}, 0.5, error="missing correspondence")


def test_summary_preserves_three_cases_all_fifteen_rows_and_unavailable_comparisons():
    cases = [case_rows(f"unit-{index}") for index in range(3)]
    for weight in routing.WEIGHTS:
        cases[1]["routing_records"] = [row for row in cases[1]["routing_records"] if not (
            row["group"] == "C" and row["type_weight"] == weight)]
        cases[1]["routing_records"].append(routing.routing_record(features(), "C", None, weight, error="unavailable"))
    report = routing.summarize(cases)
    assert report["unique_integration_cases"] == 3 and report["routing_rows"] == 45
    assert report["available_comparisons"] == 25 and report["unavailable_comparisons"] == 5
    assert len(report["comparisons"]) == 30
    assert all(row["order_changed_from_B"] is None for row in report["comparisons"] if not row["available_pair"])
    assert report["property_operations_executed"] is report["neural_benefit_measured"] is report["held_out_evaluation"] is False


@pytest.mark.parametrize("change", ["missing_case", "duplicate_case", "missing_row", "duplicate_row", "unknown_group",
                                    "unknown_weight", "different_features", "different_policy", "different_catalog",
                                    "different_features_across_weights", "invalid_status", "invalid_order"])
def test_summary_rejects_changed_denominators_or_incomparable_policy_inputs(change):
    cases = [case_rows(f"unit-{index}") for index in range(3)]
    row = cases[0]["routing_records"][0]
    if change == "missing_case":
        cases.pop()
    elif change == "duplicate_case":
        cases[1]["case_id"] = cases[0]["case_id"]
    elif change == "missing_row":
        cases[0]["routing_records"].pop()
    elif change == "duplicate_row":
        cases[0]["routing_records"][1] = deepcopy(row)
    elif change == "unknown_group":
        row["group"] = "gold"
    elif change == "unknown_weight":
        row["type_weight"] = 3
    elif change == "different_features":
        row["features_hash"] = "0" * 64
    elif change == "different_policy":
        row["policy_hash"] = "0" * 64
    elif change == "different_catalog":
        row["operation_catalog_hash"] = "0" * 64
    elif change == "different_features_across_weights":
        for item in cases[0]["routing_records"]:
            if item["type_weight"] == 0:
                item["features_hash"] = "0" * 64
    elif change == "invalid_status":
        row["status"] = "execution_succeeded"
    else:
        row["order"] = ["frame_bounds", "frame_bounds"]
    with pytest.raises(ValueError):
        routing.summarize(cases)
