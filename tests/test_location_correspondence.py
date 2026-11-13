"""Static correspondence tests on authored machine code; no empirical neural data."""

import builtins
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.location_correspondence import build_location_bundle, project_location_views
from src.selective_analysis.types import TypeInformationUnavailable, load_type_view

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def make_case():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("location-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    def make(extra="", transform="", after_load="", allocation="", prefix="f3 0f 1e fa 55 48 89 e5"):
        code = Code()
        code.emit(prefix + " " + allocation + " 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + extra + " " + transform + " 48 8b 55 f8 48 8b 45 e8 " + after_load + " 48 01 d0")
        code.write_offset = len(code.data)
        code.emit("c6 00 41 c3")
        path = folder / (uuid.uuid4().hex[:8] + ".elf")
        path.write_bytes(elf_bytes(code.finish()))
        q = Query("unit-location", str(path), file_hash(path), TEXT - BASE,
                  TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", 0, 15),))
        candidates = [{"label": "char*", "rank": 1, "raw_score": 2.0},
                      {"label": "u64", "rank": 2, "raw_score": 0.5}]
        raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": q.binary_sha256,
               "provenance": {"source": "tygr_glowgnn", "model_sha256": "a" * 64,
                              "locator": "dwarf_assisted", "ground_truth_labels_supplied_to_model": False},
               "records": [{"prediction_id": "unit:" + str(i), "function_address": TEXT,
                            "locator_variable_name": "unit-fabricated-" + str(i),
                            "locations": [{"location_class": "CfaLocation", "location_value": offset,
                                           "location_argument": offset, "location_register": None,
                                           "low_pc": TEXT, "high_pc": BASE + q.write_rva + 3}],
                            "score_kind": "raw_logits", "candidates": deepcopy(candidates)}
                           for i, offset in enumerate((-40, -24))]}
        return q, raw
    return make


@pytest.mark.parametrize("transform", ("", "48 83 45 e8 04", "48 83 65 e8 07"))
def test_static_two_slot_correspondence_has_no_property_result(make_case, transform):
    q, raw = make_case(transform=transform)
    before = deepcopy(raw)
    bundle = build_location_bundle(q, raw)
    assert bundle["status"] == "available"
    assert bundle["property_verification_performed"] is False
    assert bundle["semantics"] == "location_correspondence_only"
    assert {b["cfa_offset"] for b in bundle["bindings"]} == {-24, -40}
    assert {b["prediction_id"] for b in bundle["bindings"]} == {"unit:0", "unit:1"}
    assert len(bundle["occurrences"]) == 2
    assert not {"evidence", "plan", "object_anchor", "index_anchor", "result", "derived_status", "program_facts"} & bundle.keys()
    assert all("role" not in b and b["use_address"] == BASE + q.write_rva for b in bundle["bindings"])
    assert bundle["bundle_fingerprint"] == fingerprint({k: v for k, v in bundle.items() if k != "bundle_fingerprint"})
    assert raw == before


def test_names_labels_and_scores_cannot_choose_bindings(make_case):
    q, raw = make_case()
    original = build_location_bundle(q, raw)
    changed = deepcopy(raw)
    changed["records"].reverse()
    for record in changed["records"]:
        record["locator_variable_name"] = "misleading semantic role"
        record["candidates"] = [{"label": "i32", "rank": 1, "raw_score": 99},
                                {"label": "float", "rank": 2, "raw_score": -99}]
    after = build_location_bundle(q, changed)
    assert after["bindings"] == original["bindings"]
    assert after["occurrences"] == original["occurrences"]
    assert after["raw_payload_fingerprint"] != original["raw_payload_fingerprint"]
    # Even the property contract's numeric assumptions cannot affect association.
    other = replace(q, capacity=123, object_rva=42, inputs=(InputRange("rsi", 3, 4),))
    mapped_other = build_location_bundle(other, raw)
    assert [{k: v for k, v in b.items() if k != "occurrence_id"} for b in mapped_other["bindings"]] == [
        {k: v for k, v in b.items() if k != "occurrence_id"} for b in original["bindings"]]


def test_projection_hides_scores_from_c_and_keeps_independent_predictions(make_case):
    q, raw = make_case()
    bundle = build_location_bundle(q, raw)
    assert project_location_views(bundle, "A") == project_location_views(bundle, "B") == {}
    c, d = project_location_views(bundle, "C"), project_location_views(bundle, "D")
    assert len(c) == len(d) == 2
    for key in c:
        assert c[key].labels == ("char*",) and c[key].weights == c[key].raw_scores == ()
        assert d[key].labels == ("char*", "u64") and d[key].raw_scores == (2.0, 0.5)
        assert sum(d[key].weights) == pytest.approx(1.0)


@pytest.mark.parametrize("mutation", [
    lambda r: r["records"][0]["locations"][0].update(location_value=-48, location_argument=-48),
    lambda r: r["records"][0]["locations"][0].update(high_pc=TEXT),
    lambda r: r["records"][0]["locations"][0].update(low_pc=TEXT + 1000),
    lambda r: r["records"][0]["locations"][0].update(location_argument=0),
    lambda r: r["records"][0]["locations"][0].update(location_register="rbp"),
    lambda r: r["records"][0].update(function_address=TEXT + 1),
    lambda r: r["records"][0].update(locations=[]),
    lambda r: r["records"].append({**deepcopy(r["records"][0]), "prediction_id": "unit:ambiguous"}),
])
def test_missing_or_ambiguous_correspondence_is_retained_unavailable(make_case, mutation):
    q, raw = make_case()
    mutation(raw)
    bundle = build_location_bundle(q, raw)
    assert bundle["status"] == "unavailable"
    assert bundle["raw_export"] == raw
    assert bundle["bindings"] == [] and bundle["static_trace"]
    with pytest.raises(TypeInformationUnavailable):
        project_location_views(bundle, "D")


def test_location_half_open_range_must_cover_write_and_load(make_case):
    q, raw = make_case()
    raw["records"][0]["locations"][0]["high_pc"] = BASE + q.write_rva
    assert build_location_bundle(q, raw)["status"] == "unavailable"
    raw["records"][0]["locations"][0]["high_pc"] += 1
    assert build_location_bundle(q, raw)["status"] == "available"
    raw["records"][0]["locations"][0]["low_pc"] = BASE + q.write_rva
    assert build_location_bundle(q, raw)["status"] == "unavailable"


@pytest.mark.parametrize("extra,reason", [
    ("eb 00", "unsupported_instruction:jmp"),
    ("e8 00 00 00 00", "unsupported_instruction:call"),
    ("c3", "unsupported_instruction:ret"),
    ("48 89 fd", "frame_register"),
    ("48 89 e9", "frame_register"),
    ("c6 45 e8 00", "partial_or_noncanonical"),
    ("48 89 7d ec", "partial_or_noncanonical"),
    ("48 8b 0f", "partial_or_noncanonical"),
    ("48 8b 4d f0", "without_local_store"),
    ("b8 00 00 00 00", "partial_or_non_register"),
])
def test_unsupported_code_never_invents_correspondence(make_case, extra, reason):
    q, raw = make_case(extra=extra)
    bundle = build_location_bundle(q, raw)
    assert bundle["status"] == "unavailable" and reason in bundle["reason"]


def test_overwritten_register_origin_is_killed_not_reused(make_case):
    # RAX's loaded origin disappears; RDX still supplies one located contribution.
    q, raw = make_case(after_load="48 c7 c0 00 00 00 00")
    bundle = build_location_bundle(q, raw)
    assert bundle["status"] == "available"
    assert [b["prediction_id"] for b in bundle["bindings"]] == ["unit:1"]
    # A new unlocated incoming register cannot silently become an empty known origin.
    q, raw = make_case(after_load="48 89 c8")
    assert build_location_bundle(q, raw)["reason"] == "missing_address_load_origins"


def test_xor_zero_kills_origins_and_slot_mutation_after_load_refuses(make_case):
    q, raw = make_case(after_load="48 31 c0")
    assert [b["prediction_id"] for b in build_location_bundle(q, raw)["bindings"]] == ["unit:1"]
    q, raw = make_case(after_load="48 c7 45 e8 00 00 00 00")
    assert build_location_bundle(q, raw)["reason"] == "slot_changed_after_origin_load"


@pytest.mark.parametrize("allocation", ("48 83 ec 20", "48 81 ec 00 10 00 00"))
def test_canonical_allocation_preserves_cfa_offsets(make_case, allocation):
    q, raw = make_case(allocation=allocation)
    assert build_location_bundle(q, raw)["status"] == "available"


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema="symbai.operand_types.v1"),
    lambda r: r.update(binary_sha256="b" * 64),
    lambda r: r.update(evidence={"already_proved": True}),
    lambda r: r["provenance"].update(ground_truth_labels_supplied_to_model=True),
    lambda r: r["provenance"].update(model_sha256="invalid"),
    lambda r: r["records"][0].update(prediction_id="unit:1"),
])
def test_wrong_raw_identity_or_semantic_bundle_is_rejected(make_case, mutation):
    q, raw = make_case()
    mutation(raw)
    with pytest.raises(ValueError):
        build_location_bundle(q, raw)


def test_static_recheck_rejects_rehashed_binding_and_legacy_reader_rejects_new_schema(make_case):
    q, raw = make_case()
    bundle = build_location_bundle(q, raw)
    bundle["bindings"][0]["prediction_id"] = "unit:0" if bundle["bindings"][0]["prediction_id"] == "unit:1" else "unit:1"
    bundle["bundle_fingerprint"] = fingerprint({k: v for k, v in bundle.items() if k != "bundle_fingerprint"})
    with pytest.raises(TypeInformationUnavailable, match="recheck"):
        project_location_views(bundle, "C")
    import json
    path = Path(q.binary).with_suffix(".json")
    path.write_text(json.dumps(build_location_bundle(q, raw)), encoding="utf-8")
    with pytest.raises(TypeInformationUnavailable, match="schema"):
        load_type_view(path, q, "D")


def test_mapping_and_projection_do_not_import_property_engines(make_case, monkeypatch):
    q, raw = make_case()
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in ("angr", "claripy", "z3") or name.endswith(("operations", "operand_mapping", "compiled_fact_audit", "local_bounds", "frame_bounds")):
            raise AssertionError("Property code imported: " + name)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded)
    bundle = build_location_bundle(q, raw)
    assert len(project_location_views(bundle, "D")) == 2
