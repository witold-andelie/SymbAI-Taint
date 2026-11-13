"""Identity and score-accounting boundaries, with fabricated metadata only."""

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import struct

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import mechanism_bytes
from src.selective_analysis.contracts import InputRange, Query, fingerprint
from src.selective_analysis.information_readiness import (
    availability_inventory, elf_debug_metadata, frozen_type_case, validate_raw_logits,
)


@pytest.fixture
def fabricated():
    blob, write = mechanism_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    query = Query("scalar_span", "unused-fabricated-location.elf", digest, 4096, 4096 + write,
                  8192, 1024, (InputRange("rdi", 0, 1023),))
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": digest,
           "provenance": {"source": "tygr_glowgnn", "locator": "dwarf_assisted", "decoder": "independent",
                          "flatten_vars": True, "ground_truth_labels_supplied_to_model": False,
                          "datagen_predict_phase": False, "model_sha256": "a" * 64},
           "records": [{"prediction_id": "fabricated:0", "score_kind": "raw_logits", "normalization": "none",
                        "aggregation": "mean_raw_logits_across_value_nodes", "vocabulary": ["char*", "i64"],
                        "raw_value_node_logits": [[2.0, 0.0], [4.0, 0.0]],
                        "candidates": [{"class_id": 0, "label": "char*", "rank": 1, "raw_score": 3.0},
                                       {"class_id": 1, "label": "i64", "rank": 2, "raw_score": 0.0}]}]}
    occurrence = {"occurrence_id": query.use_site_id + ":fabricated-load", "use_rva": query.write_rva,
                  "load_rva": 4096, "cfa_offset": -24, "size_bytes": 8}
    bundle = {"schema": "symbai.location_type_bundle.v1", "revision": "static_cfa_load_correspondence_v12",
              "semantics": "location_correspondence_only", "property_verification_performed": False,
              "status": "available", "raw_export": raw, "raw_payload_fingerprint": fingerprint(raw),
              "query": asdict(query), "query_hash": query.contract_hash, "binary_sha256": digest,
              "use_site_id": query.use_site_id, "model_sha256": "a" * 64, "occurrences": [occurrence],
              "bindings": [{**occurrence, "prediction_id": "fabricated:0"}]}
    seal(bundle)
    return query, blob, raw, bundle


def seal(bundle):
    bundle.pop("bundle_fingerprint", None)
    bundle["bundle_fingerprint"] = fingerprint(bundle)


def test_sectionless_original_mechanism_has_no_debug_metadata(fabricated):
    metadata = elf_debug_metadata(fabricated[1])
    assert metadata["section_count"] == 0 and metadata["section_names"] == []
    assert not metadata["debug_info_section_present"]
    assert metadata["metadata_presence_proves_usable_locator"] is False


def with_debug_sections(blob):
    data = bytearray(blob)
    strings = b"\0.shstrtab\0.debug_info\0.debug_abbrev\0"
    at = len(data)
    data.extend(strings)
    table = len(data)
    data.extend(b"\0" * (64 * 4))
    struct.pack_into("<Q", data, 40, table)
    struct.pack_into("<HHH", data, 58, 64, 4, 1)
    struct.pack_into("<IIQQQQIIQQ", data, table + 64, 1, 3, 0, 0, at, len(strings), 0, 0, 1, 0)
    struct.pack_into("<I", data, table + 128, strings.index(b".debug_info"))
    struct.pack_into("<I", data, table + 192, strings.index(b".debug_abbrev"))
    return bytes(data)


def test_debug_section_names_do_not_claim_a_usable_locator(fabricated):
    metadata = elf_debug_metadata(with_debug_sections(fabricated[1]))
    assert metadata["debug_info_section_present"] and metadata["debug_abbrev_section_present"]
    assert metadata["metadata_presence_proves_usable_locator"] is False


@pytest.mark.parametrize("damage", ["truncated", "wrong_arch", "bad_section_bounds", "extended_count", "bad_strings"])
def test_malformed_metadata_cannot_count_as_readiness(fabricated, damage):
    blob = bytearray(with_debug_sections(fabricated[1]))
    if damage == "truncated": blob = blob[:35]
    elif damage == "wrong_arch": struct.pack_into("<H", blob, 18, 183)
    elif damage == "bad_section_bounds": struct.pack_into("<Q", blob, 40, len(blob))
    elif damage == "extended_count": struct.pack_into("<H", blob, 60, 0)
    else:
        table = struct.unpack_from("<Q", blob, 40)[0]
        struct.pack_into("<Q", blob, table + 64 + 32, len(blob))
    with pytest.raises(ValueError):
        elf_debug_metadata(bytes(blob))


@pytest.mark.parametrize("damage", ["placeholder_score", "wrong_rank", "true_gold", "bool_logit", "nan_logit", "duplicate_id", "duplicate_label"])
def test_raw_candidate_or_provenance_corruption_is_rejected(fabricated, damage):
    raw = deepcopy(fabricated[2])
    record = raw["records"][0]
    if damage == "placeholder_score": record["candidates"][0]["raw_score"] = 0.9
    elif damage == "wrong_rank": record["candidates"][0]["rank"] = 2
    elif damage == "true_gold": raw["provenance"]["ground_truth_labels_supplied_to_model"] = True
    elif damage == "bool_logit": record["raw_value_node_logits"][0][0] = True
    elif damage == "nan_logit": record["raw_value_node_logits"][0][0] = float("nan")
    elif damage == "duplicate_id": raw["records"].append(deepcopy(record))
    else: record["vocabulary"][1] = "char*"
    with pytest.raises(ValueError):
        validate_raw_logits(raw)


def test_frozen_mapping_survives_path_rebinding_without_reexecution(fabricated):
    query, blob, raw, bundle = fabricated
    rebound = replace(query, binary="a-different-copy-path.elf")
    case = frozen_type_case("fixture", rebound, blob, raw, bundle)
    assert case["recorded_mapping_only"] and not case["new_mapping_performed"]
    assert case["query_hash"] == query.contract_hash and case["recorded_binding_count"] == 1


@pytest.mark.parametrize("damage", ["other_query", "other_prediction", "duplicate_binding", "partial_binding", "semantic_proof", "binary_bytes"])
def test_matching_binary_alone_cannot_validate_another_query_or_mapping(fabricated, damage):
    query, blob, raw, bundle = deepcopy(fabricated)
    if damage == "other_query": bundle["query"]["capacity"] = 8
    elif damage == "other_prediction": bundle["bindings"][0]["prediction_id"] = "not-exported"
    elif damage == "duplicate_binding": bundle["bindings"].append(deepcopy(bundle["bindings"][0]))
    elif damage == "partial_binding": bundle["bindings"] = []
    elif damage == "semantic_proof": bundle["property_verification_performed"] = True
    else: blob += b"\0"
    seal(bundle)
    with pytest.raises(ValueError):
        frozen_type_case("fixture", query, blob, raw, bundle)


def test_inventory_matches_hash_and_query_not_reused_case_names(fabricated):
    query, blob, raw, bundle = fabricated
    case = frozen_type_case(query.query_id, query, blob, raw, bundle)
    changed = replace(query, capacity=8)
    report = availability_inventory([changed], {changed.query_id: blob}, [case])
    row = report["queries"][0]
    assert row["matching_frozen_export_cases"] == [query.query_id]
    assert row["matching_frozen_correspondence_cases"] == []
    assert row["recorded_type_view_status"] == "unavailable" and report["exact_mapped_query_intersection"] == 0
    assert report["absence_is_neural_value_result"] is False


def test_empty_export_panel_stays_unavailable_even_with_debug_sections(fabricated):
    query, blob, _, _ = fabricated
    blob = with_debug_sections(blob)
    query = replace(query, binary_sha256=hashlib.sha256(blob).hexdigest())
    report = availability_inventory([query], {query.query_id: blob}, [])
    assert report["queries"][0]["elf_metadata"]["debug_info_section_present"]
    assert report["exact_mapped_query_intersection"] == 0


def test_inventory_keeps_complete_denominator_and_rejects_changed_bytes(fabricated):
    query, blob, _, _ = fabricated
    with pytest.raises(ValueError):
        availability_inventory([query], {query.query_id: blob + b"changed"}, [])
    with pytest.raises(ValueError):
        availability_inventory([query, query], {query.query_id: blob}, [])
    report = availability_inventory([query], {query.query_id: blob}, [])
    assert report["unique_queries"] == 1 and report["frozen_export_queries"] == 0
    assert len(report["queries"]) == 1 and report["exact_mapped_query_intersection"] == 0
