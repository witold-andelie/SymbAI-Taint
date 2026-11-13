"""Offline inventory of existing metadata and genuine frozen type evidence.

No graph, property check, model invocation or new correspondence is performed here.
"""

from hashlib import sha256
import math
import struct

from .contracts import fingerprint

REVISION = "information_readiness_trace_cost_v16"


def elf_debug_metadata(data):
    """Inspect ordinary ELF64 section metadata; presence alone is not usable DWARF."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Expected a complete little-endian ELF64 header")
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("Expected AMD64 ELF")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    if offset == 0 and count == 0 and strings_index == 0:
        names = []
    else:
        if not offset or not count or size < 64 or not 0 < strings_index < count or offset + size * count > len(data):
            raise ValueError("Unsupported extended or malformed section table")
        string_header = offset + strings_index * size
        string_start, string_size = struct.unpack_from("<QQ", data, string_header + 24)
        if string_start + string_size > len(data):
            raise ValueError("Truncated ELF section names")
        strings = data[string_start:string_start + string_size]
        names = []
        for index in range(count):
            at = struct.unpack_from("<I", data, offset + index * size)[0]
            if at >= len(strings) or b"\0" not in strings[at:]:
                raise ValueError("Invalid ELF section name")
            names.append(strings[at:strings.index(b"\0", at)].decode("ascii", errors="strict"))
    return {"section_count": count, "section_names": names,
            "debug_info_section_present": any(name in names for name in (".debug_info", ".zdebug_info")),
            "debug_abbrev_section_present": any(name in names for name in (".debug_abbrev", ".zdebug_abbrev")),
            "metadata_presence_proves_usable_locator": False}


def _finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def validate_raw_logits(raw):
    """Recompute stored candidate ranking from every retained value-node logit."""
    if (not isinstance(raw, dict) or raw.get("schema") != "symbai.tygr_raw.v1"
            or not raw.get("records") or not isinstance(raw["records"], list)):
        raise ValueError("Missing frozen raw predictions")
    provenance = raw.get("provenance", {})
    if (provenance.get("source") != "tygr_glowgnn" or provenance.get("locator") != "dwarf_assisted"
            or provenance.get("decoder") != "independent" or provenance.get("flatten_vars") is not True
            or provenance.get("ground_truth_labels_supplied_to_model") is not False
            or provenance.get("datagen_predict_phase") is not False):
        raise ValueError("Raw export is not the frozen unlabeled DWARF-assisted decoder")
    for digest in (raw.get("binary_sha256"), provenance.get("model_sha256")):
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Missing binary/model hash")
    ids = []
    for record in raw["records"]:
        if (not isinstance(record, dict) or not isinstance(record.get("prediction_id"), str)
                or not record["prediction_id"] or record.get("score_kind") != "raw_logits"
                or record.get("normalization") != "none"
                or record.get("aggregation") != "mean_raw_logits_across_value_nodes"):
            raise ValueError("Invalid raw prediction identity or score semantics")
        ids.append(record["prediction_id"])
        labels, rows, candidates = (record.get(k) for k in ("vocabulary", "raw_value_node_logits", "candidates"))
        if (not isinstance(labels, list) or not labels or not all(isinstance(x, str) and x for x in labels)
                or len(set(labels)) != len(labels) or not isinstance(rows, list) or not rows
                or not isinstance(candidates, list) or not 1 <= len(candidates) <= len(labels)
                or any(not isinstance(row, list) or len(row) != len(labels)
                       or not all(_finite_number(x) for x in row) for row in rows)):
            raise ValueError("Invalid logit matrix, vocabulary or candidates")
        means = [sum(row[i] for row in rows) / len(rows) for i in range(len(labels))]
        if not all(math.isfinite(value) for value in means):
            raise ValueError("Nonfinite aggregated logits")
        order = sorted(range(len(labels)), key=lambda i: (-means[i], i))[:len(candidates)]
        for rank, (candidate, class_id) in enumerate(zip(candidates, order), 1):
            if (not isinstance(candidate, dict) or type(candidate.get("class_id")) is not int
                    or candidate["class_id"] != class_id or type(candidate.get("rank")) is not int
                    or candidate["rank"] != rank or candidate.get("label") != labels[class_id]
                    or not _finite_number(candidate.get("raw_score"))
                    or not math.isclose(candidate["raw_score"], means[class_id], rel_tol=1e-12, abs_tol=1e-12)):
                raise ValueError("Candidate scores/ranking differ from original logits")
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate prediction identity")
    return set(ids)


def frozen_type_case(case_id, query, binary_bytes, raw, bundle):
    """Verify a recorded location bundle, without recomputing or generalizing its mapping."""
    prediction_ids = validate_raw_logits(raw)
    if sha256(binary_bytes).hexdigest() != query.binary_sha256 or raw["binary_sha256"] != query.binary_sha256:
        raise ValueError("Frozen export/binary identity mismatch")
    payload = dict(bundle)
    digest = payload.pop("bundle_fingerprint", None)
    if (digest != fingerprint(payload) or bundle.get("schema") != "symbai.location_type_bundle.v1"
            or bundle.get("revision") != "static_cfa_load_correspondence_v12"
            or bundle.get("semantics") != "location_correspondence_only"
            or bundle.get("property_verification_performed") is not False or bundle.get("status") != "available"
            or bundle.get("raw_export") != raw or bundle.get("raw_payload_fingerprint") != fingerprint(raw)
            or bundle.get("query_hash") != query.contract_hash
            or bundle.get("binary_sha256") != query.binary_sha256
            or bundle.get("use_site_id") != query.use_site_id
            or bundle.get("model_sha256") != raw["provenance"]["model_sha256"]):
        raise ValueError("Frozen location-only bundle identity or semantics mismatch")
    contract = dict(bundle.get("query", {}))
    contract.pop("binary", None)
    if fingerprint(contract) != query.contract_hash:
        raise ValueError("Frozen bundle query contract mismatch")
    occurrences = {o["occurrence_id"]: o for o in bundle.get("occurrences", [])}
    bindings = bundle.get("bindings")
    if not occurrences or not isinstance(bindings, list) or not bindings:
        raise ValueError("No recorded location correspondence")
    bound = []
    for binding in bindings:
        occurrence = {k: v for k, v in binding.items() if k != "prediction_id"}
        if (binding.get("prediction_id") not in prediction_ids
                or occurrence != occurrences.get(binding.get("occurrence_id"))
                or binding.get("use_rva") != query.write_rva):
            raise ValueError("Binding refers to another prediction or use site")
        bound.append(binding["occurrence_id"])
    if len(set(bound)) != len(bound) or set(bound) != set(occurrences):
        raise ValueError("Incomplete/duplicate recorded binding coverage")
    return {"case_id": case_id, "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
            "use_site_id": query.use_site_id, "model_sha256": raw["provenance"]["model_sha256"],
            "prediction_records": len(prediction_ids), "recorded_binding_count": len(bindings),
            "recorded_mapping_only": True, "new_mapping_performed": False,
            "elf_metadata": elf_debug_metadata(binary_bytes)}


def availability_inventory(queries, binary_data, frozen_cases):
    if len({q.query_id for q in queries}) != len(queries) or set(binary_data) != {q.query_id for q in queries}:
        raise ValueError("Availability inventory query coverage differs")
    rows = []
    for query in queries:
        data = binary_data[query.query_id]
        if sha256(data).hexdigest() != query.binary_sha256:
            raise ValueError("Availability binary changed")
        metadata = elf_debug_metadata(data)
        binary_matches = [c for c in frozen_cases if c["binary_sha256"] == query.binary_sha256]
        exact = [c for c in binary_matches if c["query_hash"] == query.contract_hash and c["use_site_id"] == query.use_site_id]
        reasons = []
        if not binary_matches:
            reasons.append("no_matching_frozen_genuine_export")
        if not exact:
            reasons.append("no_matching_frozen_location_correspondence")
        if not metadata["debug_info_section_present"]:
            reasons.append("current_dwarf_assisted_locator_has_no_debug_info_section")
        rows.append({"query_id": query.query_id, "query_hash": query.contract_hash,
                     "binary_sha256": query.binary_sha256, "elf_metadata": metadata,
                     "matching_frozen_export_cases": [c["case_id"] for c in binary_matches],
                     "matching_frozen_correspondence_cases": [c["case_id"] for c in exact],
                     "recorded_type_view_status": "available" if exact else "unavailable",
                     "readiness_reasons": reasons, "new_model_or_mapping_performed": False})
    return {"schema": "symbai.information_readiness.v1", "unique_queries": len(rows),
            "frozen_export_queries": len(frozen_cases), "queries": rows,
            "exact_mapped_query_intersection": sum(r["recorded_type_view_status"] == "available" for r in rows),
            "absence_is_neural_value_result": False,
            "scope": "only_supplied_frozen_panels_not_global_model_availability"}
