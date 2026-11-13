"""Whole-variable CFA association to fresh static address-load syntax.

Association uses physical location and lifetime only. Native PC coincidences and
incoming location edges remain diagnostics: neither establishes instruction/event
identity, a semantic pointer/index role, or type truth. Event proof is not a condition
for an otherwise valid whole-variable group association.
"""

from copy import deepcopy
from types import SimpleNamespace

from .contracts import file_hash, fingerprint
from .location_correspondence import _StaticLoads
from .native_input_validation import validate_native_capture


REVISION = "native_whole_variable_cfa_association_v20"
_REQUEST_FIELDS = {"schema", "binary", "binary_sha256", "entry_rva", "write_rva", "native_capture_fingerprint"}
_OCCURRENCE_FIELDS = {"occurrence_id", "cfa_offset", "load_rva", "load_address", "use_rva", "use_address", "size_bytes"}


def _integer(value, minimum=None):
    return type(value) is int and (minimum is None or value >= minimum)


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _require(condition, message):
    if not condition:
        raise ValueError("Invalid native readout correspondence: " + message)


def _binary_hash(path):
    try:
        return file_hash(path)
    except OSError as error:
        raise ValueError("Invalid native readout correspondence: binary unavailable") from error


def _request(request):
    _require(isinstance(request, dict) and set(request) == _REQUEST_FIELDS
             and request["schema"] == "symbai.native_readout_request.v1"
             and isinstance(request["binary"], str) and bool(request["binary"])
             and _hash(request["binary_sha256"]) and _hash(request["native_capture_fingerprint"])
             and _integer(request["entry_rva"], 0) and _integer(request["write_rva"], request["entry_rva"]),
             "minimal request fields or identity")
    return f"{request['binary_sha256']}:{request['entry_rva']:x}:{request['write_rva']:x}:write_address"


def _occurrence_reason(occurrence, request, use_site_id):
    if not isinstance(occurrence, dict) or set(occurrence) != _OCCURRENCE_FIELDS:
        return "malformed_static_occurrence"
    if not _integer(occurrence["cfa_offset"]) or not all(_integer(occurrence[key], 0)
            for key in ("load_rva", "load_address", "use_rva", "use_address")):
        return "malformed_static_occurrence"
    if type(occurrence["size_bytes"]) is not int or occurrence["size_bytes"] != 8:
        return "load_width_is_not_eight_bytes"
    if (occurrence["use_rva"] != request["write_rva"]
            or not request["entry_rva"] <= occurrence["load_rva"] < occurrence["use_rva"]
            or occurrence["load_address"] - occurrence["load_rva"] < 0
            or occurrence["load_address"] - occurrence["load_rva"] != occurrence["use_address"] - occurrence["use_rva"]):
        return "static_load_or_use_identity_mismatch"
    expected_id = use_site_id + f":load@{occurrence['load_rva']:x}:cfa{occurrence['cfa_offset']:+d}"
    if occurrence["occurrence_id"] != expected_id:
        return "static_occurrence_identity_mismatch"
    return None


def _location_valid(location):
    return (isinstance(location, dict) and _integer(location.get("low_pc"), 0)
            and _integer(location.get("high_pc"), location["low_pc"] + 1)
            and isinstance(location.get("location_class"), str)
            and _integer(location.get("location_value"))
            and (location.get("location_register") is None or _integer(location.get("location_register"), 0))
            and (location.get("location_argument") is None or _integer(location.get("location_argument"))))


def _cfa_valid(location):
    return (_location_valid(location) and location["location_class"] == "CfaLocation"
            and location.get("location_register") is None
            and location.get("location_argument") == location["location_value"])


def _native_rows(function, variable, occurrence):
    """Retain every member and incoming location edge; never select by sampled value/PC."""
    labels = function["node_labels"]
    _require(isinstance(labels, list) and all(isinstance(label, dict) and _integer(label.get("graph_node_id"), 0)
                                           for label in labels), "native node metadata")
    indexed = {label["graph_node_id"]: label for label in labels}
    _require(len(indexed) == len(labels), "duplicate native node metadata")
    original, output_rows = variable["original_value_nodes"], variable["flattened_output_rows"]
    _require(isinstance(original, list) and bool(original) and all(_integer(node, 0) and node in indexed for node in original)
             and isinstance(output_rows, list) and bool(output_rows) and all(_integer(row, 0) for row in output_rows)
             and len(set(output_rows)) == len(output_rows), "native original group or row metadata")
    row_axis = function["readout_contract"]["row_axis"]
    if row_axis == "value_node":
        _require(len(original) == len(output_rows), "native value-node row count")
        row_members = [[node] for node in original]
    else:
        _require(row_axis == "variable_readout" and len(output_rows) == 1, "native variable readout row count")
        row_members = [original]
    result = []
    for row, members in zip(output_rows, row_members):
        member_rows = []
        for node in members:
            label = indexed[node]
            incoming = []
            for edge_index, edge in enumerate(function["graph_edges"]):
                _require(isinstance(edge, dict) and isinstance(edge.get("labels"), list), "native edge metadata")
                location_labels = [name for name in edge["labels"] if name in ("mem_loc", "reg_loc")]
                if edge.get("target") != node or not location_labels:
                    continue
                _require(edge.get("source") in indexed, "incoming native location source absent")
                incoming.append({"native_edge_index": edge_index, "location_labels": location_labels,
                                 "edge": deepcopy(edge), "source_node_label": deepcopy(indexed[edge["source"]])})
            pc = label.get("annotation_address")
            _require(pc is None or _integer(pc, 0), "native annotation PC metadata")
            member_rows.append({"graph_node_id": node, "node_label": deepcopy(label),
                                "incoming_location_facts": incoming,
                                "annotation_pc_coincides_with_static_load": pc == occurrence["load_address"],
                                "exact_event_status": "unverified", "exact_event_verified": False})
        result.append({"output_row": row, "members": member_rows,
                       "exact_event_status": "unverified", "exact_event_verified": False})
    return result


def associate_native_readouts(request, target_function, occurrences):
    """Pure per-occurrence association; full-capture validation belongs to build_*.

    This helper does not open the binary or establish a whole-capture fingerprint.
    It binds all emitted native group/row identities to the caller's declared capture
    fingerprint. The build API verifies that fingerprint before calling this helper.
    """
    use_site_id = _request(request)
    _require(isinstance(occurrences, list) and len(occurrences) <= 64, "static occurrence list or limit")
    result = []
    function_ok = (isinstance(target_function, dict) and _integer(target_function.get("function_address"), 0)
                   and target_function["function_address"] == request["entry_rva"]
                   and target_function.get("is_target") is True
                   and isinstance(target_function.get("variables"), list))
    for occurrence in occurrences:
        row = {"occurrence": deepcopy(occurrence), "status": "unavailable", "reason": None,
               "native_capture_fingerprint": request["native_capture_fingerprint"], "native_group_index": None,
               "native_group_id": None, "original_value_nodes": [], "flattened_output_rows": [],
               "matched_location": None, "candidate_groups": [], "native_rows": [], "exact_event_status": "unverified",
               "exact_event_verified": False, "semantic_address_role_verified": False}
        reason = _occurrence_reason(occurrence, request, use_site_id)
        if reason or not function_ok:
            row["reason"] = reason or "native_target_function_identity_mismatch"
            result.append(row)
            continue
        matches, malformed = [], False
        for group_index, variable in enumerate(target_function["variables"]):
            if (not isinstance(variable, dict) or not _integer(variable.get("function_address"), 0)
                    or variable["function_address"] != request["entry_rva"]):
                continue
            locations = variable.get("locations")
            if not isinstance(locations, list):
                malformed = True
                continue
            for location_index, location in enumerate(locations):
                if not isinstance(location, dict) or location.get("location_class") != "CfaLocation":
                    continue
                if not any(type(location.get(key)) is int and location[key] == occurrence["cfa_offset"]
                           for key in ("location_value", "location_argument")):
                    continue
                if not _cfa_valid(location):
                    malformed = True
                    continue
                if all(location["low_pc"] <= occurrence[key] < location["high_pc"] for key in ("load_address", "use_address")):
                    matches.append((group_index, location_index, variable, location))
        row["candidate_groups"] = [{"native_group_index": index, "location_index": location_index,
                                     "original_value_nodes": deepcopy(variable.get("original_value_nodes")),
                                     "flattened_output_rows": deepcopy(variable.get("flattened_output_rows")),
                                     "matched_location": deepcopy(location)}
                                    for index, location_index, variable, location in matches]
        if malformed or len(matches) != 1:
            row["reason"] = ("malformed_native_location" if malformed else "missing_native_cfa_lifetime"
                             if not matches else "ambiguous_native_cfa_location")
            row["matching_location_count"] = len(matches)
            result.append(row)
            continue
        group_index, location_index, variable, location = matches[0]
        overlapping, bad_group_location = False, False
        for index, other in enumerate(variable["locations"]):
            if index == location_index:
                continue
            if not _location_valid(other):
                bad_group_location = True
            elif other["low_pc"] < location["high_pc"] and location["low_pc"] < other["high_pc"]:
                overlapping = True
        if overlapping or bad_group_location:
            row["reason"] = "ambiguous_overlapping_native_locations" if overlapping else "malformed_native_location"
            result.append(row)
            continue
        try:
            native_rows = _native_rows(target_function, variable, occurrence)
        except (ValueError, KeyError, TypeError, IndexError) as error:
            row["reason"] = "malformed_native_group_metadata: " + str(error)
            result.append(row)
            continue
        row.update(status="available", native_group_index=group_index,
                   native_group_id=f"{request['native_capture_fingerprint']}:{request['entry_rva']:x}:group:{group_index}",
                   original_value_nodes=deepcopy(variable["original_value_nodes"]),
                   flattened_output_rows=deepcopy(variable["flattened_output_rows"]), matched_location=deepcopy(location),
                   native_rows=native_rows)
        result.append(row)
    return result


def build_native_readout_correspondence(request, capture, expected_contract):
    """Validate the frozen capture and freshly decode syntax, without old proofs/logits."""
    use_site_id = _request(request)
    _require(isinstance(capture, dict) and fingerprint(capture) == request["native_capture_fingerprint"], "native capture fingerprint differs")
    _require(capture.get("request_identity") == {"binary_sha256": request["binary_sha256"], "entry_rva": request["entry_rva"]},
             "native capture input identity differs")
    native_validation = validate_native_capture(capture, expected_contract)
    _require(_binary_hash(request["binary"]) == request["binary_sha256"], "binary SHA-256 differs")
    root = {"schema": "symbai.native_readout_correspondence.v1", "revision": REVISION,
            "request": deepcopy(request), "request_fingerprint": fingerprint(request), "use_site_id": use_site_id,
            "native_capture_fingerprint": request["native_capture_fingerprint"], "native_validation": native_validation,
            "status": "unavailable", "reason": None, "static_status": "unavailable", "static_reason": None,
            "static_trace": [], "partial_static_load_origins": [], "occurrences": [], "occurrence_records": [],
            "exact_event_status": "unverified", "exact_event_verified": False,
            "property_verification_performed": False, "semantic_address_roles_verified": False,
            "historical_logits_reused": False, "neural_inference_performed": False,
            "scope": "whole_variable_cfa_association_to_static_address_load_syntax_only"}
    minimal = SimpleNamespace(binary=request["binary"], binary_sha256=request["binary_sha256"],
                              entry_rva=request["entry_rva"], write_rva=request["write_rva"], use_site_id=use_site_id)
    walker = None
    try:
        walker = _StaticLoads(minimal)
        occurrences = walker.walk()
        root.update(static_status="available", occurrences=deepcopy(occurrences), linked_base=walker.base,
                    cfa_convention="canonical_rbp_plus_16")
    except Exception as error:
        root["static_reason"] = type(error).__name__ + ": " + str(error)
        root["reason"] = "static_decode_unavailable"
    if walker is not None:
        root["static_trace"] = deepcopy(walker.trace)
        if root["static_status"] != "available":
            root["partial_static_load_origins"] = deepcopy(list(walker.origins.values()))
    _require(_binary_hash(request["binary"]) == request["binary_sha256"], "binary changed during static decoding")
    if root["static_status"] == "available":
        targets = [function for function in capture["functions"] if function.get("is_target") is True
                   and function.get("function_address") == request["entry_rva"]]
        target = targets[0] if native_validation["captured"] and len(targets) == 1 else None
        root["occurrence_records"] = associate_native_readouts(request, target, root["occurrences"])
        if not native_validation["captured"]:
            root["reason"] = "native_capture_not_complete"
        elif root["occurrence_records"] and all(row["status"] == "available" for row in root["occurrence_records"]):
            root.update(status="available", reason=None)
        else:
            root["reason"] = "one_or_more_native_group_associations_unavailable"
    root["counts"] = {"static_address_load_occurrences": len(root["occurrences"]),
                      "available_group_associations": sum(row["status"] == "available" for row in root["occurrence_records"]),
                      "unavailable_group_associations": sum(row["status"] != "available" for row in root["occurrence_records"]),
                      "exact_event_verified_occurrences": 0}
    root["interpretation"] = ("A unique CFA location/lifetime can associate a complete original variable group. "
        "Every native row is retained. Annotation-PC coincidence is not exact-event proof; event identity and semantic address roles remain unverified.")
    root["correspondence_fingerprint"] = fingerprint(root)
    return root
