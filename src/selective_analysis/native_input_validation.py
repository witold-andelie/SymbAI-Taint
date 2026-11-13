"""Pure validation of newly observed native preprocessing receipts, without prediction.

Positional correspondences are checked without reordering native data. Domain and
node-order findings preserve a faithful capture; they say nothing about historical
inputs, model behavior, type truth, or a projection of the v17 mechanism panel.
"""

import hashlib
import json
import math
import re

from .contracts import fingerprint


CASES = ("direct_index", "offset_index", "masked_index")
MAX_FUNCTIONS, MAX_NODES, MAX_EDGES, MAX_VARIABLES, MAX_READOUT_ROWS = 64, 4096, 20000, 4096, 4096
MAX_TENSOR_VALUES, MAX_TOTAL_TENSOR_VALUES = 2000000, 16000000


def _require(condition, message):
    if not condition:
        raise ValueError("Invalid native preprocessing receipt: " + message)


def _integer(value, minimum=None):
    return type(value) is int and (minimum is None or value >= minimum)


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _json(value):
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("Invalid native preprocessing receipt: non-JSON metadata") from error


def _contract(contract):
    required = {"model_sha256", "node_label_encoding_dim", "all_ops", "num_all_ops", "num_edge_ops",
                "flatten_vars", "use_arch", "arch_fields", "type_count", "decoder_type",
                "node_aggregation", "layer_relation_capacities", "edge_reduce_op_map"}
    _require(isinstance(contract, dict) and required <= set(contract), "expected model contract fields")
    _require(_hash(contract["model_sha256"]) and _integer(contract["node_label_encoding_dim"], 1)
             and _integer(contract["type_count"], 1), "model identity or feature/class count")
    for key in ("all_ops", "arch_fields"):
        values = contract[key]
        _require(isinstance(values, list) and bool(values) and all(isinstance(x, str) and x for x in values)
                 and len(set(values)) == len(values), "ordered model vocabulary")
    _require(_integer(contract["num_all_ops"], 1) and contract["num_all_ops"] == len(contract["all_ops"]) + 1
             and _integer(contract["num_edge_ops"], 1) and contract["num_edge_ops"] == 2 * contract["num_all_ops"]
             and len(contract["arch_fields"]) <= contract["node_label_encoding_dim"], "declared model domains")
    _require(type(contract["flatten_vars"]) is type(contract["use_arch"]) is bool
             and isinstance(contract["decoder_type"], str) and bool(contract["decoder_type"])
             and isinstance(contract["node_aggregation"], str) and bool(contract["node_aggregation"]), "readout settings")
    _require(isinstance(contract["layer_relation_capacities"], list) and bool(contract["layer_relation_capacities"])
             and all(_integer(x, 1) for x in contract["layer_relation_capacities"]), "saved layer domains")
    reduction = contract["edge_reduce_op_map"]
    _require(isinstance(reduction, dict) and all(isinstance(k, str) and k and isinstance(v, str) and v
                                              for k, v in reduction.items()), "edge reduction map")
    _json(contract)


def _tensor(value, dtype, shape, budget):
    _require(isinstance(value, dict) and set(value) == {"dtype", "device", "shape", "values"}, "tensor descriptor")
    _require(value["dtype"] == dtype and value["device"] == "cpu" and isinstance(value["shape"], list)
             and all(_integer(x, 0) for x in value["shape"]) and value["shape"] == shape, "tensor dtype/device/shape")
    count = math.prod(shape)
    budget[0] += count
    _require(count <= MAX_TENSOR_VALUES and budget[0] <= MAX_TOTAL_TENSOR_VALUES, "tensor value resource limit")

    def visit(values, remaining):
        if remaining:
            _require(isinstance(values, list) and len(values) == remaining[0], "incomplete tensor values")
            for item in values:
                visit(item, remaining[1:])
        elif dtype == "torch.int64":
            _require(type(values) is int and -(1 << 63) <= values < (1 << 63), "int64 tensor value")
        else:
            _require(type(values) in (int, float) and math.isfinite(values)
                     and abs(values) <= 3.4028234663852886e38, "float32 tensor value")

    visit(value["values"], shape)
    return value["values"]


def _ast_value(value):
    _require(isinstance(value, dict) and set(value) == {"kind", "value"}, "AST value record")
    kind, literal = value["kind"], value["value"]
    if kind == "int":
        _require(isinstance(literal, str) and len(literal) <= 4096
                 and re.fullmatch(r"-?(0|[1-9][0-9]*)", literal) is not None and literal != "-0", "decimal AST integer")
    elif kind == "bool":
        _require(type(literal) is bool, "AST boolean")
    elif kind == "float":
        _require(isinstance(literal, str) and len(literal) <= 256, "hex AST float")
        try:
            _require(float.fromhex(literal).hex() == literal, "canonical hex AST float")
        except (ValueError, OverflowError) as error:
            raise ValueError("Invalid native preprocessing receipt: hex AST float") from error
    else:
        raise ValueError("Invalid native preprocessing receipt: AST value kind")


def _locations(locations):
    _require(isinstance(locations, list) and len(locations) <= MAX_VARIABLES, "variable locations")
    required = {"low_pc", "high_pc", "location_class", "location_value", "location_register", "location_argument"}
    for location in locations:
        _require(isinstance(location, dict) and required <= set(location), "location fields")
        _require(_integer(location["low_pc"], 0) and (location["high_pc"] is None
                 or _integer(location["high_pc"], location["low_pc"]))
                 and isinstance(location["location_class"], str) and bool(location["location_class"])
                 and _integer(location["location_value"])
                 and (location["location_register"] is None or _integer(location["location_register"], 0))
                 and (location["location_argument"] is None or _integer(location["location_argument"])), "location values")
        expected = location["location_register"] if location["location_register"] is not None else location["location_argument"]
        _require(location["location_value"] == (expected if expected is not None else 0), "location display value")


def _function(function, identity, contract, budget):
    _require(isinstance(function, dict), "function record")
    address = function["function_address"]
    _require(_integer(address, 0) and (function["function_high_pc"] is None
             or _integer(function["function_high_pc"], address + 1)) and type(function["is_target"]) is bool
             and function["is_target"] == (address == identity["entry_rva"])
             and isinstance(function["arch_token"], str), "function identity or target marker")
    order, labels, edges, variables = [function[key] for key in ("graph_node_order", "node_labels", "graph_edges", "variables")]
    _require(isinstance(order, list) and 0 < len(order) <= MAX_NODES and all(_integer(x, 0) for x in order)
             and len(set(order)) == len(order), "graph node iteration order")
    _require(isinstance(labels, list) and len(labels) == len(order), "NodeLabel count")
    for node_id, label in zip(order, labels):
        _require(isinstance(label, dict) and _integer(label["graph_node_id"], 0) and label["graph_node_id"] == node_id
                 and _integer(label["bitsize"], 1) and label["bitsize"] <= 65536
                 and (label["annotation_address"] is None or _integer(label["annotation_address"], 0)), "NodeLabel identity or width")
        _ast_value(label["ast_value"])
    _require(isinstance(edges, list) and len(edges) <= MAX_EDGES, "graph edge resource limit")
    _require(isinstance(variables, list) and 0 < len(variables) <= MAX_VARIABLES, "nonempty variable groups")
    findings, node_set, relation_ids, seen_edges = [], set(order), [], set()
    if order != list(range(len(order))):
        findings.append({"code": "graph_node_order_not_feature_row_range", "graph_node_order": list(order)})
    outside_rows = [node for node in order if node >= len(order)]
    if outside_rows:
        findings.append({"code": "graph_ids_outside_feature_row_domain", "graph_node_ids": outside_rows})
    prefix = [float(contract["use_arch"] and function["arch_token"] == token) for token in contract["arch_fields"]]
    if contract["use_arch"] and not any(prefix):
        findings.append({"code": "architecture_token_zero_encoding", "arch_token": function["arch_token"]})
    prepared, batch = function["prepared"], function["batch"]
    _require(isinstance(prepared, dict) and isinstance(batch, dict), "prepared/batch objects")
    node_values = _tensor(prepared["node_labels"], "torch.float32", [len(order), contract["node_label_encoding_dim"]], budget)
    _require(all(row[:len(prefix)] == prefix for row in node_values), "raw architecture token feature correspondence")
    edge_values = _tensor(prepared["edges"], "torch.int64", [2, 2 * len(edges)], budget)
    encoded = _tensor(prepared["edge_labels"], "torch.int64", [2 * len(edges)], budget)
    for index, edge in enumerate(edges):
        _require(isinstance(edge, dict) and _integer(edge["source"], 0) and _integer(edge["target"], 0)
                 and edge["source"] in node_set and edge["target"] in node_set
                 and (edge["source"], edge["target"]) not in seen_edges, "graph edge endpoints/order")
        seen_edges.add((edge["source"], edge["target"]))
        names = edge["labels"]
        _require(isinstance(names, list) and bool(names) and all(isinstance(x, str) and x for x in names)
                 and names == sorted(set(names)), "complete sorted unique edge label set")
        selected = names[0]  # Native return is inside the loop; see the v19 audit erratum.
        reduced = contract["edge_reduce_op_map"].get(selected, selected)
        known = selected in contract["all_ops"]
        _require(known or selected not in contract["edge_reduce_op_map"] or reduced in contract["all_ops"], "unencodable reduced label")
        expected = contract["all_ops"].index(selected) if known else (
            contract["all_ops"].index(reduced) if reduced in contract["all_ops"] else len(contract["all_ops"]))
        forward, inverse = edge["forward_id"], edge["inverse_id"]
        _require(_integer(forward) and _integer(inverse) and inverse == forward + contract["num_all_ops"], "native inverse ID offset")
        if forward != expected:
            _require(forward < 0 or inverse < 0 or forward >= contract["num_edge_ops"]
                     or inverse >= contract["num_edge_ops"], "native first-sorted-label encoding")
            findings.append({"code": "native_encoding_differs_from_saved_label_formula", "edge_index": index,
                             "selected_label": selected, "expected_forward_id": expected, "observed_forward_id": forward})
        if not known and reduced not in contract["all_ops"]:
            findings.append({"code": "unknown_label_encoding", "edge_index": index, "selected_label": selected,
                             "forward_id": forward, "inverse_id": inverse})
        columns = edge["prepared_columns"]
        _require(isinstance(columns, list) and all(_integer(x, 0) for x in columns)
                 and columns == [2 * index, 2 * index + 1], "prepared edge column order")
        left, right = columns
        _require([edge_values[0][left], edge_values[1][left]] == [edge["source"], edge["target"]]
                 and [edge_values[0][right], edge_values[1][right]] == [edge["target"], edge["source"]]
                 and encoded[left:right + 1] == [forward, inverse], "native/prepared edge positional correspondence")
        relation_ids.extend((forward, inverse))
    original, row_groups, cursor = [], [], 0
    for index, variable in enumerate(variables):
        _require(isinstance(variable, dict) and variable["prediction_id"] == f"{address:x}:{index}"
                 and _integer(variable["function_address"], 0) and variable["function_address"] == address
                 and (variable["locator_variable_name"] is None or isinstance(variable["locator_variable_name"], str)), "variable identity")
        _locations(variable["locations"])
        nodes = variable["original_value_nodes"]
        _require(isinstance(nodes, list) and 0 < len(nodes) <= MAX_NODES
                 and all(_integer(node, 0) and node in node_set for node in nodes), "original value nodes")
        original.append(nodes)
        count = len(nodes) if contract["flatten_vars"] else 1
        rows = list(range(cursor, cursor + count))
        _require(isinstance(variable["flattened_output_rows"], list)
                 and all(_integer(x, 0) for x in variable["flattened_output_rows"])
                 and variable["flattened_output_rows"] == rows, "original variable output-row partition")
        row_groups.append(rows)
        cursor += count
        _require(cursor <= MAX_READOUT_ROWS, "readout row resource limit")
    expected_groups = [[node] for group in original for node in group] if contract["flatten_vars"] else original
    _require(prepared["var_nodes"] == expected_groups and isinstance(prepared["var_nodes"], list)
             and all(isinstance(group, list) and all(_integer(x, 0) for x in group) for group in prepared["var_nodes"]), "prepared variable order/flattening")
    for key, dtype, shape in (("node_labels", "torch.float32", [len(order), contract["node_label_encoding_dim"]]),
                              ("edges", "torch.int64", [2, 2 * len(edges)]), ("edge_labels", "torch.int64", [2 * len(edges)])):
        _tensor(batch[key], dtype, shape, budget)
        _require(batch[key] == prepared[key], "single-function batch tensor changed")
    gather = [node for group in expected_groups for node in group]
    scatter = [index for index, group in enumerate(expected_groups) for _ in group]
    _require(_tensor(batch["var_gather"], "torch.int64", [len(gather)], budget) == gather
             and _tensor(batch["var_scatter"], "torch.int64", [len(scatter)], budget) == scatter, "native collated gather/scatter")
    _require(isinstance(batch["num_vars"], list) and len(batch["num_vars"]) == 1
             and _integer(batch["num_vars"][0], 0) and batch["num_vars"] == [len(expected_groups)]
             and batch["labels_supplied_to_model"] is False, "native batch row count or supplied gold")
    readout = function["readout_contract"]
    _require(isinstance(readout, dict) and _integer(readout["original_variable_count"], 0)
             and readout["original_variable_count"] == len(variables) and _integer(readout["prepared_readout_rows"], 0)
             and readout["prepared_readout_rows"] == cursor and readout["exporter_value_row_groups"] == row_groups
             and readout["row_axis"] == ("value_node" if contract["flatten_vars"] else "variable_readout")
             and readout["logits_computed"] is False, "native readout row contract")
    _require(isinstance(readout["exporter_value_row_groups"], list)
             and all(isinstance(group, list) and all(_integer(row, 0) for row in group)
                     for group in readout["exporter_value_row_groups"]), "readout row index types")
    declared_bad = sorted({value for value in relation_ids if value < 0 or value >= contract["num_edge_ops"]})
    layer_bad = sorted({value for value in relation_ids if value < 0
                        or any(value >= cap for cap in contract["layer_relation_capacities"])})
    if declared_bad:
        findings.append({"code": "relation_ids_outside_declared_domain", "relation_ids": declared_bad})
    if layer_bad:
        findings.append({"code": "relation_ids_outside_saved_layer_domains", "relation_ids": layer_bad})
    return {"function_address": address, "is_target": function["is_target"], "node_count": len(order),
            "native_edge_count": len(edges), "prepared_relation_count": len(encoded),
            "observed_relation_ids": sorted(set(relation_ids)), "out_of_declared_domain_ids": declared_bad,
            "out_of_saved_layer_domain_ids": layer_bad, "original_variable_count": len(variables),
            "prepared_readout_rows": cursor, "exporter_value_row_groups": row_groups,
            "arch_token": function["arch_token"], "findings": findings}


def _validate(capture, expected_contract):
    _contract(expected_contract)
    _require(isinstance(capture, dict) and capture["schema"] == "symbai.native_preprocessing.v1"
             and capture["status"] in ("captured", "failed", "collecting"), "capture schema/status")
    identity = capture["request_identity"]
    _require(isinstance(identity, dict) and set(identity) == {"binary_sha256", "entry_rva"}
             and _hash(identity["binary_sha256"]) and _integer(identity["entry_rva"], 0), "capture request identity")
    _require(type(capture["forward_attempts"]) is int and capture["forward_attempts"] == 0
             and capture["model_forward_performed"] is False, "model forward attempted or performed")
    if "limits" in capture:
        limits = {"max_nodes_per_function": MAX_NODES, "max_native_edges_per_function": MAX_EDGES,
                  "max_readout_rows_per_function": MAX_READOUT_ROWS, "max_functions": MAX_FUNCTIONS}
        _require(isinstance(capture["limits"], dict) and set(capture["limits"]) == set(limits)
                 and all(type(capture["limits"][key]) is int and capture["limits"][key] == value
                         for key, value in limits.items()), "declared capture resource limits")
    complete = capture["status"] == "captured"
    origin = capture.get("receipt_origin")
    _require(origin in (None, "native_worker", "parent_recovery") and (not complete or origin == "native_worker"),
             "captured receipt must originate from native worker")
    contract, provenance = capture.get("model_contract"), capture.get("provenance")
    if complete or contract is not None:
        _contract(contract)
        _require(fingerprint(contract) == fingerprint(expected_contract), "saved model contract differs")
    if complete:
        _require(isinstance(provenance, dict) and provenance["model_sha256"] == expected_contract["model_sha256"]
                 and provenance["locator"] == "dwarf_assisted" and provenance["datagen_predict_phase"] is False
                 and provenance["ground_truth_labels_forwarded"] is False, "native generation provenance")
        for key in ("runtime", "timings_seconds", "source_sha256", "rgcn_implementation", "integrity"):
            _require(isinstance(capture[key], dict), "capture metadata object")
            _json(capture[key])
        _require(all(_number(x) for x in capture["timings_seconds"].values()), "capture timings")
        _require(bool(capture["source_sha256"]) and all(isinstance(key, str) and key and _hash(value)
                 for key, value in capture["source_sha256"].items()), "source hashes")
        _require(set(capture["integrity"]) == {"binary_unchanged", "model_unchanged", "upstream_sources_unchanged"}
                 and all(value is True for value in capture["integrity"].values()), "capture input/source integrity")
        implementation = capture["rgcn_implementation"]
        _require(isinstance(implementation.get("class"), str) and implementation["class"]
                 and isinstance(implementation.get("source_file"), str) and implementation["source_file"]
                 and _hash(implementation.get("source_file_sha256"))
                 and isinstance(implementation.get("forward_source"), str)
                 and len(implementation["forward_source"].encode("utf-8")) <= 131072
                 and implementation.get("forward_source_sha256") == hashlib.sha256(implementation["forward_source"].encode("utf-8")).hexdigest()
                 and implementation.get("behavior_executed_or_inferred") is False, "installed RGCN source evidence")
    elif provenance is not None:
        _require(isinstance(provenance, dict) and ("model_sha256" not in provenance
                 or provenance["model_sha256"] == expected_contract["model_sha256"]), "partial provenance model identity")
        _require(provenance.get("ground_truth_labels_forwarded", False) is False
                 and provenance.get("datagen_predict_phase", False) is False, "partial provenance scope")
    functions = capture["functions"]
    _require(isinstance(functions, list) and len(functions) <= MAX_FUNCTIONS, "function resource limit")
    reports, findings, addresses, budget = [], [], set(), [0]
    for index, function in enumerate(functions):
        try:
            report = _function(function, identity, expected_contract, budget)
            _require(report["function_address"] not in addresses, "duplicate generated function")
        except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
            if complete:
                raise
            findings.append({"code": "incomplete_partial_function", "function_index": index, "reason": str(error)})
            continue
        addresses.add(report["function_address"])
        reports.append(report)
        findings.extend({"function_address": report["function_address"], **finding} for finding in report["findings"])
    targets = [report for report in reports if report["is_target"]]
    _require(not complete or len(targets) == 1, "captured target function must occur exactly once")
    if not complete:
        findings.append({"code": "capture_not_complete", "capture_status": capture["status"]})
        if origin is None:
            findings.append({"code": "receipt_origin_unobserved"})
    union = lambda key: sorted({value for report in reports for value in report[key]})
    return {"schema": "symbai.native_preprocessing_validation.v1", "capture_status": capture["status"],
            "receipt_origin": origin,
            "captured": complete, "function_count": len(functions), "validated_function_count": len(reports),
            "target_function_count": len(targets), "functions": reports, "findings": findings,
            "observed_relation_ids": union("observed_relation_ids"),
            "out_of_declared_domain_ids": union("out_of_declared_domain_ids"),
            "out_of_saved_layer_domain_ids": union("out_of_saved_layer_domain_ids"),
            "observed_native_edge_count": sum(report["native_edge_count"] for report in reports),
            "observed_prepared_relation_count": sum(report["prepared_relation_count"] for report in reports),
            "model_contract_observed": contract is not None, "forward_attempts": 0, "model_forward_performed": False,
            "historical_edge_usage_observed": False, "model_forward_effects_inferred": False,
            "scope": "new_native_preprocessing_capture_not_v17_projection_or_prediction"}


def validate_native_capture(capture, expected_contract):
    """Return checked observations/findings; malformed or forward-using receipts raise ValueError."""
    try:
        return _validate(capture, expected_contract)
    except (KeyError, TypeError, AttributeError, IndexError, OverflowError, RecursionError) as error:
        raise ValueError("Invalid native preprocessing receipt: malformed structure") from error


def summarize_native_trials(rows, expected_contract):
    """Keep the direct/offset/masked three-case denominator, including failures and partials."""
    _contract(expected_contract)
    _require(isinstance(rows, list) and len(rows) <= 3 and all(isinstance(row, dict) for row in rows), "trial matrix")
    by_case = {}
    for row in rows:
        case = row.get("case_id")
        _require(isinstance(case, str) and case in CASES and case not in by_case, "trial case identity/duplicate")
        by_case[case] = row
    cases, observed, bad_declared, bad_saved, targets = [], set(), set(), set(), []
    edge_count, relation_count, forward_coverage, attempts = 0, 0, 0, 0
    forward_violation, performed = False, False
    for name in CASES:
        row = by_case.get(name)
        item = {"case_id": name, "status": "failed", "validation": None, "failure_reasons": [], "target_rows": []}
        if row is None:
            item["failure_reasons"].append("missing_planned_trial")
            cases.append(item)
            continue
        capture = row.get("payload", {}).get("worker_candidate") if isinstance(row.get("payload"), dict) else None
        if isinstance(capture, dict):
            count, ran = capture.get("forward_attempts"), capture.get("model_forward_performed")
            forward_violation |= type(count) is not int or count != 0 or ran is not False
            performed |= ran is True
        report = None
        try:
            _require(_hash(row["binary_sha256"]) and _integer(row["entry_rva"], 0), "trial input identity")
            payload, receipt = row["payload"], row["parent_receipt"]
            _require(isinstance(payload, dict) and payload["schema"] == "symbai.native_trial_payload.v1"
                     and payload["case_id"] == name and _hash(payload["request_fingerprint"]), "trial payload identity")
            _require(isinstance(capture, dict) and capture["request_identity"] == {
                "binary_sha256": row["binary_sha256"], "entry_rva": row["entry_rva"]}, "row/capture identity")
            _require(isinstance(receipt, dict) and receipt["status"] in ("captured", "failed")
                     and isinstance(receipt["validation"], dict) and _number(receipt["charged_seconds"])
                     and type(receipt["late"]) is bool and type(receipt["budget_seconds"]) in (int, float)
                     and receipt["budget_seconds"] == 60
                     and receipt["clock_unit"] == "request_through_complete_payload_persistence"
                     and receipt["excluded"] == ["final_accounting_receipt_serialization", "aggregate_copying", "offline_evaluation"], "parent accounting receipt")
            _require(receipt["payload_fingerprint"] == fingerprint(payload)
                     and receipt["payload_sha256"] == hashlib.sha256(json.dumps(payload, indent=2).encode("utf-8")).hexdigest(),
                     "persisted trial payload hashes")
            process = payload["process"]
            _require(isinstance(process, dict) and type(process["returncode"]) is int
                     and type(process["timed_out"]) is bool and _number(process["elapsed_seconds"]), "parent process outcome")
            if (capture.get("receipt_origin") == "native_worker" and capture.get("status") in ("captured", "failed")
                    and process["returncode"] == 0 and not process["timed_out"]
                    and type(capture.get("forward_attempts")) is int and capture["forward_attempts"] >= 0
                    and type(capture.get("model_forward_performed")) is bool):
                forward_coverage += 1
                attempts += capture["forward_attempts"]
            report = validate_native_capture(capture, expected_contract)
            item["validation"] = report
            good = (report["captured"] and receipt["status"] == "captured" and not receipt["late"]
                    and receipt["charged_seconds"] < 60 and not process["timed_out"] and process["returncode"] == 0)
            if good:
                _require(fingerprint(receipt["validation"]) == fingerprint(report), "parent validation differs from fresh validation")
                item["status"] = "captured"
            else:
                item["failure_reasons"].append("incomplete_failed_late_or_unsuccessful_process")
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError, RecursionError) as error:
            item["failure_reasons"].append(str(error))
        if report is not None:
            # Partial observations remain visible, while case success still needs a complete on-time receipt.
            observed.update(report["observed_relation_ids"])
            bad_declared.update(report["out_of_declared_domain_ids"])
            bad_saved.update(report["out_of_saved_layer_domain_ids"])
            edge_count += report["observed_native_edge_count"]
            relation_count += report["observed_prepared_relation_count"]
            item["target_rows"] = [{"case_id": name, "status": item["status"], "function_address": f["function_address"],
                                    "original_variable_count": f["original_variable_count"],
                                    "prepared_readout_rows": f["prepared_readout_rows"],
                                    "exporter_value_row_groups": f["exporter_value_row_groups"]}
                                   for f in report["functions"] if f["is_target"]]
            targets.extend(item["target_rows"])
        cases.append(item)
    return {"schema": "symbai.native_preprocessing_summary.v1", "planned_cases": 3, "unique_queries": 3,
            "panel": "v12_compiled_direct_offset_masked_native_integration", "case_ids": list(CASES), "cases": cases,
            "captured": sum(case["status"] == "captured" for case in cases),
            "failed": sum(case["status"] != "captured" for case in cases),
            "observed_relation_ids": sorted(observed), "observed_native_edge_count": edge_count,
            "observed_prepared_relation_count": relation_count, "out_of_declared_domain_ids": sorted(bad_declared),
            "out_of_saved_layer_domain_ids": sorted(bad_saved), "target_rows": targets,
            "forward_attempts_observed": attempts, "forward_receipts_observed": forward_coverage,
            "model_forward_performed": performed, "no_forward": forward_coverage == 3 and not forward_violation,
            "interpretation_blocked_by_forward": forward_violation, "historical_edge_usage_observed": False,
            "model_forward_effects_inferred": False, "v17_projection_validated": False,
            "scope": "new_native_preprocessing_observations_not_historical_usage_prediction_or_v17_panel"}
