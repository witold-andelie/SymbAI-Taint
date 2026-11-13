"""Fabricated native protocol counterexamples; no framework or native collection."""

from copy import deepcopy
import ast
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from src.selective_analysis.contracts import fingerprint
from src.selective_analysis import native_input_validation as native_validation
from src.selective_analysis.native_input_validation import CASES, summarize_native_trials, validate_native_capture


@pytest.fixture
def contract():
    return {"model_sha256": "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8",
            "node_label_encoding_dim": 31, "all_ops": ["mem_data", "mem_loc", "reg_data", "reg_loc", "Concat", "Extract",
                "__sub__", "__add__", "__mul__", "__floordiv__", "SDiv", "__ge__", "SLE", "__lt__", "ULE",
                "SignExt", "ZeroExt", "LShR", "__lshift__", "__rshift__", "If", "Or", "Not", "And", "Xor", "Eq",
                "fp_conv", "fp_op", "fp_cmp"], "num_all_ops": 30, "num_edge_ops": 60,
            "flatten_vars": True, "use_arch": True, "arch_fields": ["x64", "x86", "arm32", "arm64", "mips"],
            "type_count": 75, "decoder_type": "independent", "node_aggregation": "mean",
            "layer_relation_capacities": [44] * 8, "edge_reduce_op_map": {"__and__": "And", "fpToFP": "fp_conv"}}


def tensor(values, shape, dtype="torch.int64"):
    return {"dtype": dtype, "device": "cpu", "shape": shape, "values": values}


def function(contract, address=0x1129, target=True, order=None, token="arch"):
    order = [0, 1, 2] if order is None else order
    n0, n1, n2 = order
    native_edges = [(n0, n1, ["If"], 20), (n1, n2, ["unmapped_native_op"], 29),
                    (n0, n2, ["__add__", "__sub__"], 7)]
    relations = [value for _, _, _, forward in native_edges for value in (forward, forward + 30)]
    # Column pairs are source->target, target->source, in the original edge order.
    endpoints = [[value for source, target, _, _ in native_edges for value in (source, target)],
                 [value for source, target, _, _ in native_edges for value in (target, source)]]
    prefix = [float(contract["use_arch"] and token == field) for field in contract["arch_fields"]]
    features = [prefix + [0.0] * (31 - len(prefix)) for _ in order]
    originals = [[n2, n0], [n1]]
    groups = [[n2], [n0], [n1]] if contract["flatten_vars"] else originals
    row_groups = [[0, 1], [2]] if contract["flatten_vars"] else [[0], [1]]
    prepared = {"node_labels": tensor(features, [3, 31], "torch.float32"),
                "edge_labels": tensor(relations, [6]), "edges": tensor(endpoints, [2, 6]), "var_nodes": groups}
    return {"function_address": address, "function_high_pc": address + 32, "is_target": target, "arch_token": token,
            "graph_node_order": order, "node_labels": [
                {"graph_node_id": node, "bitsize": 64, "annotation_address": address,
                 "ast_value": {"kind": "int", "value": str(value)}} for node, value in zip(order, (0, 123, -1))],
            "graph_edges": [{"source": source_id, "target": target_id, "labels": labels,
                              "forward_id": forward, "inverse_id": forward + 30, "prepared_columns": [2 * i, 2 * i + 1]}
                             for i, (source_id, target_id, labels, forward) in enumerate(native_edges)],
            "variables": [{"prediction_id": f"{address:x}:{index}", "locator_variable_name": f"v{index}",
                           "function_address": address, "locations": [{"low_pc": address, "high_pc": address + 32,
                           "location_class": "CfaLocation", "location_value": -24, "location_register": None,
                           "location_argument": -24}], "original_value_nodes": nodes, "flattened_output_rows": row_groups[index]}
                          for index, nodes in enumerate(originals)],
            "prepared": prepared, "batch": {"num_vars": [len(groups)],
                **{key: deepcopy(prepared[key]) for key in ("node_labels", "edge_labels", "edges")},
                "var_gather": tensor([n2, n0, n1], [3]),
                "var_scatter": tensor([0, 1, 2] if contract["flatten_vars"] else [0, 0, 1], [3]),
                "labels_supplied_to_model": False},
            "readout_contract": {"original_variable_count": 2, "prepared_readout_rows": len(groups),
                                 "exporter_value_row_groups": row_groups,
                                 "row_axis": "value_node" if contract["flatten_vars"] else "variable_readout",
                                 "logits_computed": False}}


@pytest.fixture
def capture(contract):
    source = "def forward(self, x):\n    return x\n"
    return {"schema": "symbai.native_preprocessing.v1", "status": "captured", "receipt_origin": "native_worker",
            "request_identity": {"binary_sha256": "1" * 64, "entry_rva": 0x1129},
            "provenance": {"model_sha256": contract["model_sha256"], "locator": "dwarf_assisted",
                           "datagen_predict_phase": False, "ground_truth_labels_forwarded": False},
            "runtime": {"python": "fabricated unit metadata", "platform": "linux"},
            "model_contract": deepcopy(contract), "forward_attempts": 0, "model_forward_performed": False,
            "functions": [function(contract)], "timings_seconds": {"preprocessing": 0.1},
            "source_sha256": {"src/example.py": "2" * 64},
            "rgcn_implementation": {"class": "example.RGCNConv", "source_file": "/unit/rgcn_conv.py",
                "source_file_sha256": "3" * 64, "forward_source": source,
                "forward_source_sha256": hashlib.sha256(source.encode()).hexdigest(), "behavior_executed_or_inferred": False},
            "integrity": {"binary_unchanged": True, "model_unchanged": True, "upstream_sources_unchanged": True}}


def reseal(row):
    row["parent_receipt"]["payload_fingerprint"] = fingerprint(row["payload"])
    row["parent_receipt"]["payload_sha256"] = hashlib.sha256(json.dumps(row["payload"], indent=2).encode()).hexdigest()


def trial(name, capture, contract):
    report = validate_native_capture(capture, contract)
    row = {"case_id": name, **capture["request_identity"], "payload": {
        "schema": "symbai.native_trial_payload.v1", "case_id": name, "request_fingerprint": "4" * 64,
        "worker_candidate": deepcopy(capture), "process": {"returncode": 0, "timed_out": False, "elapsed_seconds": 1.0}},
        "parent_receipt": {"status": "captured" if report["captured"] else "failed", "charged_seconds": 1.1,
            "budget_seconds": 60, "late": False, "validation": report,
            "clock_unit": "request_through_complete_payload_persistence",
            "excluded": ["final_accounting_receipt_serialization", "aggregate_copying", "offline_evaluation"]}}
    reseal(row)
    return row


def test_faithful_capture_retains_domain_unknown_and_architecture_findings(capture, contract):
    before = deepcopy(capture)
    report = validate_native_capture(capture, contract)
    assert report["captured"] and report["function_count"] == report["target_function_count"] == 1
    assert report["observed_relation_ids"] == [7, 20, 29, 37, 50, 59]
    assert report["out_of_saved_layer_domain_ids"] == [50, 59]
    assert report["out_of_declared_domain_ids"] == []
    codes = {finding["code"] for finding in report["findings"]}
    assert {"unknown_label_encoding", "architecture_token_zero_encoding", "relation_ids_outside_saved_layer_domains"} <= codes
    assert report["functions"][0]["exporter_value_row_groups"] == [[0, 1], [2]]
    assert not report["historical_edge_usage_observed"] and not report["model_forward_effects_inferred"]
    assert capture == before


@pytest.mark.parametrize("order", [[2, 0, 1], [10, 11, 12]])
def test_nonrange_node_order_is_finding_without_reordering(capture, contract, order):
    capture["functions"] = [function(contract, order=order)]
    report = validate_native_capture(capture, contract)
    assert report["captured"]
    assert any(row["code"] == "graph_node_order_not_feature_row_range" for row in report["findings"])
    assert capture["functions"][0]["graph_node_order"] == order


def test_raw_architecture_known_and_use_arch_false_are_encoded_as_recorded(capture, contract):
    capture["functions"] = [function(contract, token="x64")]
    assert validate_native_capture(capture, contract)["captured"]
    contract["use_arch"] = False
    capture["model_contract"] = deepcopy(contract)
    capture["functions"] = [function(contract, token="x64")]
    assert validate_native_capture(capture, contract)["captured"]


def test_false_flattening_retains_native_groups_and_batch_scatter(capture, contract):
    contract["flatten_vars"] = False
    capture["model_contract"] = deepcopy(contract)
    capture["functions"] = [function(contract)]
    report = validate_native_capture(capture, contract)
    assert report["functions"][0]["prepared_readout_rows"] == 2
    assert report["functions"][0]["exporter_value_row_groups"] == [[0], [1]]


def test_edge_encoder_uses_first_sorted_label_not_last(capture, contract):
    edge = capture["functions"][0]["graph_edges"][2]
    assert edge["labels"] == ["__add__", "__sub__"] and edge["forward_id"] == 7
    assert validate_native_capture(capture, contract)["captured"]
    edge["forward_id"], edge["inverse_id"] = 6, 36
    capture["functions"][0]["prepared"]["edge_labels"]["values"][4:] = [6, 36]
    capture["functions"][0]["batch"]["edge_labels"]["values"][4:] = [6, 36]
    with pytest.raises(ValueError, match="first-sorted-label"):
        validate_native_capture(capture, contract)


def test_reduced_edge_label_uses_saved_map(capture, contract):
    f = capture["functions"][0]
    f["graph_edges"][0].update(labels=["__and__"], forward_id=23, inverse_id=53)
    for stage in ("prepared", "batch"):
        f[stage]["edge_labels"]["values"][:2] = [23, 53]
    assert validate_native_capture(capture, contract)["observed_relation_ids"] == [7, 23, 29, 37, 53, 59]


@pytest.mark.parametrize("names", [["__sub__", "__add__"], ["__and__", "reg_loc"],
                                    ["AAA_unknown", "If"], ["If", "ZZZ_unknown"]])
def test_multilabel_validation_matches_actual_upstream_pure_encoder(capture, contract, names):
    # Execute only this reviewed pure function, not module imports, classes or a model.
    path = Path(__file__).resolve().parents[1] / "tygr_original/src/methods/glow/preproc.py"
    if not path.is_file():
        pytest.skip("Pinned optional upstream source is not available")
    function_node = next(node for node in ast.parse(path.read_text(encoding="utf-8")).body
                         if isinstance(node, ast.FunctionDef) and node.name == "encode_edge_label")
    assert len(function_node.body) == 1 and isinstance(function_node.body[0], ast.For)
    assert isinstance(function_node.body[0].body[-1], ast.Return)
    for argument in function_node.args.args:
        argument.annotation = None
    function_node.returns = None
    namespace = {"REDUCE_OP_MAP": contract["edge_reduce_op_map"]}
    exec(compile(ast.Module(body=[function_node], type_ignores=[]), str(path), "exec"), namespace)
    encode = namespace["encode_edge_label"]
    config = SimpleNamespace(**contract)
    f = capture["functions"][0]
    forward, inverse = encode(set(names), False, config), encode(set(names), True, config)
    f["graph_edges"][2].update(labels=sorted(names), forward_id=forward, inverse_id=inverse)
    for stage in ("prepared", "batch"):
        f[stage]["edge_labels"]["values"][4:] = [forward, inverse]
    assert validate_native_capture(capture, contract)["captured"]


def test_out_of_declared_domain_is_observed_finding_not_erased(capture, contract):
    f = capture["functions"][0]
    f["graph_edges"][0].update(forward_id=60, inverse_id=90)
    for stage in ("prepared", "batch"):
        f[stage]["edge_labels"]["values"][:2] = [60, 90]
    report = validate_native_capture(capture, contract)
    assert report["captured"] and report["out_of_declared_domain_ids"] == [60, 90]
    assert any(row["code"] == "native_encoding_differs_from_saved_label_formula" for row in report["findings"])


def test_negative_native_relation_ids_are_retained_as_domain_findings(capture, contract):
    f = capture["functions"][0]
    f["graph_edges"][0].update(forward_id=-1, inverse_id=29)
    for stage in ("prepared", "batch"):
        f[stage]["edge_labels"]["values"][:2] = [-1, 29]
    report = validate_native_capture(capture, contract)
    assert report["captured"] and report["out_of_declared_domain_ids"] == [-1]


def test_readout_indices_do_not_coerce_bool_to_integer(capture, contract):
    capture["functions"][0]["readout_contract"]["exporter_value_row_groups"] = [[False, True], [2]]
    with pytest.raises(ValueError, match="index types"):
        validate_native_capture(capture, contract)


@pytest.mark.parametrize("damage", ["missing_target", "duplicate_target", "wrong_target", "node_order", "ast_int", "ast_bool", "ast_float",
    "edge_order", "edge_columns", "edge_labels_unsorted", "edge_ids", "inverse_offset", "tensor_shape", "tensor_dtype", "cuda", "nonfinite",
    "architecture_prefix", "var_order", "row_partition", "prediction_id", "location", "gather", "scatter", "num_vars", "batch_features",
    "row_axis", "computed_logits", "gold_labels", "contract", "model_hash", "forward_attempt", "forward_performed", "integrity", "rgcn_source"])
def test_malformed_capture_counterexamples_are_rejected(capture, contract, damage):
    f = capture["functions"][0]
    if damage == "missing_target": capture["functions"] = [function(contract, address=0x1200, target=False)]
    elif damage == "duplicate_target": capture["functions"].append(deepcopy(f))
    elif damage == "wrong_target": f["is_target"] = False
    elif damage == "node_order": f["node_labels"][0]["graph_node_id"] = 1
    elif damage == "ast_int": f["node_labels"][0]["ast_value"]["value"] = "0x01"
    elif damage == "ast_bool": f["node_labels"][0]["ast_value"] = {"kind": "bool", "value": 1}
    elif damage == "ast_float": f["node_labels"][0]["ast_value"] = {"kind": "float", "value": 1.5}
    elif damage == "edge_order": f["graph_edges"][0], f["graph_edges"][1] = f["graph_edges"][1], f["graph_edges"][0]
    elif damage == "edge_columns": f["graph_edges"][0]["prepared_columns"] = [1, 0]
    elif damage == "edge_labels_unsorted": f["graph_edges"][2]["labels"].reverse()
    elif damage == "edge_ids": f["prepared"]["edge_labels"]["values"][0] = 0
    elif damage == "inverse_offset": f["graph_edges"][0]["inverse_id"] = 51
    elif damage == "tensor_shape": f["prepared"]["node_labels"]["shape"][0] = 4
    elif damage == "tensor_dtype": f["prepared"]["edges"]["dtype"] = "torch.float32"
    elif damage == "cuda": f["prepared"]["node_labels"]["device"] = "cuda:0"
    elif damage == "nonfinite": f["prepared"]["node_labels"]["values"][0][-1] = float("nan")
    elif damage == "architecture_prefix": f["prepared"]["node_labels"]["values"][0][0] = 1.0
    elif damage == "var_order": f["prepared"]["var_nodes"].reverse()
    elif damage == "row_partition": f["variables"][0]["flattened_output_rows"] = [1, 0]
    elif damage == "prediction_id": f["variables"][0]["prediction_id"] = "1129:99"
    elif damage == "location": f["variables"][0]["locations"][0]["location_value"] = 24
    elif damage == "gather": f["batch"]["var_gather"]["values"].reverse()
    elif damage == "scatter": f["batch"]["var_scatter"]["values"] = [0, 0, 0]
    elif damage == "num_vars": f["batch"]["num_vars"] = [2]
    elif damage == "batch_features": f["batch"]["node_labels"]["values"][0][-1] = 1.0
    elif damage == "row_axis": f["readout_contract"]["row_axis"] = "variable_readout"
    elif damage == "computed_logits": f["readout_contract"]["logits_computed"] = True
    elif damage == "gold_labels": f["batch"]["labels_supplied_to_model"] = True
    elif damage == "contract": capture["model_contract"]["type_count"] = 74
    elif damage == "model_hash": capture["provenance"]["model_sha256"] = "0" * 64
    elif damage == "forward_attempt": capture["forward_attempts"] = 1
    elif damage == "forward_performed": capture["model_forward_performed"] = True
    elif damage == "integrity": capture["integrity"]["binary_unchanged"] = False
    else: capture["rgcn_implementation"]["forward_source"] += "# changed"
    with pytest.raises(ValueError):
        validate_native_capture(capture, contract)


@pytest.mark.parametrize("kind,value", [("bool", True), ("float", "0x1.8000000000000p+0"), ("float", "nan"), ("float", "-inf")])
def test_native_scalar_representations_preserved_without_filling(capture, contract, kind, value):
    capture["functions"][0]["node_labels"][0]["ast_value"] = {"kind": kind, "value": value}
    assert validate_native_capture(capture, contract)["captured"]


def test_early_failure_without_model_contract_and_partial_functions_are_retained(capture, contract):
    capture.update(status="failed", model_contract=None, functions=[], runtime={})
    report = validate_native_capture(capture, contract)
    assert not report["captured"] and not report["model_contract_observed"] and report["function_count"] == 0
    capture["functions"] = [function(contract), {"function_address": 99}]
    report = validate_native_capture(capture, contract)
    assert report["function_count"] == 2 and report["validated_function_count"] == 1 and not report["captured"]
    assert report["observed_relation_ids"] == [7, 20, 29, 37, 50, 59]


def test_every_generated_function_is_retained_not_only_target(capture, contract):
    capture["functions"].append(function(contract, address=0x1200, target=False))
    report = validate_native_capture(capture, contract)
    assert report["function_count"] == 2 and report["observed_native_edge_count"] == 6


def test_summary_preserves_complete_three_case_denominator_and_new_native_scope(capture, contract):
    rows = [trial(name, capture, contract) for name in CASES]
    before = deepcopy(rows)
    result = summarize_native_trials(rows, contract)
    assert result["planned_cases"] == result["captured"] == 3 and result["failed"] == 0
    assert result["case_ids"] == list(CASES) and result["observed_native_edge_count"] == 9
    assert result["observed_prepared_relation_count"] == 18 and result["out_of_saved_layer_domain_ids"] == [50, 59]
    assert result["no_forward"] and len(result["target_rows"]) == 3
    assert not result["historical_edge_usage_observed"] and not result["model_forward_effects_inferred"] and not result["v17_projection_validated"]
    assert rows == before


@pytest.mark.parametrize("damage", ["timeout", "nonzero", "late", "clock", "hash", "fingerprint", "identity", "validation"])
def test_failed_or_tampered_parent_receipts_never_count_success(capture, contract, damage):
    rows = [trial(name, capture, contract) for name in CASES]
    row = rows[0]
    if damage == "timeout": row["payload"]["process"]["timed_out"] = True
    elif damage == "nonzero": row["payload"]["process"]["returncode"] = 1
    elif damage == "late": row["parent_receipt"]["late"] = True
    elif damage == "clock": row["parent_receipt"]["charged_seconds"] = 60.1
    elif damage == "hash": row["parent_receipt"]["payload_sha256"] = "0" * 64
    elif damage == "fingerprint": row["parent_receipt"]["payload_fingerprint"] = "0" * 64
    elif damage == "identity": row["entry_rva"] += 1
    else: row["parent_receipt"]["validation"]["captured"] = False
    if damage not in ("hash", "fingerprint"):
        reseal(row)
    report = summarize_native_trials(rows, contract)
    assert report["planned_cases"] == 3 and report["captured"] == 2 and report["failed"] == 1


def test_missing_and_partial_failed_cases_stay_in_matrix(capture, contract):
    good = trial(CASES[0], capture, contract)
    capture["status"] = "failed"
    partial = trial(CASES[1], capture, contract)
    report = summarize_native_trials([partial, good], contract)
    assert report["captured"] == 1 and report["failed"] == 2
    assert report["observed_native_edge_count"] == 6
    assert report["cases"][1]["target_rows"][0]["status"] == "failed"
    assert report["cases"][2]["failure_reasons"] == ["missing_planned_trial"]
    assert not report["no_forward"]


def test_forward_attempt_on_failed_capture_blocks_interpretation(capture, contract):
    rows = [trial(name, capture, contract) for name in CASES]
    failed = rows[0]["payload"]["worker_candidate"]
    failed.update(status="failed", forward_attempts=1)
    rows[0]["parent_receipt"]["status"] = "failed"
    reseal(rows[0])
    report = summarize_native_trials(rows, contract)
    assert report["captured"] == 2 and report["failed"] == 1
    assert report["interpretation_blocked_by_forward"] and report["forward_attempts_observed"] == 1 and not report["no_forward"]


def test_corrupt_payload_observations_are_not_in_summary(capture, contract):
    row = trial(CASES[0], capture, contract)
    row["parent_receipt"]["payload_sha256"] = "0" * 64
    report = summarize_native_trials([row], contract)
    assert report["captured"] == 0 and report["failed"] == 3 and report["observed_relation_ids"] == []
    assert not report["no_forward"] and report["forward_receipts_observed"] == 0


def test_v17_panel_and_duplicate_trials_are_rejected(capture, contract):
    row = trial("scalar_span", capture, contract)
    with pytest.raises(ValueError):
        summarize_native_trials([row], contract)
    row["case_id"] = CASES[0]
    with pytest.raises(ValueError):
        summarize_native_trials([row, row], contract)


def test_only_pure_protocol_modules_are_imported(capture, contract):
    before = set(sys.modules)
    validate_native_capture(capture, contract)
    summarize_native_trials([trial(CASES[0], capture, contract)], contract)
    assert not [name for name in set(sys.modules) - before if name.split(".")[0] in ("torch", "angr", "claripy", "pyvex", "archinfo")]


@pytest.mark.parametrize("limit,value", [("MAX_NODES", 2), ("MAX_EDGES", 2), ("MAX_VARIABLES", 1),
                                        ("MAX_READOUT_ROWS", 2), ("MAX_TENSOR_VALUES", 1), ("MAX_FUNCTIONS", 0)])
def test_declared_resource_limits_are_enforced(capture, contract, monkeypatch, limit, value):
    monkeypatch.setattr(native_validation, limit, value)
    with pytest.raises(ValueError):
        validate_native_capture(capture, contract)


def test_three_parent_recovery_placeholders_do_not_establish_forward_coverage(capture, contract):
    capture.update(status="failed", receipt_origin="parent_recovery", model_contract=None, functions=[],
                   runtime={}, rgcn_implementation=None, integrity={})
    rows = [trial(name, capture, contract) for name in CASES]
    result = summarize_native_trials(rows, contract)
    assert result["captured"] == 0 and result["failed"] == result["planned_cases"] == 3
    assert result["forward_receipts_observed"] == 0 and not result["no_forward"]
    assert result["observed_relation_ids"] == [] and result["target_rows"] == []
    assert not result["interpretation_blocked_by_forward"]


@pytest.mark.parametrize("origin", [None, "parent_recovery"])
def test_captured_receipt_requires_native_worker_origin(capture, contract, origin):
    if origin is None:
        capture.pop("receipt_origin")
    else:
        capture["receipt_origin"] = origin
    with pytest.raises(ValueError, match="originate"):
        validate_native_capture(capture, contract)


def test_absent_origin_cannot_be_upgraded_by_resigned_parent_envelope(capture, contract):
    rows = [trial(name, capture, contract) for name in CASES]
    for row in rows:
        row["payload"]["worker_candidate"].pop("receipt_origin")
        reseal(row)
    result = summarize_native_trials(rows, contract)
    assert result["captured"] == 0 and result["failed"] == 3
    assert result["forward_receipts_observed"] == 0 and not result["no_forward"]


@pytest.mark.parametrize("process_change,expected_coverage", [
    ({}, 3), ({"timed_out": True}, 0), ({"returncode": -9}, 0),
])
def test_failed_native_worker_final_receipts_count_only_after_successful_process_completion(
        capture, contract, process_change, expected_coverage):
    capture.update(status="failed", model_contract=None, functions=[], runtime={}, rgcn_implementation=None)
    rows = [trial(name, capture, contract) for name in CASES]
    for row in rows:
        row["payload"]["process"].update(process_change)
        reseal(row)
    result = summarize_native_trials(rows, contract)
    assert result["captured"] == 0 and result["failed"] == 3
    assert result["forward_receipts_observed"] == expected_coverage
    assert result["no_forward"] is (expected_coverage == 3)


def test_timed_out_native_partial_keeps_observations_without_forward_coverage(capture, contract):
    capture["status"] = "collecting"
    row = trial(CASES[0], capture, contract)
    row["payload"]["process"].update(timed_out=True, returncode=-9)
    reseal(row)
    result = summarize_native_trials([row], contract)
    assert result["failed"] == 3 and result["observed_native_edge_count"] == 3
    assert result["target_rows"][0]["status"] == "failed"
    assert result["forward_receipts_observed"] == 0 and not result["no_forward"]


def test_collecting_worker_intermediate_is_not_a_final_forward_receipt(capture, contract):
    capture["status"] = "collecting"
    rows = [trial(name, capture, contract) for name in CASES]
    result = summarize_native_trials(rows, contract)
    assert result["failed"] == 3 and result["observed_native_edge_count"] == 9
    assert result["forward_receipts_observed"] == 0 and not result["no_forward"]


def test_forward_clue_blocks_interpretation_even_with_invalid_parent_recovery_envelope(capture, contract):
    capture.update(status="failed", receipt_origin="parent_recovery", model_contract=None, functions=[])
    row = trial(CASES[0], capture, contract)
    row["payload"]["worker_candidate"]["forward_attempts"] = 1
    # Deliberately leave both hashes stale: the clue must still prevent a no-forward claim.
    result = summarize_native_trials([row], contract)
    assert result["failed"] == 3 and result["interpretation_blocked_by_forward"]
    assert result["forward_receipts_observed"] == 0 and not result["no_forward"]
