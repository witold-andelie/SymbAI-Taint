"""Keep labels, source-variable identities and flattened graph rows distinct."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.selective_analysis.type_graph_dataset import admit_supervision, validate_native, source_facts
from src.selective_analysis.type_corpus import UpstreamLabels, runtime_path


def example():
    nodes = [{"id": 0, "value": "984", "annotation_address": None},
             {"id": 1, "value": "7", "annotation_address": 105},
             {"id": 2, "value": "8", "annotation_address": 106}]
    graph = {"nodes": nodes, "edges": [{"source": 0, "target": n, "labels": ["mem_loc"]} for n in (1, 2)]}
    matrix = {"shape": [3, 31], "values": [[1., 0., 0., 0., 0.] + [0.] * 26 for _ in nodes]}
    relations = {"shape": [4], "values": [1, 31, 1, 31]}
    edges = {"shape": [2, 4], "values": [[0, 1, 0, 2], [1, 0, 2, 0]]}
    native = {"graph_node_order": [0, 1, 2], "variables": [{"locator_variable_name": "value",
        "original_value_nodes": [1, 2], "flattened_output_rows": [0, 1],
        "locations": [{"location_class": "CfaLocation", "location_argument": -24, "low_pc": 100, "high_pc": 120}]}],
        "graph_edges": [{"source": 0, "target": n, "forward_id": 1, "inverse_id": 31} for n in (1, 2)],
        "prepared": {"var_nodes": [[1], [2]], "node_labels": deepcopy(matrix),
            "edge_labels": deepcopy(relations), "edges": deepcopy(edges)},
        "batch": {"var_gather": {"values": [1, 2]}, "var_scatter": {"values": [0, 1]},
            "num_vars": [2], "labels_supplied_to_model": False, "node_labels": matrix,
            "edge_labels": relations, "edges": edges}}
    payload = {"status": "captured", "model_loaded": False, "model_load_attempts": 0,
        "model_forward_attempts": 0, "original_sources_rechecked": True, "binary_sha256": "elf-hash", "function_address": 100,
        "data_contract": {"feature_width": 31, "declared_relation_count": 60, "type_count": 75},
        "configured_initial_sp": 1000, "stage": {"step_exceptions": [], "splices": [{
            "before": graph, "after": deepcopy(graph), "mapping": {"0": 0, "1": 1, "2": 2}}]},
        "native_input": native, "lookup_calls": [{"name": "value", "pre_splice_nodes": [1, 2],
            "prepared_locations": [{"low_pc": 100, "high_pc": 120, "form": "addr", "value": 984}]}]}
    source = {"facts": {"function_address": 100, "entry_cfa_offset": 8,
        "variables": [{"die_offset": 20, "name": "value", "cfa_offset": -24, "range": [100, 120]}]}, "exclusions": {}}
    variables = [{"function_id": "project:f:100", "variable_die_offset": 20, "name": "value", "class_id": 12,
        "label": "type12", "status": "mapped", "before_normalization": "type12"}]
    vocabulary = ["type" + str(i) for i in range(75)]
    return payload, source, variables, vocabulary


def test_one_source_variable_has_two_rows_but_unit_total_loss_weight():
    payload, source, variables, vocab = example()
    unchanged = deepcopy(payload)
    features, supervision, review = admit_supervision(payload, source, variables, vocab)
    target, = supervision["targets"]
    assert target["readout_rows"] == [0, 1] and target["per_row_loss_weight"] == .5
    assert review["admitted_source_variables"] == 1 and review["supervised_value_rows"] == 2
    assert "class_id" not in json.dumps(features) and "type12" not in json.dumps(features)
    assert features["relation_count"] == 60 and payload == unchanged


def test_whole_struct_exclusion_cannot_label_member_rows():
    payload, source, variables, vocab = example()
    source["exclusions"] = {"20": "whole_struct_requires_separate_member_supervision"}
    source["facts"]["variables"] = []
    _, supervision, review = admit_supervision(payload, source, variables, vocab)
    assert not supervision["targets"] and review["candidate_source_variables"] == 1
    assert review["variables"][0]["status"] == "excluded"


def test_missing_mapping_is_not_replaced_with_class_zero():
    payload, source, variables, vocab = example()
    payload["lookup_calls"][0]["prepared_locations"][0]["value"] = 983
    _, supervision, review = admit_supervision(payload, source, variables, vocab)
    assert not supervision["targets"]
    assert "lookup_location_or_membership_differs" in review["variables"][0]["reasons"]


def test_same_readout_claimed_by_two_source_dies_is_excluded_even_with_same_class():
    payload, source, variables, vocab = example()
    source["facts"]["variables"].append(dict(source["facts"]["variables"][0], die_offset=21))
    variables.append(dict(variables[0], variable_die_offset=21))
    _, targets, review = admit_supervision(payload, source, variables, vocab)
    assert targets["targets"] == [] and review["candidate_source_variables"] == 2
    assert all("multiple_source_variables_claim_same_readout_row" in row["reasons"] for row in review["variables"])


def test_class_identity_mismatch_is_not_used_to_repair_correspondence():
    payload, source, variables, vocab = example()
    variables[0]["class_id"] = 13
    _, targets, review = admit_supervision(payload, source, variables, vocab)
    assert not targets["targets"]
    assert review["variables"][0]["reasons"] == ["inventory_class_vocabulary_mismatch"]


def test_conflicting_labels_on_shared_graph_values_are_not_training_targets():
    payload, source, variables, vocab = example()
    native = payload["native_input"]
    native["variables"].append(dict(deepcopy(native["variables"][0]),
        locator_variable_name="other", flattened_output_rows=[2, 3]))
    native["prepared"]["var_nodes"] += [[1], [2]]
    native["batch"]["var_gather"]["values"] += [1, 2]
    native["batch"]["var_scatter"]["values"] += [2, 3]
    native["batch"]["num_vars"] = [4]
    payload["lookup_calls"].append(dict(deepcopy(payload["lookup_calls"][0]), name="other"))
    source["facts"]["variables"].append(dict(source["facts"]["variables"][0], die_offset=21, name="other"))
    variables.append(dict(variables[0], variable_die_offset=21, name="other", class_id=13, label="type13"))
    _, targets, review = admit_supervision(payload, source, variables, vocab)
    assert targets["targets"] == []
    assert all("shared_graph_value_has_conflicting_source_labels" in r["reasons"] for r in review["variables"])


@pytest.mark.parametrize("damage", ["edge_endpoint", "edge_projection", "nonfinite", "node_order", "row_owner", "execution_error"])
def test_corrupt_graph_cannot_become_a_training_example(damage):
    payload, *_ = example()
    native = payload["native_input"]
    if damage == "edge_endpoint":
        for name in ("batch", "prepared"):
            native[name]["edges"]["values"][0][0] = 3
    elif damage == "edge_projection":
        native["graph_edges"][0]["inverse_id"] = 59
    elif damage == "nonfinite":
        for name in ("batch", "prepared"):
            native[name]["node_labels"]["values"][0][5] = float("inf")
    elif damage == "node_order":
        native["graph_node_order"] = [1, 0, 2]
    elif damage == "row_owner":
        native["variables"][0]["flattened_output_rows"] = [1, 0]
    else:
        payload["stage"]["step_exceptions"] = [{"type": "RuntimeError"}]
    with pytest.raises(ValueError):
        validate_native(payload)


def test_all_eight_reviewed_real_locations_can_generate_separate_targets():
    root = Path(__file__).resolve().parents[2]
    mapping = root / ".scratch/selective_analysis/route-b-type-mapping-20261119T223020304246Z"
    if not mapping.is_dir():
        pytest.skip("Optional local reviewed integration evidence absent")
    inventory = runtime_path(json.loads((mapping / "plan.json").read_bytes())["prior_inventory"])
    plan = json.loads((inventory / "mapping-probe-plan.json").read_bytes())
    vocabulary = UpstreamLabels(root / "SymbAI-Taint/tygr_original").vocabulary
    admitted, rows = 0, 0
    for case in plan["cases"]:
        labels = json.loads((inventory / (case["project_id"] + "-O0.labels.json")).read_bytes())
        variables = [v for v in labels["variables"] if v["variable_die_offset"] in case["selected_variable_die_offsets"]]
        source = source_facts(runtime_path(case["binary"]), case["function_address"], variables)
        payload = json.loads((mapping / case["project_id"] / "raw.json").read_bytes())
        _, _, review = admit_supervision(payload, source, variables, vocabulary)
        admitted += review["admitted_source_variables"]
        rows += review["supervised_value_rows"]
    assert admitted == 8 and rows == 80
