"""Mapping evidence must preserve slot, lifetime, node identity and row membership."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.selective_analysis.variable_mapping import matching_nodes, offline_facts, review_mapping
from src.selective_analysis.type_corpus import runtime_path


def example():
    facts = {"function_address": 100, "entry_cfa_offset": 8,
        "variables": [{"die_offset": 20, "name": "value", "cfa_offset": -24, "range": [100, 120]}]}
    graph = {"nodes": [{"id": 0, "value": "984", "annotation_address": None},
        {"id": 1, "value": "7", "annotation_address": 105}],
        "edges": [{"source": 0, "target": 1, "labels": ["mem_loc"]}]}
    native = {"graph_node_order": [0, 1], "variables": [{"locator_variable_name": "value",
        "original_value_nodes": [1], "flattened_output_rows": [0],
        "locations": [{"location_class": "CfaLocation", "location_argument": -24, "low_pc": 100, "high_pc": 120}]}],
        "prepared": {"var_nodes": [[1]]}, "batch": {"var_gather": {"values": [1]},
        "var_scatter": {"values": [0]}, "num_vars": [1], "labels_supplied_to_model": False,
        "node_labels": {"shape": [2, 31], "values": [[1.,0.,0.,0.,0.] + [0.] * 26] * 2},
        "edge_labels": {"values": [1, 31]}}}
    payload = {"status": "captured", "model_loaded": False, "model_load_attempts": 0,
        "model_forward_attempts": 0, "original_sources_rechecked": True, "function_address": 100,
        "data_contract": {"feature_width": 31, "declared_relation_count": 60, "type_count": 75},
        "configured_initial_sp": 1000, "stage": {"step_exceptions": [], "splices": [{
            "before": graph, "after": deepcopy(graph), "mapping": {"0": 0, "1": 1}}]},
        "native_input": native, "lookup_calls": [{"name": "value", "pre_splice_nodes": [1],
            "prepared_locations": [{"low_pc": 100, "high_pc": 120, "form": "addr", "value": 984}]}]}
    return facts, payload


def test_fixed_cfa_location_and_readout_agree():
    facts, payload = example()
    before = deepcopy(payload)
    result = review_mapping(payload, facts)
    assert result["consistent_variables"] == 1
    assert result["variables"][0]["expected_stack_address"] == 984
    assert payload == before


@pytest.mark.parametrize("damage", ["slot", "lifetime", "readout", "row_order", "architecture", "relation_domain", "step_exception"])
def test_correspondence_damage_stays_unresolved(damage):
    facts, payload = example()
    if damage == "slot":
        payload["lookup_calls"][0]["prepared_locations"][0]["value"] += 1
    elif damage == "lifetime":
        facts["variables"][0]["range"] = [110, 120]
    elif damage == "readout":
        payload["native_input"]["batch"]["var_gather"]["values"] = [0]
    elif damage == "row_order":
        payload["native_input"]["graph_node_order"] = [1, 0]
    elif damage == "architecture":
        payload["native_input"]["batch"]["node_labels"]["values"] = [[0.] * 31] * 2
    elif damage == "relation_domain":
        payload["native_input"]["batch"]["edge_labels"]["values"].append(60)
    else:
        payload["stage"]["step_exceptions"] = [{"type": "ValueError"}]
    result = review_mapping(payload, facts)
    assert result["consistent_variables"] == 0 and result["variables"][0]["reasons"]


def test_post_splice_node_replacement_is_not_accepted():
    facts, payload = example()
    payload["stage"]["splices"][0]["after"]["nodes"][1]["value"] = "8"
    with pytest.raises(ValueError, match="node identity"):
        review_mapping(payload, facts)


def test_location_matching_requires_location_edge_and_half_open_pc_range():
    facts, payload = example()
    graph = payload["stage"]["splices"][0]["before"]
    assert matching_nodes(graph, 984, [100, 105]) == set()
    assert matching_nodes(graph, 984, [100, 106]) == {1}
    graph["edges"][0]["labels"] = ["mem_data"]
    assert matching_nodes(graph, 984, [100, 120]) == set()


def test_eight_retained_probe_locations_are_read_without_type_labels():
    root = Path(__file__).resolve().parents[2] / ".scratch/selective_analysis/route-b-type-corpus-v2-20261119T220534466210Z/labels-20261119T220848049235Z"
    path = root / "mapping-probe-plan.json"
    if not path.is_file():
        pytest.skip("Optional fixed local probe inputs absent")
    plan = json.loads(path.read_bytes())
    count = 0
    for case in plan["cases"]:
        facts = offline_facts(runtime_path(case["binary"]), case["function_address"], case["selected_variable_die_offsets"])
        assert facts["reference_type_attributes_used"] is False
        assert facts["entry_cfa_offset"] == 8 and len(facts["variables"]) == 2
        assert all(row["cfa_offset"] < 0 for row in facts["variables"])
        count += len(facts["variables"])
    assert count == 8
