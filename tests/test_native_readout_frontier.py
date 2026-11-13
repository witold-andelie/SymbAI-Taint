"""Fabricated native graphs only; no framework, model or retained panel executes."""

from copy import deepcopy
import sys

import pytest

from src.selective_analysis import native_readout_frontier as frontier


@pytest.fixture
def graph():
    request = {"schema": "symbai.native_readout_request.v1", "binary": "D:/unit/never-opened.elf",
               "binary_sha256": "a" * 64, "entry_rva": 100, "write_rva": 140,
               "native_capture_fingerprint": "b" * 64}
    contract = {"all_ops": ["mem_loc", "mem_data", "reg_loc", "reg_data", "__add__", "And", "fp_op"],
                "edge_reduce_op_map": {"__and__": "And", "fpAdd": "fp_op"}, "flatten_vars": True}
    labels = [{"graph_node_id": node, "bitsize": 8 if node in (6, 7) else 64,
               "annotation_address": 140 if node in (6, 7) else 120,
               "ast_value": {"kind": "int", "value": "0"}} for node in range(8)]
    edges = [{"source": source, "target": target, "labels": names} for source, target, names in (
        (0, 6, ["mem_loc"]), (0, 7, ["mem_loc"]), (1, 0, ["reg_data"]),
        (2, 1, ["__add__"]), (3, 1, ["__add__"]),
        (4, 2, ["mem_data"]),  # This earlier member lies behind the first readout boundary.
        (5, 0, ["reg_loc"]),
    )]
    function = {"function_address": 100, "is_target": True, "graph_node_order": list(range(8)),
                "node_labels": labels, "graph_edges": edges,
                "variables": [{"prediction_id": "opaque-one", "locator_variable_name": "misleading-pointer",
                               "original_value_nodes": [2, 4], "flattened_output_rows": [0, 1]},
                              {"prediction_id": "opaque-two", "locator_variable_name": "misleading-index",
                               "original_value_nodes": [3], "flattened_output_rows": [2]}],
                "prepared": {"var_nodes": [[2], [4], [3]]},
                "readout_contract": {"original_variable_count": 2, "prepared_readout_rows": 3,
                                     "exporter_value_row_groups": [[0, 1], [2]]}}
    return request, function, contract


def inspect(graph):
    return frontier.inspect_native_frontier(*graph)


def member_keys(report):
    return [(member["group_index"], member["output_row"], member["node_id"]) for member in report["frontier_members"]]


def test_all_same_root_target_candidates_survive_without_unique_event_claim(graph):
    report = inspect(graph)
    assert report["schema"] == "symbai.native_readout_frontier.v1"
    assert report["target_candidates_count"] == 2
    assert [candidate["target_node_id"] for candidate in report["targets"]] == [6, 7]
    assert report["unique_address_roots"] == [0] and report["unique_address_root_count"] == 1
    assert all(candidate["address_roots"] == [0] for candidate in report["targets"])
    assert report["frontier_member_count"] == 2
    assert member_keys(report) == [(0, 0, 2), (1, 2, 3)]
    for name in ("exact_event_verified", "semantic_roles_verified", "prediction_aggregation_changed",
                 "semantic_dependency_completeness_claimed", "new_model_output_computed",
                 "native_capture_identity_verified_by_this_function"):
        assert report[name] is False


def test_reverse_value_paths_stop_at_first_readout_and_preserve_full_native_groups(graph):
    before = deepcopy(graph)
    report = inspect(graph)
    assert graph == before
    root, = report["roots"]
    assert root["frontier_members"][0]["path_witness"] == {"node_ids": [0, 1, 2], "edge_indices": [2, 3]}
    assert root["frontier_members"][1]["path_witness"] == {"node_ids": [0, 1, 3], "edge_indices": [2, 4]}
    assert 4 not in root["visited_node_ids"] and 5 not in root["traversed_edge_indices"]
    assert report["original_groups"] == [
        {"group_index": 0, "original_value_nodes": [2, 4], "flattened_output_rows": [0, 1]},
        {"group_index": 1, "original_value_nodes": [3], "flattened_output_rows": [2]},
    ]
    report["original_groups"][0]["original_value_nodes"].clear()
    assert graph == before


def test_cycles_are_reported_without_infinite_recursion_or_dropping_members(graph):
    graph[1]["graph_edges"].append({"source": 0, "target": 1, "labels": ["__add__"]})
    report = inspect(graph)
    assert report["cycle_count"] == 1 and report["frontier_member_count"] == 2
    cycle, = report["roots"][0]["cycles"]
    assert cycle["node_ids"] == [0, 1, 0]
    assert cycle["edge_indices"] == [2, 7]
    assert len(report["roots"][0]["visited_node_ids"]) == 4


def test_dag_reconvergence_is_not_misclassified_as_cycle(graph):
    graph[1]["graph_edges"][6]["labels"] = ["reg_data"]
    graph[1]["graph_edges"].append({"source": 2, "target": 5, "labels": ["mem_data"]})
    report = inspect(graph)
    assert report["cycle_count"] == 0
    assert report["frontier_member_count"] == 2
    assert report["roots"][0]["reconvergent_revisits"] == [{"node_id": 2, "via_edge_index": 7}]
    assert report["roots"][0]["traversed_edge_indices"] == [2, 3, 4, 6, 7]


@pytest.mark.parametrize("labels", [["unknown-operation"], ["mem_loc"], ["reg_loc"], ["reg_data", "unknown-operation"],
                                    ["__add__", "mem_loc"]])
def test_unknown_location_and_mixed_edges_are_explicitly_blocked(graph, labels):
    graph[1]["graph_edges"][3]["labels"] = labels
    report = inspect(graph)
    assert member_keys(report) == [(1, 2, 3)]
    blocked = next(edge for edge in report["blocked_edges"] if edge["edge_index"] == 3)
    assert blocked["labels"] == labels and blocked["blocked_labels"]
    assert any(edge["edge_index"] == 3 for edge in report["roots"][0]["encountered_blocked_edges"])
    assert report["semantic_dependency_completeness_claimed"] is False


@pytest.mark.parametrize("label", ["mem_data", "reg_data", "__add__", "__and__", "fpAdd"])
def test_declared_operator_and_raw_reduction_keys_are_traversed_without_scores(graph, label):
    graph[1]["graph_edges"][3]["labels"] = [label]
    report = inspect(graph)
    assert member_keys(report) == [(0, 0, 2), (1, 2, 3)]


def test_shared_member_is_reported_in_every_original_group_not_chosen_by_name(graph):
    function = graph[1]
    function["variables"].append({"prediction_id": "same-id-is-not-a-choice-rule", "locator_variable_name": "other",
                                  "original_value_nodes": [2], "flattened_output_rows": [3]})
    function["prepared"]["var_nodes"].append([2])
    function["readout_contract"] = {"original_variable_count": 3, "prepared_readout_rows": 4,
                                    "exporter_value_row_groups": [[0, 1], [2], [3]]}
    report = inspect(graph)
    assert member_keys(report) == [(0, 0, 2), (2, 3, 2), (1, 2, 3)]
    assert report["frontier_member_count"] == 3
    assert all(member["overlapping_group_membership"] for member in report["frontier_members"] if member["node_id"] == 2)
    assert report["original_groups"][0]["original_value_nodes"] == [2, 4]


def test_nonflattened_group_keeps_one_shared_output_row_and_complete_members(graph):
    graph[2]["flatten_vars"] = False
    function = graph[1]
    function["variables"][0]["flattened_output_rows"] = [0]
    function["variables"][1]["flattened_output_rows"] = [1]
    function["prepared"]["var_nodes"] = [[2, 4], [3]]
    function["readout_contract"] = {"original_variable_count": 2, "prepared_readout_rows": 2,
                                    "exporter_value_row_groups": [[0], [1]]}
    report = inspect(graph)
    assert member_keys(report) == [(0, 0, 2), (1, 1, 3)]
    assert report["original_groups"][0] == {"group_index": 0, "original_value_nodes": [2, 4], "flattened_output_rows": [0]}


def test_mismatched_pc_has_no_candidates_without_fallback_to_closest_or_same_value(graph):
    graph[0]["write_rva"] = 141
    report = inspect(graph)
    assert report["status"] == "unavailable" and report["target_candidates_count"] == 0
    assert report["frontier_member_count"] == 0 and report["unique_address_roots"] == []
    assert len(report["original_groups"]) == 2


def test_target_width_must_be_eight_bits_and_all_roots_remain_separate(graph):
    function = graph[1]
    function["node_labels"][6]["bitsize"] = 16
    function["graph_edges"].append({"source": 3, "target": 7, "labels": ["mem_loc"]})
    report = inspect(graph)
    assert report["target_candidates_count"] == 1
    assert report["targets"][0]["target_node_id"] == 7
    assert report["targets"][0]["address_roots"] == report["unique_address_roots"] == [0, 3]
    assert len(report["roots"]) == 2
    assert next(member for member in report["frontier_members"] if member["node_id"] == 3)["root_nodes"] == [0, 3]


def test_values_names_prediction_ids_and_source_filename_do_not_select_frontier(graph):
    first = inspect(graph)
    graph[0]["binary"] = "D:/unit/favorable-name-is-irrelevant.elf"
    for node in graph[1]["node_labels"]:
        node["ast_value"] = object()  # Not read, serialized, or used as a mapping key.
    for variable in graph[1]["variables"]:
        variable["locator_variable_name"] = "same-misleading-name"
        variable["prediction_id"] = "same-misleading-exporter-id"
        variable["candidate_type"] = "unknown-vs-pointer-is-not-an-input"
    second = inspect(graph)
    assert second == first


def test_node_renumbering_is_equivariant_not_an_id_preference(graph):
    first = inspect(graph)
    mapping = {node: 100 - node * 7 for node in graph[1]["graph_node_order"]}
    function = graph[1]
    function["graph_node_order"] = [mapping[node] for node in function["graph_node_order"]]
    for node in function["node_labels"]: node["graph_node_id"] = mapping[node["graph_node_id"]]
    for edge in function["graph_edges"]:
        edge["source"], edge["target"] = mapping[edge["source"]], mapping[edge["target"]]
    for variable in function["variables"]:
        variable["original_value_nodes"] = [mapping[node] for node in variable["original_value_nodes"]]
    function["prepared"]["var_nodes"] = [[mapping[node] for node in group] for group in function["prepared"]["var_nodes"]]
    second = inspect(graph)
    assert [(member["group_index"], member["output_row"], member["node_id"]) for member in second["frontier_members"]] == [
        (group, row, mapping[node]) for group, row, node in member_keys(first)]
    assert second["unique_address_roots"] == [mapping[node] for node in first["unique_address_roots"]]
    assert second["roots"][0]["frontier_members"][0]["path_witness"]["node_ids"] == [mapping[node] for node in [0, 1, 2]]


def test_original_edge_order_controls_first_witness_but_does_not_sort_by_group(graph):
    graph[1]["graph_edges"][3], graph[1]["graph_edges"][4] = graph[1]["graph_edges"][4], graph[1]["graph_edges"][3]
    report = inspect(graph)
    assert member_keys(report) == [(1, 2, 3), (0, 0, 2)]
    assert report["roots"][0]["frontier_members"][0]["path_witness"]["edge_indices"] == [2, 3]


@pytest.mark.parametrize("field", ["object_rva", "capacity", "inputs", "expected", "gold", "raw_types", "proof"])
def test_strict_request_rejects_property_types_and_prior_evidence(graph, field):
    graph[0][field] = "not accepted"
    with pytest.raises(ValueError): inspect(graph)


@pytest.mark.parametrize("damage", ["entry_mismatch", "target_marker", "duplicate_node", "edge_endpoint", "duplicate_edge",
                                    "missing_group_member", "row_partition", "prepared_partition", "bad_capture_hash",
                                    "bool_node", "bool_pc", "unknown_reduction"])
def test_malformed_identity_graph_or_readout_metadata_is_rejected(graph, damage):
    request, function, contract = graph
    if damage == "entry_mismatch": function["function_address"] = 101
    elif damage == "target_marker": function["is_target"] = False
    elif damage == "duplicate_node": function["graph_node_order"][-1] = function["graph_node_order"][0]
    elif damage == "edge_endpoint": function["graph_edges"][0]["source"] = 9000
    elif damage == "duplicate_edge": function["graph_edges"].append(deepcopy(function["graph_edges"][0]))
    elif damage == "missing_group_member": function["variables"][0]["original_value_nodes"] = [9000]
    elif damage == "row_partition": function["variables"][0]["flattened_output_rows"] = [1, 0]
    elif damage == "prepared_partition": function["prepared"]["var_nodes"].reverse()
    elif damage == "bad_capture_hash": request["native_capture_fingerprint"] = "bad"
    elif damage == "bool_node": function["node_labels"][0]["graph_node_id"] = False
    elif damage == "bool_pc": request["write_rva"] = True
    else: contract["edge_reduce_op_map"]["new-key"] = "undeclared-operator"
    with pytest.raises(ValueError): inspect(graph)


@pytest.mark.parametrize("limit,value", [("MAX_NODES", 7), ("MAX_EDGES", 6), ("MAX_ROWS", 2),
                                        ("MAX_GROUPS", 1), ("MAX_REVERSE_EDGE_VISITS", 1)])
def test_resource_limits_are_explicit_and_never_silently_drop_graph_or_paths(graph, monkeypatch, limit, value):
    monkeypatch.setattr(frontier, limit, value)
    with pytest.raises(ValueError, match="limit|partition"):
        inspect(graph)


def test_pure_stdlib_inventory_does_not_import_frameworks_or_mutate_original_group_order(graph):
    modules, before = set(sys.modules), deepcopy(graph)
    report = inspect(graph)
    assert graph == before and report["original_groups"][0]["original_value_nodes"] == [2, 4]
    assert not [name for name in set(sys.modules) - modules if name.split(".")[0] in
                ("angr", "claripy", "z3", "torch", "pyvex", "capstone", "archinfo", "networkx")]
