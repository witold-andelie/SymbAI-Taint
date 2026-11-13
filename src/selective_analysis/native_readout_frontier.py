"""Exploratory frontiers in an already captured native graph, without execution.

This records graph reachability under an explicit edge filter.  It neither
identifies unique read/write events nor changes any native readout group.
"""

from collections import defaultdict
import hashlib
import json


MAX_NODES, MAX_EDGES, MAX_GROUPS, MAX_ROWS = 4096, 20000, 4096, 4096
MAX_REVERSE_EDGE_VISITS = 200000
_REQUEST = {"schema", "binary", "binary_sha256", "entry_rva", "write_rva", "native_capture_fingerprint"}
_LOCATION = {"mem_loc", "reg_loc"}
_DATA = {"mem_data", "reg_data"}


def _require(condition, reason):
    if not condition:
        raise ValueError("Invalid native frontier input: " + reason)


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _fingerprint(value):
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("Invalid native frontier input: non-JSON passive contract") from error
    return hashlib.sha256(data).hexdigest()


def _inputs(request, function, contract):
    _require(isinstance(request, dict) and set(request) == _REQUEST
             and request["schema"] == "symbai.native_readout_request.v1"
             and isinstance(request["binary"], str) and bool(request["binary"])
             and _hash(request["binary_sha256"]) and _hash(request["native_capture_fingerprint"])
             and _integer(request["entry_rva"]) and _integer(request["write_rva"])
             and request["write_rva"] >= request["entry_rva"], "strict label-free request")
    _require(isinstance(contract, dict) and isinstance(contract.get("all_ops"), list)
             and contract["all_ops"] and all(isinstance(label, str) and label for label in contract["all_ops"])
             and len(set(contract["all_ops"])) == len(contract["all_ops"])
             and isinstance(contract.get("edge_reduce_op_map"), dict)
             and type(contract.get("flatten_vars")) is bool, "passive operator/readout contract")
    reductions = contract["edge_reduce_op_map"]
    _require(all(isinstance(key, str) and key and isinstance(value, str) and value in contract["all_ops"]
                 for key, value in reductions.items()), "operator reduction map")
    _require(isinstance(function, dict) and _integer(function.get("function_address"))
             and function["function_address"] == request["entry_rva"] and function.get("is_target") is True,
             "target function identity")
    order, labels, edges, variables = (function.get(name) for name in
                                      ("graph_node_order", "node_labels", "graph_edges", "variables"))
    _require(isinstance(order, list) and 0 < len(order) <= MAX_NODES
             and all(_integer(node) for node in order) and len(set(order)) == len(order)
             and isinstance(labels, list) and len(labels) == len(order), "node order/resource limit")
    indexed = {}
    for node_id, node in zip(order, labels):
        _require(isinstance(node, dict) and type(node.get("graph_node_id")) is int
                 and node["graph_node_id"] == node_id and _integer(node.get("bitsize"), 1)
                 and node["bitsize"] <= 65536
                 and (node.get("annotation_address") is None or _integer(node["annotation_address"])),
                 "node identity/annotation metadata")
        indexed[node_id] = node
    _require(isinstance(edges, list) and len(edges) <= MAX_EDGES, "edge resource limit")
    incoming, seen = defaultdict(list), set()
    allowed = (_DATA | set(contract["all_ops"]) | set(reductions)) - _LOCATION
    blocked, admissible = [], {}
    for index, edge in enumerate(edges):
        _require(isinstance(edge, dict) and _integer(edge.get("source")) and _integer(edge.get("target"))
                 and edge["source"] in indexed and edge["target"] in indexed
                 and (edge["source"], edge["target"]) not in seen, "edge endpoint/duplicate")
        names = edge.get("labels")
        _require(isinstance(names, list) and bool(names) and all(isinstance(label, str) and label for label in names)
                 and len(set(names)) == len(names), "complete edge label set")
        seen.add((edge["source"], edge["target"]))
        incoming[edge["target"]].append(index)
        excluded = [label for label in names if label not in allowed]
        admissible[index] = not excluded
        if excluded:
            blocked.append({"edge_index": index, "source": edge["source"], "target": edge["target"],
                            "labels": list(names), "blocked_labels": excluded,
                            "allowed_labels": [label for label in names if label in allowed],
                            "reason": "mixed_label_edge_excluded" if len(excluded) != len(names) else
                                      "location_or_unknown_labels_excluded"})
    _require(isinstance(variables, list) and 0 < len(variables) <= MAX_GROUPS, "original group resource limit")
    groups, membership, prepared_groups, cursor = [], defaultdict(list), [], 0
    for group_index, variable in enumerate(variables):
        _require(isinstance(variable, dict), "original variable group")
        members, rows = variable.get("original_value_nodes"), variable.get("flattened_output_rows")
        _require(isinstance(members, list) and 0 < len(members) <= MAX_NODES
                 and all(_integer(node) and node in indexed for node in members)
                 and len(set(members)) == len(members), "original group member identity")
        count = len(members) if contract["flatten_vars"] else 1
        expected_rows = list(range(cursor, cursor + count))
        _require(isinstance(rows, list) and all(_integer(row) for row in rows)
                 and rows == expected_rows and cursor + count <= MAX_ROWS, "complete output-row partition")
        groups.append({"group_index": group_index, "original_value_nodes": list(members), "flattened_output_rows": list(rows)})
        for member_index, node in enumerate(members):
            output_row = rows[member_index] if contract["flatten_vars"] else rows[0]
            membership[node].append({"group_index": group_index, "output_row": output_row, "node_id": node})
        prepared_groups.extend([[node] for node in members] if contract["flatten_vars"] else [list(members)])
        cursor += count
    _require(isinstance(function.get("prepared"), dict)
             and function["prepared"].get("var_nodes") == prepared_groups, "native prepared readout group order")
    if "readout_contract" in function:
        readout = function["readout_contract"]
        _require(isinstance(readout, dict) and readout.get("original_variable_count") == len(groups)
                 and readout.get("prepared_readout_rows") == cursor
                 and readout.get("exporter_value_row_groups") == [group["flattened_output_rows"] for group in groups],
                 "native readout partition metadata")
    return indexed, edges, incoming, admissible, blocked, groups, membership


def inspect_native_frontier(request, target_function, expected_contract):
    """Keep all target candidates and first-readout boundaries under a fixed filter.

    One first-encounter path witness is retained for each root/member; all
    inspected admissible edges remain visible, including DAG reconvergence.
    A mixed edge containing a location/unknown label is conservatively excluded
    in full.  Capture fingerprint verification belongs to the enclosing caller,
    which has the complete capture rather than only this selected function.
    """
    indexed, edges, incoming, admissible, blocked, groups, membership = _inputs(request, target_function, expected_contract)
    targets, unique_roots = [], []
    for node_id in target_function["graph_node_order"]:
        node = indexed[node_id]
        location_edges = [index for index in incoming[node_id] if "mem_loc" in edges[index]["labels"]]
        if node["bitsize"] != 8 or node.get("annotation_address") != request["write_rva"] or not location_edges:
            continue
        roots = []
        for edge_index in location_edges:
            root = edges[edge_index]["source"]
            if root not in roots:
                roots.append(root)
            if root not in unique_roots:
                unique_roots.append(root)
        targets.append({"target_node_id": node_id, "annotation_address": node["annotation_address"],
                        "width_bits": 8, "mem_loc_edge_indices": location_edges, "address_roots": roots,
                        "exact_event_verified": False})

    work, roots, aggregate_members, aggregate_index = 0, [], [], {}
    for root in unique_roots:
        colors, witnesses = {}, {}
        traversed, encountered_blocked, cycles, revisits, members = [], [], [], [], []
        stack = [(root, None)]
        active_nodes, active_edges = [], []
        while stack:
            node, incoming_edge = stack.pop()
            if incoming_edge is None and colors.get(node) == 1:
                colors[node] = 2
                active_nodes.pop()
                if active_edges:
                    active_edges.pop()
                continue
            if incoming_edge is not None:
                work += 1
                _require(work <= MAX_REVERSE_EDGE_VISITS, "reverse traversal resource limit")
                traversed.append(incoming_edge)
            if colors.get(node) == 1:
                cycles.append({"node_ids": active_nodes + [node], "edge_indices": active_edges + [incoming_edge],
                               "back_edge_index": incoming_edge})
                continue
            if colors.get(node) == 2:
                revisits.append({"node_id": node, "via_edge_index": incoming_edge})
                continue
            colors[node] = 1
            active_nodes.append(node)
            if incoming_edge is not None:
                active_edges.append(incoming_edge)
            witnesses[node] = {"node_ids": list(active_nodes), "edge_indices": list(active_edges)}
            if node in membership:
                for member in membership[node]:
                    item = {**member, "path_witness": witnesses[node],
                            "overlapping_group_membership": len(membership[node]) > 1}
                    members.append(item)
                    key = (member["group_index"], member["output_row"], node)
                    if key not in aggregate_index:
                        aggregate_index[key] = len(aggregate_members)
                        aggregate_members.append({**member, "root_nodes": [],
                                                  "overlapping_group_membership": len(membership[node]) > 1})
                    aggregate_members[aggregate_index[key]]["root_nodes"].append(root)
                colors[node] = 2
                active_nodes.pop()
                if incoming_edge is not None:
                    active_edges.pop()
                continue
            # Exit marker follows all children.  Reverse push order preserves
            # the original native edge iteration order during depth-first walk.
            stack.append((node, None))
            children = []
            for edge_index in incoming[node]:
                if admissible[edge_index]:
                    children.append((edges[edge_index]["source"], edge_index))
                else:
                    encountered_blocked.append({"edge_index": edge_index, "at_node": node,
                                                "path_witness": witnesses[node]})
            stack.extend(reversed(children))
        roots.append({"root_node_id": root, "visited_node_ids": list(witnesses),
                      "traversed_edge_indices": traversed, "frontier_members": members,
                      "encountered_blocked_edges": encountered_blocked, "cycles": cycles,
                      "reconvergent_revisits": revisits, "readout_boundary_stop_applied": True})
    return {"schema": "symbai.native_readout_frontier.v1", "status": "available" if targets else "unavailable",
            "reason": None if targets else "no_byte_sized_mem_loc_target_at_declared_annotation_address",
            "identity": {key: request[key] for key in ("binary_sha256", "entry_rva", "write_rva", "native_capture_fingerprint")},
            "expected_contract_fingerprint": _fingerprint(expected_contract), "target_candidates_count": len(targets),
            "targets": targets, "unique_address_roots": unique_roots, "unique_address_root_count": len(unique_roots),
            "roots": roots, "frontier_member_count": len(aggregate_members), "frontier_members": aggregate_members,
            "original_groups": groups, "blocked_edge_count": len(blocked), "blocked_edges": blocked,
            "blocked_edge_scope": "entire_native_graph_under_declared_filter",
            "cycle_count": sum(len(item["cycles"]) for item in roots), "cycle_count_scope": "per_unique_root_dfs_back_edges",
            "reverse_edge_visits": work, "limits": {"max_nodes": MAX_NODES, "max_edges": MAX_EDGES,
                "max_groups": MAX_GROUPS, "max_output_rows": MAX_ROWS, "max_reverse_edge_visits": MAX_REVERSE_EDGE_VISITS},
            "edge_filter": "data_and_declared_operators_only; whole_mixed_location_or_unknown_edges_excluded",
            "witness_policy": "first_encounter_per_root_member_in_native_edge_order; all_traversed_edges_retained",
            "traversal_direction": "reverse_of_native_source_to_target", "native_capture_identity_verified_by_this_function": False,
            "exact_event_verified": False, "semantic_roles_verified": False, "prediction_aggregation_changed": False,
            "semantic_dependency_completeness_claimed": False, "new_model_output_computed": False,
            "exploratory_known_development_inputs": True}
