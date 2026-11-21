"""Conservative supervision admission for the fresh 60-relation graph variant.

Labels are read from the independently inventoried ELF, never from a model.
Whole-struct labels are not assigned to the upstream enumerator's member rows.
"""
from collections import Counter, defaultdict
import math

from .variable_mapping import offline_facts, review_mapping


def source_facts(binary, address, variables):
    """Keep every source variable in the denominator, including unsupported ones."""
    facts = offline_facts(binary, address, [])
    exclusions = {}
    for variable in variables:
        offset = variable["variable_die_offset"]
        if variable["status"] != "mapped":
            exclusions[offset] = "inventory_type_unmapped"
        elif variable["before_normalization"] == "struct":
            exclusions[offset] = "whole_struct_requires_separate_member_supervision"
        else:
            try:
                item, = offline_facts(binary, address, [offset])["variables"]
                if item["name"] != variable["name"]:
                    raise ValueError("Inventory and location names differ")
                facts["variables"].append(item)
            except (ValueError, KeyError) as error:
                exclusions[offset] = "unsupported_source_location: " + str(error)
    return {"facts": facts, "exclusions": {str(k): v for k, v in exclusions.items()}}


def validate_native(payload):
    """Recheck topology/readout contracts and actual serialized tensor contents."""
    if payload.get("observer_errors") or payload.get("location_errors"):
        raise ValueError("Capture observation errors")
    review = review_mapping(payload, {"function_address": payload["function_address"], "variables": []})
    if not review["node_feature_row_order_aligned"] or not review["readout_groups_consistent"]:
        raise ValueError("Graph feature/readout order differs")
    if payload["stage"]["step_exceptions"]:
        raise ValueError("Execution step exceptions recorded")
    native = payload["native_input"]
    batch, prepared = native["batch"], native["prepared"]
    for name in ("node_labels", "edge_labels", "edges"):
        if prepared[name] != batch[name]:
            raise ValueError("Prepared and collated tensors differ")
    n = len(native["graph_node_order"])
    x = batch["node_labels"]["values"]
    if (batch["node_labels"]["shape"] != [n, 31] or len(x) != n
            or any(len(row) != 31 or row[:5] != [1., 0., 0., 0., 0.]
                   or any(type(v) not in (int, float) or not math.isfinite(v) for v in row) for row in x)):
        raise ValueError("Invalid finite x64 feature matrix")
    relations = batch["edge_labels"]["values"]
    endpoints = batch["edges"]["values"]
    if (batch["edge_labels"]["shape"] != [len(relations)]
            or batch["edges"]["shape"] != [2, len(relations)]
            or len(endpoints) != 2 or any(len(row) != len(relations) for row in endpoints)
            or any(type(v) is not int or not 0 <= v < 60 for v in relations)
            or any(type(v) is not int or not 0 <= v < n for row in endpoints for v in row)):
        raise ValueError("Invalid complete-relation endpoints or labels")
    expected_edges, expected_relations = [[], []], []
    for edge in native["graph_edges"]:
        s, t = edge["source"], edge["target"]
        expected_edges[0].extend([s, t])
        expected_edges[1].extend([t, s])
        expected_relations.extend([edge["forward_id"], edge["inverse_id"]])
    if endpoints != expected_edges or relations != expected_relations:
        raise ValueError("Serialized relations differ from native edge projection")
    nodes = batch["var_gather"]["values"]
    if any(type(v) is not int or not 0 <= v < n for v in nodes):
        raise ValueError("Invalid value readout node")
    cursor = 0
    for variable in native["variables"]:
        count = len(variable["original_value_nodes"])
        if variable["flattened_output_rows"] != list(range(cursor, cursor + count)):
            raise ValueError("Original-variable readout row ownership differs")
        cursor += count
    if cursor != len(nodes):
        raise ValueError("Readout row count differs")
    return {"schema": "symbai.type_graph_features.v1", "feature_width": 31,
            "relation_count": 60, "binary_sha256": payload["binary_sha256"],
            "function_address": payload["function_address"], "x": x,
            "edge_index": endpoints, "edge_type": relations, "readout_nodes": nodes}


def admit_supervision(payload, source, variables, vocabulary):
    """Match source DIE -> fixed CFA slot -> graph values -> flattened rows.

    No class is used to select a correspondence. Label checks follow mapping.
    Repeated rows receive weights summing to one per admitted source variable.
    """
    features = validate_native(payload)
    if len(vocabulary) != 75 or len(set(vocabulary)) != 75:
        raise ValueError("Expected the pinned 75-class vocabulary")
    review = review_mapping(payload, source["facts"])
    mapped = {row["die_offset"]: row for row in review["variables"]}
    records, candidates = [], []
    for variable in variables:
        offset = variable["variable_die_offset"]
        reasons = []
        if str(offset) in source["exclusions"]:
            reasons.append(source["exclusions"][str(offset)])
        elif offset not in mapped:
            reasons.append("source_location_not_reviewed")
        elif mapped[offset]["status"] != "location_readout_consistent":
            reasons.extend(mapped[offset]["reasons"])
        index = variable.get("class_id")
        if (type(index) is not int or not 0 <= index < 75
                or vocabulary[index] != variable.get("label")):
            reasons.append("inventory_class_vocabulary_mismatch")
        row = {"source_variable_id": variable["function_id"] + ":" + str(offset),
               "die_offset": offset, "name": variable["name"], "reasons": reasons,
               "class_id": index, "label": variable.get("label"), "readout_rows": []}
        if not reasons:
            row["readout_rows"] = mapped[offset]["flattened_rows"]
            if not row["readout_rows"]:
                reasons.append("no_supervised_value_rows")
            else:
                candidates.append(row)
        records.append(row)
    owners, node_classes = defaultdict(list), defaultdict(set)
    for row in candidates:
        for value_row in row["readout_rows"]:
            owners[value_row].append(row)
            node_classes[features["readout_nodes"][value_row]].add(row["class_id"])
    for row in candidates:
        if any(len(owners[r]) != 1 for r in row["readout_rows"]):
            row["reasons"].append("multiple_source_variables_claim_same_readout_row")
        if any(len(node_classes[features["readout_nodes"][r]]) != 1 for r in row["readout_rows"]):
            row["reasons"].append("shared_graph_value_has_conflicting_source_labels")
    targets = []
    for row in records:
        row["status"] = "admitted" if not row["reasons"] else "excluded"
        if row["status"] == "admitted":
            targets.append({key: row[key] for key in ("source_variable_id", "die_offset", "class_id", "label", "readout_rows")})
            targets[-1]["per_row_loss_weight"] = 1. / len(row["readout_rows"])
    supervision = {"schema": "symbai.type_graph_supervision.v1", "targets": targets,
        "source": "independent_ELF_DWARF_inventory_and_fixed_CFA_readout_review",
        "weighting": "Each source variable has total row weight one; rows are not independent samples.",
        "labels_in_graph_features": False}
    return features, supervision, {"variables": records,
        "candidate_source_variables": len(variables), "admitted_source_variables": len(targets),
        "supervised_value_rows": sum(len(row["readout_rows"]) for row in targets),
        "all_native_variable_records": len(payload["native_input"]["variables"]),
        "all_native_value_rows": len(features["readout_nodes"]),
        "exclusion_reasons": dict(Counter(reason for row in records for reason in row["reasons"]))}
