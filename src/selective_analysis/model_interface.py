"""Passive frozen-model structural constraints and unprojected v17 semantics.

No feature tensor, relation mapping, readout group or prediction is manufactured.
"""

from collections import Counter

from .provenance_validation import validate_syntax_graph

REVISION = "frozen_model_interface_audit_v18"
MODEL_SHA256 = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
CASES = ("scalar_span", "readonly_chain", "readonly_chain_outside")


def _positive_int(value):
    return type(value) is int and value > 0


def _metadata(metadata):
    if (not isinstance(metadata, dict) or metadata.get("schema") != "symbai.frozen_checkpoint_metadata.v1"
            or metadata.get("model_sha256") != MODEL_SHA256
            or metadata.get("external_code_executed") is not False or metadata.get("inference_performed") is not False):
        raise ValueError("Expected passive metadata from the pinned frozen checkpoint")
    model, preproc, layers, shapes = [metadata[key] for key in
                                      ("model_config", "preproc_config", "relation_layers", "parameter_shapes")]
    if (not all(isinstance(value, dict) for value in (model, preproc, shapes))
            or not isinstance(layers, list) or not layers
            or any(type(preproc.get(name)) is not bool for name in ("use_arch", "use_bitvector", "flatten_vars"))):
        raise ValueError("Missing saved model/preprocessing structures")
    labels = preproc.get("all_ops")
    if (not isinstance(labels, list) or not labels or not all(isinstance(label, str) and label for label in labels)
            or len(set(labels)) != len(labels) or preproc.get("num_all_ops") != len(labels) + 1
            or type(preproc.get("num_all_ops")) is not int
            or type(preproc.get("num_edge_ops")) is not int
            or preproc.get("num_edge_ops") != 2 * preproc["num_all_ops"]):
        raise ValueError("Saved ordered relation vocabulary and directional domain disagree")
    for name in ("arch_fields", "bitsize_fields"):
        if not isinstance(preproc.get(name), list) or not preproc[name]:
            raise ValueError("Missing saved ordered feature fields")
    if (not all(isinstance(x, str) and x for x in preproc["arch_fields"])
            or len(set(preproc["arch_fields"])) != len(preproc["arch_fields"])
            or not all(_positive_int(x) for x in preproc["bitsize_fields"])
            or len(set(preproc["bitsize_fields"])) != len(preproc["bitsize_fields"])):
        raise ValueError("Malformed saved architecture/width vocabulary")
    for name in ("node_label_encoding_dim", "bit_vector_encoding_dim", "feature_dim"):
        if not _positive_int(preproc.get(name)):
            raise ValueError("Invalid saved feature dimension")
    for path, shape in shapes.items():
        if not isinstance(path, str) or not isinstance(shape, list) or not all(_positive_int(x) for x in shape):
            raise ValueError("Invalid recorded parameter shape")
    indices = []
    for layer in layers:
        if (not isinstance(layer, dict) or type(layer.get("index")) is not int or layer["index"] < 0
                or not _positive_int(layer.get("num_relations")) or not isinstance(layer.get("parameter_shapes"), dict)):
            raise ValueError("Missing active saved layer relation capacity")
        indices.append(layer["index"])
        for name, shape in layer["parameter_shapes"].items():
            if not isinstance(name, str) or not isinstance(shape, list) or not all(_positive_int(x) for x in shape):
                raise ValueError("Malformed active-layer parameter shape")
    if indices != list(range(len(layers))):
        raise ValueError("Relation layer order or coverage differs")
    return model, preproc, layers, shapes


def validate_relation_ids(relation_ids, metadata):
    """Structural domain guard for future observed IDs; passing is not semantic compatibility."""
    _, preproc, layers, _ = _metadata(metadata)
    for layer in layers:
        for name, shape in layer["parameter_shapes"].items():
            if name in ("comp", "att") and (len(shape) != 2 or shape[0] != layer["num_relations"]):
                raise ValueError("Active relation capacity disagrees with coefficient parameters")
    if not isinstance(relation_ids, (list, tuple)):
        raise ValueError("Relation IDs must be an explicit sequence")
    for relation_id in relation_ids:
        if (type(relation_id) is not int or relation_id < 0 or relation_id >= preproc["num_edge_ops"]
                or any(relation_id >= layer["num_relations"] for layer in layers)):
            raise ValueError("Observed relation ID lies outside a declared/active relation domain")


def relation_domain_report(metadata):
    model, preproc, layers, _ = _metadata(metadata)
    offset, rows = preproc["num_all_ops"], []
    labels = [*preproc["all_ops"], "<reserved_unknown>"]
    for index, label in enumerate(labels):
        forward_bad = [layer["index"] for layer in layers if index >= layer["num_relations"]]
        inverse_bad = [layer["index"] for layer in layers if index + offset >= layer["num_relations"]]
        rows.append({"label": label, "known_vocabulary_label": index < len(labels) - 1,
                     "forward_id": index, "inverse_id": index + offset,
                     "forward_rejected_layers": forward_bad, "inverse_rejected_layers": inverse_bad})
    capacity_evidence = []
    for layer in layers:
        matrices = {name: shape for name, shape in layer["parameter_shapes"].items()
                    if name in ("comp", "att") and isinstance(shape, list) and len(shape) == 2}
        agrees = all(shape[0] == layer["num_relations"] for shape in matrices.values()) if matrices else None
        capacity_evidence.append({"layer": layer["index"], "num_relations": layer["num_relations"],
                                  "relation_coefficient_shapes": matrices, "coefficient_rows_agree": agrees})
    rejected_ids = sorted({row[direction + "_id"] for row in rows for direction in ("forward", "inverse")
                           if row[direction + "_rejected_layers"]})
    return {"ordered_vocabulary": preproc["all_ops"], "direction_offset": offset,
            "declared_relation_ids": list(range(preproc["num_edge_ops"])),
            "serialized_config_edge_dim": model.get("edge_dim"),
            "active_layer_capacities": [layer["num_relations"] for layer in layers],
            "capacity_evidence": capacity_evidence, "labels": rows,
            "potential_encoded_ids_outside_active_layers": rejected_ids,
            "whole_declared_domain_covered": not rejected_ids,
            "historical_prepared_edge_ids_observed": False,
            "historical_forward_failure_inferred": False,
            "scope": "saved_domain_coverage_not_observed_input_edge_usage"}


def analyze_model_interface(metadata, cases):
    model, preproc, layers, shapes = _metadata(metadata)
    if (not isinstance(cases, list) or len(cases) != 3
            or {case["case_id"] for case in cases} != set(CASES)):
        raise ValueError("Expected the complete three-query provenance panel")
    domain = relation_domain_report(metadata)
    encoder = shapes.get("encoder.first_layer.0.weight")
    decoder = shapes.get("decoder.last_layer.weight")
    feature_sum = len(preproc["arch_fields"]) + preproc["bit_vector_encoding_dim"] + preproc["feature_dim"]
    input_matches = (isinstance(encoder, list) and len(encoder) == 2
                     and feature_sum == preproc["node_label_encoding_dim"] == model.get("node_encoder_in_dim") == encoder[1])
    output_matches = isinstance(decoder, list) and len(decoder) == 2 and decoder[0] == model.get("out_dim")
    inventories = []
    for case in cases:
        graph, request = case["graph"], case["request"]
        validate_syntax_graph(graph, request)
        counts = Counter(node["kind"] for node in graph["nodes"])
        operations = Counter(node["operation"] for node in graph["nodes"] if node["kind"] == "expression")
        node_rows = [{"node": node["id"], "kind": node["kind"], "width_bits": node["width_bits"],
                      "syntactic_literal_candidate": node["constant"] if node["kind"] == "constant" else None,
                      "upstream_ast_value_contract": "not_projected",
                      "upstream_annotation_pc_contract": "not_projected"} for node in graph["nodes"]]
        readouts = [{"instruction_rva": access["instruction_rva"], "role": binding["role"],
                     "read_node": binding["read_node"], "register_offset": binding["register_offset"],
                     "trained_readout_group": None, "output_row_mapping": None}
                    for access in graph["accesses"] for binding in access["register_bindings"]]
        inventories.append({"case_id": case["case_id"], "binary_sha256": graph["identity"]["binary_sha256"],
                            "syntax_fingerprint": graph["syntax_fingerprint"], "node_count": len(graph["nodes"]),
                            "node_kinds": dict(sorted(counts.items())),
                            "literal_candidate_nodes": counts["constant"],
                            "nonliteral_nodes_without_upstream_value": len(graph["nodes"]) - counts["constant"],
                            "all_nodes_without_upstream_annotation_contract": len(graph["nodes"]),
                            "operations": dict(sorted(operations.items())),
                            "operation_names_not_equal_to_saved_relation_labels": sorted(set(operations) - set(preproc["all_ops"])),
                            "nodes": node_rows,
                            "unmapped_dependencies": [{**edge, "trained_relation_id": None, "mapping_status": "undeclared"}
                                                      for edge in graph["edges"]],
                            "readout_candidates": readouts, "direct_bridge_ready": False})
    blockers = ["upstream_value_and_annotation_features_not_projected", "context_and_ast_deduplication_not_projected",
                "typed_directional_relation_projection_undeclared", "readout_group_and_output_row_mapping_undeclared"]
    if not input_matches:
        blockers.append("saved_node_feature_dimension_or_encoder_shape_disagreement")
    if not output_matches:
        blockers.append("saved_output_dimension_or_decoder_shape_disagreement")
    if not domain["whole_declared_domain_covered"]:
        blockers.append("declared_relation_domain_not_fully_covered_by_active_layers")
    if any(e["coefficient_rows_agree"] is False for e in domain["capacity_evidence"]):
        blockers.append("saved_relation_coefficient_shape_disagreement")
    totals = {"nodes": sum(row["node_count"] for row in inventories),
              "literal_candidate_nodes": sum(row["literal_candidate_nodes"] for row in inventories),
              "nonliteral_nodes_without_upstream_value": sum(row["nonliteral_nodes_without_upstream_value"] for row in inventories),
              "unmapped_dependencies": sum(len(row["unmapped_dependencies"]) for row in inventories),
              "unmapped_readout_candidates": sum(len(row["readout_candidates"]) for row in inventories)}
    return {"schema": "symbai.model_interface_audit.v1", "revision": REVISION, "model_sha256": MODEL_SHA256,
            "unique_queries": 3, "cases": inventories, "totals": totals, "relation_domain": domain,
            "structural_dimensions": {"saved_input_features": preproc["node_label_encoding_dim"],
                                      "feature_group_sum": feature_sum, "encoder_weight_shape": encoder,
                                      "input_dimension_matches": input_matches, "decoder_weight_shape": decoder,
                                      "output_dimension_matches": output_matches},
            "readout_contract": {"flatten_vars": preproc["flatten_vars"], "node_aggregation": model.get("node_aggregation"),
                                 "decoder_type": model.get("decoder_type"), "saved_output_classes": model.get("out_dim"),
                                 "upstream_export_row_axis": "value_node" if preproc["flatten_vars"] else "variable_readout",
                                 "source_node_to_trained_value_node_mapping": "undeclared"},
            "blockers": blockers, "direct_bridge_ready": False,
            "no_feature_tensor_or_adapted_input_created": True, "placeholder_values_or_unknown_edges_inserted": False,
            "inference_performed": False, "neural_benefit_measured": False, "held_out_evaluation": False,
            "interpretation": "Static structural facts do not establish value/context/edge/readout compatibility. Missing projection contracts block a direct v17 bridge; no claim excludes every future bridge or infers historical edge usage."}
