"""Fabricated metadata plus existing mechanism syntax; no neural/model execution."""

from copy import deepcopy
import sys
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import mechanism_bytes
from src.selective_analysis.contracts import file_hash
from src.selective_analysis.instruction_provenance import build_syntax_provenance
from src.selective_analysis.model_interface import MODEL_SHA256, analyze_model_interface, relation_domain_report, validate_relation_ids
from src.selective_analysis.workspace import SCRATCH


@pytest.fixture
def metadata():
    return {"schema": "symbai.frozen_checkpoint_metadata.v1", "model_sha256": MODEL_SHA256,
            "external_code_executed": False, "inference_performed": False,
            "model_config": {"edge_dim": 44, "node_encoder_in_dim": 31, "out_dim": 75,
                             "decoder_type": "independent", "node_aggregation": "mean"},
            "preproc_config": {"all_ops": ["fabricated_relation_" + str(i) for i in range(29)],
                               "num_all_ops": 30, "num_edge_ops": 60,
                               "arch_fields": ["x64", "x86", "arm32", "arm64", "mips"],
                               "bitsize_fields": [1, 8, 16, 32, 64, 128, 256], "feature_dim": 18,
                               "bit_vector_encoding_dim": 8, "node_label_encoding_dim": 31,
                               "use_arch": True, "use_bitvector": False, "flatten_vars": True},
            "relation_layers": [{"index": i, "num_relations": 44, "parameter_shapes": {"comp": [44, 10]}}
                                for i in range(2)],
            "parameter_shapes": {"encoder.first_layer.0.weight": [128, 31], "decoder.last_layer.weight": [75, 128]}}


@pytest.fixture(scope="module")
def cases():
    root = SCRATCH / "tests" / ("interface-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    result = []
    for name in ("scalar_span", "readonly_chain", "readonly_chain_outside"):
        blob, write = mechanism_bytes(chain=name != "scalar_span", last_offset=12 if name.endswith("outside") else 6)
        binary = root / (name + ".elf")
        binary.write_bytes(blob)
        request = {"schema": "symbai.syntax_request.v1", "binary": str(binary), "binary_sha256": file_hash(binary),
                   "entry_rva": 4096, "target_store_rva": 4096 + write}
        result.append({"case_id": name, "request": request, "graph": build_syntax_provenance(request)})
    return result


def test_saved_relation_domain_is_compared_to_all_active_layers(metadata):
    report = relation_domain_report(metadata)
    assert report["direction_offset"] == 30 and report["declared_relation_ids"] == list(range(60))
    assert report["potential_encoded_ids_outside_active_layers"] == list(range(44, 60))
    assert report["active_layer_capacities"] == [44, 44]
    assert not report["whole_declared_domain_covered"]
    assert report["labels"][14]["inverse_id"] == 44
    assert report["labels"][14]["inverse_rejected_layers"] == [0, 1]
    assert not report["historical_prepared_edge_ids_observed"] and not report["historical_forward_failure_inferred"]


def test_actual_layer_capacity_is_used_instead_of_cached_config(metadata):
    metadata["model_config"]["edge_dim"] = 44
    for layer in metadata["relation_layers"]:
        layer["num_relations"] = 60
        layer["parameter_shapes"]["comp"] = [60, 10]
    report = relation_domain_report(metadata)
    assert report["serialized_config_edge_dim"] == 44 and report["whole_declared_domain_covered"]
    validate_relation_ids([59], metadata)


@pytest.mark.parametrize("bad", [-1, 44, 59, 60, True, False, 1.0, "1"])
def test_observed_relation_guard_does_not_coerce_or_accept_out_of_domain_ids(metadata, bad):
    with pytest.raises(ValueError):
        validate_relation_ids([bad], metadata)
    validate_relation_ids([0, 29, 30, 43], metadata)


def test_one_smaller_layer_blocks_ids_accepted_by_other_layers(metadata):
    metadata["relation_layers"][1]["num_relations"] = 20
    metadata["relation_layers"][1]["parameter_shapes"]["comp"] = [20, 10]
    with pytest.raises(ValueError):
        validate_relation_ids([29], metadata)
    report = relation_domain_report(metadata)
    assert report["labels"][29]["forward_rejected_layers"] == [1]


def test_matching_shapes_do_not_create_semantic_values_edges_or_readouts(metadata, cases):
    report = analyze_model_interface(metadata, cases)
    assert report["structural_dimensions"]["input_dimension_matches"]
    assert report["structural_dimensions"]["output_dimension_matches"]
    assert report["totals"]["nodes"] == 259 and report["totals"]["unmapped_dependencies"] == 238
    assert report["totals"]["unmapped_readout_candidates"] == 12
    assert report["totals"]["literal_candidate_nodes"] + report["totals"]["nonliteral_nodes_without_upstream_value"] == 259
    assert not report["direct_bridge_ready"] and not report["inference_performed"] and not report["neural_benefit_measured"]
    assert report["no_feature_tensor_or_adapted_input_created"] and not report["placeholder_values_or_unknown_edges_inserted"]
    for case in report["cases"]:
        assert all(node["upstream_ast_value_contract"] == "not_projected" for node in case["nodes"])
        assert all(edge["trained_relation_id"] is None for edge in case["unmapped_dependencies"])
        assert all(row["trained_readout_group"] is None and row["output_row_mapping"] is None for row in case["readout_candidates"])
    assert "declared_relation_domain_not_fully_covered_by_active_layers" in report["blockers"]


def test_missing_node_values_are_not_zero_filled(metadata, cases):
    report = analyze_model_interface(metadata, cases)
    for case in report["cases"]:
        assert all(row["syntactic_literal_candidate"] is None for row in case["nodes"] if row["kind"] != "constant")


@pytest.mark.parametrize("damage", ["hash", "executed", "inference", "count", "float_count", "duplicate_label", "layer_capacity", "shape"])
def test_malformed_or_executed_metadata_cannot_be_treated_as_passive_contract(metadata, damage):
    if damage == "hash": metadata["model_sha256"] = "0" * 64
    elif damage == "executed": metadata["external_code_executed"] = True
    elif damage == "inference": metadata["inference_performed"] = True
    elif damage == "count": metadata["preproc_config"]["num_all_ops"] -= 1
    elif damage == "float_count": metadata["preproc_config"]["num_edge_ops"] = 60.0
    elif damage == "duplicate_label": metadata["preproc_config"]["all_ops"][1] = metadata["preproc_config"]["all_ops"][0]
    elif damage == "layer_capacity": metadata["relation_layers"][0]["num_relations"] = None
    else: metadata["parameter_shapes"]["encoder.first_layer.0.weight"] = [128, -1]
    with pytest.raises(ValueError):
        relation_domain_report(metadata)


@pytest.mark.parametrize("damage", ["missing", "duplicate", "corrupt_graph"])
def test_complete_graph_denominator_and_recorded_identity_are_required(metadata, cases, damage):
    values = deepcopy(cases)
    if damage == "missing": values.pop()
    elif damage == "duplicate": values[-1] = deepcopy(values[0])
    else: values[0]["graph"]["syntax_fingerprint"] = "0" * 64
    with pytest.raises(ValueError):
        analyze_model_interface(metadata, values)


def test_global_dimension_disagreement_and_layer_weight_mismatch_remain_visible(metadata, cases):
    metadata["parameter_shapes"]["encoder.first_layer.0.weight"] = [128, 32]
    metadata["relation_layers"][0]["parameter_shapes"]["comp"] = [43, 10]
    report = analyze_model_interface(metadata, cases)
    assert "saved_node_feature_dimension_or_encoder_shape_disagreement" in report["blockers"]
    assert "saved_relation_coefficient_shape_disagreement" in report["blockers"]
    with pytest.raises(ValueError):
        validate_relation_ids([43], metadata)


def test_saved_row_axis_does_not_claim_a_readout_projection(metadata, cases):
    report = analyze_model_interface(metadata, cases)
    assert report["readout_contract"]["upstream_export_row_axis"] == "value_node"
    metadata["preproc_config"]["flatten_vars"] = False
    report = analyze_model_interface(metadata, cases)
    assert report["readout_contract"]["upstream_export_row_axis"] == "variable_readout"
    assert report["readout_contract"]["source_node_to_trained_value_node_mapping"] == "undeclared"


def test_analysis_does_not_mutate_inputs_or_import_model_engines(metadata, cases):
    before = deepcopy((metadata, cases))
    imports = set(sys.modules)
    first = analyze_model_interface(metadata, cases)
    assert (metadata, cases) == before
    assert analyze_model_interface(metadata, list(reversed(cases)))["totals"] == first["totals"]
    assert not [n for n in set(sys.modules) - imports if n.split(".")[0] in ("torch", "angr", "claripy", "z3")]
