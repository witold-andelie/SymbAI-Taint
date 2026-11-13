"""Fabricated native metadata and authored unit bytes; no model/solver collection."""

from copy import deepcopy
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, Code, elf_bytes
from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis import native_readout_correspondence as correspondence


ROOT = Path(__file__).resolve().parents[1]


def location(offset, low=0x1000, high=0x1100, kind="CfaLocation"):
    return {"location_class": kind, "location_value": offset, "location_argument": offset,
            "location_register": None, "low_pc": low, "high_pc": high}


def request(binary="unused-pure-helper.elf", binary_hash="a" * 64, write=0x1040, capture_fp="c" * 64):
    return {"schema": "symbai.native_readout_request.v1", "binary": binary, "binary_sha256": binary_hash,
            "entry_rva": 0x1000, "write_rva": write, "native_capture_fingerprint": capture_fp}


def occurrence(req, offset, load):
    use = f"{req['binary_sha256']}:{req['entry_rva']:x}:{req['write_rva']:x}:write_address"
    return {"occurrence_id": use + f":load@{load:x}:cfa{offset:+d}", "cfa_offset": offset,
            "load_rva": load, "load_address": load, "use_rva": req["write_rva"],
            "use_address": req["write_rva"], "size_bytes": 8}


def target_function():
    members = [[5, 1, 3], [2, 6, 4]]
    labels = [{"graph_node_id": index, "bitsize": 64, "annotation_address": 0x1000 + index,
               "ast_value": {"kind": "int", "value": str(index)}} for index in range(8)]
    labels[3]["annotation_address"], labels[6]["annotation_address"] = 0x1030, 0x1020
    edges = []
    for group, nodes in enumerate(members):
        for node in nodes:
            index = len(edges)
            source, label, forward = (0, "mem_loc", 1) if group == 0 else (7, "reg_loc", 3)
            edges.append({"source": source, "target": node, "labels": [label], "forward_id": forward,
                          "inverse_id": forward + 30, "prepared_columns": [2 * index, 2 * index + 1]})
    variables = [{"prediction_id": f"1000:{index}", "locator_variable_name": "pointer" if index == 0 else "index",
                  "function_address": 0x1000, "locations": [location(offset)], "original_value_nodes": members[index],
                  "flattened_output_rows": list(range(3 * index, 3 * index + 3))}
                 for index, offset in enumerate((-40, -24))]
    return {"function_address": 0x1000, "function_high_pc": 0x1100, "is_target": True, "arch_token": "arch",
            "graph_node_order": list(range(8)), "node_labels": labels, "graph_edges": edges, "variables": variables,
            "readout_contract": {"original_variable_count": 2, "prepared_readout_rows": 6,
                                 "exporter_value_row_groups": [[0, 1, 2], [3, 4, 5]],
                                 "row_axis": "value_node", "logits_computed": False}}


@pytest.fixture
def pure_case():
    req = request()
    return req, target_function(), [occurrence(req, -24, 0x1020), occurrence(req, -40, 0x1030)]


@pytest.fixture
def contract():
    return {"model_sha256": "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8",
            "node_label_encoding_dim": 31, "all_ops": ["mem_data", "mem_loc", "reg_data", "reg_loc", "Concat", "Extract",
                "__sub__", "__add__", "__mul__", "__floordiv__", "SDiv", "__ge__", "SLE", "__lt__", "ULE",
                "SignExt", "ZeroExt", "LShR", "__lshift__", "__rshift__", "If", "Or", "Not", "And", "Xor", "Eq",
                "fp_conv", "fp_op", "fp_cmp"], "num_all_ops": 30, "num_edge_ops": 60, "flatten_vars": True,
            "use_arch": True, "arch_fields": ["x64", "x86", "arm32", "arm64", "mips"], "type_count": 75,
            "decoder_type": "independent", "node_aggregation": "mean", "layer_relation_capacities": [44] * 8,
            "edge_reduce_op_map": {"__and__": "And"}}


def tensor(values, shape, dtype="torch.int64"):
    return {"values": values, "shape": shape, "dtype": dtype, "device": "cpu"}


@pytest.fixture
def make_case(contract):
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("native-readout-" + uuid.uuid4().hex)
    folder.mkdir(parents=True)

    def make(between_loads="", before_loads=""):
        code = Code()
        code.emit("55 48 89 e5 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + before_loads)
        pointer_load = 0x1000 + len(code.data)
        code.emit("48 8b 55 f8 " + between_loads)
        index_load = 0x1000 + len(code.data)
        code.emit("48 8b 45 e8 48 01 d0")
        write = 0x1000 + len(code.data)
        code.emit("c6 00 41 c3")
        blob = bytearray(elf_bytes(code.finish()))
        struct.pack_into("<Q", blob, 24, TEXT - BASE)
        for index in range(2):
            for delta in (16, 24):
                position = 64 + 56 * index + delta
                struct.pack_into("<Q", blob, position, struct.unpack_from("<Q", blob, position)[0] - BASE)
        binary = folder / (uuid.uuid4().hex + ".elf")
        binary.write_bytes(blob)
        function = target_function()
        function["node_labels"][3]["annotation_address"] = index_load
        function["node_labels"][6]["annotation_address"] = pointer_load
        edges = function["graph_edges"]
        endpoints = [[value for edge in edges for value in (edge["source"], edge["target"])],
                     [value for edge in edges for value in (edge["target"], edge["source"])]]
        relations = [value for edge in edges for value in (edge["forward_id"], edge["inverse_id"])]
        prepared = {"node_labels": tensor([[0.0] * 31 for _ in range(8)], [8, 31], "torch.float32"),
                    "edges": tensor(endpoints, [2, 12]), "edge_labels": tensor(relations, [12]),
                    "var_nodes": [[node] for variable in function["variables"] for node in variable["original_value_nodes"]]}
        function["prepared"] = prepared
        function["batch"] = {"num_vars": [6], **{key: deepcopy(prepared[key]) for key in ("node_labels", "edges", "edge_labels")},
                             "var_gather": tensor([5, 1, 3, 2, 6, 4], [6]), "var_scatter": tensor(list(range(6)), [6]),
                             "labels_supplied_to_model": False}
        import hashlib
        source = "def forward(self):\n    pass\n"
        capture = {"schema": "symbai.native_preprocessing.v1", "status": "captured", "receipt_origin": "native_worker",
            "request_identity": {"binary_sha256": file_hash(binary), "entry_rva": 0x1000},
            "provenance": {"model_sha256": contract["model_sha256"], "locator": "dwarf_assisted",
                           "datagen_predict_phase": False, "ground_truth_labels_forwarded": False},
            "runtime": {"platform": "fabricated unit metadata"}, "model_contract": deepcopy(contract),
            "forward_attempts": 0, "model_forward_performed": False, "functions": [function], "timings_seconds": {},
            "source_sha256": {"src/unit.py": "f" * 64}, "rgcn_implementation": {"class": "unit.RGCNConv",
                "source_file": "unit.py", "source_file_sha256": "e" * 64, "forward_source": source,
                "forward_source_sha256": hashlib.sha256(source.encode()).hexdigest(), "behavior_executed_or_inferred": False},
            "integrity": {"binary_unchanged": True, "model_unchanged": True, "upstream_sources_unchanged": True}}
        req = request(str(binary), file_hash(binary), write, fingerprint(capture))
        return req, capture

    return make


def test_unique_physical_location_associates_whole_group_without_event_proof(pure_case):
    req, function, occurrences = pure_case
    before = deepcopy((req, function, occurrences))
    rows = correspondence.associate_native_readouts(req, function, occurrences)
    assert [row["status"] for row in rows] == ["available", "available"]
    assert [row["native_group_index"] for row in rows] == [1, 0]
    assert rows[0]["original_value_nodes"] == [2, 6, 4] and rows[0]["flattened_output_rows"] == [3, 4, 5]
    assert [row["output_row"] for row in rows[0]["native_rows"]] == [3, 4, 5]
    assert [row["members"][0]["graph_node_id"] for row in rows[0]["native_rows"]] == [2, 6, 4]
    assert rows[0]["native_group_id"] == f"{'c' * 64}:1000:group:1"
    assert all(row["exact_event_status"] == "unverified" and not row["exact_event_verified"] for row in rows)
    assert (req, function, occurrences) == before


def test_every_member_and_location_fact_survives_pc_coincidence(pure_case):
    req, function, occurrences = pure_case
    rows = correspondence.associate_native_readouts(req, function, occurrences)
    members = [row["members"][0] for row in rows[0]["native_rows"]]
    assert [member["annotation_pc_coincides_with_static_load"] for member in members] == [False, True, False]
    assert all(member["incoming_location_facts"][0]["location_labels"] == ["reg_loc"] for member in members)
    assert all(member["incoming_location_facts"][0]["source_node_label"]["graph_node_id"] == 7 for member in members)
    assert all(not member["exact_event_verified"] for member in members)


@pytest.mark.parametrize("coincident_count", [0, 1, 3])
def test_none_one_or_many_same_pc_rows_never_change_group_availability_or_prove_event(pure_case, coincident_count):
    req, function, occurrences = pure_case
    for index, node in enumerate(function["variables"][1]["original_value_nodes"]):
        function["node_labels"][node]["annotation_address"] = occurrences[0]["load_address"] if index < coincident_count else None
    row = correspondence.associate_native_readouts(req, function, occurrences)[0]
    assert row["status"] == "available" and len(row["native_rows"]) == 3 and not row["exact_event_verified"]
    assert sum(member["annotation_pc_coincides_with_static_load"] for item in row["native_rows"] for member in item["members"]) == coincident_count


@pytest.mark.parametrize("boundary,available", [("low_at_load", True), ("low_after_load", False),
                                              ("high_at_use", False), ("high_after_use", True),
                                              ("high_at_load", False), ("high_none", False)])
def test_location_lifetime_is_half_open_and_covers_both_load_and_use(pure_case, boundary, available):
    req, function, occurrences = pure_case
    loc = function["variables"][1]["locations"][0]
    if boundary == "low_at_load": loc["low_pc"] = occurrences[0]["load_address"]
    elif boundary == "low_after_load": loc["low_pc"] = occurrences[0]["load_address"] + 1
    elif boundary == "high_at_use": loc["high_pc"] = occurrences[0]["use_address"]
    elif boundary == "high_after_use": loc["high_pc"] = occurrences[0]["use_address"] + 1
    elif boundary == "high_at_load": loc["high_pc"] = occurrences[0]["load_address"]
    else: loc["high_pc"] = None
    rows = correspondence.associate_native_readouts(req, function, occurrences)
    assert (rows[0]["status"] == "available") is available
    assert rows[1]["status"] == "available"


@pytest.mark.parametrize("damage", ["duplicate_same_location", "overlap_other_cfa", "overlap_register_location",
                                    "second_matching_group", "argument_mismatch", "register_not_none", "missing_locations"])
def test_ambiguous_or_malformed_locations_never_use_name_tie_breaks(pure_case, damage):
    req, function, occurrences = pure_case
    variable = function["variables"][1]
    if damage == "duplicate_same_location": variable["locations"].append(deepcopy(variable["locations"][0]))
    elif damage == "overlap_other_cfa": variable["locations"].append(location(-80))
    elif damage == "overlap_register_location": variable["locations"].append(location(56, kind="RegLocation"))
    elif damage == "second_matching_group": function["variables"][0]["locations"] = [location(-24)]
    elif damage == "argument_mismatch": variable["locations"][0]["location_argument"] = -32
    elif damage == "register_not_none": variable["locations"][0]["location_register"] = 7
    else: variable["locations"] = []
    rows = correspondence.associate_native_readouts(req, function, occurrences)
    assert rows[0]["status"] == "unavailable" and rows[0]["native_group_index"] is None
    assert not rows[0]["exact_event_verified"]


def test_nonoverlapping_location_changes_do_not_make_current_unique_storage_ambiguous(pure_case):
    req, function, occurrences = pure_case
    function["variables"][1]["locations"] = [location(-24, 0x1000, 0x1041), location(-80, 0x1041, 0x1100)]
    assert correspondence.associate_native_readouts(req, function, occurrences)[0]["status"] == "available"


def test_ambiguous_candidate_groups_keep_original_member_order_and_row_partitions(pure_case):
    req, function, occurrences = pure_case
    function["variables"][0]["locations"] = [location(-24)]
    row = correspondence.associate_native_readouts(req, function, occurrences)[0]
    assert row["status"] == "unavailable" and row["native_group_index"] is None
    assert [group["native_group_index"] for group in row["candidate_groups"]] == [0, 1]
    assert [group["original_value_nodes"] for group in row["candidate_groups"]] == [[5, 1, 3], [2, 6, 4]]
    assert [group["flattened_output_rows"] for group in row["candidate_groups"]] == [[0, 1, 2], [3, 4, 5]]


def test_variable_group_from_another_function_cannot_match_same_storage(pure_case):
    req, function, occurrences = pure_case
    function["variables"][1]["function_address"] += 1
    rows = correspondence.associate_native_readouts(req, function, occurrences)
    assert rows[0]["status"] == "unavailable" and rows[1]["status"] == "available"


def test_load_and_use_cannot_be_joined_across_disjoint_lifetime_entries(pure_case):
    req, function, occurrences = pure_case
    function["variables"][1]["locations"] = [location(-24, 0x1000, 0x1030), location(-24, 0x1030, 0x1100)]
    assert correspondence.associate_native_readouts(req, function, occurrences)[0]["status"] == "unavailable"


def test_names_exporter_id_strings_sampled_values_and_other_row_pcs_cannot_choose_group(pure_case):
    req, function, occurrences = pure_case
    before = correspondence.associate_native_readouts(req, function, occurrences)
    for variable in function["variables"]:
        variable["prediction_id"] = "same arbitrary label"
        variable["locator_variable_name"] = "pointer index expected answer"
    for label in function["node_labels"]:
        label["ast_value"] = {"kind": "int", "value": "4194304"}
        label["annotation_address"] = occurrences[0]["load_address"]
    after = correspondence.associate_native_readouts(req, function, occurrences)
    assert [row["native_group_index"] for row in after] == [row["native_group_index"] for row in before] == [1, 0]
    assert [row["original_value_nodes"] for row in after] == [row["original_value_nodes"] for row in before]
    assert all(row["status"] == "available" and not row["exact_event_verified"] for row in after)


def test_reversed_native_member_order_is_preserved_in_full(pure_case):
    req, function, occurrences = pure_case
    function["variables"][1]["original_value_nodes"].reverse()
    row = correspondence.associate_native_readouts(req, function, occurrences)[0]
    assert row["original_value_nodes"] == [4, 6, 2]
    assert [item["members"][0]["graph_node_id"] for item in row["native_rows"]] == [4, 6, 2]
    assert row["flattened_output_rows"] == [3, 4, 5]


def test_changed_declared_capture_fingerprint_changes_group_identity_only_in_pure_helper(pure_case):
    req, function, occurrences = pure_case
    original = correspondence.associate_native_readouts(req, function, occurrences)
    req["native_capture_fingerprint"] = "d" * 64
    changed = correspondence.associate_native_readouts(req, function, occurrences)
    assert original[0]["native_group_id"] != changed[0]["native_group_id"]
    assert original[0]["original_value_nodes"] == changed[0]["original_value_nodes"]


@pytest.mark.parametrize("damage", ["function", "width", "use", "occurrence_id", "address_base", "missing_member"])
def test_wrong_function_or_occurrence_and_missing_member_metadata_stay_unavailable(pure_case, damage):
    req, function, occurrences = pure_case
    if damage == "function": function["function_address"] += 1
    elif damage == "width": occurrences[0]["size_bytes"] = 4
    elif damage == "use": occurrences[0]["use_rva"] += 1
    elif damage == "occurrence_id": occurrences[0]["occurrence_id"] = "borrowed occurrence"
    elif damage == "address_base": occurrences[0]["load_address"] += 0x400000
    else: function["node_labels"] = [label for label in function["node_labels"] if label["graph_node_id"] != 6]
    row = correspondence.associate_native_readouts(req, function, occurrences)[0]
    assert row["status"] == "unavailable" and not row["exact_event_verified"]


def test_build_fresh_walks_only_minimal_namespace_and_retains_two_complete_groups(make_case, contract, monkeypatch):
    req, capture = make_case()
    original = correspondence._StaticLoads
    calls = []
    def record(minimal):
        assert type(minimal) is SimpleNamespace
        assert set(vars(minimal)) == {"binary", "binary_sha256", "entry_rva", "write_rva", "use_site_id"}
        calls.append(vars(minimal))
        return original(minimal)
    monkeypatch.setattr(correspondence, "_StaticLoads", record)
    result = correspondence.build_native_readout_correspondence(req, capture, contract)
    again = correspondence.build_native_readout_correspondence(req, capture, contract)
    assert len(calls) == 2 and result == again
    assert result["status"] == result["static_status"] == "available"
    assert result["counts"] == {"static_address_load_occurrences": 2, "available_group_associations": 2,
                                "unavailable_group_associations": 0, "exact_event_verified_occurrences": 0}
    assert [row["native_group_index"] for row in result["occurrence_records"]] == [1, 0]
    assert len(result["static_trace"]) >= 8 and result["native_validation"]["captured"]
    assert not result["exact_event_verified"] and not result["semantic_address_roles_verified"]
    assert not result["historical_logits_reused"] and not result["neural_inference_performed"]
    assert result["correspondence_fingerprint"] == fingerprint({key: value for key, value in result.items() if key != "correspondence_fingerprint"})


@pytest.mark.parametrize("field", ["capacity", "object_rva", "inputs", "expected", "raw_types", "raw_export", "role_proof", "candidates"])
def test_build_rejects_nonminimal_or_old_evidence_fields_before_decode(make_case, contract, field):
    req, capture = make_case()
    req[field] = "forbidden"
    with pytest.raises(ValueError, match="minimal"):
        correspondence.build_native_readout_correspondence(req, capture, contract)


@pytest.mark.parametrize("damage", ["capture_fp", "capture_binary", "capture_entry", "binary_file", "capture_tamper", "request_bool"])
def test_tampered_capture_or_binary_identity_is_rejected(make_case, contract, damage):
    req, capture = make_case()
    if damage == "capture_fp": req["native_capture_fingerprint"] = "0" * 64
    elif damage == "capture_binary":
        capture["request_identity"]["binary_sha256"] = "0" * 64
        req["native_capture_fingerprint"] = fingerprint(capture)
    elif damage == "capture_entry":
        capture["request_identity"]["entry_rva"] += 1
        req["native_capture_fingerprint"] = fingerprint(capture)
    elif damage == "binary_file": Path(req["binary"]).write_bytes(b"changed")
    elif damage == "capture_tamper": capture["functions"][0]["node_labels"][0]["ast_value"]["value"] = "999"
    else: req["entry_rva"] = True
    with pytest.raises(ValueError):
        correspondence.build_native_readout_correspondence(req, capture, contract)


def test_group_unavailable_keeps_both_static_occurrences_and_other_successful_group(make_case, contract):
    req, capture = make_case()
    capture["functions"][0]["variables"][1]["locations"][0]["high_pc"] = req["write_rva"]
    req["native_capture_fingerprint"] = fingerprint(capture)
    result = correspondence.build_native_readout_correspondence(req, capture, contract)
    assert result["status"] == "unavailable" and result["static_status"] == "available"
    assert len(result["occurrences"]) == len(result["occurrence_records"]) == 2
    assert [row["status"] for row in result["occurrence_records"]] == ["unavailable", "available"]
    assert result["counts"]["available_group_associations"] == 1


def test_unsupported_static_walk_retains_trace_and_partial_origins_without_claiming_target_dependencies(make_case, contract):
    req, capture = make_case(between_loads="eb 00")
    result = correspondence.build_native_readout_correspondence(req, capture, contract)
    assert result["status"] == result["static_status"] == "unavailable"
    assert "unsupported_instruction:jmp" in result["static_reason"]
    assert result["static_trace"][-1]["mnemonic"] == "jmp"
    assert len(result["partial_static_load_origins"]) == 1
    assert result["occurrences"] == result["occurrence_records"] == []


def test_unexpected_static_failure_still_retains_partial_diagnostic(make_case, contract, monkeypatch):
    req, capture = make_case()
    class FailedWalker:
        def __init__(self, minimal):
            self.trace = [{"unit": "started"}]
            self.origins = {"partial": {"unit": "load"}}
        def walk(self):
            raise RuntimeError("unit unexpected decoder fault")
    monkeypatch.setattr(correspondence, "_StaticLoads", FailedWalker)
    result = correspondence.build_native_readout_correspondence(req, capture, contract)
    assert result["status"] == "unavailable" and result["static_trace"] == [{"unit": "started"}]
    assert result["partial_static_load_origins"] == [{"unit": "load"}]
    assert "RuntimeError" in result["static_reason"]


def test_failed_native_capture_does_not_erase_fresh_static_occurrence_denominator(make_case, contract):
    req, capture = make_case()
    capture.update(status="failed", model_contract=None, functions=[])
    req["native_capture_fingerprint"] = fingerprint(capture)
    result = correspondence.build_native_readout_correspondence(req, capture, contract)
    assert result["static_status"] == "available" and result["reason"] == "native_capture_not_complete"
    assert len(result["occurrence_records"]) == 2 and result["counts"]["unavailable_group_associations"] == 2


def test_build_does_not_mutate_inputs_or_import_frameworks(make_case, contract):
    req, capture = make_case()
    before = deepcopy((req, capture, contract))
    modules = set(sys.modules)
    correspondence.build_native_readout_correspondence(req, capture, contract)
    assert (req, capture, contract) == before
    assert not [name for name in set(sys.modules) - modules if name.split(".")[0] in ("torch", "angr", "claripy", "z3")]


def test_missing_binary_is_an_identity_failure_not_a_fabricated_static_result(make_case, contract):
    req, capture = make_case()
    req["binary"] = str(Path(req["binary"]).with_name("absent.elf"))
    with pytest.raises(ValueError, match="binary unavailable"):
        correspondence.build_native_readout_correspondence(req, capture, contract)
