"""Parent consistency validation, including tampering with a freshly resealed graph."""

from copy import deepcopy
from pathlib import Path
import struct
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import mechanism_bytes
from benchmarks.selective_analysis.mechanisms import BASE, TEXT
from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis.instruction_provenance import build_syntax_provenance
from src.selective_analysis.provenance_validation import validate_syntax_graph


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def make_graph():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("provenance-validation-" + uuid.uuid4().hex)
    folder.mkdir(parents=True)

    def make(chain=True, last=6, prefix=None, target="c6 00 41"):
        blob, write = mechanism_bytes(chain=chain, last_offset=last)
        if prefix is not None:
            before = bytes.fromhex(prefix)
            code = before + bytes.fromhex(target) + b"\xc3"
            blob = bytearray(blob)
            blob[0x1000:0x2000] = b"\0" * 0x1000
            blob[0x1000:0x1000 + len(code)] = code
            struct.pack_into("<QQ", blob, 96, 0x1000 + len(code), 0x1000 + len(code))
            write = len(before)
        binary = folder / (uuid.uuid4().hex + ".elf")
        binary.write_bytes(blob)
        request = {"schema": "symbai.syntax_request.v1", "binary": str(binary),
                   "binary_sha256": file_hash(binary), "entry_rva": TEXT - BASE,
                   "target_store_rva": TEXT - BASE + write}
        graph = build_syntax_provenance(request)
        assert graph["status"] == "available", graph.get("reason")
        return request, graph

    return make


@pytest.fixture(scope="module")
def original_chain(make_graph):
    return make_graph()


def reseal(graph, repair_edges=True):
    if repair_edges:
        graph["edges"] = [{"source": source, "target": node["id"], "operand_index": index}
                          for node in graph["nodes"] for index, source in enumerate(node["operands"])]
    graph["syntax_fingerprint"] = fingerprint({key: graph[key] for key in ("nodes", "instructions", "accesses")})


def one(graph, kind):
    return next(node for node in graph["nodes"] if node["kind"] == kind)


@pytest.mark.parametrize("chain,last", [(False, 6), (True, 6), (True, 12)])
def test_original_three_shapes_are_accepted_without_mutating_graph(make_graph, chain, last):
    request, graph = make_graph(chain=chain, last=last)
    before = deepcopy(graph)
    assert validate_syntax_graph(graph, request) is None
    assert graph == before


@pytest.mark.parametrize("write", ["b0 12", "b4 34", "66 b8 78 56", "b8 78 56 34 12"])
def test_partial_byte_writes_and_eax_full_write_are_accepted(make_graph, write):
    request, graph = make_graph(prefix="48 b8 88 77 66 55 44 33 22 11 " + write)
    assert validate_syntax_graph(graph, request) is None


def test_store_data_reads_are_not_required_as_address_bindings(make_graph):
    request, graph = make_graph(prefix="", target="48 89 54 c8 10")
    assert validate_syntax_graph(graph, request) is None


@pytest.mark.parametrize("field,value", [
    ("schema", "other"), ("revision", "other"), ("status", "unavailable"), ("reason", "partial"),
    ("complete", False), ("property_verification_performed", True), ("neural_information_used", 0),
    ("tygr_readout_compatibility_validated", True), ("scope", "property_analysis"),
    ("memory_value_provenance", "concrete"), ("temporary_scope", "whole_graph"),
    ("register_offset_space", "dwarf"), ("max_nodes", 4097), ("max_instructions", True),
])
def test_scope_flags_and_declared_limits_are_checked(original_chain, field, value):
    request, original = original_chain
    graph = deepcopy(original)
    graph[field] = value
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("field", ["binary_sha256", "entry_rva", "target_store_rva"])
def test_identity_is_checked_separately_from_neutral_fingerprint(original_chain, field):
    request, original = original_chain
    graph = deepcopy(original)
    graph["identity"][field] = "0" * 64 if field == "binary_sha256" else graph["identity"][field] + 1
    reseal(graph)
    with pytest.raises(ValueError, match="identity"):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("damage", ["empty", "missing_target", "gap", "hex", "length", "ir_count", "branch"])
def test_empty_or_truncated_and_malformed_instruction_graphs_are_rejected(original_chain, damage):
    request, original = original_chain
    graph = deepcopy(original)
    if damage == "empty":
        graph["nodes"] = []
        graph["accesses"] = []
    elif damage == "missing_target":
        graph["instructions"].pop()
    elif damage == "gap":
        graph["instructions"][1]["rva"] += 1
    elif damage == "hex":
        graph["instructions"][0]["bytes"] = "zz" * graph["instructions"][0]["length"]
    elif damage == "length":
        graph["instructions"][0]["length"] = 0
    elif damage == "ir_count":
        graph["instructions"][0]["vex_statement_count"] = 0
    else:
        graph["instructions"][0]["mnemonic"] = "jmp"
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("damage", ["id", "forward", "width", "unknown_kind", "wrong_pc", "wrong_statement", "operation", "entry"])
def test_node_shape_dependencies_and_events_are_checked(original_chain, damage):
    request, original = original_chain
    graph = deepcopy(original)
    if damage == "id":
        graph["nodes"][1]["id"] = graph["nodes"][0]["id"]
    elif damage == "forward":
        graph["nodes"][0]["operands"] = [graph["nodes"][-1]["id"]]
    elif damage == "width":
        graph["nodes"][0]["width_bits"] = True
    elif damage == "unknown_kind":
        graph["nodes"][0]["kind"] = "modeled_value"
    elif damage == "wrong_pc":
        one(graph, "register_read")["instruction_rva"] = request["target_store_rva"] + 1
    elif damage == "wrong_statement":
        one(graph, "register_read")["statement_index"] = 99999
    elif damage == "operation":
        one(graph, "expression")["operation"] = "execute_memory"
    else:
        one(graph, "entry_byte")["instruction_rva"] = request["entry_rva"]
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("damage", ["cross_instruction", "width", "duplicate", "not_definition"])
def test_temporary_identity_requires_prior_definition_in_same_instruction(original_chain, damage):
    request, original = original_chain
    graph = deepcopy(original)
    if damage == "cross_instruction":
        definitions = []
        for node in graph["nodes"]:
            if node["kind"] == "temporary_definition":
                definitions.append(node)
            if node["kind"] == "temporary_read":
                prior = next((value for value in definitions if value["instruction_rva"] != node["instruction_rva"]
                              and value["width_bits"] == node["width_bits"]), None)
                if prior:
                    node["temporary"], node["operands"] = prior["temporary"], [prior["id"]]
                    break
        else:
            pytest.fail("Fixture needs reused temporary widths across instructions")
    elif damage == "width":
        node = one(graph, "temporary_read")
        node["width_bits"] = 8 if node["width_bits"] != 8 else 64
    elif damage == "duplicate":
        first = one(graph, "temporary_definition")
        second = next(node for node in graph["nodes"] if node["kind"] == "temporary_definition"
                      and node["instruction_rva"] == first["instruction_rva"] and node["id"] != first["id"])
        second["temporary"] = first["temporary"]
    else:
        node = one(graph, "temporary_read")
        node["operands"] = [one(graph, "entry_byte")["id"]]
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


def test_old_register_definition_cannot_replace_event_time_version(original_chain):
    request, original = original_chain
    graph = deepcopy(original)
    target = graph["accesses"][-1]
    read_id = next(binding["read_node"] for binding in target["register_bindings"] if binding["register_name"] == "rax")
    read = next(node for node in graph["nodes"] if node["id"] == read_id)
    current = read["byte_sources"][0]["definition"]
    old = next(node for node in graph["nodes"] if node["kind"] == "register_write"
               and node["register_offset"] == read["register_offset"] and node["width_bits"] == 64 and node["id"] != current)
    for source in read["byte_sources"]:
        source["definition"] = old["id"]
    read["operands"] = [old["id"]]
    reseal(graph)
    with pytest.raises(ValueError, match="register byte versions"):
        validate_syntax_graph(graph, request)


def test_subregister_write_cannot_claim_untouched_upper_bytes(make_graph):
    request, graph = make_graph(prefix="48 b8 88 77 66 55 44 33 22 11 b0 12")
    read_id = graph["accesses"][-1]["register_bindings"][0]["read_node"]
    read = next(node for node in graph["nodes"] if node["id"] == read_id)
    read["byte_sources"][1]["definition"] = read["byte_sources"][0]["definition"]
    read["operands"] = list(dict.fromkeys(source["definition"] for source in read["byte_sources"]))
    reseal(graph)
    with pytest.raises(ValueError, match="register byte versions"):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("damage", ["concrete_load", "load_extra_value", "load_operand", "store_width", "put_value", "constant"])
def test_value_node_shapes_and_opaque_load_contract_are_checked(original_chain, damage):
    request, original = original_chain
    graph = deepcopy(original)
    if damage == "concrete_load":
        one(graph, "load")["value_semantics"] = "concrete_memory_value"
    elif damage == "load_extra_value":
        one(graph, "load")["loaded_bytes"] = "00"
    elif damage == "load_operand":
        node = one(graph, "load")
        node["operands"].append(node["address"])
    elif damage == "store_width":
        one(graph, "store")["width_bits"] = 64
    elif damage == "put_value":
        one(graph, "register_write")["value"] = graph["nodes"][-1]["id"]
    else:
        one(graph, "constant")["constant"] = -1
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("damage", ["missing", "duplicate", "direction", "pc", "address", "width", "formula", "binding_offset", "binding_role"])
def test_memory_access_identity_and_affine_fields_are_checked(original_chain, damage):
    request, original = original_chain
    graph = deepcopy(original)
    access = graph["accesses"][-1]
    if damage == "missing":
        graph["accesses"].pop()
    elif damage == "duplicate":
        graph["accesses"].append(deepcopy(access))
    elif damage == "direction":
        access["direction"] = "read"
    elif damage == "pc":
        access["instruction_rva"] = request["entry_rva"]
    elif damage == "address":
        access["address_node"] = graph["accesses"][0]["address_node"]
    elif damage == "width":
        access["width_bits"] = 64
    elif damage == "formula":
        access["address_formula"]["constant"] += 1
    elif damage == "binding_offset":
        access["register_bindings"][0]["register_offset"] += 8
    else:
        access["register_bindings"][1]["role"] = access["register_bindings"][0]["role"]
    reseal(graph)
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("source", ["store_data", "prior_read"])
def test_address_bindings_cannot_use_store_data_or_previous_instruction_reads(make_graph, original_chain, source):
    if source == "store_data":
        request, graph = make_graph(prefix="", target="48 89 54 c8 10")
        replacement = next(node for node in graph["nodes"] if node["kind"] == "register_read" and node["register_name"] == "rdx")
    else:
        request, original = original_chain
        graph = deepcopy(original)
        replacement = next(node for node in graph["nodes"] if node["kind"] == "register_read"
                           and node["register_name"] == "rax" and node["instruction_rva"] != request["target_store_rva"])
    access = graph["accesses"][-1]
    binding = access["register_bindings"][0]
    old_read = binding["read_node"]
    binding.update(read_node=replacement["id"], register_name=replacement["register_name"], register_offset=replacement["register_offset"])
    term = next(term for term in access["address_formula"]["terms"] if term["read_node"] == old_read)
    term.update(read_node=replacement["id"], register_offset=replacement["register_offset"])
    access["address_formula"]["terms"].sort(key=lambda value: value["read_node"])
    reseal(graph)
    with pytest.raises(ValueError, match="address formula"):
        validate_syntax_graph(graph, request)


def test_edges_are_checked_even_when_neutral_fingerprint_matches(original_chain):
    request, original = original_chain
    graph = deepcopy(original)
    graph["edges"].pop()
    reseal(graph, repair_edges=False)
    with pytest.raises(ValueError, match="edge dependencies"):
        validate_syntax_graph(graph, request)


def test_checksum_is_also_checked_after_structural_consistency(original_chain):
    request, original = original_chain
    graph = deepcopy(original)
    graph["syntax_fingerprint"] = "0" * 64
    with pytest.raises(ValueError, match="fingerprint"):
        validate_syntax_graph(graph, request)


@pytest.mark.parametrize("graph", [None, [], {}, {"status": "available", "complete": True}])
def test_malformed_candidate_never_leaks_key_or_type_errors(original_chain, graph):
    request, _ = original_chain
    with pytest.raises(ValueError):
        validate_syntax_graph(graph, request)
