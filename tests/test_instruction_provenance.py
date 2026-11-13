"""Instruction provenance on authored unit bytes; no execution or type inference."""

from collections import defaultdict
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import READONLY, mechanism_bytes
from benchmarks.selective_analysis.mechanisms import BASE, TEXT
from src.selective_analysis.contracts import file_hash
from src.selective_analysis import instruction_provenance as provenance


ROOT = Path(__file__).resolve().parents[1]
KINDS = {"register_read", "register_write", "entry_byte", "temporary_definition", "temporary_read",
         "constant", "expression", "load", "store"}


@pytest.fixture
def make_request():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("instruction-syntax-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)

    def make(prefix="", target="c6 00 41", chain=None, last=6, raw=None, target_offset=None):
        blob, write = mechanism_bytes(chain=bool(chain), last_offset=last)
        blob = bytearray(blob)
        if chain is None:
            before = bytes.fromhex(prefix)
            code = before + bytes.fromhex(target) + b"\xc3" if raw is None else raw
            write = len(before) if target_offset is None else target_offset
            blob[0x1000:0x2000] = b"\0" * 0x1000
            blob[0x1000:0x1000 + len(code)] = code
            struct.pack_into("<QQ", blob, 96, 0x1000 + len(code), 0x1000 + len(code))
        binary = folder / (uuid.uuid4().hex[:8] + ".elf")
        binary.write_bytes(blob)
        return {"schema": "symbai.syntax_request.v1", "binary": str(binary), "binary_sha256": file_hash(binary),
                "entry_rva": TEXT - BASE, "target_store_rva": TEXT - BASE + write}

    return make


def available(request):
    result = provenance.build_syntax_provenance(request)
    assert result["status"] == "available", result.get("reason")
    assert result["complete"] is True
    return result


def unavailable(request):
    try:
        result = provenance.build_syntax_provenance(request)
    except ValueError:
        return
    assert result["status"] == "unavailable" and result["reason"]
    assert result["complete"] is False


def nodes(result):
    return {node["id"]: node for node in result["nodes"]}


def access(result, direction, index=0):
    return [item for item in result["accesses"] if item["direction"] == direction][index]


def binding(item, name):
    return next(value for value in item["register_bindings"] if value["register_name"] == name)


def ancestors(result, root, stop_at_reads=False):
    indexed = nodes(result)
    seen, pending = set(), [root]
    while pending:
        node_id = pending.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        node = indexed[node_id]
        if not stop_at_reads or node["kind"] != "register_read":
            pending.extend(node["operands"])
    return seen


def source_definitions(result, read_id):
    return {source["definition"] for source in nodes(result)[read_id]["byte_sources"]}


def test_all_original_mechanism_shapes_record_exact_memory_occurrences(make_request):
    for chain, last, expected in ((False, 6, ["write"]), (True, 6, ["read", "read", "write"]),
                                  (True, 12, ["read", "read", "write"])):
        request = make_request(chain=chain, last=last)
        result = available(request)
        assert result["identity"] == {key: request[key] for key in ("binary_sha256", "entry_rva", "target_store_rva")}
        assert [item["direction"] for item in result["accesses"]] == expected
        assert result["instructions"][-1]["rva"] == request["target_store_rva"]
        assert all(item["mnemonic"] != "ret" for item in result["instructions"])
        assert access(result, "write")["width_bits"] == 8
        assert all(item["width_bits"] == 64 for item in result["accesses"] if item["direction"] == "read")
        for item in result["accesses"]:
            node = nodes(result)[item["node"]]
            assert node["instruction_rva"] == item["instruction_rva"]
            assert node["address"] == item["address_node"]


def test_graph_edges_are_prior_and_temporary_identities_never_cross_instruction_scope(make_request):
    result = available(make_request(chain=True))
    indexed = nodes(result)
    assert [node["id"] for node in result["nodes"]] == [f"n{index}" for index in range(len(indexed))]
    prior, definitions, scopes = set(), {}, defaultdict(set)
    for node in result["nodes"]:
        assert node["kind"] in KINDS and type(node["width_bits"]) is int and node["width_bits"] > 0
        assert isinstance(node["operands"], list) and set(node["operands"]) <= prior
        if node["kind"] == "entry_byte":
            assert node["instruction_rva"] is node["statement_index"] is None
        else:
            assert type(node["instruction_rva"]) is type(node["statement_index"]) is int
        if node["kind"] in ("temporary_definition", "temporary_read"):
            key = (node["instruction_rva"], node["temporary"])
            scopes[node["temporary"]].add(node["instruction_rva"])
            if node["kind"] == "temporary_definition":
                assert key not in definitions
                definitions[key] = node["id"]
                assert node["value"] in node["operands"]
            else:
                assert definitions[key] in node["operands"]
        if node["kind"] == "register_read":
            sources = node["byte_sources"]
            assert len(sources) * 8 == node["width_bits"]
            assert [source["offset"] for source in sources] == list(range(node["register_offset"], node["register_offset"] + len(sources)))
            assert all(indexed[source["definition"]]["kind"] in ("entry_byte", "register_write") for source in sources)
            assert {source["definition"] for source in sources} <= set(node["operands"])
        prior.add(node["id"])
    assert any(len(pcs) > 1 for pcs in scopes.values()), "Fixture must exercise reused temporary numbers across PCs"
    assert result["edges"] == [{"source": source, "target": node["id"], "operand_index": index}
                               for node in result["nodes"] for index, source in enumerate(node["operands"])]


def test_intermediate_rax_pointer_and_rdi_versions_survive_later_overwrites(make_request):
    request = make_request(chain=True)
    result = available(request)
    indexed = nodes(result)
    first, second = [item for item in result["accesses"] if item["direction"] == "read"]
    target = access(result, "write")
    old_rax_get = binding(second, "rax")["read_node"]
    old_rax_writes = source_definitions(result, old_rax_get)
    assert len(old_rax_writes) == 1
    old_rax_write = indexed[next(iter(old_rax_writes))]
    assert old_rax_write["instruction_rva"] == first["instruction_rva"]
    assert first["node"] in ancestors(result, old_rax_write["value"])
    target_rax = binding(target, "rax")["read_node"]
    target_rdi = binding(target, "rdi")["read_node"]
    new_rax_writes = source_definitions(result, target_rax)
    assert len(new_rax_writes) == 1 and new_rax_writes.isdisjoint(old_rax_writes)
    new_rax_write = indexed[next(iter(new_rax_writes))]
    assert new_rax_write["instruction_rva"] > second["instruction_rva"]
    assert first["node"] not in ancestors(result, new_rax_write["value"])
    rdi_writes = source_definitions(result, target_rdi)
    assert len(rdi_writes) == 1
    rdi_write = indexed[next(iter(rdi_writes))]
    assert rdi_write["instruction_rva"] == second["instruction_rva"]
    assert second["node"] in ancestors(result, rdi_write["value"])
    assert {term["read_node"] for term in target["address_formula"]["terms"]} == {target_rax, target_rdi}


@pytest.mark.parametrize("write,changed,width", [("b0 12", [0], 8), ("b4 34", [1], 8),
                                                 ("66 b8 78 56", [0, 1], 16),
                                                 ("b8 78 56 34 12", list(range(8)), 64)])
def test_subregister_byte_updates_and_eax_zero_extension_follow_lifted_puts(make_request, write, changed, width):
    prefix = "48 b8 88 77 66 55 44 33 22 11 " + write
    request = make_request(prefix=prefix)
    result = available(request)
    indexed = nodes(result)
    target_read = indexed[binding(access(result, "write"), "rax")["read_node"]]
    definitions = [indexed[source["definition"]] for source in target_read["byte_sources"]]
    first_rva, second_rva = request["entry_rva"], request["entry_rva"] + 10
    for offset, definition in enumerate(definitions):
        assert definition["instruction_rva"] == (second_rva if offset in changed else first_rva)
    writes = {definition["id"]: definition for offset, definition in enumerate(definitions) if offset in changed}
    assert len(writes) == 1
    update = next(iter(writes.values()))
    assert update["width_bits"] == width
    assert update["register_offset"] == target_read["register_offset"] + (1 if changed == [1] else 0)
    if width == 64:
        assert indexed[update["value"]]["width_bits"] == 64
        assert not [indexed[node] for node in ancestors(result, update["value"]) if indexed[node]["kind"] == "register_read"]


def test_store_data_get_is_not_an_address_contributor(make_request):
    result = available(make_request(target="48 89 54 c8 10"))  # [rax+rcx*8+16] = rdx
    item, indexed = access(result, "write"), nodes(result)
    assert {entry["register_name"] for entry in item["register_bindings"]} == {"rax", "rcx"}
    assert item["address_formula"]["constant"] == 16
    store = indexed[item["node"]]
    address_reads = {node for node in ancestors(result, store["address"], True) if indexed[node]["kind"] == "register_read"}
    data_reads = {node for node in ancestors(result, store["data"], True) if indexed[node]["kind"] == "register_read"}
    assert address_reads == {entry["read_node"] for entry in item["register_bindings"]}
    assert {indexed[node]["register_name"] for node in data_reads} == {"rdx"}
    assert address_reads.isdisjoint(data_reads)


def test_load_into_its_own_address_register_reads_old_definition_first(make_request):
    result = available(make_request(prefix="48 8b 00"))
    first, target, indexed = access(result, "read"), access(result, "write"), nodes(result)
    old_read = binding(first, "rax")["read_node"]
    assert all(indexed[node]["kind"] == "entry_byte" for node in source_definitions(result, old_read))
    later_read = binding(target, "rax")["read_node"]
    definitions = source_definitions(result, later_read)
    assert len(definitions) == 1
    write = indexed[next(iter(definitions))]
    assert write["kind"] == "register_write" and first["node"] in ancestors(result, write["value"])


def test_multiple_get_and_put_events_preserve_statement_time_not_final_state(make_request):
    request = make_request(prefix="48 01 d8 48 89 c1", target="c6 01 41")  # add rax,rbx; rcx=rax; [rcx]=byte
    result = available(request)
    indexed = nodes(result)
    first_rva = request["entry_rva"]
    first_reads = [node for node in result["nodes"] if node["kind"] == "register_read" and node["instruction_rva"] == first_rva]
    first_writes = [node for node in result["nodes"] if node["kind"] == "register_write" and node["instruction_rva"] == first_rva]
    assert {node["register_name"] for node in first_reads} >= {"rax", "rbx"}
    assert len(first_writes) >= 3  # General register, condition-code state and PC are separate Put events.
    for read in [node for node in first_reads if node["register_name"] in ("rax", "rbx")]:
        assert all(indexed[source["definition"]]["kind"] == "entry_byte" for source in read["byte_sources"])
    for read in [node for node in result["nodes"] if node["kind"] == "register_read"]:
        for source in read["byte_sources"]:
            definition = indexed[source["definition"]]
            if definition["kind"] == "register_write":
                assert (definition["instruction_rva"], definition["statement_index"]) < (read["instruction_rva"], read["statement_index"])
    copied_rax = next(node for node in result["nodes"] if node["kind"] == "register_read"
                      and node["register_name"] == "rax" and node["instruction_rva"] == first_rva + 3)
    assert all(indexed[source["definition"]]["instruction_rva"] == first_rva for source in copied_rax["byte_sources"])


def test_rip_load_and_scaled_address_are_matched_without_dereference(make_request):
    displacement = struct.pack("<i", READONLY - (TEXT + 7)).hex(" ")
    result = available(make_request(prefix="48 8b 05 " + displacement))
    first = access(result, "read")
    assert first["address_formula"] == {"constant": READONLY, "terms": []}
    assert first["register_bindings"] == []
    result = available(make_request(prefix="48 8b 44 fa 10"))  # [rdx+rdi*8+16]
    first = access(result, "read")
    assert first["address_formula"]["constant"] == 16
    assert {(item["role"], item["register_name"], item["scale"]) for item in first["register_bindings"]} == {
        ("base", "rdx", 1), ("index", "rdi", 8)}
    assert {(term["read_node"], term["register_offset"], term["coefficient"]) for term in first["address_formula"]["terms"]} == {
        (item["read_node"], item["register_offset"], item["scale"]) for item in first["register_bindings"]}


def test_only_opaque_loads_and_no_store_to_load_value_forwarding(make_request):
    result = available(make_request(prefix="48 89 02 48 8b 02"))  # [rdx]=rax; rax=[rdx]
    indexed = nodes(result)
    read = access(result, "read")
    load = indexed[read["node"]]
    assert load["operands"] == [load["address"]]
    assert "value" not in load and "loaded_bytes" not in load and "concrete_value" not in load
    assert result["memory_value_provenance"] == "opaque_no_dereference_or_store_to_load_forwarding"
    for name in ("property_verification_performed", "neural_information_used", "tygr_readout_compatibility_validated"):
        assert result[name] is False


def test_data_only_difference_and_path_changes_leave_normalized_syntax_identical(make_request):
    safe_request, outside_request = make_request(chain=True, last=6), make_request(chain=True, last=12)
    safe, outside = available(safe_request), available(outside_request)
    assert safe["identity"]["binary_sha256"] != outside["identity"]["binary_sha256"]
    assert safe["syntax_fingerprint"] == outside["syntax_fingerprint"]
    assert safe["nodes"] == outside["nodes"] and safe["accesses"] == outside["accesses"]
    moved = Path(safe_request["binary"]).with_name("opposite-expected-status.elf")
    moved.write_bytes(Path(safe_request["binary"]).read_bytes())
    renamed = available({**safe_request, "binary": str(moved)})
    assert renamed == safe


@pytest.mark.parametrize("field", ["capacity", "object_rva", "inputs", "expected", "gold", "raw_types", "proof", "query_id"])
def test_request_rejects_property_type_and_old_evidence_fields(make_request, field):
    request = make_request()
    request[field] = "forbidden"
    unavailable(request)


@pytest.mark.parametrize("change", ["schema", "hash", "entry_bool", "target_bool", "negative", "target_before_entry", "missing"])
def test_invalid_minimal_requests_are_rejected(make_request, change):
    request = make_request()
    if change == "schema": request["schema"] = "symbai.queries.v1"
    elif change == "hash": request["binary_sha256"] = "0" * 64
    elif change == "entry_bool": request["entry_rva"] = True
    elif change == "target_bool": request["target_store_rva"] = False
    elif change == "negative": request["entry_rva"] = -1
    elif change == "target_before_entry": request["target_store_rva"] = request["entry_rva"] - 1
    else: del request["binary"]
    unavailable(request)


@pytest.mark.parametrize("damage", ["missing_file", "not_elf"])
def test_unreadable_or_malformed_binary_has_the_declared_input_error_boundary(make_request, damage):
    request = make_request()
    if damage == "missing_file":
        request["binary"] = str(Path(request["binary"]).with_name("missing-file.elf"))
    else:
        Path(request["binary"]).write_bytes(b"fabricated invalid ELF header")
        request["binary_sha256"] = file_hash(request["binary"])
    unavailable(request)


@pytest.mark.parametrize("prefix", ["eb 00", "e8 00 00 00 00", "c3", "67 48 8b 00", "f0 48 83 00 01", "a4", "48 8b 04 5b"])
def test_branches_calls_special_effects_addr32_and_repeated_base_index_are_unavailable(make_request, prefix):
    unavailable(make_request(prefix=prefix))


def test_truncated_instruction_non_store_and_mid_instruction_target_are_unavailable(make_request):
    unavailable(make_request(raw=bytes.fromhex("48 8b"), target_offset=0))
    unavailable(make_request(raw=bytes.fromhex("48 89 d8 c6 00 41"), target_offset=0))
    unavailable(make_request(prefix="48 89 d8", target_offset=1))


@pytest.mark.parametrize("damage", ["unknown_after_store", "multiple_imark", "wrong_imark_address", "wrong_imark_length",
                                    "wrong_imark_delta", "non_fallthrough", "unknown_expression"])
def test_entire_target_ir_is_validated_before_returning_available(make_request, monkeypatch, damage):
    import pyvex
    request = make_request(prefix="90")
    target = BASE + request["target_store_rva"]
    original = provenance._lift_instruction

    def modified(data, address, arch):
        block = original(data, address, arch)
        if address != target:
            return block
        if damage == "unknown_after_store":
            block.statements.append(SimpleNamespace(tag="Ist_UnknownUnitEffect"))
        elif damage == "multiple_imark":
            block.statements.append(pyvex.stmt.IMark(address + len(data), 1, 0))
        elif damage.startswith("wrong_imark"):
            index = next(index for index, statement in enumerate(block.statements) if statement.tag == "Ist_IMark")
            block.statements[index] = pyvex.stmt.IMark(address + (1 if damage == "wrong_imark_address" else 0),
                                                     len(data) + (1 if damage == "wrong_imark_length" else 0),
                                                     1 if damage == "wrong_imark_delta" else 0)
        elif damage == "non_fallthrough":
            block.next = pyvex.expr.Const(pyvex.const.U64(address + len(data) + 1))
        else:
            store = next(statement for statement in block.statements if statement.tag == "Ist_Store")
            store.data = SimpleNamespace(tag="Iex_UnknownUnitValue", result_size=lambda tyenv: 8)
        return block

    monkeypatch.setattr(provenance, "_lift_instruction", modified)
    unavailable(request)


@pytest.mark.parametrize("damage", ["displacement", "scale", "extra_register", "width", "endness"])
def test_independent_capstone_address_or_access_check_rejects_modified_ir(make_request, monkeypatch, damage):
    import pyvex
    request = make_request(target="48 89 54 c8 10")
    original = provenance._lift_instruction
    def changed(data, address, arch):
        block = original(data, address, arch)
        store = next(statement for statement in block.statements if statement.tag == "Ist_Store")
        if damage == "displacement":
            store.addr = pyvex.expr.Binop("Iop_Add64", [store.addr, pyvex.expr.Const(pyvex.const.U64(1))])
        elif damage == "scale":
            store.addr = pyvex.expr.Binop("Iop_Mul64", [store.addr, pyvex.expr.Const(pyvex.const.U64(2))])
        elif damage == "extra_register":
            store.addr = pyvex.expr.Binop("Iop_Add64", [store.addr, pyvex.expr.Get(arch.registers["rsi"][0], "Ity_I64")])
        elif damage == "width":
            store.data = pyvex.expr.Const(pyvex.const.U8(0))
        else:
            store.end = "Iend_BE"
        return block
    monkeypatch.setattr(provenance, "_lift_instruction", changed)
    unavailable(request)


def test_fixed_instruction_limit_keeps_partial_artifact_unavailable(make_request):
    request = make_request(prefix="90 " * 64)
    result = provenance.build_syntax_provenance(request)
    assert result["status"] == "unavailable" and result["complete"] is False
    assert len(result["instructions"]) == 64
    assert all(item["rva"] < request["target_store_rva"] for item in result["instructions"])


def test_lifter_exception_in_second_instruction_preserves_completed_prefix(make_request, monkeypatch):
    request = make_request(prefix="48 89 d8 48 89 c1", target="c6 01 41")
    original = provenance._lift_instruction
    calls = []
    def fail_second(data, address, arch):
        calls.append(address)
        if len(calls) == 2:
            raise RuntimeError("fabricated second-instruction lift failure")
        return original(data, address, arch)
    monkeypatch.setattr(provenance, "_lift_instruction", fail_second)
    result = provenance.build_syntax_provenance(request)
    assert result["status"] == "unavailable" and result["complete"] is False
    assert "RuntimeError" in result["reason"] and "second-instruction" in result["reason"]
    assert len(result["instructions"]) == 1
    assert result["instructions"][0]["rva"] == request["entry_rva"]
    assert result["instructions"][0]["bytes"] == "4889d8"
    assert result["nodes"] and any(node["kind"] == "register_write" for node in result["nodes"])
    assert all(node["instruction_rva"] in (None, request["entry_rva"]) for node in result["nodes"])
    assert result["accesses"] == []


def test_lifter_receives_only_one_exact_instruction_and_no_forbidden_engines_import(make_request, monkeypatch):
    original = provenance._lift_instruction
    calls, before = [], set(sys.modules)
    def record(data, address, arch):
        calls.append((bytes(data), address))
        return original(data, address, arch)
    monkeypatch.setattr(provenance, "_lift_instruction", record)
    request = make_request(chain=True)
    result = available(request)
    assert calls == [(bytes.fromhex(instruction["bytes"]), BASE + instruction["rva"]) for instruction in result["instructions"]]
    assert all(len(data) == instruction["length"] for (data, _), instruction in zip(calls, result["instructions"]))
    assert not [name for name in set(sys.modules) - before if name.split(".")[0] in ("angr", "claripy", "z3", "torch")]
