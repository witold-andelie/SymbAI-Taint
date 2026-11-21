"""Hand-assembled and project-disjoint checks for static structural features."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys

import capstone
import pytest

from src.selective_analysis.contracts import InputRange, Query
from src.selective_analysis.structural_features import (
    FEATURE_SCHEMA,
    extract_features,
    feature_names,
    feature_vector,
)


BASE = 0x400000
PAGE = 0x1000
TEXT = BASE + PAGE
DATA = BASE + 2 * PAGE
PANEL = "route-b-project-disjoint-20261119T141817Z"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def make_elf(code):
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, TEXT, 64, 0, 0,
                         64, 56, 3, 0, 0, 0)
    ph0 = struct.pack("<IIQQQQQQ", 1, 4, 0, BASE, BASE, PAGE, PAGE, PAGE)
    ph1 = struct.pack("<IIQQQQQQ", 1, 5, PAGE, TEXT, TEXT, len(code), len(code), PAGE)
    ph2 = struct.pack("<IIQQQQQQ", 1, 6, 2 * PAGE, DATA, DATA, 8, PAGE, PAGE)
    return (header + ph0 + ph1 + ph2).ljust(PAGE, b"\0") + code + b"\0" * 8


def make_query(code, write_off, capacity=8, maximum=15, query_id="unit"):
    blob = make_elf(code)
    query = Query(query_id, "in-memory.elf", _sha(blob), TEXT - BASE,
                  TEXT - BASE + write_off, DATA - BASE, capacity,
                  (InputRange("rdi", 0, maximum),))
    return query, blob


def mnemonics(code):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    return [insn.mnemonic for insn in decoder.disasm(code, TEXT)]


def assert_vector(features):
    names = feature_names()
    assert list(features) == ["schema"] + names
    assert features["schema"] == FEATURE_SCHEMA
    vector = feature_vector(features)
    assert len(vector) == len(names)
    assert all(isinstance(value, float) for value in vector)


def test_determinism_same_bytes_same_dict():
    code = bytes.fromhex("31 c0 83 c0 01 83 f8 08 7c f8 c3")
    query, blob = make_query(code, 0)
    first = extract_features(query, elf_bytes=blob)
    second = extract_features(query, elf_bytes=bytes(blob))
    assert first == second
    assert_vector(first)


def test_loop_counts():
    # xor eax,eax; add eax,1; cmp eax,8; jl add; ret
    code = bytes.fromhex("31 c0 83 c0 01 83 f8 08 7c f8 c3")
    assert mnemonics(code) == ["xor", "add", "cmp", "jl", "ret"]
    query, blob = make_query(code, 0)
    features = extract_features(query, elf_bytes=blob)
    assert_vector(features)
    assert features["instruction_count"] == 5
    assert features["basic_block_count"] == 3
    assert features["conditional_branch_count"] == 1
    assert features["unconditional_branch_count"] == 0
    assert features["back_edge_count"] == 1
    assert features["direct_call_count"] == 0
    assert features["indirect_call_count"] == 0
    assert features["distinct_callee_count"] == 0
    assert features["ret_count"] == 1
    assert features["compare_count"] == 1
    assert features["test_count"] == 0
    assert features["stack_load_count"] == 0
    assert features["stack_store_count"] == 0
    assert features["rip_load_count"] == 0
    assert features["other_load_count"] == 0
    assert features["other_store_count"] == 0
    assert features["truncated"] is False
    assert features["indirect_transfer_seen"] is False
    assert features["store_site_found"] is False
    assert features["domain_size"] == 16
    assert features["log2_domain_size"] == 4.0
    assert features["capacity"] == 8
    assert features["log2_capacity"] == 3.0
    assert features["input_register_count"] == 1


def test_conditional_counts():
    # cmp rdi,0; je ret; nop; ret
    code = bytes.fromhex("48 83 ff 00 74 01 90 c3")
    assert mnemonics(code) == ["cmp", "je", "nop", "ret"]
    query, blob = make_query(code, 0)
    features = extract_features(query, elf_bytes=blob)
    assert_vector(features)
    assert features["instruction_count"] == 4
    assert features["basic_block_count"] == 3
    assert features["conditional_branch_count"] == 1
    assert features["unconditional_branch_count"] == 0
    assert features["back_edge_count"] == 0
    assert features["ret_count"] == 1
    assert features["compare_count"] == 1
    assert features["store_site_found"] is False
    assert features["truncated"] is False
    assert features["indirect_transfer_seen"] is False


def test_call_counts():
    # call callee; ret; callee: ret
    code = bytes.fromhex("e8 01 00 00 00 c3 c3")
    assert mnemonics(code) == ["call", "ret", "ret"]
    query, blob = make_query(code, 0)
    features = extract_features(query, elf_bytes=blob)
    assert_vector(features)
    assert features["instruction_count"] == 3
    assert features["basic_block_count"] == 3
    assert features["direct_call_count"] == 1
    assert features["indirect_call_count"] == 0
    assert features["distinct_callee_count"] == 1
    assert features["ret_count"] == 2
    assert features["conditional_branch_count"] == 0
    assert features["unconditional_branch_count"] == 0
    assert features["back_edge_count"] == 0
    assert features["store_site_found"] is False
    assert features["truncated"] is False
    assert features["indirect_transfer_seen"] is False


def test_masked_index_store_counts():
    # and edi,7; lea rax,[rip+0]; mov byte ptr [rax+rdi],0x41; ret
    code = bytes.fromhex("83 e7 07 48 8d 05 00 00 00 00 c6 04 38 41 c3")
    assert mnemonics(code) == ["and", "lea", "mov", "ret"]
    query, blob = make_query(code, 10, capacity=8, maximum=15)
    features = extract_features(query, elf_bytes=blob)
    assert_vector(features)
    assert features["instruction_count"] == 4
    assert features["basic_block_count"] == 1
    assert features["ret_count"] == 1
    assert features["rip_load_count"] == 0
    assert features["other_store_count"] == 1
    assert features["stack_load_count"] == 0
    assert features["stack_store_count"] == 0
    assert features["other_load_count"] == 0
    assert features["store_site_found"] is True
    assert features["store_has_base"] == 1
    assert features["store_has_index"] == 1
    assert features["store_scale"] == 1
    assert features["store_disp_magnitude"] == 0
    assert features["store_index_masked"] == 1
    assert features["truncated"] is False
    assert features["indirect_transfer_seen"] is False
    assert features["domain_size"] == 16
    assert features["log2_domain_size"] == 4.0
    assert features["capacity"] == 8
    assert features["log2_capacity"] == 3.0
    assert features["input_register_count"] == 1


def test_reads_fixture_bytes_from_query_path():
    code = bytes.fromhex("83 e7 07 48 8d 05 00 00 00 00 c6 04 38 41 c3")
    query, blob = make_query(code, 10)
    folder = Path(".test-output") / "structural-file-read"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    path = folder / "unit.elf"
    try:
        path.write_bytes(blob)
        on_disk = Query("unit", str(path), _sha(blob), query.entry_rva, query.write_rva,
                        query.object_rva, query.capacity, query.inputs)
        features = extract_features(on_disk)
        assert features["store_site_found"] is True
        assert features == extract_features(on_disk, elf_bytes=blob)
    finally:
        shutil.rmtree(folder)


def test_malformed_elf_and_rva_outside_executable():
    code = bytes.fromhex("c3")
    query, blob = make_query(code, 0)
    with pytest.raises(ValueError):
        extract_features(query, elf_bytes=b"not-an-elf")
    with pytest.raises(ValueError):
        extract_features(Query("bad-entry", "in-memory.elf", _sha(blob), 0,
                               query.write_rva, query.object_rva, 8, query.inputs),
                         elf_bytes=blob)
    with pytest.raises(ValueError):
        extract_features(Query("bad-write", "in-memory.elf", _sha(blob), query.entry_rva,
                               DATA - BASE, query.object_rva, 8, query.inputs),
                         elf_bytes=blob)


def test_does_not_import_angr_or_solvers():
    before = set(sys.modules)
    code = bytes.fromhex("c3")
    query, blob = make_query(code, 0)
    extract_features(query, elf_bytes=blob)
    loaded = set(sys.modules) - before
    assert not loaded.intersection(("angr", "claripy", "z3", "pyvex"))


def _panel_dir():
    here = Path(__file__).resolve()
    seen = []
    for root in [Path("."), here.parent, here.parents[1], *here.parents]:
        for rel in (
            Path("..") / ".scratch" / "selective_analysis" / PANEL,
            Path(".scratch") / "selective_analysis" / PANEL,
            Path("selective_analysis") / PANEL,
        ):
            candidate = (root / rel).resolve()
            if candidate in seen:
                continue
            seen.append(candidate)
            if (candidate / "intake.json").is_file():
                return candidate
    return None


def _panel_cases():
    folder = _panel_dir()
    if folder is None:
        pytest.skip("project-disjoint fixtures unavailable: panel directory not found")
    try:
        intake = json.loads((folder / "intake.json").read_text(encoding="utf-8"))
    except OSError:
        pytest.skip("project-disjoint fixtures unavailable: intake.json cannot be read")
    rows = []
    for rec in intake.values():
        query = rec.get("query")
        if rec.get("status") != "available" or not isinstance(query, dict):
            continue
        local = folder / (query["query_id"] + ".elf")
        path = local if local.is_file() else Path(query["binary"])
        if not path.is_file():
            continue
        data = path.read_bytes()
        rows.append(Query(
            query["query_id"], str(path), query["binary_sha256"], query["entry_rva"],
            query["write_rva"], query["object_rva"], query["capacity"],
            tuple(InputRange(**item) for item in query["inputs"]),
            query.get("scope", "first_dynamic_visit"),
            query.get("bounds_source", "explicit_query_contract"),
        ))
        rows[-1] = (rows[-1], data)
    if len(rows) != 6:
        pytest.skip("project-disjoint fixtures unavailable: expected 6 ELF queries, found %d"
                    % len(rows))
    return rows


def test_project_disjoint_fixtures():
    names = feature_names()
    for query, data in _panel_cases():
        features = extract_features(query, elf_bytes=data)
        assert features["store_site_found"] is True
        assert features["schema"] == FEATURE_SCHEMA
        assert len(feature_vector(features)) == len(names)
        assert_vector(features)
