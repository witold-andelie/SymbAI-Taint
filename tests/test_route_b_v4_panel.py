"""Native construction checks; these tests never build held-out sources."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import pytest

from src.selective_analysis import fixture_build as fixture
from scripts import build_route_b_v4_panel as builder


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = (ROOT.parent / ".scratch/selective_analysis"
           / "route-b-project-disjoint-20261119T141817Z")


@pytest.fixture(scope="module", autouse=True)
def native_temporary_directory():
    path = ROOT / ".test-output/temp"
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    previous = {key: os.environ.get(key) for key in ("TEMP", "TMP")}
    os.environ.update(TEMP=str(path), TMP=str(path))
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if not existed:
            path.rmdir()


@contextlib.contextmanager
def workspace(name):
    path = ROOT / ".test-output" / name
    assert path.resolve().parent == (ROOT / ".test-output").resolve()
    if path.exists():
        shutil.rmtree(str(path))
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(str(path))


def load(path):
    return json.loads(path.read_bytes())


def test_archived_six_cases_are_byte_identical():
    cohort = load(ARCHIVE / "cohort.json")
    intake = load(ARCHIVE / "intake.json")
    sources = {}
    for name, meta in cohort["sources"].items():
        data = (ARCHIVE / meta["file"]).read_bytes()
        assert hashlib.sha1(("blob %d\0" % len(data)).encode() + data).hexdigest() == meta["git_blob_sha1"]
        sources[name] = data
    assert len(cohort["cases"]) == 6
    with workspace("route-b-v4-regression") as output:
        for case in cohort["cases"]:
            query, reference = fixture.compile_case(case, sources, output,
                                                    cohort["capacity"], cohort["flags"])
            archived = ARCHIVE / (case["id"] + ".elf")
            assert (output / query["binary"]).read_bytes() == archived.read_bytes(), case["id"]
            expected = intake[case["id"]]["query"]
            for key in ("entry_rva", "write_rva", "object_rva", "capacity", "inputs", "binary_sha256"):
                actual = json.loads(json.dumps(query[key]))
                assert actual == expected[key], (case["id"], key)
            assert reference["indices"] == load(ARCHIVE / (case["id"] + "-native-reference.json"))["indices"]
            assert reference["outcome"] == "safe"


@pytest.mark.parametrize("indices,capacity,minimum,expected", [
    ([0, 1, 9], 10, 0, {"outcome": "safe"}),
    ([0, 10, 999, 10], 10, 4, {"outcome": "violation", "witness": {"rdi": 5}}),
    ([None, 9, None], 10, 0, {"outcome": "safe"}),
    ([None, None], 10, 0, {"outcome": "safe"}),
    ([2 ** 64 - 1, 0], 65536, 0, {"outcome": "violation", "witness": {"rdi": 0}}),
])
def test_outcome(indices, capacity, minimum, expected):
    assert fixture.derive_outcome(indices, capacity, minimum) == expected


@pytest.mark.parametrize("capacity", [0, -1, 2 ** 64])
def test_invalid_capacity(capacity):
    with pytest.raises(ValueError):
        fixture.derive_outcome([0], capacity)


@pytest.mark.parametrize("indices,capacities", [
    ([0, 0], [1]), ([0, 1], [2, 1]), ([65535], [65536, 65535]),
    ([65536], [65536]), ([2 ** 64 - 1], [65536]),
])
def test_s2_capacity_rule(indices, capacities):
    assert fixture.s2_capacities(indices) == capacities


def test_native_out_of_bounds_and_runtime_separation():
    spec = {"id": "wide", "min": 0, "max": 255, "definition":
            "static uint64_t f(uint64_t x) { return x ? UINT64_MAX : 0; }", "call": "f(x)"}
    with workspace("route-b-v4-wide") as output:
        query, reference = fixture.compile_case(spec, {}, output, 10)
        assert reference["indices"] == [0] + [2 ** 64 - 1] * 255
        assert reference["witness"] == {"rdi": 1}
        assert str(2 ** 64 - 1) not in (output / "wide-build.log").read_text()
        rows = [{"case_id": "wide", "stratum": "S2", "project": "tiny",
                 "binary_group": "tiny", "query": query}]
        fixture.write_panel(output, rows, {"wide": reference})
        runtime = (output / "panel.json").read_text()
        for word in ("outcome", "indices", "witness", "safe", "violation"):
            assert word not in runtime
        assert load(output / "offline-references.json")["references"]["wide"] == reference
        fixture.Query.from_dict(load(output / "panel.json")["records"][0]["query"], output)
        with pytest.raises(ValueError):
            fixture.write_panel(output, [dict(rows[0], outcome="safe")], {})


def debug_elf_from_pe(path, target):
    """Wrap already linked MinGW DWARF sections for the tiny test inventory.

    No objcopy or Linux compiler is needed; linked PE DWARF section references
    are section-relative already. This is test input, never a runtime fixture.
    """
    import pefile

    raw = path.read_bytes()
    image = pefile.PE(data=raw)
    strings = image.FILE_HEADER.PointerToSymbolTable + 18 * image.FILE_HEADER.NumberOfSymbols
    sections = []
    for section in image.sections:
        name = section.Name.rstrip(b"\0")
        if name.startswith(b"/"):
            first = strings + int(name[1:])
            name = raw[first:raw.index(b"\0", first)]
        if name.startswith(b".debug_"):
            sections.append((name, section.get_data()[:section.Misc_VirtualSize]))
    assert {name for name, _ in sections} >= {b".debug_info", b".debug_abbrev", b".debug_line"}
    names = b"\0.shstrtab\0"
    name_offsets = {}
    for name, _ in sections:
        name_offsets[name] = len(names)
        names += name + b"\0"
    payload = bytearray(b"\0" * 64)
    headers = [b"\0" * 64]
    headers.append(struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, len(payload), len(names), 0, 0, 1, 0))
    payload.extend(names)
    for name, data in sections:
        headers.append(struct.pack("<IIQQQQIIQQ", name_offsets[name], 1, 0, 0,
                                   len(payload), len(data), 0, 0, 1, 0))
        payload.extend(data)
    shoff = len(payload)
    payload.extend(b"".join(headers))
    payload[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                               2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), 1)
    target.write_bytes(payload)


TINY_SOURCE = """#include <stdint.h>
typedef unsigned char byte;
enum kind { ZERO, ONE };
static int unused_external(int x) { extern int absent(int); return absent(x); }
static const unsigned char table[2] = {0, 1};
static int dep(int x) { return table[x & 1]; }
int integer_kernel(byte x) { return dep(x); }
int char_kernel(const char *s) { return (unsigned char)s[0]; }
int bool_kernel(_Bool x) { return x; }
int enum_kernel(enum kind x) { return x; }
int wrong_count(int x, int y) { return x + y; }
double wrong_return(int x) { return x; }
int wrong_pointer(unsigned char *x) { return *x; }
int wrong_volatile(volatile char *x) { return *x; }
int wrong_variadic(int x, ...) { return x; }
int link_failure(int x) { extern int absent(int); return absent(x); }
int main(void) { return 0; }
"""


def tiny_project(root):
    source_dir = root / "sources/tiny"
    source_dir.mkdir(parents=True)
    source = source_dir / "tiny.c"
    fixture.write_text(source, TINY_SOURCE)
    # An object with unresolved externals cannot be natively linked. Build the
    # inventory with the two intentionally non-freestanding functions omitted,
    # then give DWARF its exact, unchanged declaration line positions.
    inventory_source = source_dir / "inventory.c"
    fixture.write_text(inventory_source, TINY_SOURCE.replace(
        "extern int absent(int); return absent(x);", "return x;"))
    executable = root / "tiny-debug.exe"
    fixture.cmd(["gcc", "-O0", "-g", "-gdwarf-4", "-fno-inline", "-fkeep-inline-functions",
                 str(inventory_source), "-o", str(executable)], ROOT)
    dwarf_elf = root / "tiny.elf"
    debug_elf_from_pe(executable, dwarf_elf)
    executable.unlink()
    # The source-location matcher must use the exact source path from DWARF.
    # Rename the recorded inventory file back to its source role in this fixture.
    fixture.write_text(inventory_source, TINY_SOURCE)
    project = {"project_id": "tiny", "source_directory": builder.relative(source_dir),
               "source_files": {"inventory.c": fixture.file_hash(inventory_source)},
               "dwarf_elf": builder.relative(dwarf_elf)}
    manifest = root / "sources.json"
    fixture.write_json(manifest, {"schema": "symbai.route_b_v4_sources.v1", "projects": [project]})
    return manifest, project


def test_plan_only_tiny_project_and_rejection_recording():
    with workspace("route-b-v4-plan") as root:
        manifest, _ = tiny_project(root)
        output = root / "panel"
        result = subprocess.run([sys.executable, "-B", "scripts/build_route_b_v4_panel.py",
                                 "--plan-only", "--output", builder.relative(output),
                                 "--sources-manifest", builder.relative(manifest),
                                 "--juliet-dir", builder.relative(root / "empty-juliet")],
                                cwd=str(ROOT), capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        plan = load(output / "plan.json")
        assert sorted(path.name for path in output.iterdir()) == ["plan.json"]
        assert {row["name"] for row in plan["candidates"]} == {
            "unused_external", "dep", "integer_kernel", "char_kernel", "bool_kernel", "enum_kernel", "link_failure"}
        by_name = {row["name"]: row for row in plan["candidates"]}
        assert by_name["char_kernel"]["spec"]["setup"] == "char s[2] = {(char)x, 0};"
        assert by_name["char_kernel"]["spec"]["call"] == "char_kernel(s)"
        assert by_name["integer_kernel"]["spec"]["call"] == "integer_kernel((byte)x)"
        assert by_name["integer_kernel"]["spec"]["static_dependencies"] == ["dep"]
        assert "unused_external" not in by_name["integer_kernel"]["spec"]["definition"]
        assert "table[2]" in by_name["integer_kernel"]["spec"]["definition"]
        rejected = {row["name"]: row["reason"] for row in plan["rejections"] if "name" in row}
        assert rejected["wrong_count"] == "signature_parameter_count"
        assert rejected["wrong_return"] == "signature_return_type"
        assert rejected["wrong_pointer"] == "signature_parameter_type"
        assert rejected["wrong_volatile"] == "signature_parameter_type"
        assert rejected["wrong_variadic"] == "signature_parameter_count"
        assert rejected["main"] == "signature_parameter_count"
        assert all(row["status"] == "pending_freestanding_link" for row in plan["candidates"])
        assert plan["design_sha256"] == fixture.file_hash(builder.DESIGN)
        assert plan["compiler"]["version"].startswith("gcc")
        assert plan["overlap_check"]["projects"]["tiny"] == {"overlap": False}
        builder.verify_pins(plan)


def test_build_tiny_project_with_real_link_rejections():
    with workspace("route-b-v4-tiny-build") as root:
        manifest, _ = tiny_project(root)
        plan = builder.make_plan(root / "empty-juliet", manifest)
        output = root / "panel"
        output.mkdir()
        failures = builder.build_panel(plan, output)
        assert set(failures) == {row["case_id"] for row in plan["candidates"]
                                 if row.get("name") in ("unused_external", "link_failure")}
        reasons = {row.get("name"): row["reason"] for row in plan["rejections"]}
        assert reasons["link_failure"] == "freestanding_link_failed"
        assert reasons["unused_external"] == "freestanding_link_failed"
        assert load(output / "plan.json")["build_complete"] is True
        runtime = load(output / "panel.json")
        offline = load(output / "offline-references.json")
        assert len(runtime["records"]) == 10
        assert len(offline["references"]) == 10
        for row in runtime["records"]:
            query = fixture.Query.from_dict(row["query"], output)
            assert query.capacity in (1, 2, 255, 256)
            assert row["binary_group"] == "tiny"
            assert row["query"]["query_id"] == row["case_id"]
            reference = offline["references"][row["case_id"]]
            assert len(reference["indices"]) == 256
            assert reference["outcome"] == ("safe" if query.capacity in (2, 256) else "violation")


def test_plan_only_never_compiles_and_build_reuses_plan(monkeypatch):
    with workspace("route-b-v4-frozen-plan") as root:
        manifest, _ = tiny_project(root)
        output = root / "panel"
        original_cmd = fixture.cmd

        def version_only(args, *rest, **kwargs):
            assert args in (["gcc", "--version"], ["gcc", "-dumpmachine"])
            return original_cmd(args, *rest, **kwargs)

        monkeypatch.setattr(fixture, "cmd", version_only)
        assert builder.main(["--plan-only", "--output", builder.relative(output),
                             "--sources-manifest", builder.relative(manifest),
                             "--juliet-dir", builder.relative(root / "empty-juliet")]) == 0
        frozen = load(output / "plan.json")
        monkeypatch.setattr(fixture, "cmd", original_cmd)

        def no_reselection(*args, **kwargs):
            raise AssertionError("A frozen plan must not reselect candidates")

        monkeypatch.setattr(builder, "make_plan", no_reselection)
        assert builder.main(["--build", "--output", builder.relative(output)]) == 0
        built = load(output / "plan.json")
        assert built["hashes"] == frozen["hashes"]
        assert built["compiler"] == frozen["compiler"]
        assert built["runtime_queries"] == 10


def test_changed_input_and_native_reference_failure_are_not_silently_dropped(monkeypatch):
    with workspace("route-b-v4-failure") as root:
        manifest, project = tiny_project(root)
        plan = builder.make_plan(root / "empty-juliet", manifest)
        source = ROOT / project["source_directory"] / "inventory.c"
        original = source.read_text()
        fixture.write_text(source, original + "\n")
        with pytest.raises(ValueError, match="Input changed"):
            builder.verify_pins(plan)
        fixture.write_text(source, original)
        plan["candidates"] = [row for row in plan["candidates"] if row["name"] == "integer_kernel"]

        def fail_reference(*args, **kwargs):
            raise ValueError("incomplete enumeration")

        monkeypatch.setattr(fixture, "native_reference", fail_reference)
        output = root / "panel"
        output.mkdir()
        assert builder.build_panel(plan, output) == [plan["candidates"][0]["case_id"]]
        assert plan["build_complete"] is False
        assert plan["rejections"][-1]["reason"] == "native_reference_failed"
        assert load(output / "panel.json")["records"] == []


@pytest.mark.parametrize("indices", [[], [-1], [2 ** 64]])
def test_invalid_reference_indices(indices):
    with pytest.raises(ValueError):
        fixture.derive_outcome(indices, 10)
    with pytest.raises(ValueError):
        fixture.s2_capacities(indices)


def test_static_dependency_closure_through_macros_and_data():
    source = """#define APPLY(x) helper(x)
static int helper(int x) { return x & 1; }
static int via_pointer(int x) { return x; }
static int (*const dispatch)(int) = via_pointer;
static int unrelated(int x) { return missing(x); }
int kernel(int x) { return APPLY(x) + dispatch(x); }
"""
    names = ("helper", "via_pointer", "unrelated", "kernel")
    spans = {name: builder.definition_span(source, name, line)
             for name, line in zip(names, (2, 3, 5, 6))}
    selected = {"kernel"}
    context = builder.declaration_context(source, spans, selected, (), names[:-1])
    assert selected == {"kernel", "helper", "via_pointer"}
    assert "dispatch" in context
    assert "unrelated" not in context and "missing" not in context


def test_overlap_and_sealed_projects_are_rejected_without_source_reads():
    plan = {"hashes": {}, "candidates": [], "rejections": [], "overlap_check": {"projects": {}}}
    builder.select_projects(plan, [{"project_id": "AlreadySeen"}, {"project_id": "b64"},
                                   {"project_id": "utf8_h"}], {"alreadyseen"})
    assert [row["reason"] for row in plan["rejections"]] == [
        "project_overlap", "sealed_project", "sealed_project"]
    assert plan["hashes"] == {}


def test_output_confinement():
    assert builder.output_directory(".test-output/route-b-v4-output") == ROOT / ".test-output/route-b-v4-output"
    for path in (".", "..", ".test-output", ".test-output/../outside"):
        with pytest.raises(ValueError):
            builder.output_directory(path)


def test_juliet_selection_preserves_constants_guards_and_source_casts():
    # Reading/transformation only: the held-out sources are never compiled here.
    paths = sorted((ROOT / "benchmarks/juliet/cases").glob("*CWE129*.c"))
    assert len(paths) == 6
    for path in paths:
        for variant in ("bad", "goodG2B", "goodB2G"):
            spec = builder.juliet_spec(path, variant)
            assert spec["capacity"] == 10
            assert spec["min"] == 0 and spec["max"] == 255
            assert spec["body"].count("QUERY_STORE(data)") == 1
            assert "data = -1;" in spec["body"]
            assert "data = 7;" in spec["body"] if variant == "goodG2B" else True
            if variant != "goodG2B":
                assert ("data = 10;" if "large" in path.name else "data = (int)x;") in spec["body"]
            if variant == "goodB2G":
                assert "data >= 0 && data < (10)" in spec["body"]
            assert "-O0" in spec["flags"]


@pytest.mark.parametrize("source,indices", [
    ("{ int data = (int)x; if (data >= 0 && data < 10) { QUERY_STORE(data); } }", list(range(10)) + [None] * 246),
    ("{ int data = 10; if (data >= 0 && data < 10) { QUERY_STORE(data); } }", [None] * 256),
])
def test_synthetic_guarded_juliet_stores(source, indices):
    with workspace("route-b-v4-guarded") as output:
        spec = {"id": "guarded", "kind": "juliet", "body": source, "min": 0, "max": 255}
        flags = ["-O0" if flag == "-O1" else flag for flag in fixture.FLAGS]
        query, reference = fixture.compile_case(spec, {}, output, 10, flags)
        assert reference["indices"] == indices
        assert reference["outcome"] == "safe"
        assert query["write_rva"] > query["entry_rva"]
