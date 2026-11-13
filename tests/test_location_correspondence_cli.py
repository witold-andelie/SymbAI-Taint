"""Fabricated location-projection orchestration tests, without property engines."""

from dataclasses import asdict
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import uuid

import pytest

from scripts import run_location_correspondence as cli
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis.types import TypeView


ROOT = Path(__file__).resolve().parents[1]
MODULE = "src.selective_analysis.location_correspondence"
SOURCE_FILES = (
    "scripts/run_location_correspondence.py", "src/selective_analysis/location_correspondence.py",
    "src/selective_analysis/contracts.py", "src/selective_analysis/types.py",
    "src/selective_analysis/elf_guard.py", "src/selective_analysis/workspace.py",
    "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v12.md",
)


@pytest.fixture
def tmp_path():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("location-cli-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    return folder


@pytest.fixture
def inputs(tmp_path):
    inference, compiled = tmp_path / "inference", tmp_path / "compiled"
    queries = {}
    for case_id, binary, manifest, raw in cli.input_cases(inference, compiled):
        binary.parent.mkdir(parents=True, exist_ok=True)
        manifest.parent.mkdir(parents=True, exist_ok=True)
        # Query loading checks content identity, not ELF semantics.  These bytes
        # intentionally cannot run through a binary/property analysis engine.
        binary.write_bytes(b"fabricated, non-executable unit bytes: " + case_id.encode())
        query = Query("compiled-direct-index" if case_id == "direct_index" else case_id,
                      str(binary), file_hash(binary), 16, 32, 48, 8,
                      (InputRange("rdi", 0, 15),))
        contract = asdict(query)
        contract["binary"] = "historical/unavailable/original-path.elf"
        content = {"queries": [contract]}
        if case_id == "direct_index":
            content = {"schema": "symbai.queries.v1", **content}
        manifest.write_text(json.dumps(content, indent=3) + "\n", encoding="utf-8")
        raw.write_text(json.dumps({"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256,
                                   "provenance": {"source": "tygr_glowgnn", "model_sha256": "f" * 64},
                                   "records": []}, indent=3) + "\n", encoding="utf-8")
        queries[case_id] = query
    return {"inference": inference, "compiled": compiled, "queries": queries,
            "cases": cli.input_cases(inference, compiled)}


@pytest.fixture
def mapping_stub(monkeypatch):
    """Mock only the module boundary; real CLI identity checks and I/O still run."""
    stub = ModuleType(MODULE)
    stub.build_calls, stub.projection_calls = [], []
    stub.unavailable, stub.errors = set(), set()
    stub.clock = 0.0

    def fabricated_clock():
        stub.clock += 0.125
        return stub.clock

    def build(query, raw):
        stub.build_calls.append((query, raw))
        if query.query_id in stub.errors:
            raise ValueError("fabricated unsupported static dependency")
        return {"schema": "symbai.location_type_bundle.v1", "query_hash": query.contract_hash,
                "binary_sha256": query.binary_sha256,
                "status": "unavailable" if query.query_id in stub.unavailable else "available",
                "reason": "fabricated missing location" if query.query_id in stub.unavailable else None,
                "bindings": [] if query.query_id in stub.unavailable else [{"prediction_id": "unit-location"}],
                "property_verification_performed": False}

    def project(bundle, group):
        stub.projection_calls.append((bundle, group))
        if group in ("A", "B"):
            return {}
        return {"unit-location": TypeView(("u64",) if group == "C" else ("u64", "void *"),
                                          () if group == "C" else (0.75, 0.25),
                                          "tygr_glowgnn", "a" * 64, "f" * 64,
                                          () if group == "C" else (3.0, 1.0))}

    stub.build_location_bundle, stub.project_location_views = build, project
    monkeypatch.setitem(sys.modules, MODULE, stub)
    # Other tests can have loaded a property engine in this interpreter.  The
    # detector is tested separately; these tests isolate CLI orchestration.
    monkeypatch.setattr(cli, "forbidden_imports", lambda: [])
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=fabricated_clock))
    return stub


def make_request(inputs, tmp_path, case_index=0):
    output = tmp_path / "snapshot"
    output.mkdir()
    saved = cli.snapshot_input(inputs["cases"][case_index], output)
    return Path(saved["request"]), saved


def test_snapshots_preserve_original_bytes_hashes_and_relocate_only_query_path(inputs, tmp_path):
    output = tmp_path / "all-snapshots"
    output.mkdir()
    for case in inputs["cases"]:
        before = {name: path.read_bytes() for name, path in zip(("binary", "queries", "raw"), case[1:])}
        saved = cli.snapshot_input(case, output)
        request_path = Path(saved["request"])
        request = cli.read(request_path)
        assert set(request) == {"schema", "case_id", "query", "query_hash", "raw_type_file", "raw_file_sha256"}
        assert request["schema"] == "symbai.location_request.v1"
        copied = {"binary": request_path.parent / "query.elf",
                  "queries": request_path.parent / "original-queries.json",
                  "raw": request_path.parent / "raw-types.json"}
        for name, source in zip(("binary", "queries", "raw"), case[1:]):
            assert source.read_bytes() == before[name] == copied[name].read_bytes()
            assert saved["source_sha256"][name] == file_hash(source) == file_hash(copied[name])
        relocated = Query.from_dict(request["query"])
        original = inputs["queries"][case[0]]
        assert relocated.binary == str(copied["binary"].resolve())
        assert relocated.contract_hash == original.contract_hash == request["query_hash"]
        assert {k: v for k, v in asdict(relocated).items() if k != "binary"} == {
            k: v for k, v in asdict(original).items() if k != "binary"}


@pytest.mark.parametrize("extra", ["expected", "gold", "operand_plan", "proof", "prior_result"])
def test_snapshot_rejects_extra_manifest_fields(inputs, tmp_path, extra):
    case = inputs["cases"][0]
    manifest = cli.read(case[2])
    manifest[extra] = {"status": "excluded_within_scope"}
    cli.write(case[2], manifest)
    with pytest.raises(ValueError, match="fixed query contract"):
        make_request(inputs, tmp_path)


@pytest.mark.parametrize("extra", ["expected", "gold", "operand_plan", "proof", "anchor", "prior_result"])
def test_projection_request_rejects_old_property_inputs_before_mapping(inputs, tmp_path, mapping_stub, extra):
    path, _ = make_request(inputs, tmp_path)
    request = cli.read(path)
    request[extra] = "forbidden"
    cli.write(path, request)
    with pytest.raises(ValueError, match="Invalid location-only request"):
        cli.project_request(path, tmp_path / "results")
    assert mapping_stub.build_calls == mapping_stub.projection_calls == []


@pytest.mark.parametrize("change", ["schema", "missing_field", "query_hash", "binary_hash", "query_extra", "input_extra"])
def test_projection_rejects_malformed_or_changed_query_identity(inputs, tmp_path, mapping_stub, change):
    path, _ = make_request(inputs, tmp_path)
    request = cli.read(path)
    if change == "schema":
        request["schema"] = "symbai.operand_plan.v1"
    elif change == "missing_field":
        del request["case_id"]
    elif change == "query_hash":
        request["query_hash"] = "0" * 64
    elif change == "binary_hash":
        request["query"]["binary_sha256"] = "0" * 64
    elif change == "query_extra":
        request["query"]["expected"] = "violation"
    else:
        request["query"]["inputs"][0]["proof"] = "previously_verified"
    cli.write(path, request)
    with pytest.raises((ValueError, TypeError)):
        cli.project_request(path, tmp_path / "results")
    assert mapping_stub.build_calls == mapping_stub.projection_calls == []


@pytest.mark.parametrize("change", ["raw_bytes", "raw_path", "raw_digest", "binary_bytes"])
def test_forged_or_changed_frozen_input_is_rejected_before_mapping(inputs, tmp_path, mapping_stub, change):
    path, _ = make_request(inputs, tmp_path)
    request = cli.read(path)
    if change == "raw_bytes":
        raw_path = Path(request["raw_type_file"])
        raw = cli.read(raw_path)
        raw["binary_sha256"] = "0" * 64
        cli.write(raw_path, raw)
    elif change == "raw_path":
        impostor = tmp_path / "impostor-raw.json"
        impostor.write_text('{"schema":"symbai.operand_types.v1","proof":"old evidence"}', encoding="utf-8")
        request["raw_type_file"] = str(impostor)
        cli.write(path, request)
    elif change == "raw_digest":
        request["raw_file_sha256"] = "0" * 64
        cli.write(path, request)
    else:
        Path(request["query"]["binary"]).write_bytes(b"forged binary bytes")
    with pytest.raises(ValueError, match="identity changed|Binary hash differs"):
        cli.project_request(path, tmp_path / "results")
    assert mapping_stub.build_calls == mapping_stub.projection_calls == []


def test_available_projection_serializes_views_and_keeps_independent_input_identities(inputs, tmp_path, mapping_stub):
    path, saved = make_request(inputs, tmp_path)
    request = cli.read(path)
    raw_before = Path(request["raw_type_file"]).read_bytes()
    output = tmp_path / "results"
    record = cli.project_request(path, output)
    assert len(mapping_stub.build_calls) == 1
    query, raw = mapping_stub.build_calls[0]
    assert query.contract_hash == request["query_hash"]
    assert raw == json.loads(raw_before)
    assert Path(request["raw_type_file"]).read_bytes() == raw_before
    assert [group for _, group in mapping_stub.projection_calls] == ["A", "B", "C", "D"]
    views = cli.read(output / request["case_id"] / "views.json")
    assert views["A"] == views["B"] == {}
    assert views["C"]["unit-location"]["labels"] == ["u64"]
    assert views["C"]["unit-location"]["weights"] == []
    assert views["D"]["unit-location"]["labels"] == ["u64", "void *"]
    assert views["D"]["unit-location"]["weights"] == [0.75, 0.25]
    assert views["D"]["unit-location"]["raw_scores"] == [3.0, 1.0]
    assert record["status"] == "available" and record["binding_count"] == 1
    assert record["mapping_seconds"] == record["projection_seconds"] == 0.125
    assert record["query_hash"] == request["query_hash"]
    assert record["binary_sha256"] == query.binary_sha256
    assert record["raw_file_sha256"] == saved["source_sha256"]["raw"]
    assert record["bundle_sha256"] == file_hash(output / request["case_id"] / "location-bundle.json")
    assert record["views_sha256"] == file_hash(output / request["case_id"] / "views.json")
    assert record["property_verification_performed"] is False
    assert record["forbidden_runtime_imports"] == []


def test_unavailable_projection_keeps_a_record_and_does_not_project_views(inputs, tmp_path, mapping_stub):
    path, _ = make_request(inputs, tmp_path)
    request = cli.read(path)
    mapping_stub.unavailable.add(request["query"]["query_id"])
    output = tmp_path / "results"
    record = cli.project_request(path, output)
    assert record["status"] == "unavailable" and record["binding_count"] == 0
    assert record["reason"] == "fabricated missing location"
    assert record["query_hash"] == request["query_hash"]
    assert record["view_counts"] == {"A": 0, "B": 0, "C": None, "D": None}
    assert cli.read(output / request["case_id"] / "views.json") == {"A": {}, "B": {}, "C": None, "D": None}
    assert mapping_stub.projection_calls == []


def test_forbidden_import_detector_catches_roots_and_descendants_without_prefix_false_positives(monkeypatch):
    baseline = set(cli.forbidden_imports())
    forbidden = {"angr", "angr.engines", "claripy", "claripy.ast.bv", "z3", "z3.z3",
                 "src.selective_analysis.operations", "src.selective_analysis.operations.child",
                 "src.selective_analysis.operand_mapping", "src.selective_analysis.compiled_fact_audit",
                 "src.selective_analysis.local_bounds", "src.selective_analysis.frame_bounds"}
    allowed = {"angrish", "claripy_extra", "z3_extra", "src.selective_analysis.operations_extra",
               "src.selective_analysis.types", "src.selective_analysis.location_correspondence"}
    for name in forbidden | allowed:
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    detected = cli.forbidden_imports()
    assert detected == sorted(baseline | forbidden)
    assert not set(detected) & allowed


def test_forbidden_imports_prevent_publishing_projection_records(inputs, tmp_path, mapping_stub, monkeypatch):
    path, _ = make_request(inputs, tmp_path)
    monkeypatch.setattr(cli, "forbidden_imports", lambda: ["angr.engines"])
    output = tmp_path / "results"
    with pytest.raises(RuntimeError, match="Forbidden property-engine imports"):
        cli.project_request(path, output)
    assert not output.exists()


def prepare_main(inputs, tmp_path, monkeypatch):
    root = tmp_path / "fabricated-source-tree"
    for name in SOURCE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fabricated source snapshot: " + name + "\n", encoding="utf-8")
    scratch = tmp_path / "main-output"
    scratch.mkdir()
    monkeypatch.setattr(cli, "ROOT", root)
    monkeypatch.setattr(cli, "configure_workspace", lambda: scratch)
    monkeypatch.setattr(sys, "argv", [cli.__file__, "--inference-dir", str(inputs["inference"]),
                                      "--compiled-dir", str(inputs["compiled"])])
    return scratch


@pytest.mark.parametrize("failure", ["snapshot", "projection_exception", "bundle_unavailable", "all_snapshots"])
def test_main_retains_all_three_cases_when_inputs_or_projection_are_unavailable(
        inputs, tmp_path, mapping_stub, monkeypatch, failure):
    scratch = prepare_main(inputs, tmp_path, monkeypatch)
    if failure in ("snapshot", "all_snapshots"):
        real_snapshot = cli.snapshot_input

        def snapshot(case, output):
            if failure == "all_snapshots" or case[0] == "offset_index":
                raise ValueError("fabricated unavailable retained input")
            return real_snapshot(case, output)

        monkeypatch.setattr(cli, "snapshot_input", snapshot)
    elif failure == "projection_exception":
        mapping_stub.errors.add("offset_index")
    else:
        mapping_stub.unavailable.add("offset_index")
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    output, = scratch.iterdir()
    records, summary, plan = [cli.read(output / name) for name in ("records.json", "summary.json", "run-plan.json")]
    assert len(records) == summary["planned_cases"] == summary["retained_cases"] == 3
    assert {record["case_id"] for record in records} == {case[0] for case in inputs["cases"]}
    expected_unavailable = 3 if failure == "all_snapshots" else 1
    assert summary["unavailable"] == expected_unavailable and summary["available"] == 3 - expected_unavailable
    assert all(record["property_verification_performed"] is False for record in records)
    assert summary["fresh_model_inference_performed"] is summary["neural_selection_measured"] is False
    assert summary["changed_inputs"] == summary["changed_sources"] == summary["forbidden_runtime_imports"] == []
    assert plan["planned_cases"] == 3 and plan["selector_integration"] is False
    assert len(plan["inputs"]) == (0 if failure == "all_snapshots" else 2 if failure == "snapshot" else 3)


def test_main_available_projection_keeps_fixed_three_input_denominator_and_hashed_source_snapshots(
        inputs, tmp_path, mapping_stub, monkeypatch):
    scratch = prepare_main(inputs, tmp_path, monkeypatch)
    cli.main()
    output, = scratch.iterdir()
    records, summary, plan = [cli.read(output / name) for name in ("records.json", "summary.json", "run-plan.json")]
    assert len(records) == summary["planned_cases"] == summary["retained_cases"] == summary["available"] == 3
    assert summary["unavailable"] == 0
    assert len(mapping_stub.build_calls) == 3 and len(mapping_stub.projection_calls) == 12
    assert {record["query_hash"] for record in records} == {
        query.contract_hash for query in inputs["queries"].values()}
    assert set(plan["source_sha256"]) == set(SOURCE_FILES)
    for source, digest in plan["source_sha256"].items():
        assert file_hash(output / "source_snapshot" / source) == digest
    assert summary["held_out_evaluation"] is summary["fresh_model_inference_performed"] is False
