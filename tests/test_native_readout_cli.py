"""Offline v20 projection, accounting and source-evidence boundaries."""

from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from scripts import run_native_readout_correspondence as cli
from src.selective_analysis.workspace import SCRATCH


@pytest.fixture
def root():
    path = SCRATCH / "tests" / ("native-readout-cli-" + uuid.uuid4().hex)
    path.mkdir(parents=True)
    return path


@pytest.fixture
def panel(root, monkeypatch):
    folder = root / "native/direct_index"
    folder.mkdir(parents=True)
    binary = folder / "query.elf"
    binary.write_bytes(b"unit binary identity only")
    query = {"binary": "original-path", "binary_sha256": cli.file_hash(binary), "entry_rva": 10,
        "write_rva": 20, "capacity": 123, "object_rva": 999, "inputs": [{"minimum": 0, "maximum": 99}]}
    cli.write(folder / "queries.json", {"queries": [query]})
    capture = {"request_identity": {"binary_sha256": query["binary_sha256"], "entry_rva": 10}}
    cli.write(folder / "capture.json", capture)
    contract = {key: value for key, value in query.items() if key != "binary"}
    anchor = (cli.file_hash(binary), cli.fingerprint(contract))
    monkeypatch.setattr(cli, "ANCHORS", {"direct_index": anchor})
    plan = {"case_identities": [{"case_id": "direct_index", "entry_rva": 10, "source_query_hash": anchor[1]}]}
    return root, plan, capture


def test_runtime_projection_excludes_property_bounds_inputs_and_old_names(panel):
    root, plan, capture = panel
    request, copied = cli.minimal_request("direct_index", plan, root)
    assert set(request) == {"schema", "binary", "binary_sha256", "entry_rva", "write_rva", "native_capture_fingerprint"}
    assert request["native_capture_fingerprint"] == cli.fingerprint(capture) and copied == capture
    assert request["schema"] == "symbai.native_readout_request.v1"


@pytest.mark.parametrize("changed", ["binary", "query", "native_plan"])
def test_projection_does_not_accept_same_folder_metadata_as_identity(panel, changed):
    root, plan, _ = panel
    if changed == "binary":
        (root / "native/direct_index/query.elf").write_bytes(b"changed")
    elif changed == "query":
        path = root / "native/direct_index/queries.json"
        value = cli.read(path)
        value["queries"][0]["write_rva"] += 1
        cli.write(path, value)
    else:
        plan["case_identities"][0]["source_query_hash"] = "0" * 64
    with pytest.raises(ValueError):
        cli.minimal_request("direct_index", plan, root)


def rows():
    return [{"case_id": name, "correspondence": {"occurrence_records": [
        {"status": "available", "exact_event_verified": False},
        {"status": "available", "exact_event_verified": False}]},
        "frontier": {"status": "available", "target_candidates_count": 2, "frontier_member_count": 2},
        "diagnostic_seconds": 0.01, "forbidden_runtime_imports": []} for name in cli.CASE_IDS]


def test_association_success_never_upgrades_event_proof_or_counts_rows_as_samples():
    summary = cli.summarize(rows())
    assert summary["planned_queries"] == 3 and summary["planned_address_load_occurrences"] == 6
    assert summary["associated_groups"] == 6 and summary["unavailable_groups"] == 0
    assert summary["exact_events_verified"] == 0 and summary["exact_events_unverified"] == 6
    assert not summary["semantic_roles_verified"] and not summary["model_forward_performed"]


def test_failed_case_stays_in_six_occurrence_denominator():
    records = rows()
    records[0]["correspondence"] = {"status": "unavailable", "occurrence_records": []}
    records[0]["frontier"] = {"status": "unavailable", "reason": "correspondence_failed"}
    summary = cli.summarize(records)
    assert summary["associated_groups"] == 4 and summary["unavailable_groups"] == 2
    assert summary["frontier_errors"] == 1 and summary["exact_events_unverified"] == 6


def test_frontier_error_does_not_erase_valid_coarse_associations():
    records = rows()
    records[1]["frontier"] = {"status": "unavailable", "error": {"type": "unit failure"}}
    summary = cli.summarize(records)
    assert summary["associated_groups"] == 6 and summary["frontier_errors"] == 1


@pytest.mark.parametrize("bad", ["missing_case", "duplicate_case", "event_claim", "extra_occurrence"])
def test_summary_rejects_incomplete_matrix_or_unsupported_claims(bad):
    records = rows()
    if bad == "missing_case":
        records.pop()
    elif bad == "duplicate_case":
        records[0]["case_id"] = records[1]["case_id"]
    elif bad == "event_claim":
        records[0]["correspondence"]["occurrence_records"][0]["exact_event_verified"] = True
    else:
        records[0]["correspondence"]["occurrence_records"].append({"status": "available", "exact_event_verified": False})
    with pytest.raises(ValueError):
        cli.summarize(records)


def test_source_inspection_recovers_mixed_annotation_context_without_executing(root):
    folder = root / "tygr_original/src/analysis/angr"
    folder.mkdir(parents=True)
    (folder / "ast_graph.py").write_text("raise RuntimeError('never execute')\ndef get_state_WR():\n"
        + "".join(" x{}[key] = (act.bbl_addr, data)\n".format(i) for i in range(4)), encoding="utf-8")
    (folder / "sim_exec.py").write_text("raise RuntimeError('never execute')\n" + "\n".join(
        name + "(state.addr, loc, data)" for name in
        ("RegisterReadAnnotation", "RegisterWriteAnnotation", "MemoryReadAnnotation", "MemoryWriteAnnotation")), encoding="utf-8")
    result = cli.source_semantics(root)
    assert len(result["history_summary_assignments"]) == len(result["direct_hook_annotations"]) == 4
    assert result["annotation_address_has_mixed_context"] and not result["v19_exports_annotation_class"]


def test_snapshot_checks_copy_identity_without_mutating_source(root):
    source = root / "source"
    source.write_bytes(b"original bytes")
    hashes = cli.snapshot({"nested/copy": source}, root / "snapshots")
    assert source.read_bytes() == b"original bytes"
    assert cli.file_hash(root / "snapshots/nested/copy") == hashes["nested/copy"]


def test_loaded_source_inventory_includes_package_initializers_and_deduplicates_aliases():
    modules = {"scripts": SimpleNamespace(__file__=str(cli.ROOT / "scripts/__init__.py")),
        "src": SimpleNamespace(__file__=str(cli.ROOT / "src/__init__.py")),
        "same_src": SimpleNamespace(__file__=str(cli.ROOT / "src/__init__.py")), "builtin": SimpleNamespace(),
        "native": SimpleNamespace(__file__=str(cli.ROOT / "native.dll"))}
    assert cli.loaded_project_sources(modules) == ["scripts/__init__.py", "src/__init__.py"]


def test_loaded_source_inventory_separates_missing_dependency_from_snapshotted_sources():
    loaded = cli.loaded_project_sources({"module": SimpleNamespace(__file__=str(cli.ROOT / "new_dependency.py"))})
    assert set(loaded) - set(cli.SOURCE_FILES) == {"new_dependency.py"}
