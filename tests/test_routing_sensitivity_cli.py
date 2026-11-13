"""Authored orchestration tests; fake model data and clocks are never run evidence."""

from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

from scripts import run_routing_sensitivity as cli
from scripts.run_location_correspondence import snapshot_input
from src.selective_analysis import location_correspondence as mapping
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.types import TypeView

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("routing-cli-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


@pytest.fixture
def case_request(tmp_path):
    binary = tmp_path / "not-executable.bin"
    binary.write_bytes(b"authored non-executable unit input")
    query = Query("unit-no-gold", str(binary), file_hash(binary), 16, 32, 48, 8,
                  (InputRange("rdi", 0, 15),))
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256,
                              "unit_fake_payload": True}), encoding="utf-8")
    path = tmp_path / "case_request.json"
    cli.write(path, {"schema": "symbai.location_request.v1", "case_id": "direct_index",
                     "query": asdict(query), "query_hash": query.contract_hash,
                     "raw_type_file": str(raw), "raw_file_sha256": file_hash(raw)})
    return path


@pytest.fixture
def stubs(case_request, monkeypatch):
    calls = []
    clock = [0.0]
    def tick():
        clock[0] += 0.125
        return clock[0]
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=tick))
    monkeypatch.setattr(cli, "forbidden_imports", lambda: [])
    def features(query):
        calls.append("features")
        return {"schema": "symbai.routing_features.v1", "query_hash": query.contract_hash,
                "binary_sha256": query.binary_sha256, "available": True, "reason": None,
                "instruction_count": 8, "address_load_count": 2, "has_immediate_mask": False}
    monkeypatch.setattr(cli, "static_routing_features", features)
    raw_path = Path(cli.read(case_request)["raw_type_file"])
    original_read = cli.read
    def read(path):
        if Path(path) == raw_path:
            calls.append("raw_candidates_read")
        return original_read(path)
    monkeypatch.setattr(cli, "read", read)
    original_record = cli.routing_record
    def record(features, group, views, weight, error=None):
        calls.append("select_" + group)
        return original_record(features, group, views, weight, error)
    monkeypatch.setattr(cli, "routing_record", record)
    def build(query, raw):
        calls.append("mapping")
        return {"status": "available", "raw_payload_fingerprint": fingerprint(raw), "model_sha256": "a" * 64,
                "bindings": [{"occurrence_id": "slot-a", "prediction_id": "p-a", "cfa_offset": -24,
                              "load_rva": 20, "use_rva": 32},
                             {"occurrence_id": "slot-b", "prediction_id": "p-b", "cfa_offset": -40,
                              "load_rva": 24, "use_rva": 32}]}
    def project(bundle, group):
        calls.append("project_" + group)
        labels = {"slot-a": ("char*",), "slot-b": ("u64",)}
        if group == "C":
            return {key: TypeView(value) for key, value in labels.items()}
        return {key: TypeView(value + ("other",), (0.5, 0.5), raw_scores=(0.0, 0.0))
                for key, value in labels.items()}
    monkeypatch.setattr(mapping, "build_location_bundle", build)
    monkeypatch.setattr(mapping, "project_location_views", project)
    return calls


def test_b_finishes_with_shared_features_before_raw_is_parsed(case_request, stubs):
    result = cli.run_case(case_request)
    assert stubs[:7] == ["features", *(["select_B"] * 5), "raw_candidates_read"]
    assert len(result["routing_records"]) == 15
    assert result["projected_views"]["B"] == {}
    assert all(not view["weights"] and not view["raw_scores"] for view in result["projected_views"]["C"].values())
    assert {row["features_hash"] for row in result["routing_records"]} == {fingerprint(result["features"])}
    assert len({r["policy_hash"] for r in result["routing_records"]}) == 1
    assert result["property_operations_executed"] is result["fresh_neural_inference_performed"] is False
    assert set(result["occurrence_bindings"]) == {"slot-a", "slot-b"}
    assert all(result["costs_seconds"][name] == 0.125 for name in result["costs_seconds"])


@pytest.mark.parametrize("extra", ["gold", "expected", "plan", "evidence", "prior_result"])
def test_old_proof_or_labels_cannot_enter_request(case_request, stubs, extra):
    data = cli.read(case_request)
    data[extra] = "offline only"
    cli.write(case_request, data)
    with pytest.raises(ValueError, match="label-free"):
        cli.run_case(case_request)
    assert stubs == []


@pytest.mark.parametrize("change", ["binary", "raw", "query_hash", "query_extra"])
def test_changed_input_is_rejected_before_feature_acquisition(case_request, stubs, change):
    data = cli.read(case_request)
    if change == "binary":
        Path(data["query"]["binary"]).write_bytes(b"changed")
    elif change == "raw":
        Path(data["raw_type_file"]).write_text("{}", encoding="utf-8")
    elif change == "query_hash":
        data["query_hash"] = "bad"
    else:
        data["query"]["expected"] = "violation"
    cli.write(case_request, data)
    with pytest.raises(ValueError):
        cli.run_case(case_request)
    assert not any(c.startswith("select_") or c == "features" for c in stubs)


def test_mapping_failure_preserves_b_and_all_ten_unavailable_c_d_rows(case_request, stubs, monkeypatch):
    def failed(*args):
        raise ValueError("unit missing CFA identity")
    monkeypatch.setattr(mapping, "build_location_bundle", failed)
    result = cli.run_case(case_request)
    assert result["status"] == "partially_unavailable"
    rows = result["routing_records"]
    assert len(rows) == 15
    assert all(r["status"] == "available" for r in rows if r["group"] == "B")
    assert all(r["status"] == "unavailable" and r["order"] is None for r in rows if r["group"] != "B")
    assert result["projected_views"]["C"] is result["projected_views"]["D"] is None
    assert "mapping" not in stubs


def test_d_failure_is_not_replaced_by_top1_or_b(case_request, stubs, monkeypatch):
    original = mapping.project_location_views
    def project(bundle, group):
        if group == "D":
            raise ValueError("unit missing actual logits")
        return original(bundle, group)
    monkeypatch.setattr(mapping, "project_location_views", project)
    result = cli.run_case(case_request)
    assert all(r["status"] == "available" for r in result["routing_records"] if r["group"] in ("B", "C"))
    assert all(r["status"] == "unavailable" for r in result["routing_records"] if r["group"] == "D")


def test_forbidden_property_import_prevents_successful_record(case_request, stubs, monkeypatch):
    monkeypatch.setattr(cli, "forbidden_imports", lambda: ["angr"])
    with pytest.raises(RuntimeError, match="Forbidden runtime imports"):
        cli.run_case(case_request)


def test_unavailable_case_has_full_grid_and_incomplete_cost_measurement():
    result = cli.unavailable_case("unit", "unit input unavailable")
    assert len(result["routing_records"]) == 15
    assert result["cost_measurement_complete"] is False
    assert all(r["status"] == "unavailable" and r["order"] is None for r in result["routing_records"])
    summary = cli.summarize([{**deepcopy(result), "case_id": str(i)} for i in range(3)])
    assert summary["unavailable_comparisons"] == 30 and summary["changed_orders"] == 0


@pytest.mark.parametrize("failure", ["snapshot", "case", "all_snapshots"])
def test_main_retains_all_case_and_group_denominators(case_request, stubs, monkeypatch, tmp_path, failure):
    source = tmp_path / "retained-v12"
    query_data = cli.read(case_request)["query"]
    for case in cli.CASES:
        folder = source / "inputs" / case
        folder.mkdir(parents=True)
        (folder / "query.elf").write_bytes(Path(query_data["binary"]).read_bytes())
        cli.write(folder / "original-queries.json", {"queries": [query_data]})
        cli.write(folder / "raw-types.json", {"unit": True})
    scratch = tmp_path / "outputs"
    scratch.mkdir()
    monkeypatch.setattr(cli, "configure_workspace", lambda: scratch)
    monkeypatch.setattr(sys, "argv", [cli.__file__, "--location-input-dir", str(source)])
    monkeypatch.setattr(cli, "version", lambda name: "unit-not-installed")
    if failure in ("snapshot", "all_snapshots"):
        def snapshot(case, output):
            if case[0] == "offset_index" or failure == "all_snapshots":
                raise ValueError("unit unavailable source")
            return snapshot_input(case, output)
        monkeypatch.setattr(cli, "snapshot_input", snapshot)
    def run(path):
        case = cli.read(path)["case_id"]
        if failure == "case" and case == "offset_index":
            raise ValueError("unit feature acquisition failed")
        return cli.unavailable_case(case, "unit unavailable projections")
    monkeypatch.setattr(cli, "run_case", run)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    output, = scratch.iterdir()
    summary, records = cli.read(output / "summary.json"), cli.read(output / "records.json")
    assert summary["unique_integration_cases"] == len(records) == 3
    assert summary["routing_rows"] == 45 and summary["unavailable_comparisons"] == 30
    assert summary["changed_sources"] == summary["changed_inputs"] == summary["forbidden_runtime_imports"] == []
    assert {r["case_id"] for r in records} == set(cli.CASES)
