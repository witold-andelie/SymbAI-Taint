#!/usr/bin/env python3
"""Audit retained v19 WSL receipts without starting a native runtime or a model."""

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.native_input_validation import summarize_native_trials

MODEL = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
ANCHORS = {
    "direct_index": ("0fb55db6be585f4c71134f6a9483828292f5a73f529420bc21a753a62a7c81a5", "3d2a4a0103efffea4c649986f265a32e6518fc79c15218c6a6b045a598e0299c"),
    "offset_index": ("87ddc7b2c076cbf8eac8752d722b2bd94a1bd007d68c49d4dc13d3b13caaf79e", "d2252e8db5eaa09df65266540ebcc3568eb330e08156d9005c7308ce30eadd6a"),
    "masked_index": ("3819825049678a3cf15229507fea4a16c39f17c4deff2248d79005a6e95b04d7", "a9cb251b1c3635d651ad3e7b5d8ea757214316ff5398af7e39fd073e63b941e2"),
}
REQUEST_FIELDS = {"schema", "binary", "binary_sha256", "entry_rva", "tygr_root", "model", "model_sha256",
                  "scratch_dir", "source_sha256", "worker_sha256"}


def require(value, message):
    if not value:
        raise ValueError("Native receipt audit: " + message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def local_path(value):
    """Map only this D workspace's WSL paths; reject foreign drives and traversal."""
    path = PurePosixPath(value)
    require(".." not in path.parts, "path traversal")
    relative = path.relative_to("/mnt/d/AI_Models/symbolic")
    resolved = (WORKSPACE / Path(*relative.parts)).resolve()
    require(resolved.is_relative_to(WORKSPACE.resolve()), "path outside workspace")
    return resolved


def native_first_label_rule(source):
    """Check actual return placement without importing or executing the upstream module."""
    function, = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
                  and node.name == "encode_edge_label"]
    require(len(function.body) == 1 and isinstance(function.body[0], ast.For), "unreviewed edge encoder body")
    loop = function.body[0]
    require(len(loop.body) == 2 and isinstance(loop.body[0], ast.If) and isinstance(loop.body[1], ast.Return)
            and not loop.orelse and ast.unparse(loop.iter) == "sorted(list(edge_label))",
            "edge encoder must return inside sorted-label loop")
    return "first_sorted_label"


def audit(root):
    plan, rows, summary, expected = [read(root / name) for name in
        ("run-plan.json", "records.json", "summary.json", "expected-model-contract.json")]
    require(plan["prepare_only"] is False and plan["planned_cases"] == 3
            and plan["prediction_authorized"] is False and plan["model_parameters_mapped_to"] == "cpu",
            "runtime plan scope")
    require(len(plan["source_sha256"]) == 79 and len(plan["input_sha256"]) == 8, "frozen source/input denominator")
    preflight = read(WORKSPACE / ".scratch/selective_analysis/native-preprocessing-v19-20261112-132530-111772/run-plan.json")
    require(plan["source_sha256"] == preflight["source_sha256"]
            and plan["input_sha256"] == preflight["input_sha256"], "WSL/preflight source or input identity differs")
    current_differences = []
    for name, value in plan["source_sha256"].items():
        require(digest(root / "source_snapshot" / name) == value, "changed captured source: " + name)
        if digest(ROOT / name) != value:
            current_differences.append(name)
    require(set(current_differences) <= {"src/selective_analysis/native_input_validation.py"},
            "undocumented live source changes")
    for name, value in plan["input_sha256"].items():
        require(digest(root / "input_snapshot" / name) == digest(local_path(plan["input_sources"][name])) == value,
                "changed original/copied input: " + name)
    require(digest(root / "input_snapshot/model/x64.O0.base.model") == expected["model_sha256"] == MODEL,
            "pinned model")
    require(digest(root / "expected-model-contract.json") == "ef673a606d712667fa5b20916c02c7e683bcac4e41fcd11e6d23ae25e7416449",
            "expected saved model contract")
    source = root / "source_snapshot/tygr_original/src/methods/glow/preproc.py"
    rule = native_first_label_rule(source.read_text(encoding="utf-8"))
    cases = {case["case_id"]: case for case in plan["case_identities"]}
    require(set(cases) == set(ANCHORS) and len(rows) == 3 and {row["case_id"] for row in rows} == set(ANCHORS),
            "fixed three-case identities")
    observations, all_ids, multi_label_edges = [], set(), 0
    for row in rows:
        name, case = row["case_id"], cases[row["case_id"]]
        folder = root / "workers" / name
        request, capture, payload, receipt = [read(folder / filename) for filename in
            ("request.json", "capture.json", "trial-payload.json", "receipt.json")]
        query = dict(read(root / "input_snapshot/native" / name / "original-queries.json")["queries"][0])
        query.pop("binary")
        require((digest(local_path(case["binary"])), canonical(query)) == ANCHORS[name], "binary/query anchor: " + name)
        require(set(request) == REQUEST_FIELDS and request["schema"] == "symbai.native_preprocessing_request.v1"
                and request["entry_rva"] == case["entry_rva"] == query["entry_rva"]
                and request["binary_sha256"] == row["binary_sha256"] == ANCHORS[name][0], "runtime request identity")
        require(local_path(request["binary"]) == root / "input_snapshot/native" / name / "query.elf"
                and local_path(request["model"]) == root / "input_snapshot/model/x64.O0.base.model"
                and local_path(request["tygr_root"]) == ROOT / "tygr_original"
                and local_path(request["scratch_dir"]) == folder / "cache", "runtime paths")
        require(request["source_sha256"] == {key.removeprefix("tygr_original/"): value
                for key, value in plan["source_sha256"].items() if key.startswith("tygr_original/")}
                and request["worker_sha256"] == plan["source_sha256"]["scripts/capture_tygr_preprocessing.py"],
                "request source dependency identity")
        require(payload == row["payload"] and receipt == row["parent_receipt"]
                and capture == payload["worker_candidate"] and canonical(request) == payload["request_fingerprint"],
                "worker/parent/aggregate correspondence")
        require(digest(folder / "trial-payload.json") == receipt["payload_sha256"]
                and canonical(payload) == receipt["payload_fingerprint"], "persisted payload bytes")
        require(receipt["status"] == "captured" and receipt["charged_seconds"] < 60
                and payload["process"]["elapsed_seconds"] <= receipt["charged_seconds"]
                and not payload["process"]["timed_out"] and payload["process"]["returncode"] == 0,
                "complete parent-owned process/budget")
        require(capture["forward_guarded_modules"] > 0 and capture["forward_attempts"] == 0
                and capture["model_forward_performed"] is False, "native forward guards")
        require(capture["runtime"]["platform"] == "linux" and capture["runtime"]["torch"] == "1.8.1+cpu"
                and capture["runtime"]["angr"] == "9.0.7491" and capture["runtime"]["torch-geometric"] == "1.7.0",
                "original environment receipt")
        require(capture["source_sha256"] == request["source_sha256"], "native source receipt")
        nodes, edges, relations, readout_rows = 0, 0, 0, 0
        for function in capture["functions"]:
            nodes += len(function["node_labels"])
            readout_rows += len(function["prepared"]["var_nodes"])
            for index, edge in enumerate(function["graph_edges"]):
                labels = sorted(edge["labels"])
                multi_label_edges += len(labels) > 1
                label = labels[0]
                reduced = expected["edge_reduce_op_map"].get(label, label)
                vocabulary = expected["all_ops"]
                forward = vocabulary.index(label) if label in vocabulary else (
                    vocabulary.index(reduced) if reduced in vocabulary else len(vocabulary))
                pair = [forward, forward + expected["num_all_ops"]]
                require(pair == [edge["forward_id"], edge["inverse_id"]]
                        == function["prepared"]["edge_labels"]["values"][2 * index:2 * index + 2],
                        "independent source-faithful edge ID")
                require(all(value < cap for value in pair for cap in expected["layer_relation_capacities"]),
                        "observed saved-layer capacity")
                all_ids.update(pair)
                edges += 1
                relations += 2
        observations.append({"case_id": name, "nodes": nodes, "native_edges": edges,
            "prepared_relation_entries": relations, "readout_rows": readout_rows,
            "charged_seconds": receipt["charged_seconds"], "guarded_modules": capture["forward_guarded_modules"],
            "payload_sha256": digest(folder / "trial-payload.json")})
    # Replays all shape/order/group/receipt checks; on this single-label matrix the corrected
    # live encoder rule and frozen validator produce exactly the same full report.
    replay = summarize_native_trials(rows, expected)
    require(all(summary[key] == value for key, value in replay.items()), "fresh full summary differs")
    require(replay["captured"] == 3 and replay["no_forward"] is True, "complete no-forward observations")
    result = {"schema": "symbai.native_preprocessing_audit.v1", "captured": 3, "source_snapshots_verified": 79,
        "audit_source_sha256": digest(Path(__file__)),
        "corrected_validator_sha256": digest(ROOT / "src/selective_analysis/native_input_validation.py"),
        "input_files_verified": 8, "native_source_rule": rule, "multi_label_edges": multi_label_edges,
        "current_source_differences": current_differences, "documented_live_correction": "v19_encoder_erratum",
        "observations": observations, "nodes": sum(row["nodes"] for row in observations),
        "native_edges": sum(row["native_edges"] for row in observations),
        "prepared_relation_entries": sum(row["prepared_relation_entries"] for row in observations),
        "observed_relation_ids": sorted(all_ids), "no_forward_receipts": 3,
        "no_prediction_performed": True, "v17_projection_validated": False, "neural_benefit_measured": False,
        "records_sha256": digest(root / "records.json"), "summary_sha256": digest(root / "summary.json"),
        "scope": "audited_native_inputs_on_three_compiled_integration_cases_only"}
    require(not {"torch", "angr", "claripy", "pyvex"} & set(sys.modules), "audit imported a framework")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", type=Path)
    args = parser.parse_args()
    roots = sorted((WORKSPACE / ".scratch/selective_analysis").glob("native-preprocessing-v19-*"), reverse=True)
    root = (args.capture_dir or next(path for path in roots if (path / "records.json").is_file())).resolve()
    result = audit(root)
    (root / "validated-audit.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
