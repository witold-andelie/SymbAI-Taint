#!/usr/bin/env python3
"""Capture original TYGR preprocessing on three retained integration queries, without forward."""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.checkpoint_metadata import inspect_frozen_checkpoint
from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis.native_input_validation import validate_native_capture, summarize_native_trials
from src.selective_analysis.processes import ProcessOutcome, run_bounded
from src.selective_analysis.workspace import configure_workspace

CASE_IDS = ("direct_index", "offset_index", "masked_index")
MODEL_SHA256 = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
FROZEN_IDENTITIES = {
    "direct_index": ("0fb55db6be585f4c71134f6a9483828292f5a73f529420bc21a753a62a7c81a5", "3d2a4a0103efffea4c649986f265a32e6518fc79c15218c6a6b045a598e0299c"),
    "offset_index": ("87ddc7b2c076cbf8eac8752d722b2bd94a1bd007d68c49d4dc13d3b13caaf79e", "d2252e8db5eaa09df65266540ebcc3568eb330e08156d9005c7308ce30eadd6a"),
    "masked_index": ("3819825049678a3cf15229507fea4a16c39f17c4deff2248d79005a6e95b04d7", "a9cb251b1c3635d651ad3e7b5d8ea757214316ff5398af7e39fd073e63b941e2"),
}
SOURCE_FILES = ("scripts/run_native_preprocessing.py", "scripts/capture_tygr_preprocessing.py",
                "src/selective_analysis/native_input_validation.py", "src/selective_analysis/checkpoint_metadata.py",
                "src/selective_analysis/contracts.py", "src/selective_analysis/processes.py",
                "src/selective_analysis/workspace.py", "src/selective_analysis/__init__.py",
                "docs/architecture/pilot_revision_v19.md")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, indent=2, allow_nan=False).encode("utf-8"))


def snapshot(sources, destination):
    result = {}
    for name, source in sources.items():
        digest = file_hash(source)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != digest:
            raise ValueError("Snapshot changed: " + name)
        result[name] = digest
    return result


def latest(scratch):
    for folder in sorted(scratch.glob("location-correspondence-v12-*"), reverse=True):
        if (folder / "run-plan.json").is_file() and all((folder / "inputs" / name / "query.elf").is_file() for name in CASE_IDS):
            return folder
    raise FileNotFoundError("No retained complete native-integration input panel")


def expected_model_contract(metadata, edge_source):
    assignment, = [node for node in ast.parse(edge_source).body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "REDUCE_OP_MAP" for target in node.targets)]
    reductions = ast.literal_eval(assignment.value)
    pp, config = metadata["preproc_config"], metadata["model_config"]
    return {"model_sha256": metadata["model_sha256"], "node_label_encoding_dim": pp["node_label_encoding_dim"],
            "all_ops": pp["all_ops"], "num_all_ops": pp["num_all_ops"], "num_edge_ops": pp["num_edge_ops"],
            "flatten_vars": pp["flatten_vars"], "use_arch": pp["use_arch"], "arch_fields": pp["arch_fields"],
            "type_count": metadata["output_class_count"], "decoder_type": config["decoder_type"],
            "node_aggregation": config["node_aggregation"],
            "layer_relation_capacities": [layer["num_relations"] for layer in metadata["relation_layers"]],
            "edge_reduce_op_map": reductions}


def prepare_cases(retained, copied):
    plan = read(copied / "location-plan.json")
    planned = {case["case_id"]: case for case in plan["inputs"]}
    if set(planned) != set(CASE_IDS):
        raise ValueError("Frozen location-plan denominator differs")
    cases = []
    for name in CASE_IDS:
        folder = copied / name
        binary, manifest = folder / "query.elf", folder / "original-queries.json"
        if (file_hash(binary) != planned[name]["source_sha256"]["binary"]
                or file_hash(manifest) != planned[name]["source_sha256"]["queries"]):
            raise ValueError("Retained native input differs from the old plan")
        data = read(manifest)
        if len(data["queries"]) != 1:
            raise ValueError("Expected one original query per native binary")
        contract = dict(data["queries"][0])
        contract.pop("binary")
        if (file_hash(binary), fingerprint(contract)) != FROZEN_IDENTITIES[name]:
            raise ValueError("Native binary/query differs from the original fixed identity")
        cases.append({"case_id": name, "binary": str(binary.resolve()), "binary_sha256": file_hash(binary),
                      "entry_rva": contract["entry_rva"], "source_query_hash": fingerprint(contract)})
    return cases


def placeholder(request, reason):
    return {"schema": "symbai.native_preprocessing.v1", "status": "failed", "receipt_origin": "parent_recovery",
            "request_identity": {key: request[key] for key in ("binary_sha256", "entry_rva")},
            "provenance": {"model_sha256": MODEL_SHA256, "locator": "dwarf_assisted",
                           "datagen_predict_phase": False, "ground_truth_labels_forwarded": False},
            "model_contract": None, "runtime": {}, "functions": [], "forward_attempts": 0,
            "model_forward_performed": False, "error": {"type": "parent_recovery", "message": reason}}


def run_case(case, request, expected, output, python):
    folder = output / "workers" / case["case_id"]
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request_path, result_path = folder / "request.json", folder / "capture.json"
    write(request_path, request)
    command = [str(python), "-B", str(output / "source_snapshot/scripts/capture_tygr_preprocessing.py"),
               "--request", str(request_path), "--output", str(result_path)]
    try:
        process = run_bounded(command, folder / "worker.log", 60 - (time.monotonic() - started), env=os.environ.copy())
    except Exception as error:
        process = ProcessOutcome(-1, False, time.monotonic() - started)
        write(folder / "launch-error.json", {"type": type(error).__name__, "message": str(error)})
    try:
        candidate = read(result_path)
        if candidate["request_identity"] != {key: request[key] for key in ("binary_sha256", "entry_rva")}:
            raise ValueError("Native worker binary/entry identity differs")
        validation = validate_native_capture(candidate, expected)
    except Exception as error:
        # Original worker bytes remain in capture.json even when malformed/unreadable.
        candidate = locals().get("candidate")
        if not isinstance(candidate, dict):
            candidate = placeholder(request, str(error))
        validation = {"captured": False, "error": type(error).__name__ + ": " + str(error)}
    payload = {"schema": "symbai.native_trial_payload.v1", "case_id": case["case_id"],
               "request_fingerprint": fingerprint(request), "worker_candidate": candidate, "process": vars(process)}
    payload_path = folder / "trial-payload.json"
    write(payload_path, payload)
    digest = file_hash(payload_path)
    elapsed = time.monotonic() - started
    captured = validation.get("captured") is True and candidate.get("status") == "captured"
    receipt = {"status": "captured" if captured and not process.timed_out and process.returncode == 0 and elapsed < 60 else "failed",
               "charged_seconds": elapsed, "budget_seconds": 60, "late": elapsed >= 60,
               "payload_sha256": digest, "payload_fingerprint": fingerprint(payload), "validation": validation,
               "clock_unit": "request_through_complete_payload_persistence",
               "excluded": ["final_accounting_receipt_serialization", "aggregate_copying", "offline_evaluation"]}
    write(folder / "receipt.json", receipt)
    return {"case_id": case["case_id"], "binary_sha256": case["binary_sha256"], "entry_rva": case["entry_rva"],
            "payload": payload, "parent_receipt": receipt}


def unchanged(path, digest):
    try:
        return file_hash(path) == digest
    except OSError:
        return False


def integrity_report(output, inputs, sources, input_hashes, source_hashes, tygr, external):
    return {
        "changed_sources": [name for name, digest in source_hashes.items() if not unchanged(sources[name], digest)],
        "changed_source_copies": [name for name, digest in source_hashes.items() if not unchanged(output / "source_snapshot" / name, digest)],
        "changed_inputs": [name for name, digest in input_hashes.items() if not unchanged(inputs[name], digest)],
        "changed_copied_inputs": [name for name, digest in input_hashes.items() if not unchanged(output / "input_snapshot" / name, digest)],
        "source_inventory_unchanged": set(external) == {p.relative_to(tygr).as_posix() for p in (tygr / "src").rglob("*.py")},
    }


def integrity_changed(report):
    return any(report[key] for key in ("changed_sources", "changed_source_copies", "changed_inputs", "changed_copied_inputs")) or not report["source_inventory_unchanged"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--location-dir", type=Path)
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--prepare-only", action="store_true", help="snapshot/validate inputs without starting native workers")
    args = parser.parse_args()
    scratch = configure_workspace()
    if not args.prepare_only and (not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/")):
        parser.error("Run capture from WSL angr-env on /mnt/d; Windows supports --prepare-only")
    if not args.prepare_only and not args.tygr_python.is_file():
        parser.error("Existing tygr-orig Python is missing; no environments are installed or changed")
    retained = (args.location_dir or latest(scratch)).resolve()
    model, tygr = ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model", ROOT / "tygr_original"
    if file_hash(model) != MODEL_SHA256:
        raise ValueError("Pinned checkpoint differs")
    output = scratch / ("native-preprocessing-v19-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Native preprocessing output: " + str(output), flush=True)
    inputs = {"model/x64.O0.base.model": model, "native/location-plan.json": retained / "run-plan.json"}
    for name in CASE_IDS:
        for file in ("query.elf", "original-queries.json"):
            inputs["native/" + name + "/" + file] = retained / "inputs" / name / file
    input_hashes = snapshot(inputs, output / "input_snapshot")
    sources = {name: ROOT / name for name in SOURCE_FILES}
    external = {path.relative_to(tygr).as_posix(): path for path in sorted((tygr / "src").rglob("*.py"))}
    sources.update({"tygr_original/" + name: path for name, path in external.items()})
    source_hashes = snapshot(sources, output / "source_snapshot")
    external_hashes = {name: source_hashes["tygr_original/" + name] for name in external}
    metadata = inspect_frozen_checkpoint(output / "input_snapshot/model/x64.O0.base.model")
    expected = expected_model_contract(metadata, (output / "source_snapshot/tygr_original/src/analysis/angr/edge.py").read_text(encoding="utf-8"))
    cases = prepare_cases(retained, output / "input_snapshot/native")
    write(output / "expected-model-contract.json", expected)
    plan = {"schema": "symbai.native_preprocessing_plan.v1", "planned_cases": 3, "panel": "existing_compiled_native_integration_only",
            "model_sha256": MODEL_SHA256, "case_identities": cases, "parent_owned_budget_seconds": 60,
            "source_sha256": source_hashes, "input_sha256": input_hashes, "input_sources": {k: str(v) for k, v in inputs.items()},
            "tygr_python": str(args.tygr_python), "tygr_root": str(tygr), "prepare_only": args.prepare_only,
            "prediction_authorized": False, "model_parameters_mapped_to": "cpu"}
    write(output / "run-plan.json", plan)
    if args.prepare_only:
        report = {"schema": "symbai.native_preflight.v1", "planned_cases": 3, "native_workers_launched": 0,
                  "input_identities_verified": True, "expected_model_contract_recorded": True,
                  "native_capture_validated": False, "prediction_performed": False,
                  **integrity_report(output, inputs, sources, input_hashes, source_hashes, tygr, external)}
        write(output / "preflight-summary.json", report)
        if integrity_changed(report):
            raise RuntimeError("Preflight input/source integrity changed")
        print(json.dumps(report, indent=2))
        print("Preparation only. Native runtime capture still requires the existing WSL environments.")
        return
    rows = []
    for case in cases:
        request = {"schema": "symbai.native_preprocessing_request.v1", "binary": case["binary"],
                   "binary_sha256": case["binary_sha256"], "entry_rva": case["entry_rva"],
                   "tygr_root": str(tygr), "model": str(output / "input_snapshot/model/x64.O0.base.model"),
                   "model_sha256": MODEL_SHA256, "scratch_dir": str(output / "workers" / case["case_id"] / "cache"),
                   "source_sha256": external_hashes, "worker_sha256": source_hashes["scripts/capture_tygr_preprocessing.py"]}
        row = run_case(case, request, expected, output, args.tygr_python)
        rows.append(row)
        write(output / "records.json", rows)
        validation = row["parent_receipt"]["validation"]
        print("{}: {}; observed IDs {}; outside saved layer domain {}".format(case["case_id"], row["parent_receipt"]["status"],
              validation.get("observed_relation_ids", []), validation.get("out_of_saved_layer_domain_ids", [])), flush=True)
    summary = summarize_native_trials(rows, expected)
    summary.update(integrity_report(output, inputs, sources, input_hashes, source_hashes, tygr, external))
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    if integrity_changed(summary):
        raise RuntimeError("Original/copied source or input integrity changed")
    if summary["failed"] or summary["interpretation_blocked_by_forward"] or not summary["no_forward"]:
        print("Completed with failed or unverified native captures; all trial records retained: " + str(output))
        raise SystemExit(1)
    print("Finished. Native inputs retained without model forward: " + str(output))


if __name__ == "__main__":
    main()
