#!/usr/bin/env python3
"""Prepare/run three compiled readiness queries and one guarded cold native acquisition."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.contracts import Query, file_hash, fingerprint
from src.selective_analysis.processes import run_bounded, ProcessOutcome
from src.selective_analysis.typed_complementarity import CASE_IDS, METHODS, validate_specs, extract_typed_queries
from src.selective_analysis.workspace import configure_workspace

MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
FLAGS = ["-std=gnu11", "-O1", "-gdwarf-4", "-fPIE", "-pie", "-fno-stack-protector",
         "-fomit-frame-pointer", "-fno-inline", "-fno-builtin", "-fno-lto", "-fcf-protection=none"]
PANEL = "benchmarks/selective_analysis/typed_complementarity"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, indent=2, allow_nan=False).encode("utf-8"))


def snapshot(sources, destination):
    hashes = {}
    for name, path in sources.items():
        digest = file_hash(path)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if file_hash(target) != digest:
            raise ValueError("Snapshot changed: " + name)
        hashes[name] = digest
    return hashes


def operation_worker(request_path, output):
    request = read(request_path)
    if (set(request) != {"schema", "query", "query_hash", "method", "started_at", "budget_seconds"}
            or request["schema"] != "symbai.typed_operation_request.v1"
            or request["method"] not in (*METHODS, "reference") or request["budget_seconds"] != 30):
        raise ValueError("Invalid label/type-free operation request")
    query = Query.from_dict(request["query"])
    if query.contract_hash != request["query_hash"]:
        raise ValueError("Query identity differs")
    deadline = request["started_at"] + 30
    payload = {"schema": "symbai.typed_operation.v1", "query_hash": query.contract_hash,
        "binary_sha256": query.binary_sha256, "method": request["method"], "attempts": [],
        "result": {"status": "unknown", "reason": "not_completed"}, "complete": False,
        "neural_information_used": False}
    write(output, payload)
    if request["method"] == "reference":
        from src.selective_analysis.literal_reference import reference_query
        reference = reference_query(query, deadline)
        payload.update(reference=reference, result=reference["result"])
    else:
        from src.selective_analysis.fixed_cascade import execute_operation
        for operation in METHODS[request["method"]]:
            if time.monotonic() >= deadline:
                break
            attempt = execute_operation(query, operation, deadline)
            payload["attempts"].append(attempt)
            payload["result"] = attempt["result"]
            write(output, payload)
            if payload["result"]["status"] != "unknown":
                break
    payload["complete"] = time.monotonic() < deadline
    write(output, payload)


def run_stage(command, request, folder, cap):
    """Parent clock includes request, process cleanup and persisted normalized payload."""
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request_path, candidate_path = folder / "request.json", folder / "candidate.json"
    request = dict(request)
    if request.get("schema") == "symbai.typed_operation_request.v1":
        request["started_at"] = started
    write(request_path, request)
    try:
        process = run_bounded([*command, "--request", str(request_path), "--output", str(candidate_path)],
            folder / "worker.log", max(0.0, cap - (time.monotonic() - started)), env=os.environ.copy())
    except Exception as error:
        process = ProcessOutcome(-1, False, time.monotonic() - started)
        write(folder / "launch-error.json", {"type": type(error).__name__, "message": str(error)})
    try:
        candidate = read(candidate_path)
        json.dumps(candidate, allow_nan=False)
        if not isinstance(candidate, dict):
            raise ValueError("Worker response must be an object")
    except Exception as error:
        candidate = {"status": "failed", "result": {"status": "unknown"},
                     "error": {"type": type(error).__name__, "message": str(error)}}
    payload = {"request_fingerprint": fingerprint(request), "candidate": candidate, "process": asdict(process)}
    payload_path = folder / "payload.json"
    write(payload_path, payload)
    elapsed = time.monotonic() - started
    receipt = {"status": "completed" if not process.timed_out and process.returncode == 0 and elapsed < cap else "failed",
        "charged_seconds": elapsed, "budget_seconds": cap, "payload_sha256": file_hash(payload_path),
        "payload_fingerprint": fingerprint(payload), "clock_unit": "request_through_payload_persistence",
        "exclusions": ["final_receipt", "aggregate_copying", "offline_evaluation"]}
    write(folder / "receipt.json", receipt)
    return {"payload": payload, "parent_receipt": receipt}


def validated_acquisition(record, binary_hash):
    from scripts.export_typed_complementarity import guard_native_input
    from scripts.export_tygr_candidates import pack_logits
    candidate = record["payload"]["candidate"]
    if (record["parent_receipt"]["status"] != "completed" or candidate.get("status") != "completed"
            or candidate.get("binary_sha256") != binary_hash or candidate.get("model_sha256") != MODEL_HASH
            or candidate.get("identities_rechecked") is not True
            or candidate.get("ground_truth_labels_supplied_to_model") is not False
            or candidate.get("provenance") != {"source": "tygr_glowgnn", "locator": "dwarf_assisted", "decoder": "independent",
                "datagen_predict_phase": False, "ground_truth_labels_supplied_to_model": False}):
        raise ValueError("Cold acquisition did not complete with verified unlabeled identity")
    functions = {entry["function_address"]: entry for entry in candidate["functions"]}
    if len(functions) != len(candidate["functions"]) or not functions:
        raise ValueError("Duplicate/missing native functions")
    if candidate.get("forward_calls_attempted") != len(functions) or candidate.get("forward_calls_completed") != len(functions):
        raise ValueError("Native forward accounting differs")
    for entry in functions.values():
        if (entry["status"] != "completed" or entry["forward_completed"] is not True
                or entry["native_input"]["function_address"] != entry["function_address"]
                or entry["input_guard"] != guard_native_input(entry["native_input"], candidate["model_contract"])):
            raise ValueError("Native input/forward receipt differs")
    counts = {address: 0 for address in functions}
    seen = set()
    for record in candidate["records"]:
        identity = record["function_address"], record["prediction_id"]
        if identity in seen:
            raise ValueError("Duplicate native prediction identity")
        seen.add(identity)
        entry = functions[record["function_address"]]
        variables = {v["prediction_id"]: v for v in entry["native_input"]["variables"]}
        variable = variables[record["prediction_id"]]
        packed = pack_logits(record["raw_value_node_logits"], record["vocabulary"], 3)
        if (any(record[key] != value for key, value in packed.items()) or len(record["vocabulary"]) != 75
                or record["value_nodes"] != variable["original_value_nodes"]
                or record["locations"] != variable["locations"]
                or len(record["raw_value_node_logits"]) != len(variable["flattened_output_rows"])):
            raise ValueError("Whole-variable raw-logit identity/aggregation differs")
        counts[record["function_address"]] += 1
    if any(counts[address] != len(functions[address]["native_input"]["variables"]) for address in functions):
        raise ValueError("Incomplete native variable exports")
    return counts


def summarize(rows, acquisition, labels):
    expected = {item["query_id"]: item["expected"] for item in labels["labels"]}
    if set(expected) != set(CASE_IDS) or len(rows) != 3 or [row["case_id"] for row in rows] != list(CASE_IDS):
        raise ValueError("Keep the fixed three-query denominator")
    coverage, failure = {}, None
    if acquisition is not None and all("query" in row for row in rows):
        try:
            coverage = validated_acquisition(acquisition, rows[0]["query"]["binary_sha256"])
        except Exception as error:
            failure = type(error).__name__ + ": " + str(error)
    cases, wrong, fixed_seconds, completed_controls = [], 0, 0.0, 0
    for row in rows:
        operations, reasons, admissible = {}, {}, {}
        for method in (*METHODS, "reference"):
            trial = row.get("operations", {}).get(method)
            result = {"status": "unknown", "reason": "missing_or_failed_trial"}
            admissible[method] = False
            if trial and trial["parent_receipt"]["status"] == "completed":
                payload = trial["payload"]["candidate"]
                if (payload.get("complete") is True and payload.get("query_hash") == row.get("query_hash")
                        and payload.get("binary_sha256") == row.get("query", {}).get("binary_sha256")
                        and payload.get("method") == method
                        and payload.get("result", {}).get("status") in ("unknown", "violation", "excluded_within_scope")):
                    result = payload["result"]
                    admissible[method] = True
                    completed_controls += 1
            operations[method] = result["status"]
            reasons[method] = result.get("reason")
            if result["status"] != "unknown" and result["status"] != expected[row["case_id"]]:
                wrong += 1
            if method == "fixed_cascade" and trial:
                fixed_seconds += trial["parent_receipt"]["charged_seconds"]
        typed = bool(coverage.get(row.get("query", {}).get("entry_rva"), 0))
        single = [operations[name] for name in ("interval_only", "finite_readonly_only", "expanded_only")]
        differentiated = (all(admissible[name] for name in ("interval_only", "finite_readonly_only", "expanded_only"))
                          and "unknown" in single and any(value != "unknown" for value in single))
        cases.append({"case_id": row["case_id"], "query_extracted": "query" in row,
            "genuine_function_output_available": typed, "variable_records": coverage.get(row.get("query", {}).get("entry_rva"), 0),
            "operation_statuses": operations, "operation_reasons": reasons,
            "completed_control_trials": sum(admissible.values()), "single_operation_capability_differs": differentiated,
            "type_and_operation_readiness_overlap": typed and differentiated})
    acquisition_seconds = acquisition["parent_receipt"]["charged_seconds"] if acquisition else None
    return {"schema": "symbai.typed_complementarity_summary.v1", "planned_queries": 3, "compiled_binaries": 1,
        "cases": cases, "wrong_decisions_including_separate_reference": wrong,
        "planned_control_and_reference_trials": 15, "completed_control_and_reference_trials": completed_controls,
        "genuine_function_coverage": sum(case["genuine_function_output_available"] for case in cases),
        "typed_capability_overlap": sum(case["type_and_operation_readiness_overlap"] for case in cases),
        "acquisition_validation_failure": failure, "cold_acquisition_parent_seconds": acquisition_seconds,
        "cold_acquisition_amortized_per_query_seconds": acquisition_seconds / 3 if acquisition_seconds is not None else None,
        "total_fixed_control_parent_seconds": fixed_seconds,
        "cost_interpretation": "one_binary_three_queries_one_pass_descriptive_only_not_runtime_bound_or_speedup",
        "use_site_mapping_validated": False, "new_selector_evaluated": False,
        "neural_benefit_measured": False, "held_out_evaluation": False}


def unchanged(path, digest):
    try:
        return file_hash(path) == digest
    except OSError:
        return False


def loaded_project_sources():
    result = set()
    for module in sys.modules.values():
        filename = getattr(module, "__file__", None)
        if filename:
            path = Path(filename).resolve()
            if path.suffix == ".py" and path.is_relative_to(ROOT):
                result.add(path.relative_to(ROOT).as_posix())
    return sorted(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--operation-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--request", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    if args.operation_worker:
        operation_worker(args.request, args.output)
        return
    if not args.prepare_only and (not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/") or not args.tygr_python.is_file()):
        parser.error("Run in the existing WSL angr-env on /mnt/d; Windows supports --prepare-only")
    specs = read(ROOT / PANEL / "cases.json")
    validate_specs(specs)
    output = scratch / ("typed-complementarity-v21-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Typed complementarity output: " + str(output), flush=True)
    sources = {path.relative_to(ROOT).as_posix(): path for path in (ROOT / "src/selective_analysis").glob("*.py")}
    for name in ("src/__init__.py", "scripts/__init__.py", "scripts/run_typed_complementarity.py",
            "scripts/export_typed_complementarity.py", "scripts/capture_tygr_preprocessing.py", "scripts/export_tygr_candidates.py",
            "docs/architecture/pilot_revision_v21.md", *[PANEL + "/" + name for name in ("cases.c", "constants.c", "cases.json", "gold.json")]):
        sources[name] = ROOT / name
    tygr = ROOT / "tygr_original"
    upstream = {path.relative_to(tygr).as_posix(): path for path in (tygr / "src").rglob("*.py")}
    sources.update({"tygr_original/" + key: value for key, value in upstream.items()})
    source_hashes = snapshot(sources, output / "source_snapshot")
    model = ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"
    if file_hash(model) != MODEL_HASH:
        raise ValueError("Pinned model differs")
    input_hashes = snapshot({"model.model": model}, output / "input_snapshot")
    copy_root = output / "source_snapshot"
    command = ["gcc", *FLAGS, str(copy_root / PANEL / "cases.c"), str(copy_root / PANEL / "constants.c"), "-o", str(output / "queries.elf")]
    plan = {"schema": "symbai.typed_complementarity_plan.v1", "planned_queries": list(CASE_IDS),
        "compiled_binaries": 1, "compiler_command": command, "prepare_only": args.prepare_only,
        "source_sha256": source_hashes, "source_paths": {key: str(value) for key, value in sources.items()},
        "input_sha256": input_hashes, "model_sha256": MODEL_HASH, "shared_acquisition_cap_seconds": 120,
        "runtime": {"python": sys.version, "platform": sys.platform,
                    **{name: version(name) for name in ("angr", "capstone", "pyelftools")}},
        "control_cap_seconds": 30, "controls": METHODS, "new_selector_evaluated": False}
    write(output / "run-plan.json", plan)
    rows = [{"case_id": name, "operations": {}} for name in CASE_IDS]
    acquisition = None
    if not args.prepare_only:
        compiler_version_process = run_bounded(["gcc", "--version"], output / "compiler-version.log", 5, env=os.environ.copy())
        compilation = run_bounded(command, output / "compile.log", 60, env=os.environ.copy())
        write(output / "compilation.json", {"compiler_version_process": asdict(compiler_version_process), "process": asdict(compilation)})
        try:
            if compilation.returncode or compilation.timed_out:
                raise ValueError("Compilation failed; inspect compile.log")
            extracted = extract_typed_queries(output / "queries.elf", specs)
            write(output / "extracted-queries.json", extracted)
            for row, query in zip(rows, extracted["queries"]):
                row.update(query=query, query_hash=Query.from_dict(query).contract_hash)
            # One shared cold native acquisition; it does not influence fixed control order.
            request = {"schema": "symbai.typed_acquisition_request.v1", "binary": str(output / "queries.elf"),
                "binary_sha256": file_hash(output / "queries.elf"), "model": str(output / "input_snapshot/model.model"),
                "model_sha256": MODEL_HASH, "tygr_root": str(tygr),
                "source_sha256": {name: source_hashes["tygr_original/" + name] for name in upstream},
                "helpers": {key: {"path": str(copy_root / filename), "sha256": source_hashes[filename]} for key, filename in
                    (("capture", "scripts/capture_tygr_preprocessing.py"), ("export", "scripts/export_tygr_candidates.py"))},
                "scratch_dir": str(output / "acquisition/cache"), "worker_sha256": source_hashes["scripts/export_typed_complementarity.py"]}
            acquisition = run_stage([str(args.tygr_python), "-B", str(copy_root / "scripts/export_typed_complementarity.py")],
                request, output / "acquisition", 120)
            write(output / "acquisition.json", acquisition)
            for index, row in enumerate(rows):
                order = list(METHODS)
                order = order[index % 4:] + order[:index % 4] + ["reference"]
                for method in order:
                    request = {"schema": "symbai.typed_operation_request.v1", "query": row["query"], "query_hash": row["query_hash"],
                               "method": method, "started_at": 0, "budget_seconds": 30}
                    trial = run_stage([sys.executable, "-B", str(copy_root / "scripts/run_typed_complementarity.py"), "--operation-worker"],
                        request, output / "controls" / row["case_id"] / method, 30)
                    row["operations"][method] = trial
                    write(output / "records.json", rows)
                    print(row["case_id"] + " " + method + ": " + trial["payload"]["candidate"].get("result", {}).get("status", "unknown"), flush=True)
        except Exception as error:
            write(output / "pipeline-failure.json", {"type": type(error).__name__, "message": str(error)})
    changed_sources = [name for name, digest in source_hashes.items() if not unchanged(sources[name], digest)]
    changed_copies = [name for name, digest in source_hashes.items() if not unchanged(copy_root / name, digest)]
    model_intact = unchanged(model, MODEL_HASH) and unchanged(output / "input_snapshot/model.model", MODEL_HASH)
    inventory_intact = set(upstream) == {path.relative_to(tygr).as_posix() for path in (tygr / "src").rglob("*.py")}
    if args.prepare_only:
        summary = {"schema": "symbai.typed_complementarity_preflight.v1", "planned_queries": 3,
            "compiled_binaries": 0, "native_workers_launched": 0, "native_predictions_performed": False,
            "Linux_collection_pending": True}
    else:
        write(output / "records.json", rows)
        summary = summarize(rows, acquisition, read(copy_root / PANEL / "gold.json"))
    summary.update(changed_sources=changed_sources, changed_copied_sources=changed_copies,
                   model_identity_unchanged=model_intact, upstream_inventory_unchanged=inventory_intact)
    summary["loaded_project_sources"] = loaded_project_sources()
    summary["untracked_loaded_project_sources"] = sorted(set(summary["loaded_project_sources"]) - set(source_hashes))
    write(output / ("preflight-summary.json" if args.prepare_only else "summary.json"), summary)
    print(json.dumps(summary, indent=2))
    if changed_sources or changed_copies or not model_intact or not inventory_intact or summary["untracked_loaded_project_sources"]:
        raise RuntimeError("Input/source integrity changed")
    if not args.prepare_only and (summary["wrong_decisions_including_separate_reference"] or summary["genuine_function_coverage"] < 3
            or summary["completed_control_and_reference_trials"] < 15
            or any(not case["query_extracted"] for case in summary["cases"])):
        raise SystemExit(1)
    print("Finished. Readiness only; no same-budget neural selection comparison: " + str(output))


if __name__ == "__main__":
    main()
