#!/usr/bin/env python3
"""Run the fixed interval/finite/full baseline on the retained three mechanisms."""

import argparse
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.contracts import Checkpoint, Query, file_hash, fingerprint
from src.selective_analysis.workspace import configure_workspace
from src.selective_analysis.fixed_cascade import METHODS, REPETITIONS, BUDGET_SECONDS, REVISION, run_query, runtime_versions

CASE_IDS = ("scalar_span", "readonly_chain", "readonly_chain_outside")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    # Exact bytes make detailed-result persistence reproducible without OS newline translation.
    path.write_bytes(json.dumps(value, indent=2).encode("utf-8"))


def unchanged(path, digest):
    try:
        return file_hash(path) == digest
    except OSError:
        return False


def validate_request(request):
    if (not isinstance(request, dict)
            or set(request) != {"schema", "query", "query_hash", "method", "repetition", "started_at", "budget_seconds", "request_id"}
            or request["schema"] != "symbai.cascade_request.v1" or request["method"] not in (*METHODS, "reference")
            or type(request["repetition"]) is not int or request["repetition"] not in REPETITIONS
            or request["method"] == "reference" and request["repetition"] != 0
            or type(request["started_at"]) not in (int, float) or not math.isfinite(request["started_at"])
            or request["started_at"] < 0 or request["budget_seconds"] != BUDGET_SECONDS):
        raise ValueError("Invalid label-free fixed-cascade request")
    query = Query.from_dict(request["query"])
    identity = {key: request[key] for key in ("query_hash", "method", "repetition")}
    if query.contract_hash != request["query_hash"] or fingerprint(identity) != request["request_id"]:
        raise ValueError("Cascade request identity differs")
    return query


def worker(request_path, result_path, event_path):
    request = read(request_path)
    query = validate_request(request)
    with event_path.open("w", encoding="utf-8") as stream:
        def emit(event):
            stream.write(json.dumps(event) + "\n")
            stream.flush()
        payload = run_query(query, request["method"], request["repetition"], request["started_at"], emit)
        write(result_path, payload)


def finalize_payload(payload, process, charged_seconds, digest):
    """Finalize only from parent-owned persistence/process observations; keep worker evidence."""
    if type(charged_seconds) not in (int, float) or not math.isfinite(charged_seconds) or charged_seconds < 0:
        raise ValueError("Invalid parent clock")
    late = process["timed_out"] or charged_seconds > BUDGET_SECONDS
    failed = process["returncode"] != 0 or payload.get("cost_measurement_complete") is not True
    result = deepcopy(payload["worker_result"])
    reason = "parent_persistence_deadline_exceeded" if late else "worker_failure_or_incomplete_payload" if failed else None
    if reason:
        result = {"status": "unknown", "reason": reason}
    receipt = {"charged_seconds": charged_seconds, "budget_seconds": BUDGET_SECONDS,
               "process": process, "late": bool(late),
               "accounting_unit": "query_through_detailed_result_persistence", "payload_sha256": digest,
               "worker_payload_fingerprint": fingerprint(payload), "final_status": result["status"],
               "final_reason": reason, "exclusions": ["final_accounting_receipt_serialization", "aggregate_copying", "offline_evaluation"]}
    return {**payload, "result": result, "parent_receipt": receipt}


def run_isolated(query, method, repetition, output):
    from src.selective_analysis.processes import run_bounded
    folder = output / "workers" / method / str(repetition) / query.query_id
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    identity = {"query_hash": query.contract_hash, "method": method, "repetition": repetition}
    request = {"schema": "symbai.cascade_request.v1", "query": asdict(query), **identity,
               "started_at": started, "budget_seconds": BUDGET_SECONDS, "request_id": fingerprint(identity)}
    request_path, result_path, event_path = [folder / name for name in ("request.json", "worker-result.json", "events.jsonl")]
    write(request_path, request)
    process = asdict(run_bounded([sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
        str(request_path), str(result_path), str(event_path)], folder / "worker.log",
        max(0.001, BUDGET_SECONDS - (time.monotonic() - started))))
    payload = None
    if result_path.is_file():
        try:
            payload = read(result_path)
        except (ValueError, UnicodeError):
            pass
    valid = (isinstance(payload, dict) and payload.get("schema") == "symbai.cascade_trial.v1"
             and payload.get("query_id") == query.query_id and payload.get("query_hash") == query.contract_hash
             and payload.get("binary_sha256") == query.binary_sha256 and payload.get("method") == method
             and payload.get("repetition") == repetition and isinstance(payload.get("worker_result"), dict)
             and payload["worker_result"].get("status") in ("unknown", "violation", "excluded_within_scope"))
    if not valid:
        events = []
        if event_path.is_file():
            for line in event_path.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                    if isinstance(event, dict) and all(event.get(k) == v for k, v in identity.items()):
                        events.append(event)
                except ValueError:
                    continue
        payload = {"schema": "symbai.cascade_trial.v1", "query_id": query.query_id, **identity,
                   "binary_sha256": query.binary_sha256, "checkpoint_id": Checkpoint(query.contract_hash).checkpoint_id,
                   "worker_result": {"status": "unknown", "reason": "missing_or_invalid_complete_worker_payload"},
                   "attempts": [e["attempt"] for e in events if e.get("event") == "operation_finished" and isinstance(e.get("attempt"), dict)],
                   "runtime_versions": {"availability": "unavailable", "reason": "incomplete_worker_payload"},
                   "worker_costs_seconds": None, "worker_elapsed_seconds": None, "cost_measurement_complete": False,
                   "ledger": events, "reference": None, "neural_information_used": False,
                   "native_replay": "not_attempted", "revision": REVISION}
    # Persist all detailed evidence before closing the primary query clock.
    payload_path = folder / "trial-payload.json"
    write(payload_path, payload)
    digest = file_hash(payload_path)
    charged = time.monotonic() - started
    row = finalize_payload(payload, process, charged, digest)
    write(folder / "receipt.json", row["parent_receipt"])
    return row


def snapshot_inputs(source, output):
    manifest_path = source / "mechanisms/queries.json"
    manifest = read(manifest_path)
    if set(manifest) != {"schema", "queries"} or manifest["schema"] != "symbai.queries.v1" or len(manifest["queries"]) != 3:
        raise ValueError("Expected complete v14 query inputs")
    if {q["query_id"] for q in manifest["queries"]} != set(CASE_IDS):
        raise ValueError("The baseline uses the fixed three v14 mechanisms")
    folder = output / "inputs"
    folder.mkdir(exist_ok=False)
    hashes = {"queries.json": file_hash(manifest_path), "gold.json": file_hash(source / "mechanisms/gold.json")}
    shutil.copyfile(manifest_path, folder / "queries.json")
    # Copy opaque bytes only; expected outcomes are parsed after all reference workers.
    shutil.copyfile(source / "mechanisms/gold.json", folder / "gold.json")
    queries = []
    for spec in manifest["queries"]:
        name = spec["binary"]
        if Path(name).name != name or name != spec["query_id"] + ".elf":
            raise ValueError("Unexpected binary input path")
        hashes[name] = file_hash(source / "mechanisms" / name)
        shutil.copyfile(source / "mechanisms" / name, folder / name)
        queries.append(Query.from_dict(spec, folder))
    if len({q.contract_hash for q in queries}) != 3 or not all(unchanged(folder / name, digest) for name, digest in hashes.items()):
        raise ValueError("Input copy identity differs")
    return queries, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=3, type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--input-dir", type=Path, help="Retained v14 root; old results are not read")
    args = parser.parse_args()
    scratch = configure_workspace()
    logging.getLogger("angr").setLevel(logging.ERROR)
    if args.worker:
        worker(*args.worker)
        return
    source = args.input_dir
    if source is None:
        choices = sorted((p for p in scratch.glob("indirection-gate-v14-*")
                          if (p / "mechanisms/queries.json").is_file()), reverse=True)
        if not choices:
            raise FileNotFoundError("No retained v14 mechanism inputs")
        source = choices[0]
    output = scratch / ("fixed-cascade-v15-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Fixed cascade output: " + str(output), flush=True)
    sources = ["scripts/run_fixed_cascade.py", "src/selective_analysis/fixed_cascade.py",
               "src/selective_analysis/cascade_evaluation.py", "src/selective_analysis/local_bounds.py",
               "src/selective_analysis/readonly_values.py", "src/selective_analysis/literal_reference.py",
               "src/selective_analysis/operations.py", "src/selective_analysis/elf_guard.py",
               "src/selective_analysis/processes.py", "src/selective_analysis/contracts.py",
               "src/selective_analysis/workspace.py", "src/selective_analysis/__init__.py",
               "docs/architecture/pilot_revision_v15.md"]
    source_hashes = {}
    for name in sources:
        original, target = ROOT / name, output / "source_snapshot" / name
        source_hashes[name] = file_hash(original)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        if not unchanged(target, source_hashes[name]):
            raise ValueError("Changed source snapshot")
    queries, input_hashes = snapshot_inputs(source, output)
    lookup = {q.query_id: q for q in queries}
    schedule = []
    for rep in REPETITIONS:
        order = CASE_IDS[rep:] + CASE_IDS[:rep]
        for position, qid in enumerate(order):
            methods = tuple(METHODS) if (position + rep) % 2 == 0 else tuple(reversed(METHODS))
            schedule.extend({"query_id": qid, "method": method, "repetition": rep} for method in methods)
    plan = {"schema": "symbai.cascade_plan.v1", "revision": REVISION, "unique_queries": 3,
            "methods": METHODS, "repetitions": list(REPETITIONS), "planned_records": 18, "separate_references": 3,
            "budget_seconds_per_query": BUDGET_SECONDS, "source_sha256": source_hashes, "input_sha256": input_hashes,
            "input_root": str(source), "schedule": schedule, "parent_runtime_versions": runtime_versions(),
            "neural_information_used": False, "held_out_evaluation": False}
    write(output / "run-plan.json", plan)
    records = []
    for item in schedule:
        row = run_isolated(lookup[item["query_id"]], item["method"], item["repetition"], output)
        records.append(row)
        write(output / "records.json", records)
        sequence = " -> ".join(a["operation"] for a in row["attempts"])
        print(f"r{item['repetition']} {item['query_id']} {item['method']}: {row['result']['status']} [{sequence}]", flush=True)
    references = []
    for qid in CASE_IDS:
        references.append(run_isolated(lookup[qid], "reference", 0, output))
        write(output / "references.json", references)
    from src.selective_analysis.cascade_evaluation import evaluate
    summary = evaluate(records, references, read(output / "inputs/gold.json"))
    summary.update(changed_sources=[name for name, digest in source_hashes.items() if not unchanged(ROOT / name, digest)],
                   changed_original_inputs=[name for name, digest in input_hashes.items() if not unchanged(source / "mechanisms" / name, digest)],
                   changed_copied_inputs=[name for name, digest in input_hashes.items() if not unchanged(output / "inputs" / name, digest)])
    write(output / "summary.json", summary)
    display = {key: summary[key] for key in ("schema", "interpretation_allowed", "blockers", "planned_trials", "unique_queries", "repetitions", "pair_class_counts")}
    display["methods"] = [{k: v for k, v in method.items() if k != "query_vectors"} for method in summary["methods"]]
    display["matched_correct_costs"] = {k: v for k, v in summary["matched_correct_costs"].items() if k != "pairs"}
    display.update(neural_benefit_measured=False, changed_sources=summary["changed_sources"],
                   changed_original_inputs=summary["changed_original_inputs"], changed_copied_inputs=summary["changed_copied_inputs"])
    print(json.dumps(display, indent=2), flush=True)
    if (summary["changed_sources"] or summary["changed_original_inputs"] or summary["changed_copied_inputs"]
            or not summary["interpretation_allowed"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
