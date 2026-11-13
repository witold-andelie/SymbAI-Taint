#!/usr/bin/env python3
"""Three authored operation-capability mechanisms; no neural selection is measured."""

import argparse
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

from src.selective_analysis.contracts import Checkpoint, Query, file_hash
from src.selective_analysis.workspace import configure_workspace

METHODS = {"interval_only": ("interval",), "finite_readonly_only": ("finite_readonly",),
           "expanded_only": ("expanded",), "interval_then_finite": ("interval", "finite_readonly")}
BUDGET_SECONDS = 30.0


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def worker(request_path, result_path, events_path):
    request = read(request_path)
    if (set(request) != {"schema", "query", "query_hash", "method", "started_at", "budget_seconds"}
            or request["schema"] != "symbai.indirection_request.v1"
            or request["method"] not in (*METHODS, "literal_reference")
            or request["budget_seconds"] != BUDGET_SECONDS
            or type(request["started_at"]) not in (int, float)
            or not math.isfinite(request["started_at"]) or request["started_at"] < 0):
        raise ValueError("Invalid label-free indirection request")
    query = Query.from_dict(request["query"])
    if query.contract_hash != request["query_hash"]:
        raise ValueError("Query identity differs")
    started, method = request["started_at"], request["method"]
    deadline = started + request["budget_seconds"]
    costs = {phase: 0.0 for phase in ("preparation", "execution", "validation", "recording")}
    ledger = []
    with events_path.open("w", encoding="utf-8") as stream:
        def emit(event, **payload):
            before = time.monotonic()
            row = {"event": event, "elapsed_from_parent_start_seconds": before - started, **payload}
            ledger.append(row)
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            costs["recording"] += time.monotonic() - before
        result = {"status": "unknown", "reason": "nothing_completed"}
        emit("worker_started", query_hash=query.contract_hash, method=method,
             checkpoint=Checkpoint(query.contract_hash).checkpoint_id, types="not_accepted")
        reference = None
        if method == "literal_reference":
            before = time.monotonic()
            from src.selective_analysis.literal_reference import reference_query
            reference = reference_query(query, deadline)
            costs["validation"] += time.monotonic() - before
            result = reference["result"]
            emit("reference_completed", reference=reference)
        else:
            for operation in METHODS[method]:
                if time.monotonic() >= deadline:
                    result = {"status": "unknown", "reason": "worker_budget_exhausted"}
                    break
                emit("operation_started", operation=operation, basis="fresh_function_entry")
                phase, before, candidate = "preparation", time.monotonic(), None
                try:
                    if operation == "interval":
                        from src.selective_analysis.local_bounds import LocalBoundsChecker
                        checker = LocalBoundsChecker(query)
                    elif operation == "finite_readonly":
                        from src.selective_analysis.readonly_values import FiniteReadonlyChecker
                        checker = FiniteReadonlyChecker(query, cardinality_limit=32)
                    else:
                        from src.selective_analysis.operations import BinaryChecker
                        checker = BinaryChecker(query)
                    costs[phase] += time.monotonic() - before
                    phase, before = "execution", time.monotonic()
                    candidate = checker.check(128, deadline, use_prepared=False) if operation == "expanded" else checker.check(deadline)
                    costs[phase] += time.monotonic() - before
                    phase, before = "validation", time.monotonic()
                    candidate = checker.validate(candidate, 128, deadline) if operation == "expanded" else checker.validate(candidate, deadline)
                    costs[phase] += time.monotonic() - before
                    phase = None
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Operation evidence completed after deadline")
                except Exception as exc:
                    if phase is not None:
                        costs[phase] += time.monotonic() - before
                    candidate = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc),
                                 "incomplete_candidate": candidate}
                result = candidate
                emit("operation_finished", operation=operation, outcome=result)
                if result["status"] in ("violation", "excluded_within_scope"):
                    break
        if time.monotonic() >= deadline:
            result = {"status": "unknown", "reason": "worker_finalization_exceeded_deadline", "late_candidate": result}
        emit("worker_finished", result=result)
        row = {"schema": "symbai.indirection_trial.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
               "binary_sha256": query.binary_sha256, "method": method, "result": result,
               "checkpoint_id": Checkpoint(query.contract_hash).checkpoint_id, "ledger": ledger,
               "costs_seconds": costs, "worker_observed_seconds": time.monotonic() - started,
               "reference": reference, "neural_information_used": False,
               "native_replay": "not_attempted"}
        write(result_path, row)


def run_isolated(query, method, output):
    from src.selective_analysis.processes import run_bounded
    folder = output / "workers" / method / query.query_id
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request = {"schema": "symbai.indirection_request.v1", "query": asdict(query), "query_hash": query.contract_hash,
               "method": method, "started_at": started, "budget_seconds": BUDGET_SECONDS}
    request_path, result_path, events_path = [folder / name for name in ("request.json", "result.json", "events.jsonl")]
    write(request_path, request)
    process = asdict(run_bounded([sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
        str(request_path), str(result_path), str(events_path)], folder / "worker.log",
        max(0.001, BUDGET_SECONDS - (time.monotonic() - started))))
    row = None
    if result_path.is_file():
        try:
            row = read(result_path)
        except (ValueError, UnicodeError):
            pass
    identity = (isinstance(row, dict) and row.get("query_hash") == query.contract_hash
                and row.get("binary_sha256") == query.binary_sha256 and row.get("method") == method)
    if not identity:
        row = {"schema": "symbai.indirection_trial.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
               "binary_sha256": query.binary_sha256, "method": method, "result": {"status": "unknown", "reason": "missing_worker_result"},
               "ledger": [], "costs_seconds": None, "neural_information_used": False,
               "checkpoint_id": Checkpoint(query.contract_hash).checkpoint_id}
    elapsed = time.monotonic() - started
    if process["timed_out"] or process["returncode"] or elapsed > BUDGET_SECONDS:
        row["retained_candidate_result"] = row["result"]
        row["result"] = {"status": "unknown", "reason": "parent_deadline_or_worker_failure"}
    row.update(parent_process=process, parent_elapsed_through_recovery_seconds=elapsed,
               budget_seconds=BUDGET_SECONDS, cost_accounting="full_parent_process_and_recovery_not_stage_sum",
               final_parent_and_aggregate_serialization_outside_reported_clock=True)
    write(folder / "parent-record.json", row)
    return row


def evaluate(records, references, gold):
    if (gold.get("schema") != "symbai.gold.v1" or gold.get("panel") != "v14_three_authored_capability_mechanisms"
            or len(gold.get("labels", [])) != 3):
        raise ValueError("Expected the separate v14 offline panel only")
    ids = {label["query_id"] for label in gold["labels"]}
    if len(ids) != 3 or len(records) != 12 or len(references) != 3:
        raise ValueError("Incomplete three-case mechanism denominator")
    if {(r["query_id"], r["method"]) for r in records} != {(qid, method) for qid in ids for method in METHODS}:
        raise ValueError("Missing/duplicate operation record")
    if {r["query_id"] for r in references} != ids:
        raise ValueError("Missing/duplicate reference")
    expected = {r["query_id"]: r for r in gold["labels"]}
    wrong, reference_disagreements, comparisons = [], [], []
    for row in (*records, *references):
        label = expected[row["query_id"]]
        if label["binary_sha256"] != row["binary_sha256"]:
            raise ValueError("Offline gold belongs to another binary")
        if row["result"]["status"] not in ("violation", "excluded_within_scope", "unknown"):
            raise ValueError("Invalid query result")
        if row["result"]["status"] != "unknown" and row["result"]["status"] != label["expected"]:
            wrong.append({"query_id": row["query_id"], "method": row["method"]})
    refs = {r["query_id"]: r for r in references}
    for row in records:
        ref = refs[row["query_id"]]
        if row["query_hash"] != ref["query_hash"]:
            raise ValueError("Reference/check query identity differs")
        if (row["result"]["status"] != "unknown" and ref["result"]["status"] != "unknown"
                and row["result"]["status"] != ref["result"]["status"]):
            reference_disagreements.append({"query_id": row["query_id"], "method": row["method"]})
    for method in METHODS:
        rows = [r for r in records if r["method"] == method]
        comparisons.append({"method": method, "records": len(rows),
                            "resolved": sum(r["result"]["status"] != "unknown" for r in rows),
                            "unknown": sum(r["result"]["status"] == "unknown" for r in rows),
                            "parent_observed_total_seconds": sum(r["parent_elapsed_through_recovery_seconds"] for r in rows)})
    unresolved_refs = [r["query_id"] for r in references if r["result"]["status"] == "unknown"]
    return {"schema": "symbai.indirection_summary.v1", "unique_mechanism_queries": 3,
            "runtime_records": 12, "separate_reference_records": 3, "comparisons": comparisons,
            "wrong_decisions": wrong, "reference_disagreements": reference_disagreements,
            "unresolved_references": unresolved_refs,
            "correctness_review_required": bool(wrong or reference_disagreements or unresolved_refs),
            "neural_selection_measured": False, "policy_speedup_measured": False,
            "held_out_evaluation": False, "interpretation": "Three authored operation-capability mechanisms only; unknowns retained, separate modeled references, one pass without speed or neural-value claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=3, type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    scratch = configure_workspace()
    logging.getLogger("angr").setLevel(logging.ERROR)
    if args.worker:
        worker(*args.worker)
        return
    output = scratch / ("indirection-gate-v14-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Indirection mechanism output: " + str(output), flush=True)
    sources = ["scripts/run_indirection_gate.py", "benchmarks/selective_analysis/indirection_mechanisms.py",
               "benchmarks/selective_analysis/mechanisms.py", "src/selective_analysis/readonly_values.py",
               "src/selective_analysis/literal_reference.py", "src/selective_analysis/local_bounds.py",
               "src/selective_analysis/elf_guard.py", "src/selective_analysis/operations.py",
               "src/selective_analysis/contracts.py", "src/selective_analysis/processes.py",
               "src/selective_analysis/workspace.py", "docs/architecture/pilot_revision_v14.md"]
    hashes = {}
    for name in sources:
        source, target = ROOT / name, output / "source_snapshot" / name
        hashes[name] = file_hash(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != hashes[name]:
            raise ValueError("Source changed during snapshot")
    write(output / "run-plan.json", {"schema": "symbai.indirection_plan.v1", "planned_cases": 3,
        "methods": METHODS, "cardinality_limit": 32, "planned_runtime_records": 12,
        "separate_reference_records": 3, "worker_budget_seconds": BUDGET_SECONDS,
        "source_sha256": hashes, "neural_information_used": False, "original_panels_unchanged": True})
    from benchmarks.selective_analysis.indirection_mechanisms import make_indirection_mechanisms
    manifest = make_indirection_mechanisms(output / "mechanisms")
    queries = [Query.from_dict(q, manifest.parent) for q in read(manifest)["queries"]]
    records = []
    for i, query in enumerate(queries):
        order = list(METHODS)
        order = order[i:] + order[:i]
        for method in order:
            row = run_isolated(query, method, output)
            records.append(row)
            write(output / "records.json", records)
            print(query.query_id + " " + method + ": " + row["result"]["status"], flush=True)
    references = []
    for query in queries:
        references.append(run_isolated(query, "literal_reference", output))
        write(output / "references.json", references)
    # Gold never reaches operation or correctness-reference workers.
    gold = read(manifest.parent / "gold.json")
    summary = evaluate(records, references, gold)
    summary["changed_sources"] = [name for name, digest in hashes.items() if file_hash(ROOT / name) != digest]
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    if summary["changed_sources"] or summary["correctness_review_required"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
