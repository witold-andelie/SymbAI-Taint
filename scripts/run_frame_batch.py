#!/usr/bin/env python3
"""Explicit three-query, shared-process cost diagnostic using unchanged fixed controls."""

import argparse
from dataclasses import asdict, replace
import json
import logging
import os
from pathlib import Path
import platform
import shutil
from statistics import median
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def read_events(path):
    result = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                break  # Keep the completed prefix if the last write was interrupted.
    return result


def worker(request_path, result_path, event_path):
    from src.selective_analysis.frame_batch import run_worker
    request = read(request_path)
    with event_path.open("w", encoding="utf-8") as stream:
        def emit(event):
            stream.write(json.dumps(event) + "\n")
            stream.flush()
        result = run_worker(request, emit)
    write(result_path, result)


def run_batch_isolated(queries, method, repetition, output, budget=15.0):
    from src.selective_analysis.contracts import fingerprint
    from src.selective_analysis.frame_batch import finalize_batch
    from src.selective_analysis.processes import run_bounded
    batch_id = fingerprint({"query_order": [q.contract_hash for q in queries], "method": method,
                            "repetition": repetition, "budget": budget})[:20]
    folder = output / "batches" / batch_id
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request = {"schema": "symbai.frame_batch_request.v1", "batch_id": batch_id, "variant": method,
        "budget_seconds": budget, "started_at": started,
        "queries": [{"query": asdict(q), "query_hash": q.contract_hash} for q in queries]}
    request_path, result_path, event_path = [folder / name for name in ("request.json", "worker-result.json", "events.jsonl")]
    write(request_path, request)
    process = run_bounded([sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
        str(request_path), str(result_path), str(event_path)], folder / "worker.log",
        budget - (time.monotonic() - started))
    worker_result = None
    if result_path.is_file():
        try:
            worker_result = read(result_path)
        except (json.JSONDecodeError, UnicodeError):
            pass
    events = read_events(event_path)
    record = finalize_batch(request, worker_result, events, asdict(process), time.monotonic() - started)
    # Include initial parent finalization and complete provisional receipt serialization.
    write(folder / "provisional-receipt.json", record)
    elapsed = time.monotonic() - started
    record = finalize_batch(request, worker_result, events, asdict(process), elapsed)
    record.update(repetition=repetition,
        timing_boundary="through_recovery_initial_finalization_and_provisional_serialization; final_clock_stamp_write_excluded")
    write(folder / "result.json", record)
    return record


def summarize_batches(batches, gold):
    """Offline only; primary cost is the complete batch, never free-start query durations."""
    from src.selective_analysis.frame_batch import METHODS
    labels = {(r["query_id"], r["binary_sha256"]): r["expected"] for r in gold["labels"]}
    if len(labels) != 3 or len(gold["labels"]) != 3 or len(batches) != 9:
        raise ValueError("The fixed three-query/nine-batch denominator differs")
    seen, reports = set(), []
    for batch in batches:
        identity = (batch["repetition"], batch["variant"])
        if identity in seen or batch["variant"] not in METHODS or batch["repetition"] not in range(3):
            raise ValueError("Duplicate or unexpected batch identity")
        seen.add(identity)
        keys = [(q["query_id"], q["binary_sha256"]) for q in batch["queries"]]
        if len(keys) != 3 or set(keys) != set(labels):
            raise ValueError("Missing, duplicate or unmatched query in batch")
    for method in METHODS:
        selected = [b for b in batches if b["variant"] == method]
        if len(selected) != 3:
            raise ValueError("Missing fixed method/repetition")
        query_rows = [q for b in selected for q in b["queries"]]
        wrong = sum(q["result"]["status"] != "unknown" and q["result"]["status"] != labels[(q["query_id"], q["binary_sha256"])] for q in query_rows)
        unknown = sum(q["result"]["status"] == "unknown" for q in query_rows)
        reports.append({"variant": method, "batches": 3, "query_outcomes": 9,
            "resolved": 9 - unknown, "wrong": wrong, "unknown": unknown,
            "batch_timeouts": sum(b["process"].get("timed_out", False) for b in selected),
            "batch_overruns": sum(b["charged_seconds"] > b["budget_seconds"] for b in selected),
            "total_batch_wall_seconds": sum(b["charged_seconds"] for b in selected),
            "median_batch_wall_seconds": median(b["charged_seconds"] for b in selected),
            "batch_records": [{"batch_id": b["batch_id"], "repetition": b["repetition"] ,
                "query_order": [q["query_id"] for q in b["queries"]], "charged_seconds": b["charged_seconds"],
                "batch_status": b["batch_status"],
                "query_local_seconds": sum(q.get("query_elapsed_seconds", 0) or 0 for q in b["queries"]),
                "outside_completed_query_intervals_seconds": b["charged_seconds"] - sum(q.get("query_elapsed_seconds", 0) or 0 for q in b["queries"])} for b in selected]})
    return {"schema": "symbai.frame_batch_summary.v1", "unique_queries": 3, "planned_batches": 9,
        "planned_query_outcomes": 27, "accounting_unit": "three_query_cold_batch", "budget_seconds_per_batch": 15,
        "comparisons": reports, "neural_information_used": False, "selector_changed": False,
        "interpretation": "Explicit shared-process developer cost diagnostic; query-local durations exclude shared batch overhead and are not primary costs. Not a neural or held-out evaluation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--compiled-dir", type=Path)
    parser.add_argument("--worker", nargs=3, type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    from src.selective_analysis.workspace import configure_workspace
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    if args.worker:
        worker(*args.worker)
        return 0
    from scripts.run_frame_bounds_gate import load_queries, offline_gold
    from src.selective_analysis.frame_batch import METHODS
    from src.selective_analysis.contracts import file_hash
    inputs_root = ROOT.parent / ".scratch/wsl"
    probes = sorted(inputs_root.glob("inference-*/mapping-review/queries.json"))
    compiled = sorted(inputs_root.glob("compiled-queries-v8-*"))
    if args.probe_dir is None:
        if not probes:
            parser.error("The existing reviewed compiled probe is required")
        args.probe_dir = probes[-1].parent.parent
    if args.compiled_dir is None:
        if not compiled:
            parser.error("The existing v8 compiled queries are required")
        args.compiled_dir = compiled[-1]
    queries = load_queries(args.probe_dir.resolve(), args.compiled_dir.resolve())
    output = scratch / ("frame-batch-v10-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Frame batch output: " + str(output), flush=True)
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/run_frame_bounds_gate.py", ROOT / "docs/architecture/pilot_revision_v10.md"]
    hashes = {}
    for source in sources:
        name = source.relative_to(ROOT).as_posix()
        hashes[name] = file_hash(source)
        saved = output / "source_snapshot" / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, saved)
    copied = []
    for query in queries:
        folder = output / "inputs" / query.query_id
        folder.mkdir(parents=True)
        shutil.copyfile(query.binary, folder / "query.elf")
        copied.append(replace(query, binary=str((folder / "query.elf").resolve())))
    queries = copied
    schedule = []
    for repetition in range(3):
        order = queries[repetition:] + queries[:repetition]
        methods = METHODS[repetition:] + METHODS[:repetition]
        schedule.extend({"repetition": repetition, "variant": method, "query_order": [q.query_id for q in order]} for method in methods)
    write(output / "run-plan.json", {"revision_spec": "docs/architecture/pilot_revision_v10.md", "source_sha256": hashes,
        "query_contracts": [asdict(q) for q in queries], "schedule": schedule,
        "accounting_unit": "three_query_cold_batch", "budget_seconds_per_batch": 15,
        "planned_batches": 9, "planned_query_outcomes": 27, "unique_queries": 3,
        "platform": platform.platform(), "python": platform.python_version(),
        "cache_policy": "fresh_process_per_batch; imports_and_library_caches_can_warm_within_batch; no_explicit_cross_query_analysis_reuse; OS_caches_not_flushed",
        "timing_boundary": "parent_start_through_recovery_initial_finalization_and_provisional_serialization",
        "excluded_setup": "source/input snapshots, orchestration, final timing stamp/write, offline evaluation"})
    batches, by_id = [], {q.query_id: q for q in queries}
    for item in schedule:
        record = run_batch_isolated([by_id[name] for name in item["query_order"]], item["variant"], item["repetition"], output)
        batches.append(record)
        write(output / "batches.json", batches)
        statuses = [q["result"]["status"] for q in record["queries"]]
        print("Batch {}/9 {}: {}; {:.3f}s".format(len(batches), item["variant"], statuses, record["charged_seconds"]), flush=True)
    # All workers are stopped before any expected outcome is read.
    gold = offline_gold(queries, args.probe_dir.resolve(), args.compiled_dir.resolve())
    write(output / "offline-gold.json", gold)
    summary = summarize_batches(batches, gold)
    changed = [name for name, digest in hashes.items() if file_hash(ROOT / name) != digest]
    summary.update(source_integrity_unchanged=not changed, changed_sources=changed)
    if changed:
        summary["interpretation"] = "INVALID comparison: runtime sources changed; original batches retained"
    write(output / "summary.json", summary)
    for row in summary["comparisons"]:
        print("{}: {}/{} resolved; {} wrong; {} unknown; total batch {:.3f}s; median batch {:.3f}s".format(
            row["variant"], row["resolved"], row["query_outcomes"], row["wrong"], row["unknown"],
            row["total_batch_wall_seconds"], row["median_batch_wall_seconds"]), flush=True)
    print("Finished. Nine complete batch costs retained; no neural inference or speedup claim: " + str(output), flush=True)
    return 1 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
