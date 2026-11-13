#!/usr/bin/env python3
"""Compare fixed frame-bound controls on three existing compiled developer queries."""

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
METHODS = ("expanded_only", "frame_bounds_only", "frame_bounds_then_expanded")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def load_queries(probe, compiled):
    from src.selective_analysis.contracts import Query
    queries = []
    for manifest, binary in [(probe / "mapping-review/queries.json", probe / "probe.elf")] + [
            (compiled / name / "queries.json", compiled / name / "query.elf") for name in ("offset_index", "masked_index")]:
        data = read(manifest)
        if len(data["queries"]) != 1:
            raise ValueError("Each fixed input must contain exactly one label-free query")
        queries.append(Query.from_dict(dict(data["queries"][0], binary=str(binary.resolve()))))
    if [q.query_id for q in queries] != ["compiled-direct-index", "offset_index", "masked_index"]:
        raise ValueError("The three predeclared query identities differ")
    if len({q.contract_hash for q in queries}) != 3:
        raise ValueError("Queries must be distinct")
    return queries


def offline_gold(queries, probe, compiled):
    old = read(probe / "mapping-review/gold.json")
    new = read(compiled / "offline-labels.json")
    labels = {(r["query_id"], r["binary_sha256"]): r["expected"] for r in old["labels"]}
    extra = {r["query_id"]: r["expected"] for r in new["labels"]}
    if len(labels) != 1 or len(extra) != 2:
        raise ValueError("Offline label denominator differs")
    return {"schema": "symbai.gold.v1", "purpose": "three_compiled_developer_queries_not_held_out",
        "labels": [{"query_id": q.query_id, "binary_sha256": q.binary_sha256,
            "expected": labels[(q.query_id, q.binary_sha256)] if index == 0 else extra[q.query_id]}
            for index, q in enumerate(queries)]}


def summarize(runs, reports):
    output = []
    for method in METHODS:
        selected = [r for r in runs if r["variant"] == method]
        groups = [next(c for c in report["comparisons"] if c["variant"] == method) for report in reports]
        output.append({"variant": method, **{key: sum(row[key] for row in groups) for key in
            ("queries", "resolved", "unknown", "wrong_decisions", "timeouts", "total_wall_seconds")},
            "median_wall_seconds": median(r["elapsed_wall_seconds"] for r in selected),
            "per_query": [{"query_id": name, "statuses": [r["result"]["status"] for r in selected if r["query_id"] == name],
                "median_wall_seconds": median(r["elapsed_wall_seconds"] for r in selected if r["query_id"] == name),
                "operation_orders": [[e["operation_id"] for e in r["ledger"] if e["event"] == "action_selected"]
                    for r in selected if r["query_id"] == name]} for name in sorted({r["query_id"] for r in selected})]})
    return {"schema": "symbai.frame_bounds_gate.v1", "unique_queries": 3, "repetitions": 3,
        "planned_records": 27, "comparisons": output, "scheduler_changed": False, "neural_information_used": False,
        "interpretation": "Existing compiled developer queries only; applicability/fixed-control costs, not neural value or generalization."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--compiled-dir", type=Path)
    args = parser.parse_args()
    from src.selective_analysis.workspace import configure_workspace
    from src.selective_analysis.contracts import file_hash
    from scripts.run_selective_pilot import run_isolated
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    source_root = ROOT.parent / ".scratch/wsl"
    probes = sorted(source_root.glob("inference-*/mapping-review/queries.json"))
    compiled = sorted(source_root.glob("compiled-queries-v8-*"))
    if args.probe_dir is None:
        if not probes:
            parser.error("The existing reviewed probe is required")
        args.probe_dir = probes[-1].parent.parent
    if args.compiled_dir is None:
        if not compiled:
            parser.error("The existing two v8 compiled queries are required")
        args.compiled_dir = compiled[-1]
    queries = load_queries(args.probe_dir.resolve(), args.compiled_dir.resolve())
    output = scratch / ("frame-bounds-gate-v9-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Frame bounds gate output: " + str(output), flush=True)
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/run_selective_pilot.py", ROOT / "scripts/evaluate_selective_pilot.py",
        ROOT / "docs/architecture/pilot_revision_v9.md"]
    hashes = {}
    for source in sources:
        name = source.relative_to(ROOT).as_posix()
        hashes[name] = file_hash(source)
        saved = output / "source_snapshot" / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, saved)
    inputs = {}
    copied_queries = []
    for query in queries:
        folder = output / "inputs" / query.query_id
        folder.mkdir(parents=True)
        shutil.copyfile(query.binary, folder / "query.elf")
        inputs[query.query_id] = {"query_hash": query.contract_hash, "binary_sha256": query.binary_sha256}
        copied_queries.append(replace(query, binary=str((folder / "query.elf").resolve())))
    queries = copied_queries
    schedule = []
    for repetition in range(3):
        for index, query in enumerate(queries):
            shift = (repetition + index) % len(METHODS)
            schedule.extend({"repetition": repetition, "query_id": query.query_id, "method": method}
                            for method in METHODS[shift:] + METHODS[:shift])
    write(output / "run-plan.json", {"revision_spec": "docs/architecture/pilot_revision_v9.md", "source_sha256": hashes,
        "query_contracts": [asdict(q) for q in queries], "input_identities": inputs,
        "budget_seconds": 5, "repetitions": 3, "unique_queries": 3, "planned_records": 27,
        "schedule": schedule, "python": platform.python_version(), "platform": platform.platform(),
        "regime": "end_to_end", "cache_policy": "cold_process_per_query; OS_caches_not_flushed",
        "scope": "same_three_developer_queries_no_inference_or_neural_selection",
        "excluded_setup": "fixed input discovery/copy, orchestration, source snapshots, offline evaluation"})
    runs = []
    by_id = {q.query_id: q for q in queries}
    for trial in schedule:
        row = run_isolated(by_id[trial["query_id"]], trial["method"], 5.0, "end_to_end",
                           output / ("repetition-" + str(trial["repetition"])))
        row["repetition"] = trial["repetition"]
        runs.append(row)
        write(output / "runs.json", runs)
        if len(runs) % 3 == 0:
            print("Completed {}/27 records".format(len(runs)), flush=True)
    # Only after all runtime processes exit, read offline outcomes.
    gold = offline_gold(queries, args.probe_dir.resolve(), args.compiled_dir.resolve())
    write(output / "offline-gold.json", gold)
    from scripts.evaluate_selective_pilot import evaluate
    reports = []
    for repetition in range(3):
        report = evaluate([r for r in runs if r["repetition"] == repetition], gold)
        reports.append(report)
        write(output / ("evaluation-" + str(repetition) + ".json"), report)
    changed = [name for name, digest in hashes.items() if file_hash(ROOT / name) != digest]
    summary = summarize(runs, reports)
    summary.update(source_integrity_unchanged=not changed, changed_sources=changed)
    if changed:
        summary["interpretation"] = "INVALID comparison: runtime sources changed; original records retained"
    write(output / "summary.json", summary)
    for row in summary["comparisons"]:
        print("{}: {}/{} resolved; {} wrong; {} timeouts; total {:.3f}s; median {:.3f}s".format(
            row["variant"], row["resolved"], row["queries"], row["wrong_decisions"], row["timeouts"],
            row["total_wall_seconds"], row["median_wall_seconds"]), flush=True)
    print("Finished. Three existing developer queries; no neural gain measured. Reports: " + str(output), flush=True)
    return 1 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
