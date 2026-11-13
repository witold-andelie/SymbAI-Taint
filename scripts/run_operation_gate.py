#!/usr/bin/env python3
"""Measure frozen B and three operation controls on the same twelve existing mechanisms."""

from collections import defaultdict
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


def summarize(runs, evaluation):
    rows = defaultdict(list)
    for run in runs:
        rows[run["variant"]].append(run)
    comparisons = []
    for result in evaluation["comparisons"]:
        measured = rows[result["variant"]]
        actions = defaultdict(list)
        for run in measured:
            for event in run["ledger"]:
                if event["event"] == "action_finished":
                    actions[event["operation_id"]].append({"query_id": run["query_id"],
                        "execution_seconds": event["execution_seconds"],
                        "validation_seconds": event["validation_seconds"],
                        "status": event["outcome"]["status"]})
        comparisons.append({**result,
            "correct_resolved": result["resolved"] - result["wrong_decisions"],
            "median_wall_seconds": median(r["elapsed_wall_seconds"] for r in measured),
            "total_preparation_seconds": sum(r.get("costs_seconds", {}).get("preparation", 0) for r in measured),
            "actions": dict(actions)})
    return {"schema": "symbai.operation_gate.v1", "comparisons": comparisons,
            "interpretation": "Three repeated developer-fixture trials; not independent samples or neural benefit."}


def main():
    from benchmarks.selective_analysis.mechanisms import make_mechanisms
    from src.selective_analysis.contracts import Query, file_hash
    from src.selective_analysis.workspace import configure_workspace
    from scripts.run_selective_pilot import run_isolated
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    methods = ["B", "expanded_only", "bounds_only", "bounds_then_expanded"]
    repetitions, budget = 3, 3.0
    output = scratch / ("operation-gate-v4-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    manifest = make_mechanisms(output / "existing-mechanisms")
    queries = [Query.from_dict(raw, manifest.parent) for raw in json.loads(manifest.read_text(encoding="utf-8"))["queries"]]
    schedule = []
    for repetition in range(repetitions):
        for index, query in enumerate(queries):
            shift = (repetition + index) % len(methods)
            schedule.extend({"repetition": repetition, "query_id": query.query_id, "method": method}
                            for method in methods[shift:] + methods[:shift])
    source_paths = list((ROOT / "src/selective_analysis").glob("*.py")) + [
        ROOT / "scripts/run_selective_pilot.py", Path(__file__).resolve(),
        ROOT / "scripts/evaluate_selective_pilot.py", ROOT / "benchmarks/selective_analysis/mechanisms.py"]
    sources = {str(p.relative_to(ROOT)).replace("\\", "/"): file_hash(p) for p in source_paths}
    for name in sources:
        target = output / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    plan = {"revision_spec": "docs/architecture/pilot_revision_v4.md", "budget_seconds": budget,
            "repetitions": repetitions, "unique_developer_queries": len(queries), "planned_records": len(schedule),
            "platform": platform.platform(), "python": platform.python_version(),
            "scope": "existing_mechanisms_only_no_neural_information_no_training",
            "regime": "end_to_end", "accounting_unit": "single_query_cold_process",
            "cache_policy": "fresh_worker_and_analysis; OS_cache_not_flushed",
            "schedule": schedule, "runtime_source_sha256": sources,
            "excluded_setup": "fixed mechanism/query generation, orchestration and offline evaluation"}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print("Operation gate output: " + str(output), flush=True)
    query_by_id = {query.query_id: query for query in queries}
    runs = []
    for trial in schedule:
        record = run_isolated(query_by_id[trial["query_id"]], trial["method"], budget, "end_to_end",
                              output / ("repetition-" + str(trial["repetition"])))
        record["repetition"] = trial["repetition"]
        runs.append(record)
        (output / "runs.json").write_text(json.dumps(runs, indent=2), encoding="utf-8")
        if len(runs) % len(methods) == 0:
            print("Completed {}/{} records".format(len(runs), len(schedule)), flush=True)
    # Read labels only after every runtime worker has terminated.
    from scripts.evaluate_selective_pilot import evaluate
    gold = json.loads((manifest.parent / "gold.json").read_text(encoding="utf-8"))
    grouped_evaluations = []
    for repetition in range(repetitions):
        report = evaluate([r for r in runs if r["repetition"] == repetition], gold)
        (output / ("evaluation-" + str(repetition) + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        grouped_evaluations.append(report)
    combined = {"comparisons": []}
    for method in methods:
        reports = [next(row for row in e["comparisons"] if row["variant"] == method) for e in grouped_evaluations]
        combined["comparisons"].append({"variant": method, **{
            key: sum(row[key] for row in reports) for key in
            ("queries", "resolved", "unknown", "wrong_decisions", "timeouts", "total_wall_seconds")}})
    summary = summarize(runs, combined)
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    for row in summary["comparisons"]:
        print("{}: {}/{} resolved; {} wrong; {} timeouts; total {:.3f}s; median {:.3f}s".format(
            row["variant"], row["resolved"], row["queries"], row["wrong_decisions"], row["timeouts"],
            row["total_wall_seconds"], row["median_wall_seconds"]), flush=True)
    print("Finished. All original records and measured sources retained: " + str(output), flush=True)


if __name__ == "__main__":
    main()
