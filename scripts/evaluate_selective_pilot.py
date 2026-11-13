#!/usr/bin/env python3
"""Offline label join. Never import this evaluator into the runtime scheduler."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.selective_analysis.workspace import configure_workspace


def evaluate(runs, gold):
    labels = {(r["query_id"], r["binary_sha256"]): r["expected"] for r in gold["labels"]}
    if len(labels) != len(gold["labels"]):
        raise ValueError("Duplicate gold-label identity")
    groups = defaultdict(list)
    seen = set()
    for run in runs:
        key = (run["regime"], run["budget_seconds"], run["variant"])
        identity = (run["query_id"], run["binary_sha256"])
        if identity not in labels or (key, identity) in seen:
            raise ValueError("Unmatched or duplicate run identity")
        seen.add((key, identity))
        groups[key].append(run)
    denominators = [{(r["query_id"], r["binary_sha256"]) for r in rows} for rows in groups.values()]
    if denominators and any(d != denominators[0] for d in denominators):
        raise ValueError("Methods/budgets do not contain the same fixed query denominator")
    if denominators and denominators[0] != set(labels):
        raise ValueError("Missing fixed queries; failures must remain in the denominator")
    reports = []
    for (regime, budget, variant), rows in sorted(groups.items()):
        unknown = sum(r["result"]["status"] == "unknown" for r in rows)
        errors = sum(r["result"]["status"] != "unknown" and
                     r["result"]["status"] != labels[(r["query_id"], r["binary_sha256"])] for r in rows)
        timeouts = sum(r["result"]["status"] == "unknown" and
                       any(word in r["result"].get("reason", "").lower()
                           for word in ("timeout", "budget", "deadline")) for r in rows)
        missing_type_cost = any(r.get("online_acquisition_requested") and
                                "type_acquisition" not in r.get("costs_seconds", {}) for r in rows)
        reports.append({"variant": variant, "regime": regime, "budget_seconds": budget,
                        "queries": len(rows), "resolved": len(rows) - unknown,
                        "unknown": unknown, "wrong_decisions": errors,
                        "timeouts": timeouts,
                        "coverage": (len(rows) - unknown) / len(rows),
                        "unavailable": sum(r["availability"] != "available" for r in rows),
                        "total_wall_seconds": sum(r["elapsed_wall_seconds"] for r in rows),
                        "type_acquisition_seconds": None if missing_type_cost else
                            sum(r.get("costs_seconds", {}).get("type_acquisition", 0) for r in rows),
                        "type_sources": sorted({r["type_source"] for r in rows})})
    return {"schema": "symbai.evaluation.v1", "comparisons": reports,
            "interpretation": "Mechanism and plumbing validation only; missing/synthetic GNN inputs establish no neural benefit."}


def main():
    configure_workspace()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(json.loads(args.runs.read_text(encoding="utf-8")),
                      json.loads(args.gold.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
