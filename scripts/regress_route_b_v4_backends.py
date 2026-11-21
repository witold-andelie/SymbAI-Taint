#!/usr/bin/env python3
"""Regression gate for the consolidated Route B v4 backends (run in WSL angr-env).

Re-runs the archived project-disjoint cohort with the fixed symbolic-to-concrete order through the
consolidated ``finite_backends`` and ``v4_runner``. It requires the archived per-case outcome sets:
five cases verified within scope and bzip2 unresolved, in every repetition, at the archived 3 s
request budget. Decisive results are checked against the archived native references afterwards.
No new panel, selector or held-out data is involved.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.contracts import file_hash
from src.selective_analysis.type_corpus import runtime_path
from src.selective_analysis.v4_runner import WarmWorker, fixed_cascade_order

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
ARCHIVE = SCRATCH / "route-b-project-disjoint-20261119T141817Z"
EXPECTED = {"jansson_utf8_first": "excluded_within_scope", "cjson_hex4": "excluded_within_scope",
            "lz4_common_bytes": "excluded_within_scope", "bzip2_index": "unknown",
            "xz_bsr32": "excluded_within_scope", "brotli_reverse8": "excluded_within_scope"}
BUDGET_SECONDS = 3.0
REPETITIONS = 2


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    intake = json.loads((ARCHIVE / "intake.json").read_bytes())
    if set(intake) != set(EXPECTED):
        raise ValueError("Archived cohort differs")
    queries = {}
    for case, row in intake.items():
        query = dict(row["query"])
        query["binary"] = str(runtime_path(query["binary"]))
        if file_hash(query["binary"]) != query["binary_sha256"]:
            raise ValueError("Archived fixture changed: " + case)
        queries[case] = query
    output = SCRATCH / ("route-b-v4-backend-regression-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    print("Regression output: " + str(output), flush=True)
    started = time.monotonic()
    worker = WarmWorker()
    cold_start = time.monotonic() - started
    rows = []
    try:
        for repetition in range(REPETITIONS):
            order = list(EXPECTED) if repetition % 2 == 0 else list(reversed(list(EXPECTED)))
            for case in order:
                result = worker.run("{}-{}".format(repetition, case), queries[case],
                                    fixed_cascade_order(queries[case]), BUDGET_SECONDS)
                result.update(case=case, repetition=repetition)
                rows.append(result)
                write(output / "records.json", rows)
                print("{} {}: {} via {} in {:.3f} s".format(repetition, case, result["status"],
                      result["final"].get("backend"), result["charged_seconds"]), flush=True)
    finally:
        worker.stop()
    mismatches = [r for r in rows if r["status"] != EXPECTED[r["case"]]]
    # Offline check of decisive results against the archived native references.
    wrong = []
    for r in rows:
        if r["status"] in ("excluded_within_scope", "violation"):
            reference = json.loads((ARCHIVE / (r["case"] + "-native-reference.json")).read_bytes())
            capacity = queries[r["case"]]["capacity"]
            truth = "violation" if any(i >= capacity for i in reference["indices"]) else "excluded_within_scope"
            if truth != r["status"]:
                wrong.append(r["case"])
    summary = {"schema": "symbai.route_b_v4_backend_regression.v1", "archive": str(ARCHIVE),
               "budget_seconds": BUDGET_SECONDS, "repetitions": REPETITIONS, "cold_start_seconds": cold_start,
               "worker_replacements": worker.replacements, "records": len(rows),
               "outcome_mismatches": [{"case": r["case"], "repetition": r["repetition"], "status": r["status"]}
                                      for r in mismatches],
               "wrong_decisions": wrong, "passed": not mismatches and not wrong,
               "verified": sum(r["status"] == "excluded_within_scope" for r in rows)}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
