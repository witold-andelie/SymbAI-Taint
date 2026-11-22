#!/usr/bin/env python3
"""Route B v5 step 4: label the 141 development queries with single-backend runs and refit L.

Run in WSL angr-env after the v5 freeze. Development queries are the 79 v4 development queries
(the recorded rows of the v4 selector run) and the 62 v4 held-out panel queries. Each backend runs
alone on each query at the frozen 3 s budget, twice (second repetition in reversed query and
backend order). The model specification is the unchanged v4 selector. No v5 held-out query is read.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.contracts import Query, file_hash
from src.selective_analysis.structural_features import extract_features, feature_names, feature_vector
from src.selective_analysis.type_corpus import runtime_path
from src.selective_analysis.v4_runner import WarmWorker
from src.selective_analysis import v4_selector

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
V4_SELECTOR = SCRATCH / "route-b-v4-selector-20261121T074211473909Z"
V4_PANEL = SCRATCH / "route-b-v4-panel-20261121T073950924Z"
BUDGET_SECONDS = v4_selector.BUDGET_SECONDS
DECISIVE = ("excluded_within_scope", "violation")
EXPECTED_QUERIES = 141


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))


def verify_freeze(freeze_dir):
    from scripts.freeze_route_b_v5 import verify_freeze as verify
    return verify(freeze_dir, defer_references=True)


def development_queries():
    rows = []
    previous = json.loads((V4_SELECTOR / "development-queries.json").read_bytes())["rows"]
    for row in previous:
        raw = dict(row["query"])
        raw["binary"] = str(runtime_path(raw["binary"]))
        rows.append({"id": "v4dev:" + row["id"], "query": raw})
    for record in json.loads((V4_PANEL / "panel.json").read_bytes())["records"]:
        raw = dict(record["query"])
        raw["binary"] = str((V4_PANEL / raw["binary"]).resolve())
        rows.append({"id": "v4panel:" + record["case_id"], "query": raw})
    for row in rows:
        row["features"] = feature_vector(extract_features(Query.from_dict(row["query"])))
    if len(rows) != EXPECTED_QUERIES or len({r["id"] for r in rows}) != EXPECTED_QUERIES:
        raise ValueError("Expected %d distinct development queries, found %d" % (EXPECTED_QUERIES, len(rows)))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    args = parser.parse_args()
    freeze_dir = runtime_path(args.freeze).resolve()
    freeze_dir.relative_to(SCRATCH)
    freeze = verify_freeze(freeze_dir)
    rows = development_queries()
    output = SCRATCH / ("route-b-v5-selector-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    write(output / "development-queries.json", {"rows": rows, "feature_names": feature_names()})
    print("Selector output: {} ({} development queries)".format(output, len(rows)), flush=True)
    worker = WarmWorker()
    runs = []
    try:
        for repetition in (0, 1):
            order = rows if repetition == 0 else list(reversed(rows))
            backends = v4_selector.BACKENDS if repetition == 0 else tuple(reversed(v4_selector.BACKENDS))
            for row in order:
                for backend in backends:
                    result = worker.run("{}|{}|{}".format(repetition, row["id"], backend), row["query"],
                                        (backend,), BUDGET_SECONDS)
                    runs.append({"id": row["id"], "repetition": repetition, "backend": backend,
                                 "status": result["status"], "admitted": result["admitted"],
                                 "charged_seconds": result["charged_seconds"],
                                 "worker_replaced": result["worker_replaced"]})
            write(output / "runs.json", runs)
            print("repetition {} done ({} runs)".format(repetition, len(runs)), flush=True)
    finally:
        worker.stop()
    by_key = {(r["id"], r["repetition"], r["backend"]): r for r in runs}
    features, labels = [], []
    for repetition in (0, 1):
        for row in rows:
            entry = {}
            for backend in v4_selector.BACKENDS:
                r = by_key[(row["id"], repetition, backend)]
                decisive = r["admitted"] and r["status"] in DECISIVE
                entry[backend] = {"decisive": decisive,
                                  "seconds": r["charged_seconds"] if decisive else BUDGET_SECONDS}
            features.append(row["features"])
            labels.append(entry)
    model = v4_selector.fit(features, labels)
    model.update(feature_names=feature_names(), freeze_design_sha256=freeze["design_sha256"],
                 freeze_sha256=file_hash(freeze_dir / "freeze.json"),
                 training_rows=len(labels), development_queries=len(rows))
    write(output / "model.json", model)
    summary = {"schema": "symbai.route_b_v5_selector_summary.v1", "development_queries": len(rows),
               "runs": len(runs),
               "decisive_by_backend": {b: sum(r["status"] in DECISIVE and r["admitted"] for r in runs if r["backend"] == b)
                                       for b in v4_selector.BACKENDS},
               "worker_replacements": len(worker.replacements), "model_sha256": file_hash(output / "model.json"),
               "freeze": str(freeze_dir), "freeze_sha256": file_hash(freeze_dir / "freeze.json"),
               "held_out_read": False}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
