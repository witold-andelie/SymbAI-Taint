#!/usr/bin/env python3
"""Route B v4 step 2: label development queries with single-backend runs and fit selector L.

Run in WSL angr-env. Development queries are the distinct single-input queries recorded in earlier
Route B cohorts (route-b-*/intake.json, excluding every route-b-v4-* directory). Each backend runs
alone on each query at the frozen 3 s budget, twice (second repetition in reversed query and backend
order). No held-out panel query is read.
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
BUDGET_SECONDS = 3.0
DECISIVE = ("excluded_within_scope", "violation")


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def verify_freeze(freeze_dir):
    freeze = json.loads((freeze_dir / "freeze.json").read_bytes())
    for relative, expected in freeze["pins"].items():
        if file_hash(ROOT / relative) != expected:
            raise ValueError("Frozen v4 file changed: " + relative)
    return freeze


def development_queries():
    seen, rows, skipped = set(), [], []
    for intake in sorted(SCRATCH.glob("route-b-*/intake.json")):
        if intake.parent.name.startswith("route-b-v4-"):
            continue
        try:
            data = json.loads(intake.read_bytes())
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        for case, value in data.items():
            if not (isinstance(value, dict) and isinstance(value.get("query"), dict)
                    and "binary_sha256" in value["query"] and len(value["query"].get("inputs", [])) == 1):
                continue
            raw = dict(value["query"])
            key = (raw["binary_sha256"], raw["write_rva"], raw["capacity"], json.dumps(raw["inputs"]))
            if key in seen:
                continue
            seen.add(key)
            raw["binary"] = str(runtime_path(raw["binary"]))
            try:
                query = Query.from_dict(raw)
                features = extract_features(query)
            except (OSError, ValueError, KeyError) as error:
                skipped.append({"cohort": intake.parent.name, "case": case, "reason": "{}: {}".format(type(error).__name__, error)})
                continue
            rows.append({"id": "{}:{}".format(intake.parent.name, case), "query": raw,
                         "features": feature_vector(features)})
    return rows, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    args = parser.parse_args()
    freeze_dir = runtime_path(args.freeze).resolve()
    freeze_dir.relative_to(SCRATCH)
    freeze = verify_freeze(freeze_dir)
    rows, skipped = development_queries()
    output = SCRATCH / ("route-b-v4-selector-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    write(output / "development-queries.json", {"rows": rows, "skipped": skipped,
                                                 "feature_names": feature_names()})
    print("Selector output: {} ({} development queries, {} skipped)".format(output, len(rows), len(skipped)), flush=True)
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
                 training_rows=len(labels), development_queries=len(rows))
    write(output / "model.json", model)
    summary = {"schema": "symbai.route_b_v4_selector_summary.v1", "development_queries": len(rows),
               "skipped": len(skipped), "runs": len(runs),
               "decisive_by_backend": {b: sum(r["status"] in DECISIVE and r["admitted"] for r in runs if r["backend"] == b)
                                       for b in v4_selector.BACKENDS},
               "worker_replacements": len(worker.replacements), "model_sha256": file_hash(output / "model.json"),
               "held_out_read": False}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
