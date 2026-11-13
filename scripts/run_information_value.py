#!/usr/bin/env python3
"""One reviewed-query information ablation; no free precomputed score is an online result."""

from collections import Counter
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
MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"


def validate_frozen_inputs(query, raw_path, mapped_path, mapping_path, receipt):
    from src.selective_analysis.contracts import file_hash
    from src.selective_analysis.types import load_type_view
    from scripts.map_tygr_candidates import map_candidates
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    mapped = json.loads(mapped_path.read_text(encoding="utf-8"))
    review = json.loads(mapping_path.read_text(encoding="utf-8"))
    provenance = raw.get("provenance", {})
    if (raw.get("binary_sha256") != query.binary_sha256
            or provenance.get("model_sha256") != MODEL_HASH or receipt.get("model_sha256") != MODEL_HASH
            or provenance.get("decoder") != "independent"
            or provenance.get("ground_truth_labels_supplied_to_model") is not False
            or file_hash(raw_path) != receipt.get("raw_artifact_sha256")
            or file_hash(raw_path) != mapped.get("raw_artifact_sha256")
            or file_hash(mapped_path) != receipt.get("mapped_artifact_sha256")
            or not raw.get("acquisition_id")
            or raw["acquisition_id"] != receipt.get("acquisition_id")
            or raw["acquisition_id"] != mapped.get("acquisition_id")):
        raise ValueError("Frozen raw/mapped acquisition identities differ")
    if any(not link.get("expected_identity") for link in review["mappings"]):
        raise ValueError("Frozen types require a reviewed physical location anchor")
    rebuilt = map_candidates(raw, [query], review)
    if mapped["records"] != rebuilt["records"] or mapped["provenance"] != rebuilt["provenance"]:
        raise ValueError("Frozen mapped records differ from reviewed raw remapping")
    c = load_type_view(mapped_path, query, "C")
    d = load_type_view(mapped_path, query, "D")
    if c.labels != d.labels[:1] or c.weights or c.raw_scores:
        raise ValueError("Type-view isolation failed")
    return {"query_hash": query.contract_hash, "model_sha256": MODEL_HASH,
            "acquisition_id": raw["acquisition_id"], "raw_sha256": file_hash(raw_path),
            "mapped_sha256": file_hash(mapped_path), "review_sha256": file_hash(mapping_path),
            "reviewed_use_sites": len(mapped["records"]), "top1": list(c.labels), "topk": list(d.labels)}


def summarize(runs, evaluations, methods):
    results = []
    for budget in sorted({r["budget_seconds"] for r in runs}):
        for method in methods:
            records = [r for r in runs if r["variant"] == method and r["budget_seconds"] == budget]
            reports = [r for e in evaluations for r in e["comparisons"]
                       if r["variant"] == method and r["budget_seconds"] == budget]
            sequences = Counter(" -> ".join(e["operation_id"] for e in row["ledger"] if e["event"] == "action_selected")
                                or "no_action" for row in records)
            charged = [r["charged_seconds"] for r in records if r.get("charged_seconds") is not None]
            results.append({"method": method, "budget_seconds": budget, "trials": len(records),
                **{key: sum(report[key] for report in reports) for key in ("resolved", "unknown", "wrong_decisions", "timeouts")},
                "median_charged_seconds": median(charged) if charged else None,
                "missing_charged_breakdowns": len(records) - len(charged),
                "median_full_process_wall_seconds": median(r["elapsed_wall_seconds"] for r in records),
                "action_sequences": dict(sequences)})
    return {"schema": "symbai.information_value_summary.v1", "unique_queries": len({r["query_hash"] for r in runs}),
            "records": len(runs), "comparisons": results,
            "interpretation": "Information-only, one reviewed developer query; no end-to-end benefit or generalization claim."}


def main():
    from src.selective_analysis.workspace import configure_workspace
    from src.selective_analysis.contracts import Query, file_hash
    from src.selective_analysis.information_value import METHODS
    from scripts.run_selective_pilot import run_isolated
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    reviewed = sorted((ROOT.parent / ".scratch/wsl").glob("inference-*/mapping-review/queries.json"))
    acquisitions = sorted((ROOT.parent / ".scratch/wsl").glob("acquisition-profile-v5-*/trials.json"))
    if not reviewed or not acquisitions:
        raise ValueError("Existing reviewed probe and completed v5 acquisition are required")
    probe = reviewed[-1].parent.parent
    manifest = json.loads(reviewed[-1].read_text(encoding="utf-8"))
    if len(manifest["queries"]) != 1:
        raise ValueError("This diagnostic requires the one existing reviewed query")
    manifest["queries"][0]["binary"] = str(probe / "probe.elf")
    query = Query.from_dict(manifest["queries"][0])
    chosen = None
    for record_file in reversed(acquisitions):
        for row in json.loads(record_file.read_text(encoding="utf-8")):
            if row["status"] == "completed" and row["profile"]["binary_sha256"] == query.binary_sha256:
                chosen = (record_file.parent, row)
                break
        if chosen:
            break
    if chosen is None:
        raise ValueError("No completed v5 acquisition matches the reviewed query")
    origin, origin_row = chosen
    attempt = origin / ("trial-" + str(origin_row["trial"]))
    output = scratch / ("information-value-v6-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    inputs = output / "inputs"
    inputs.mkdir()
    for source, name in ((attempt / "raw-types.json", "raw-types.json"),
                         (attempt / "mapped-types.json", "mapped-types.json"),
                         (origin / "reviewed-mapping.json", "reviewed-mapping.json")):
        shutil.copyfile(source, inputs / name)
    types = inputs / "mapped-types.json"
    receipt = origin_row["receipt"]
    (inputs / "acquisition-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    validation = validate_frozen_inputs(query, inputs / "raw-types.json", types, inputs / "reviewed-mapping.json", receipt)
    (inputs / "validation.json").write_text(json.dumps(validation, indent=2), encoding="utf-8")
    methods, budgets, repetitions = list(METHODS), [0.05, 0.15, 0.50], 3
    schedule = []
    for budget_index, budget in enumerate(budgets):
        for repetition in range(repetitions):
            shift = (budget_index + repetition) % len(methods)
            schedule.extend({"budget_seconds": budget, "repetition": repetition, "method": method}
                            for method in methods[shift:] + methods[:shift])
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/run_selective_pilot.py", ROOT / "scripts/map_tygr_candidates.py",
        ROOT / "scripts/evaluate_selective_pilot.py", ROOT / "docs/architecture/pilot_revision_v6.md"]
    hashes = {}
    for source in sources:
        name = str(source.relative_to(ROOT)).replace("\\", "/")
        hashes[name] = file_hash(source)
        archived = output / "source_snapshot" / name
        archived.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, archived)
    plan = {"revision_spec": "docs/architecture/pilot_revision_v6.md", "unique_queries": 1,
        "expected_records": 54, "methods": methods, "budgets": budgets, "repetitions": repetitions,
        "platform": platform.platform(), "python": platform.python_version(), "query_hash": query.contract_hash,
        "type_input_validation": validation, "source_sha256": hashes, "schedule": schedule,
        "regime": "information_only", "cache_policy": "fresh_process_and_checkers; OS_cache_not_flushed",
        "excluded": "model, mapping, artifact projection and common symbolic/byte checker preparation",
        "included": "selection, selected operations, reanalysis, validation, recording and parent finalization"}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print("Information-value output: " + str(output), flush=True)
    runs = []
    for trial in schedule:
        record = run_isolated(query, trial["method"], trial["budget_seconds"], "information_only",
            output / ("repetition-" + str(trial["repetition"])), type_artifact=types)
        record["repetition"] = trial["repetition"]
        runs.append(record)
        (output / "runs.json").write_text(json.dumps(runs, indent=2), encoding="utf-8")
        if len(runs) % len(methods) == 0:
            print("Completed {}/54 records".format(len(runs)), flush=True)
    # Labels enter only now, after every worker has terminated.
    from scripts.evaluate_selective_pilot import evaluate
    gold = json.loads((probe / "mapping-review/gold.json").read_text(encoding="utf-8"))
    evaluations = []
    for repetition in range(repetitions):
        report = evaluate([r for r in runs if r["repetition"] == repetition], gold)
        evaluations.append(report)
        (output / ("evaluation-" + str(repetition) + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
    report = summarize(runs, evaluations, methods)
    (output / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for row in report["comparisons"]:
        charged = "unknown" if row["median_charged_seconds"] is None else "{:.4f}s".format(row["median_charged_seconds"])
        print("{} {:g}s: {}/{} resolved, {} unknown, {} wrong; median charged {}; {}".format(
            row["method"], row["budget_seconds"], row["resolved"], row["trials"], row["unknown"],
            row["wrong_decisions"], charged, row["action_sequences"]), flush=True)
    print("Finished. One-query information-only diagnostic: " + str(output), flush=True)


if __name__ == "__main__":
    main()
