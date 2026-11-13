#!/usr/bin/env python3
"""Probe evidence and applicability on the unchanged twelve developer mechanisms."""

import argparse
from copy import deepcopy
from dataclasses import asdict
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


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def worker(request_path, result_path, event_path):
    from src.selective_analysis.contracts import Query
    from src.selective_analysis.operation_effects import PROBES, initial_features, structural_first_hint, probe_operation, missing_probe
    request = read(request_path)
    fields = {"schema", "query", "query_hash", "repetition", "probe_order", "budget_seconds", "started_at"}
    if (set(request) != fields or request["schema"] != "symbai.operation_effect_request.v1"
            or type(request["repetition"]) is not int or request["repetition"] not in range(3)
            or len(request["probe_order"]) != len(PROBES) or set(request["probe_order"]) != set(PROBES)
            or type(request["budget_seconds"]) not in (int, float) or not math.isfinite(request["budget_seconds"])
            or request["budget_seconds"] <= 0
            or type(request["started_at"]) not in (int, float) or not math.isfinite(request["started_at"])):
        raise ValueError("Invalid label-free operation-effect request")
    query = Query.from_dict(request["query"])
    if query.contract_hash != request["query_hash"]:
        raise ValueError("Operation-effect query identity differs")
    started = request["started_at"]
    deadline = started + request["budget_seconds"]
    with event_path.open("w", encoding="utf-8") as stream:
        def emit(event, **payload):
            stream.write(json.dumps({"event": event, "query_hash": query.contract_hash,
                "repetition": request["repetition"], "elapsed_seconds": time.monotonic() - started, **payload}) + "\n")
            stream.flush()
        emit("worker_started", probe_order=request["probe_order"])
        feature_started, feature_error = time.monotonic(), None
        try:
            if feature_started >= deadline:
                raise TimeoutError("Feature deadline reached")
            features = initial_features(query)
        except Exception as exc:
            features = {"available": False}
            feature_error = type(exc).__name__ + ": " + str(exc)
        feature_seconds = time.monotonic() - feature_started
        hint = structural_first_hint(features)
        emit("features_recorded", initial_features=features, feature_acquisition_seconds=feature_seconds,
             feature_error=feature_error, structural_first_operation=hint,
             hint_role="predeclared_first_choice_not_measured_policy")
        rows = []
        for probe in request["probe_order"]:
            emit("probe_started", probe_id=probe)
            if time.monotonic() >= deadline:
                row = missing_probe(query, probe, request["repetition"], features, "worker_budget_exhausted")
            else:
                row = probe_operation(query, probe, request["repetition"], features, deadline)
            rows.append(row)
            emit("probe_finished", record=row)
        write(result_path, {"schema": "symbai.operation_effect_worker.v1", "query_hash": query.contract_hash,
            "repetition": request["repetition"], "probes": rows, "initial_features": features,
            "feature_acquisition_seconds": feature_seconds, "feature_error": feature_error,
            "structural_first_operation": hint, "worker_elapsed_seconds": time.monotonic() - started})


def finish_records(query, repetition, probe_order, worker_result, events, process, elapsed, budget):
    """Recover a complete denominator; late evidence never becomes an on-time decision."""
    from src.selective_analysis.contracts import Checkpoint
    from src.selective_analysis.operation_effects import missing_probe
    def valid(row):
        return (isinstance(row, dict) and row.get("schema") == "symbai.operation_effect_trial.v1"
            and row.get("query_id") == query.query_id and row.get("query_hash") == query.contract_hash
            and row.get("binary_sha256") == query.binary_sha256 and row.get("repetition") == repetition
            and row.get("checkpoint_id") == Checkpoint(query.contract_hash).checkpoint_id
            and row.get("probe_id") in probe_order)
    features = {"available": False}
    candidates, starts = {}, {}
    for event in events:
        if event.get("query_hash") != query.contract_hash or event.get("repetition") != repetition:
            continue
        if event.get("event") == "features_recorded":
            features = event["initial_features"]
        if event.get("event") == "probe_started" and event.get("probe_id") in probe_order:
            starts[event["probe_id"]] = event["elapsed_seconds"]
        if event.get("event") == "probe_finished" and valid(event.get("record")):
            candidates[event["record"]["probe_id"]] = event["record"]
    if (not process["timed_out"] and process["returncode"] == 0 and isinstance(worker_result, dict)
            and worker_result.get("schema") == "symbai.operation_effect_worker.v1"
            and worker_result.get("query_hash") == query.contract_hash
            and worker_result.get("repetition") == repetition):
        records = worker_result.get("probes", [])
        if len(records) == len(probe_order) and all(valid(r) for r in records) and len({r["probe_id"] for r in records}) == len(probe_order):
            candidates = {r["probe_id"]: r for r in records}
    rows = []
    for probe in probe_order:
        row = deepcopy(candidates.get(probe))
        if row is None:
            observed = max(0.0, elapsed - starts[probe]) if probe in starts else 0.0
            row = missing_probe(query, probe, repetition, features, "worker_failure_or_missing_probe",
                "not_completed" if probe in starts else "not_started", observed)
        if process["timed_out"] or elapsed > budget:
            if row["result"]["status"] != "unknown":
                row["late_candidate_result"] = row["result"]
                row["result"] = {"status": "unknown", "reason": "parent_worker_deadline_exceeded"}
            row["effects"]["query_decision_progress"] = False
            row["availability"] = "late"
        rows.append(row)
    return rows


def run_isolated(query, repetition, probe_order, output, budget=20.0):
    from src.selective_analysis.processes import run_bounded
    from scripts.run_frame_batch import read_events
    folder = output / "query-workers" / ("repetition-" + str(repetition)) / query.query_id
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request = {"schema": "symbai.operation_effect_request.v1", "query": asdict(query),
        "query_hash": query.contract_hash, "repetition": repetition, "probe_order": list(probe_order),
        "budget_seconds": budget, "started_at": started}
    request_path, result_path, events_path = [folder / name for name in ("request.json", "worker-result.json", "events.jsonl")]
    write(request_path, request)
    process = asdict(run_bounded([sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
        str(request_path), str(result_path), str(events_path)], folder / "worker.log", budget - (time.monotonic() - started)))
    result = None
    if result_path.is_file():
        try:
            result = read(result_path)
        except (ValueError, UnicodeError):
            pass
    events = read_events(events_path)
    elapsed = time.monotonic() - started
    rows = finish_records(query, repetition, probe_order, result, events, process, elapsed, budget)
    write(folder / "provisional-records.json", rows)
    elapsed = time.monotonic() - started
    rows = finish_records(query, repetition, probe_order, result, events, process, elapsed, budget)
    receipt = {"query_id": query.query_id, "query_hash": query.contract_hash, "repetition": repetition,
        "process": process, "budget_seconds": budget, "parent_worker_seconds": elapsed,
        "record_count": len(rows), "feature_acquisition_seconds": result.get("feature_acquisition_seconds") if isinstance(result, dict) else None,
        "structural_first_operation": result.get("structural_first_operation") if isinstance(result, dict) else None,
        "timing_role": "all_five_alternatives_worker_cost_not_a_deployed_policy"}
    write(folder / "receipt.json", receipt)
    write(folder / "records.json", rows)
    return rows, receipt


def compiled_panel():
    """Only retained proof-backed integration inputs, after all primary runtime work."""
    from src.selective_analysis.contracts import Query
    from src.selective_analysis.compiled_fact_audit import audit_compiled_facts
    wsl = ROOT.parent / ".scratch/wsl"
    probes = sorted(wsl.glob("inference-*/mapping-review/queries.json"))
    mappings = sorted((ROOT.parent / ".scratch/selective_analysis").glob("operand-mapping-v7-*/operand-types.json"))
    compiled = sorted(wsl.glob("compiled-queries-v8-*"))
    entries = []
    for name in ("compiled-direct-index", "offset_index", "masked_index"):
        try:
            if name == "compiled-direct-index":
                folder = probes[-1].parent.parent
                raw = read(folder / "mapping-review/queries.json")["queries"][0]
                binary, bundle = folder / "probe.elf", mappings[-1]
            else:
                folder = compiled[-1] / name
                raw = read(folder / "queries.json")["queries"][0]
                binary, bundle = folder / "query.elf", folder / "operand-types.json"
            query = Query.from_dict(dict(raw, binary=str(binary)))
            entries.append(audit_compiled_facts(query, bundle))
        except Exception as exc:
            entries.append({"query_id": name, "derived_status": "unknown",
                "reason": type(exc).__name__ + ": " + str(exc)})
    return {"panel": "posthoc_existing_compiled_proof_information", "primary_denominator_includes_panel": False,
        "prior_mapping_proof_cost_is_not_free": True, "no_new_inference": True, "records": entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=3, type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    from src.selective_analysis.workspace import configure_workspace
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    if args.worker:
        worker(*args.worker)
        return 0
    from benchmarks.selective_analysis.mechanisms import make_mechanisms
    from src.selective_analysis.contracts import Query, file_hash
    from src.selective_analysis.operation_effects import PROBES
    output = scratch / ("operation-effects-v11-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Operation effects output: " + str(output), flush=True)
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/run_frame_batch.py", ROOT / "benchmarks/selective_analysis/mechanisms.py",
        ROOT / "docs/architecture/pilot_revision_v11.md"]
    hashes = {}
    for source in sources:
        name = source.relative_to(ROOT).as_posix()
        hashes[name] = file_hash(source)
        target = output / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    manifest = make_mechanisms(output / "inputs")
    queries = [Query.from_dict(q, manifest.parent) for q in read(manifest)["queries"]]
    schedule = []
    for repetition in range(3):
        for index, query in enumerate(queries):
            shift = (repetition + index) % len(PROBES)
            schedule.append({"query_id": query.query_id, "repetition": repetition,
                             "probe_order": list(PROBES[shift:] + PROBES[:shift])})
    write(output / "run-plan.json", {"revision_spec": "docs/architecture/pilot_revision_v11.md",
        "source_sha256": hashes, "query_contracts": [asdict(q) for q in queries], "schedule": schedule,
        "primary_panel": "primary_existing_12_mechanisms", "unique_queries": 12,
        "planned_workers": 36, "planned_probe_records": 180, "worker_cap_seconds": 20,
        "cost_regime": "operation_local_cost_plus_separately_retained_shared_worker_charge",
        "policy_speedup_measured": False, "neural_information_used": False})
    rows, receipts, by_id = [], [], {q.query_id: q for q in queries}
    for item in schedule:
        records, receipt = run_isolated(by_id[item["query_id"]], item["repetition"], item["probe_order"], output)
        rows.extend(records)
        receipts.append(receipt)
        write(output / "records.json", rows)
        write(output / "worker-receipts.json", receipts)
        print("Completed {}/180 probes".format(len(rows)), flush=True)
    # Expected outcomes are read only after every runtime worker is stopped.
    gold = read(manifest.parent / "gold.json")
    gold["panel"] = "primary_existing_12_mechanisms"
    write(output / "offline-gold.json", gold)
    from src.selective_analysis.operation_effects_evaluation import evaluate_effects
    report = evaluate_effects(rows, gold)
    write(output / "evaluation.json", report)
    panel = compiled_panel()
    write(output / "compiled-proof-panel.json", panel)
    changed = [name for name, digest in hashes.items() if file_hash(ROOT / name) != digest]
    summary = {"schema": "symbai.operation_effect_summary.v1", "unique_queries": 12,
        "probe_records": len(rows), "worker_records": len(receipts), "evaluation": "evaluation.json",
        "compiled_proof_panel": "compiled-proof-panel.json", "source_integrity_unchanged": not changed,
        "correctness_review_required": report["correctness_review"]["required"],
        "changed_sources": changed, "neural_selection_measured": False, "policy_speedup_measured": False,
        "interpretation": "Operation evidence/applicability gate; graphs and prepared states are not validated decisions. Inspect correctness and work/cost comparisons before any selector experiment."}
    write(output / "summary.json", summary)
    for probe, data in report["probes"].items():
        counts = data["trial_counts"]
        measured = data["median_probe_elapsed_seconds"]
        print("{}: {}/{} resolved; {} wrong; {} unknown; median probe {}s".format(
            probe, counts["resolved"], counts["total"], counts["wrong"], counts["unknown"],
            "unobserved" if measured is None else "{:.6f}".format(measured)), flush=True)
    print("Bounded/full shared same-work pairs: {}".format(
        report["comparisons"]["bounded_vs_expanded"]["same_work_pairs"]), flush=True)
    print("Compiled proof decisions already available after mapping: {}/3".format(
        sum(row.get("query_decision_available_after_mapping", False) for row in panel["records"])), flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    print("Finished. Primary 12-case denominator and separate proof panel retained: " + str(output), flush=True)
    return 1 if changed or report["correctness_review"]["required"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
