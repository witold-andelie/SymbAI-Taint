#!/usr/bin/env python3
"""Run fixed-query mechanisms with hard process limits; labels are not a runtime input."""

import argparse
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from src.selective_analysis.workspace import configure_workspace
from src.selective_analysis.processes import run_bounded


def worker(request_path, result_path, event_path):
    from src.selective_analysis.contracts import Query
    from src.selective_analysis.controls import CONTROL_OPERATIONS
    from src.selective_analysis.information_value import METHODS as INFORMATION_METHODS
    request = json.loads(request_path.read_text(encoding="utf-8"))
    query = Query.from_dict(request["query"])
    with event_path.open("w", encoding="utf-8") as events:
        def emit(row):
            events.write(json.dumps(row) + "\n")
            events.flush()
        if request["variant"] in INFORMATION_METHODS:
            from src.selective_analysis.information_value import run_information_query
            if request["regime"] != "information_only" or request.get("online_config") or request.get("allow_synthetic"):
                raise ValueError("Information diagnostic requires precomputed genuine types and information-only accounting")
            result = run_information_query(query, request["variant"], request["budget_seconds"],
                                           request.get("type_artifact"), request["started_at"], emit)
        elif request["variant"] in ("frame_bounds_only", "frame_bounds_then_expanded"):
            from src.selective_analysis.frame_controls import run_frame_control
            if request.get("type_artifact") or request.get("online_config") or request.get("allow_synthetic"):
                raise ValueError("Frame controls cannot consume neural type inputs")
            result = run_frame_control(query, request["variant"], request["budget_seconds"],
                                       request["regime"], request["started_at"], emit)
        elif request["variant"] in CONTROL_OPERATIONS:
            from src.selective_analysis.controls import run_control
            if request.get("type_artifact") or request.get("online_config") or request.get("allow_synthetic"):
                raise ValueError("Diagnostic controls cannot consume neural type inputs")
            result = run_control(query, request["variant"], request["budget_seconds"],
                                 request["regime"], request["started_at"], emit)
        else:
            from src.selective_analysis.runner import run_query
            result = run_query(query, request["variant"], request["budget_seconds"],
                           request["regime"], request.get("type_artifact"),
                           request.get("allow_synthetic", False), request["started_at"], emit,
                           online_config=request.get("online_config"),
                           acquisition_dir=result_path.parent / "online-types",
                           within_worker=os.name == "posix")
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")


def run_isolated(query, variant, budget, regime, output, type_artifact=None, allow_synthetic=False,
                 preparation_limit=30.0, online_config=None):
    from src.selective_analysis.contracts import fingerprint
    run_id = fingerprint({"query": query.contract_hash, "variant": variant,
                          "budget": budget, "regime": regime, "types": str(type_artifact),
                          "online_config": str(online_config)})[:20]
    run_dir = output / run_id
    # Existing records are not silently mixed with a new execution.
    run_dir.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request = {"query": asdict(query), "variant": variant, "budget_seconds": budget,
               "regime": regime, "started_at": started,
               "type_artifact": str(type_artifact.resolve()) if type_artifact else None,
               "online_config": str(Path(online_config).resolve()) if online_config else None,
               "allow_synthetic": allow_synthetic}
    request_path, result_path, event_path = (run_dir / name for name in ("request.json", "result.json", "events.jsonl"))
    request_path.write_text(json.dumps(request), encoding="utf-8")
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker",
               str(request_path), str(result_path), str(event_path)]
    limit = budget if regime == "end_to_end" else budget + preparation_limit
    failure = None
    child = run_bounded(command, run_dir / "worker.log", limit - (time.monotonic() - started))
    if child.timed_out:
        failure = "hard_process_timeout"
    elif child.returncode:
        failure = f"worker_exit_{child.returncode}"
    if failure or not result_path.exists():
        failure = failure or "missing_worker_result"
        events = []
        if event_path.exists():
            for line in event_path.read_text(encoding="utf-8").splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    break
        result = {"schema": "symbai.run.v1", "query_id": query.query_id,
                  "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
                  "variant": variant, "regime": regime, "budget_seconds": budget,
                  "availability": "execution_failed", "type_source": "unknown",
                  "result": {"status": "unknown", "reason": failure},
                  "elapsed_wall_seconds": time.monotonic() - started,
                  "charged_seconds": time.monotonic() - started if regime == "end_to_end" else None,
                  "ledger": events, "accounting_unit": "single_query_cold_run"}
        result["last_event"] = events[-1]["event"] if events else None
        result["online_acquisition_requested"] = bool(online_config and variant in ("C", "D"))
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    process_elapsed = time.monotonic() - started
    result["process_wall_seconds"] = process_elapsed
    tail_cost = max(0.0, process_elapsed - result["elapsed_wall_seconds"])
    result["elapsed_wall_seconds"] = process_elapsed
    if regime == "end_to_end":
        # Include cleanup and record recovery even when the worker was killed.
        result["charged_seconds"] = process_elapsed
    if not failure:
        if regime == "information_only":
            result["charged_seconds"] += tail_cost
        if result["charged_seconds"] > budget and result["result"]["status"] != "unknown":
            result["late_candidate_result"] = result["result"]
            result["result"] = {"status": "unknown", "reason": "finalization_exceeded_budget"}
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main():
    scratch = configure_workspace()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--make-mechanisms", action="store_true")
    methods = parser.add_mutually_exclusive_group()
    methods.add_argument("--variants", nargs="+", choices=list("ABCD"))
    methods.add_argument("--controls", nargs="+", choices=["expanded_only", "bounds_only", "bounds_then_expanded",
                        "frame_bounds_only", "frame_bounds_then_expanded"])
    parser.add_argument("--budgets", nargs="+", type=float, default=[1.0])
    parser.add_argument("--regime", choices=["information_only", "end_to_end"], default="information_only")
    type_inputs = parser.add_mutually_exclusive_group()
    type_inputs.add_argument("--types", type=Path)
    type_inputs.add_argument("--online-tygr", type=Path)
    parser.add_argument("--allow-synthetic-types", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", nargs=3, type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    if args.worker:
        worker(*args.worker)
        return
    if any(b <= 0 for b in args.budgets):
        parser.error("Budgets must be positive")
    if args.allow_synthetic_types and args.regime != "information_only":
        parser.error("Synthetic type fixtures cannot establish end-to-end neural results")
    if args.online_tygr and args.regime != "end_to_end":
        parser.error("Use --online-tygr only with --regime end_to_end")
    if args.controls and (args.regime != "end_to_end" or args.types or args.online_tygr or args.allow_synthetic_types):
        parser.error("Controls require end-to-end accounting without neural inputs")
    variants = args.controls or args.variants or list("ABCD")
    if args.make_mechanisms:
        from benchmarks.selective_analysis.mechanisms import make_mechanisms
        args.manifest = make_mechanisms(scratch / "mechanisms")
    if args.manifest is None:
        parser.error("Supply --manifest or --make-mechanisms")
    from src.selective_analysis.contracts import Query
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("schema") != "symbai.queries.v1":
        parser.error("Unsupported query manifest")
    queries = [Query.from_dict(q, args.manifest.parent) for q in manifest["queries"]]
    if len({q.query_id for q in queries}) != len(queries):
        parser.error("Query IDs must be unique")
    output = args.output or scratch / ("run-" + time.strftime("%Y%m%d-%H%M%S"))
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for budget in args.budgets:
        for query in queries:
            for variant in variants:
                result = run_isolated(query, variant, budget, args.regime, output,
                                      args.types, args.allow_synthetic_types, online_config=args.online_tygr)
                results.append(result)
                (output / "runs.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
                print(f"{query.query_id} {variant} {budget:g}s: {result['result']['status']} ({result['availability']})", flush=True)
    print(f"Runtime records: {output / 'runs.json'}")


if __name__ == "__main__":
    main()
