#!/usr/bin/env python3
"""Compare the frozen native cascade with direct concrete execution at equal budgets."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import importlib.metadata
import json
import logging
import os
from pathlib import Path
from statistics import median
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import measure_native_pair_baseline as baseline

ARMS = ("fixed_cascade", "concrete_only")


def controller(output):
    legacy = baseline.controller(output)
    legacy.batch.iso.__file__ = str(Path(__file__).resolve())
    return legacy


def backend_worker(marker):
    output = baseline.within(marker.parent.parent, baseline.SCRATCH)
    baseline.require_pins(baseline.read(output / "plan.json")["pins"])
    legacy = controller(output)
    panel = legacy.batch.iso.load_panel()
    selector = panel.selector
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    import z3
    from src.selective_analysis.path_certificate import PathChecker, SCHEMA
    sys.path.insert(0, str(legacy.METHOD))
    from solver_policy import CachePreservingChecker

    active, result, attempt = {}, None, None
    buffered = []
    deadline = 0.0

    def emit(event, **fields):
        nonlocal result
        payload = {"event": event, "time": time.monotonic(), **fields}
        if active:
            payload["operation_nonce"] = active["nonce"]
        if event == "result":
            result = payload
        if attempt is not None:
            buffered.append(payload)
            payload = {"event": "attempt_event", "time": time.monotonic(),
                "operation_nonce": active["nonce"], "attempt": attempt, "payload": payload}
        print(json.dumps(payload), flush=True)

    selector.runner.emit = selector.base.runner.emit = emit

    def checker(query):
        return CachePreservingChecker(query, deadline)

    symbolic = selector.load_executor(selector.REFERENCE_RUNNER, "worker", '    route = "producer_unresolved"',
        dict(vars(selector.runner), BinaryChecker=checker, PathChecker=PathChecker, SCHEMA=SCHEMA, z3=z3),
        (("DiagnosticChecker(query, True, False).validate(", "PathChecker(query).validate("),))
    concrete = selector.load_executor(selector.NARROW / "run.py", "concrete_worker",
        "    checker = ConcreteFirstWrite(BinaryChecker(query))", dict(vars(selector.base)))
    emit("runtime_ready", pid=os.getpid())
    baseline.write(marker, {"pid": os.getpid()})
    intake = baseline.read(output / "intake.json")
    for line in sys.stdin.buffer:
        request = json.loads(line)
        active, result = request["identity"], None
        if active["strategy"] not in ARMS:
            raise ValueError("Unknown fixed control arm")
        deadline = request["deadline"]
        query = panel.Query.from_dict(intake[active["case"]]["query"])
        if query.contract_hash != active["query_hash"]:
            raise ValueError("Control query identity differs")
        direct = active["strategy"] == "concrete_only"
        attempt, buffered = ("concrete_enumeration" if direct else "frozen_symbolic"), []
        emit("operation_opened", deadline=deadline)
        if direct:
            concrete(active, deadline, query)
            switch = False
        else:
            symbolic(active, deadline, query)
            switch = result is None or result["status"] == "unknown"
        backend = attempt
        if switch and time.monotonic() < deadline:
            emit("discard_cleanup_started")
            gc.collect()
            emit("discard_cleanup_finished")
            attempt, result, buffered = "concrete_enumeration", None, []
            backend = attempt
            if time.monotonic() < deadline:
                concrete(active, deadline, query)
        emit("final_cleanup_started")
        gc.collect()
        emit("final_cleanup_finished")
        attempt = None
        emit("policy_choice", backend=backend, probe=None, selection=None, requested_switch=switch,
             direct_concrete=direct, scope="fixed_control_with_original_absolute_deadline")
        for payload in buffered:
            print(json.dumps(payload), flush=True)
        reply = {"kind": "backend", "nonce": active["nonce"], "query_hash": query.contract_hash,
                 "time": time.monotonic(), "result": result}
        emit("request_finished", reply=reply)
        legacy.batch.publish(Path(request["reply_path"]), reply)
        active = {}


def stage_details(row):
    nested = [e for e in row["events"] if e["event"] == "attempt_event"]
    starts = [e["attempt"] for e in nested if e["payload"]["event"] == "producer_started"]
    opened = [e["payload"]["time"] for e in nested if e["payload"]["event"] == "operation_opened"]
    concrete_finished = any(e["attempt"] == "concrete_enumeration"
        and e["payload"]["event"] == "producer_finished" for e in nested)
    fallback = "frozen_symbolic" in starts and "concrete_enumeration" in starts
    return {"last_started_backend": starts[-1] if starts else None,
        "fallback_started": fallback, "fallback_unfinished": fallback and not concrete_finished,
        "pre_operation_seconds": opened[0] - row["query_entered"] if len(opened) == 1 else None}


def prepare(prior, output, smoke=False):
    previous, previous_summary = baseline.read(prior / "plan.json"), baseline.read(prior / "summary.json")
    if (previous_summary["smoke_only"] or not previous_summary["validation_passed"]
            or previous_summary["query_records"] != 36 or not (prior / "independent-audit.json").is_file()):
        raise ValueError("A reviewed complete native baseline is required")
    previous_d_pins = {name: value for name, value in previous["pins"].items()
                      if not (os.name == "nt" and name.startswith("/root/"))}
    baseline.require_pins(previous_d_pins)
    plan, intake = baseline.prepare(baseline.runtime_path(previous["pairs"]), output, smoke)
    schedule = []
    for item in plan["schedule"]:
        order = ARMS if (item["repetition"] + item["group"]) % 2 == 0 else ARMS[::-1]
        schedule.extend({**item, "arm": arm} for arm in order)
    plan.update(schema="symbai.native_backend_comparison_plan.v1", schedule=schedule, arms=ARMS,
        prior_baseline=baseline.linux_path(prior),
        controls="Same frozen symbolic producer, exact concrete enumeration, checkers and cleanup in both arms. Only the cascade attempts the symbolic producer before a conditional fallback.",
        scope="Twelve known native functions, three repetitions per arm. This is operation capability and cost evaluation, not a learned or neural scheduler test.",
        cost_attribution="Report pre-operation waiting separately. Derive attempted backends from producer-start receipts; absent final choices do not mean a fallback never started.")
    for path in (Path(__file__), prior / "plan.json", prior / "summary.json", prior / "independent-audit.json"):
        plan["pins"][baseline.linux_path(path)] = baseline.digest(path)
    copy = output / "source_snapshot" / Path(__file__).name
    copy.write_bytes(Path(__file__).read_bytes())
    plan["pins"][baseline.linux_path(copy)] = baseline.digest(copy)
    baseline.write(output / "plan.json", plan)
    return plan, intake


def run(output, plan, intake):
    legacy = controller(output)
    panel = legacy.batch.iso.load_panel()
    batches = []
    for index, item in enumerate(plan["schedule"], 1):
        record = legacy.batch.run_batch(panel, index, item["arm"], item["repetition"], item["cases"], intake)
        record["group"] = item["group"]
        for row in record["rows"]:
            choices = [e for e in row["events"] if e["event"] == "policy_choice"]
            if choices:
                row["backend"] = choices[-1]["backend"]
        batches.append(record)
        baseline.write(output / "batches.json", batches)
        print("Batch {}/{} {}: {}/{} resolved; {:.3f}s".format(index, len(plan["schedule"]),
            item["arm"], sum(r["status"] == panel.PROVEN for r in record["rows"]),
            len(item["cases"]), record["elapsed_seconds"]), flush=True)
    rows = [r for b in batches for r in b["rows"]]
    audit_started = time.monotonic()
    concrete, symbolic = panel.selector.base.audit(
        [{**r, "strategy": r["backend"]} for r in rows
         if any(e["event"] == "policy_choice" for e in r["events"])], intake)
    errors = {"wrong_decisions": sum(r["status"] == "violation" for r in rows),
        "late_admissions": sum(r["admitted"] and r["result_received"] > r["deadline"] for r in rows),
        "unreaped_workers": sum(not p["worker_reaped"] for b in batches for p in b["processes"]),
        "batch_budget_failures": sum(not b["admitted"] for b in batches),
        "concrete_mismatches": sum(r["address_or_length_mismatches"] for r in concrete.values()),
        "symbolic_audit_failures": [c for c, r in symbolic.items()
            if r["status"] not in ("verified", "no_decisive_timed_result")]}
    baseline.require_pins(plan["pins"])
    pairs = {}
    for row in rows:
        pairs.setdefault((row["case"], row["repetition"]), {})[row["strategy"]] = row
    elapsed = {(b["repetition"], b["group"], b["arm"]): b["elapsed_seconds"] for b in batches}
    units = list(dict.fromkeys((s["repetition"], s["group"]) for s in plan["schedule"]))
    savings = [elapsed[r, g, ARMS[0]] - elapsed[r, g, ARMS[1]] for r, g in units]
    per_case = {}
    for arm in ARMS:
        selected = [r for r in rows if r["strategy"] == arm]
        costs = baseline.case_costs(selected, plan["neural_availability"])
        for case, value in costs.items():
            detail = [stage_details(r) for r in selected if r["case"] == case]
            value["finalized_concrete_choices"] = value.pop("fallback_trials")
            value["fallback_started_trials"] = sum(d["fallback_started"] for d in detail)
            value["fallback_unfinished_trials"] = sum(d["fallback_unfinished"] for d in detail)
            waits = [d["pre_operation_seconds"] for d in detail if d["pre_operation_seconds"] is not None]
            value["median_pre_operation_seconds"] = median(waits) if waits else None
            value["actual_last_started_backends"] = dict(Counter(d["last_started_backend"] for d in detail))
        per_case[arm] = costs
    summary = {"schema": "symbai.native_backend_comparison_summary.v1", "smoke_only": plan["smoke_only"],
        "unique_cases": len({r["case"] for r in rows}), "query_records": len(rows), "batches": len(batches),
        "counts": {arm: dict(Counter(r["status"] for r in rows if r["strategy"] == arm)) for arm in ARMS},
        "direct_concrete_gains": [key for key, p in pairs.items()
            if p[ARMS[1]]["status"] == panel.PROVEN and p[ARMS[0]]["status"] != panel.PROVEN],
        "direct_concrete_losses": [key for key, p in pairs.items()
            if p[ARMS[0]]["status"] == panel.PROVEN and p[ARMS[1]]["status"] != panel.PROVEN],
        "cascade_minus_concrete_paired_batch_seconds": savings,
        "median_paired_batch_seconds": median(savings), "per_case": per_case, "errors": errors,
        "validation_passed": not any(errors.values()), "offline_reaudit_seconds": time.monotonic() - audit_started,
        "neural_scheduling_benefit_measured": False, "held_out_evaluation": False, "output": str(output)}
    baseline.write(output / "summary.json", summary)
    return summary


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        backend_worker(Path(sys.argv[2]).resolve())
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="One case per arm for host compatibility only")
    args = parser.parse_args()
    if not args.prepare_only and not args.smoke and not sys.platform.startswith("linux"):
        parser.error("Official matched comparison must run in WSL angr-env")
    prior = baseline.within(args.baseline, baseline.SCRATCH)
    output = baseline.SCRATCH / ("route-b-native-backend-controls-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    started = time.monotonic()
    plan, intake = prepare(prior, output, args.smoke)
    setup_seconds = time.monotonic() - started
    print("Native backend controls output: " + str(output), flush=True)
    if args.prepare_only:
        print(json.dumps({"prepare_only": True, "planned_records": sum(len(s["cases"]) for s in plan["schedule"]),
            "batches": len(plan["schedule"]), "output": str(output)}, indent=2))
        return
    summary = run(output, plan, intake)
    summary.update(setup_seconds=setup_seconds, total_parent_seconds=time.monotonic() - started,
        runtime={"python": sys.version, "angr": importlib.metadata.version("angr"), "platform": sys.platform})
    baseline.write(output / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "per_case"}, indent=2), flush=True)
    if not summary["validation_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
