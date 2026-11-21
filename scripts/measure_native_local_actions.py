#!/usr/bin/env python3
"""Measure local action value after fresh worker readiness; retain all startup costs."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
from statistics import median
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import compare_native_backends as controls

base = controls.baseline
ACTION_SECONDS = 3.0
STARTUP_SECONDS = 20.0


def prepare(prior, output, smoke=False):
    old_plan, old_summary = base.read(prior / "plan.json"), base.read(prior / "summary.json")
    if (old_summary["smoke_only"] or not old_summary["validation_passed"]
            or old_summary["query_records"] != 72 or not (prior / "independent-audit.json").is_file()):
        raise ValueError("A complete independently reviewed global control comparison is required")
    base.require_pins({name: checksum for name, checksum in old_plan["pins"].items()
        if not (os.name == "nt" and name.startswith("/root/"))})
    plan, intake = controls.prepare(base.runtime_path(old_plan["prior_baseline"]), output, smoke)
    cases = ["miniz_two_byte_adler_n256"] if smoke else plan["cases"]
    schedule = []
    for repetition in range(1 if smoke else 3):
        ordered = cases if repetition == 0 else cases[::-1] if repetition == 1 else cases[4:] + cases[:4]
        for case in ordered:
            order = controls.ARMS if (cases.index(case) + repetition) % 2 == 0 else controls.ARMS[::-1]
            schedule.extend({"case": case, "repetition": repetition, "arm": arm} for arm in order)
    for name in ("arm", "batch_seconds", "cleanup_reserve_seconds"):
        plan.pop(name, None)
    plan.update(schema="symbai.native_local_actions_plan.v1", schedule=schedule,
        action_seconds=ACTION_SECONDS, startup_limit_seconds=STARTUP_SECONDS,
        prior_global_controls=base.linux_path(prior),
        scope="Same twelve known native queries, two fixed strategies, three repetitions. One fresh worker per action prevents preceding query timeouts from consuming its allowance.",
        clock_semantics="Wait for the worker readiness marker before opening a fresh absolute 3 s deadline. Charge query initialization, transport, analysis, validation and worker-side cleanup inside that allowance. Record startup and parent termination/reaping separately and retain total diagnostic wall time.",
        interpretation="Local capability/information diagnostic only. Startup is not free deployment work; no global 18 s batch comparison, end-to-end speedup, neural selection or held-out generalization is evaluated.")
    for path in (Path(__file__), prior / "plan.json", prior / "summary.json", prior / "independent-audit.json"):
        plan["pins"][base.linux_path(path)] = base.digest(path)
    snapshot = output / "source_snapshot" / Path(__file__).name
    snapshot.write_bytes(Path(__file__).read_bytes())
    plan["pins"][base.linux_path(snapshot)] = base.digest(snapshot)
    base.write(output / "plan.json", plan)
    return plan, intake


def execute_action(transport, output, index, item, query):
    """Start the action clock after readiness, with no shared batch deadline."""
    folder = output / ("action-{:03d}".format(index))
    folder.mkdir()
    identity = {"nonce": "local-action-{:03d}".format(index), "case": item["case"],
        "repetition": item["repetition"], "strategy": item["arm"], "startup": "fresh_ready_worker",
        "budget": ACTION_SECONDS, "query_hash": query.contract_hash}
    child = None
    response = received = opened = ready = deadline = None
    error = None
    late_files = []
    started = time.monotonic()
    signal = folder / "backend.reply.json"
    try:
        child = transport.iso.launch("backend", "worker", folder)
        ready = transport.wait_ready(child, started + STARTUP_SECONDS)
        if ready is None:
            raise TimeoutError("Fresh worker did not reach readiness within the startup limit")
        opened = time.monotonic()
        deadline = opened + ACTION_SECONDS
        transport.send(child, {"identity": identity, "backend": None, "probe": None,
            "deadline": deadline, "reply_path": str(signal)})
        response, received = transport.receive(child, signal, deadline)
        matching = transport.matching(response, received, deadline, identity, "backend")
        result = response.get("result") if response is not None else None
        identity_ok = isinstance(result, dict) and all(result.get(k) == v for k, v in identity.items())
        admitted = bool(matching and identity_ok)
        if matching and result is not None and not identity_ok:
            raise ValueError("Local action result identity differs")
    except (OSError, RuntimeError, ValueError, TimeoutError) as failure:
        error = {"type": type(failure).__name__, "message": str(failure)}
        result, admitted = None, False
    finally:
        observed = time.monotonic()
        process = None
        if child is not None:
            killed = transport.iso.finish(child)
            process = {"pid": child[0].pid, "killed": killed,
                "worker_reaped": child[0].poll() is not None, "return_code": child[0].returncode,
                "log": str(child[3])}
        reaped = time.monotonic()
        # Read pending transport files only after the producer has been reaped.
        for path in (signal, signal.with_suffix(".tmp")):
            if path.exists():
                raw = path.read_bytes()
                late_files.append({"name": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
                                   "text": raw.decode("utf-8", errors="replace")})
                path.unlink()
    events = transport.iso.log_events(child[3]) if child is not None else []
    choices = [e for e in events if e.get("event") == "policy_choice"]
    row = {**identity, "action_index": index, "attempt_started": started, "ready_observed": ready,
        "query_entered": opened, "deadline": deadline, "result_received": received,
        "action_observed": observed, "worker_reaped_at": reaped,
        "startup_seconds": (opened if opened is not None else observed) - started,
        "action_wall_seconds": observed - opened if opened is not None else None,
        "recovery_seconds": reaped - observed, "diagnostic_parent_seconds": reaped - started,
        "admitted": admitted, "status": result["status"] if admitted else "unknown",
        "route": result["route"] if admitted else "startup_failure" if opened is None else "action_deadline",
        "reply": response, "backend": choices[-1]["backend"] if choices else None,
        "failure": error, "process": process, "unadmitted_transport_files": late_files, "events": events}
    validate_clock(row)
    return row


def validate_clock(row):
    if row["query_entered"] is not None:
        if (row["ready_observed"] is None or row["query_entered"] < row["ready_observed"]
                or abs(row["deadline"] - row["query_entered"] - ACTION_SECONDS) > 1e-8):
            raise ValueError("Readiness must precede the full local action allowance")
    charged = row["startup_seconds"] + (row["action_wall_seconds"] or 0.0) + row["recovery_seconds"]
    if abs(charged - row["diagnostic_parent_seconds"]) > 1e-8:
        raise ValueError("Startup, action and recovery do not cover the recorded parent interval")
    if row["admitted"] and not (row["reply"]["time"] <= row["result_received"] <= row["deadline"]):
        raise ValueError("Local reply was admitted after its deadline")


def summarize(rows):
    pairs = {}
    for row in rows:
        pairs.setdefault((row["case"], row["repetition"]), {})[row["strategy"]] = row
    if any(set(pair) != set(controls.ARMS) for pair in pairs.values()):
        raise ValueError("Incomplete local action pairs")
    per_case, matrix = {}, []
    for (case, repetition), pair in pairs.items():
        matrix.append({"case": case, "repetition": repetition, "actions": {arm: {
            k: pair[arm][k] for k in ("status", "admitted", "action_wall_seconds", "startup_seconds",
                                     "recovery_seconds", "diagnostic_parent_seconds")} for arm in controls.ARMS}})
    for case in dict.fromkeys(r["case"] for r in rows):
        per_case[case] = {}
        for arm in controls.ARMS:
            selected = [r for r in rows if r["case"] == case and r["strategy"] == arm]
            measured = [r["action_wall_seconds"] for r in selected if r["action_wall_seconds"] is not None]
            per_case[case][arm] = {"trials": len(selected),
                "resolved": sum(r["status"] == "excluded_within_scope" for r in selected),
                "unknown": sum(r["status"] == "unknown" for r in selected),
                "median_action_wall_seconds": median(measured) if measured else None,
                "median_startup_seconds": median(r["startup_seconds"] for r in selected),
                "median_recovery_seconds": median(r["recovery_seconds"] for r in selected)}
    both = [pair for pair in pairs.values()
            if all(r["status"] == "excluded_within_scope" for r in pair.values())]
    return {"counts": {arm: dict(Counter(r["status"] for r in rows if r["strategy"] == arm))
                       for arm in controls.ARMS}, "per_case": per_case,
        "direct_concrete_gains": [key for key, p in pairs.items()
            if p["concrete_only"]["status"] == "excluded_within_scope" and p["fixed_cascade"]["status"] != "excluded_within_scope"],
        "direct_concrete_losses": [key for key, p in pairs.items()
            if p["fixed_cascade"]["status"] == "excluded_within_scope" and p["concrete_only"]["status"] != "excluded_within_scope"],
        "both_resolved_pairs": len(both), "both_resolved_cascade_minus_concrete_seconds": [
            p["fixed_cascade"]["action_wall_seconds"] - p["concrete_only"]["action_wall_seconds"] for p in both],
        "total_startup_seconds": sum(r["startup_seconds"] for r in rows),
        "total_parent_recovery_seconds": sum(r["recovery_seconds"] for r in rows),
        "total_action_parent_seconds": sum(r["diagnostic_parent_seconds"] for r in rows)}, matrix


def run(output, plan, intake):
    legacy = controls.controller(output)
    legacy.batch.iso.__file__ = str(Path(__file__).resolve())
    panel = legacy.batch.iso.load_panel()
    rows = []
    for index, item in enumerate(plan["schedule"], 1):
        query = panel.Query.from_dict(intake[item["case"]]["query"])
        row = execute_action(legacy.batch, output, index, item, query)
        rows.append(row)
        base.write(output / "actions.json", rows)
        print("{}/{} {} {}: {}; action {}; startup {:.3f}s".format(index, len(plan["schedule"]),
            item["case"], item["arm"], row["status"],
            "{:.3f}s".format(row["action_wall_seconds"]) if row["action_wall_seconds"] is not None else "not started",
            row["startup_seconds"]), flush=True)
    audit_started = time.monotonic()
    concrete, symbolic = panel.selector.base.audit(
        [{**r, "strategy": r["backend"]} for r in rows
         if any(e["event"] == "policy_choice" for e in r["events"])], intake)
    errors = {"infrastructure_failures": sum(r["failure"] is not None for r in rows),
        "wrong_decisions": sum(r["status"] == "violation" for r in rows),
        "late_admissions": sum(r["admitted"] and r["result_received"] > r["deadline"] for r in rows),
        "unreaped_workers": sum(r["process"] is not None and not r["process"]["worker_reaped"] for r in rows),
        "concrete_mismatches": sum(r["address_or_length_mismatches"] for r in concrete.values()),
        "symbolic_audit_failures": [c for c, r in symbolic.items()
            if r["status"] not in ("verified", "no_decisive_timed_result")]}
    base.require_pins(plan["pins"])
    values, matrix = summarize(rows)
    base.write(output / "matrix.json", matrix)
    summary = {"schema": "symbai.native_local_actions_summary.v1", "smoke_only": plan["smoke_only"],
        "unique_cases": len({r["case"] for r in rows}), "action_records": len(rows), **values,
        "errors": errors, "validation_passed": not any(errors.values()),
        "offline_reaudit_seconds": time.monotonic() - audit_started, "local_diagnostic_only": True,
        "end_to_end_savings_measured": False, "neural_scheduling_benefit_measured": False,
        "held_out_evaluation": False, "output": str(output)}
    base.write(output / "summary.json", summary)
    return summary


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        controls.backend_worker(Path(sys.argv[2]).resolve())
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="One native query per arm for host compatibility only")
    args = parser.parse_args()
    if not args.prepare_only and not args.smoke and not sys.platform.startswith("linux"):
        parser.error("Formal local-action collection must run in WSL angr-env")
    prior = base.within(args.controls, base.SCRATCH)
    output = base.SCRATCH / ("route-b-native-local-actions-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    started = time.monotonic()
    plan, intake = prepare(prior, output, args.smoke)
    setup_seconds = time.monotonic() - started
    print("Native local actions output: " + str(output), flush=True)
    if args.prepare_only:
        print(json.dumps({"prepare_only": True, "planned_actions": len(plan["schedule"]),
            "action_seconds_after_ready": ACTION_SECONDS, "output": str(output)}, indent=2))
        return
    summary = run(output, plan, intake)
    summary.update(setup_seconds=setup_seconds, total_parent_seconds=time.monotonic() - started,
        runtime={"python": sys.version, "angr": importlib.metadata.version("angr"), "platform": sys.platform})
    base.write(output / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in
        ("per_case", "both_resolved_cascade_minus_concrete_seconds")}, indent=2), flush=True)
    if not summary["validation_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
