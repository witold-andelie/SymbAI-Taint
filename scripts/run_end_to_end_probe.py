#!/usr/bin/env python3
"""Run one reviewed query with fresh, charged TYGR acquisition inside every C/D budget."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"


def check_group_cleanup(output):
    """Live WSL infrastructure check, outside the measured query budgets."""
    from src.selective_analysis.processes import run_bounded
    started = output / "cleanup-child-started"
    survived = output / "cleanup-child-survived"
    child = "import time;from pathlib import Path;time.sleep(1.2);Path(" + repr(str(survived)) + ").touch()"
    parent = ("import subprocess,sys,time;from pathlib import Path;"
              "subprocess.Popen([sys.executable,'-B','-c'," + repr(child) + "]);"
              "Path(" + repr(str(started)) + ").touch();time.sleep(30)")
    result = run_bounded([sys.executable, "-B", "-c", parent], output / "process-cleanup.log", 0.7)
    time.sleep(1.3)
    passed = result.timed_out and started.exists() and not survived.exists()
    (output / "process-cleanup.json").write_text(json.dumps(
        {"passed": passed, "fixture_started": started.exists(), "descendant_survived": survived.exists(),
         "scope": "infrastructure_check_outside_query_budgets"}, indent=2), encoding="utf-8")
    if not passed:
        raise RuntimeError("Process-group cleanup check failed; inspect the retained infrastructure logs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--budgets", nargs="+", type=float, default=[3, 10, 20])
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run in the existing angr-env inside WSL from the D-drive project")
    if any(budget <= 0 for budget in args.budgets):
        parser.error("Budgets must be positive")
    from src.selective_analysis.workspace import configure_workspace
    from src.selective_analysis.contracts import Query, file_hash
    configure_workspace()
    scratch = ROOT.parent / ".scratch/wsl"
    if args.probe_dir is None:
        reviewed = sorted(scratch.glob("inference-*/mapping-review/reviewed_mapping.json"))
        if not reviewed:
            parser.error("No reviewed integration fixture found; supply --probe-dir")
        args.probe_dir = reviewed[-1].parent.parent
    probe = args.probe_dir.resolve()
    original = json.loads((probe / "mapping-review/queries.json").read_text(encoding="utf-8"))
    queries = []
    for value in original["queries"]:
        value["binary"] = str(probe / "probe.elf")  # Same bytes; normalize the Windows review path for WSL.
        queries.append(Query.from_dict(value))
    mapping = json.loads((probe / "mapping-review/reviewed_mapping.json").read_text(encoding="utf-8"))
    if any(not link.get("expected_identity") for link in mapping["mappings"]):
        parser.error("The reviewed plan needs physical function/location identity anchors")
    output = scratch / ("end-to-end-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("End-to-end probe output: " + str(output), flush=True)
    manifest_path = output / "queries.json"
    manifest_path.write_text(json.dumps({"schema": "symbai.queries.v1", "queries": [asdict(q) for q in queries]}, indent=2), encoding="utf-8")
    mapping_path = output / "reviewed-mapping.json"
    mapping_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    config = {"schema": "symbai.online_tygr.v1", "python": str(args.tygr_python),
              "tygr_root": str(ROOT / "tygr_original"),
              "model": str(ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"),
              "model_sha256": MODEL_HASH, "mapping": str(mapping_path), "top_k": 3, "device": "cpu"}
    config_path = output / "online-tygr.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    plan = {"scope": "one_pre_reviewed_developer_query_not_held_out_evaluation", "budgets": args.budgets,
            "order": "budget_then_query_then_A_B_C_D", "accounting_unit": "single_query_cold_process",
            "model_cache_policy": "no_inference_reuse_between_runs; OS_file_cache_not_flushed",
            "mapping_plan_sha256": file_hash(mapping_path),
            "excluded_setup": "fixed query/bounds and prior human locator-plan review; harness orchestration",
            "charged": "worker startup, input validation, C/D model loading/export/mapping, checking, validation and finalization"}
    source_files = list((ROOT / "src/selective_analysis").glob("*.py")) + [
        ROOT / "scripts/export_tygr_candidates.py", ROOT / "scripts/map_tygr_candidates.py",
        ROOT / "scripts/run_selective_pilot.py", Path(__file__).resolve()]
    plan["runtime_source_sha256"] = {str(path.relative_to(ROOT)): file_hash(path) for path in source_files}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    check_group_cleanup(output)
    command = [sys.executable, "-B", str(ROOT / "scripts/run_selective_pilot.py"),
               "--manifest", str(manifest_path), "--variants", "A", "B", "C", "D",
               "--budgets", *[str(budget) for budget in args.budgets], "--regime", "end_to_end",
               "--online-tygr", str(config_path), "--output", str(output / "results")]
    with (output / "run.log").open("w", encoding="utf-8") as log:
        subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    # Labels enter only here, after all runtime workers have terminated.
    from scripts.evaluate_selective_pilot import evaluate
    runs = json.loads((output / "results/runs.json").read_text(encoding="utf-8"))
    gold = json.loads((probe / "mapping-review/gold.json").read_text(encoding="utf-8"))
    report = evaluate(runs, gold)
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for row in report["comparisons"]:
        acquisition = row["type_acquisition_seconds"]
        cost = "partial, charged in total" if acquisition is None else "{:.3f}s".format(acquisition)
        print("{} {:g}s: {}/{} resolved, {} unknown, {} wrong, {} timeouts; wall {:.3f}s; model+mapping {}".format(
            row["variant"], row["budget_seconds"], row["resolved"], row["queries"],
            row["unknown"], row["wrong_decisions"], row["timeouts"], row["total_wall_seconds"], cost), flush=True)
    print("Finished. Elapsed acquisition and checking are included; inspect statuses and receipts: " + str(output))


if __name__ == "__main__":
    main()
