#!/usr/bin/env python3
"""Prepare/run the frozen four-function mapping panel with separate offline labels."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import runtime_path, sha
from src.selective_analysis.variable_mapping import offline_facts, review_mapping


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def linux(path):
    value = str(Path(path).resolve()).replace("\\", "/")
    return "/mnt/d/" + value[3:] if value[:3].lower() == "d:/" else value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Use WSL angr-env with existing tygr-orig; preparation is portable")
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    prior = runtime_path(args.inventory).resolve()
    prior.relative_to(scratch)
    summary, audit, plan = (read(prior / name) for name in ("summary.json", "independent-audit.json", "mapping-probe-plan.json"))
    if summary["inventoried_builds"] != 12 or audit["builds_replayed"] != 12 or len(plan["cases"]) != 4:
        raise ValueError("The reviewed complete inventory and frozen four-case panel are required")
    for name, expected in audit["sha256"].items():
        if sha(prior / name) != expected:
            raise ValueError("Reviewed inventory evidence changed")
    output = scratch / ("route-b-type-mapping-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    copies, temp = output / "source_snapshot", output / "temp"
    copies.mkdir()
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    implementation, pins = {}, {}
    for key, name in (("worker", "capture_type_mapping.py"), ("capture", "capture_tygr_preprocessing.py"),
        ("stages", "capture_tygr_graph_stages.py"), ("hooks", "tygr_read_hook_variants.py"), ("locations", "tygr_location_adapter.py")):
        path = ROOT / "scripts" / name
        target = copies / name
        target.write_bytes(path.read_bytes())
        implementation[key] = {"path": linux(target), "sha256": sha(target)}
        pins[linux(path)] = pins[linux(target)] = sha(path)
    for path in (Path(__file__), ROOT / "src/selective_analysis/variable_mapping.py", ROOT / "src/selective_analysis/type_corpus.py"):
        target = copies / path.name
        target.write_bytes(path.read_bytes())
        pins[linux(path)] = pins[linux(target)] = sha(path)
    source_inventory = {path.relative_to(ROOT / "tygr_original").as_posix(): sha(path) for path in (ROOT / "tygr_original/src").rglob("*.py")}
    for path in (prior / "mapping-probe-plan.json", prior / "mapping-probe-offline-labels.json", prior / "summary.json", prior / "independent-audit.json"):
        pins[linux(path)] = sha(path)
    jobs = []
    for case in plan["cases"]:
        if case["status"] != "selected" or case["split"] not in ("train", "development"):
            raise ValueError("Evaluation inputs or substituted probes forbidden")
        binary = runtime_path(case["binary"])
        if sha(binary) != case["binary_sha256"]:
            raise ValueError("Selected ELF changed")
        facts = offline_facts(binary, case["function_address"], case["selected_variable_die_offsets"])
        if facts["function_name"] != case["function_name"]:
            raise ValueError("Selected function identity differs")
        directory = output / case["project_id"]
        directory.mkdir()
        write(directory / "offline-facts.json", facts)
        request = {"schema": "symbai.type_mapping_request.v1", "binary": linux(binary), "binary_sha256": sha(binary),
            "function_address": case["function_address"], "tygr_root": linux(ROOT / "tygr_original"),
            "source_inventory": source_inventory, "implementation": implementation, "scratch_dir": linux(directory / "cache")}
        write(directory / "request.json", request)
        pins[linux(binary)] = sha(binary)
        for path in (directory / "request.json", directory / "offline-facts.json"):
            pins[linux(path)] = sha(path)
        jobs.append({"project_id": case["project_id"], "directory": directory, "facts": facts})
    write(output / "plan.json", {"schema": "symbai.type_mapping_run_plan.v1", "pins": pins,
        "prior_inventory": linux(prior), "planned_functions": 4, "planned_variables": 8,
        "pipeline_variant": "original_native_graphs_with_registered_AFTER_read_hooks_and_explicit_x64_architecture",
        "scope": "Fixed train/development CFA locations, graph membership and value readouts. Fresh 60-relation data; no model loading/forward, legacy-checkpoint admission, training or evaluation-project execution."})
    print("Type mapping output: " + str(output), flush=True)
    rows = []
    if not args.prepare_only:
        for job in jobs:
            directory = job["directory"]
            try:
                with (directory / "worker.log").open("w", encoding="utf-8") as stream:
                    subprocess.run([str(args.tygr_python), "-B", implementation["worker"]["path"], "--request",
                        str(directory / "request.json"), "--output", str(directory / "raw.json")],
                        cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=120)
                payload = read(directory / "raw.json")
                if payload["binary_sha256"] != read(directory / "request.json")["binary_sha256"]:
                    raise ValueError("Capture identity differs")
                row = dict(review_mapping(payload, job["facts"]), project_id=job["project_id"], status="reviewed")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row = {"project_id": job["project_id"], "status": "failed", "error": str(error)}
                if (directory / "raw.json").is_file():
                    row["worker_error"] = read(directory / "raw.json").get("error")
                if (directory / "worker.log").is_file():
                    row["log_tail"] = (directory / "worker.log").read_text(encoding="utf-8", errors="replace").splitlines()[-10:]
            rows.append(row)
            write(output / "records.json", rows)
            print(job["project_id"] + ": " + row["status"] + "; consistent variables " + str(row.get("consistent_variables", 0)), flush=True)
    for name, expected in pins.items():
        if sha(runtime_path(name)) != expected:
            raise ValueError("Pinned source or input changed")
    for relative, expected in source_inventory.items():
        if sha(ROOT / "tygr_original" / relative) != expected:
            raise ValueError("Original source changed")
    result = {"schema": "symbai.type_mapping_summary.v1", "prepare_only": args.prepare_only,
        "planned_functions": 4, "planned_variables": 8, "reviewed_functions": sum(row["status"] == "reviewed" for row in rows),
        "location_readout_consistent_variables": sum(row.get("consistent_variables", 0) for row in rows), "cases": rows,
        "training_allowed": False, "full_semantic_use_site_mapping_validated": False,
        "evaluation_projects_executed": False, "model_loaded": False, "model_forward_performed": False,
        "neural_benefit_measured": False, "output": str(output)}
    write(output / "summary.json", result)
    print(json.dumps(result, indent=2), flush=True)
    if not args.prepare_only and result["reviewed_functions"] != 4:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
