#!/usr/bin/env python3
"""Compare three external read-hook interventions on the two reviewed functions."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import audit_native_graph_stages as stages
from scripts.tygr_read_hook_variants import VARIANTS

base = stages.baseline


def prepare(prior, output):
    prior_plan, prior_summary = base.read(prior / "plan.json"), base.read(prior / "summary.json")
    if prior_summary["prepare_only"] or prior_summary["reviewed"] != 2 or not (prior / "independent-audit.json").is_file():
        raise ValueError("Both reviewed graph-stage captures are required")
    base.require_pins(prior_plan["pins"])
    local_plan, = [base.runtime_path(name) for name in prior_plan["pins"]
                   if "route-b-native-local-actions-" in name and name.endswith("/plan.json")]
    cases, _, pins = stages.prepare(local_plan.parent, output)
    implementation = {}
    for key, name in (("worker", "capture_tygr_hook_variants.py"),
                      ("variant_adapter", "tygr_read_hook_variants.py"),
                      ("driver", Path(__file__).name)):
        source, copy = ROOT / "scripts" / name, output / "source_snapshot" / name
        copy.write_bytes(source.read_bytes())
        implementation[key] = {"path": base.linux_path(copy), "sha256": base.digest(copy)}
        pins[base.linux_path(source)] = pins[base.linux_path(copy)] = base.digest(source)
    jobs = []
    for case in cases:
        common = case["directory"]
        original_request = base.read(common / "request.json")
        for variant in VARIANTS:
            directory = common / variant
            directory.mkdir()
            native = dict(original_request["native_request"], scratch_dir=base.linux_path(directory / "cache"))
            impl = {"worker": implementation["worker"], "variant_adapter": implementation["variant_adapter"],
                "stages": original_request["implementation"]["worker"],
                "guard": original_request["implementation"]["guard"],
                "adapter": original_request["implementation"]["adapter"]}
            request = {"schema": "symbai.hook_variant_request.v1", "variant": variant,
                       "native_request": native, "implementation": impl}
            base.write(directory / "request.json", request)
            jobs.append({**case, "variant": variant, "job_directory": directory,
                         "reference_stage_raw": prior / case["case_id"] / "raw.json"})
    for path in (prior / "plan.json", prior / "summary.json", prior / "independent-audit.json",
                 *(job["reference_stage_raw"] for job in jobs)):
        pins[base.linux_path(path)] = base.digest(path)
    base.write(output / "plan.json", {"schema": "symbai.read_hook_comparison_plan.v1",
        "pins": pins, "cases": stages.CASES, "variants": VARIANTS,
        "prior_graph_stages": base.linux_path(prior), "planned_captures": 6,
        "interventions": {"original": "No callback or timing change.",
            "field_names_before": "Call original read callbacks once, then route only their freshly created expressions to reg_read_expr/mem_read_expr; preserve BEFORE timing.",
            "field_names_after": "Use the same field routing and move only the two matching read breakpoints from BEFORE to AFTER; preserve write hooks."},
        "scope": "Fresh original-runtime subprocess per function/variant. No forward calls, property checks, learned policies, checkpoint edits, source-file edits or edge deletion. Guard rejection is retained separately from capture success.",
        "interpretation": "Dependency restoration, saved input-domain compatibility, and eventual neural usefulness are separate questions. Passing the tensor guard does not validate predictions on an intervened graph."})
    return jobs, pins


def review(job, payload):
    if (payload["status"] != "captured" or payload["variant"] != job["variant"]
            or payload["forward_attempts"] != 0 or payload["model_forward_performed"]
            or not payload["original_identities_rechecked"] or payload["observer_errors"] or payload["location_errors"]):
        raise ValueError("Incomplete no-forward intervention: " + repr(payload.get("error")))
    request = base.read(job["job_directory"] / "request.json")
    native = request["native_request"]
    if any(payload[key] != native[key] for key in ("binary_sha256", "model_sha256")):
        raise ValueError("Capture binary/model identity differs")
    entry = request["implementation"]["guard"]
    guard_path = base.runtime_path(entry["path"])
    if base.digest(guard_path) != entry["sha256"]:
        raise ValueError("Saved input guard implementation differs")
    spec = importlib.util.spec_from_file_location("reviewed_variant_guard", guard_path)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    expected = {json.dumps(r, sort_keys=True) for r in base.read(job["directory"] / "offline-location-trace.json")}
    if not payload["location_records"] or any(json.dumps(r, sort_keys=True) not in expected for r in payload["location_records"]):
        raise ValueError("Location trace differs from independent projection")
    report = payload["intervention"]
    if (report["variant"] != job["variant"]
            or report["routing_installed"] != (job["variant"] != "original")
            or report["timing_override_installed"] != (job["variant"] == "field_names_after")):
        raise ValueError("Intervention receipt differs")
    if job["variant"] == "original":
        stages.review(job, payload)
        prior = base.read(job["reference_stage_raw"])
        if payload["functions"][0]["native_input"]["batch"] != prior["functions"][0]["native_input"]["batch"]:
            raise ValueError("Original control no longer reproduces the frozen stage input")
    elif report["field_routes"].get("reg_read_expr", 0) == 0:
        raise ValueError("Registered register-read field intervention was not exercised")
    if job["variant"] == "field_names_after":
        if {r["event"] for r in report["timing_moves"]} != {"reg_read", "mem_read"}:
            raise ValueError("Read-event timing intervention was not exercised")
    elif report["timing_moves"]:
        raise ValueError("Control/field-only arm unexpectedly changed timing")
    function, = [f for f in payload["functions"] if f["function_address"] == job["address"]]
    try:
        guard_result = guard.guard_native_input(function["native_input"], payload["model_contract"])
    except ValueError as rejection:
        guard_result = {"status": "rejected", "reason": str(rejection)}
    if guard_result != function["saved_model_input_guard"]:
        raise ValueError("Saved input guard receipt differs on independent replay")
    static = base.read(job["directory"] / "static-instructions.json")
    actions = [a for block in function["blocks"] for a in block["actions"]]
    reached = any(a["type"] == "mem" and a["action"] == "write"
                  and a["instruction_address"] == static["write_address"] for a in actions)
    splice, = function["splices"]
    # Reachability is checked on original typed-edge topology, not a weak component.
    import networkx as nx
    network = nx.DiGraph()
    network.add_nodes_from(n["id"] for n in splice["before"]["nodes"])
    network.add_edges_from((e["source"], e["target"]) for e in splice["before"]["edges"])
    targets = [n["id"] for n in splice["before"]["nodes"] if n["annotation_address"] == static["write_address"]
        and any(e["target"] == n["id"] and "mem_loc" in e["labels"] for e in splice["before"]["edges"])]
    paths = [(seed, target) for seed in splice["seed_nodes"] for target in targets
             if nx.has_path(network, seed, target)]
    ids = function["native_input"]["batch"]["edge_labels"]["values"]
    return {"case_id": job["case_id"], "variant": job["variant"], "status": "reviewed",
        "pre_splice_nodes": splice["before"]["node_count"], "post_splice_nodes": splice["after"]["node_count"],
        "target_write_in_history": reached, "step_exceptions": function["step_exceptions"],
        "seed_to_target_pc_memory_paths": paths,
        "target_pc_dependency_observed": reached and bool(paths),
        "post_splice_edge_labels": sorted({label for e in splice["after"]["edges"] for label in e["labels"]}),
        "saved_model_guard": function["saved_model_input_guard"],
        "saved_model_guard_replayed": True,
        "out_of_saved_relation_domain_ids": sorted({i for i in ids if not 0 <= i < 44}),
        "field_routes": report["field_routes"], "timing_moves": report["timing_moves"],
        "forward_attempts": 0,
        "scope_note": "Target-PC memory nodes are a diagnostic indicator; exact full use-site mapping and property validity are not established."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-stages", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Collect in WSL using angr-env and the existing tygr-orig interpreter")
    prior = base.within(args.graph_stages, base.SCRATCH)
    output = base.SCRATCH / ("route-b-read-hook-controls-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    jobs, pins = prepare(prior, output)
    print("Read-hook controls output: " + str(output), flush=True)
    rows = []
    if not args.prepare_only:
        for job in jobs:
            directory = job["job_directory"]
            request = base.read(directory / "request.json")
            try:
                with (directory / "worker.log").open("w", encoding="utf-8") as stream:
                    subprocess.run([str(args.tygr_python), "-B", request["implementation"]["worker"]["path"],
                        "--request", str(directory / "request.json"), "--output", str(directory / "raw.json")],
                        cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90)
                row = review(job, base.read(directory / "raw.json"))
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row = {"case_id": job["case_id"], "variant": job["variant"], "status": "failed", "reason": str(error)}
                if (directory / "raw.json").is_file():
                    row["worker_error"] = base.read(directory / "raw.json").get("error")
                if (directory / "worker.log").is_file():
                    row["worker_log_tail"] = (directory / "worker.log").read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
            rows.append(row)
            base.write(output / "records.json", rows)
            print(job["case_id"] + " " + job["variant"] + ": " + row["status"] + (
                " " + str(row.get("worker_error") or row.get("reason")) if row["status"] == "failed" else ""), flush=True)
    base.require_pins(pins)
    summary = {"schema": "symbai.read_hook_comparison_summary.v1", "prepare_only": args.prepare_only,
        "planned_captures": 6, "reviewed": sum(r["status"] == "reviewed" for r in rows), "cases": rows,
        "model_forward_performed": False, "new_property_checks": False, "upstream_files_modified": False,
        "checkpoint_modified": False, "diagnostic_interventions_only": True, "output": str(output)}
    base.write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not args.prepare_only and summary["reviewed"] != 6:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
