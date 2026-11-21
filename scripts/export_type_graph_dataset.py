#!/usr/bin/env python3
"""Export all frozen O0 train/development graphs with separate reviewed targets."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import UpstreamLabels, runtime_path, sha
from src.selective_analysis.type_graph_dataset import source_facts, admit_supervision


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def linux(path):
    value = str(Path(path).resolve()).replace("\\", "/")
    return "/mnt/d/" + value[3:] if value[:3].lower() == "d:/" else value


def validate_scope(mapping, scratch):
    mapping = runtime_path(mapping).resolve()
    mapping.relative_to(scratch)
    plan = read(mapping / "plan.json")
    audit = read(mapping / "independent-audit.json")
    if (audit["reviewed_functions"] != 4 or audit["location_readout_consistent_source_variables"] != 8
            or audit["evaluation_projects_executed"] or audit["model_loaded"]):
        raise ValueError("Reviewed four-function mapping prerequisite differs")
    for name, expected in audit["sha256"].items():
        if sha(mapping / name) != expected:
            raise ValueError("Mapping review evidence changed")
    for name, expected in plan["pins"].items():
        if sha(runtime_path(name)) != expected:
            raise ValueError("Reviewed mapping source or input changed")
    original = ROOT / "tygr_original"
    expected_sources = read(mapping / "inih/request.json")["source_inventory"]
    current_sources = {path.relative_to(original).as_posix(): sha(path) for path in (original / "src").rglob("*.py")}
    if current_sources != expected_sources:
        raise ValueError("Upstream source differs from the reviewed mapping variant")
    scope = read(mapping / "next-export-inputs.json")
    cases = scope["cases"]
    if (scope["schema"] != "symbai.type_graph_export_scope.v1"
            or scope["candidate_functions"] != 43 or len(cases) != 43
            or scope["candidate_source_variable_records"] != 190
            or sum(c["source_variable_records"] for c in cases) != 190
            or len({c["function_id"] for c in cases}) != 43
            or any(c["split"] not in ("train", "development") or c["profile"] != "O0" for c in cases)
            or scope["evaluation_projects_selected"]):
        raise ValueError("Frozen 43-function train/development scope differs")
    inventory = runtime_path(plan["prior_inventory"]).resolve()
    inventory.relative_to(scratch)
    inventory_audit = read(inventory / "independent-audit.json")
    if inventory_audit["builds_replayed"] != 12:
        raise ValueError("Complete reviewed corpus required")
    for name, expected in inventory_audit["sha256"].items():
        if sha(inventory / name) != expected:
            raise ValueError("Corpus review evidence changed")
    rows = []
    for case in cases:
        labels_path = inventory / (case["project_id"] + "-O0.labels.json")
        labels = read(labels_path)
        function, = [f for f in labels["functions"] if f["function_id"] == case["function_id"]]
        variables = [v for v in labels["variables"] if v["function_id"] == case["function_id"]]
        if (function["address"] != case["function_address"] or function["name"] != case["function_name"]
                or function["split"] != case["split"] or len(variables) != case["source_variable_records"]
                or labels["binary_sha256"] != case["binary_sha256"]
                or sha(runtime_path(case["binary"])) != case["binary_sha256"]):
            raise ValueError("Frozen scope and inventory differ")
        rows.append((case, variables, labels_path))
    return inventory, rows


def summarize(records, samples, planned, prepare_only):
    splits = {}
    for split in ("train", "development"):
        rows = [r for r in records if r["split"] == split]
        histogram = Counter(str(v["class_id"]) for r in rows for v in r.get("variables", []) if v["status"] == "admitted")
        splits[split] = {"planned_functions": sum(c[0]["split"] == split for c in planned),
            "candidate_source_variables": sum(len(c[1]) for c in planned if c[0]["split"] == split),
            "exported_functions": sum(s["split"] == split for s in samples),
            "admitted_source_variables": sum(r.get("admitted_source_variables", 0) for r in rows),
            "supervised_value_rows": sum(r.get("supervised_value_rows", 0) for r in rows),
            "source_variable_label_histogram": dict(histogram)}
    return {"schema": "symbai.type_graph_dataset_summary.v1", "prepare_only": prepare_only,
        "planned_functions": len(planned), "candidate_source_variables": sum(len(c[1]) for c in planned),
        "completed_functions": len(records), "exported_functions": len(samples),
        "failed_or_empty_functions": [r["function_id"] for r in records if r["status"] != "exported"],
        "splits": splits, "exclusion_reasons": dict(Counter(reason for r in records for v in r.get("variables", []) for reason in v["reasons"])),
        "training_allowed": False, "next_step": "Review export coverage and identities before minimal pilot training.",
        "evaluation_projects_executed": False, "model_loaded": False, "model_forward_performed": False,
        "neural_benefit_measured": False, "full_semantic_use_site_mapping_validated": False,
        "scope": "Exploratory project-split data, DWARF-assisted variable enumeration, partial execution, complete 60-relation preprocessing. Not publication generalization evidence or frozen-checkpoint compatibility."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", type=Path, required=True, help="Reviewed mapping directory containing next-export-inputs.json")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--function-timeout", type=float, default=120.)
    args = parser.parse_args()
    if not 0 < args.function_timeout <= 600:
        parser.error("Function timeout must be in (0, 600] seconds")
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Run collection in WSL angr-env; preparation is portable")
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    inventory, cases = validate_scope(args.mapping, scratch)
    output = scratch / ("route-b-type-graphs-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
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
    for path in (Path(__file__), ROOT / "src/selective_analysis/type_graph_dataset.py",
            ROOT / "src/selective_analysis/variable_mapping.py", ROOT / "src/selective_analysis/type_corpus.py"):
        target = copies / path.name
        target.write_bytes(path.read_bytes())
        pins[linux(path)] = pins[linux(target)] = sha(path)
    tygr = ROOT / "tygr_original"
    sources = {path.relative_to(tygr).as_posix(): sha(path) for path in (tygr / "src").rglob("*.py")}
    vocabulary = UpstreamLabels(tygr).vocabulary
    write(output / "vocabulary.json", vocabulary)
    for path in (runtime_path(args.mapping) / "next-export-inputs.json", runtime_path(args.mapping) / "independent-audit.json",
            inventory / "independent-audit.json", inventory / "summary.json", output / "vocabulary.json"):
        pins[linux(path)] = sha(path)
    jobs = []
    print("Type graph dataset output: " + str(output), flush=True)
    for index, (case, variables, labels_path) in enumerate(cases):
        directory = output / ("{:02d}-{}-{:x}".format(index, case["project_id"], case["function_address"]))
        directory.mkdir()
        binary = runtime_path(case["binary"])
        try:
            source = source_facts(binary, case["function_address"], variables)
            if source["facts"]["function_name"] != case["function_name"]:
                raise ValueError("Offline function identity differs")
        except (ValueError, KeyError) as error:
            source = {"error": str(error)}
        # All source labels/facts remain parent-side; the child sees no gold inventory.
        write(directory / "offline-source.json", {"case": case, "variables": variables, "locations": source})
        request = {"schema": "symbai.type_mapping_request.v1", "binary": linux(binary), "binary_sha256": case["binary_sha256"],
            "function_address": case["function_address"], "tygr_root": linux(tygr), "source_inventory": sources,
            "implementation": implementation, "scratch_dir": linux(directory / "cache")}
        write(directory / "request.json", request)
        for path in (binary, labels_path, directory / "offline-source.json", directory / "request.json"):
            pins[linux(path)] = sha(path)
        jobs.append((directory, case, variables, source))
    write(output / "plan.json", {"schema": "symbai.type_graph_dataset_plan.v1", "pins": pins,
        "original_source_inventory": sources, "function_timeout_seconds": args.function_timeout,
        "planned_functions": 43, "candidate_source_variables": 190, "inventory": linux(inventory),
        "mapping_prerequisite": linux(runtime_path(args.mapping)), "evaluation_projects_selected": False,
        "admission": "Independent fixed CFA correspondence; exclude whole structs, missing locations, graph errors, duplicate row claims and conflicting shared-node labels. Source-variable weights sum to one."})
    records, samples = [], []
    if not args.prepare_only:
        for index, (directory, case, variables, source) in enumerate(jobs):
            start = time.monotonic()
            row = {key: case[key] for key in ("function_id", "project_id", "split", "function_name")}
            try:
                if "error" in source:
                    raise ValueError(source["error"])
                with (directory / "worker.log").open("w", encoding="utf-8") as stream:
                    subprocess.run([str(args.tygr_python), "-B", implementation["worker"]["path"], "--request",
                        str(directory / "request.json"), "--output", str(directory / "raw.json")],
                        cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=args.function_timeout)
                payload = read(directory / "raw.json")
                if payload["binary_sha256"] != case["binary_sha256"] or payload["function_address"] != case["function_address"]:
                    raise ValueError("Collected function identity differs")
                features, targets, review = admit_supervision(payload, source, variables, vocabulary)
                row.update(review, status="exported" if targets["targets"] else "no_admissible_targets")
                write(directory / "features.json", features)
                write(directory / "supervision.json", targets)
                if targets["targets"]:
                    samples.append({key: case[key] for key in ("function_id", "project_id", "split")})
                    for key in ("features", "supervision"):
                        path = directory / (key + ".json")
                        samples[-1][key] = {"path": path.relative_to(output).as_posix(), "sha256": sha(path)}
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row.update(status="failed", error=str(error), admitted_source_variables=0, supervised_value_rows=0,
                    candidate_source_variables=len(variables), variables=[{"die_offset": v["variable_die_offset"],
                        "status": "excluded", "reasons": ["function_capture_or_review_failed"]} for v in variables])
                if (directory / "raw.json").is_file():
                    row["worker_error"] = read(directory / "raw.json").get("error")
                if (directory / "worker.log").is_file():
                    row["log_tail"] = (directory / "worker.log").read_text(encoding="utf-8", errors="replace").splitlines()[-10:]
            row["parent_elapsed_seconds"] = time.monotonic() - start
            row["directory"] = directory.relative_to(output).as_posix()
            records.append(row)
            write(output / "records.json", records)
            print("{}/43 {} {}: {}; {}/{} source variables".format(index + 1, case["project_id"], case["function_name"],
                row["status"], row["admitted_source_variables"], len(variables)), flush=True)
    for name, expected in pins.items():
        if sha(runtime_path(name)) != expected:
            raise ValueError("Pinned source or input changed during export")
    current_sources = {path.relative_to(tygr).as_posix(): sha(path) for path in (tygr / "src").rglob("*.py")}
    if current_sources != sources:
        raise ValueError("Original TYGR source inventory changed")
    write(output / "dataset.json", {"schema": "symbai.type_graph_dataset.v1", "samples": samples,
        "vocabulary": {"path": "vocabulary.json", "sha256": sha(output / "vocabulary.json")},
        "relation_count": 60, "feature_width": 31, "training_allowed": False,
        "evaluation_projects_executed": False, "labels_separate_from_features": True})
    result = summarize(records, samples, cases, args.prepare_only)
    result.update(source_integrity_unchanged=True, output=str(output))
    write(output / "summary.json", result)
    print(json.dumps(result, indent=2), flush=True)
    if not args.prepare_only and (not samples or len(records) != 43):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
