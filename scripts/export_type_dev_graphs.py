#!/usr/bin/env python3
"""Export graphs for the pre-registered type pilot v2 development extension.

Versioned counterpart of export_type_graph_dataset.py, whose scope is pinned to the
v1 43-function panel. Collection, admission and dataset layout are unchanged: the
reviewed capture worker runs in the original TYGR runtime, source labels stay
parent-side, and admit_supervision applies the v1 rules. Only development functions
from dev-export-scope.json are exported; no model is loaded or trained.
"""
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
from src.selective_analysis.type_graph_dataset import admit_supervision, source_facts

PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v2_preregistration.md"
PREREGISTRATION_SHA256 = "945832e331c1c90cb345d3476cf174b46def6140b3b4694ac4635521b3ff3fdf"
V1_DATASET = "route-b-type-graphs-20261119T225215150614Z"
FORBIDDEN_PROJECTS = {"inih", "rxi_map", "jsmn", "optparse", "utf8_h", "b64"}
WORKER_FILES = (("worker", "capture_type_mapping.py"), ("capture", "capture_tygr_preprocessing.py"),
    ("stages", "capture_tygr_graph_stages.py"), ("hooks", "tygr_read_hook_variants.py"),
    ("locations", "tygr_location_adapter.py"))


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def linux(path):
    value = str(Path(path).resolve()).replace("\\", "/")
    return "/mnt/d/" + value[3:] if value[:3].lower() == "d:/" else value


def validate_mapping(mapping, scratch):
    """Same reviewed-capture prerequisite as v1, without the v1 export scope."""
    mapping = runtime_path(mapping).resolve()
    mapping.relative_to(scratch)
    plan, audit = read(mapping / "plan.json"), read(mapping / "independent-audit.json")
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
    current = {p.relative_to(original).as_posix(): sha(p) for p in (original / "src").rglob("*.py")}
    if current != expected_sources:
        raise ValueError("Upstream source differs from the reviewed mapping variant")
    return mapping


def validate_scope(inventory, scratch):
    """Admit only the completed, pre-registered development inventory."""
    inventory = runtime_path(inventory).resolve()
    inventory.relative_to(scratch)
    extension = inventory.parent
    manifest_path, selection_path = extension / "manifest.json", extension / "selection.json"
    manifest, selection = read(manifest_path), read(selection_path)
    scope, summary = read(inventory / "dev-export-scope.json"), read(inventory / "summary.json")
    if sha(PREREGISTRATION) != PREREGISTRATION_SHA256:
        raise ValueError("Pre-registration changed")
    if (selection["preregistration_sha256"] != PREREGISTRATION_SHA256
            or scope["preregistration_sha256"] != PREREGISTRATION_SHA256
            or manifest["selection_sha256"] != sha(selection_path)
            or scope["manifest_sha256"] != sha(manifest_path)):
        raise ValueError("Inventory is not bound to the frozen selection")
    if (scope["schema"] != "symbai.type_dev_export_scope.v1" or scope["evaluation_projects_selected"]
            or scope["labels_in_scope"] or summary.get("failed_builds")):
        raise ValueError("Development export scope differs")
    planned = summary.get("planned_builds")
    if summary.get("inventoried_builds") != (len(planned) if isinstance(planned, list) else planned):
        raise ValueError("Incomplete development inventory")
    rows, seen = [], set()
    for case in scope["cases"]:
        if (case["split"] != "development" or case["profile"] != "O0" or case["project_id"] in FORBIDDEN_PROJECTS
                or case["function_id"] in seen):
            raise ValueError("Invalid development case")
        seen.add(case["function_id"])
        labels_path = inventory / (case["project_id"] + "-O0.labels.json")
        labels = read(labels_path)
        function, = [f for f in labels["functions"] if f["function_id"] == case["function_id"]]
        variables = [v for v in labels["variables"] if v["function_id"] == case["function_id"]]
        if (function["address"] != case["function_address"] or function["name"] != case["function_name"]
                or function["split"] != "development" or len(variables) != case["source_variable_records"]
                or labels["binary_sha256"] != case["binary_sha256"]
                or sha(runtime_path(case["binary"])) != case["binary_sha256"]):
            raise ValueError("Scope and inventory differ: " + case["function_id"])
        rows.append((case, variables, labels_path))
    if len(rows) != scope["candidate_functions"] or sum(len(r[1]) for r in rows) != scope["candidate_source_variable_records"]:
        raise ValueError("Scope denominators differ")
    return inventory, extension, scope, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True, help="labels-* directory of the development extension")
    parser.add_argument("--mapping", type=Path, required=True, help="Reviewed v1 mapping directory (capture prerequisite)")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--function-timeout", type=float, default=120.)
    args = parser.parse_args()
    if not 0 < args.function_timeout <= 600:
        parser.error("Function timeout must be in (0, 600] seconds")
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Run collection in WSL angr-env; preparation is portable")
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    mapping = validate_mapping(args.mapping, scratch)
    inventory, extension, scope, cases = validate_scope(args.inventory, scratch)
    v1 = read(scratch / V1_DATASET / "dataset.json")
    output = scratch / ("route-b-type-dev-graphs-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    copies, temp = output / "source_snapshot", output / "temp"
    copies.mkdir()
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    implementation, pins = {}, {}
    for key, name in WORKER_FILES:
        path, target = ROOT / "scripts" / name, copies / name
        target.write_bytes(path.read_bytes())
        implementation[key] = {"path": linux(target), "sha256": sha(target)}
        pins[linux(path)] = pins[linux(target)] = sha(path)
    for path in (Path(__file__), ROOT / "src/selective_analysis/type_graph_dataset.py",
            ROOT / "src/selective_analysis/variable_mapping.py", ROOT / "src/selective_analysis/type_corpus.py",
            ROOT / "scripts/verify_type_dev_export.py", PREREGISTRATION):
        target = copies / path.name
        target.write_bytes(path.read_bytes())
        pins[linux(path)] = pins[linux(target)] = sha(path)
    # The passive verifier runs from the dataset directory, like the v1 verify_export.py.
    (output / "verify_type_dev_export.py").write_bytes((ROOT / "scripts/verify_type_dev_export.py").read_bytes())
    tygr = ROOT / "tygr_original"
    sources = {p.relative_to(tygr).as_posix(): sha(p) for p in (tygr / "src").rglob("*.py")}
    vocabulary = UpstreamLabels(tygr).vocabulary
    write(output / "vocabulary.json", vocabulary)
    if sha(output / "vocabulary.json") != v1["vocabulary"]["sha256"]:
        raise ValueError("Vocabulary differs from the v1 reviewed dataset")
    for path in (mapping / "independent-audit.json", inventory / "dev-export-scope.json", inventory / "summary.json",
            extension / "manifest.json", extension / "selection.json", scratch / V1_DATASET / "dataset.json"):
        pins[linux(path)] = sha(path)
    jobs = []
    print("Development graph dataset output: " + str(output), flush=True)
    for index, (case, variables, labels_path) in enumerate(cases):
        directory = output / "{:03d}-{}-{:x}".format(index, case["project_id"], case["function_address"])
        directory.mkdir()
        binary = runtime_path(case["binary"])
        try:
            source = source_facts(binary, case["function_address"], variables)
            if source["facts"]["function_name"] != case["function_name"]:
                raise ValueError("Offline function identity differs")
        except (ValueError, KeyError) as error:
            source = {"error": str(error)}
        write(directory / "offline-source.json", {"case": case, "variables": variables, "locations": source})
        request = {"schema": "symbai.type_mapping_request.v1", "binary": linux(binary), "binary_sha256": case["binary_sha256"],
            "function_address": case["function_address"], "tygr_root": linux(tygr), "source_inventory": sources,
            "implementation": implementation, "scratch_dir": linux(directory / "cache")}
        write(directory / "request.json", request)
        for path in (binary, labels_path, directory / "offline-source.json", directory / "request.json"):
            pins[linux(path)] = sha(path)
        jobs.append((directory, case, variables, source))
    planned_variables = sum(len(v) for _, _, v, _ in jobs)
    write(output / "plan.json", {"schema": "symbai.type_dev_graph_dataset_plan.v1", "pins": pins,
        "original_source_inventory": sources, "function_timeout_seconds": args.function_timeout,
        "planned_functions": len(jobs), "candidate_source_variables": planned_variables,
        "inventory": linux(inventory), "mapping_prerequisite": linux(mapping),
        "preregistration_sha256": PREREGISTRATION_SHA256, "evaluation_projects_selected": False,
        "admission": "v1 rules: independent fixed CFA correspondence; exclude whole structs, missing locations, graph errors, duplicate row claims and conflicting shared-node labels. Source-variable weights sum to one."})
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
            print("{}/{} {} {}: {}; {}/{} source variables".format(index + 1, len(jobs), case["project_id"],
                case["function_name"], row["status"], row["admitted_source_variables"], len(variables)), flush=True)
    for name, expected in pins.items():
        if sha(runtime_path(name)) != expected:
            raise ValueError("Pinned source or input changed during export")
    if {p.relative_to(tygr).as_posix(): sha(p) for p in (tygr / "src").rglob("*.py")} != sources:
        raise ValueError("Original TYGR source inventory changed")
    admitted = sum(r.get("admitted_source_variables", 0) for r in records)
    rows = sum(r.get("supervised_value_rows", 0) for r in records)
    write(output / "dataset.json", {"schema": "symbai.type_dev_graph_dataset.v1", "samples": samples,
        "vocabulary": {"path": "vocabulary.json", "sha256": sha(output / "vocabulary.json")},
        "relation_count": 60, "feature_width": 31, "training_allowed": False,
        "evaluation_projects_executed": False, "labels_separate_from_features": True,
        "preregistration_sha256": PREREGISTRATION_SHA256, "selection_sha256": sha(extension / "selection.json"),
        "admitted_source_variables": admitted, "supervised_value_rows": rows,
        "projects": sorted({c["project_id"] for c, _, _ in cases})})
    by_project = {}
    for project in sorted({c["project_id"] for c, _, _ in cases}):
        chosen = [r for r in records if r["project_id"] == project]
        by_project[project] = {"planned_functions": sum(c["project_id"] == project for c, _, _ in cases),
            "exported_functions": sum(r["status"] == "exported" for r in chosen),
            "candidate_source_variables": sum(len(v) for c, v, _ in cases if c["project_id"] == project),
            "admitted_source_variables": sum(r.get("admitted_source_variables", 0) for r in chosen),
            "supervised_value_rows": sum(r.get("supervised_value_rows", 0) for r in chosen)}
    summary = {"schema": "symbai.type_dev_graph_dataset_summary.v1", "prepare_only": args.prepare_only,
        "planned_functions": len(jobs), "completed_functions": len(records),
        "exported_functions": len(samples), "candidate_source_variables": planned_variables,
        "admitted_source_variables": admitted, "supervised_value_rows": rows, "projects": by_project,
        "exclusion_reasons": dict(Counter(reason for r in records for v in r.get("variables", []) for reason in v["reasons"])),
        "backup_rule_triggered_by_count": (not args.prepare_only) and admitted < 100,
        "evaluation_projects_executed": False, "model_loaded": False, "training_performed": False,
        "source_integrity_unchanged": True, "output": str(output),
        "scope": "Pre-registered v2 development extension; DWARF-assisted variable enumeration, partial execution, complete 60-relation preprocessing."}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not args.prepare_only and (not samples or len(records) != len(jobs)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
