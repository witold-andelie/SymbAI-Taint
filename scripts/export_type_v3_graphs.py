#!/usr/bin/env python3
"""Export new training and development graphs for the frozen type pilot v3.

Collection, worker invocation and v1/v2 admission are unchanged. Labels remain
parent-side; no model is loaded or trained. Preparation is portable; collection
requires the original TYGR Python runtime in WSL.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import UpstreamLabels, runtime_path, sha
from src.selective_analysis.type_graph_dataset import admit_supervision, source_facts

PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md"
PREREGISTRATION_SHA256 = "efb974c46039dfb14219687f6390f1d7b45a6226142141a69d42388716bf9392"
V1_DATASET = "route-b-type-graphs-20261119T225215150614Z"
FORBIDDEN_PROJECTS = {"inih", "rxi_map", "jsmn", "optparse", "sds", "tiny_regex_c", "utf8_h", "b64"}
SPLITS = ("train", "development")
WORKER_FILES = (("worker", "capture_type_mapping.py"), ("capture", "capture_tygr_preprocessing.py"),
    ("stages", "capture_tygr_graph_stages.py"), ("hooks", "tygr_read_hook_variants.py"),
    ("locations", "tygr_location_adapter.py"))


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2, allow_nan=False) + "\n").encode("ascii"))


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
    """Validate all scope inputs before creating an output or invoking a worker."""
    inventory = runtime_path(inventory).resolve()
    inventory.relative_to(scratch)
    extension = inventory.parent
    if not inventory.name.startswith("labels-") or not extension.name.startswith("route-b-type-corpus-v3-"):
        raise ValueError("Expected labels-* directly inside route-b-type-corpus-v3-*")
    manifest_path, selection_path = extension / "manifest.json", extension / "selection.json"
    manifest, selection = read(manifest_path), read(selection_path)
    scope, summary = read(inventory / "export-scope.json"), read(inventory / "summary.json")
    if sha(PREREGISTRATION) != PREREGISTRATION_SHA256:
        raise ValueError("Pre-registration changed")
    if (selection["preregistration_sha256"] != PREREGISTRATION_SHA256
            or scope["preregistration_sha256"] != PREREGISTRATION_SHA256
            or manifest["selection_sha256"] != sha(selection_path)
            or scope["manifest_sha256"] != sha(manifest_path)):
        raise ValueError("Inventory is not bound to the frozen selection")
    if (scope["schema"] != "symbai.type_v3_export_scope.v1"
            or scope["evaluation_projects_selected"] is not False or scope["labels_in_scope"] is not False
            or summary["schema"] != "symbai.type_v3_inventory.v1"):
        raise ValueError("V3 export scope or inventory schema/flags differ")
    if (any(type(summary.get(k)) is not int or summary[k] < 0
            for k in ("planned_builds", "inventoried_builds", "failed_builds"))
            or summary["failed_builds"] != 0 or summary["inventoried_builds"] != summary["planned_builds"]):
        raise ValueError("Incomplete v3 inventory")
    for field in ("candidate_functions", "candidate_source_variable_records"):
        value = scope[field]
        if (not isinstance(value, dict) or set(value) != set(SPLITS)
                or any(type(v) is not int or v < 0 for v in value.values())):
            raise ValueError("Invalid split denominators")
    if (not isinstance(scope["cases"], list)
            or not all(k in scope for k in ("capped_out_functions", "excluded_clone_functions"))):
        raise ValueError("Invalid scope function lists")
    rows, seen, project_splits = [], set(), {}
    for case in scope["cases"]:
        project, split = case["project_id"], case["split"]
        if (split not in SPLITS or case["profile"] != "O0" or project in FORBIDDEN_PROJECTS
                or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", project) or case["function_id"] in seen
                or project_splits.get(project, split) != split):
            raise ValueError("Invalid v3 case")
        project_splits[project] = split
        seen.add(case["function_id"])
        labels_path = inventory / (case["project_id"] + "-O0.labels.json")
        labels = read(labels_path)
        function, = [f for f in labels["functions"] if f["function_id"] == case["function_id"]]
        variables = [v for v in labels["variables"] if v["function_id"] == case["function_id"]]
        if (function["address"] != case["function_address"] or function["name"] != case["function_name"]
                or function["split"] != split or len(variables) != case["source_variable_records"]
                or type(case["source_variable_records"]) is not int
                or type(case["mapped_source_variable_records"]) is not int
                or sum(v["status"] == "mapped" for v in variables) != case["mapped_source_variable_records"]
                or labels["binary_sha256"] != case["binary_sha256"]
                or runtime_path(case["binary"]).resolve() != (inventory / (project + "-O0.elf")).resolve()
                or sha(runtime_path(case["binary"])) != case["binary_sha256"]):
            raise ValueError("Scope and inventory differ: " + case["function_id"])
        rows.append((case, variables, labels_path))
    if (any(sum(c["split"] == split for c, _, _ in rows) != scope["candidate_functions"][split] for split in SPLITS)
            or any(sum(len(v) for c, v, _ in rows if c["split"] == split)
                   != scope["candidate_source_variable_records"][split] for split in SPLITS)):
        raise ValueError("Scope denominators differ")
    return inventory, extension, scope, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True, help="labels-* directory of the v3 corpus")
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
    tygr = ROOT / "tygr_original"
    vocabulary = UpstreamLabels(tygr).vocabulary
    vocabulary_bytes = (json.dumps(vocabulary, indent=2, allow_nan=False) + "\n").encode("ascii")
    if hashlib.sha256(vocabulary_bytes).hexdigest() != v1["vocabulary"]["sha256"]:
        raise ValueError("Vocabulary differs from the v1 reviewed dataset")
    output = scratch / ("route-b-type-v3-graphs-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
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
            ROOT / "scripts/verify_type_v3_export.py", PREREGISTRATION):
        target = copies / path.name
        target.write_bytes(path.read_bytes())
        pins[linux(path)] = pins[linux(target)] = sha(path)
    # The passive verifier runs from the dataset directory, like the v1 verify_export.py.
    (output / "verify_type_v3_export.py").write_bytes((ROOT / "scripts/verify_type_v3_export.py").read_bytes())
    sources = {p.relative_to(tygr).as_posix(): sha(p) for p in (tygr / "src").rglob("*.py")}
    write(output / "vocabulary.json", vocabulary)
    if sha(output / "vocabulary.json") != v1["vocabulary"]["sha256"]:
        raise ValueError("Vocabulary differs from the v1 reviewed dataset")
    for path in (mapping / "independent-audit.json", inventory / "export-scope.json", inventory / "summary.json",
            extension / "manifest.json", extension / "selection.json", scratch / V1_DATASET / "dataset.json"):
        pins[linux(path)] = sha(path)
    jobs = []
    print("V3 graph dataset output: " + str(output), flush=True)
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
    write(output / "plan.json", {"schema": "symbai.type_v3_graph_dataset_plan.v1", "pins": pins,
        "original_source_inventory": sources, "function_timeout_seconds": args.function_timeout,
        "planned_functions": len(jobs), "candidate_source_variables": planned_variables,
        "inventory": linux(inventory), "mapping_prerequisite": linux(mapping),
        "preregistration_sha256": PREREGISTRATION_SHA256, "selection_sha256": sha(extension / "selection.json"),
        "evaluation_projects_selected": False,
        "admission": "v1 rules: independent fixed CFA correspondence; exclude whole structs, missing locations, graph errors, duplicate row claims and conflicting shared-node labels. Source-variable weights sum to one."})
    records, samples = [], []
    write(output / "records.json", records)
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
    counts = {}
    for split in SPLITS:
        chosen = [r for r in records if r["split"] == split]
        counts[split] = {"planned_functions": sum(c["split"] == split for c, _, _ in cases),
            "completed_functions": len(chosen), "exported_functions": sum(r["status"] == "exported" for r in chosen),
            "candidate_source_variables": sum(len(v) for c, v, _ in cases if c["split"] == split),
            "admitted_source_variables": sum(r.get("admitted_source_variables", 0) for r in chosen),
            "supervised_value_rows": sum(r.get("supervised_value_rows", 0) for r in chosen)}
    totals = {key: {split: counts[split][key] for split in SPLITS} for key in counts["train"]}
    projects = {split: sorted({c["project_id"] for c, _, _ in cases if c["split"] == split}) for split in SPLITS}
    dataset = {"schema": "symbai.type_v3_graph_dataset.v1", "samples": samples,
        "vocabulary": {"path": "vocabulary.json", "sha256": sha(output / "vocabulary.json")},
        "relation_count": 60, "feature_width": 31, "training_allowed": False,
        "evaluation_projects_executed": False, "labels_separate_from_features": True,
        "preregistration_sha256": PREREGISTRATION_SHA256, "selection_sha256": sha(extension / "selection.json"),
        "admitted_source_variables": totals["admitted_source_variables"],
        "supervised_value_rows": totals["supervised_value_rows"], "exported_functions": totals["exported_functions"],
        "projects": projects}
    by_project = {}
    for project in sorted({c["project_id"] for c, _, _ in cases}):
        chosen = [r for r in records if r["project_id"] == project]
        by_project[project] = {"planned_functions": sum(c["project_id"] == project for c, _, _ in cases),
            "split": next(c["split"] for c, _, _ in cases if c["project_id"] == project),
            "completed_functions": len(chosen),
            "exported_functions": sum(r["status"] == "exported" for r in chosen),
            "candidate_source_variables": sum(len(v) for c, v, _ in cases if c["project_id"] == project),
            "admitted_source_variables": sum(r.get("admitted_source_variables", 0) for r in chosen),
            "supervised_value_rows": sum(r.get("supervised_value_rows", 0) for r in chosen)}
    summary = {"schema": "symbai.type_v3_graph_dataset_summary.v1", "prepare_only": args.prepare_only,
        **totals, "projects": by_project,
        "exclusion_reasons": dict(Counter(reason for r in records for v in r.get("variables", []) for reason in v["reasons"])),
        "exclusion_reasons_by_split": {split: dict(Counter(reason for r in records if r["split"] == split
            for v in r.get("variables", []) for reason in v["reasons"])) for split in SPLITS},
        "development_minimum_met": totals["admitted_source_variables"]["development"] >= 150,
        "new_training_admitted": totals["admitted_source_variables"]["train"],
        "evaluation_projects_executed": False, "model_loaded": False, "training_performed": False,
        "source_integrity_unchanged": True, "output": str(output),
        "scope": "Pre-registered v3 new training and development; unchanged v1/v2 admission, partial execution, complete 60-relation preprocessing."}
    dataset["project_counts"] = by_project
    write(output / "dataset.json", dataset)
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not args.prepare_only and (not samples or len(records) != len(jobs)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
