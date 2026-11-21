#!/usr/bin/env python3
"""Build development-extension ELF profiles and inventory labels without training."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis import type_corpus as corpus

PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v2_preregistration.md"
PREREGISTRATION_SHA256 = "945832e331c1c90cb345d3476cf174b46def6140b3b4694ac4635521b3ff3fdf"
EXPECTED_DEVELOPMENT_IDS = ("sds", "tiny_regex_c", "json_parser", "parson")
EXPECTED_DEVELOPMENT_ROLES = ("primary", "primary", "primary", "backup")
EXPECTED_TRAINING_IDS = ("inih", "rxi_map", "jsmn")
SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()


def write(path, value):
    text = json.dumps(value, indent=2, allow_nan=False) + "\n"
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def require_digest(path, expected, message):
    path = corpus.runtime_path(path)
    try:
        digest = corpus.sha(path)
    except OSError:
        raise ValueError(message)
    if digest != expected:
        raise ValueError(message)
    return digest


def validate_extension(extension, preregistration, expected_sha):
    extension = corpus.runtime_path(extension)
    preregistration = corpus.runtime_path(preregistration)
    manifest = json.loads((extension / "manifest.json").read_bytes())
    if manifest.get("schema") != "symbai.type_dev_extension_manifest.v1":
        raise ValueError("Unexpected extension manifest schema")
    require_digest(extension / "selection.json", manifest["selection_sha256"],
                   "selection.json does not match the pinned digest")
    selection = json.loads((extension / "selection.json").read_bytes())
    if selection.get("preregistration_sha256") != expected_sha:
        raise ValueError("selection preregistration digest mismatch")
    if corpus.sha(preregistration) != expected_sha:
        raise ValueError("preregistration file digest mismatch")
    for path, digest in manifest["implementation_pins"].items():
        require_digest(path, digest, "Pinned implementation or original type rules changed")
    development = manifest["development_projects"]
    training = manifest["training_projects"]
    if (tuple(row["project_id"] for row in development) != EXPECTED_DEVELOPMENT_IDS
            or tuple(row["role"] for row in development) != EXPECTED_DEVELOPMENT_ROLES):
        raise ValueError("Unexpected development projects or roles")
    for row in development:
        if row["status"] != "pinned":
            raise ValueError("Development project is not pinned")
        if row["split"] != "development":
            raise ValueError("Development project split is not development")
        directory = corpus.runtime_path(row["source_directory"])
        for relative, digest in row["source_files"].items():
            require_digest(directory / relative, digest, "Pinned source changed")
    if tuple(row["project_id"] for row in training) != EXPECTED_TRAINING_IDS:
        raise ValueError("Unexpected training projects")
    for row in training:
        if row["split"] != "train":
            raise ValueError("Training project split is not train")
        directory = corpus.runtime_path(row["source_directory"])
        for relative, digest in row["source_files"].items():
            require_digest(directory / relative, digest, "Pinned source changed")
        if row.get("bridge"):
            require_digest(corpus.runtime_path(row["corpus_directory"]) / row["bridge"],
                           row["bridge_sha256"], "Header bridge changed")
        require_digest(corpus.runtime_path(row["corpus_directory"]) / "manifest.json",
                       selection["parent_manifest_sha256"], "Parent corpus manifest digest mismatch")
    require_digest(manifest["harness"], manifest["harness_sha256"], "Link-only harness changed")
    development_families = {row["family"].casefold() for row in development}
    training_families = {row["family"].casefold() for row in training}
    if development_families & training_families:
        raise ValueError("Development families overlap training families")
    return manifest, selection


def _plan_item(row, profile, purpose):
    item = {
        "project_id": row["project_id"],
        "family": row["family"],
        "split": row["split"],
        "role": row.get("role"),
        "profile": profile,
        "purpose": purpose,
        "source_directory": row["source_directory"],
        "translation_units": list(row["translation_units"]),
        "bridge": row.get("bridge"),
        "source_files": row["source_files"],
    }
    if row.get("corpus_directory"):
        item["corpus_directory"] = row["corpus_directory"]
    return item


def recorded_failure(extension, evidence, project_id):
    extension = corpus.runtime_path(extension).resolve()
    evidence = corpus.runtime_path(evidence).resolve()
    evidence.relative_to(extension)
    records = json.loads((evidence / "records.json").read_bytes())
    failed = [r for r in records if r["project_id"] == project_id and r["purpose"] == "development_inventory"]
    if not failed or any(r["status"] != "failed" for r in failed):
        raise ValueError("No recorded build failure for " + project_id)
    return {"project_id": project_id, "failure_evidence": str(evidence),
            "failure_records_sha256": corpus.sha(evidence / "records.json"),
            "failures": [{"profile": r["profile"], "error": r["error"]} for r in failed]}


def failed_primary_evidence(extension, evidence, primary, backup_evidence=None):
    """Pre-registered backup rule: a primary may be replaced only after a recorded build failure.

    If the backup's own build failure is also recorded, the backup is dropped as well and
    no further substitution is made (the pre-registration allows none).
    """
    if primary not in EXPECTED_DEVELOPMENT_IDS[:3]:
        raise ValueError("Only a primary development project can be replaced")
    result = {"replaced_primary": primary, "primary_failure": recorded_failure(extension, evidence, primary),
              "backup_failure": None}
    if backup_evidence is not None:
        result["backup_failure"] = recorded_failure(extension, backup_evidence, EXPECTED_DEVELOPMENT_IDS[3])
    return result


def build_plan(manifest, include_backup, replaced=None):
    plan = []
    for row in manifest["development_projects"]:
        if row["project_id"] == replaced:
            continue
        if row["role"] == "backup" and not include_backup:
            continue
        for profile in manifest["compiler_profiles"]:
            plan.append(_plan_item(row, profile, "development_inventory"))
    for row in manifest["training_projects"]:
        plan.append(_plan_item(row, "O0", "clone_screen_reference"))
    return plan


def compile_command(compiler, profile, directory, units, harness, binary):
    command = [compiler, "-std=gnu99", "-" + profile, "-g3", "-gdwarf-4", "-fno-omit-frame-pointer",
               "-fno-inline", "-fkeep-inline-functions", "-fno-builtin", "-no-pie", "-I", str(directory)]
    command += [str(path) for path in units] + [str(harness), "-o", str(binary)]
    return command


def unit_paths(row, extension):
    directory = corpus.runtime_path(row["source_directory"])
    units = [directory / name for name in row["translation_units"]]
    if row.get("bridge"):
        if row.get("corpus_directory"):
            base = corpus.runtime_path(row["corpus_directory"])
        else:
            base = corpus.runtime_path(extension)
        units.append(base / row["bridge"])
    return directory, units


def export_scope(inventories, clone_groups, preregistration_sha256, manifest_sha256, backup_included):
    cloned = {}
    for group in clone_groups:
        if "train" not in group["splits"]:
            continue
        for function_id in group["function_ids"]:
            cloned.setdefault(function_id, []).append(group)
    cases, excluded = [], []
    for inventory in inventories:
        if inventory["split"] != "development" or inventory["profile"] != "O0":
            continue
        variable_counts, mapped_counts = {}, {}
        for variable in inventory["variables"]:
            function_id = variable["function_id"]
            variable_counts[function_id] = variable_counts.get(function_id, 0) + 1
            if variable["status"] == "mapped":
                mapped_counts[function_id] = mapped_counts.get(function_id, 0) + 1
        for function in inventory["functions"]:
            function_id = function["function_id"]
            record = {
                "function_id": function_id,
                "project_id": inventory["project_id"],
                "role": inventory["role"],
                "split": "development",
                "function_name": function["name"],
                "function_address": function["address"],
                "binary": inventory["binary"],
                "binary_sha256": inventory["binary_sha256"],
                "profile": "O0",
                "source_variable_records": variable_counts.get(function_id, 0),
                "mapped_source_variable_records": mapped_counts.get(function_id, 0),
            }
            groups = cloned.get(function_id)
            if groups:
                excluded.append({
                    "function_id": function_id,
                    "project_id": record["project_id"],
                    "role": record["role"],
                    "function_name": record["function_name"],
                    "function_address": record["function_address"],
                    "binary": record["binary"],
                    "binary_sha256": record["binary_sha256"],
                    "clone_groups": groups,
                })
            else:
                cases.append(record)
    order = {project_id: index for index, project_id in enumerate(EXPECTED_DEVELOPMENT_IDS)}
    key = lambda row: (order.get(row["project_id"], len(order)), row["function_address"])
    cases.sort(key=key)
    excluded.sort(key=key)
    return {
        "schema": "symbai.type_dev_export_scope.v1",
        "cases": cases,
        "excluded_clone_functions": excluded,
        "candidate_functions": len(cases),
        "candidate_source_variable_records": sum(row["source_variable_records"] for row in cases),
        "preregistration_sha256": preregistration_sha256,
        "manifest_sha256": manifest_sha256,
        "backup_included": backup_included,
        "evaluation_projects_selected": False,
        "labels_in_scope": False,
    }


def run_inventory(extension, output, prepare_only, include_backup, preregistration=None, expected_sha=None,
                  replacement=None):
    if preregistration is None:
        preregistration = PREREGISTRATION
    if expected_sha is None:
        expected_sha = PREREGISTRATION_SHA256
    extension = corpus.runtime_path(extension)
    output = corpus.runtime_path(output)
    manifest, _selection = validate_extension(extension, preregistration, expected_sha)
    replaced = replacement["replaced_primary"] if replacement else None
    if replaced:
        include_backup = replacement["backup_failure"] is None
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    labels = corpus.UpstreamLabels(ROOT / "tygr_original")
    write(output / "label-vocabulary.json", labels.vocabulary)
    compiler = shutil.which("gcc") if not prepare_only else None
    plan_rows = build_plan(manifest, include_backup, replaced)
    write(output / "plan.json", {
        "schema": "symbai.type_dev_extension_build_plan.v1",
        "manifest_sha256": corpus.sha(extension / "manifest.json"),
        "compiler": compiler,
        "compiler_profiles": manifest["compiler_profiles"],
        "include_backup": include_backup,
        "backup_replacement": replacement,
        "label_vocabulary_size": len(labels.vocabulary),
        "builds": plan_rows,
        "scope": "Development-extension data inventory only; no graph extraction, model loading/training, property analysis or scheduling.",
    })
    print("Type development-extension label inventory output: " + str(output), flush=True)
    if prepare_only:
        return
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True).stdout
    with (output / "compiler-version.txt").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(version)
    harness = corpus.runtime_path(manifest["harness"])
    rows, inventories = [], []
    for item in plan_rows:
        directory, units = unit_paths(item, extension)
        name = item["project_id"] + "-" + item["profile"]
        binary = output / (name + ".elf")
        command = compile_command(compiler, item["profile"], directory, units, harness, binary)
        row = {"project_id": item["project_id"], "family": item["family"], "split": item["split"],
               "role": item.get("role"), "profile": item["profile"], "purpose": item["purpose"],
               "command": command}
        try:
            with (output / (name + ".build.log")).open("w", encoding="utf-8", newline="\n") as stream:
                subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True,
                               timeout=90, cwd=output)
            inventory = corpus.inspect_binary(binary, {
                "project_id": item["project_id"],
                "source_directory": str(directory),
                "source_files": item["source_files"],
                "split": item["split"],
            }, labels)
            write(output / (name + ".labels.json"), inventory)
            if not inventory["functions"]:
                raise ValueError("No source-owned function definitions found")
            row.update(status="inventoried", binary_sha256=inventory["binary_sha256"],
                       functions=len(inventory["functions"]),
                       variable_records=len(inventory["variables"]),
                       mapped_variables=sum(v["status"] == "mapped" for v in inventory["variables"]),
                       location_attribute_present=sum(v["location_attribute_present"] for v in inventory["variables"]),
                       label_histogram=inventory["mapped_label_histogram"])
            inventories.append({
                "project_id": item["project_id"], "role": item.get("role"), "split": item["split"],
                "profile": item["profile"], "binary": str(binary),
                "binary_sha256": inventory["binary_sha256"],
                "functions": inventory["functions"], "variables": inventory["variables"],
            })
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        rows.append(row)
        write(output / "records.json", rows)
        print(name + ": " + row["status"], flush=True)
    o0_functions = []
    for inventory in inventories:
        if inventory["profile"] == "O0":
            o0_functions.extend(inventory["functions"])
    clones = corpus.cross_split_clones(o0_functions)
    write(output / "cross-split-clone-review.json", clones)
    scope = export_scope(inventories, clones, expected_sha, corpus.sha(extension / "manifest.json"),
                         include_backup)
    write(output / "dev-export-scope.json", scope)
    counts = {}
    for item in plan_rows:
        if item["profile"] == "O0":
            counts[item["project_id"]] = {"functions": 0, "variable_records": 0, "mapped_variables": 0}
    for inventory in inventories:
        if inventory["profile"] != "O0":
            continue
        counts[inventory["project_id"]] = {
            "functions": len(inventory["functions"]),
            "variable_records": len(inventory["variables"]),
            "mapped_variables": sum(v["status"] == "mapped" for v in inventory["variables"]),
        }
    inventoried = sum(row["status"] == "inventoried" for row in rows)
    summary = {
        "schema": "symbai.type_dev_extension_inventory.v1",
        "planned_builds": len(plan_rows),
        "inventoried_builds": inventoried,
        "failed_builds": sum(row["status"] == "failed" for row in rows),
        "o0_project_counts": counts,
        "cross_split_clone_review_groups": len(clones),
        "excluded_clone_function_count": len(scope["excluded_clone_functions"]),
        "training_allowed": False,
        "graph_extraction_performed": False,
        "model_loaded": False,
        "backup_included": include_backup,
        "backup_replacement": replacement,
        "output": str(output),
        "cases": rows,
    }
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if inventoried != len(plan_rows):
        raise SystemExit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--include-backup", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replace-failed", metavar="PRIMARY",
                        help="Apply the pre-registered backup rule: drop this primary and build parson")
    parser.add_argument("--failure-evidence", type=Path,
                        help="Earlier labels-* run of this extension recording the primary's build failure")
    parser.add_argument("--backup-failure-evidence", type=Path,
                        help="Earlier labels-* run recording the backup's build failure; drops the backup too")
    args = parser.parse_args(argv)
    if bool(args.replace_failed) != bool(args.failure_evidence):
        parser.error("--replace-failed and --failure-evidence must be given together")
    if args.backup_failure_evidence and not args.replace_failed:
        parser.error("--backup-failure-evidence requires --replace-failed")
    if args.backup_failure_evidence and args.include_backup:
        parser.error("--backup-failure-evidence cannot be combined with --include-backup")
    extension = corpus.runtime_path(args.extension).resolve()
    extension.relative_to(SCRATCH)
    if args.output is None:
        output = extension / ("labels-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    else:
        output = corpus.runtime_path(args.output).resolve()
        output.relative_to(extension)
    validate_extension(extension, PREREGISTRATION, PREREGISTRATION_SHA256)
    replacement = (failed_primary_evidence(extension, args.failure_evidence, args.replace_failed,
                                           args.backup_failure_evidence) if args.replace_failed else None)
    if not args.prepare_only and (not sys.platform.startswith("linux") or shutil.which("gcc") is None):
        parser.error("Build native ELF profiles in WSL using existing gcc; --prepare-only is portable")
    run_inventory(extension, output, args.prepare_only, args.include_backup,
                  PREREGISTRATION, PREREGISTRATION_SHA256, replacement)


if __name__ == "__main__":
    main()
