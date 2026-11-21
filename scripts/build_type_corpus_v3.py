#!/usr/bin/env python3
"""Build type-corpus v3 ELF profiles and inventory labels without training."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis import type_corpus as type_corpus

PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md"
PREREGISTRATION_SHA256 = "efb974c46039dfb14219687f6390f1d7b45a6226142141a69d42388716bf9392"
FUNCTION_CAP = 60
SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
REUSED_V1_INVENTORY = (SCRATCH / "route-b-type-corpus-v2-20261119T220534466210Z"
                       / "labels-20261119T220848049235Z")
REUSED_V2_INVENTORY = (SCRATCH / "route-b-type-dev-extension-20261120T192757085592Z"
                       / "labels-20261120T195143703618Z")
REUSED_V1_PROJECTS = ("inih", "rxi_map", "jsmn", "optparse")
REUSED_V2_PROJECTS = ("sds", "tiny_regex_c")
REUSED_INVENTORIES = (
    (REUSED_V1_INVENTORY, REUSED_V1_PROJECTS),
    (REUSED_V2_INVENTORY, REUSED_V2_PROJECTS),
)
EXPECTED_NEW_DEVELOPMENT_ID = "md4c"
EXPECTED_REUSED_DEVELOPMENT_IDS = ("json_parser", "parson")
EXPECTED_REUSED_TRAINING_IDS = REUSED_V1_PROJECTS + REUSED_V2_PROJECTS


def write(path, value):
    text = json.dumps(value, indent=2, allow_nan=False) + "\n"
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def require_digest(path, expected, message):
    path = type_corpus.runtime_path(path)
    try:
        digest = type_corpus.sha(path)
    except OSError:
        raise ValueError(message)
    if digest != expected:
        raise ValueError(message)
    return digest


def validate_corpus(corpus, preregistration, expected_sha, reused_inventories):
    corpus = type_corpus.runtime_path(corpus)
    preregistration = type_corpus.runtime_path(preregistration)
    manifest = json.loads((corpus / "manifest.json").read_bytes())
    if manifest.get("schema") != "symbai.type_corpus_v3_manifest.v1":
        raise ValueError("Unexpected corpus manifest schema")
    require_digest(corpus / "selection.json", manifest["selection_sha256"],
                   "selection.json does not match the pinned digest")
    selection = json.loads((corpus / "selection.json").read_bytes())
    if selection.get("preregistration_sha256") != expected_sha:
        raise ValueError("selection preregistration digest mismatch")
    if type_corpus.sha(preregistration) != expected_sha:
        raise ValueError("preregistration file digest mismatch")
    for path, digest in manifest["implementation_pins"].items():
        require_digest(path, digest, "Pinned implementation or original type rules changed")
    for row in manifest["new_projects"]:
        if row["status"] != "pinned":
            raise ValueError("New project is not pinned")
        directory = type_corpus.runtime_path(row["source_directory"])
        for relative, digest in row["source_files"].items():
            require_digest(directory / relative, digest, "Pinned source changed")
    for row in manifest["reused_development_projects"]:
        directory = type_corpus.runtime_path(row["source_directory"])
        for relative, digest in row["source_files"].items():
            require_digest(directory / relative, digest, "Pinned source changed")
    sel_new = [(row["project_id"], row["split"]) for row in selection["new_projects"]]
    man_new = [(row["project_id"], row["split"]) for row in manifest["new_projects"]]
    man_new_dev = tuple(project_id for project_id, split in man_new if split == "development")
    man_reused_dev = tuple(row["project_id"] for row in manifest["reused_development_projects"])
    sel_reused_dev = tuple(selection.get("reused_development_projects") or ())
    sel_reused_train = tuple(selection.get("reused_training_projects") or ())
    if (sel_new != man_new or man_new_dev != (EXPECTED_NEW_DEVELOPMENT_ID,)
            or man_reused_dev != EXPECTED_REUSED_DEVELOPMENT_IDS
            or sel_reused_dev != EXPECTED_REUSED_DEVELOPMENT_IDS
            or sel_reused_train != EXPECTED_REUSED_TRAINING_IDS):
        raise ValueError("Split sets do not match the selection")
    require_digest(manifest["harness"], manifest["harness_sha256"], "Link-only harness changed")
    for entry in manifest["reused_exports"].values():
        directory = type_corpus.runtime_path(entry["directory"])
        require_digest(directory / "dataset.json", entry["dataset_sha256"],
                       "Reused export digest mismatch")
        require_digest(directory / "independent-export-audit.json", entry["audit_sha256"],
                       "Reused export digest mismatch")
    provided = []
    for directory, project_ids in reused_inventories:
        directory = type_corpus.runtime_path(directory)
        for project_id in project_ids:
            path = directory / (project_id + "-O0.labels.json")
            if not path.is_file():
                raise ValueError("Reused inventory labels file missing")
            provided.append(project_id)
    if tuple(provided) != EXPECTED_REUSED_TRAINING_IDS:
        raise ValueError("Reused inventory labels file missing")
    families = selection["author_families"]
    train_families = {name.casefold() for name in families["train"]}
    development_families = {name.casefold() for name in families["development"]}
    if train_families & development_families:
        raise ValueError("Development families overlap training families")
    return manifest, selection


def _plan_item(row, profile, purpose):
    relative_include = row.get("include_directory") or "."
    return {
        "project_id": row["project_id"],
        "family": row["family"],
        "split": row["split"],
        "role": row.get("role"),
        "profile": profile,
        "purpose": purpose,
        "source_directory": row["source_directory"],
        "translation_units": list(row["translation_units"]),
        "include_directory": relative_include,
        "source_files": row["source_files"],
    }


def build_plan(manifest):
    by_id = {}
    for row in list(manifest["new_projects"]) + list(manifest["reused_development_projects"]):
        by_id[row["project_id"]] = row
    plan = []
    for row in manifest["new_projects"]:
        if row["split"] == "train":
            plan.append(_plan_item(row, "O0", "training_inventory"))
    for project_id in (EXPECTED_NEW_DEVELOPMENT_ID,) + EXPECTED_REUSED_DEVELOPMENT_IDS:
        plan.append(_plan_item(by_id[project_id], "O0", "development_inventory"))
    return plan


def compile_command(compiler, profile, directory, units, harness, binary):
    command = [compiler, "-std=gnu99", "-" + profile, "-g3", "-gdwarf-4", "-fno-omit-frame-pointer",
               "-fno-inline", "-fkeep-inline-functions", "-fno-builtin", "-no-pie", "-I", str(directory)]
    command += [str(path) for path in units] + [str(harness), "-o", str(binary), "-lm"]
    return command


def unit_paths(row):
    directory = type_corpus.runtime_path(row["source_directory"])
    relative_include = row.get("include_directory") or "."
    if relative_include in (".", ""):
        include = directory
    else:
        include = directory / relative_include
    units = [directory / name for name in row["translation_units"]]
    return directory, include, units


def cap_digest(project_id, name):
    return hashlib.sha256((project_id + ":" + name).encode("utf-8")).hexdigest()


def apply_cap(project_id, functions, limit=FUNCTION_CAP):
    functions = list(functions)
    if len(functions) <= limit:
        return functions, []
    ranked = sorted(functions, key=lambda row: (cap_digest(project_id, row["name"]),
                                                row["address"], row["function_id"]))
    kept_ids = {row["function_id"] for row in ranked[:limit]}
    kept = [row for row in functions if row["function_id"] in kept_ids]
    kept.sort(key=lambda row: (row["address"], row["function_id"]))
    capped_out = [row["function_id"] for row in functions if row["function_id"] not in kept_ids]
    return kept, capped_out


def load_reused_training_functions(reused_inventories):
    records = []
    for directory, project_ids in reused_inventories:
        directory = type_corpus.runtime_path(directory)
        for project_id in project_ids:
            inventory = json.loads((directory / (project_id + "-O0.labels.json")).read_bytes())
            for function in inventory["functions"]:
                record = dict(function)
                record["split"] = "train"
                records.append(record)
    return records


def clone_screen(inventories, reused_inventories):
    records = []
    for inventory in inventories:
        if inventory.get("profile", "O0") == "O0":
            records.extend(inventory["functions"])
    records.extend(load_reused_training_functions(reused_inventories))
    return type_corpus.cross_split_clones(records)


def export_scope(inventories, clone_groups, preregistration_sha256, manifest_sha256, project_order):
    cloned = {}
    for group in clone_groups:
        if "train" not in group["splits"]:
            continue
        for function_id in group["function_ids"]:
            cloned.setdefault(function_id, []).append(group)
    cases, excluded = [], []
    capped_out_functions = {}
    inventories_by_id = {}
    for inventory in inventories:
        if inventory.get("profile", "O0") != "O0":
            continue
        inventories_by_id[inventory["project_id"]] = inventory
    for project_id in list(project_order) + [row["project_id"] for row in inventories
                                             if row["project_id"] not in project_order]:
        inventory = inventories_by_id.get(project_id)
        if inventory is None or project_id in capped_out_functions:
            continue
        kept, capped_out = apply_cap(inventory["project_id"], inventory["functions"])
        kept_ids = {row["function_id"] for row in kept}
        capped_out_functions[project_id] = {
            "total_functions": len(inventory["functions"]),
            "kept": len(kept),
            "capped_out_function_ids": capped_out,
        }
        variable_counts, mapped_counts = {}, {}
        for variable in inventory["variables"]:
            function_id = variable["function_id"]
            variable_counts[function_id] = variable_counts.get(function_id, 0) + 1
            if variable["status"] == "mapped":
                mapped_counts[function_id] = mapped_counts.get(function_id, 0) + 1
        for function in kept:
            function_id = function["function_id"]
            record = {
                "function_id": function_id,
                "project_id": inventory["project_id"],
                "split": "train" if inventory["split"] == "train" else "development",
                "function_name": function["name"],
                "function_address": function["address"],
                "binary": inventory["binary"],
                "binary_sha256": inventory["binary_sha256"],
                "profile": "O0",
                "source_variable_records": variable_counts.get(function_id, 0),
                "mapped_source_variable_records": mapped_counts.get(function_id, 0),
            }
            groups = cloned.get(function_id)
            if groups and record["split"] == "development":
                excluded.append({
                    "function_id": function_id,
                    "project_id": record["project_id"],
                    "split": "development",
                    "function_name": record["function_name"],
                    "function_address": record["function_address"],
                    "binary": record["binary"],
                    "binary_sha256": record["binary_sha256"],
                    "clone_groups": groups,
                })
            else:
                cases.append(record)
    order = {project_id: index for index, project_id in enumerate(project_order)}
    train_rank = {project_id: index for index, project_id in enumerate(
        [row["project_id"] for row in inventories if row["split"] == "train"])}
    development_rank = {project_id: index for index, project_id in enumerate(
        [row["project_id"] for row in inventories if row["split"] != "train"])}

    def case_key(row):
        split_rank = 0 if row["split"] == "train" else 1
        if row["project_id"] in order:
            project_rank = order[row["project_id"]]
        elif row["split"] == "train":
            project_rank = train_rank.get(row["project_id"], len(order))
        else:
            project_rank = len(order) + development_rank.get(row["project_id"], 0)
        return (split_rank, project_rank, row["function_address"], row["function_id"])

    cases.sort(key=case_key)
    excluded.sort(key=case_key)
    candidate_functions = {"train": 0, "development": 0}
    candidate_source_variable_records = {"train": 0, "development": 0}
    for row in cases:
        candidate_functions[row["split"]] += 1
        candidate_source_variable_records[row["split"]] += row["source_variable_records"]
    return {
        "schema": "symbai.type_v3_export_scope.v1",
        "cases": cases,
        "capped_out_functions": capped_out_functions,
        "excluded_clone_functions": excluded,
        "candidate_functions": candidate_functions,
        "candidate_source_variable_records": candidate_source_variable_records,
        "preregistration_sha256": preregistration_sha256,
        "manifest_sha256": manifest_sha256,
        "evaluation_projects_selected": False,
        "labels_in_scope": False,
    }


def run_inventory(corpus, output, prepare_only, preregistration=None, expected_sha=None,
                  reused_inventories=None):
    if preregistration is None:
        preregistration = PREREGISTRATION
    if expected_sha is None:
        expected_sha = PREREGISTRATION_SHA256
    if reused_inventories is None:
        reused_inventories = REUSED_INVENTORIES
    corpus = type_corpus.runtime_path(corpus)
    output = type_corpus.runtime_path(output)
    manifest, _selection = validate_corpus(corpus, preregistration, expected_sha, reused_inventories)
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    labels = type_corpus.UpstreamLabels(ROOT / "tygr_original")
    write(output / "label-vocabulary.json", labels.vocabulary)
    compiler = shutil.which("gcc") if not prepare_only else None
    plan_rows = build_plan(manifest)
    write(output / "plan.json", {
        "schema": "symbai.type_v3_build_plan.v1",
        "manifest_sha256": type_corpus.sha(corpus / "manifest.json"),
        "compiler": compiler,
        "compiler_profiles": manifest["compiler_profiles"],
        "function_cap": FUNCTION_CAP,
        "label_vocabulary_size": len(labels.vocabulary),
        "builds": plan_rows,
        "scope": "Type corpus v3 data inventory only; no graph extraction, model loading/training, property analysis or scheduling. Sealed evaluation projects are not compiled or labelled.",
    })
    print("Type corpus v3 label inventory output: " + str(output), flush=True)
    if prepare_only:
        return
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True).stdout
    with (output / "compiler-version.txt").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(version)
    harness = type_corpus.runtime_path(manifest["harness"])
    rows, inventories = [], []
    for item in plan_rows:
        directory, include, units = unit_paths(item)
        name = item["project_id"] + "-" + item["profile"]
        binary = output / (name + ".elf")
        command = compile_command(compiler, item["profile"], include, units, harness, binary)
        row = {"project_id": item["project_id"], "family": item["family"], "split": item["split"],
               "role": item.get("role"), "profile": item["profile"], "purpose": item["purpose"],
               "command": command}
        try:
            with (output / (name + ".build.log")).open("w", encoding="utf-8", newline="\n") as stream:
                subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True,
                               timeout=90, cwd=output)
            inventory = type_corpus.inspect_binary(binary, {
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
                "project_id": item["project_id"], "split": item["split"],
                "profile": item["profile"], "binary": str(binary),
                "binary_sha256": inventory["binary_sha256"],
                "functions": inventory["functions"], "variables": inventory["variables"],
            })
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        rows.append(row)
        write(output / "records.json", rows)
        print(name + ": " + row["status"], flush=True)
    clones = clone_screen(inventories, reused_inventories)
    write(output / "cross-split-clone-review.json", clones)
    project_order = [item["project_id"] for item in plan_rows]
    scope = export_scope(inventories, clones, expected_sha, type_corpus.sha(corpus / "manifest.json"),
                         project_order)
    write(output / "export-scope.json", scope)
    counts = {}
    for inventory in inventories:
        kept, _capped_out = apply_cap(inventory["project_id"], inventory["functions"])
        kept_ids = {row["function_id"] for row in kept}
        counts[inventory["project_id"]] = {
            "before_cap": {
                "functions": len(inventory["functions"]),
                "variable_records": len(inventory["variables"]),
            },
            "after_cap": {
                "functions": len(kept),
                "variable_records": sum(1 for variable in inventory["variables"]
                                        if variable["function_id"] in kept_ids),
            },
        }
    inventoried = sum(row["status"] == "inventoried" for row in rows)
    summary = {
        "schema": "symbai.type_v3_inventory.v1",
        "planned_builds": len(plan_rows),
        "inventoried_builds": inventoried,
        "failed_builds": sum(row["status"] == "failed" for row in rows),
        "o0_project_counts": counts,
        "cross_split_clone_review_groups": len(clones),
        "excluded_clone_function_count": len(scope["excluded_clone_functions"]),
        "training_allowed": False,
        "graph_extraction_performed": False,
        "model_loaded": False,
        "output": str(output),
        "cases": rows,
    }
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if inventoried != len(plan_rows):
        raise SystemExit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    corpus_dir = type_corpus.runtime_path(args.corpus).resolve()
    corpus_dir.relative_to(SCRATCH)
    if args.output is None:
        output = corpus_dir / ("labels-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    else:
        output = type_corpus.runtime_path(args.output).resolve()
        output.relative_to(corpus_dir)
    validate_corpus(corpus_dir, PREREGISTRATION, PREREGISTRATION_SHA256, REUSED_INVENTORIES)
    if not args.prepare_only and (not sys.platform.startswith("linux") or shutil.which("gcc") is None):
        parser.error("Build native ELF profiles in WSL using existing gcc; --prepare-only is portable")
    run_inventory(corpus_dir, output, args.prepare_only, PREREGISTRATION, PREREGISTRATION_SHA256,
                  REUSED_INVENTORIES)


if __name__ == "__main__":
    main()
