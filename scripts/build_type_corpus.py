#!/usr/bin/env python3
"""Build twelve small native ELF profiles and inventory real labels without training."""
import argparse
from collections import Counter
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


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    source = corpus.runtime_path(args.corpus).resolve()
    source.relative_to((ROOT.parent / ".scratch/selective_analysis").resolve())
    manifest = json.loads((source / "manifest.json").read_bytes())
    if manifest["schema"] != "symbai.type_corpus_manifest.v1" or any(row["status"] != "pinned" for row in manifest["projects"]):
        raise ValueError("All six pinned source projects are required")
    corpus.validate_splits(manifest["projects"])
    for path, expected in manifest["implementation_pins"].items():
        if corpus.sha(corpus.runtime_path(path)) != expected:
            raise ValueError("Pinned implementation or original type rules changed")
    if corpus.sha(source / manifest["harness"]) != manifest["harness_sha256"]:
        raise ValueError("Link-only harness changed")
    for row in manifest["projects"]:
        directory = corpus.runtime_path(row["source_directory"])
        for relative, expected in row["source_files"].items():
            if corpus.sha(directory / relative) != expected:
                raise ValueError("Pinned source changed")
        if row["bridge"] and corpus.sha(source / row["bridge"]) != row["bridge_sha256"]:
            raise ValueError("Header bridge changed")
    if not args.prepare_only and (not sys.platform.startswith("linux") or shutil.which("gcc") is None):
        parser.error("Build native ELF profiles in WSL using existing gcc; --prepare-only is portable")
    output = source / ("labels-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    labels = corpus.UpstreamLabels(ROOT / "tygr_original")
    write(output / "label-vocabulary.json", labels.vocabulary)
    compiler = shutil.which("gcc") if not args.prepare_only else None
    write(output / "plan.json", {"schema": "symbai.type_label_build_plan.v1", "manifest_sha256": corpus.sha(source / "manifest.json"),
        "compiler": compiler, "compiler_profiles": manifest["compiler_profiles"], "label_vocabulary_size": len(labels.vocabulary),
        "scope": "Data inventory only; no graph extraction, model loading/training, property analysis or scheduling. Existing diagnostic projects excluded."})
    print("Type label inventory output: " + str(output), flush=True)
    rows, primary_functions, primary_labels = [], [], []
    if not args.prepare_only:
        version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True).stdout
        (output / "compiler-version.txt").write_text(version, encoding="utf-8")
        for project in manifest["projects"]:
            directory = corpus.runtime_path(project["source_directory"])
            units = [directory / name for name in project["translation_units"]]
            if project["bridge"]:
                units.append(source / project["bridge"])
            for profile in manifest["compiler_profiles"]:
                name = project["project_id"] + "-" + profile
                binary = output / (name + ".elf")
                command = [compiler, "-std=gnu99", "-" + profile, "-g3", "-gdwarf-4", "-fno-omit-frame-pointer",
                    "-fno-inline", "-fkeep-inline-functions", "-fno-builtin", "-no-pie", "-I", str(directory)]
                command += [str(path) for path in units] + [str(source / manifest["harness"]), "-o", str(binary)]
                row = {"project_id": project["project_id"], "family": project["family"], "split": project["split"], "profile": profile,
                       "command": command}
                try:
                    with (output / (name + ".build.log")).open("w", encoding="utf-8") as stream:
                        subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90, cwd=output)
                    inventory = corpus.inspect_binary(binary, project, labels)
                    write(output / (name + ".labels.json"), inventory)
                    row.update(status="inventoried", binary_sha256=corpus.sha(binary),
                        functions=len(inventory["functions"]), variable_records=len(inventory["variables"]),
                        mapped_variables=sum(v["status"] == "mapped" for v in inventory["variables"]),
                        location_attribute_present=sum(v["location_attribute_present"] for v in inventory["variables"]),
                        label_histogram=inventory["mapped_label_histogram"])
                    if not inventory["functions"]:
                        raise ValueError("No source-owned function definitions found")
                    if profile == "O0":
                        primary_functions.extend(inventory["functions"])
                        primary_labels.extend(dict(v, split=project["split"]) for v in inventory["variables"])
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
                rows.append(row)
                write(output / "records.json", rows)
                print(name + ": " + row["status"], flush=True)
    clones = corpus.cross_split_clones(primary_functions)
    write(output / "cross-split-clone-review.json", clones)
    per_split = {split: dict(Counter(row["label"] for row in primary_labels if row["split"] == split and row["status"] == "mapped"))
                 for split in ("train", "development", "evaluation")}
    summary = {"schema": "symbai.type_label_inventory_summary.v1", "prepare_only": args.prepare_only,
        "planned_builds": 12, "inventoried_builds": sum(row["status"] == "inventoried" for row in rows), "cases": rows,
        "primary_counting_profile": "O0", "O1_is_not_additional_independent_data": True,
        "primary_functions": len(primary_functions), "primary_variable_records": len(primary_labels),
        "primary_mapped_labels_by_split": per_split, "cross_split_clone_review_groups": len(clones),
        "function_fingerprints_unavailable": sum(row["fingerprints"] is None for row in primary_functions),
        "training_allowed": False, "graph_and_use_site_mapping_validated": False,
        "training_blockers": ["graph_and_value_readout_validation_pending", "small_exploratory_split_not_formal_generalization_evidence"],
        "model_loaded": False, "model_training_performed": False, "neural_benefit_measured": False, "output": str(output)}
    if clones:
        summary["training_blockers"].append("cross_split_clone_review_required")
    if not args.prepare_only and summary["inventoried_builds"] != 12:
        summary["training_blockers"].append("incomplete_compilation_or_inventory")
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not args.prepare_only and summary["inventoried_builds"] != 12:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
