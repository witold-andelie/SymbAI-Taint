#!/usr/bin/env python3
"""Pin the pre-registered type pilot v2 development projects before any labels.

Only fetches sources and records commits, file hashes and license evidence.
It compiles nothing, reads no DWARF label, extracts no graph and trains nothing.
Training rows are referenced from the reviewed v2 corpus without modification.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v2_preregistration.md"
PARENT_CORPUS = SCRATCH / "route-b-type-corpus-v2-20261119T220534466210Z"
TRAINING_DATASET = SCRATCH / "route-b-type-graphs-20261119T225215150614Z"
# (project_id, repository, role, translation units, headers)
PROJECTS = (
    ("sds", "antirez/sds", "primary", ["sds.c"], ["sds.h", "sdsalloc.h"]),
    ("tiny_regex_c", "kokke/tiny-regex-c", "primary", ["re.c"], ["re.h"]),
    ("json_parser", "json-parser/json-parser", "primary", ["json.c"], ["json.h"]),
    ("parson", "kgabis/parson", "backup", ["parson.c"], ["parson.h"]),
)
EXCLUDED_AUTHOR_FAMILIES = ("benhoyt", "rxi", "zserge", "skeeto", "sheredom", "jwerle")
KNOWN_PROJECT_FAMILIES = ("lua", "xxhash", "stb", "miniz", "utf8proc", "libpng", "jansson", "cjson",
                          "lz4", "bzip2", "xz", "brotli")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def check_families():
    for _, repository, *_ in PROJECTS:
        owner, name = repository.casefold().split("/")
        if owner in EXCLUDED_AUTHOR_FAMILIES or any(f in name.replace("-", "").replace(".", "")
                                                    for f in KNOWN_PROJECT_FAMILIES):
            raise ValueError("Selected project overlaps an excluded family: " + repository)


def license_evidence(directory, files):
    found = {p.name: sha(p) for p in directory.iterdir() if p.is_file()
             and p.name.lower().startswith(("license", "licence", "unlicense", "copying"))}
    if found:
        return found
    embedded = [n for n in files if any(t in (directory / n).read_text(encoding="utf-8", errors="replace").lower()
                for t in ("public domain", "permission is hereby granted", "redistribution and use"))]
    if not embedded:
        raise ValueError("No retained license notice found")
    return {n + " (embedded notice)": files[n] for n in embedded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    check_families()
    parent_manifest = json.loads((PARENT_CORPUS / "manifest.json").read_bytes())
    training_rows = [dict(row, corpus_directory=str(PARENT_CORPUS)) for row in parent_manifest["projects"]
                     if row["split"] == "train"]
    if [r["project_id"] for r in training_rows] != ["inih", "rxi_map", "jsmn"]:
        raise ValueError("Unexpected reviewed training projects")
    for row in training_rows:
        for relative, expected in row["source_files"].items():
            if sha(Path(row["source_directory"]) / relative) != expected:
                raise ValueError("Reviewed training source changed")
    output = SCRATCH / ("route-b-type-dev-extension-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    sources, temp = output / "sources", output / "temp"
    sources.mkdir()
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    selection = {"schema": "symbai.type_dev_extension_selection.v1",
        "preregistration": str(PREREGISTRATION), "preregistration_sha256": sha(PREREGISTRATION),
        "projects": [{"project_id": p, "repository": r, "family": r, "split": "development", "role": role}
                     for p, r, role, *_ in PROJECTS],
        "backup_rule": "parson replaces a failed primary project, or is added in full if the primaries admit fewer than 100 development source variables.",
        "excluded_author_families": EXCLUDED_AUTHOR_FAMILIES, "known_diagnostic_families_excluded": KNOWN_PROJECT_FAMILIES,
        "training_rows_reused_from": str(PARENT_CORPUS), "parent_manifest_sha256": sha(PARENT_CORPUS / "manifest.json"),
        "training_dataset_sha256": sha(TRAINING_DATASET / "dataset.json"),
        "sealed_evaluation_projects": ["utf8_h", "b64"], "inspected_development_project": "optparse",
        "selection_before_labels_or_training": True, "split_unit": "project_family"}
    write(output / "selection.json", selection)
    print("Development extension output: " + str(output), flush=True)
    rows = []
    for project_id, repository, role, units, headers in PROJECTS:
        directory = sources / project_id
        row = {"project_id": project_id, "repository": "https://github.com/" + repository, "family": repository,
               "split": "development", "role": role}
        try:
            with (output / (project_id + "-fetch.log")).open("w", encoding="utf-8") as log:
                subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--no-tags",
                    row["repository"] + ".git", str(directory)], stdout=log, stderr=subprocess.STDOUT,
                    env=env, check=True, timeout=120)
            row["commit"] = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], env=env,
                capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            files = {}
            for relative in [*units, *headers]:
                if not (directory / relative).is_file():
                    raise ValueError("Declared compilation input missing: " + relative)
                files[relative] = sha(directory / relative)
            row.update(status="pinned", source_directory=str(directory), source_files=files,
                license_evidence=license_evidence(directory, files), translation_units=units,
                headers=headers, bridge=None, bridge_sha256=None)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        rows.append(row)
        print(project_id + ": " + row["status"], flush=True)
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    (snapshot / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    (snapshot / PREREGISTRATION.name).write_bytes(PREREGISTRATION.read_bytes())
    write(output / "manifest.json", {"schema": "symbai.type_dev_extension_manifest.v1",
        "selection_sha256": sha(output / "selection.json"), "development_projects": rows,
        "training_projects": training_rows, "compiler_profiles": ["O0", "O1"],
        "harness": str(PARENT_CORPUS / parent_manifest["harness"]), "harness_sha256": parent_manifest["harness_sha256"],
        "implementation_pins": {str(Path(__file__)): sha(Path(__file__)), str(PREREGISTRATION): sha(PREREGISTRATION)},
        "compilation_performed": False, "labels_extracted": False, "graph_extraction_performed": False,
        "training_allowed": False, "evaluation_projects_selected": False})
    pinned = [r for r in rows if r["status"] == "pinned"]
    summary = {"schema": "symbai.type_dev_extension_preparation.v1", "planned_projects": len(PROJECTS),
        "pinned_projects": len(pinned), "pinned": {r["project_id"]: r["commit"] for r in pinned},
        "failed": [r["project_id"] for r in rows if r["status"] != "pinned"],
        "compilation_performed": False, "labels_extracted": False, "output": str(output)}
    write(output / "preparation-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if len(pinned) != len(PROJECTS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
