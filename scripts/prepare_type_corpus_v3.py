#!/usr/bin/env python3
"""Pin the pre-registered type pilot v3 projects before any labels.

Fetches the new training and development sources, reuses the already pinned
json-parser and parson sources after re-checking their hashes, and records the
reused audited exports. Compiles nothing, reads no DWARF label, trains nothing.
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
PREREGISTRATION = ROOT / "benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md"
V2_EXTENSION = SCRATCH / "route-b-type-dev-extension-20261120T192757085592Z"
V1_CORPUS = SCRATCH / "route-b-type-corpus-v2-20261119T220534466210Z"
REUSED_EXPORTS = {
    "v1_reviewed_export": SCRATCH / "route-b-type-graphs-20261119T225215150614Z",
    "v2_development_export": SCRATCH / "route-b-type-dev-graphs-20261120T195202135627Z",
}
REUSED_TRAINING_PROJECTS = ("inih", "rxi_map", "jsmn", "optparse", "sds", "tiny_regex_c")
# (project_id, repository, split, translation units, headers, include directory)
NEW_PROJECTS = (
    ("hashmap", "tidwall/hashmap.c", "train", ["hashmap.c"], ["hashmap.h"], "."),
    ("btree", "tidwall/btree.c", "train", ["btree.c"], ["btree.h"], "."),
    ("c_algorithms", "fragglet/c-algorithms", "train",
     ["src/" + n for n in ("arraylist.c", "avl-tree.c", "binary-heap.c", "binomial-heap.c", "bloom-filter.c",
                           "compare-int.c", "compare-pointer.c", "compare-string.c", "hash-int.c",
                           "hash-pointer.c", "hash-string.c", "hash-table.c", "list.c", "queue.c",
                           "rb-tree.c", "set.c", "slist.c", "sortedarray.c", "trie.c")],
     ["src/" + n for n in ("arraylist.h", "avl-tree.h", "binary-heap.h", "binomial-heap.h", "bloom-filter.h",
                           "compare-int.h", "compare-pointer.h", "compare-string.h", "hash-int.h",
                           "hash-pointer.h", "hash-string.h", "hash-table.h", "list.h", "queue.h",
                           "rb-tree.h", "set.h", "slist.h", "sortedarray.h", "trie.h")], "src"),
    ("tiny_aes", "kokke/tiny-AES-c", "train", ["aes.c"], ["aes.h"], "."),
    ("klib_kstring", "attractivechaos/klib", "train", ["kstring.c"], ["kstring.h"], "."),
    ("slre", "cesanta/slre", "train", ["slre.c"], ["slre.h"], "."),
    ("linenoise", "antirez/linenoise", "train", ["linenoise.c"], ["linenoise.h"], "."),
    ("rxi_log", "rxi/log.c", "train", ["src/log.c"], ["src/log.h"], "src"),
    ("tpl", "troydhanson/tpl", "train", ["src/tpl.c"], ["src/tpl.h"], "src"),
    ("md4c", "mity/md4c", "development", ["src/md4c.c"], ["src/md4c.h"], "src"),
)
REUSED_DEVELOPMENT = ("json_parser", "parson")
TRAINING_AUTHORS = ("benhoyt", "rxi", "zserge", "skeeto", "antirez", "kokke", "tidwall", "fragglet",
                    "attractivechaos", "cesanta", "troydhanson")
DEVELOPMENT_AUTHORS = ("json-parser", "kgabis", "mity")
SEALED_AUTHORS = ("sheredom", "jwerle")
KNOWN_PROJECT_FAMILIES = ("lua", "xxhash", "stb", "miniz", "utf8proc", "libpng", "jansson", "cjson",
                          "lz4", "bzip2", "xz", "brotli")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, allow_nan=False) + "\n")


def check_families():
    if set(TRAINING_AUTHORS) & set(DEVELOPMENT_AUTHORS) or (set(TRAINING_AUTHORS) | set(DEVELOPMENT_AUTHORS)) & set(SEALED_AUTHORS):
        raise ValueError("Author families cross splits")
    for _, repository, split, *_ in NEW_PROJECTS:
        owner, name = repository.casefold().split("/")
        if owner not in (TRAINING_AUTHORS if split == "train" else DEVELOPMENT_AUTHORS):
            raise ValueError("Undeclared author family: " + repository)
        if any(f in name.replace("-", "").replace(".", "").replace("_", "") for f in KNOWN_PROJECT_FAMILIES):
            raise ValueError("Known diagnostic family selected: " + repository)


def license_evidence(directory):
    found = {p.name: sha(p) for p in directory.iterdir() if p.is_file()
             and p.name.lower().startswith(("license", "licence", "unlicense", "copying"))}
    if not found:
        raise ValueError("No license file found")
    return found


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    check_families()
    reused = {}
    for key, directory in REUSED_EXPORTS.items():
        audit = directory / "independent-export-audit.json"
        reused[key] = {"directory": str(directory), "dataset_sha256": sha(directory / "dataset.json"),
                       "audit_sha256": sha(audit)}
    v2_manifest = json.loads((V2_EXTENSION / "manifest.json").read_bytes())
    reused_dev = []
    for row in v2_manifest["development_projects"]:
        if row["project_id"] in REUSED_DEVELOPMENT:
            for relative, expected in row["source_files"].items():
                if sha(Path(row["source_directory"]) / relative) != expected:
                    raise ValueError("Pinned development source changed: " + row["project_id"])
            reused_dev.append(dict(row, split="development", role="primary", include_directory=".",
                                   pinned_in=str(V2_EXTENSION)))
    if [r["project_id"] for r in reused_dev] != list(REUSED_DEVELOPMENT):
        raise ValueError("Reused development projects missing")
    output = SCRATCH / ("route-b-type-corpus-v3-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    sources, temp = output / "sources", output / "temp"
    sources.mkdir()
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    write(output / "selection.json", {"schema": "symbai.type_corpus_v3_selection.v1",
        "preregistration": str(PREREGISTRATION), "preregistration_sha256": sha(PREREGISTRATION),
        "new_projects": [{"project_id": p, "repository": r, "family": r, "split": s} for p, r, s, *_ in NEW_PROJECTS],
        "reused_development_projects": list(REUSED_DEVELOPMENT),
        "reused_training_projects": list(REUSED_TRAINING_PROJECTS), "reused_exports": reused,
        "v2_extension_manifest_sha256": sha(V2_EXTENSION / "manifest.json"),
        "v1_corpus_manifest_sha256": sha(V1_CORPUS / "manifest.json"),
        "author_families": {"train": TRAINING_AUTHORS, "development": DEVELOPMENT_AUTHORS, "sealed": SEALED_AUTHORS},
        "known_diagnostic_families_excluded": KNOWN_PROJECT_FAMILIES,
        "build_recipe": "v1 command plus -lm at the end of the link line",
        "function_cap": {"limit": 60, "rule": "smallest sha256(project_id + ':' + function_name)", "applies_to": "new projects"},
        "minimum_admitted": {"development": 150, "expanded_training": 600},
        "sealed_evaluation_projects": ["utf8_h", "b64"], "selection_before_labels_or_training": True,
        "split_unit": "project_family"})
    print("Type corpus v3 output: " + str(output), flush=True)
    rows = []
    for project_id, repository, split, units, headers, include in NEW_PROJECTS:
        directory = sources / project_id
        row = {"project_id": project_id, "repository": "https://github.com/" + repository, "family": repository,
               "split": split, "role": "primary" if split == "development" else None}
        try:
            with (output / (project_id + "-fetch.log")).open("w", encoding="utf-8") as log:
                subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--no-tags",
                    row["repository"] + ".git", str(directory)], stdout=log, stderr=subprocess.STDOUT,
                    env=env, check=True, timeout=180)
            row["commit"] = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], env=env,
                capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            files = {}
            for relative in [*units, *headers]:
                if not (directory / relative).is_file():
                    raise ValueError("Declared compilation input missing: " + relative)
                files[relative] = sha(directory / relative)
            row.update(status="pinned", source_directory=str(directory), source_files=files,
                license_evidence=license_evidence(directory), translation_units=units, headers=headers,
                include_directory=include, bridge=None, bridge_sha256=None)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        rows.append(row)
        print(project_id + ": " + row["status"], flush=True)
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    for path in (Path(__file__), PREREGISTRATION):
        (snapshot / path.name).write_bytes(path.read_bytes())
    write(output / "manifest.json", {"schema": "symbai.type_corpus_v3_manifest.v1",
        "selection_sha256": sha(output / "selection.json"), "new_projects": rows,
        "reused_development_projects": reused_dev, "reused_exports": reused,
        "harness": str(V1_CORPUS / "intake-main.c"), "harness_sha256": sha(V1_CORPUS / "intake-main.c"),
        "compiler_profiles": ["O0"], "link_libraries": ["-lm"],
        "implementation_pins": {str(Path(__file__)): sha(Path(__file__)), str(PREREGISTRATION): sha(PREREGISTRATION)},
        "compilation_performed": False, "labels_extracted": False, "graph_extraction_performed": False,
        "training_allowed": False, "evaluation_projects_selected": False})
    pinned = [r for r in rows if r["status"] == "pinned"]
    summary = {"schema": "symbai.type_corpus_v3_preparation.v1", "planned_new_projects": len(NEW_PROJECTS),
        "pinned_new_projects": len(pinned), "pinned": {r["project_id"]: r["commit"] for r in pinned},
        "failed": [r["project_id"] for r in rows if r["status"] != "pinned"],
        "reused_development": [r["project_id"] for r in reused_dev], "output": str(output)}
    write(output / "preparation-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if len(pinned) != len(NEW_PROJECTS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
