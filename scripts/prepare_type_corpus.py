#!/usr/bin/env python3
"""Pin six new source projects and project-level exploratory splits before labels."""
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
SCRATCH = ROOT.parent / ".scratch/selective_analysis"
PROJECTS = (
    ("inih", "benhoyt/inih", "train", ["ini.c"], ["ini.h"], None),
    ("rxi_map", "rxi/map", "train", ["src/map.c"], ["src/map.h"], None),
    ("jsmn", "zserge/jsmn", "train", [], ["jsmn.h"], '#include "jsmn.h"\n'),
    ("optparse", "skeeto/optparse", "development", [], ["optparse.h"], '#define OPTPARSE_IMPLEMENTATION\n#include "optparse.h"\n'),
    ("utf8_h", "sheredom/utf8.h", "evaluation", [], ["utf8.h"], '#include "utf8.h"\n'),
    ("b64", "jwerle/b64.c", "evaluation", ["encode.c", "decode.c", "buffer.c"], ["b64.h"], None),
)
KNOWN_PROJECT_FAMILIES = ("lua", "xxhash", "stb", "miniz", "utf8proc", "libpng", "jansson", "cjson", "lz4", "bzip2", "xz", "brotli")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = (args.output or SCRATCH / ("route-b-type-corpus-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))).resolve()
    output.relative_to(SCRATCH.resolve())
    output.mkdir()
    sources, temp = output / "sources", output / "temp"
    sources.mkdir()
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    env.pop("GIT_SSH_COMMAND", None)
    if os.name == "nt":
        env.update(GIT_SSH="C:/Windows/System32/OpenSSH/ssh.exe", GIT_SSH_VARIANT="ssh")
    write(output / "selection.json", {"schema": "symbai.type_corpus_selection.v1",
        "projects": [{"project_id": name, "repository": repository, "family": repository,
                      "split": split} for name, repository, split, *_ in PROJECTS],
        "known_diagnostic_families_excluded": KNOWN_PROJECT_FAMILIES,
        "selection_before_labels_or_training": True, "split_unit": "project_family",
        "scope": "Six-project exploratory data-readiness panel, not a journal-scale evaluation or training approval."})
    print("Type corpus output: " + str(output), flush=True)
    rows = []
    for name, repository, split, units, headers, bridge in PROJECTS:
        directory = sources / name
        row = {"project_id": name, "repository": "https://github.com/" + repository,
               "ssh_origin": "git@github.com:" + repository + ".git", "family": repository, "split": split}
        try:
            with (output / (name + "-fetch.log")).open("w", encoding="utf-8") as log:
                subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--no-tags",
                    row["ssh_origin"], str(directory)], stdout=log, stderr=subprocess.STDOUT, env=env, check=True, timeout=120)
            row["commit"] = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"],
                env=env, capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            files = {}
            for relative in [*units, *headers]:
                path = directory / relative
                if not path.is_file():
                    raise ValueError("Declared compilation input missing: " + relative)
                files[relative] = sha(path)
            license_files = [path for path in directory.iterdir() if path.is_file()
                and path.name.lower().startswith(("license", "licence", "unlicense", "copying"))]
            license_evidence = {path.name: sha(path) for path in license_files}
            if not license_evidence:
                # Embedded notices are retained verbatim with the selected header/source.
                embedded = [name for name in files if any(token in (directory / name).read_text(encoding="utf-8", errors="replace").lower()
                    for token in ("public domain", "permission is hereby granted", "redistribution and use"))]
                if not embedded:
                    raise ValueError("No retained license notice found")
                license_evidence = {name + " (embedded notice)": files[name] for name in embedded}
            bridge_file = None
            if bridge is not None:
                bridge_file = name + "-unit.c"
                (output / bridge_file).write_text(bridge, encoding="utf-8")
            row.update(status="pinned", source_directory=str(directory), source_files=files,
                license_evidence=license_evidence, translation_units=units, headers=headers,
                bridge=bridge_file, bridge_sha256=sha(output / bridge_file) if bridge_file else None)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        rows.append(row)
        write(output / "source-records.json", rows)
        print(name + ": " + row["status"], flush=True)
    harness = output / "intake-main.c"
    harness.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    implementations = [Path(__file__), ROOT / "scripts/build_type_corpus.py",
        ROOT / "src/selective_analysis/type_corpus.py",
        ROOT / "tygr_original/src/analysis/types/types.py",
        ROOT / "tygr_original/src/analysis/types/type_set.py",
        ROOT / "tygr_original/src/analysis/dwarf/types.py"]
    snapshots = output / "source_snapshot"
    snapshots.mkdir()
    pins = {}
    for path in implementations:
        target = snapshots / (str(len(pins)) + "-" + path.name)
        target.write_bytes(path.read_bytes())
        pins[str(path)] = pins[str(target)] = sha(path)
    write(output / "manifest.json", {"schema": "symbai.type_corpus_manifest.v1", "projects": rows,
        "compiler_profiles": ["O0", "O1"], "split_unit": "project_family",
        "harness": harness.name, "harness_sha256": sha(harness), "implementation_pins": pins,
        "selection_sha256": sha(output / "selection.json"),
        "training_allowed": False, "graph_extraction_performed": False,
        "required_followup": ["real_DWARF_label_inventory", "cross_split_function_clone_screening", "graph_and_variable_readout_validation"],
        "scope": "Original source interfaces preserved. Header bridges contain only original configuration macros/includes. Harness main is excluded from all variable counts."})
    summary = {"schema": "symbai.type_corpus_preparation.v1", "planned_projects": 6,
        "pinned_projects": sum(row["status"] == "pinned" for row in rows),
        "project_splits": {split: [row["project_id"] for row in rows if row["split"] == split] for split in ("train", "development", "evaluation")},
        "compilation_performed": False, "labels_extracted": False, "training_allowed": False,
        "output": str(output)}
    write(output / "preparation-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if summary["pinned_projects"] != 6:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
