#!/usr/bin/env python3
"""Merge the two compiled Route B v5 sources manifests without changing their projects."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "symbai.route_b_v5_sources.v1"


def relative(path):
    return Path(os.path.relpath(str(Path(path).resolve()), str(ROOT))).as_posix()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def merge(base, amendment, output):
    base, amendment, output = Path(base), Path(amendment), Path(output)
    allowed = ((ROOT.parent / ".scratch/selective_analysis").resolve(),
               (ROOT / ".test-output").resolve())
    # Check the lexical name and resolved parent, so an existing symlink cannot redirect writes.
    if output.exists() or output.is_symlink() or output.resolve().parent not in allowed:
        raise ValueError("Output must be a new child of scratch/selective_analysis or .test-output")
    inputs = [(path, path.read_bytes()) for path in (base, amendment)]
    documents = [json.loads(data) for path, data in inputs]
    for document in documents:
        if document.get("schema") != SCHEMA or document.get("compilation_performed") is not True:
            raise ValueError("Expected compiled v5 sources manifests")
    if not isinstance(documents[0].get("juliet"), dict) or documents[1].get("juliet", {}) is not None:
        raise ValueError("Expected base Juliet and amendment juliet: null")
    projects, pins, seen = [], {}, set()
    for document in documents:
        for project in document["projects"]:
            name = project["project_id"]
            if name.lower() in seen:
                raise ValueError("Duplicate project_id: " + name)
            seen.add(name.lower())
            projects.append(project)
        for name, value in document["pins"].items():
            if name in pins and pins[name] != value:
                raise ValueError("Conflicting pin: " + name)
            pins[name] = value
    for path, data in inputs:
        name, value = relative(path), sha(data)
        if name in pins and pins[name] != value:
            raise ValueError("Conflicting manifest pin: " + name)
        pins[name] = value
    result = {"schema": SCHEMA, "juliet": documents[0]["juliet"], "projects": projects,
              "pins": pins, "compilation_performed": True,
              "merged_from": [relative(path) for path, data in inputs]}
    output.mkdir()
    (output / "sources-manifest.json").write_bytes(
        (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("ascii"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--amendment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = merge(args.base, args.amendment, args.output)
    print(json.dumps({"projects": len(result["projects"]), "merged_from": result["merged_from"]}))


if __name__ == "__main__":
    main()
