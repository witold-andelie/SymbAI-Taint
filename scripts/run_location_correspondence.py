#!/usr/bin/env python3
"""Project three retained compiled inputs using static location correspondence only."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.contracts import Query, file_hash
from src.selective_analysis.workspace import configure_workspace


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def latest(root, pattern, required):
    choices = sorted((p for p in root.glob(pattern)
                      if all((p / name).is_file() for name in required)), reverse=True)
    if not choices:
        raise FileNotFoundError(f"No retained {pattern} input containing {required}")
    return choices[0]


def input_cases(inference, compiled):
    """Only binary, fixed query manifest and raw export enter the projection runtime."""
    return [
        ("direct_index", inference / "probe.elf", inference / "mapping-review/queries.json",
         inference / "raw-types.json"),
        *[(name, compiled / name / "query.elf", compiled / name / "queries.json",
           compiled / name / "raw-types.json") for name in ("offset_index", "masked_index")],
    ]


def snapshot_input(case, output):
    case_id, binary, queries, raw = case
    folder = output / "inputs" / case_id
    folder.mkdir(parents=True, exist_ok=False)
    sources = {"binary": binary, "queries": queries, "raw": raw}
    hashes = {name: file_hash(path) for name, path in sources.items()}
    copied = {}
    for name, path in sources.items():
        target = folder / {"binary": "query.elf", "queries": "original-queries.json",
                           "raw": "raw-types.json"}[name]
        shutil.copyfile(path, target)
        if file_hash(target) != hashes[name]:
            raise ValueError("Input changed during snapshot: " + name)
        copied[name] = target
    manifest = read(copied["queries"])
    if (set(manifest) not in ({"schema", "queries"}, {"queries"})
            or manifest.get("schema", "symbai.queries.v1") != "symbai.queries.v1"
            or len(manifest["queries"]) != 1):
        raise ValueError("Expected exactly one fixed query contract")
    contract = dict(manifest["queries"][0])
    contract["binary"] = str(copied["binary"].resolve())
    query = Query.from_dict(contract)
    request = {"schema": "symbai.location_request.v1", "case_id": case_id,
               "query": asdict(query), "query_hash": query.contract_hash,
               "raw_type_file": str(copied["raw"].resolve()),
               "raw_file_sha256": hashes["raw"]}
    write(folder / "request.json", request)
    return {"case_id": case_id, "sources": {k: str(v) for k, v in sources.items()},
            "source_sha256": hashes, "request": str(folder / "request.json")}


def forbidden_imports():
    """This entry runs in a fresh process; property engines have no runtime role here."""
    names = ("angr", "claripy", "z3", "src.selective_analysis.operations",
             "src.selective_analysis.operand_mapping", "src.selective_analysis.compiled_fact_audit",
             "src.selective_analysis.local_bounds", "src.selective_analysis.frame_bounds")
    return sorted(name for name in sys.modules if any(name == p or name.startswith(p + ".") for p in names))


def unchanged(path, expected):
    try:
        return file_hash(path) == expected
    except OSError:
        return False


def project_request(request_path, output):
    from src.selective_analysis.location_correspondence import build_location_bundle, project_location_views
    request = read(request_path)
    if (set(request) != {"schema", "case_id", "query", "query_hash", "raw_type_file", "raw_file_sha256"}
            or request["schema"] != "symbai.location_request.v1"):
        raise ValueError("Invalid location-only request")
    query = Query.from_dict(request["query"])
    raw_path = Path(request["raw_type_file"])
    if query.contract_hash != request["query_hash"] or file_hash(raw_path) != request["raw_file_sha256"]:
        raise ValueError("Input identity changed after snapshot")
    started = time.monotonic()
    bundle = build_location_bundle(query, read(raw_path))
    mapping_seconds = time.monotonic() - started
    projection_started = time.monotonic()
    views = {}
    if bundle["status"] == "available":
        for group in ("A", "B", "C", "D"):
            views[group] = {key: asdict(view) for key, view in project_location_views(bundle, group).items()}
    else:
        views = {"A": {}, "B": {}, "C": None, "D": None}
    projection_seconds = time.monotonic() - projection_started
    imports = forbidden_imports()
    if imports:
        raise RuntimeError("Forbidden property-engine imports: " + repr(imports))
    folder = output / request["case_id"]
    folder.mkdir(parents=True, exist_ok=False)
    write(folder / "location-bundle.json", bundle)
    write(folder / "views.json", views)
    record = {"case_id": request["case_id"], "query_hash": query.contract_hash,
              "binary_sha256": query.binary_sha256, "raw_file_sha256": request["raw_file_sha256"],
              "status": bundle["status"], "reason": bundle.get("reason"),
              "binding_count": len(bundle.get("bindings", [])),
              "mapping_seconds": mapping_seconds, "projection_seconds": projection_seconds,
              "view_counts": {group: len(view) if view is not None else None for group, view in views.items()},
              "property_verification_performed": False, "forbidden_runtime_imports": imports,
              "bundle_sha256": file_hash(folder / "location-bundle.json"),
              "views_sha256": file_hash(folder / "views.json")}
    write(folder / "record.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inference-dir", type=Path)
    parser.add_argument("--compiled-dir", type=Path)
    args = parser.parse_args()
    scratch = configure_workspace()
    wsl = ROOT.parent / ".scratch" / "wsl"
    inference = args.inference_dir or latest(wsl, "inference-*", ("probe.elf", "raw-types.json", "mapping-review/queries.json"))
    compiled = args.compiled_dir or latest(wsl, "compiled-queries-v8-*", ("offset_index/query.elf", "masked_index/query.elf"))
    output = scratch / ("location-correspondence-v12-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Location correspondence output: " + str(output), flush=True)
    sources = ["scripts/run_location_correspondence.py", "src/selective_analysis/location_correspondence.py",
               "src/selective_analysis/contracts.py", "src/selective_analysis/types.py",
               "src/selective_analysis/elf_guard.py", "src/selective_analysis/workspace.py",
               "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v12.md"]
    source_hashes = {}
    for relative in sources:
        source = ROOT / relative
        target = output / "source_snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source_hashes[relative] = file_hash(source)
        shutil.copyfile(source, target)
        if file_hash(target) != source_hashes[relative]:
            raise ValueError("Source changed during snapshot: " + relative)
    plan = {"schema": "symbai.location_plan.v1", "planned_cases": 3,
            "semantics": "location_correspondence_only", "source_sha256": source_hashes,
            "runtime": {"python": sys.version, "platform": sys.platform,
                        "capstone": version("capstone"), "pyelftools": version("pyelftools")},
            "property_verification_performed": False, "selector_integration": False,
            "fresh_model_inference_performed": False, "inputs": []}
    failures = []
    for case in input_cases(inference, compiled):
        try:
            plan["inputs"].append(snapshot_input(case, output))
        except Exception as exc:
            failures.append({"case_id": case[0], "status": "unavailable", "reason": type(exc).__name__ + ": " + str(exc),
                             "binding_count": 0, "property_verification_performed": False})
    write(output / "run-plan.json", plan)
    records = list(failures)
    runtime_started = time.monotonic()
    for item in plan["inputs"]:
        try:
            record = project_request(Path(item["request"]), output)
        except Exception as exc:
            record = {"case_id": item["case_id"], "status": "unavailable",
                      "reason": type(exc).__name__ + ": " + str(exc), "binding_count": 0,
                      "property_verification_performed": False}
        records.append(record)
        write(output / "records.json", records)
        print(f"{record['case_id']}: {record['status']}; {record['binding_count']} syntactic load bindings", flush=True)
    runtime_seconds = time.monotonic() - runtime_started
    changed_sources = [p for p, digest in source_hashes.items() if not unchanged(ROOT / p, digest)]
    changed_inputs = [{"case_id": item["case_id"], "input": name}
                      for item in plan["inputs"] for name, path in item["sources"].items()
                      if not unchanged(path, item["source_sha256"][name])]
    imports = forbidden_imports()
    summary = {"schema": "symbai.location_summary.v1", "planned_cases": 3, "retained_cases": len(records),
               "available": sum(r["status"] == "available" for r in records),
               "unavailable": sum(r["status"] != "available" for r in records),
               "runtime_with_recording_seconds": runtime_seconds,
               "forbidden_runtime_imports": imports, "changed_sources": changed_sources,
               "changed_inputs": changed_inputs, "property_verification_performed": False,
               "fresh_model_inference_performed": False, "neural_selection_measured": False,
               "held_out_evaluation": False,
               "interpretation": "Location projection of three frozen integration exports only. Timings exclude historical inference; no property decisions or neural benefit measured."}
    write(output / "records.json", records)
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if changed_sources or changed_inputs or imports or summary["unavailable"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
