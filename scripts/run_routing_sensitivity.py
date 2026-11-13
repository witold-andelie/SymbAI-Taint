#!/usr/bin/env python3
"""Compare fixed B/C/D operation orders on three frozen integration exports."""

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

from src.selective_analysis.contracts import Query, file_hash, fingerprint
from src.selective_analysis.workspace import configure_workspace
from src.selective_analysis.routing_sensitivity import (POLICY, WEIGHTS, PRIMARY_WEIGHT,
    static_routing_features, routing_record, summarize)
from scripts.run_location_correspondence import read, write, snapshot_input, forbidden_imports, unchanged

CASES = ("direct_index", "offset_index", "masked_index")


def local_path(value):
    text = str(value)
    if sys.platform == "win32" and text.startswith("/mnt/d/"):
        return Path("D:/" + text[len("/mnt/d/"):])
    return Path(value)


def empty_features(reason):
    return {"schema": "symbai.routing_features.v1", "query_hash": "unavailable",
            "binary_sha256": "unavailable", "available": False, "reason": reason,
            "instruction_count": 0, "address_load_count": None, "has_immediate_mask": None}


def unavailable_case(case_id, error):
    features = empty_features(error)
    return {"schema": "symbai.routing_case.v1", "case_id": case_id, "status": "unavailable",
            "error": error, "features": features, "routing_records": [routing_record(features, group, {}, weight, error)
                for group in ("B", "C", "D") for weight in WEIGHTS],
            "costs_seconds": {}, "cost_measurement_complete": False}


def run_case(request_path):
    request = read(request_path)
    if (set(request) != {"schema", "case_id", "query", "query_hash", "raw_type_file", "raw_file_sha256"}
            or request["schema"] != "symbai.location_request.v1"):
        raise ValueError("Invalid label-free routing input")
    query = Query.from_dict(request["query"])
    raw_path = local_path(request["raw_type_file"])
    if query.contract_hash != request["query_hash"] or file_hash(raw_path) != request["raw_file_sha256"]:
        raise ValueError("Frozen routing input identity differs")
    costs = {}
    before = time.monotonic()
    features = static_routing_features(query)
    costs["common_static_features"] = time.monotonic() - before
    rows, projections, errors = [], {}, {}
    before = time.monotonic()
    # B is fully scored before any raw candidate JSON is parsed.
    for weight in WEIGHTS:
        rows.append(routing_record(features, "B", {}, weight))
    costs["B_selection_grid"] = time.monotonic() - before
    mapping_started = time.monotonic()
    raw_identity, bundle = {}, None
    try:
        raw = read(raw_path)
        from src.selective_analysis.location_correspondence import build_location_bundle
        bundle = build_location_bundle(query, raw)
        raw_identity = {"raw_file_sha256": request["raw_file_sha256"],
                        "raw_payload_fingerprint": bundle["raw_payload_fingerprint"],
                        "model_sha256": bundle["model_sha256"]}
        if bundle["status"] != "available":
            raise ValueError(bundle["reason"])
        bindings = {b["occurrence_id"]: {"prediction_id": b["prediction_id"],
                    "cfa_offset": b["cfa_offset"], "load_rva": b["load_rva"], "use_rva": b["use_rva"]}
                    for b in bundle["bindings"]}
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
        errors.update(C=error, D=error)
        bindings = {}
    costs["shared_C_D_raw_read_and_mapping"] = time.monotonic() - mapping_started
    for group in ("C", "D"):
        views = {}
        before = time.monotonic()
        if group not in errors:
            try:
                from src.selective_analysis.location_correspondence import project_location_views
                views = project_location_views(bundle, group)
            except Exception as exc:
                errors[group] = type(exc).__name__ + ": " + str(exc)
        costs[group + "_projection_with_static_recheck"] = time.monotonic() - before
        projections[group] = {key: asdict(view) for key, view in views.items()} if group not in errors else None
        before = time.monotonic()
        try:
            group_rows = [routing_record(features, group, views, weight, errors.get(group)) for weight in WEIGHTS]
        except Exception as exc:
            errors[group] = type(exc).__name__ + ": " + str(exc)
            group_rows = [routing_record(features, group, {}, weight, errors[group]) for weight in WEIGHTS]
            projections[group] = None
        rows.extend(group_rows)
        costs[group + "_selection_grid"] = time.monotonic() - before
    imports = forbidden_imports()
    if imports:
        raise RuntimeError("Forbidden runtime imports: " + repr(imports))
    return {"schema": "symbai.routing_case.v1", "case_id": request["case_id"],
            "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
            "status": "available" if not errors else "partially_unavailable", "errors_by_arm": errors,
            "features": features, "routing_records": rows, "raw_identity": raw_identity,
            "occurrence_bindings": bindings, "projected_views": {"B": {}, **projections},
            "fixed_controls": {"frame_first": ["frame_bounds", "expanded_paths"],
                               "full_first": ["expanded_paths", "frame_bounds"]},
            "costs_seconds": costs, "cost_measurement_complete": True,
            "property_operations_executed": False, "fresh_neural_inference_performed": False,
            "forbidden_runtime_imports": imports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--location-input-dir", type=Path,
                        help="Retained v12 root; only copied binary/query/raw input files are read")
    args = parser.parse_args()
    scratch = configure_workspace()
    source_root = args.location_input_dir
    if source_root is None:
        choices = sorted((p for p in scratch.glob("location-correspondence-v12-*")
            if all((p / "inputs" / case / name).is_file() for case in CASES
                   for name in ("query.elf", "original-queries.json", "raw-types.json"))), reverse=True)
        if not choices:
            raise FileNotFoundError("No complete retained v12 inputs")
        source_root = choices[0]
    output = scratch / ("routing-sensitivity-v13-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Routing sensitivity output: " + str(output), flush=True)
    sources = ["scripts/run_routing_sensitivity.py", "src/selective_analysis/routing_sensitivity.py",
               "scripts/run_location_correspondence.py", "src/selective_analysis/location_correspondence.py",
               "src/selective_analysis/contracts.py", "src/selective_analysis/types.py",
               "src/selective_analysis/elf_guard.py", "src/selective_analysis/workspace.py",
               "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v13.md"]
    source_hashes = {}
    for name in sources:
        source, target = ROOT / name, output / "source_snapshot" / name
        source_hashes[name] = file_hash(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != source_hashes[name]:
            raise ValueError("Source changed during snapshot: " + name)
    plan = {"schema": "symbai.routing_plan.v1", "policy": POLICY, "primary_weight": PRIMARY_WEIGHT,
            "input_role": "known_developer_inputs_not_held_out", "planned_cases": 3,
            "planned_routing_rows": 45, "source_sha256": source_hashes, "input_root": str(source_root),
            "runtime": {"python": sys.version, "platform": sys.platform,
                        "capstone": version("capstone"), "pyelftools": version("pyelftools")},
            "property_operations_executed": False, "frozen_selector_changed": False,
            "inputs": [], "snapshot_failures": []}
    for case in CASES:
        folder = source_root / "inputs" / case
        try:
            plan["inputs"].append(snapshot_input((case, folder / "query.elf", folder / "original-queries.json",
                                                 folder / "raw-types.json"), output))
        except Exception as exc:
            plan["snapshot_failures"].append({"case_id": case, "error": type(exc).__name__ + ": " + str(exc)})
    write(output / "run-plan.json", plan)
    cases = [unavailable_case(row["case_id"], row["error"]) for row in plan["snapshot_failures"]]
    started = time.monotonic()
    recording_seconds = 0.0
    for item in plan["inputs"]:
        try:
            row = run_case(Path(item["request"]))
        except Exception as exc:
            row = unavailable_case(item["case_id"], type(exc).__name__ + ": " + str(exc))
        cases.append(row)
        before = time.monotonic()
        folder = output / item["case_id"]
        folder.mkdir(exist_ok=False)
        write(folder / "record.json", row)
        write(output / "records.json", cases)
        recording_seconds += time.monotonic() - before
        primary = {r["group"]: r["order"] if r["status"] == "available" else "unavailable"
                   for r in row["routing_records"] if r["primary_weight"]}
        print(item["case_id"] + ": " + json.dumps(primary), flush=True)
    before = time.monotonic()
    summary = summarize(cases)
    summary.update(changed_sources=[p for p, h in source_hashes.items() if not unchanged(ROOT / p, h)],
                   changed_inputs=[{"case_id": item["case_id"], "input": kind}
                       for item in plan["inputs"] for kind, source in item["sources"].items()
                       if not unchanged(source, item["source_sha256"][kind])],
                   changed_copied_inputs=[{"case_id": item["case_id"], "input": kind}
                       for item in plan["inputs"] for kind, name in
                       {"binary": "query.elf", "queries": "original-queries.json", "raw": "raw-types.json"}.items()
                       if not unchanged(output / "inputs" / item["case_id"] / name, item["source_sha256"][kind])],
                   forbidden_runtime_imports=forbidden_imports(),
                   historical_acquisition_included=False, command_startup_included=False,
                   input_snapshot_included_in_diagnostic_clock=False,
                   preparation_cost_role="retained_shared_diagnostic_cost_not_free_deployment_data")
    identities = [row["query_hash"] for row in cases if row.get("query_hash")]
    summary["unique_observed_query_hashes"] = len(set(identities))
    summary["identity_review_required"] = len(identities) != len(set(identities))
    write(output / "records.json", cases)
    recording_seconds += time.monotonic() - before
    summary.update(recording_and_summary_preparation_seconds=recording_seconds,
                   diagnostic_through_records_seconds=time.monotonic() - started)
    write(output / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "comparisons"}, indent=2))
    if (summary["changed_sources"] or summary["changed_inputs"] or summary["changed_copied_inputs"]
            or summary["forbidden_runtime_imports"] or summary["unavailable_comparisons"] or summary["identity_review_required"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
