#!/usr/bin/env python3
"""Probe guarded neural output and entry binding on verified native input pairs."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.prepare_native_query_pairs import compare_pair, digest, within, write, WORKSPACE
from scripts.run_location_repair import offline_trace
from scripts.tygr_location_adapter import REVISION, validate_api

MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
CASES = ("cjson_hex4", "brotli_reverse8")
HELPERS = {
    "base_worker": "export_typed_complementarity.py", "wrapper": "export_location_repair.py",
    "adapter": "tygr_location_adapter.py", "capture": "capture_tygr_preprocessing.py",
    "export": "export_tygr_candidates.py",
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def linux_path(path):
    path = Path(path).resolve()
    if sys.platform.startswith("linux"):
        return str(path)
    value = path.as_posix()
    if not value.lower().startswith("d:/"):
        raise ValueError("Prepared native paths must be on D")
    return "/mnt/d/" + value[3:]


def selected_cases(manifest, remaining=False):
    names = tuple(case["case_id"] for case in manifest["cases"])
    if len(names) != 12 or len(set(names)) != 12 or not set(CASES).issubset(names):
        raise ValueError("Expected twelve unique frozen cases including the original probe pair")
    return tuple(name for name in names if name not in CASES) if remaining else CASES


def prepare(pairs, output, remaining=False):
    summary = json.loads((pairs / "summary.json").read_bytes())
    if summary["verified_pairs"] != 12 or summary["entry_argument_bindings_verified"] != 12 or summary["failed_cases"]:
        raise ValueError("The twelve-case native pair gate is incomplete")
    build_plan = json.loads((pairs / "plan.json").read_bytes())
    if build_plan["script_sha256"] != digest(ROOT / "scripts/prepare_native_query_pairs.py"):
        raise ValueError("Native builder identity differs")
    manifest = pairs.parent / "source-manifest.json"
    if digest(manifest) != build_plan["manifest_sha256"]:
        raise ValueError("Native input manifest differs")
    case_ids = selected_cases(json.loads(manifest.read_bytes()), remaining)
    tygr = ROOT / "tygr_original"
    model = tygr / "model/MODEL_base/x64.O0.base.model"
    if not model.is_file() or digest(model) != MODEL_HASH:
        raise ValueError("Existing pinned TYGR checkpoint is unavailable or differs")
    inventory = {p.relative_to(tygr).as_posix(): digest(p) for p in sorted((tygr / "src").rglob("*.py"))}
    if not inventory:
        raise ValueError("Existing TYGR source inventory is empty")
    copies = output / "source_snapshot"
    copies.mkdir()
    # Preserve the parent implementation as well as every child helper for later review.
    (copies / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    implementation = {}
    for key, name in HELPERS.items():
        target = copies / name
        target.write_bytes((ROOT / "scripts" / name).read_bytes())
        implementation[key] = {"path": linux_path(target), "sha256": digest(target)}
    prepared = []
    for name in case_ids:
        record = json.loads((pairs / (name + ".json")).read_bytes())
        debug, stripped = pairs / (name + ".debug.elf"), pairs / (name + ".stripped.elf")
        identity = compare_pair(debug, stripped)
        if (identity["debug_sha256"] != record["identity"]["debug_sha256"]
                or identity["stripped_sha256"] != record["identity"]["stripped_sha256"]):
            raise ValueError("Verified native input changed")
        case = output / name
        case.mkdir()
        trace = offline_trace(debug)
        write(case / "offline-location-trace.json", trace)
        native = {
            "schema": "symbai.typed_acquisition_request.v1", "binary": linux_path(debug),
            "binary_sha256": digest(debug), "model": linux_path(model), "model_sha256": MODEL_HASH,
            "tygr_root": linux_path(tygr), "source_sha256": inventory,
            "scratch_dir": linux_path(case / "cache"), "worker_sha256": implementation["base_worker"]["sha256"],
            "helpers": {key: implementation[key] for key in ("capture", "export")},
        }
        envelope = {"schema": "symbai.location_repair_request.v1", "native_request": native,
                    "implementation": {key: implementation[key] for key in ("base_worker", "adapter", "wrapper")}}
        write(case / "request.json", envelope)
        base = min(row[0] for row in identity["load_geometry"])
        prepared.append({"case_id": name, "directory": case, "request": envelope,
            "debug": debug, "stripped": stripped, "entry_address": base + record["query"]["entry_rva"],
            "first_read_address": record["entry_argument_binding"]["first_read"]["address"]})
    pins = {str(ROOT / "scripts" / name): digest(ROOT / "scripts" / name) for name in HELPERS.values()}
    pins.update({str(path): digest(path) for path in (Path(__file__), manifest, pairs / "plan.json", pairs / "summary.json")})
    for case in prepared:
        pins[str(case["debug"])] = digest(case["debug"])
        pins[str(case["stripped"])] = digest(case["stripped"])
    write(output / "plan.json", {
        "schema": "symbai.native_pair_neural_probe.v1", "cases": list(case_ids), "pins": pins,
        "model_sha256": MODEL_HASH, "upstream_source_sha256": inventory,
        "scope": "Known native development functions. Debug-sidecar acquisition and entry-argument correspondence only; no type-accuracy, scheduling, or timing-benefit claim.",
        "cost_scope": "Cold child-process acquisition with full native-input capture and parent validation. This diagnostic cost is not a warm-service estimate.",
        "binding": "Admit only a unique target-function x record whose register-5 location covers the already verified first input-register read.",
        "reference_labels_in_request": False,
    })
    return prepared, pins, implementation, inventory, model


def review(payload, case, base_worker, exporter):
    if payload.get("status") != "completed":
        error = payload.get("error", {})
        raise ValueError("Guarded acquisition failed: {}: {}".format(
            error.get("type", "IncompleteAcquisition"), error.get("message", payload.get("status"))))
    if (payload.get("binary_sha256") != digest(case["debug"])
            or payload.get("model_sha256") != MODEL_HASH or payload.get("ground_truth_labels_supplied_to_model") is not False
            or payload.get("identities_rechecked") is not True):
        raise ValueError("Guarded acquisition did not complete with the expected identities")
    adapter = payload["location_adapter"]
    validate_api(adapter["entry_api"])
    if adapter["revision"] != REVISION or adapter["errors"]:
        raise ValueError("Location adapter failed")
    expected = json.loads((case["directory"] / "offline-location-trace.json").read_bytes())
    canonical = lambda value: json.dumps(value, sort_keys=True)
    expected_set = {canonical(row) for row in expected}
    if not adapter["records"] or any(canonical(row) not in expected_set for row in adapter["records"]):
        raise ValueError("Native location trace differs from the independent DWARF projection")
    for function in payload["functions"]:
        if function["status"] == "completed":
            base_worker.guard_native_input(function["native_input"], payload["model_contract"])
            if not function["forward_attempted"] or not function["forward_completed"]:
                raise ValueError("Completed function lacks a forward receipt")
    target = [f for f in payload["functions"] if f["function_address"] == case["entry_address"] and f["status"] == "completed"]
    matches = []
    for record in payload["records"]:
        packed = exporter.pack_logits(record["raw_value_node_logits"], record["vocabulary"], 3)
        if any(record[key] != value for key, value in packed.items()):
            raise ValueError("Logits or candidate scores differ from retained raw rows")
        if record["function_address"] != case["entry_address"] or record["locator_variable_name"] != "x":
            continue
        for location in record["locations"]:
            if (location["location_register"] == 5 and location["low_pc"] <= case["first_read_address"]
                    and (location["high_pc"] is None or case["first_read_address"] < location["high_pc"])):
                matches.append(record)
                break
    unique = {record["prediction_id"]: record for record in matches}
    return {"case_id": case["case_id"], "status": "reviewed", "genuine_target_output": bool(target),
            "target_entry_records": len(unique), "entry_prediction_binding_verified": bool(target) and len(unique) == 1,
            "entry_predictions": [{"prediction_id": r["prediction_id"], "candidates": r["candidates"]} for r in unique.values()],
            "variable_records": len(payload["records"]), "forward_calls_completed": payload["forward_calls_completed"],
            "recorded_location_traces": len(adapter["records"]), "offline_location_traces": len(expected),
            "score_kind": "uncalibrated_raw_logits", "full_use_site_mapping_validated": False}


def failure_details(payload):
    """Explain retained child failures without admitting their output or changing inputs."""
    details = {"upstream_error": payload.get("error"),
        "forward_calls_attempted": payload.get("forward_calls_attempted"),
        "forward_calls_completed": payload.get("forward_calls_completed"),
        "failure_stage": "acquisition_or_review", "relation_domain_findings": []}
    capacities = payload.get("model_contract", {}).get("layer_relation_capacities", [])
    if not capacities or any(type(value) is not int or value <= 0 for value in capacities):
        return details
    capacity = min(capacities)
    for function in payload.get("functions", []):
        native = function.get("native_input", {})
        batch = native.get("batch") or {}
        ids = batch.get("edge_labels", {}).get("values", [])
        invalid = sorted({value for value in ids if type(value) is int and (value < 0 or value >= capacity)})
        if invalid:
            details["relation_domain_findings"].append({"function_address": function["function_address"],
                "saved_relation_capacity": capacity, "out_of_saved_domain_ids": invalid,
                "edges": [edge for edge in native.get("graph_edges", [])
                          if edge["forward_id"] in invalid or edge["inverse_id"] in invalid]})
    if (details["relation_domain_findings"] and details["forward_calls_attempted"] == 0
            and details["upstream_error"] == {"type": "ValueError", "message":
                "Observed native relation outside declared/saved layer domains; forward refused"}):
        details["failure_stage"] = "pre_forward_relation_domain"
    return details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--remaining", action="store_true",
        help="Probe the other ten frozen cases; do not rerun the original cJSON/Brotli pair")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    started = time.monotonic()
    pairs = within(args.pairs, WORKSPACE)
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Use the existing WSL angr-env with the existing tygr-orig interpreter")
    output = pairs.parent / ("neural-probe-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    cases, pins, implementation, inventory, model = prepare(pairs, output, args.remaining)
    setup_seconds = time.monotonic() - started
    print("Native neural probe output: " + str(output), flush=True)
    rows = []
    if not args.prepare_only:
        base_worker = load("probe_guard", output / "source_snapshot/export_typed_complementarity.py")
        exporter = load("probe_exporter", output / "source_snapshot/export_tygr_candidates.py")
        for case in cases:
            directory = case["directory"]
            launch = time.monotonic()
            payload = None
            try:
                with (directory / "worker.log").open("w", encoding="utf-8") as stream:
                    subprocess.run([str(args.tygr_python), "-B", implementation["wrapper"]["path"],
                        "--request", str(directory / "request.json"), "--output", str(directory / "raw.json")],
                        cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=120)
                acquired = time.monotonic()
                payload = json.loads((directory / "raw.json").read_bytes())
                row = review(payload, case, base_worker, exporter)
                row["cold_acquisition_parent_seconds"] = acquired - launch
                row["parent_review_seconds"] = time.monotonic() - acquired
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row = {"case_id": case["case_id"], "status": "failed", "reason": f"{type(error).__name__}: {error}",
                       "parent_elapsed_seconds": time.monotonic() - launch}
                if payload is not None:
                    row.update(failure_details(payload))
            rows.append(row)
            write(output / "records.json", rows)
            message = case["case_id"] + ": " + row["status"]
            if row["status"] == "failed":
                message += " (" + row["reason"] + ")"
            print(message, flush=True)
    changed = [name for name, checksum in pins.items() if digest(name) != checksum]
    tygr = ROOT / "tygr_original"
    if inventory != {p.relative_to(tygr).as_posix(): digest(p) for p in sorted((tygr / "src").rglob("*.py"))}:
        changed.append("original_tygr_inventory")
    if digest(model) != MODEL_HASH:
        changed.append("model_identity")
    summary = {"schema": "symbai.native_pair_neural_summary.v1", "planned_cases": len(cases),
        "case_ids": [case["case_id"] for case in cases],
        "prepare_only": args.prepare_only, "completed_cases": len(rows),
        "genuine_target_coverage": sum(r.get("genuine_target_output", False) for r in rows),
        "entry_prediction_bindings_verified": sum(r.get("entry_prediction_binding_verified", False) for r in rows),
        "failed_cases": [r for r in rows if r["status"] != "reviewed"], "setup_seconds": setup_seconds,
        "total_parent_seconds": time.monotonic() - started, "changed_sources_or_inputs": changed,
        "baseline_timing_performed": False, "full_use_site_mapping_validated": False,
        "neural_scheduling_benefit_measured": False, "output": str(output)}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if changed or (not args.prepare_only and summary["entry_prediction_bindings_verified"] != len(cases)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
