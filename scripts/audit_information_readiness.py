#!/usr/bin/env python3
"""Audit retained type-information coverage and optimistic frozen-trace deletion costs."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from statistics import median
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.contracts import Query, file_hash, fingerprint
from src.selective_analysis.information_readiness import REVISION, availability_inventory, frozen_type_case
from src.selective_analysis.trace_headroom import summarize_trace_headroom
from src.selective_analysis.workspace import configure_workspace

COMPILED_CASES = ("direct_index", "offset_index", "masked_index")
SOURCE_FINDINGS = (
    ("dwarf_locator_required", "scripts/export_tygr_candidates.py", "options = datagen.Options", 4),
    ("missing_dwarf_is_rejected", "tygr_original/src/analysis/dwarf/utils.py", "def get_dwarf_info", 13),
    ("register_prediction_branch_incomplete", "tygr_original/src/methods/glow/datagen.py", 'print("This part need to be implemented")', 34),
    ("register_location_uses_dwarf_numbering", "tygr_original/src/analysis/dwarf/location.py", 'class RegLocation', 9),
    ("block_and_final_state_action_summary", "tygr_original/src/analysis/angr/ast_graph.py", 'def get_state_WR', 63),
    ("CFA_frame_only_correspondence", "src/selective_analysis/location_correspondence.py", 'def walk(self)', 34),
    ("CFA_locations_only", "src/selective_analysis/location_correspondence.py", 'def _associate', 28),
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def latest(root, pattern, required, linux=False):
    for folder in sorted(root.glob(pattern), reverse=True):
        if all((folder / name).is_file() for name in required):
            if not linux or read(folder / "records.json")[0].get("runtime_versions", {}).get("platform") == "linux":
                return folder
    raise FileNotFoundError(f"No complete retained {pattern} input")


def snapshot(sources, destination):
    hashes = {}
    for relative, source in sources.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        hashes[relative] = file_hash(source)
        shutil.copyfile(source, target)
        if file_hash(target) != hashes[relative]:
            raise ValueError("Input changed during snapshot: " + relative)
    return hashes


def retained_sources(cascade, location, profile):
    sources = {"cascade/" + name: cascade / name for name in ("run-plan.json", "records.json", "references.json", "summary.json")}
    for name in ("queries.json", "gold.json", "scalar_span.elf", "readonly_chain.elf", "readonly_chain_outside.elf"):
        sources["cascade/inputs/" + name] = cascade / "inputs" / name
    for name in ("run-plan.json", "records.json"):
        sources["location/" + name] = location / name
    for case in COMPILED_CASES:
        for name in ("query.elf", "original-queries.json", "raw-types.json"):
            sources[f"location/inputs/{case}/{name}"] = location / "inputs" / case / name
        sources[f"location/{case}/location-bundle.json"] = location / case / "location-bundle.json"
    for name in ("plan.json", "summary.json", "trials.json"):
        sources["historical-profile/" + name] = profile / name
    return sources


def validate_prior_snapshots(folder):
    plan = read(folder / "run-plan.json")
    for relative, digest in plan["source_sha256"].items():
        if file_hash(folder / "source_snapshot" / relative) != digest or file_hash(ROOT / relative) != digest:
            raise ValueError("Retained runtime source differs: " + relative)
    for relative, digest in plan.get("input_sha256", {}).items():
        if Path(relative).name != relative or file_hash(folder / "inputs" / relative) != digest:
            raise ValueError("Retained cascade input differs: " + relative)


def load_frozen_cases(location):
    plan, records = read(location / "run-plan.json"), read(location / "records.json")
    if (plan.get("schema") != "symbai.location_plan.v1" or plan.get("planned_cases") != 3
            or {r["case_id"] for r in records} != set(COMPILED_CASES) or len(records) != 3):
        raise ValueError("Frozen location-panel denominator differs")
    indexed, cases = {r["case_id"]: r for r in records}, []
    plans = {p["case_id"]: p for p in plan["inputs"]}
    for case_id in COMPILED_CASES:
        folder = location / "inputs" / case_id
        files = {"binary": folder / "query.elf", "queries": folder / "original-queries.json", "raw": folder / "raw-types.json"}
        if any(file_hash(path) != plans[case_id]["source_sha256"][name] for name, path in files.items()):
            raise ValueError("Retained type input differs")
        manifest = read(files["queries"])
        if len(manifest["queries"]) != 1:
            raise ValueError("Expected one frozen query per compiled case")
        contract = dict(manifest["queries"][0])
        contract["binary"] = str(files["binary"])
        query = Query.from_dict(contract)
        bundle_path = location / case_id / "location-bundle.json"
        record = indexed[case_id]
        if (file_hash(bundle_path) != record["bundle_sha256"] or record["query_hash"] != query.contract_hash
                or record["raw_file_sha256"] != file_hash(files["raw"]) or record["status"] != "available"
                or record["property_verification_performed"] is not False or record["forbidden_runtime_imports"]):
            raise ValueError("Retained location record mismatch")
        case = frozen_type_case(case_id, query, files["binary"].read_bytes(), read(files["raw"]), read(bundle_path))
        if case["recorded_binding_count"] != record["binding_count"]:
            raise ValueError("Retained binding count differs")
        cases.append(case)
    return cases


def historical_context(folder, query_hashes):
    plan, summary, trials = [read(folder / name) for name in ("plan.json", "summary.json", "trials.json")]
    if (summary.get("schema") != "symbai.acquisition_profile_summary.v1" or len(trials) != 3
            or summary.get("trials") != 3 or summary.get("completed") != 3 or summary.get("failed") != 0
            or any(t.get("status") != "completed" for t in trials)):
        raise ValueError("Historical profile is incomplete")
    times = [t["wall_seconds"] for t in trials]
    if any(type(t) not in (int, float) or not 0 < t < float("inf") for t in times):
        raise ValueError("Historical clock is invalid")
    if median(times) != summary["median_acquisition_wall_seconds"]:
        raise ValueError("Historical profile summary mismatch")
    contract = dict(plan["query"])
    contract.pop("binary")
    qhash = fingerprint(contract)
    return {"role": "separate_historical_context_only", "query_hash": qhash,
            "binary_sha256": plan["query"]["binary_sha256"], "same_query_as_cascade": qhash in query_hashes,
            "cold_acquisitions": 3, "median_acquisition_wall_seconds": median(times),
            "median_stage_seconds": summary["median_stage_seconds"],
            "new_panel_acquisition_estimate": None, "cross_panel_net_gain_or_ratio_computed": False,
            "warm_service_measured": False}


def forbidden_imports():
    prefixes = ("angr", "claripy", "z3", "torch", "capstone", "elftools",
                "src.selective_analysis.operations", "src.selective_analysis.local_bounds",
                "src.selective_analysis.readonly_values", "src.selective_analysis.location_correspondence")
    return sorted(n for n in sys.modules if any(n == p or n.startswith(p + ".") for p in prefixes))


def finding_excerpt(name, lines, anchor, count):
    start, stop = 0, len(lines)
    if name == "register_prediction_branch_incomplete":
        start, = [i for i, line in enumerate(lines) if line.startswith("def sym_exec_one(task)")]
        stop = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("def ")), len(lines))
    index, = [i for i in range(start, stop) if anchor in lines[i]]
    return index + 1, lines[index:min(index + count, stop)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cascade-dir", type=Path)
    parser.add_argument("--location-dir", type=Path)
    parser.add_argument("--profile-dir", type=Path)
    args = parser.parse_args()
    scratch = configure_workspace()
    started = time.monotonic()
    cascade = (args.cascade_dir or latest(scratch, "fixed-cascade-v15-*", ("records.json", "references.json", "summary.json", "inputs/queries.json"), linux=True)).resolve()
    location = (args.location_dir or latest(scratch, "location-correspondence-v12-*", ("records.json", "inputs/direct_index/raw-types.json"))).resolve()
    profile = (args.profile_dir or latest(ROOT.parent / ".scratch/wsl", "acquisition-profile-v5-*", ("summary.json", "trials.json", "plan.json"))).resolve()
    validate_prior_snapshots(cascade)
    validate_prior_snapshots(location)
    output = scratch / ("information-readiness-v16-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Information readiness output: " + str(output), flush=True)
    inputs = retained_sources(cascade, location, profile)
    input_hashes = snapshot(inputs, output / "input_snapshot")
    source_names = {"scripts/audit_information_readiness.py", "src/selective_analysis/information_readiness.py",
                    "src/selective_analysis/trace_headroom.py", "src/selective_analysis/cascade_evaluation.py",
                    "src/selective_analysis/contracts.py", "src/selective_analysis/workspace.py",
                    "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v16.md",
                    *(item[1] for item in SOURCE_FINDINGS)}
    sources = {name: ROOT / name for name in sorted(source_names)}
    source_hashes = snapshot(sources, output / "source_snapshot")
    plan = {"schema": "symbai.information_readiness_plan.v1", "revision": REVISION,
            "cascade_root": str(cascade), "location_root": str(location), "historical_profile_root": str(profile),
            "input_sha256": input_hashes, "input_sources": {k: str(v) for k, v in inputs.items()},
            "source_sha256": source_hashes, "study": "retrospective_offline_gate",
            "fresh_model_or_property_execution": False, "new_queries_or_variants": False}
    write(output / "run-plan.json", plan)
    archived = output / "input_snapshot"
    rows, refs, gold = [read(archived / "cascade" / name) for name in ("records.json", "references.json", "inputs/gold.json")]
    headroom = summarize_trace_headroom(rows, refs, gold)
    contracts = read(archived / "cascade/inputs/queries.json")["queries"]
    queries, blobs = [], {}
    for contract in contracts:
        contract = dict(contract)
        if Path(contract["binary"]).name != contract["binary"]:
            raise ValueError("Copied cascade binary must be a flat relative name")
        binary = archived / "cascade/inputs" / contract["binary"]
        contract["binary"] = str(binary)
        query = Query.from_dict(contract)
        queries.append(query)
        blobs[query.query_id] = binary.read_bytes()
    if (len(queries) != 3 or len({q.contract_hash for q in queries}) != 3
            or {q.contract_hash for q in queries} != {row["query_hash"] for row in rows}):
        raise ValueError("Copied query manifest differs from validated trial identities")
    frozen_cases = load_frozen_cases(archived / "location")
    availability = availability_inventory(queries, blobs, frozen_cases)
    findings = []
    for name, relative, anchor, count in SOURCE_FINDINGS:
        lines = (output / "source_snapshot" / relative).read_text(encoding="utf-8").splitlines()
        line, excerpt = finding_excerpt(name, lines, anchor, count)
        findings.append({"finding_id": name, "source": relative, "sha256": source_hashes[relative],
                         "line": line, "excerpt": excerpt,
                         "role": "source_evidence_for_review_not_an_executed_mapping_test"})
    context = historical_context(archived / "historical-profile", {q.contract_hash for q in queries})
    write(output / "availability.json", {**availability, "frozen_cases": frozen_cases})
    write(output / "trace-headroom.json", headroom)
    write(output / "source-findings.json", findings)
    write(output / "historical-context.json", context)
    imports = forbidden_imports()
    changed_inputs = [name for name, path in inputs.items() if file_hash(path) != input_hashes[name]]
    changed_copies = [name for name, digest in input_hashes.items() if file_hash(archived / name) != digest]
    changed_sources = [name for name, path in sources.items() if file_hash(path) != source_hashes[name]]
    if imports or changed_inputs or changed_copies or changed_sources:
        raise RuntimeError("Offline import or source/input integrity violation")
    summary = {"schema": "symbai.information_readiness_summary.v1", "revision": REVISION,
               "unique_complementary_queries": len(queries), "frozen_genuine_export_queries": len(frozen_cases),
               "exact_mapped_query_intersection": availability["exact_mapped_query_intersection"],
               "ready_for_neural_comparison": availability["exact_mapped_query_intersection"] == len(queries),
               "trace_headroom": headroom["aggregate"], "historical_context": context,
               "forbidden_runtime_imports": imports, "changed_inputs": changed_inputs,
               "changed_copied_inputs": changed_copies, "changed_sources": changed_sources,
               "diagnostic_through_aggregation_seconds": time.monotonic() - started,
               "diagnostic_clock_is_deployment_cost": False,
               "final_summary_serialization_excluded": True, "fresh_model_or_property_execution": False,
               "counterfactual_only": True, "neural_benefit_measured": False,
               "interpretation": "Frozen mapped type exports and complementary-operation queries must intersect before a valid C/D comparison. Trace deletion is optimistic offline accounting, not a measured neural gain or real-time upper bound."}
    write(output / "summary.json", summary)
    print(json.dumps({k: summary[k] for k in ("schema", "unique_complementary_queries", "frozen_genuine_export_queries", "exact_mapped_query_intersection", "ready_for_neural_comparison", "trace_headroom", "fresh_model_or_property_execution", "neural_benefit_measured")}, indent=2))
    print("Finished. Existing files unchanged; no WSL/model/checker run required: " + str(output))


if __name__ == "__main__":
    main()
