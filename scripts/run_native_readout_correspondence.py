#!/usr/bin/env python3
"""Offline native readout/location and graph-frontier diagnostic on three retained cases."""

import argparse
import ast
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

from scripts.audit_native_preprocessing import audit as audit_native, ANCHORS
from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis.workspace import configure_workspace

NATIVE_ROOT = ROOT.parent / ".scratch/selective_analysis/native-preprocessing-v19-20261112-132805-3628"
CASE_IDS = ("direct_index", "offset_index", "masked_index")
SOURCE_FILES = ("scripts/run_native_readout_correspondence.py", "scripts/audit_native_preprocessing.py",
    "scripts/__init__.py", "src/__init__.py",
    "src/selective_analysis/native_readout_correspondence.py", "src/selective_analysis/native_readout_frontier.py",
    "src/selective_analysis/native_input_validation.py", "src/selective_analysis/location_correspondence.py",
    "src/selective_analysis/types.py", "src/selective_analysis/contracts.py", "src/selective_analysis/elf_guard.py",
    "src/selective_analysis/workspace.py", "src/selective_analysis/__init__.py",
    "docs/architecture/pilot_revision_v20.md", "docs/architecture/pilot_revision_v19_erratum.md")
UPSTREAM_FILES = ("src/analysis/angr/ast_graph.py", "src/analysis/angr/bityr_annots.py",
                  "src/analysis/angr/sim_exec.py", "src/methods/glow/datagen.py")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, indent=2, allow_nan=False).encode("utf-8"))


def snapshot(paths, destination):
    hashes = {}
    for name, path in paths.items():
        digest = file_hash(path)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if file_hash(target) != digest:
            raise ValueError("Snapshot changed: " + name)
        hashes[name] = digest
    return hashes


def source_semantics(snapshot_root):
    graph_path = snapshot_root / "tygr_original/src/analysis/angr/ast_graph.py"
    graph = ast.parse(graph_path.read_text(encoding="utf-8"))
    collector, = [node for node in graph.body if isinstance(node, ast.FunctionDef) and node.name == "get_state_WR"]
    summaries = []
    for node in ast.walk(collector):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple) and node.value.elts:
            first = node.value.elts[0]
            if isinstance(first, ast.Attribute) and first.attr == "bbl_addr":
                summaries.append({"line": node.lineno, "assignment": ast.unparse(node), "address_attribute": "bbl_addr"})
    if len(summaries) != 4:
        raise ValueError("Unreviewed native history-summary address source")
    hooks = ast.parse((snapshot_root / "tygr_original/src/analysis/angr/sim_exec.py").read_text(encoding="utf-8"))
    direct = [node for node in ast.walk(hooks) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in {"RegisterReadAnnotation", "RegisterWriteAnnotation", "MemoryReadAnnotation", "MemoryWriteAnnotation"}
              and node.args and ast.unparse(node.args[0]) == "state.addr"]
    if len(direct) != 4:
        raise ValueError("Unreviewed native direct-hook annotation address source")
    return {"schema": "symbai.native_readout_source_semantics.v1", "history_summary_assignments": summaries,
        "direct_hook_annotations": [{"line": node.lineno, "annotation_class": node.func.id,
                                     "address_expression": "state.addr"} for node in direct],
        "annotation_address_has_mixed_context": True,
        "v19_exports_annotation_class": False, "v19_exports_event_order": False,
        "v19_exports_instruction_statement_or_path_identity": False,
        "scope": "source_control_flow_evidence_not_observed_event_provenance"}


def minimal_request(case, native_plan, copied):
    query, = read(copied / "native" / case / "queries.json")["queries"]
    query = dict(query)
    query.pop("binary")
    binary = copied / "native" / case / "query.elf"
    if (file_hash(binary), fingerprint(query)) != ANCHORS[case]:
        raise ValueError("Fixed query/binary identity differs: " + case)
    planned, = [entry for entry in native_plan["case_identities"] if entry["case_id"] == case]
    if query["entry_rva"] != planned["entry_rva"] or fingerprint(query) != planned["source_query_hash"]:
        raise ValueError("Native query identity differs")
    capture = read(copied / "native" / case / "capture.json")
    request = {"schema": "symbai.native_readout_request.v1", "binary": str(binary.resolve()),
        "binary_sha256": file_hash(binary), "entry_rva": query["entry_rva"], "write_rva": query["write_rva"],
        "native_capture_fingerprint": fingerprint(capture)}
    return request, capture


def forbidden_imports():
    forbidden = ("angr", "claripy", "z3", "torch", "pyvex", "src.methods",
        "src.selective_analysis.operations", "src.selective_analysis.operand_mapping",
        "src.selective_analysis.compiled_fact_audit", "src.selective_analysis.frame_bounds")
    return sorted(name for name in sys.modules if any(name == p or name.startswith(p + ".") for p in forbidden))


def loaded_project_sources(modules=None):
    sources = set()
    for module in (sys.modules if modules is None else modules).values():
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        path = Path(filename).resolve()
        if path.suffix == ".py" and path.is_relative_to(ROOT):
            sources.add(path.relative_to(ROOT).as_posix())
    return sorted(sources)


def unchanged(path, expected):
    try:
        return file_hash(path) == expected
    except OSError:
        return False


def run_case(name, output, native_plan, expected):
    from src.selective_analysis.native_readout_correspondence import build_native_readout_correspondence
    from src.selective_analysis.native_readout_frontier import inspect_native_frontier
    folder = output / "cases" / name
    folder.mkdir(parents=True)
    request, capture = minimal_request(name, native_plan, output / "input_snapshot")
    write(folder / "request.json", request)
    started = time.monotonic()
    try:
        correspondence = build_native_readout_correspondence(request, capture, expected)
        target, = [f for f in capture["functions"] if f["is_target"]]
        try:
            frontier = inspect_native_frontier(request, target, expected)
        except Exception as error:
            frontier = {"status": "unavailable", "error": {"type": type(error).__name__, "message": str(error)}}
        record = {"case_id": name, "request": request, "correspondence": correspondence, "frontier": frontier}
    except Exception as error:
        record = {"case_id": name, "request": request, "correspondence": {"status": "unavailable",
            "occurrences": [], "occurrence_records": [], "error": {"type": type(error).__name__, "message": str(error)}},
            "frontier": {"status": "unavailable", "reason": "correspondence_failed"}}
    record["diagnostic_seconds"] = time.monotonic() - started
    record["forbidden_runtime_imports"] = forbidden_imports()
    if record["forbidden_runtime_imports"]:
        raise RuntimeError("Forbidden runtime imports: " + repr(record["forbidden_runtime_imports"]))
    write(folder / "record.json", record)
    return record


def summarize(rows):
    if len(rows) != 3 or {r["case_id"] for r in rows} != set(CASE_IDS):
        raise ValueError("Retain all three planned cases")
    by_case, group_count = [], 0
    for row in rows:
        report = row["correspondence"]
        bindings = report.get("occurrence_records", [])
        available = [b for b in bindings if b["status"] == "available"]
        if len(bindings) > 2:
            raise ValueError("Unexpected address-load occurrence count")
        group_count += len(available)
        for entry in available:
            if entry.get("exact_event_verified") is not False:
                raise ValueError("An unproven exact-event result was upgraded")
        frontier = row["frontier"]
        by_case.append({"case_id": row["case_id"], "observed_address_loads": len(bindings),
            "associated_groups": len(available), "unavailable_groups": 2 - len(available),
            "exact_events_verified": 0, "exact_events_unverified": 2,
            "target_candidates_count": frontier.get("target_candidates_count"),
            "frontier_member_count": frontier.get("frontier_member_count"),
            "frontier_status": frontier.get("status", "recorded"), "diagnostic_seconds": row["diagnostic_seconds"]})
    return {"schema": "symbai.native_readout_summary.v1", "planned_queries": 3, "planned_address_load_occurrences": 6,
        "associated_groups": group_count, "unavailable_groups": 6 - group_count,
        "exact_events_verified": 0, "exact_events_unverified": 6, "cases": by_case,
        "frontier_errors": sum("error" in row["frontier"] or row["frontier"].get("reason") == "correspondence_failed" for row in rows),
        "semantic_roles_verified": False, "native_prediction_aggregation_changed": False,
        "historical_native_acquisition_included": False, "model_forward_performed": False,
        "property_verification_performed": False, "v17_projection_validated": False,
        "neural_selection_measured": False, "held_out_evaluation": False,
        "forbidden_runtime_imports": sorted({name for row in rows for name in row["forbidden_runtime_imports"]}),
        "scope": "coarse_native_variable_group_association_and_exploratory_graph_frontier_only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", type=Path, default=NATIVE_ROOT)
    args = parser.parse_args()
    scratch = configure_workspace()
    native = args.native_dir.resolve()
    native_audit = audit_native(native)
    output = scratch / ("native-readout-v20-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Native readout output: " + str(output), flush=True)
    inputs = {"native-plan.json": native / "run-plan.json", "native-records.json": native / "records.json",
              "native-summary.json": native / "summary.json", "expected-model-contract.json": native / "expected-model-contract.json"}
    for name in CASE_IDS:
        inputs.update({"native/" + name + "/query.elf": native / "input_snapshot/native" / name / "query.elf",
            "native/" + name + "/queries.json": native / "input_snapshot/native" / name / "original-queries.json",
            "native/" + name + "/capture.json": native / "workers" / name / "capture.json"})
    sources = {name: ROOT / name for name in SOURCE_FILES}
    sources.update({"tygr_original/" + name: native / "source_snapshot/tygr_original" / name for name in UPSTREAM_FILES})
    input_hashes = snapshot(inputs, output / "input_snapshot")
    source_hashes = snapshot(sources, output / "source_snapshot")
    write(output / "native-audit.json", native_audit)
    write(output / "source-semantics.json", source_semantics(output / "source_snapshot"))
    write(output / "run-plan.json", {"schema": "symbai.native_readout_plan.v1", "planned_cases": list(CASE_IDS),
        "source_sha256": source_hashes, "input_sha256": input_hashes,
        "source_paths": {k: str(v) for k, v in sources.items()}, "input_paths": {k: str(v) for k, v in inputs.items()},
        "runtime": {"python": sys.version, "platform": sys.platform, "capstone": version("capstone"), "pyelftools": version("pyelftools")},
        "diagnostic_clock": "per_case_analysis_only_not_historical_acquisition_or_deployment_cost",
        "new_native_generation_or_model_forward_authorized": False})
    expected, native_plan = read(output / "input_snapshot/expected-model-contract.json"), read(output / "input_snapshot/native-plan.json")
    rows = []
    for name in CASE_IDS:
        row = run_case(name, output, native_plan, expected)
        rows.append(row)
        write(output / "records.json", rows)
        bindings = row["correspondence"].get("occurrence_records", [])
        print("{}: {}/2 group associations; exact event proof unverified; frontier {}".format(
            name, sum(b["status"] == "available" for b in bindings), row["frontier"].get("status", "recorded")), flush=True)
    summary = summarize(rows)
    summary["loaded_project_sources"] = loaded_project_sources()
    summary["untracked_loaded_project_sources"] = sorted(set(summary["loaded_project_sources"]) - set(source_hashes))
    summary.update({"changed_sources": [name for name, digest in source_hashes.items() if not unchanged(sources[name], digest)],
        "changed_copied_sources": [name for name, digest in source_hashes.items() if not unchanged(output / "source_snapshot" / name, digest)],
        "changed_inputs": [name for name, digest in input_hashes.items() if not unchanged(inputs[name], digest)],
        "changed_copied_inputs": [name for name, digest in input_hashes.items() if not unchanged(output / "input_snapshot" / name, digest)]})
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    if any(summary[key] for key in ("changed_sources", "changed_copied_sources", "changed_inputs", "changed_copied_inputs")):
        raise RuntimeError("Source/input integrity changed")
    if summary["untracked_loaded_project_sources"]:
        raise RuntimeError("Loaded project dependencies were omitted from the source snapshot")
    if summary["unavailable_groups"] or summary["frontier_errors"]:
        raise SystemExit(1)
    print("Finished. Group association and graph frontier only; no exact-event or neural-gain claim: " + str(output))


if __name__ == "__main__":
    main()
