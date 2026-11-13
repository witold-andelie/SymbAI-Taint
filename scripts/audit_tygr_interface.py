#!/usr/bin/env python3
"""Offline audit of frozen checkpoint metadata against the unprojected v17 interface."""

import argparse
import ast
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from src.selective_analysis.checkpoint_metadata import inspect_frozen_checkpoint
from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis.model_interface import CASES, MODEL_SHA256, REVISION, analyze_model_interface
from src.selective_analysis.workspace import configure_workspace

FINDINGS = (
    ("architecture_token_encoding", "tygr_original/src/methods/glow/preproc.py", "encode_arch", 12),
    ("value_address_features", "tygr_original/src/methods/glow/preproc.py", "encode_node_features", 88),
    ("width_encoding", "tygr_original/src/methods/glow/preproc.py", "encode_bit_vector", 36),
    ("edge_direction_and_label_choice", "tygr_original/src/methods/glow/preproc.py", "encode_edge_label", 15),
    ("preprocessing_context_and_flattening", "tygr_original/src/methods/glow/preproc.py", "preproc_input", 58),
    ("ast_value_and_deduplication", "tygr_original/src/analysis/angr/ast_graph.py", "process_ast", 45),
    ("ast_context_slicing", "tygr_original/src/analysis/angr/ast_graph.py", "directed_splice_and_normalize", 42),
    ("saved_variable_readout_unit", "tygr_original/src/methods/glow/common.py", "GlowVar", 20),
    ("forward_readout_semantics", "tygr_original/src/methods/glow/model.py", "GlowGNN.forward", 30),
    ("source_model_constructor", "tygr_original/src/methods/glow/model.py", "Config.__init__", 48),
    ("current_relation_vocabulary", "tygr_original/src/analysis/angr/edge.py", "REDUCED_OPS", 20),
    ("serial_generator_architecture_literal", "tygr_original/src/methods/glow/datagen.py", "generate_glow_dataset_no_parallel", 90),
    ("batch_readout_indices", "tygr_original/src/methods/glow/predict.py", "collate_inputs", 45),
    ("export_row_aggregation", "scripts/export_tygr_candidates.py", "pack_logits", 20),
    ("export_value_node_axis", "scripts/export_tygr_candidates.py", "main", 130),
)
SOURCE_FILES = ("scripts/audit_tygr_interface.py", "src/selective_analysis/checkpoint_metadata.py",
                "src/selective_analysis/model_interface.py", "src/selective_analysis/provenance_validation.py",
                "src/selective_analysis/contracts.py", "src/selective_analysis/workspace.py",
                "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v18.md")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def latest(scratch):
    for folder in sorted(scratch.glob("instruction-provenance-v17-*"), reverse=True):
        if (folder / "records.json").is_file() and (folder / "summary.json").is_file():
            rows = read(folder / "records.json")
            if len(rows) == 3 and rows[0]["payload"]["worker_candidate"]["runtime"]["platform"] == "linux":
                return folder
    raise FileNotFoundError("No retained WSL v17 provenance panel")


def snapshot(sources, destination):
    hashes = {}
    for name, source in sources.items():
        hashes[name] = file_hash(source)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != hashes[name]:
            raise ValueError("Input/source changed while snapshotting: " + name)
    return hashes


def syntax_cases(folder, identity_source):
    plan = read(folder / "run-plan.json")
    # Read literal identity anchors from the archived runner; execute no source code.
    source = identity_source.read_text(encoding="utf-8")
    assignments = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "FROZEN_IDENTITIES" for target in node.targets)]
    assignment, = assignments
    anchors = ast.literal_eval(assignment.value)
    contracts = {q["query_id"]: q for q in read(folder / "inputs/queries.json")["queries"]}
    rows = read(folder / "records.json")
    if len(rows) != 3 or len(contracts) != 3 or {row["case_id"] for row in rows} != set(CASES):
        raise ValueError("Retained syntax panel denominator differs")
    for name, digest in plan["input_sha256"].items():
        if Path(name).name != name or file_hash(folder / "inputs" / name) != digest:
            raise ValueError("Retained syntax binary/manifest changed")
    result = []
    for row in rows:
        name, payload, receipt = row["case_id"], row["payload"], row["parent_receipt"]
        contract = dict(contracts[name])
        if contract.pop("binary") != name + ".elf" or file_hash(folder / "inputs" / (name + ".elf")) != anchors[name][0]:
            raise ValueError("Copied ELF bytes/path differ from the original pinned identity")
        if (contract["binary_sha256"], fingerprint(contract)) != anchors[name]:
            raise ValueError("Not the original pinned syntax/query identity")
        request = read(folder / "workers" / name / "request.json")
        worker = payload["worker_candidate"]
        if (receipt["status"] != "available" or receipt["late"] or payload["process"]["timed_out"]
                or payload["process"]["returncode"] or worker["forbidden_runtime_imports"]
                or worker["graph"]["identity"]["binary_sha256"] != contract["binary_sha256"]
                or payload["source_query_hash"] != fingerprint(contract)
                or payload["request_fingerprint"] != fingerprint(request)
                or fingerprint(payload) != receipt["payload_fingerprint"]
                or hashlib.sha256(json.dumps(payload, indent=2).encode("utf-8")).hexdigest() != receipt["payload_sha256"]):
            raise ValueError("Retained parent/worker syntax status or identity differs")
        if (request["entry_rva"], request["target_store_rva"]) != (contract["entry_rva"], contract["write_rva"]):
            raise ValueError("Syntax request sites differ from fixed contract")
        result.append({"case_id": name, "request": request, "graph": worker["graph"]})
    return result


def excerpt(source, qualified_name, limit):
    tree = ast.parse(source)
    parts = qualified_name.split(".")
    candidates = tree.body
    selected = None
    for part in parts:
        selected, = [node for node in candidates if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == part]
        candidates = selected.body
    if selected is None:
        raise ValueError("Missing source evidence node")
    lines = source.splitlines()
    return selected.lineno, lines[selected.lineno - 1:min(selected.end_lineno, selected.lineno - 1 + limit)]


def source_finding(name, path, qualified, limit):
    source = path.read_text(encoding="utf-8")
    if qualified == "REDUCED_OPS":
        statement, = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == qualified for target in node.targets)]
        line = statement.lineno
        lines = source.splitlines()[line - 1:statement.end_lineno]
    elif qualified in ("process_ast", "directed_splice_and_normalize"):
        line, lines = excerpt(source, "AstGraph." + qualified, limit)
    else:
        line, lines = excerpt(source, qualified, limit)
    return {"finding_id": name, "source_line": line, "excerpt": lines,
            "scope": "hashed_source_evidence_not_a_runtime_projection"}


def forbidden_imports():
    prefixes = ("torch", "torch_geometric", "angr", "claripy", "z3", "pyvex", "archinfo", "capstone", "elftools",
                "src.selective_analysis.instruction_provenance", "src.selective_analysis.operations")
    return sorted(name for name in sys.modules if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syntax-dir", type=Path)
    parser.add_argument("--model", type=Path, default=ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model")
    args = parser.parse_args()
    scratch = configure_workspace()
    started = time.monotonic()
    retained, model = (args.syntax_dir or latest(scratch)).resolve(), args.model.resolve()
    if file_hash(model) != MODEL_SHA256:
        raise ValueError("The frozen checkpoint SHA-256 differs")
    syntax_plan = read(retained / "run-plan.json")
    for name, digest in syntax_plan["source_sha256"].items():
        if file_hash(retained / "source_snapshot" / name) != digest or file_hash(ROOT / name) != digest:
            raise ValueError("Frozen v17 source differs: " + name)
    output = scratch / ("model-interface-v18-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Model interface audit output: " + str(output), flush=True)
    inputs = {"checkpoint/x64.O0.base.model": model}
    for name in ("run-plan.json", "records.json", "summary.json", "inputs/queries.json", *("inputs/" + case + ".elf" for case in CASES)):
        inputs["syntax/" + name] = retained / name
    for case in CASES:
        inputs[f"syntax/workers/{case}/request.json"] = retained / "workers" / case / "request.json"
    input_hashes = snapshot(inputs, output / "input_snapshot")
    source_names = sorted({*SOURCE_FILES, *(finding[1] for finding in FINDINGS), "scripts/run_instruction_provenance.py"})
    sources = {name: ROOT / name for name in source_names}
    source_hashes = snapshot(sources, output / "source_snapshot")
    write(output / "run-plan.json", {"schema": "symbai.model_interface_plan.v1", "revision": REVISION,
          "source_sha256": source_hashes, "input_sha256": input_hashes,
          "input_sources": {name: str(path) for name, path in inputs.items()}, "fixed_queries": 3,
          "model_sha256": MODEL_SHA256, "syntax_root": str(retained), "model_arrays_or_framework_loaded": False})
    metadata = inspect_frozen_checkpoint(output / "input_snapshot/checkpoint/x64.O0.base.model")
    cases = syntax_cases(output / "input_snapshot/syntax", output / "source_snapshot/scripts/run_instruction_provenance.py")
    report = analyze_model_interface(metadata, cases)
    findings = []
    for name, relative, function, limit in FINDINGS:
        finding = source_finding(name, output / "source_snapshot" / relative, function, limit)
        findings.append({**finding, "source": relative, "source_sha256": source_hashes[relative]})
    write(output / "checkpoint-metadata.json", metadata)
    write(output / "interface-report.json", report)
    write(output / "source-findings.json", findings)
    imports = forbidden_imports()
    changed_inputs = [name for name, path in inputs.items() if file_hash(path) != input_hashes[name]]
    changed_copies = [name for name, digest in input_hashes.items() if file_hash(output / "input_snapshot" / name) != digest]
    changed_sources = [name for name, path in sources.items() if file_hash(path) != source_hashes[name]]
    changed_source_copies = [name for name, digest in source_hashes.items() if file_hash(output / "source_snapshot" / name) != digest]
    if imports or changed_inputs or changed_copies or changed_sources or changed_source_copies:
        raise RuntimeError("Offline interface audit imported forbidden engines or changed inputs/sources")
    summary = {"schema": "symbai.model_interface_summary.v1", "revision": REVISION, "unique_queries": 3,
               "model_sha256": MODEL_SHA256, "saved_node_features": metadata["preproc_config"]["node_label_encoding_dim"],
               "declared_relation_count": metadata["preproc_config"]["num_edge_ops"],
               "actual_layer_relation_capacities": report["relation_domain"]["active_layer_capacities"],
               "potential_encoded_ids_outside_active_layers": report["relation_domain"]["potential_encoded_ids_outside_active_layers"],
               "totals": report["totals"], "direct_bridge_ready": report["direct_bridge_ready"], "blockers": report["blockers"],
               "forbidden_runtime_imports": imports, "changed_sources": changed_sources,
               "changed_source_copies": changed_source_copies,
               "changed_inputs": changed_inputs, "changed_copied_inputs": changed_copies,
               "diagnostic_through_aggregation_seconds": time.monotonic() - started,
               "diagnostic_clock_is_acquisition_or_deployment_cost": False, "final_summary_serialization_excluded": True,
               "external_model_code_executed": False, "feature_tensors_created": False, "inference_performed": False,
               "neural_benefit_measured": False, "historical_prepared_edge_usage_observed": False,
               "interpretation": report["interpretation"]}
    write(output / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("schema", "unique_queries", "saved_node_features", "declared_relation_count",
          "actual_layer_relation_capacities", "potential_encoded_ids_outside_active_layers", "totals", "direct_bridge_ready",
          "blockers", "inference_performed")}, indent=2))
    print("Finished. Passive metadata only; no new WSL/model execution required: " + str(output))


if __name__ == "__main__":
    main()
