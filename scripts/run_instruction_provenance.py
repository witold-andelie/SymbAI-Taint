#!/usr/bin/env python3
"""Record syntax-only register provenance on the three retained mechanism binaries."""

import argparse
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

from src.selective_analysis.contracts import file_hash, fingerprint
from src.selective_analysis.instruction_provenance import REVISION, build_syntax_provenance
from src.selective_analysis.provenance_validation import validate_syntax_graph
from src.selective_analysis.processes import run_bounded
from src.selective_analysis.workspace import configure_workspace

CASE_IDS = ("scalar_span", "readonly_chain", "readonly_chain_outside")
FROZEN_IDENTITIES = {
    "scalar_span": ("137e0a130e8c81c2191d4a81f73b79a76c7a206940d2f826fcfe8cc7c469222e", "4cd9feba854cdafd4df107d5679610a367579a8aa335e6c2bbe3b924d98723ae"),
    "readonly_chain": ("546e1e361aaee040edf94fed45be9820a0d02ec1af1e50a1ff418af24edf5f58", "b6a1bd54786692f92dda03c0ad63c62d1f62179574fb0c376210752ed24d170f"),
    "readonly_chain_outside": ("1fc13b988fe7f1f83340c5a628d70c92b5c0c1bcde4a9f85c633fb661a096d48", "f40a81b706a45b5b89bfe23d21f63ef287025c75db635f43db59b006eb43631f"),
}
SOURCE_FILES = ("scripts/run_instruction_provenance.py", "src/selective_analysis/instruction_provenance.py",
                "src/selective_analysis/contracts.py", "src/selective_analysis/elf_guard.py",
                "src/selective_analysis/provenance_validation.py",
                "src/selective_analysis/processes.py", "src/selective_analysis/workspace.py",
                "src/selective_analysis/__init__.py", "docs/architecture/pilot_revision_v17.md")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, indent=2).encode("utf-8"))


def metadata():
    return {"python": sys.version, "executable": sys.executable, "platform": sys.platform,
            **{name: version(name) for name in ("pyvex", "archinfo", "capstone", "pyelftools")}}


def forbidden_imports():
    prefixes = ("angr", "claripy", "z3", "torch", "src.selective_analysis.operations",
                "src.selective_analysis.readonly_values", "src.selective_analysis.local_bounds",
                "src.selective_analysis.location_correspondence")
    return sorted(name for name in sys.modules if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes))


def worker(request_path, destination):
    started = time.monotonic()
    runtime = metadata()
    try:
        graph = build_syntax_provenance(read(request_path))
    except Exception as error:
        graph = {"status": "unavailable", "reason": type(error).__name__ + ": " + str(error), "complete": False}
    imports = forbidden_imports()
    if imports:
        graph = {"status": "unavailable", "reason": "forbidden_analysis_import", "retained_graph": graph, "complete": False}
    write(destination, {"graph": graph, "runtime": runtime, "forbidden_runtime_imports": imports,
                        "worker_elapsed_seconds": time.monotonic() - started})


def run_case(case_id, request, source_query_hash, output):
    folder = output / "workers" / case_id
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    request_path, result_path = folder / "request.json", folder / "worker-result.json"
    write(request_path, request)
    remaining = 30 - (time.monotonic() - started)
    process = run_bounded([sys.executable, "-B", str(Path(__file__).resolve()),
                           "--worker-request", str(request_path), "--worker-result", str(result_path)],
                          folder / "worker.log", remaining, env=os.environ.copy())
    try:
        candidate = read(result_path)
        identity = {key: request[key] for key in ("binary_sha256", "entry_rva", "target_store_rva")}
        graph = candidate["graph"]
        if graph.get("status") == "available":
            validate_syntax_graph(graph, request)
            if candidate.get("forbidden_runtime_imports") != []:
                raise ValueError("Worker imported a forbidden analysis/model module")
            runtime = candidate.get("runtime", {})
            if any(not isinstance(runtime.get(key), str) or not runtime[key]
                   for key in ("python", "executable", "platform", "pyvex", "archinfo", "capstone", "pyelftools")):
                raise ValueError("Worker omitted actual runtime provenance")
    except Exception as error:
        candidate = {"graph": {"status": "unavailable", "complete": False,
                               "reason": "worker_recovery_failed:" + str(error)}}
    payload = {"schema": "symbai.syntax_trial_payload.v1", "case_id": case_id,
               "request_fingerprint": fingerprint(request), "source_query_hash": source_query_hash,
               "worker_candidate": candidate, "process": vars(process)}
    payload_path = folder / "trial-payload.json"
    write(payload_path, payload)
    digest = file_hash(payload_path)
    elapsed = time.monotonic() - started
    complete = candidate["graph"].get("status") == "available" and candidate["graph"].get("complete") is True
    receipt = {"schema": "symbai.syntax_parent_receipt.v1", "charged_seconds": elapsed, "budget_seconds": 30,
               "late": elapsed >= 30, "payload_sha256": digest, "payload_fingerprint": fingerprint(payload),
               "status": "available" if complete and not process.timed_out and process.returncode == 0 and elapsed < 30 else "unavailable",
               "clock_unit": "request_through_complete_payload_persistence",
               "excluded": ["final_accounting_receipt_serialization", "aggregate_copying"],
               "cost_is_policy_or_neural_comparison": False}
    write(folder / "receipt.json", receipt)
    return {"case_id": case_id, "payload": payload, "parent_receipt": receipt}


def latest(root):
    candidates = sorted((p for p in root.glob("fixed-cascade-v15-*")
                         if all((p / "inputs" / name).is_file() for name in ("queries.json", *(name + ".elf" for name in CASE_IDS)))), reverse=True)
    if not candidates:
        raise FileNotFoundError("No retained complete v15 input panel")
    return candidates[0]


def unchanged(path, digest):
    try:
        return file_hash(path) == digest
    except OSError:
        return False


def validate_frozen_contract(contract):
    case_id = contract.get("query_id")
    if case_id not in FROZEN_IDENTITIES or contract.get("binary") != case_id + ".elf":
        raise ValueError("Unexpected retained case/binary path")
    identity = dict(contract)
    identity.pop("binary")
    query_hash = fingerprint(identity)
    if (contract.get("binary_sha256"), query_hash) != FROZEN_IDENTITIES[case_id]:
        raise ValueError("Input differs from the original frozen binary/query identity")
    return query_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--worker-request", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    scratch = configure_workspace()
    if args.worker_request:
        if not args.worker_result:
            parser.error("Worker output required")
        worker(args.worker_request, args.worker_result)
        return
    retained = (args.input_dir or latest(scratch)).resolve()
    plan = read(retained / "run-plan.json")
    names = ("queries.json", *(name + ".elf" for name in CASE_IDS))
    if any(not unchanged(retained / "inputs" / name, plan["input_sha256"][name]) for name in names):
        raise ValueError("Retained input differs from the v15 plan")
    output = scratch / ("instruction-provenance-v17-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Instruction provenance output: " + str(output), flush=True)
    input_hashes, source_hashes = {}, {}
    for name in names:
        target = output / "inputs" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(retained / "inputs" / name, target)
        input_hashes[name] = file_hash(target)
        if input_hashes[name] != plan["input_sha256"][name]:
            raise ValueError("Input changed during copy")
    for name in SOURCE_FILES:
        target = output / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        source_hashes[name] = file_hash(ROOT / name)
        shutil.copyfile(ROOT / name, target)
        if file_hash(target) != source_hashes[name]:
            raise ValueError("Source changed during copy")
    manifest = read(output / "inputs/queries.json")
    contracts = manifest["queries"]
    if (manifest.get("schema") != "symbai.queries.v1" or len(contracts) != 3
            or {contract["query_id"] for contract in contracts} != set(CASE_IDS)):
        raise ValueError("Three-query input panel differs")
    requests = []
    for contract in contracts:
        query_hash = validate_frozen_contract(contract)
        binary = output / "inputs" / contract["binary"]
        if file_hash(binary) != contract["binary_sha256"]:
            raise ValueError("Manifest binary identity differs")
        stripped = {"schema": "symbai.syntax_request.v1", "binary": str(binary),
                    "binary_sha256": contract["binary_sha256"], "entry_rva": contract["entry_rva"],
                    "target_store_rva": contract["write_rva"]}
        requests.append((contract["query_id"], stripped, query_hash))
    write(output / "run-plan.json", {"schema": "symbai.syntax_plan.v1", "revision": REVISION,
          "input_root": str(retained), "planned_cases": 3, "worker_budget_seconds": 30,
          "input_sha256": input_hashes, "source_sha256": source_hashes,
          "property_parameters_stripped_before_runtime": True, "gold_or_raw_types_read": False,
          "runtime": metadata()})
    rows, groups = [], {}
    for case_id, request, query_hash in requests:
        row = run_case(case_id, request, query_hash, output)
        rows.append(row)
        status = row["parent_receipt"]["status"]
        graph = row["payload"]["worker_candidate"]["graph"]
        if status == "available":
            groups.setdefault(graph["syntax_fingerprint"], []).append(case_id)
        print(f"{case_id}: {status}; {len(graph.get('nodes', []))} nodes, {len(graph.get('accesses', []))} memory syntax bindings", flush=True)
    write(output / "records.json", rows)
    changed_sources = [name for name, digest in source_hashes.items() if not unchanged(ROOT / name, digest)]
    changed_inputs = [name for name, digest in input_hashes.items() if not unchanged(retained / "inputs" / name, digest)]
    changed_copies = [name for name, digest in input_hashes.items() if not unchanged(output / "inputs" / name, digest)]
    summary = {"schema": "symbai.syntax_summary.v1", "planned_cases": 3, "retained_cases": len(rows),
               "available": sum(r["parent_receipt"]["status"] == "available" for r in rows),
               "unavailable": sum(r["parent_receipt"]["status"] != "available" for r in rows),
               "equal_syntax_groups": list(groups.values()), "changed_sources": changed_sources,
               "changed_inputs": changed_inputs, "changed_copied_inputs": changed_copies,
               "property_verification_performed": False, "model_inference_performed": False,
               "tygr_readout_compatibility_validated": False, "neural_benefit_measured": False,
               "held_out_evaluation": False,
               "interpretation": "Instruction syntax/register-byte provenance only; opaque loads, no property decision or TYGR compatibility claim."}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    if changed_sources or changed_inputs or changed_copies:
        raise RuntimeError("Source/input identities changed")


if __name__ == "__main__":
    main()
