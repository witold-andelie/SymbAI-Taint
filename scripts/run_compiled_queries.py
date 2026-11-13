#!/usr/bin/env python3
"""Acquire and verify two compiled developer queries; no scheduler comparison."""

import argparse
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
FLAGS = ["-gdwarf-4", "-O0", "-fPIE", "-pie", "-fno-stack-protector",
         "-fno-omit-frame-pointer", "-fno-inline", "-fno-builtin"]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_export(raw, query, acquisition_id):
    provenance = raw.get("provenance", {})
    if (raw.get("schema") != "symbai.tygr_raw.v1" or raw.get("acquisition_id") != acquisition_id
            or raw.get("binary_sha256") != query.binary_sha256
            or provenance.get("source") != "tygr_glowgnn" or provenance.get("model_sha256") != MODEL_HASH
            or provenance.get("decoder") != "independent" or provenance.get("locator") != "dwarf_assisted"
            or provenance.get("flatten_vars") is not True
            or provenance.get("ground_truth_labels_supplied_to_model") is not False
            or not raw.get("records")):
        raise ValueError("Fresh unlabeled raw export identity failed")


def offline_summary(cases, rows, labels):
    """Join labels only after runtime. Failed cases remain in the planned denominator."""
    ids = [case["query_id"] for case in cases]
    expected = {entry["query_id"]: entry["expected"] for entry in labels["labels"]}
    if (labels.get("schema") != "symbai.compiled_query_labels.v1" or len(set(ids)) != len(ids)
            or len(expected) != len(labels["labels"]) or set(expected) != set(ids)
            or [r["query_id"] for r in rows] != ids
            or any(v not in ("violation", "excluded_within_scope") for v in expected.values())):
        raise ValueError("Offline labels or planned-case coverage differ")
    judgments = []
    for row in rows:
        status = row.get("property", {}).get("status", "unknown")
        judgments.append({"query_id": row["query_id"], "expected": expected[row["query_id"]],
            "actual": status, "judgment": "unknown" if status == "unknown" else (
                "correct" if status == expected[row["query_id"]] else "wrong")})
    return {"schema": "symbai.compiled_query_summary.v1", "planned_queries": len(ids),
        "extracted_queries": sum("query" in r for r in rows),
        "unique_query_hashes": len({r["query_hash"] for r in rows if "query_hash" in r}),
        "fresh_exports": sum(r.get("acquisition", {}).get("status") == "completed" for r in rows),
        "verified_mappings": sum(r.get("mapping", {}).get("status") == "verified" for r in rows),
        **{k: sum(j["judgment"] == k for j in judgments) for k in ("correct", "wrong", "unknown")},
        "judgments": judgments, "scheduler_integration": False, "held_out_evaluation": False,
        "interpretation": "Two authored developer queries; property validity and mapping success are separate. No neural benefit measured."}


def stage_worker(stage, request, destination):
    from src.selective_analysis.contracts import Query
    from src.selective_analysis.compiled_queries import extract_compiled_query, propose_operand_assignments, resolve_operand_assignment
    started = time.monotonic()
    try:
        if stage == "extract":
            query, metadata = extract_compiled_query(Path(request["binary"]), request["case"])
            result = {"status": "completed", "query": asdict(query), "metadata": metadata}
        else:
            query = Query.from_dict(request["query"])
            if stage == "property":
                from src.selective_analysis.operations import BinaryChecker
                deadline = started + 10
                checker = BinaryChecker(query)
                result = checker.validate(checker.check(128, deadline), 128, deadline)
                if time.monotonic() >= deadline:
                    result = {"status": "unknown", "reason": "late_property_validation", "late_result": result}
            else:
                from src.selective_analysis.operand_mapping import operand_program_facts, map_operand_candidates, load_operand_views
                deadline = started + 20
                folder = destination.parent
                raw = read_json(folder / "raw-types.json")
                proposals = propose_operand_assignments(query, raw, request["anchor"],
                    request["proposal_source_fingerprint"], request["linked_base"])
                write_json(folder / "operand-proposals.json", proposals)
                result = resolve_operand_assignment(query, proposals, deadline,
                    on_attempt=lambda attempts: write_json(folder / "assignment-attempts.json", attempts))
                # Preserve all attempted proofs even if projection fails later.
                write_json(folder / "assignment-search.json", result)
                if result["status"] == "verified":
                    plan, evidence = result["selected_plan"], result["validated_evidence"]
                    write_json(folder / "operand-program-facts.json", operand_program_facts(query, plan, evidence))
                    bundle = map_operand_candidates(query, raw, plan, evidence)
                    path = folder / "operand-types.json"
                    write_json(path, bundle)
                    counts = {}
                    for variant in "ABCD":
                        views = load_operand_views(path, query, variant)
                        counts[variant] = len(views)
                        write_json(folder / ("views-" + variant + ".json"), [
                            {"role": v.role, "prediction_id": v.prediction_id, "operand_id": v.operand_id,
                             "labels": list(v.view.labels), "raw_scores": list(v.view.raw_scores),
                             "features": v.selector_features()} for v in views])
                    result = {"status": "verified", "view_counts": counts,
                        "checks": evidence["checks"], "verification_passes": 2,
                        "scope": evidence["scope"], "raw_predictions_preserved": bundle["raw_export"] == raw}
                if time.monotonic() >= deadline:
                    result = {"status": "unknown", "reason": "late_mapping_result", "late_result": result}
    except Exception as exc:
        result = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc)}
    result["worker_seconds"] = time.monotonic() - started
    write_json(destination, result)


def invoke_stage(stage, request, folder, environment):
    from src.selective_analysis.processes import run_bounded
    cap = {"extract": 30, "property": 10, "mapping": 20}[stage]
    request_path, result_path = folder / (stage + "-request.json"), folder / (stage + "-result.json")
    write_json(request_path, request)
    process = run_bounded([sys.executable, "-B", str(Path(__file__).resolve()),
        "--worker-stage", stage, "--request", str(request_path), "--result", str(result_path)],
        folder / (stage + ".log"), cap, env=environment)
    result = read_json(result_path) if result_path.is_file() else {"status": "unknown", "reason": "missing_worker_result"}
    if process.timed_out or process.returncode or process.elapsed_seconds >= cap:
        result = {"status": "unknown", "reason": "worker_failed_or_exceeded_cap", "late_result": result}
    result["process"] = asdict(process)
    write_json(folder / (stage + "-receipt.json"), result)
    return result


def run_case(case, snapshot, folder, environment, tygr_python):
    from src.selective_analysis.contracts import Query, file_hash, fingerprint
    from src.selective_analysis.processes import run_bounded
    row = {"query_id": case["query_id"], "property": {"status": "unknown"}, "mapping": {"status": "unknown"}}
    binary, source = folder / "query.elf", snapshot / case["source"]
    try:
        compile_result = run_bounded(["gcc", *FLAGS, str(source), "-o", str(binary)],
            folder / "compile.log", 30, env=environment)
        row["compilation"] = asdict(compile_result)
        if compile_result.returncode or compile_result.timed_out or not binary.is_file():
            raise ValueError("Compilation failed; see compile.log")
        extraction = invoke_stage("extract", {"case": case, "binary": str(binary)}, folder, environment)
        row["extraction"] = extraction
        if extraction["status"] != "completed":
            raise ValueError("Query extraction unresolved; see extract-receipt.json")
        query = Query.from_dict(extraction["query"])
        row.update(query=asdict(query), query_hash=query.contract_hash)
        write_json(folder / "queries.json", {"queries": [asdict(query)]})
        # Run independently of acquisition or mapping success; labels are not loaded.
        row["property"] = invoke_stage("property", {"query": asdict(query)}, folder, environment)
        try:
            model = ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"
            if file_hash(model) != MODEL_HASH:
                raise ValueError("Pinned TYGR model hash differs")
            nonce = uuid.uuid4().hex
            command = [str(tygr_python), "-B", str(ROOT / "scripts/export_tygr_candidates.py"),
                "--tygr-root", str(ROOT / "tygr_original"), "--model", str(model),
                "--binary", str(binary), "--output", str(folder / "raw-types.json"),
                "--top-k", "3", "--device", "cpu", "--scratch-dir", environment["TMPDIR"], "--acquisition-id", nonce]
            process = run_bounded(command, folder / "export.log", 120, env=environment)
            receipt = {"status": "unknown", "acquisition_id": nonce, "process": asdict(process)}
            row["acquisition"] = receipt
            write_json(folder / "acquisition-receipt.json", receipt)
            if process.returncode or process.timed_out:
                raise ValueError("Fresh TYGR export failed; see export.log")
            raw_path = folder / "raw-types.json"
            validate_export(read_json(raw_path), query, nonce)
            if file_hash(model) != MODEL_HASH or file_hash(binary) != query.binary_sha256:
                raise ValueError("Model/binary changed during acquisition")
            receipt.update(status="completed", raw_artifact_sha256=file_hash(raw_path), model_sha256=MODEL_HASH)
            write_json(folder / "acquisition-receipt.json", receipt)
            row["mapping"] = invoke_stage("mapping", {"query": asdict(query),
                "anchor": {"kind": "entry_input", "register": case["input"]["register"], "transform": case["index_transform"]},
                "linked_base": extraction["metadata"]["linked_image_base"],
                "proposal_source_fingerprint": fingerprint({"case_spec": case, "source_sha256": file_hash(source),
                    "binary_sha256": query.binary_sha256, "query_hash": query.contract_hash})}, folder, environment)
        except Exception as exc:
            row["neural_failure"] = type(exc).__name__ + ": " + str(exc)
    except Exception as exc:
        row["failure"] = type(exc).__name__ + ": " + str(exc)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--worker-stage", choices=("extract", "property", "mapping"), help=argparse.SUPPRESS)
    parser.add_argument("--request", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    from src.selective_analysis.workspace import configure_workspace
    configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    if args.worker_stage:
        stage_worker(args.worker_stage, read_json(args.request), args.result)
        return 0
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run in WSL angr-env from the D-drive project")
    from src.selective_analysis.compiled_queries import validate_case_spec
    from src.selective_analysis.contracts import file_hash
    spec_root = ROOT / "benchmarks/selective_analysis/compiled_queries"
    specs = read_json(spec_root / "cases.json")
    cases = specs["cases"]
    if specs.get("schema") != "symbai.compiled_query_specs.v1" or [c["query_id"] for c in cases] != ["offset_index", "masked_index"]:
        parser.error("The predeclared two-query specification differs")
    for case in cases:
        validate_case_spec(case)
        if Path(case["source"]).name != case["source"]:
            parser.error("Case source must be a filename inside the specification directory")
    output = ROOT.parent / ".scratch/wsl" / ("compiled-queries-v8-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Compiled queries output: " + str(output), flush=True)
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/export_tygr_candidates.py", ROOT / "docs/architecture/pilot_revision_v8.md",
        spec_root / "cases.json", *[spec_root / c["source"] for c in cases]]
    hashes = {}
    for source in sources:
        relative = source.relative_to(ROOT)
        hashes[relative.as_posix()] = file_hash(source)
        archived = output / "source_snapshot" / relative
        archived.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, archived)
    write_json(output / "run-plan.json", {"revision_spec": "docs/architecture/pilot_revision_v8.md",
        "source_sha256": hashes, "cases": cases, "compiler_flags": FLAGS, "python": platform.python_version(),
        "platform": platform.platform(), "model_sha256": MODEL_HASH,
        "caps_seconds": {"compilation": 30, "extraction": 30, "export": 120, "mapping": 20, "property": 10},
        "scheduler_integration": False, "scope": "separate_authored_developer_queries_not_held_out_or_A_D"})
    rows = []
    for case in cases:
        folder = output / case["query_id"]
        cache = folder / "cache"
        cache.mkdir(parents=True)
        environment = os.environ.copy()
        for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
            environment[key] = str(cache)
        for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
            environment[key] = "1"
        environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
        print("Running " + case["query_id"], flush=True)
        row = run_case(case, output / "source_snapshot/benchmarks/selective_analysis/compiled_queries",
                       folder, environment, args.tygr_python)
        rows.append(row)
        write_json(output / "case-results.json", rows)
        print("{}: property {}; mapping {}; {}".format(case["query_id"], row["property"]["status"],
            row["mapping"]["status"], row.get("failure", row.get("neural_failure", "logs retained"))), flush=True)
    changed = [name for name, digest in hashes.items() if file_hash(ROOT / name) != digest]
    if changed:
        for row in rows:
            row["property"] = {"status": "unknown", "reason": "runtime_source_changed", "late_result": row["property"]}
            row["mapping"] = {"status": "unknown", "reason": "runtime_source_changed", "late_result": row["mapping"]}
        write_json(output / "case-results.json", rows)
    # Only now read expected outcomes. No label file is supplied to workers/exporter.
    labels_path = spec_root / "offline_labels.json"
    labels = read_json(labels_path)
    shutil.copyfile(labels_path, output / "offline-labels.json")
    summary = offline_summary(cases, rows, labels)
    summary.update(source_integrity_unchanged=not changed, changed_sources=changed,
                   offline_labels_sha256=file_hash(labels_path))
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    print("Finished. No scheduling comparison; raw outputs and failed attempts retained: " + str(output), flush=True)
    return 0 if summary["correct"] == 2 and summary["verified_mappings"] == 2 and not changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
