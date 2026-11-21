#!/usr/bin/env python3
"""Prepare or collect no-forward graph-stage observations for the frozen collision pair."""
import argparse
from datetime import datetime, timezone
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import measure_native_pair_baseline as baseline
from scripts.run_location_repair import offline_trace

CASES = ("utf8proc_byte_class_n256", "lz4_common_bytes")


def instructions(binary):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from elftools.elf.elffile import ELFFile
    with Path(binary).open("rb") as stream:
        elf = ELFFile(stream)
        symbol, = elf.get_section_by_name(".symtab").get_symbol_by_name("benchmark_step")
        address, size = int(symbol["st_value"]), int(symbol["st_size"])
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= address < int(segment["p_vaddr"]) + int(segment["p_filesz"]):
                start = address - int(segment["p_vaddr"])
                code = segment.data()[start:start + size]
                break
        else:
            raise ValueError("Function bytes are outside a file-backed segment")
    result = [{"address": i.address, "mnemonic": i.mnemonic, "operands": i.op_str, "bytes": i.bytes.hex()}
              for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, address)]
    if sum(len(bytes.fromhex(i["bytes"])) for i in result) != size:
        raise ValueError("Incomplete static function decoding")
    return address, result


def equal_inputs(left, right):
    """Exact small-graph correspondence including the actual variable readout."""
    n = left["node_labels"]["shape"][0]
    if n != right["node_labels"]["shape"][0] or n > 8:
        return False
    if left["num_vars"] != right["num_vars"] or left["var_scatter"] != right["var_scatter"]:
        return False
    target = sorted(zip(right["edges"]["values"][0], right["edges"]["values"][1], right["edge_labels"]["values"]))
    for permutation in itertools.permutations(range(n)):
        if any(left["node_labels"]["values"][i] != right["node_labels"]["values"][permutation[i]] for i in range(n)):
            continue
        edges = sorted((permutation[s], permutation[t], relation) for s, t, relation in zip(
            left["edges"]["values"][0], left["edges"]["values"][1], left["edge_labels"]["values"]))
        if edges == target and [permutation[i] for i in left["var_gather"]["values"]] == right["var_gather"]["values"]:
            return True
    return False


def prepare(prior, output):
    plan = baseline.read(prior / "plan.json")
    summary = baseline.read(prior / "summary.json")
    if (summary["smoke_only"] or not summary["validation_passed"] or summary["action_records"] != 72
            or not (prior / "neural-information-assessment.json").is_file()):
        raise ValueError("The reviewed complete local matrix and information assessment are required")
    baseline.require_pins({name: checksum for name, checksum in plan["pins"].items()
        if not (sys.platform == "win32" and name.startswith("/root/"))})
    coverage = baseline.read(baseline.runtime_path(plan["coverage_audit"]))
    known = {r["case_id"]: r for r in coverage["cases"]}
    pairs = baseline.runtime_path(plan["pairs"])
    copies = output / "source_snapshot"
    copies.mkdir()
    helpers = {"guard": "export_typed_complementarity.py", "adapter": "tygr_location_adapter.py",
               "worker": "capture_tygr_graph_stages.py", "capture": "capture_tygr_preprocessing.py",
               "export": "export_tygr_candidates.py"}
    implementation = {}
    for key, name in helpers.items():
        target = copies / name
        target.write_bytes((ROOT / "scripts" / name).read_bytes())
        implementation[key] = {"path": baseline.linux_path(target), "sha256": baseline.digest(target)}
    (copies / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    prepared = []
    for case in CASES:
        old_raw = baseline.runtime_path(known[case]["raw_file"])
        if not known[case]["available"] or baseline.digest(old_raw) != known[case]["raw_sha256"]:
            raise ValueError("Historical guarded graph input differs")
        old_request = baseline.read(old_raw.with_name("request.json"))["native_request"]
        directory = output / case
        directory.mkdir()
        native = dict(old_request)
        native.update(binary=baseline.linux_path(pairs / (case + ".debug.elf")),
            tygr_root=baseline.linux_path(ROOT / "tygr_original"),
            model=baseline.linux_path(ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"),
            scratch_dir=baseline.linux_path(directory / "cache"), worker_sha256=implementation["guard"]["sha256"],
            helpers={key: implementation[key] for key in ("capture", "export")})
        request = {"schema": "symbai.graph_stage_request.v1", "native_request": native,
                   "implementation": {key: implementation[key] for key in ("worker", "guard", "adapter")}}
        baseline.write(directory / "request.json", request)
        binary = pairs / (case + ".debug.elf")
        address, code = instructions(binary)
        record = baseline.read(pairs / (case + ".json"))
        identity = baseline.compare_pair(binary, pairs / (case + ".stripped.elf"))
        if identity["debug_sha256"] != native["binary_sha256"]:
            raise ValueError("Native debug binary changed")
        base = min(row[0] for row in identity["load_geometry"])
        baseline.write(directory / "static-instructions.json", {"function_address": address,
            "write_address": base + record["query"]["write_rva"], "instructions": code,
            "note": "Graph annotation PCs may be block PCs; they are not exact use-site bindings."})
        baseline.write(directory / "offline-location-trace.json", offline_trace(binary))
        prepared.append({"case_id": case, "directory": directory, "old_raw": old_raw, "address": address})
    pins = {baseline.linux_path(ROOT / "scripts" / name): baseline.digest(ROOT / "scripts" / name)
            for name in (*helpers.values(), Path(__file__).name)}
    for path in (prior / "plan.json", prior / "summary.json", prior / "independent-audit.json",
                 prior / "neural-information-assessment.json"):
        pins[baseline.linux_path(path)] = baseline.digest(path)
    baseline.write(output / "plan.json", {"schema": "symbai.graph_stage_plan.v1", "cases": CASES,
        "pins": pins, "implementation": implementation,
        "scope": "Two existing native functions; original execution and splicing methods wrapped for observation only. Existing model loaded for its preprocessing configuration, with every forward blocked. No property verification, new prediction, timing comparison, or repair.",
        "source_hypotheses": ["Execution may return partial states after caught step exceptions.",
            "Read-expression field names may not match the original runtime inspection interface.",
            "Splicing may remove query-relevant nodes disconnected from the selected variable.",
            "Feature encoding may merge differences that survive graph construction."]})
    return prepared, implementation, pins


def review(case, payload):
    if (payload["status"] != "captured" or payload["forward_attempts"] != 0
            or payload["model_forward_performed"] or not payload["original_identities_rechecked"]):
        raise ValueError("No-forward capture is incomplete: " + repr(payload.get("error")))
    function, = [f for f in payload["functions"] if f["function_address"] == case["address"]]
    old = baseline.read(case["old_raw"])
    original, = [f for f in old["functions"] if f["function_address"] == case["address"]]
    matches = equal_inputs(function["native_input"]["batch"], original["native_input"]["batch"])
    if not matches:
        raise ValueError("Observed final batch no longer matches the frozen original graph")
    expected = {json.dumps(row, sort_keys=True) for row in baseline.read(case["directory"] / "offline-location-trace.json")}
    if not payload["location_records"] or any(json.dumps(row, sort_keys=True) not in expected for row in payload["location_records"]):
        raise ValueError("Observed location trace differs from the independent projection")
    static = baseline.read(case["directory"] / "static-instructions.json")
    actions = [a for block in function["blocks"] for a in block["actions"]]
    splice, = function["splices"]
    return {"case_id": case["case_id"], "status": "reviewed", "final_input_matches_frozen": matches,
        "blocks_observed": len(function["blocks"]), "step_exceptions": function["step_exceptions"],
        "pre_splice_nodes": splice["before"]["node_count"], "post_splice_nodes": splice["after"]["node_count"],
        "pre_splice_edge_labels": sorted({label for e in splice["before"]["edges"] for label in e["labels"]}),
        "post_splice_edge_labels": sorted({label for e in splice["after"]["edges"] for label in e["labels"]}),
        "target_write_recorded_in_action_history": any(a["type"] == "mem" and a["action"] == "write"
            and a["instruction_address"] == static["write_address"] for a in actions),
        "read_expression_attribute_registration": {name: name in payload["inspection_attributes"] for name in
            ("reg_read_expr", "register_read_expr", "mem_read_expr", "memory_read_expr")},
        "forward_attempts": payload["forward_attempts"], "no_semantic_repair_performed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-actions", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Collect with WSL angr-env and the existing tygr-orig interpreter")
    prior = baseline.within(args.local_actions, baseline.SCRATCH)
    output = baseline.SCRATCH / ("route-b-graph-stages-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    scratch = output / "temp"
    scratch.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(scratch)
    cases, implementation, pins = prepare(prior, output)
    print("Graph stage audit output: " + str(output), flush=True)
    rows = []
    if not args.prepare_only:
        for case in cases:
            directory = case["directory"]
            try:
                with (directory / "worker.log").open("w", encoding="utf-8") as stream:
                    subprocess.run([str(args.tygr_python), "-B", implementation["worker"]["path"],
                        "--request", str(directory / "request.json"), "--output", str(directory / "raw.json")],
                        cwd=output, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90)
                row = review(case, baseline.read(directory / "raw.json"))
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row = {"case_id": case["case_id"], "status": "failed", "reason": str(error)}
                if (directory / "raw.json").is_file():
                    row["worker_error"] = baseline.read(directory / "raw.json").get("error")
                if (directory / "worker.log").is_file():
                    row["worker_log_tail"] = (directory / "worker.log").read_text(
                        encoding="utf-8", errors="replace").splitlines()[-12:]
            rows.append(row)
            baseline.write(output / "records.json", rows)
            print(case["case_id"] + ": " + row["status"] + (
                ": " + str(row.get("worker_error") or row.get("reason")) if row["status"] == "failed" else ""), flush=True)
    baseline.require_pins(pins)
    summary = {"schema": "symbai.graph_stage_summary.v1", "prepare_only": args.prepare_only,
        "planned_cases": 2, "cases": rows, "reviewed": sum(r["status"] == "reviewed" for r in rows),
        "new_model_predictions": False, "new_property_checks": False, "repair_performed": False,
        "output": str(output)}
    baseline.write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not args.prepare_only and summary["reviewed"] != 2:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
