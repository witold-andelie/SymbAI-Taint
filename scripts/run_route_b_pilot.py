#!/usr/bin/env python3
"""Run the frozen Route B information pilot on its six bundled toy programs."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from scripts.run_location_repair import offline_trace
from scripts.run_typed_complementarity import (
    FLAGS, MODEL_HASH, read, run_stage, snapshot, validated_acquisition, write,
)
from scripts.tygr_location_adapter import REVISION, VARIANT, validate_api
from src.selective_analysis.contracts import OPERATIONS, file_hash, fingerprint
from src.selective_analysis.processes import run_bounded
from src.selective_analysis.route_b_pilot import (
    ARMS, BUDGETS, GROUPS, PRIMARY_BUDGET, REPETITIONS, SCOPES, evaluate,
    extract_queries, project_views, run_trial, trial_order,
)
from src.selective_analysis.scheduler import POLICY
from src.selective_analysis.workspace import configure_workspace

PANEL = Path("benchmarks/selective_analysis/route_b")
WRAPPERS = {"base_worker": "scripts/export_typed_complementarity.py",
            "adapter": "scripts/tygr_location_adapter.py",
            "wrapper": "scripts/export_location_repair.py"}
HELPERS = {"capture": "scripts/capture_tygr_preprocessing.py",
           "export": "scripts/export_tygr_candidates.py"}


def source_inventory():
    names = [f"{PANEL.as_posix()}/{group}.c" for group in GROUPS]
    names += [f"{PANEL.as_posix()}/panel.h", "scripts/run_route_b_pilot.py",
              "scripts/run_location_repair.py", "scripts/run_typed_complementarity.py",
              *WRAPPERS.values(), *HELPERS.values()]
    names += [path.relative_to(ROOT).as_posix()
              for path in (ROOT / "src/selective_analysis").glob("*.py")]
    return {name: ROOT / name for name in names}


def run_reference(compiler, source, folder):
    """Check the complete finite source-level domain using a native executable."""
    target = folder / ("reference.exe" if sys.platform == "win32" else "reference")
    command = [compiler, "-std=gnu11", "-O1", "-Werror", "-DROUTE_B_SELF_CHECK",
               str(source), "-o", str(target)]
    try:
        build = run_bounded(command, folder / "reference-compile.log", 30)
        if build.timed_out or build.returncode != 0:
            raise ValueError("Native reference compilation failed")
        check = run_bounded([str(target)], folder / "reference.log", 5)
        if check.timed_out or check.returncode != 0:
            raise ValueError("The source-level reference did not establish bounds")
        return {"checked_input_values": 256, "status": "confirmed",
                "compiler_command": command, "reference_wall_seconds": check.elapsed_seconds}
    finally:
        target.unlink(missing_ok=True)


def collect_model(binary, native_python, tygr, inventory, model, hashes, copies, folder):
    def identity(name):
        return {"path": str(copies / name), "sha256": hashes[name]}

    wrappers = {key: identity(name) for key, name in WRAPPERS.items()}
    native = {"schema": "symbai.typed_acquisition_request.v1", "binary": str(binary),
              "binary_sha256": file_hash(binary), "model": str(model),
              "model_sha256": MODEL_HASH, "tygr_root": str(tygr),
              "source_sha256": inventory,
              "worker_sha256": wrappers["base_worker"]["sha256"],
              "helpers": {key: identity(name) for key, name in HELPERS.items()}}
    expected_trace = offline_trace(binary)
    write(folder / "location-reference.json", expected_trace)
    with TemporaryDirectory(prefix="native-cache-", dir=folder) as cache:
        native["scratch_dir"] = cache
        request = {"schema": "symbai.location_repair_request.v1", "native_request": native,
                   "implementation": wrappers}
        record = run_stage([str(native_python), "-B", wrappers["wrapper"]["path"]],
                           request, folder / "acquisition", 120)
    return admit_model(record, native["binary_sha256"], wrappers, expected_trace)


def admit_model(record, binary_hash, wrappers, expected_trace):
    """Require matching location traces and independently checked raw logits."""
    payload = record["payload"].get("candidate") or {}
    adapter = payload.get("location_adapter", {})
    if (payload.get("acquisition_variant") != VARIANT or adapter.get("revision") != REVISION
            or adapter.get("errors") != [] or adapter.get("implementation") != wrappers
            or adapter.get("original_source_files_modified") is not False
            or sorted(adapter.get("records", []), key=lambda row: row["die_offset"]) !=
            sorted(expected_trace, key=lambda row: row["die_offset"])):
        raise ValueError("Location trace did not match the independent extraction")
    validate_api(adapter.get("entry_api"))
    validated_acquisition(record, binary_hash)
    return payload["records"], fingerprint(payload), record["parent_receipt"]["charged_seconds"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-only", action="store_true",
                        help="Check all six source bounds with the local compiler")
    parser.add_argument("--tygr-python", type=Path,
                        default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    scratch = configure_workspace()
    if not args.reference_only and (sys.platform != "linux" or not str(ROOT).startswith("/mnt/d/")):
        parser.error("The guarded model run needs the existing WSL environment on /mnt/d")
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = scratch / ("route-b-information-" + now)
    output.mkdir()
    print(f"Route B output: {output}", flush=True)
    sources = source_inventory()
    copies = output / "source_snapshot"
    hashes = snapshot(sources, copies)
    label_path = ROOT / PANEL / "offline_labels.json"
    label_hash = file_hash(label_path)
    tygr = ROOT / "tygr_original"
    model = tygr / "model/MODEL_base/x64.O0.base.model"
    upstream = {}
    if not args.reference_only:
        if not args.tygr_python.is_file() or not model.is_file() or file_hash(model) != MODEL_HASH:
            raise ValueError("The pinned checkpoint or existing TYGR interpreter is unavailable")
        upstream = {path.relative_to(tygr).as_posix(): file_hash(path)
                    for path in sorted((tygr / "src").rglob("*.py"))}
        if not upstream:
            raise ValueError("Missing original TYGR source")
    compiler_version = subprocess.run([args.cc, "--version"], check=True, text=True,
                                      stdout=subprocess.PIPE, timeout=10).stdout.splitlines()[0]
    plan = {"schema": "symbai.route_b_information_plan.v1", "reference_only": args.reference_only,
            "groups": GROUPS, "scopes": SCOPES, "arms": ARMS, "budgets_seconds": BUDGETS,
            "primary_budget_seconds": PRIMARY_BUDGET, "repetitions": REPETITIONS,
            "model_sha256": MODEL_HASH, "upstream_sha256": upstream, "source_sha256": hashes,
            "offline_labels_sha256": label_hash, "compiler_version": compiler_version,
            "elf_flags": FLAGS, "python": sys.version, "policy_hash": fingerprint(POLICY),
            "operations": [op.operation_id for op in OPERATIONS]}
    write(output / "plan.json", plan)
    rows, preparation = [], {}
    for index, group in enumerate(GROUPS):
        folder = output / group
        folder.mkdir()
        source = copies / PANEL / (group + ".c")
        preparation[group] = run_reference(args.cc, source, folder)
        if args.reference_only:
            print(f"{group}: 256 reference inputs verified", flush=True)
            continue
        binary = folder / (group + ".elf")
        compiled = run_bounded([args.cc, *FLAGS, str(source), "-o", str(binary)],
                               folder / "compile.log", 30)
        if compiled.returncode or compiled.timed_out:
            raise ValueError(f"Compilation failed for {group}. See compile.log")
        queries = extract_queries(binary, group)
        write(folder / "queries.json", [asdict(query) for query in queries])
        views, unavailable = project_views([], queries[0].entry_rva, "", MODEL_HASH)
        try:
            records, artifact_hash, acquisition_time = collect_model(
                binary, args.tygr_python, tygr, upstream, model, hashes, copies, folder)
            views, unavailable = project_views(records, queries[0].entry_rva, artifact_hash, MODEL_HASH)
            preparation[group]["acquisition_wall_seconds"] = acquisition_time
        except (ValueError, OSError, KeyError, TypeError) as error:
            unavailable = f"{type(error).__name__}: {error}"
        preparation[group]["neural_unavailable_reason"] = unavailable
        for scope_index, query in enumerate(queries):
            for budget_index, budget in enumerate(BUDGETS):
                for repetition in range(REPETITIONS):
                    for arm in trial_order(index, scope_index, budget_index, repetition):
                        rows.append(run_trial(query, arm, views.get(arm), budget, repetition,
                                              group, None if arm in views else unavailable))
        if file_hash(binary) != queries[0].binary_sha256:
            raise ValueError(f"Compiled fixture changed during collection for {group}")
        write(output / "trials.json", rows)
        print(f"{group}: {len(queries)} queries, {len(views) - 1} genuine type views", flush=True)

    if any(file_hash(sources[name]) != digest or file_hash(copies / name) != digest
           for name, digest in hashes.items()) or file_hash(label_path) != label_hash:
        raise ValueError("Frozen source or reference identity changed during the run")
    if upstream and (file_hash(model) != MODEL_HASH
                     or any(file_hash(tygr / name) != digest for name, digest in upstream.items())):
        raise ValueError("Upstream inputs changed during the run")
    if args.reference_only:
        summary = {"schema": "symbai.route_b_reference_check.v1", "groups_checked": len(preparation),
                   "source_inputs_checked": len(preparation) * 256,
                   "neural_information_measured": False, "scheduled_trials": 0}
    else:
        label_file = read(label_path)
        if label_file.get("schema") != "symbai.route_b_reference.v1":
            raise ValueError("Invalid offline label schema")
        summary = evaluate(rows, label_file["cases"])
    summary["group_preparation"] = preparation
    write(output / "summary.json", summary)
    print(f"Summary: {output / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
