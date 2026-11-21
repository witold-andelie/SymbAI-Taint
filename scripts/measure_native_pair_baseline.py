#!/usr/bin/env python3
"""Measure the frozen cascade on all twelve native ELF queries, without neural routing."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from importlib.machinery import SourceFileLoader
import importlib.metadata
import json
import os
from pathlib import Path
from statistics import median
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.prepare_native_query_pairs import WORKSPACE, compare_pair, digest, load_manifest, within, write
from scripts.probe_native_pair_tygr import linux_path, load

SCRATCH = WORKSPACE / ".scratch/selective_analysis"
LEGACY = SCRATCH / "route-b-live-phase-rule-20261119T150054Z"
ARCHIVE_READER = SCRATCH / "route-b-cold-warm-certificate-20261118T214546898406Z/run.py"
ARM = "fixed_cascade"


def read(path):
    return json.loads(Path(path).read_bytes())


def runtime_path(name):
    """Resolve retained Windows and WSL paths on the current side of the D mount."""
    name = str(name)
    if sys.platform.startswith("linux") and name[:3].lower() in ("d:/", "d:\\"):
        return Path("/mnt/d/" + name[3:].replace("\\", "/"))
    if os.name == "nt" and name.startswith("/mnt/d/"):
        return Path("D:/" + name[7:])
    return Path(name)


def require_pins(pins):
    changed = [name for name, checksum in pins.items() if digest(runtime_path(name)) != checksum]
    if changed:
        raise ValueError("Frozen sources or inputs changed: " + repr(changed))


def archive_path_identity(value):
    """Compare D-drive dictionary keys without changing their retained spelling."""
    if not isinstance(value, str):
        return None
    value = value.replace("\\", "/")
    if value[:3].lower() == "d:/":
        tail = value[3:]
    elif value.startswith("/mnt/d/"):
        tail = value[7:]
    else:
        return None
    parts = [part for part in tail.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise ValueError("Parent traversal in an archived path key")
    return "/".join(parts)


class ArchivePathKeys(dict):
    """Resolve a unique Windows/WSL spelling; never replace a digest or add an alias."""
    def __init__(self, values):
        super().__init__(values)
        self._path_keys = {}
        for key in self:
            identity = archive_path_identity(key)
            if identity is not None:
                if identity in self._path_keys:
                    raise ValueError("Ambiguous Windows/WSL keys in an archived mapping")
                self._path_keys[identity] = key

    def __missing__(self, key):
        identity = archive_path_identity(key)
        if identity is None or identity not in self._path_keys:
            raise KeyError(key)
        return dict.__getitem__(self, self._path_keys[identity])


def portable_archive_keys(value):
    if isinstance(value, dict):
        values = {key: portable_archive_keys(item) for key, item in value.items()}
        return ArchivePathKeys(values) if any(archive_path_identity(key) is not None for key in values) else values
    if isinstance(value, list):
        return [portable_archive_keys(item) for item in value]
    return value


class ArchiveReaderLoader(SourceFileLoader):
    def exec_module(self, module):
        super().exec_module(module)
        original_read = module.read

        @wraps(original_read)
        def read_with_portable_keys(path):
            return portable_archive_keys(original_read(path))

        module.read = read_with_portable_keys


@contextmanager
def archive_json_paths():
    """Adapt one archived JSON reader while its original callers bootstrap."""
    original_spec = importlib.util.spec_from_file_location

    @wraps(original_spec)
    def portable_spec(name, location=None, *args, **kwargs):
        spec = original_spec(name, location, *args, **kwargs)
        if location is not None and Path(location).resolve() == ARCHIVE_READER.resolve():
            if spec is None or not isinstance(spec.loader, SourceFileLoader):
                raise ValueError("Unexpected loader for the frozen archive reader")
            spec.loader = ArchiveReaderLoader(spec.loader.name, spec.loader.path)
        return spec

    importlib.util.spec_from_file_location = portable_spec
    try:
        yield
    finally:
        importlib.util.spec_from_file_location = original_spec


def controller(output):
    legacy = load("native_baseline_legacy", LEGACY / "run.py")
    legacy.OUTPUT = legacy.batch.OUTPUT = legacy.batch.iso.OUTPUT = output
    # The existing parent transport launches this entry point for every worker.
    legacy.batch.iso.__file__ = str(Path(__file__).resolve())
    original_load_panel = legacy.batch.iso.load_panel

    @wraps(original_load_panel)
    def load_panel():
        with archive_json_paths():
            return original_load_panel()

    legacy.batch.iso.load_panel = load_panel
    return legacy


def prepare(pairs, output, smoke=False):
    manifest_path, manifest = load_manifest(pairs.parent / "source-manifest.json")
    build = read(pairs / "plan.json")
    if build["manifest_sha256"] != digest(manifest_path):
        raise ValueError("Native build and source manifest differ")
    built = read(pairs / "summary.json")
    if (built["verified_pairs"] != 12 or built["entry_argument_bindings_verified"] != 12
            or built["failed_cases"]):
        raise ValueError("Twelve verified native pairs are required")
    coverage_path = pairs.parent / "neural-coverage.json"
    coverage = read(coverage_path)
    cases = [case["case_id"] for case in manifest["cases"]]
    coverage_rows = {row["case_id"]: row for row in coverage["cases"]}
    if (coverage["schema"] != "symbai.native_neural_coverage_audit.v1"
            or len(cases) != 12 or len(set(cases)) != 12 or set(coverage_rows) != set(cases)
            or coverage["usable_entry_predictions"] != sum(r["available"] for r in coverage_rows.values())):
        raise ValueError("Reviewed coverage must retain all twelve cases")
    retained_pins = {**read(LEGACY / "plan.json")["pins"], **coverage["pins"]}
    # The previous baseline ran on Windows. Keep its implementation/input pins,
    # and record the actual installed libraries for this new runtime separately.
    original_pins = {name: checksum for name, checksum in retained_pins.items()
                     if str(name).lower().startswith(("d:", "/mnt/d/"))}
    historical_runtime_pins = {name: checksum for name, checksum in retained_pins.items()
                               if name not in original_pins}
    require_pins(original_pins)
    pins = {linux_path(runtime_path(name)): checksum for name, checksum in original_pins.items()}
    runtime_sources = {}
    for package, relative in (("angr", "angr/state_plugins/solver.py"),
            ("claripy", "claripy/frontend/mixin/model_cache_mixin.py"),
            ("claripy", "claripy/backends/backend_z3.py")):
        installed = Path(importlib.metadata.distribution(package).locate_file(relative)).resolve()
        runtime_sources[relative] = {"path": str(installed), "sha256": digest(installed),
                                    "package_version": importlib.metadata.version(package)}
        pins[str(installed)] = digest(installed)
    intake = {}
    for spec in manifest["cases"]:
        case = spec["case_id"]
        record = read(pairs / (case + ".json"))
        debug, stripped = (pairs / (case + suffix) for suffix in (".debug.elf", ".stripped.elf"))
        identity = compare_pair(debug, stripped)
        if (identity["debug_sha256"] != coverage_rows[case]["debug_binary_sha256"]
                or identity["stripped_sha256"] != coverage_rows[case]["query_binary_sha256"]):
            raise ValueError("Baseline and neural acquisition must use code-identical pairs")
        query = dict(record["query"], binary=str(stripped.resolve()))
        reference_path = pairs.parent / spec["reference"]
        reference = read(reference_path)
        bounds, = query["inputs"]
        if (reference["input_minimum"] != bounds["minimum"]
                or reference["input_maximum"] != bounds["maximum"]
                or len(reference["indices"]) != 256
                or any(type(value) is not int or not 0 <= value < query["capacity"]
                       for value in reference["indices"])):
            raise ValueError("Frozen finite reference and query scope differ")
        intake[case] = {"status": "available", "query": query}
        (output / (case + "-native-reference.json")).write_bytes(reference_path.read_bytes())
        for path in (pairs / (case + ".json"), debug, stripped, reference_path,
                     output / (case + "-native-reference.json")):
            pins[linux_path(path)] = digest(path)
    # Type availability is kept in the parent plan, never in the worker's runtime intake.
    write(output / "intake.json", intake)
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    (snapshot / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    for path in (Path(__file__), snapshot / Path(__file__).name, coverage_path,
                 manifest_path, pairs / "plan.json", pairs / "summary.json", output / "intake.json"):
        pins[linux_path(path)] = digest(path)
    groups = [cases[:6], cases[6:]]
    schedule = []
    if smoke:
        schedule = [{"repetition": 0, "group": 0, "cases": ["miniz_two_byte_adler_n256"]}]
    else:
        for repetition in range(3):
            for group in (range(2) if repetition % 2 == 0 else reversed(range(2))):
                ordered = groups[group][repetition:] + groups[group][:repetition]
                if repetition % 2:
                    ordered = ordered[::-1]
                schedule.append({"repetition": repetition, "group": group, "cases": ordered})
    plan = {"schema": "symbai.native_baseline_plan.v1", "pins": pins, "cases": cases,
        "schedule": schedule, "arm": ARM, "smoke_only": smoke,
        "query_seconds": 3.0, "batch_seconds": 18.0, "cleanup_reserve_seconds": 0.05,
        "neural_availability": {case: bool(coverage_rows[case]["available"]) for case in cases},
        "coverage_audit": linux_path(coverage_path), "pairs": linux_path(pairs),
        "runtime_source_pins": runtime_sources, "historical_runtime_pins_not_reused": historical_runtime_pins,
        "archive_path_adapter": {"revision": "unique_d_dictionary_keys_v1",
            "reader": linux_path(ARCHIVE_READER), "reader_sha256": digest(ARCHIVE_READER),
            "scope": "Only the frozen reader's returned dictionaries accept equivalent D-drive keys. Stored keys, path values, digests, source bytes and analysis operations are unchanged. Applied in parent and worker bootstrap."},
        "scope": "Twelve known authored native functions, not complete applications or held-out evaluation. Three repetitions, one frozen baseline, no neural decisions.",
        "cost_scope": "Existing cache-preserving symbolic-to-concrete cascade. Charge worker startup, request transport, checks, validation, state discard, final cleanup and worker recovery to batch clocks. Offline re-audit is recorded separately.",
        "interpretation": "Pre-fallback elapsed work is descriptive opportunity, not an achieved saving or a hard bound on another policy. Historical cold neural captures are not a matched warm-service cost."}
    write(output / "plan.json", plan)
    require_pins(pins)
    return plan, intake


def case_costs(rows, availability):
    result = {}
    for case, available in availability.items():
        selected = [row for row in rows if row["case"] == case]
        fallback_seconds = []
        fallback_trials = 0
        for row in selected:
            choices = [e for e in row["events"] if e["event"] == "policy_choice"]
            if not choices or choices[-1]["backend"] != "concrete_enumeration":
                continue
            fallback_trials += 1
            nested = [e["payload"] for e in row["events"] if e["event"] == "attempt_event"]
            opened = [e["time"] for e in nested if e["event"] == "operation_opened"]
            cleaned = [e["time"] for e in nested if e["event"] == "discard_cleanup_finished"]
            if len(opened) == len(cleaned) == 1 and cleaned[0] >= opened[0]:
                fallback_seconds.append(cleaned[0] - opened[0])
        result[case] = {"neural_entry_available": available, "trials": len(selected),
            "resolved": sum(row["status"] == "excluded_within_scope" for row in selected),
            "unknown": sum(row["status"] == "unknown" for row in selected),
            "median_query_wall_seconds": median(r["query_wall_seconds"] for r in selected) if selected else None,
            "fallback_trials": fallback_trials,
            "observed_pre_fallback_seconds": fallback_seconds}
    return result


def run(output, plan, intake):
    legacy = controller(output)
    panel = legacy.batch.iso.load_panel()
    batches = []
    for index, item in enumerate(plan["schedule"], 1):
        record = legacy.batch.run_batch(panel, index, ARM, item["repetition"], item["cases"], intake)
        record["group"] = item["group"]
        for row in record["rows"]:
            choices = [e for e in row["events"] if e["event"] == "policy_choice"]
            if choices:
                row["backend"] = choices[-1]["backend"]
        batches.append(record)
        write(output / "batches.json", batches)
        print("Batch {}/{}: {}/{} resolved; {:.3f}s".format(index, len(plan["schedule"]),
            sum(r["status"] == panel.PROVEN for r in record["rows"]), len(item["cases"]),
            record["elapsed_seconds"]), flush=True)
    rows = [row for batch in batches for row in batch["rows"]]
    audit_started = time.monotonic()
    audited = [{**row, "strategy": row["backend"]} for row in rows
               if any(e["event"] == "policy_choice" for e in row["events"])]
    concrete, symbolic = panel.selector.base.audit(audited, intake)
    errors = {"wrong_decisions": sum(r["status"] == "violation" for r in rows),
        "late_admissions": sum(r["admitted"] and r["result_received"] > r["deadline"] for r in rows),
        "unreaped_workers": sum(not p["worker_reaped"] for b in batches for p in b["processes"]),
        "batch_budget_failures": sum(not b["admitted"] for b in batches),
        "concrete_mismatches": sum(r["address_or_length_mismatches"] for r in concrete.values()),
        "symbolic_audit_failures": [c for c, r in symbolic.items()
            if r["status"] not in ("verified", "no_decisive_timed_result")]}
    require_pins(plan["pins"])
    costs = case_costs(rows, plan["neural_availability"])
    summary = {"schema": "symbai.native_baseline_summary.v1", "smoke_only": plan["smoke_only"],
        "planned_cases": 12, "measured_unique_cases": len({r["case"] for r in rows}),
        "query_records": len(rows), "batches": len(batches),
        "counts": dict(Counter(r["status"] for r in rows)), "per_case": costs,
        "by_neural_availability": {str(available).lower(): {
            "unique_cases": sum(r["neural_entry_available"] == available for r in costs.values()),
            "trials": sum(r["trials"] for r in costs.values() if r["neural_entry_available"] == available),
            "resolved": sum(r["resolved"] for r in costs.values() if r["neural_entry_available"] == available),
            "fallback_trials": sum(r["fallback_trials"] for r in costs.values() if r["neural_entry_available"] == available)}
            for available in (False, True)},
        "batch_elapsed_seconds": [b["elapsed_seconds"] for b in batches], "errors": errors,
        "validation_passed": not any(errors.values()),
        "offline_reaudit_seconds": time.monotonic() - audit_started,
        "neural_information_used_by_worker": False, "neural_scheduling_benefit_measured": False,
        "full_use_site_mapping_validated": False, "held_out_evaluation": False,
        "output": str(output)}
    write(output / "summary.json", summary)
    return summary


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        marker = Path(sys.argv[2]).resolve()
        output = within(marker.parent.parent, SCRATCH)
        require_pins(read(output / "plan.json")["pins"])
        controller(output).backend_worker(marker)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="One-case host compatibility check, never official timing")
    args = parser.parse_args()
    if not args.prepare_only and not args.smoke and not sys.platform.startswith("linux"):
        parser.error("Official matched baseline timing must run in WSL angr-env")
    pairs = within(args.pairs, WORKSPACE)
    output = SCRATCH / ("route-b-native-baseline-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    scratch = output / "temp"
    scratch.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(scratch)
    started = time.monotonic()
    plan, intake = prepare(pairs, output, args.smoke)
    setup_seconds = time.monotonic() - started
    print("Native baseline output: " + str(output), flush=True)
    if args.prepare_only:
        print(json.dumps({"prepare_only": True, "planned_records": sum(len(s["cases"]) for s in plan["schedule"]),
            "neural_available": sum(plan["neural_availability"].values()), "output": str(output)}, indent=2))
        return
    summary = run(output, plan, intake)
    summary.update(setup_seconds=setup_seconds, total_parent_seconds=time.monotonic() - started,
        runtime={"python": sys.version, "angr": importlib.metadata.version("angr"), "platform": sys.platform})
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if not summary["validation_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
