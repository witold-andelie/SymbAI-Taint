#!/usr/bin/env python3
"""Freeze Route B v5: pre-registration, amendment, implementation, sources, screen and panel.

Refuses unless the v4 backends are byte-identical to the v4 freeze, the re-run v4 regression gate
passed, and the finalized panel meets the pre-registered minimum. No backend has touched a v5
held-out query when this runs.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.contracts import file_hash

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
V4_FREEZE = SCRATCH / "route-b-v4-freeze-20261121T073634943739Z"
DESIGN = "benchmarks/selective_analysis/route_b/cascade_headroom_v5_design.md"
AMENDMENTS = ["benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_1.md",
              "benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_2.md",
              "benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_3.md"]
V4_IDENTICAL = [
    "src/selective_analysis/finite_backends.py", "src/selective_analysis/v4_runner.py",
    "src/selective_analysis/structural_features.py", "src/selective_analysis/fixture_build.py",
    "src/selective_analysis/contracts.py", "src/selective_analysis/operations.py",
    "src/selective_analysis/local_bounds.py", "src/selective_analysis/path_certificate.py",
    "scripts/build_route_b_v4_panel.py", "scripts/regress_route_b_v4_backends.py",
]
IMPLEMENTATION = V4_IDENTICAL + [
    "src/selective_analysis/v4_selector.py", "src/selective_analysis/type_corpus.py",
    "src/selective_analysis/elf_guard.py", "src/selective_analysis/__init__.py",
    "scripts/prepare_route_b_v5_sources.py", "scripts/build_route_b_v5_dwarf.py",
    "scripts/build_route_b_v5_panel.py", "scripts/screen_route_b_v5_sanitizers.py",
    "scripts/rescore_route_b_v4_screened.py", "scripts/label_route_b_v5_development.py",
    "scripts/run_route_b_v5_panel.py", "scripts/freeze_route_b_v5.py",
    "scripts/merge_route_b_v5_sources.py", "scripts/report_route_b_v5.py",
]
PANEL_FILES = ("panel.json", "offline-references.json", "selection.json")
V4_SELECTOR = SCRATCH / "route-b-v4-selector-20261121T074211473909Z"
V4_PANEL = SCRATCH / "route-b-v4-panel-20261121T073950924Z"


def inside(value):
    path = Path(value).resolve()
    path.relative_to(SCRATCH)
    return path


def panel_child(directory, value):
    path = Path(value)
    if path.is_absolute() or path.drive or "\\" in str(value) or ".." in path.parts:
        raise ValueError("Expected a contained relative path: " + str(value))
    target = (directory / path).resolve()
    target.relative_to(directory.resolve())
    return target


def artifact_path(value):
    from src.selective_analysis.type_corpus import runtime_path
    path = (ROOT / runtime_path(value)).resolve()
    for base in (ROOT, SCRATCH):
        try:
            path.relative_to(base)
            return path
        except ValueError:
            pass
    raise ValueError("Frozen artifact outside repository or scratch: " + str(value))


def verify_freeze(freeze_dir, defer_references=False):
    freeze = json.loads((freeze_dir / "freeze.json").read_bytes())
    if freeze.get("schema") != "symbai.route_b_v5_freeze.v1":
        raise ValueError("Not a v5 freeze")
    for relative, expected in freeze["pins"].items():
        if file_hash(panel_child(ROOT, relative)) != expected:
            raise ValueError("Frozen v5 file changed: " + relative)
    for relative, expected in freeze["artifact_files"].items():
        # References, including the unscreened build references, stay sealed until collection.
        if defer_references and "references" in Path(relative).name:
            continue
        if file_hash(artifact_path(relative)) != expected:
            raise ValueError("Frozen v5 artifact changed: " + relative)
    return freeze


def collect_artifacts(sources, build, screen, panel, regression):
    paths = [sources / "sources-manifest.json", build / "plan.json", screen,
             regression / "summary.json", regression / "records.json",
             V4_SELECTOR / "development-queries.json", V4_PANEL / "panel.json"]
    manifest = json.loads((sources / "sources-manifest.json").read_bytes())
    for project in manifest["projects"]:
        if project["status"] != "pinned":
            continue
        inventory = artifact_path(project["dwarf_elf"])
        if file_hash(inventory) != project["dwarf_elf_sha256"]:
            raise ValueError("Inventory differs from compiled sources manifest")
        paths.append(inventory)
    for directory in (panel,):
        paths.extend(directory / name for name in PANEL_FILES)
    for directory, name, key in ((V4_SELECTOR, "development-queries.json", "rows"),
                                  (V4_PANEL, "panel.json", "records"),
                                  (panel, "panel.json", "records")):
        for row in json.loads((directory / name).read_bytes())[key]:
            query = row["query"]
            binary = (artifact_path(query["binary"]) if key == "rows"
                      else panel_child(directory, query["binary"]))
            if file_hash(binary) != query["binary_sha256"]:
                raise ValueError("Fixture differs from query contract")
            paths.append(binary)
    plan = json.loads((build / "plan.json").read_bytes())
    if artifact_path(plan["selection_inputs"]["sources_manifest"]) != sources / "sources-manifest.json":
        raise ValueError("Build used another sources manifest")
    for relative, expected in plan["hashes"].items():
        path = artifact_path(relative)
        if file_hash(path) != expected:
            raise ValueError("Build input changed: " + relative)
        paths.append(path)
    selection = json.loads((panel / "selection.json").read_bytes())
    if (artifact_path(selection["pins"]["build_directory"]) != build
            or artifact_path(selection["pins"]["screen"]) != screen
            or file_hash(screen) != selection["pins"]["screen_sha256"]):
        raise ValueError("Panel was finalized from another build or screen")
    for relative, expected in selection["pins"]["build_files"].items():
        path = panel_child(build, relative)
        if file_hash(path) != expected:
            raise ValueError("Finalized build artifact changed: " + relative)
        paths.append(path)
    return {Path(os.path.relpath(str(path), str(ROOT))).as_posix(): file_hash(path)
            for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--screen", required=True)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--regression", required=True)
    args = parser.parse_args()
    sources, build, screen, panel, regression = (inside(v) for v in
                                                (args.sources, args.build, args.screen, args.panel, args.regression))
    v4_freeze = json.loads((V4_FREEZE / "freeze.json").read_bytes())
    v4 = v4_freeze["pins"]
    for relative in V4_IDENTICAL:
        if relative not in v4 or file_hash(ROOT / relative) != v4[relative]:
            raise ValueError("Differs from the v4 freeze: " + relative)
    if regression == artifact_path(v4_freeze["regression"]["directory"]):
        raise ValueError("Expected a re-run of the v4 regression gate, not the archived gate")
    gate = json.loads((regression / "summary.json").read_bytes())
    if not gate["passed"] or gate["wrong_decisions"] or gate["outcome_mismatches"]:
        raise ValueError("The re-run v4 regression gate has not passed")
    selection = json.loads((panel / "selection.json").read_bytes())
    records = json.loads((panel / "panel.json").read_bytes())["records"]
    counts = {"queries": len(records), "groups": len({r["binary_group"] for r in records}),
              "by_stratum": {s: sum(r["stratum"] == s for r in records)
                             for s in {r["stratum"] for r in records}}}
    if (not selection.get("minimum_met") or counts["queries"] < 120 or counts["groups"] < 30
            or len({r["case_id"] for r in records}) != len(records)):
        raise SystemExit("Finalized panel below the pre-registered minimum; v5 is uninterpretable")
    if any(selection["counts"][key] != value for key, value in counts.items()):
        raise ValueError("Selection counts differ from panel")
    screen_data = json.loads(screen.read_bytes())
    if screen_data.get("schema") != "symbai.route_b_v5_sanitizer_screen.v1":
        raise ValueError("Not a v5 sanitizer screen")
    if (screen_data["plan_sha256"] != file_hash(build / "plan.json")
            or screen_data["references_sha256"] != file_hash(build / "unscreened-references.json")):
        raise ValueError("Screen belongs to a different build")
    prefix = screen_data.get("run_prefix") or []
    if screen_data.get("aslr_disabled") is not True or not prefix or prefix[-1] != "-R":
        raise ValueError("Screen did not run with address randomization disabled (amendment 3)")
    if not json.loads((sources / "sources-manifest.json").read_bytes()).get("compilation_performed"):
        raise ValueError("Sources have not been compiled")
    artifacts = collect_artifacts(sources, build, screen, panel, regression)
    pins = {relative: file_hash(ROOT / relative) for relative in [DESIGN] + AMENDMENTS + IMPLEMENTATION}
    output = SCRATCH / ("route-b-v5-freeze-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    for relative in pins:
        (snapshot / Path(relative).name).write_bytes((ROOT / relative).read_bytes())
    freeze = {"schema": "symbai.route_b_v5_freeze.v1", "design_sha256": pins[DESIGN], "pins": pins,
              "artifact_files": artifacts,
              "v4_identical_checked": V4_IDENTICAL,
              "regression": {"directory": str(regression), "summary_sha256": file_hash(regression / "summary.json")},
              "sources": {"directory": str(sources), "manifest_sha256": file_hash(sources / "sources-manifest.json")},
              "build": {"directory": str(build), "plan_sha256": file_hash(build / "plan.json")},
              "screen": {"file": str(screen), "sha256": file_hash(screen),
                         "counts": {"by_status": screen_data["counts_by_status"],
                                    "by_reason": screen_data["counts_by_reason"]}},
              "panel": {"directory": str(panel), "files": {name: file_hash(panel / name) for name in PANEL_FILES},
                         "counts": counts},
              "held_out_timed": False, "held_out_features_extracted": False, "selector_fitted": False}
    (output / "freeze.json").write_bytes((json.dumps(freeze, indent=2) + "\n").encode("ascii"))
    print(json.dumps({"freeze": str(output), "design_sha256": freeze["design_sha256"],
                      "panel": freeze["panel"]["counts"]}, indent=2))


if __name__ == "__main__":
    main()
