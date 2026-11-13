#!/usr/bin/env python3
"""Profile three fresh CPU acquisitions on the existing reviewed probe; no analysis comparison."""

import argparse
from dataclasses import asdict
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
MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"


def prediction_identity(raw):
    from src.selective_analysis.contracts import fingerprint
    return fingerprint([{key: record[key] for key in
        ("prediction_id", "function_address", "locations", "candidates", "raw_value_node_logits")}
        for record in raw["records"]])


def summarize(trials):
    completed = [row for row in trials if row["status"] == "completed"]
    phases = sorted({name for row in completed for name in row["profile"]["stage_seconds"]})
    return {"schema": "symbai.acquisition_profile_summary.v1", "trials": len(trials),
            "completed": len(completed), "failed": len(trials) - len(completed),
            "all_completed_predictions_identical": len({r["prediction_identity"] for r in completed}) == 1 if completed else None,
            "median_acquisition_wall_seconds": median(r["wall_seconds"] for r in completed) if completed else None,
            "median_stage_seconds": {name: median(r["profile"]["stage_seconds"][name] for r in completed) for name in phases},
            "interpretation": "Cold-process cost diagnostic on one reviewed probe; no warm-service or neural scheduling benefit measured."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path)
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run in WSL angr-env from the D-drive project")
    from src.selective_analysis.contracts import Query, file_hash
    from src.selective_analysis.online_types import acquire_type_view
    from src.selective_analysis.workspace import configure_workspace
    configure_workspace()
    scratch = ROOT.parent / ".scratch/wsl"
    if args.probe_dir is None:
        reviewed = sorted(scratch.glob("inference-*/mapping-review/reviewed_mapping.json"))
        if not reviewed:
            parser.error("No reviewed probe found; supply --probe-dir")
        args.probe_dir = reviewed[-1].parent.parent
    probe = args.probe_dir.resolve()
    manifest = json.loads((probe / "mapping-review/queries.json").read_text(encoding="utf-8"))
    if len(manifest["queries"]) != 1:
        parser.error("This diagnostic requires the single existing reviewed probe")
    manifest["queries"][0]["binary"] = str(probe / "probe.elf")
    query = Query.from_dict(manifest["queries"][0])
    mapping = json.loads((probe / "mapping-review/reviewed_mapping.json").read_text(encoding="utf-8"))
    if any(not link.get("expected_identity") for link in mapping["mappings"]):
        parser.error("Reviewed physical location anchors are required")
    output = scratch / ("acquisition-profile-v5-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Acquisition profile output: " + str(output), flush=True)
    mapping_path = output / "reviewed-mapping.json"
    mapping_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    config = {"schema": "symbai.online_tygr.v1", "python": str(args.tygr_python),
              "tygr_root": str(ROOT / "tygr_original"),
              "model": str(ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"),
              "model_sha256": MODEL_HASH, "mapping": str(mapping_path), "top_k": 3, "device": "cpu"}
    config_path = output / "provider.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [
        ROOT / "scripts/export_tygr_candidates.py", ROOT / "scripts/map_tygr_candidates.py",
        Path(__file__).resolve(), ROOT / "docs/architecture/pilot_revision_v5.md"]
    hashes = {}
    for source in sources:
        name = str(source.relative_to(ROOT)).replace("\\", "/")
        hashes[name] = file_hash(source)
        archived = output / "source_snapshot" / name
        archived.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, archived)
    plan = {"revision_spec": "docs/architecture/pilot_revision_v5.md", "trials": 3,
            "acquisition_cap_seconds": 30, "query": asdict(query), "model_sha256": MODEL_HASH,
            "mapping_plan_sha256": file_hash(mapping_path), "source_sha256": hashes,
            "scope": "cold_CPU_acquisition_only_not_A_D_or_warm_comparison",
            "cache_policy": "fresh_export_and_cache_per_trial; OS_cache_not_flushed",
            "excluded_setup": "existing compilation, fixed query and prior human locator review; harness setup"}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    trials = []
    for index in range(3):
        before = time.monotonic()
        attempt = output / ("trial-" + str(index))
        with (output / ("events-" + str(index) + ".jsonl")).open("w", encoding="utf-8") as stream:
            def emit(event, **payload):
                stream.write(json.dumps({"event": event, "elapsed_seconds": time.monotonic() - before, **payload}) + "\n")
                stream.flush()
            try:
                _, receipt = acquire_type_view(query, "D", config_path, attempt,
                    before + 30, emit, profile_stages=True)
                wall = time.monotonic() - before
                profile_path = attempt / "stage-profile.json"
                if file_hash(profile_path) != receipt["stage_profile_sha256"]:
                    raise ValueError("Stage profile changed after provider validation")
                profile = json.loads(profile_path.read_text(encoding="utf-8"))
                raw = json.loads((attempt / "raw-types.json").read_text(encoding="utf-8"))
                row = {"trial": index, "status": "completed", "wall_seconds": wall,
                       "receipt": receipt, "profile": profile, "prediction_identity": prediction_identity(raw),
                       "export_outside_script_seconds": max(0.0, receipt["export_wall_seconds"] - profile["script_elapsed_seconds"])}
                print("Trial {}: total {:.3f}s; imports {:.3f}s; load {:.3f}s; graph {:.3f}s; forward {:.6f}s; mapping {:.3f}s".format(
                    index + 1, wall, profile["stage_seconds"]["imports"], profile["stage_seconds"]["model_loading"],
                    profile["stage_seconds"]["graph_generation"], profile["stage_seconds"]["model_forward"], receipt["mapping_seconds"]), flush=True)
            except Exception as exc:
                row = {"trial": index, "status": "failed", "wall_seconds": time.monotonic() - before,
                       "reason": type(exc).__name__ + ": " + str(exc)}
                print("Trial {} failed: {}; logs retained".format(index + 1, row["reason"]), flush=True)
        trials.append(row)
        (output / "trials.json").write_text(json.dumps(trials, indent=2), encoding="utf-8")
    report = summarize(trials)
    (output / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Finished. Three cold acquisitions only; no warm-service claim. Reports: " + str(output), flush=True)


if __name__ == "__main__":
    main()
