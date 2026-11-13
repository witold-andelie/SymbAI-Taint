#!/usr/bin/env python3
"""Verify separate base/index bindings on the existing probe, preserving genuine predictions."""

import argparse
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path)
    args = parser.parse_args()
    from src.selective_analysis.workspace import configure_workspace
    from src.selective_analysis.contracts import Query, file_hash, fingerprint
    from src.selective_analysis.operand_mapping import (make_probe_plan, verify_operand_plan,
        validate_operand_evidence, operand_program_facts, map_operand_candidates, load_operand_views)
    from scripts.run_information_value import validate_frozen_inputs
    scratch = configure_workspace()
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    wsl = ROOT.parent / ".scratch/wsl"
    if args.probe_dir is None:
        reviewed = sorted(wsl.glob("inference-*/mapping-review/queries.json"))
        if not reviewed:
            parser.error("An existing reviewed probe is required")
        args.probe_dir = reviewed[-1].parent.parent
    probe = args.probe_dir.resolve()
    manifest = json.loads((probe / "mapping-review/queries.json").read_text(encoding="utf-8"))
    if len(manifest["queries"]) != 1:
        parser.error("This review covers the one existing compiled query")
    manifest["queries"][0]["binary"] = str(probe / "probe.elf")
    query = Query.from_dict(manifest["queries"][0])
    prior_audit = probe / "mapping-review/audit.json"
    audit = json.loads(prior_audit.read_text(encoding="utf-8"))
    if audit.get("query_hash") != query.contract_hash or not all(audit["claims_proved_by_UNSAT_of_negation"].get(k) is True for k in (
            "CFA_minus_24_equals_object_base", "CFA_minus_40_equals_entry_rdi", "write_rax_equals_pointer_plus_index")):
        parser.error("The existing physical slot review is missing or mismatched")
    chosen = None
    for trials_path in reversed(sorted(wsl.glob("acquisition-profile-v5-*/trials.json"))):
        for row in json.loads(trials_path.read_text(encoding="utf-8")):
            if row["status"] == "completed" and row["profile"]["binary_sha256"] == query.binary_sha256:
                chosen = trials_path.parent, row
                break
        if chosen:
            break
    if chosen is None:
        parser.error("No completed genuine v5 acquisition matches this query")
    origin, row = chosen
    attempt = origin / ("trial-" + str(row["trial"]))
    output = scratch / ("operand-mapping-v7-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("Operand mapping output: " + str(output), flush=True)
    inputs = output / "inputs"
    inputs.mkdir()
    for source, name in ((attempt / "raw-types.json", "raw-types.json"),
                         (attempt / "mapped-types.json", "legacy-base-types.json"),
                         (origin / "reviewed-mapping.json", "legacy-review.json"),
                         (prior_audit, "prior-slot-audit.json")):
        shutil.copyfile(source, inputs / name)
    receipt = row["receipt"]
    (inputs / "acquisition-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    input_validation = validate_frozen_inputs(query, inputs / "raw-types.json", inputs / "legacy-base-types.json",
                                            inputs / "legacy-review.json", receipt)
    raw = json.loads((inputs / "raw-types.json").read_text(encoding="utf-8"))
    plan = make_probe_plan(query, raw, file_hash(prior_audit))
    (output / "operand-plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    sources = list((ROOT / "src/selective_analysis").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "scripts/map_tygr_candidates.py", ROOT / "scripts/run_information_value.py",
        ROOT / "docs/architecture/pilot_revision_v7.md"]
    hashes = {}
    for source in sources:
        name = str(source.relative_to(ROOT)).replace("\\", "/")
        hashes[name] = file_hash(source)
        target = output / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (output / "run-plan.json").write_text(json.dumps({
        "revision_spec": "docs/architecture/pilot_revision_v7.md", "platform": platform.platform(),
        "python": platform.python_version(), "query_hash": query.contract_hash, "unique_queries": 1,
        "declared_address_roles": ["base_pointer", "index"], "input_validation": input_validation,
        "source_sha256": hashes, "verification_cap_seconds": 10,
        "scope": "mapping_and_projection_diagnostic_no_scheduler_integration_no_new_inference"}, indent=2), encoding="utf-8")
    started = time.monotonic()
    report = {"schema": "symbai.operand_review.v1", "query_hash": query.contract_hash,
              "status": "unknown", "unique_queries": 1, "scheduler_integration": False,
              "raw_artifact_sha256": file_hash(inputs / "raw-types.json")}
    try:
        proof = verify_operand_plan(query, plan, started + 10)
        (output / "first-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
        if proof["status"] != "verified":
            raise ValueError("Operand proof not verified: " + proof.get("reason", proof["status"]))
        validated = validate_operand_evidence(query, plan, proof, started + 10)
        verification_seconds = time.monotonic() - started
        (output / "validated-proof.json").write_text(json.dumps(validated, indent=2), encoding="utf-8")
        facts = operand_program_facts(query, plan, validated)
        (output / "operand-program-facts.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
        bundle = map_operand_candidates(query, raw, plan, validated)
        bundle_path = output / "operand-types.json"
        bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        views = {variant: load_operand_views(bundle_path, query, variant) for variant in "ABCD"}
        for variant in "CD":
            projected = [{"role": v.role, "operand_id": v.operand_id, "prediction_id": v.prediction_id,
                          "labels": list(v.view.labels), "features": v.selector_features()} for v in views[variant]]
            (output / ("views-" + variant + ".json")).write_text(json.dumps(projected, indent=2), encoding="utf-8")
        records = {r["prediction_id"]: r for r in raw["records"]}
        for view in views["D"]:
            record = records[view.prediction_id]
            if view.view.labels != tuple(c["label"] for c in record["candidates"]) or view.view.raw_scores != tuple(c["raw_score"] for c in record["candidates"]):
                raise ValueError("Operand projection changed a genuine candidate")
            print("{}: {} -> {}; Top-K {}".format(view.role, view.prediction_id, view.operand_id, list(view.view.labels)), flush=True)
        if fingerprint(raw) != fingerprint(bundle["raw_export"]):
            raise ValueError("Raw predictions changed during binding")
        report.update(status="verified", checks=validated["checks"], verification_passes=2,
            prefix_steps_per_pass=validated["prefix_steps"], verification_seconds=verification_seconds,
            role_count=len(views["D"]), role_ids=[v.operand_id for v in views["D"]],
            view_counts={variant: len(value) for variant, value in views.items()},
            common_program_facts_exported=True,
            raw_predictions_preserved=True, constant_length_bytes=1,
            scope="two declared address operands in one query; not general mapping completeness")
    except Exception as exc:
        report["reason"] = type(exc).__name__ + ": " + str(exc)
    report["diagnostic_pipeline_seconds"] = time.monotonic() - started
    (output / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Finished. Role mapping/projection only; retained artifacts: " + str(output), flush=True)
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
