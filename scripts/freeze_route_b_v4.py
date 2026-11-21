#!/usr/bin/env python3
"""Freeze the Route B v4 pre-registration, implementation and regression evidence by hash."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.contracts import file_hash

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
DESIGN = ROOT / "benchmarks/selective_analysis/route_b/structural_selection_v4_design.md"
IMPLEMENTATION = [
    "src/selective_analysis/finite_backends.py", "src/selective_analysis/v4_runner.py",
    "src/selective_analysis/structural_features.py", "src/selective_analysis/fixture_build.py",
    "src/selective_analysis/contracts.py", "src/selective_analysis/operations.py",
    "src/selective_analysis/local_bounds.py", "src/selective_analysis/path_certificate.py",
    "scripts/build_route_b_v4_panel.py", "scripts/regress_route_b_v4_backends.py", "scripts/freeze_route_b_v4.py",
]
REGRESSION = SCRATCH / "route-b-v4-backend-regression-20261121T073429858926Z"


def main():
    summary = json.loads((REGRESSION / "summary.json").read_bytes())
    if not summary["passed"] or summary["wrong_decisions"] or summary["outcome_mismatches"]:
        raise ValueError("The backend regression gate has not passed")
    output = SCRATCH / ("route-b-v4-freeze-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    pins = {}
    for relative in [str(DESIGN.relative_to(ROOT)).replace("\\", "/")] + IMPLEMENTATION:
        path = ROOT / relative
        (snapshot / path.name).write_bytes(path.read_bytes())
        pins[relative] = file_hash(path)
    freeze = {"schema": "symbai.route_b_v4_freeze.v1", "design_sha256": pins[str(DESIGN.relative_to(ROOT)).replace("\\", "/")],
              "pins": pins, "regression": {"directory": str(REGRESSION),
              "summary_sha256": file_hash(REGRESSION / "summary.json"),
              "records_sha256": file_hash(REGRESSION / "records.json")},
              "held_out_panel_built": False, "held_out_timed": False, "selector_fitted": False}
    (output / "freeze.json").write_text(json.dumps(freeze, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"freeze": str(output), "design_sha256": freeze["design_sha256"]}, indent=2))


if __name__ == "__main__":
    main()
