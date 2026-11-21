#!/usr/bin/env python3
"""Route B v4 step 4: run arms F, C and L once on the held-out panel, then audit offline.

Run in WSL angr-env. Runtime reads panel.json (query contracts) and fixture bytes only. The offline
references are opened only after every trial has been collected. One batch per binary group and arm
with a fresh warm worker, two repetitions (second in reversed query order), arm order rotated.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.contracts import Query, file_hash
from src.selective_analysis.structural_features import extract_features, feature_vector
from src.selective_analysis.type_corpus import runtime_path
from src.selective_analysis.v4_runner import WarmWorker
from src.selective_analysis import v4_selector as sel

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
BUDGET = sel.BUDGET_SECONDS
ARMS = ("F", "C", "L")
STATUS_TO_OUTCOME = {"excluded_within_scope": "safe", "violation": "violation"}
BOOTSTRAP = 10000


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def inside(path):
    path = runtime_path(path).resolve()
    path.relative_to(SCRATCH)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--selector", type=Path, required=True)
    parser.add_argument("--panel", type=Path, required=True)
    args = parser.parse_args()
    freeze_dir, selector_dir, panel_dir = inside(args.freeze), inside(args.selector), inside(args.panel)
    freeze = json.loads((freeze_dir / "freeze.json").read_bytes())
    for relative, expected in freeze["pins"].items():
        if file_hash(ROOT / relative) != expected:
            raise ValueError("Frozen v4 file changed: " + relative)
    summary_sel = json.loads((selector_dir / "summary.json").read_bytes())
    if file_hash(selector_dir / "model.json") != summary_sel["model_sha256"]:
        raise ValueError("Selector model changed after fitting")
    model = json.loads((selector_dir / "model.json").read_bytes())
    if model["freeze_design_sha256"] != freeze["design_sha256"]:
        raise ValueError("Selector was fitted under a different pre-registration")
    panel = json.loads((panel_dir / "panel.json").read_bytes())["records"]
    groups = sorted({r["binary_group"] for r in panel})
    if len(panel) < 60 or len(groups) < 15:
        raise SystemExit("Panel below the pre-registered minimum; v4 stops as uninterpretable")
    output = SCRATCH / ("route-b-v4-run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    pins = {str(p): file_hash(p) for p in (Path(__file__), ROOT / "src/selective_analysis/v4_selector.py",
            selector_dir / "model.json", panel_dir / "panel.json")}
    queries, orders, choices = {}, {}, {}
    for record in panel:
        raw = dict(record["query"])
        raw["binary"] = str((panel_dir / raw["binary"]).resolve())
        query = Query.from_dict(raw)
        order, info = sel.choose_order(model, feature_vector(extract_features(query)))
        queries[record["case_id"]] = raw
        orders[record["case_id"]] = {"F": sel.F_ORDER, "C": sel.C_ORDER, "L": order}
        choices[record["case_id"]] = {"L_order": list(order), "expected_F": info["expected_F"],
                                      "expected_C": info["expected_C"]}
    write(output / "plan.json", {"schema": "symbai.route_b_v4_run_plan.v1", "pins": pins, "freeze": str(freeze_dir),
                                 "selector": str(selector_dir), "panel": str(panel_dir), "budget_seconds": BUDGET,
                                 "arms": ARMS, "groups": groups, "L_choices": choices,
                                 "offline_references_read_before_collection": False})
    print("Run output: {} ({} queries, {} groups; L chose concrete-first for {})".format(
        output, len(panel), len(groups), sum(c["L_order"][0] == "concrete_enumeration" for c in choices.values())), flush=True)
    rows, replacements, cold = [], [], []
    for repetition in (0, 1):
        for g_index, group in enumerate(groups):
            cases = [r["case_id"] for r in panel if r["binary_group"] == group]
            if repetition == 1:
                cases = list(reversed(cases))
            shift = (g_index + repetition) % len(ARMS)
            for arm in ARMS[shift:] + ARMS[:shift]:
                worker = WarmWorker()
                try:
                    for case in cases:
                        result = worker.run("{}|{}|{}".format(repetition, arm, case), queries[case],
                                            orders[case][arm], BUDGET)
                        rows.append({"case": case, "group": group, "arm": arm, "repetition": repetition,
                                     "order": list(orders[case][arm]), "status": result["status"],
                                     "admitted": result["admitted"], "charged_seconds": result["charged_seconds"],
                                     "backend": result["final"].get("backend"), "worker_replaced": result["worker_replaced"]})
                finally:
                    replacements.extend(worker.replacements)
                    worker.stop()
            write(output / "records.json", rows)
        print("repetition {} collected ({} records)".format(repetition, len(rows)), flush=True)
    # ---------------- offline audit (references opened only now)
    references = json.loads((panel_dir / "offline-references.json").read_bytes())["references"]
    for r in rows:
        decided = STATUS_TO_OUTCOME.get(r["status"]) if r["admitted"] else None
        r["decisive"] = decided is not None
        r["correct"] = decided == references[r["case"]]["outcome"] if decided else None
        r["charged_for_m2"] = r["charged_seconds"] if r["decisive"] and r["admitted"] else BUDGET
    write(output / "records.json", rows)
    wrong = [r for r in rows if r["correct"] is False]
    m1 = {a: sum(1 for r in rows if r["arm"] == a and r["correct"]) for a in ARMS}
    m2 = {a: sum(r["charged_for_m2"] for r in rows if r["arm"] == a) for a in ARMS}
    per_group = {g: {a: sum(r["charged_for_m2"] for r in rows if r["arm"] == a and r["group"] == g) for a in ARMS}
                 for g in groups}
    best_fixed = "F" if m2["F"] <= m2["C"] else "C"
    rng = random.Random(0)
    diffs = []
    for _ in range(BOOTSTRAP):
        sample = [rng.choice(groups) for _ in groups]
        diffs.append(sum(per_group[g][best_fixed] - per_group[g]["L"] for g in sample))
    diffs.sort()
    interval = (diffs[int(0.025 * BOOTSTRAP)], diffs[int(0.975 * BOOTSTRAP) - 1])
    oracle_m1 = oracle_m2 = 0.0
    for case in queries:
        for repetition in (0, 1):
            pair = [r for r in rows if r["case"] == case and r["repetition"] == repetition and r["arm"] in ("F", "C")]
            ok = [r for r in pair if r["correct"]]
            oracle_m1 += 1 if ok else 0
            oracle_m2 += min(r["charged_for_m2"] for r in ok) if ok else BUDGET
    l_wrong = [r for r in wrong if r["arm"] == "L"]
    supported = (not l_wrong and m1["L"] >= max(m1["F"], m1["C"]) and m2["L"] < min(m2["F"], m2["C"])
                 and interval[0] > 0)
    summary = {"schema": "symbai.route_b_v4_run_summary.v1", "queries": len(panel), "groups": len(groups),
               "records": len(rows), "M1_verified": m1, "M2_charged_seconds": m2, "best_fixed": best_fixed,
               "M2_best_fixed_minus_L_bootstrap95": interval, "oracle": {"M1": oracle_m1, "M2": oracle_m2},
               "wrong_decisions": [{"case": r["case"], "arm": r["arm"], "repetition": r["repetition"], "status": r["status"]}
                                   for r in wrong],
               "L_concrete_first_queries": sum(c["L_order"][0] == "concrete_enumeration" for c in choices.values()),
               "worker_replacements": len(replacements),
               "decision": "supported" if supported else "not_supported",
               "positive_claim_blocked_by_wrong_decisions": bool(wrong)}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
