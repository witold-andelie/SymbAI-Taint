#!/usr/bin/env python3
"""Route B v5 step 5: run arms F, C and L once on the held-out panel, then audit offline.

Run in WSL angr-env after the v5 freeze and the L refit. The protocol is the v4 protocol: runtime
reads panel.json and fixture bytes only, one batch per binary group and arm with a fresh warm worker,
two repetitions (the second in reversed query order) and arm order rotated. offline-references.json
is opened only after every trial is collected. The decision statistics are the pre-registered
equivalence (Q1: F against the derived oracle O) and non-superiority (Q2: L against F) tests.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
ARMS = ("F", "C", "L")
STATUS_TO_OUTCOME = {"excluded_within_scope": "safe", "violation": "violation"}
BOOTSTRAP = 10000
SEED = 0
DELTA_T = 0.05
DELTA_V = 0.02
MIN_QUERIES, MIN_GROUPS = 120, 30


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))


def audit(rows, references, budget):
    """Mark decisive/correct rows and charge unknown or late requests at the budget (v4 rule)."""
    for r in rows:
        decided = STATUS_TO_OUTCOME.get(r["status"]) if r["admitted"] else None
        r["decisive"] = decided is not None
        r["correct"] = decided == references[r["case"]]["outcome"] if decided else None
        r["charged_for_m2"] = r["charged_seconds"] if r["decisive"] else budget
    return rows


def trial_table(rows, budget):
    """Per (case, repetition): cost and verified indicator of F, C, L and the derived oracle O."""
    table = {}
    for r in rows:
        key = (r["case"], r["repetition"])
        table.setdefault(key, {"group": r["group"], "stratum": r.get("stratum")})[r["arm"]] = r
    trials = []
    for (case, repetition), entry in sorted(table.items()):
        if any(arm not in entry for arm in ARMS):
            raise ValueError("Missing arm for %s repetition %d" % (case, repetition))
        cost = {a: entry[a]["charged_for_m2"] for a in ARMS}
        verified = {a: 1.0 if entry[a]["correct"] else 0.0 for a in ARMS}
        ok = [entry[a]["charged_for_m2"] for a in ("F", "C") if entry[a]["correct"]]
        cost["O"] = min(ok) if ok else budget
        verified["O"] = 1.0 if ok else 0.0
        trials.append({"case": case, "repetition": repetition, "group": entry["group"],
                       "stratum": entry["stratum"], "cost": cost, "verified": verified})
    return trials


CONTRASTS = (("t", "F", "O"), ("v", "O", "F"), ("t", "F", "L"), ("v", "L", "F"))


def contrast_sums(trials):
    """Per group: number of trials and the summed differences for each contrast."""
    groups = {}
    for t in trials:
        g = groups.setdefault(t["group"], {"n": 0, **{c: 0.0 for c in CONTRASTS}})
        g["n"] += 1
        for c in CONTRASTS:
            kind, x, y = c
            field = "cost" if kind == "t" else "verified"
            g[c] += t[field][x] - t[field][y]
    return groups


def ratio(groups, names):
    n = sum(groups[g]["n"] for g in names)
    return {c: sum(groups[g][c] for g in names) / n for c in CONTRASTS}


def bootstrap(groups, resamples=BOOTSTRAP, seed=SEED):
    """Percentile cluster bootstrap over binary groups; one shared resample for all contrasts."""
    import numpy as np

    names = sorted(groups)
    if not names or resamples < 1:
        raise ValueError("Bootstrap requires groups and positive resamples")
    rng = random.Random(seed)
    draws = {c: [] for c in CONTRASTS}
    for _ in range(resamples):
        sample = [rng.choice(names) for _ in names]
        value = ratio(groups, sample)
        for c in CONTRASTS:
            draws[c].append(value[c])
    out = {}
    for c in CONTRASTS:
        values = sorted(draws[c])
        lower, upper = np.percentile(values, [5, 95])
        out[c] = {"estimate": ratio(groups, names)[c], "lower90": float(lower),
                  "upper90": float(upper)}
    return out


def decide(stats, wrong):
    f_wrong = any(w["arm"] == "F" for w in wrong)
    l_wrong = any(w["arm"] == "L" for w in wrong)
    t_fo, v_of = stats[("t", "F", "O")], stats[("v", "O", "F")]
    t_fl, v_lf = stats[("t", "F", "L")], stats[("v", "L", "F")]
    q1 = (not f_wrong and -DELTA_T < t_fo["lower90"] and t_fo["upper90"] < DELTA_T
          and -DELTA_V < v_of["lower90"] and v_of["upper90"] < DELTA_V)
    q2 = not l_wrong and t_fl["upper90"] < DELTA_T and v_lf["upper90"] < DELTA_V
    exploratory = (not q1) and t_fl["lower90"] > 0 and v_lf["estimate"] >= 0
    return {"Q1_F_equivalent_to_oracle": q1, "Q2_L_non_superior_to_F": q2,
            "Q1_blocked_by_F_wrong_decision": f_wrong, "Q2_blocked_by_L_wrong_decision": l_wrong,
            "exploratory_L_captures_headroom": exploratory}


def named(stats):
    return {"D_%s(%s,%s)" % c: value for c, value in stats.items()}


def verify_inputs(freeze_dir, selector_dir, panel_dir):
    from src.selective_analysis.contracts import file_hash
    from scripts.freeze_route_b_v5 import verify_freeze, panel_child
    from src.selective_analysis.type_corpus import runtime_path

    freeze = verify_freeze(freeze_dir, defer_references=True)
    for name, expected in freeze["panel"]["files"].items():
        if name == "offline-references.json":
            continue
        if file_hash(panel_child(panel_dir, name)) != expected:
            raise ValueError("Frozen panel file changed: " + name)
    if runtime_path(freeze["panel"]["directory"]).resolve() != panel_dir.resolve():
        raise ValueError("Panel is not the frozen panel")
    summary = json.loads((selector_dir / "summary.json").read_bytes())
    if file_hash(selector_dir / "model.json") != summary["model_sha256"]:
        raise ValueError("Selector model changed after fitting")
    model = json.loads((selector_dir / "model.json").read_bytes())
    if (model["freeze_design_sha256"] != freeze["design_sha256"]
            or runtime_path(summary["freeze"]).resolve() != freeze_dir.resolve()
            or summary["freeze_sha256"] != file_hash(freeze_dir / "freeze.json")
            or model["freeze_sha256"] != summary["freeze_sha256"]):
        raise ValueError("Selector was not fitted under this freeze")
    return freeze, model


def main():
    from src.selective_analysis.contracts import Query, file_hash
    from src.selective_analysis.structural_features import extract_features, feature_vector
    from src.selective_analysis.type_corpus import runtime_path
    from src.selective_analysis.v4_runner import WarmWorker
    from src.selective_analysis import v4_selector as sel

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--selector", type=Path, required=True)
    parser.add_argument("--panel", type=Path, required=True)
    args = parser.parse_args()
    dirs = []
    for value in (args.freeze, args.selector, args.panel):
        path = runtime_path(value).resolve()
        path.relative_to(SCRATCH)
        dirs.append(path)
    freeze_dir, selector_dir, panel_dir = dirs
    freeze, model = verify_inputs(freeze_dir, selector_dir, panel_dir)
    budget = sel.BUDGET_SECONDS
    panel = json.loads((panel_dir / "panel.json").read_bytes())["records"]
    groups = sorted({r["binary_group"] for r in panel})
    if len(panel) < MIN_QUERIES or len(groups) < MIN_GROUPS:
        raise SystemExit("Panel below the pre-registered minimum; v5 is uninterpretable")
    output = SCRATCH / ("route-b-v5-run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp = output / "temp"
    temp.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    queries, orders, choices = {}, {}, {}
    strata = {r["case_id"]: r["stratum"] for r in panel}
    for record in panel:
        raw = dict(record["query"])
        raw["binary"] = str((panel_dir / raw["binary"]).resolve())
        order, info = sel.choose_order(model, feature_vector(extract_features(Query.from_dict(raw))))
        queries[record["case_id"]] = raw
        orders[record["case_id"]] = {"F": sel.F_ORDER, "C": sel.C_ORDER, "L": order}
        choices[record["case_id"]] = {"L_order": list(order), "expected_F": info["expected_F"],
                                      "expected_C": info["expected_C"]}
    pins = {str(p): file_hash(p) for p in (Path(__file__), selector_dir / "model.json", panel_dir / "panel.json")}
    write(output / "plan.json", {"schema": "symbai.route_b_v5_run_plan.v1", "pins": pins, "freeze": str(freeze_dir),
                                 "selector": str(selector_dir), "panel": str(panel_dir), "budget_seconds": budget,
                                 "arms": ARMS, "groups": groups, "L_choices": choices,
                                 "offline_references_read_before_collection": False})
    print("Run output: {} ({} queries, {} groups; L chose concrete-first for {})".format(
        output, len(panel), len(groups), sum(c["L_order"][0] == "concrete_enumeration" for c in choices.values())), flush=True)
    rows, replacements, cold_starts = [], [], []
    for repetition in (0, 1):
        for g_index, group in enumerate(groups):
            cases = [r["case_id"] for r in panel if r["binary_group"] == group]
            if repetition == 1:
                cases = list(reversed(cases))
            shift = (g_index + repetition) % len(ARMS)
            for arm in ARMS[shift:] + ARMS[:shift]:
                started = time.monotonic()
                worker = WarmWorker()
                cold_starts.append({"repetition": repetition, "group": group, "arm": arm,
                                    "seconds": time.monotonic() - started})
                try:
                    for case in cases:
                        result = worker.run("{}|{}|{}".format(repetition, arm, case), queries[case],
                                            orders[case][arm], budget)
                        rows.append({"case": case, "group": group, "stratum": strata[case], "arm": arm,
                                     "repetition": repetition, "order": list(orders[case][arm]),
                                     "status": result["status"], "admitted": result["admitted"],
                                     "charged_seconds": result["charged_seconds"],
                                     "backend": result["final"].get("backend"),
                                     "worker_replaced": result["worker_replaced"]})
                finally:
                    replacements.extend(worker.replacements)
                    worker.stop()
            write(output / "records.json", rows)
        print("repetition {} collected ({} records)".format(repetition, len(rows)), flush=True)
    # ---------------- offline audit (references opened only now)
    from scripts.freeze_route_b_v5 import verify_freeze
    verify_freeze(freeze_dir)
    if file_hash(panel_dir / "offline-references.json") != freeze["panel"]["files"]["offline-references.json"]:
        raise ValueError("Frozen offline references changed")
    references = json.loads((panel_dir / "offline-references.json").read_bytes())["references"]
    audit(rows, references, budget)
    write(output / "records.json", rows)
    write(output / "summary.json", summarize(rows, budget, len(panel), groups, choices, replacements, cold_starts))
    print((output / "summary.json").read_text(encoding="utf-8"), flush=True)


def summarize(rows, budget, queries, groups, choices, replacements, cold_starts=None):
    wrong = [{"case": r["case"], "arm": r["arm"], "repetition": r["repetition"], "status": r["status"]}
             for r in rows if r["correct"] is False]
    trials = trial_table(rows, budget)
    sums = contrast_sums(trials)
    stats = bootstrap(sums)
    by_stratum = {}
    for stratum in sorted({t["stratum"] for t in trials}):
        subset = contrast_sums([t for t in trials if t["stratum"] == stratum])
        by_stratum[stratum] = {"D_%s(%s,%s)" % c: v for c, v in ratio(subset, sorted(subset)).items()}
    totals = {a: {"M1_verified": sum(t["verified"][a] for t in trials),
                  "M2_charged_seconds": sum(t["cost"][a] for t in trials)} for a in ARMS + ("O",)}
    return {"schema": "symbai.route_b_v5_run_summary.v1", "queries": queries, "groups": len(groups),
            "trials_per_arm": len(trials), "margins": {"delta_t": DELTA_T, "delta_v": DELTA_V},
            "bootstrap": {"resamples": BOOTSTRAP, "seed": SEED, "unit": "binary group", "interval": "percentile 90%"},
            "totals": totals, "contrasts": named(stats), "by_stratum_point_estimates": by_stratum,
            "wrong_decisions": wrong, "decision": decide(stats, wrong),
            "L_concrete_first_queries": sum(c["L_order"][0] == "concrete_enumeration" for c in choices.values()),
            "worker_replacements": len(replacements), "worker_cold_starts": cold_starts or []}


if __name__ == "__main__":
    main()
