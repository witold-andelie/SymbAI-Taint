#!/usr/bin/env python3
"""Report-only v4 re-score with sanitizer-excluded kernels removed.

Reproduces the offline audit in scripts/run_route_b_v4_panel.py on the recorded
rows, then again after dropping rows whose kernel the screen excluded. The all
block must match the original summary on every shared field.
"""
import argparse
import json
from pathlib import Path
import random
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


SCHEMA = "symbai.route_b_v4_screened_rescore.v1"
ARMS = ("F", "C", "L")
BUDGET = 3.0
BOOTSTRAP = 10000
CAP_SUFFIX = re.compile(r"-cap\d+$")


def write_json(path, value):
    text = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    with open(str(path), "w", encoding="ascii", newline="\n") as stream:
        stream.write(text)


def case_kernel(case):
    return CAP_SUFFIX.sub("", case)


def load_json(path):
    return json.loads(Path(path).read_bytes())


def load_screen(screen):
    if isinstance(screen, dict):
        return screen
    return load_json(screen)


def excluded_kernel_ids(screen):
    return sorted({row["kernel_id"] for row in screen.get("kernels", [])
                   if row.get("status") == "excluded"})


def evaluate(rows, budget=BUDGET, n_bootstrap=BOOTSTRAP):
    """Copy of the v4 offline audit, reading already-charged rows."""
    groups = sorted({row["group"] for row in rows})
    cases = []
    seen = set()
    for row in rows:
        if row["case"] not in seen:
            seen.add(row["case"])
            cases.append(row["case"])
    wrong = [row for row in rows if row["correct"] is False]
    m1 = {arm: sum(1 for row in rows if row["arm"] == arm and row["correct"]) for arm in ARMS}
    m2 = {arm: sum(row["charged_for_m2"] for row in rows if row["arm"] == arm) for arm in ARMS}
    per_group = {group: {arm: sum(row["charged_for_m2"] for row in rows
                                  if row["arm"] == arm and row["group"] == group)
                         for arm in ARMS}
                 for group in groups}
    best_fixed = "F" if m2["F"] <= m2["C"] else "C"
    rng = random.Random(0)
    diffs = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(groups) for _ in groups]
        diffs.append(sum(per_group[group][best_fixed] - per_group[group]["L"] for group in sample))
    diffs.sort()
    interval = [diffs[int(0.025 * n_bootstrap)], diffs[int(0.975 * n_bootstrap) - 1]]
    oracle_m1 = oracle_m2 = 0.0
    for case in cases:
        for repetition in (0, 1):
            pair = [row for row in rows if row["case"] == case and row["repetition"] == repetition
                    and row["arm"] in ("F", "C")]
            ok = [row for row in pair if row["correct"]]
            oracle_m1 += 1 if ok else 0
            oracle_m2 += min(row["charged_for_m2"] for row in ok) if ok else budget
    l_wrong = [row for row in wrong if row["arm"] == "L"]
    supported = (not l_wrong and m1["L"] >= max(m1["F"], m1["C"])
                 and m2["L"] < min(m2["F"], m2["C"]) and interval[0] > 0)
    return {
        "schema": "symbai.route_b_v4_run_summary.v1",
        "queries": len(cases),
        "groups": len(groups),
        "records": len(rows),
        "M1_verified": m1,
        "M2_charged_seconds": m2,
        "best_fixed": best_fixed,
        "M2_best_fixed_minus_L_bootstrap95": interval,
        "oracle": {"M1": oracle_m1, "M2": oracle_m2},
        "wrong_decisions": [{"case": row["case"], "arm": row["arm"],
                             "repetition": row["repetition"], "status": row["status"]}
                            for row in wrong],
        "decision": "supported" if supported else "not_supported",
        "positive_claim_blocked_by_wrong_decisions": bool(wrong),
    }


def canon(value):
    return json.loads(json.dumps(value))


def assert_all_matches_summary(block, summary):
    mismatches = []
    for key, value in block.items():
        if key not in summary:
            continue
        if canon(value) != canon(summary[key]):
            mismatches.append("%s: computed=%r summary=%r" % (key, value, summary[key]))
    if mismatches:
        raise ValueError("all-block does not match run summary on shared fields:\n"
                         + "\n".join(mismatches))


def rescore(run_dir, screen, output):
    run_dir = Path(run_dir)
    rows = load_json(run_dir / "records.json")
    summary = load_json(run_dir / "summary.json")
    screen_data = load_screen(screen)
    excluded = excluded_kernel_ids(screen_data)
    excluded_set = set(excluded)
    all_block = evaluate(rows)
    assert_all_matches_summary(all_block, summary)
    kept = [row for row in rows if case_kernel(row["case"]) not in excluded_set]
    document = {
        "schema": SCHEMA,
        "excluded_kernels": excluded,
        "all": all_block,
        "screened": evaluate(kept),
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    write_json(output, document)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--screen", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = rescore(args.run, args.screen, args.output)
        print(json.dumps({"excluded_kernels": document["excluded_kernels"],
                          "all": {"M1_verified": document["all"]["M1_verified"],
                                  "M2_charged_seconds": document["all"]["M2_charged_seconds"],
                                  "decision": document["all"]["decision"]},
                          "screened": {"M1_verified": document["screened"]["M1_verified"],
                                       "M2_charged_seconds": document["screened"]["M2_charged_seconds"],
                                       "decision": document["screened"]["decision"],
                                       "wrong_decisions": document["screened"]["wrong_decisions"]}},
                         indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        parser.exit(1, "%s: %s\n" % (type(error).__name__, error))


if __name__ == "__main__":
    sys.exit(main())
