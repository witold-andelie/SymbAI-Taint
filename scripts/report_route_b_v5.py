#!/usr/bin/env python3
"""Render recorded v5 results and report-only v4 sensitivity and pooled statistics.

--output is a directory containing report.json and report.md. No backend is run and no
decision is computed here. The pooled block uses all recorded v4 and v5 trials.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_route_b_v5_panel import (BOOTSTRAP, SEED, bootstrap, contrast_sums,
                                         named, ratio, trial_table)


def load(path):
    return json.loads(Path(path).read_bytes())


def raw_field(text, field):
    """Keep the original JSON value's spelling and indentation for the decision block."""
    decoder = json.JSONDecoder()
    pos = text.index("{") + 1
    while True:
        while text[pos].isspace() or text[pos] == ",":
            pos += 1
        if text[pos] == "}":
            raise ValueError("Missing summary field: " + field)
        key, pos = decoder.raw_decode(text, pos)
        pos = text.index(":", pos) + 1
        while text[pos].isspace():
            pos += 1
        start = pos
        value, pos = decoder.raw_decode(text, pos)
        if key == field:
            return text[start:pos]


def exclusions(screen):
    rows = [row for row in screen["kernels"] if row["status"] == "excluded"]
    reason = Counter(row["reason"] for row in rows)
    klass = Counter(row.get("class") or "unspecified" for row in rows)
    pairs = Counter((row["reason"], row.get("class") or "unspecified") for row in rows)
    return {"total": len(rows), "by_reason": dict(sorted(reason.items())),
            "by_class": dict(sorted(klass.items())),
            "by_reason_and_class": [{"reason": r, "class": c, "count": count}
                                    for (r, c), count in sorted(pairs.items())], "kernels": rows}


def selection_counts(selection):
    decisions = selection["decisions"]
    counts = Counter((row["stage"], row["decision"], row.get("reason") or "unspecified")
                     for row in decisions)
    rejections = Counter(row["reason"] for row in selection["build_rejections"])
    return {"counts": selection["counts"], "minimum_met": selection["minimum_met"],
            "s1_query_limit": selection["s1_query_limit"],
            "by_stage_decision_reason": [{"stage": stage, "decision": decision,
                                          "reason": reason, "count": count}
                                         for (stage, decision, reason), count in sorted(counts.items())],
            "build_exclusions_by_reason": dict(sorted(rejections.items()))}


def chosen_orders(plan, rows):
    projects = {}
    for row in rows:
        project = "Juliet" if row.get("stratum") == "S1" else row["group"]
        if row["case"] in projects and projects[row["case"]] != project:
            raise ValueError("Inconsistent project for query: " + row["case"])
        projects[row["case"]] = project
    if set(projects) != set(plan["L_choices"]):
        raise ValueError("L choices do not match recorded queries")
    counts = defaultdict(lambda: {"queries": 0, "concrete_first_queries": 0})
    for case, choice in plan["L_choices"].items():
        count = counts[projects[case]]
        count["queries"] += 1
        count["concrete_first_queries"] += choice["L_order"][0] == "concrete_enumeration"
    return dict(sorted(counts.items()))


def pooled(v4_rows, v5_rows, budget):
    trials = []
    for version, rows in (("v4", v4_rows), ("v5", v5_rows)):
        for trial in trial_table(rows, budget):
            trial["group"] = version + ":" + trial["group"]
            trials.append(trial)
    sums = contrast_sums(trials)
    return {"report_only": True, "population": "All recorded v4 and v5 trials, including v4 screen exclusions",
            "trials_per_arm": len(trials), "groups": sorted(sums),
            "point_estimates": named(ratio(sums, sorted(sums))),
            "contrasts": named(bootstrap(sums)),
            "bootstrap": {"resamples": BOOTSTRAP, "seed": SEED,
                          "unit": "version-prefixed binary group", "interval": "percentile 90%"}}


def cell(value):
    text = json.dumps(value, ensure_ascii=True) if not isinstance(value, str) else value
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def table(headers, rows):
    return ["| " + " | ".join(map(cell, headers)) + " |",
            "| " + " | ".join("---" for _ in headers) + " |"] + [
                "| " + " | ".join(map(cell, row)) + " |" for row in rows] + [""]


def markdown(report, decision_text):
    lines = ["# Route B v5 report", ""]
    wrong = [("v5", row) for row in report["wrong_decisions"]]
    wrong += [("v4 (unscreened)", row) for row in report["v4_summary"]["wrong_decisions"]]
    if wrong:
        lines += ["## Wrong decisions", ""]
        lines += table(["Panel", "Case", "Arm", "Repetition", "Status"],
                       [(version, r["case"], r["arm"], r["repetition"], r["status"]) for version, r in wrong])
    lines += ["## Pre-registered decision (verbatim from v5 summary)", "", "```json", decision_text, "```", "",
              "## Totals per arm", ""]
    lines += table(["Arm", "Verified trials", "Charged seconds"],
                   [(a, report["totals"][a]["M1_verified"], report["totals"][a]["M2_charged_seconds"])
                    for a in ("F", "C", "L", "O")])
    lines += ["## Contrasts and pre-registered margins", ""]
    lines += table(["Contrast", "Estimate", "90% lower", "90% upper", "Margin"],
                   [(name, s["estimate"], s["lower90"], s["upper90"],
                     report["margins"]["delta_t" if name.startswith("D_t") else "delta_v"])
                    for name, s in report["contrasts"].items()])
    lines += ["Q1 uses strict bounds inside both margins. Q2 uses the upper 95% one-sided bounds",
              "(the upper endpoints of the 90% intervals). Decisions above are copied, not recomputed.", "",
              "## Per-stratum point estimates", ""]
    lines += table(["Stratum", "Contrast", "Estimate"],
                   [(s, name, value) for s, stats in report["by_stratum_point_estimates"].items()
                    for name, value in stats.items()])
    lines += ["## Sanitizer exclusions (kernels or cases)", ""]
    lines += table(["Panel", "Reason", "Class", "Count"],
                   [(version, row["reason"], row["class"], row["count"])
                    for version, block in report["sanitizer_exclusions"].items()
                    for row in block["by_reason_and_class"]])
    lines += ["## v4 re-score (report-only)", ""]
    for name in ("all", "screened"):
        block = report["v4_rescore"][name]
        lines += ["### " + ("With screen-excluded kernels" if name == "all" else "Without screen-excluded kernels"), ""]
        lines += table(["Field", "Recorded value"], list(block.items()))
    lines += ["## v4 and v5 pooled (report-only)", "", report["pooled"]["population"], ""]
    lines += table(["Contrast", "Estimate", "90% lower", "90% upper"],
                   [(name, s["estimate"], s["lower90"], s["upper90"])
                    for name, s in report["pooled"]["contrasts"].items()])
    lines += ["## L chosen orders by project", ""]
    lines += table(["Project", "Queries", "Concrete-first queries"],
                   [(p, c["queries"], c["concrete_first_queries"])
                    for p, c in report["L_orders_by_project"].items()])
    counts = report["selection_counts"]
    lines += ["## Caps and exclusions", ""]
    lines += table(["Field", "Recorded value"], [(key, counts[key]) for key in
                                                ("counts", "minimum_met", "s1_query_limit")])
    lines += table(["Stage", "Decision", "Reason", "Count"],
                   [(r["stage"], r["decision"], r["reason"], r["count"])
                    for r in counts["by_stage_decision_reason"]])
    lines += table(["Build exclusion reason", "Count"], list(counts["build_exclusions_by_reason"].items()))
    return "\n".join(lines) + "\n"


def report(run_dir, selection, screen, v4_screen, v4_rescore, v4_run, output, verify_freeze_pins=False):
    run_dir, v4_run, output = Path(run_dir), Path(v4_run), Path(output)
    summary_text = (run_dir / "summary.json").read_bytes().decode("ascii")
    summary = json.loads(summary_text)
    rows, plan = load(run_dir / "records.json"), load(run_dir / "plan.json")
    if verify_freeze_pins:
        # Every later v5 step refuses to run if a pinned hash changed, including this one.
        from scripts.freeze_route_b_v5 import verify_freeze
        from src.selective_analysis.type_corpus import runtime_path
        verify_freeze(runtime_path(plan["freeze"]).resolve())
    v4_summary, v4_rows = load(v4_run / "summary.json"), load(v4_run / "records.json")
    result = {"schema": "symbai.route_b_v5_report.v1"}
    if summary["wrong_decisions"]:
        result["wrong_decisions"] = summary["wrong_decisions"]
    for key in ("decision", "totals", "contrasts", "margins", "bootstrap",
                "wrong_decisions", "by_stratum_point_estimates"):
        result[key] = summary[key]
    result["v5_summary"] = summary
    result["v4_summary"] = v4_summary
    result["v4_rescore"] = load(v4_rescore)
    result["sanitizer_exclusions"] = {"v5": exclusions(load(screen)), "v4": exclusions(load(v4_screen))}
    result["selection_counts"] = selection_counts(load(selection))
    result["L_orders_by_project"] = chosen_orders(plan, rows)
    result["pooled"] = pooled(v4_rows, rows, plan["budget_seconds"])
    rendered = markdown(result, raw_field(summary_text, "decision"))
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_bytes((json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("ascii"))
    (output / "report.md").write_bytes(rendered.encode("ascii", errors="backslashreplace"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", "--v5-run", dest="run_dir", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--screen", "--v5-screen", dest="screen", type=Path, required=True)
    parser.add_argument("--v4-screen", type=Path, required=True)
    parser.add_argument("--v4-rescore", type=Path, required=True)
    parser.add_argument("--v4-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="directory for report.json and report.md")
    args = parser.parse_args(argv)
    report(verify_freeze_pins=True, **vars(args))
    print("Wrote " + str(args.output / "report.json") + " and " + str(args.output / "report.md"))


if __name__ == "__main__":
    main()
