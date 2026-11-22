"""Report tests with small synthetic run directories under .test-output."""
import json
from pathlib import Path
import shutil
import uuid

import pytest

from scripts import report_route_b_v5 as reporter
from scripts import run_route_b_v5_panel as runner


@pytest.fixture
def folder():
    Path(".test-output").mkdir(exist_ok=True)
    path = Path(".test-output") / ("v5-report-" + uuid.uuid4().hex)
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(str(path))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))


def fixture_files(folder, wrong=True):
    v5, v4 = folder / "v5", folder / "v4"
    rows = []
    for case, group, stratum in (("x", "shared", "S2"), ("y", "shared", "S2"), ("z", "file.c", "S1")):
        for rep in (0, 1):
            for arm, cost in (("F", 0.2), ("C", 0.1), ("L", 0.15)):
                rows.append({"case": case, "group": group, "stratum": stratum, "arm": arm,
                             "repetition": rep, "charged_for_m2": cost, "correct": True})
    old_rows = [{**row, "charged_for_m2": row["charged_for_m2"] * 2} for row in rows if row["case"] == "x"]
    # Deliberately disagree with the records: the report must copy recorded summary values.
    summary = {"decision": {"Q1_F_equivalent_to_oracle": False, "Q2_L_non_superior_to_F": True,
                            "sentinel": "copy exactly"},
               "totals": {arm: {"M1_verified": 99, "M2_charged_seconds": 123.0}
                          for arm in ("F", "C", "L", "O")},
               "contrasts": {"D_%s(%s,%s)" % c: {"estimate": 0.123, "lower90": -0.4, "upper90": 0.9}
                             for c in runner.CONTRASTS}, "margins": {"delta_t": 0.05, "delta_v": 0.02},
               "bootstrap": {"resamples": 10000, "seed": 0},
               "by_stratum_point_estimates": {"S1": {"D_t(F,O)": 0.777}, "S2": {"D_t(F,O)": 0.888}},
               "wrong_decisions": ([{"case": "x", "arm": "L", "repetition": 1, "status": "violation"}]
                                   if wrong else [])}
    old_summary = {"queries": 1, "groups": 1, "wrong_decisions": [], "decision": "not_supported"}
    rescore = {"schema": "symbai.route_b_v4_screened_rescore.v1", "excluded_kernels": ["bad"],
               "all": {"queries": 2, "M1_verified": {"F": 3}, "M2_charged_seconds": {"F": 9},
                       "decision": "not_supported"},
               "screened": {"queries": 1, "M1_verified": {"F": 2}, "M2_charged_seconds": {"F": 4},
                            "decision": "not_supported"}}
    screen = {"kernels": [{"kernel_id": "pass", "status": "pass", "reason": None, "class": None},
                           {"kernel_id": "bad1", "status": "excluded", "reason": "native_undefined_behavior",
                            "class": "stack-buffer-overflow"},
                           {"kernel_id": "bad2", "status": "excluded", "reason": "sanitizer_build_failed", "class": None},
                           {"kernel_id": "bad3", "status": "excluded", "reason": "native_undefined_behavior",
                            "class": "stack-buffer-overflow"}]}
    selection = {"counts": {"queries": 3, "groups": 2, "by_stratum": {"S1": 1, "S2": 2}},
                 "minimum_met": False, "s1_query_limit": 4,
                 "decisions": [{"stage": "s2_cap", "decision": "excluded", "reason": "project_kernel_cap"},
                               {"stage": "s2_cap", "decision": "kept", "reason": "project_kernel_cap"},
                               {"stage": "s1_cap", "decision": "excluded", "reason": "file_query_cap"}],
                 "build_rejections": [{"reason": "source_extraction_failed"}]}
    choices = {case: {"L_order": ["concrete_enumeration" if case != "y" else "symbolic_certificate"]}
               for case in ("x", "y", "z")}
    write(v5 / "summary.json", summary)
    write(v5 / "records.json", rows)
    write(v5 / "plan.json", {"budget_seconds": 3.0, "L_choices": choices})
    write(v4 / "summary.json", old_summary)
    write(v4 / "records.json", old_rows)
    write(folder / "selection.json", selection)
    write(folder / "v5-screen.json", screen)
    write(folder / "v4-screen.json", {"kernels": screen["kernels"][:2]})
    write(folder / "v4-rescore.json", rescore)
    return {"run_dir": v5, "selection": folder / "selection.json", "screen": folder / "v5-screen.json",
            "v4_screen": folder / "v4-screen.json", "v4_rescore": folder / "v4-rescore.json",
            "v4_run": v4, "output": folder / "output"}, summary, rows, old_rows, rescore


def test_report_copies_summary_and_rescore_without_deciding(folder, monkeypatch):
    args, summary, rows, old_rows, rescore = fixture_files(folder)

    def forbidden(*a, **k):
        pytest.fail("A report must not decide, re-audit, or summarize the run")

    for name in ("decide", "audit", "summarize"):
        monkeypatch.setattr(runner, name, forbidden)
    result = reporter.report(**args)
    for key in ("decision", "totals", "contrasts", "margins", "bootstrap", "wrong_decisions", "by_stratum_point_estimates"):
        assert result[key] == summary[key]
    assert result["v4_rescore"] == rescore
    assert result["sanitizer_exclusions"]["v5"]["total"] == 3
    assert result["sanitizer_exclusions"]["v5"]["by_class"] == {"stack-buffer-overflow": 2, "unspecified": 1}
    assert result["sanitizer_exclusions"]["v4"]["by_reason"] == {"native_undefined_behavior": 1}
    assert result["L_orders_by_project"] == {"shared": {"queries": 2, "concrete_first_queries": 1},
                                             "Juliet": {"queries": 1, "concrete_first_queries": 1}}
    assert result["selection_counts"]["counts"] == {"queries": 3, "groups": 2, "by_stratum": {"S1": 1, "S2": 2}}
    assert result["selection_counts"]["build_exclusions_by_reason"] == {"source_extraction_failed": 1}
    assert sum(r["count"] for r in result["selection_counts"]["by_stage_decision_reason"] if r["decision"] == "excluded") == 2
    text = (args["output"] / "report.md").read_bytes().decode("ascii")
    assert text.index("## Wrong decisions") < text.index("## Pre-registered decision")
    original = (args["run_dir"] / "summary.json").read_bytes().decode("ascii")
    assert reporter.raw_field(original, "decision") in text
    for phrase in ("Totals per arm", "0.777", "stack-buffer-overflow", "With screen-excluded kernels",
                   "Without screen-excluded kernels", "pooled (report-only)", "Concrete-first queries", "project_kernel_cap"):
        assert phrase in text
    for name in ("report.json", "report.md"):
        data = (args["output"] / name).read_bytes()
        assert b"\r" not in data
        data.decode("ascii")
    assert json.loads((args["output"] / "report.json").read_bytes()) == result
    json_text = (args["output"] / "report.json").read_bytes().decode("ascii")
    assert json_text.index('"wrong_decisions"') < json_text.index('"decision"')


def test_pool_uses_union_versioned_groups_and_imported_statistics(folder):
    args, summary, rows, old_rows, rescore = fixture_files(folder)
    result = reporter.report(**args)["pooled"]
    trials = []
    for version, source in (("v4", old_rows), ("v5", rows)):
        for t in runner.trial_table(source, 3.0):
            t["group"] = version + ":" + t["group"]
            trials.append(t)
    sums = runner.contrast_sums(trials)
    assert result["point_estimates"] == runner.named(runner.ratio(sums, sorted(sums)))
    assert result["contrasts"] == runner.named(runner.bootstrap(sums))
    assert result["groups"] == ["v4:shared", "v5:file.c", "v5:shared"]
    assert result["trials_per_arm"] == 8
    assert result["report_only"] is True
    assert "decision" not in result
    assert reporter.contrast_sums is runner.contrast_sums
    assert reporter.ratio is runner.ratio
    assert reporter.bootstrap is runner.bootstrap


def test_cli_and_no_wrong_decisions(folder, monkeypatch):
    args, summary, rows, old_rows, rescore = fixture_files(folder, wrong=False)
    plan_path = args["run_dir"] / "plan.json"
    plan = json.loads(plan_path.read_bytes())
    plan["freeze"] = str(folder / "route-b-v5-freeze-x")
    write(plan_path, plan)
    import scripts.freeze_route_b_v5 as freeze_module
    verified = []
    monkeypatch.setattr(freeze_module, "verify_freeze", lambda path, defer_references=False: verified.append(path))
    argv = []
    for name, value in args.items():
        option = "run" if name == "run_dir" else name.replace("_", "-")
        argv.extend(["--" + option, str(value)])
    reporter.main(argv)
    assert len(verified) == 1, "the CLI must verify the freeze"
    text = (args["output"] / "report.md").read_bytes().decode("ascii")
    assert "## Wrong decisions" not in text


def test_missing_choice_fails_before_writing(folder):
    args, summary, rows, old_rows, rescore = fixture_files(folder)
    plan = reporter.load(args["run_dir"] / "plan.json")
    del plan["L_choices"]["z"]
    write(args["run_dir"] / "plan.json", plan)
    with pytest.raises(ValueError, match="choices"):
        reporter.report(**args)
    assert not args["output"].exists()


def test_report_refuses_when_the_freeze_no_longer_verifies(folder, monkeypatch):
    args = fixture_files(folder)[0]
    plan_path = args["run_dir"] / "plan.json"
    plan = json.loads(plan_path.read_bytes())
    plan["freeze"] = str(folder / "route-b-v5-freeze-x")
    write(plan_path, plan)
    import scripts.freeze_route_b_v5 as freeze_module
    seen = []

    def refuse(path, defer_references=False):
        seen.append(Path(path).name)
        raise ValueError("Frozen v5 file changed: scripts/run_route_b_v5_panel.py")

    monkeypatch.setattr(freeze_module, "verify_freeze", refuse)
    with pytest.raises(ValueError, match="Frozen v5 file changed"):
        reporter.report(verify_freeze_pins=True, **args)
    assert seen == ["route-b-v5-freeze-x"]
    assert not (args["output"] / "report.json").exists()
