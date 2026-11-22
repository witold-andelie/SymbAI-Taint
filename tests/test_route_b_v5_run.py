"""Synthetic checks of the Route B v5 audit, oracle and decision statistics (no angr)."""
import importlib.util
import json
from pathlib import Path
import shutil
import uuid

import pytest

from scripts import freeze_route_b_v5 as freeze
from scripts import label_route_b_v5_development as label
from scripts import prepare_route_b_v5_sources as prepare
from scripts import build_route_b_v5_dwarf as dwarf

SPEC = importlib.util.spec_from_file_location(
    "run_route_b_v5_panel", str(Path(__file__).resolve().parents[1] / "scripts/run_route_b_v5_panel.py"))
run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run)
B = 3.0


def row(case, group, arm, repetition, status, seconds, admitted=True, stratum="S2"):
    return {"case": case, "group": group, "arm": arm, "repetition": repetition, "status": status,
            "admitted": admitted, "charged_seconds": seconds, "stratum": stratum}


def panel(groups=40, f_seconds=0.2, c_seconds=0.25, l_seconds=0.2):
    rows, references = [], {}
    for g in range(groups):
        case = "g%d-k" % g
        references[case] = {"outcome": "safe"}
        for repetition in (0, 1):
            rows.append(row(case, "g%d" % g, "F", repetition, "excluded_within_scope", f_seconds))
            rows.append(row(case, "g%d" % g, "C", repetition, "excluded_within_scope", c_seconds))
            rows.append(row(case, "g%d" % g, "L", repetition, "excluded_within_scope", l_seconds))
    return rows, references


def test_audit_charges_unknown_and_late_at_budget():
    rows = [row("a", "g", "F", 0, "unknown", 1.0), row("b", "g", "F", 0, "violation", 0.4, admitted=False),
            row("c", "g", "F", 0, "violation", 0.4)]
    run.audit(rows, {"a": {"outcome": "safe"}, "b": {"outcome": "violation"}, "c": {"outcome": "safe"}}, B)
    assert [r["charged_for_m2"] for r in rows] == [B, B, 0.4]
    assert [r["correct"] for r in rows] == [None, None, False]


def test_oracle_takes_cheaper_correct_and_budget_when_none():
    rows = [row("a", "g", "F", 0, "unknown", 3.0), row("a", "g", "C", 0, "excluded_within_scope", 1.2),
            row("a", "g", "L", 0, "unknown", 3.0),
            row("b", "g", "F", 0, "violation", 0.3), row("b", "g", "C", 0, "violation", 0.2),
            row("b", "g", "L", 0, "violation", 0.3)]
    run.audit(rows, {"a": {"outcome": "safe"}, "b": {"outcome": "safe"}}, B)
    trials = {t["case"]: t for t in run.trial_table(rows, B)}
    assert trials["a"]["cost"]["O"] == 1.2 and trials["a"]["verified"]["O"] == 1.0
    assert trials["b"]["cost"]["O"] == B and trials["b"]["verified"]["O"] == 0.0


def test_equal_arms_support_both_questions():
    rows, references = panel()
    run.audit(rows, references, B)
    stats = run.bootstrap(run.contrast_sums(run.trial_table(rows, B)), resamples=500)
    decision = run.decide(stats, [])
    assert decision["Q1_F_equivalent_to_oracle"] and decision["Q2_L_non_superior_to_F"]
    assert abs(stats[("t", "F", "O")]["estimate"]) < 1e-12


def test_headroom_beyond_margin_fails_q1_and_fast_l_fails_q2():
    rows, references = panel(f_seconds=0.5, c_seconds=0.3, l_seconds=0.3)
    run.audit(rows, references, B)
    stats = run.bootstrap(run.contrast_sums(run.trial_table(rows, B)), resamples=500)
    decision = run.decide(stats, [])
    assert abs(stats[("t", "F", "O")]["estimate"] - 0.2) < 1e-9
    assert not decision["Q1_F_equivalent_to_oracle"] and not decision["Q2_L_non_superior_to_F"]
    assert decision["exploratory_L_captures_headroom"]


def test_wrong_decisions_block_their_question():
    rows, references = panel()
    run.audit(rows, references, B)
    stats = run.bootstrap(run.contrast_sums(run.trial_table(rows, B)), resamples=200)
    decision = run.decide(stats, [{"arm": "F"}])
    assert not decision["Q1_F_equivalent_to_oracle"] and decision["Q2_L_non_superior_to_F"]
    decision = run.decide(stats, [{"arm": "L"}])
    assert decision["Q1_F_equivalent_to_oracle"] and not decision["Q2_L_non_superior_to_F"]


def test_ratio_is_weighted_by_trials():
    groups = {"a": {"n": 1, **{c: 1.0 for c in run.CONTRASTS}}, "b": {"n": 3, **{c: 0.0 for c in run.CONTRASTS}}}
    assert run.ratio(groups, ["a", "b"])[("t", "F", "O")] == 0.25


def test_summary_runs_end_to_end():
    rows, references = panel(groups=31)
    run.audit(rows, references, B)
    summary = run.summarize(rows, B, 31, ["g%d" % g for g in range(31)],
                            {"g0-k": {"L_order": ["symbolic_certificate", "concrete_enumeration"]}}, [])
    assert summary["trials_per_arm"] == 62 and summary["totals"]["O"]["M1_verified"] == 62
    assert summary["decision"]["Q1_F_equivalent_to_oracle"]


@pytest.fixture
def folder():
    Path(".test-output").mkdir(exist_ok=True)
    path = Path(".test-output") / ("v5-review-" + uuid.uuid4().hex)
    path.mkdir()
    try:
        yield path.resolve()
    finally:
        shutil.rmtree(str(path))


def test_percentile_endpoints_use_the_same_linear_quantile(monkeypatch):
    class Draws:
        def __init__(self, seed):
            assert seed == 0
            self.index = 0

        def choice(self, names):
            result = names[self.index // len(names)]
            self.index += 1
            return result

    groups = {"%02d" % n: {"n": 1, **{c: float(n) for c in run.CONTRASTS}} for n in range(20)}
    monkeypatch.setattr(run.random, "Random", Draws)
    stats = run.bootstrap(groups, resamples=20)
    assert stats[("t", "F", "O")]["lower90"] == pytest.approx(0.95)
    assert stats[("t", "F", "O")]["upper90"] == pytest.approx(18.05)


def test_bootstrap_default_resamples_seed_and_cluster_ratio(monkeypatch):
    import random
    actual_random = random.Random
    draws = []

    class TrackingRandom:
        def __init__(self, seed):
            assert seed == 0
            self.rng = actual_random(seed)

        def choice(self, names):
            value = self.rng.choice(names)
            draws.append(value)
            return value

    monkeypatch.setattr(run.random, "Random", TrackingRandom)
    groups = {"a": {"n": 1, **{c: 1.0 for c in run.CONTRASTS}},
              "b": {"n": 3, **{c: 0.0 for c in run.CONTRASTS}}}
    stats = run.bootstrap(groups)
    assert len(draws) == 20000
    assert stats[("t", "F", "O")]["estimate"] == 0.25
    assert stats[("t", "F", "O")]["lower90"] == 0.0
    assert stats[("t", "F", "O")]["upper90"] == 1.0


@pytest.mark.parametrize("contrast,boundary", [(("t", "F", "O"), 0.05),
                                               (("v", "O", "F"), 0.02),
                                               (("t", "F", "L"), 0.05),
                                               (("v", "L", "F"), 0.02)])
def test_decision_margins_are_strict(contrast, boundary):
    stats = {c: {"estimate": 0.0, "lower90": 0.0, "upper90": 0.0} for c in run.CONTRASTS}
    stats[contrast]["upper90"] = boundary
    decision = run.decide(stats, [])
    key = "Q1_F_equivalent_to_oracle" if contrast in run.CONTRASTS[:2] else "Q2_L_non_superior_to_F"
    assert not decision[key]


def test_oracle_is_derived_separately_in_each_repetition():
    rows, refs = panel(groups=1)
    for r in rows:
        r["charged_seconds"] = 0.1 if (r["arm"], r["repetition"]) in (("F", 0), ("C", 1)) else 0.9
    run.audit(rows, refs, B)
    assert [t["cost"]["O"] for t in run.trial_table(rows, B)] == [0.1, 0.1]


def frozen_inputs(folder):
    fd, sd, pd = (folder / name for name in ("freeze", "selector", "panel"))
    for path in (fd, sd, pd):
        path.mkdir()
    records = []
    for group, case in (("a", "a1"), ("a", "a2"), ("b", "b1")):
        (pd / (case + ".elf")).write_bytes(case.encode("ascii"))
        records.append({"case_id": case, "binary_group": group, "stratum": "S2", "project": group,
                        "query": {"binary": case + ".elf", "binary_sha256": freeze.file_hash(pd / (case + ".elf"))}})
    run.write(pd / "panel.json", {"records": records})
    run.write(pd / "selection.json", {})
    run.write(pd / "offline-references.json", {"references": {r["case_id"]: {"outcome": "safe"} for r in records}})
    files = {p.name: freeze.file_hash(p) for p in pd.iterdir()}
    data = {"schema": "symbai.route_b_v5_freeze.v1", "pins": {}, "design_sha256": "d" * 64,
            "artifact_files": {str(p): freeze.file_hash(p) for p in pd.iterdir()},
            "panel": {"directory": str(pd), "files": files}}
    run.write(fd / "freeze.json", data)
    model = {"freeze_design_sha256": data["design_sha256"], "freeze_sha256": freeze.file_hash(fd / "freeze.json")}
    run.write(sd / "model.json", model)
    run.write(sd / "summary.json", {"freeze": str(fd), "freeze_sha256": model["freeze_sha256"],
                                     "model_sha256": freeze.file_hash(sd / "model.json")})
    return fd, sd, pd


def test_verify_inputs_defers_reference_open_and_detects_changed_fixture(folder, monkeypatch):
    fd, sd, pd = frozen_inputs(folder)
    original = Path.read_bytes

    def guard(path):
        assert path.name != "offline-references.json"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guard)
    run.verify_inputs(fd, sd, pd)
    (pd / "a1.elf").write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact changed"):
        run.verify_inputs(fd, sd, pd)


def test_full_freeze_identity_not_just_basename(folder):
    fd, sd, pd = frozen_inputs(folder)
    other = folder / "other" / fd.name
    other.mkdir(parents=True)
    (other / "freeze.json").write_bytes((fd / "freeze.json").read_bytes())
    with pytest.raises(ValueError, match="under this freeze"):
        run.verify_inputs(other, sd, pd)
    copied = folder / "other" / pd.name
    copied.mkdir()
    for p in pd.iterdir():
        (copied / p.name).write_bytes(p.read_bytes())
    with pytest.raises(ValueError, match="frozen panel"):
        run.verify_inputs(fd, sd, copied)


def test_label_checks_frozen_data_and_model_binds_whole_freeze(folder):
    fd, sd, pd = frozen_inputs(folder)
    data = json.loads((fd / "freeze.json").read_bytes())
    data["new_amendment_pin"] = "changed"
    run.write(fd / "freeze.json", data)
    with pytest.raises(ValueError, match="under this freeze"):
        run.verify_inputs(fd, sd, pd)
    (pd / "a1.elf").write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact changed"):
        label.verify_freeze(fd)


@pytest.mark.parametrize("path", ["../escape", "sub/../../escape", "C:/escape", "sub\\escape"])
def test_frozen_panel_paths_cannot_escape(folder, path):
    with pytest.raises(ValueError):
        freeze.panel_child(folder, path)


def test_freeze_covers_amendments_and_runtime_dependency():
    assert any(p.endswith("amendment_2.md") for p in freeze.AMENDMENTS)
    assert "src/selective_analysis/elf_guard.py" in freeze.IMPLEMENTATION
    assert "scripts/merge_route_b_v5_sources.py" in freeze.IMPLEMENTATION
    assert "scripts/report_route_b_v5.py" in freeze.IMPLEMENTATION


def test_collection_protocol_and_references_only_after_all_trials(folder, monkeypatch):
    from src.selective_analysis import structural_features, v4_selector
    from src.selective_analysis.contracts import Query
    from src.selective_analysis import v4_runner
    import sys

    fd, sd, pd = frozen_inputs(folder)
    monkeypatch.setattr(run, "SCRATCH", folder)
    monkeypatch.setattr(run, "MIN_QUERIES", 1)
    monkeypatch.setattr(run, "MIN_GROUPS", 1)
    monkeypatch.setattr(Query, "from_dict", lambda raw: raw)
    monkeypatch.setattr(structural_features, "extract_features", lambda query: [])
    monkeypatch.setattr(structural_features, "feature_vector", lambda features: [])
    monkeypatch.setattr(v4_selector, "choose_order", lambda model, features:
                        (v4_selector.F_ORDER, {"expected_F": 0.1, "expected_C": 0.2}))
    batches, calls = [], []

    class Worker:
        def __init__(self):
            self.replacements = []
            self.requests = []
            batches.append(self.requests)

        def run(self, request, query, order, budget):
            assert budget == 3.0
            self.requests.append(request)
            calls.append(request)
            return {"status": "excluded_within_scope", "admitted": True, "charged_seconds": 0.1,
                    "final": {"backend": order[0]}, "worker_replaced": False}

        def stop(self):
            pass

    monkeypatch.setattr(v4_runner, "WarmWorker", Worker)
    original = Path.read_bytes

    def read(path):
        if path.name == "offline-references.json":
            assert len(calls) == 18
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(sys, "argv", ["run", "--freeze", str(fd), "--selector", str(sd), "--panel", str(pd)])
    run.main()
    expected = []
    for rep in (0, 1):
        for index, cases in enumerate((("a1", "a2"), ("b1",))):
            shift = (index + rep) % 3
            for arm in ("F", "C", "L")[shift:] + ("F", "C", "L")[:shift]:
                expected.append(["%d|%s|%s" % (rep, arm, case)
                                 for case in (cases if rep == 0 else tuple(reversed(cases)))])
    assert batches == expected
    output = next(folder.glob("route-b-v5-run-*"))
    summary = json.loads((output / "summary.json").read_bytes())
    assert len(summary["worker_cold_starts"]) == 12
    assert all(row["seconds"] >= 0 for row in summary["worker_cold_starts"])


@pytest.mark.parametrize("text,reason", [("int main(void) { return 0; }", "defines_main"),
                                         ("int\nmain(int argc, char **argv)\n{\nreturn 0;\n}", "defines_main"),
                                         ("// int main(void) {\nint f(int x) { return x; }", None),
                                         ("int main(void);\nint f(int x) { return x; }", None)])
def test_source_main_definition_filter(text, reason):
    assert prepare.unit_exclusion("unit.c", text) == reason


def test_prepare_excludes_sealed_names_before_reading(folder, monkeypatch):
    # No sealed file is created or opened: the candidate is only a mocked path.
    sealed = folder / "project" / "base64.c"
    clean = folder / "project" / "unit.c"
    clean.parent.mkdir()
    clean.write_bytes(b"int f(int x) { return x; }\n")
    original_glob, original_read = Path.glob, Path.read_text
    monkeypatch.setattr(prepare, "git", lambda *a, **k: "commit")
    monkeypatch.setattr(prepare, "remove_tree", lambda path: None)
    monkeypatch.setattr(Path, "is_file", lambda p: True if p == sealed else p.exists())
    monkeypatch.setattr(Path, "glob", lambda p, pattern, **kwargs:
                        iter([sealed, clean]) if p == clean.parent and pattern == "*.c"
                        else original_glob(p, pattern, **kwargs))

    def read(path, *a, **k):
        assert path != sealed
        return original_read(path, *a, **k)

    monkeypatch.setattr(Path, "read_text", read)
    entry = prepare.prepare_project(folder, ("project", "owner/repo", ["."], [], [], None))
    assert entry["translation_units"] == ["unit.c"]
    assert entry["rejected_units"] == [{"unit": "base64.c", "reason": "excluded_file_name"}]


def test_dwarf_checks_headers_and_containment(folder, monkeypatch):
    monkeypatch.setattr(dwarf, "SCRATCH", folder)
    source = folder / "source"
    source.mkdir()
    (source / "unit.c").write_bytes(b"unit")
    (source / "config.h").write_bytes(b"config")
    project = {"project_id": "p", "source_directory": str(source), "translation_units": ["unit.c"],
               "include_directories": ["."], "defines": [],
               "source_files": {n: dwarf.sha(source / n) for n in ("unit.c", "config.h")}}
    assert dwarf.verify_project(project) == source
    (source / "config.h").write_bytes(b"modified")
    with pytest.raises(ValueError, match="Pinned source changed"):
        dwarf.verify_project(project)
    with pytest.raises(ValueError):
        dwarf.source_child(source, "../escape")


def test_inventory_requires_linked_elf_even_after_successful_link(folder):
    path = folder / "inventory.elf"
    for header in (b"COFF", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x01\x00"):
        path.write_bytes(header)
        assert not dwarf.inventory_elf(path)
    path.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\x00")
    assert dwarf.inventory_elf(path)


def test_json_writers_emit_ascii_lf_on_python38(folder):
    for index, writer in enumerate((run.write, label.write, prepare.write)):
        path = folder / ("%d.json" % index)
        writer(path, {"value": "\u00e9"})
        data = path.read_bytes()
        assert b"\r" not in data
        data.decode("ascii")


def freeze_fixture(folder, monkeypatch):
    """A minimum-sized metadata panel; no feature extraction or analysis."""
    dirs = {name: folder / name for name in ("sources", "build", "panel", "regression", "old-gate", "v4-freeze",
                                             "v4-selector", "v4-panel")}
    for path in dirs.values():
        path.mkdir()
    monkeypatch.setattr(freeze, "SCRATCH", folder)
    monkeypatch.setattr(freeze, "V4_FREEZE", dirs["v4-freeze"])
    monkeypatch.setattr(freeze, "V4_SELECTOR", dirs["v4-selector"])
    monkeypatch.setattr(freeze, "V4_PANEL", dirs["v4-panel"])
    run.write(dirs["v4-freeze"] / "freeze.json", {
        "pins": {p: freeze.file_hash(freeze.ROOT / p) for p in freeze.V4_IDENTICAL},
        "regression": {"directory": str(dirs["old-gate"])}})
    gate = {"passed": True, "wrong_decisions": [], "outcome_mismatches": []}
    run.write(dirs["regression"] / "summary.json", gate)
    run.write(dirs["regression"] / "records.json", [])
    run.write(dirs["old-gate"] / "summary.json", gate)
    run.write(dirs["sources"] / "sources-manifest.json", {"compilation_performed": True, "projects": []})
    binary = dirs["panel"] / "fixture.elf"
    binary.write_bytes(b"fixture bytes")
    query = {"binary": binary.name, "binary_sha256": freeze.file_hash(binary)}
    records = [{"case_id": "q%d" % n, "binary_group": "g%d" % (n // 4), "stratum": "S2", "query": query}
               for n in range(120)]
    run.write(dirs["panel"] / "panel.json", {"records": records})
    run.write(dirs["panel"] / "offline-references.json", {"references": {}})
    run.write(dirs["build"] / "unscreened-references.json", {"references": {}})
    run.write(dirs["build"] / "plan.json", {"hashes": {}, "selection_inputs": {
        "sources_manifest": str(dirs["sources"] / "sources-manifest.json")}})
    screen = folder / "screen.json"
    run.write(screen, {"schema": "symbai.route_b_v5_sanitizer_screen.v1",
                       "plan_sha256": freeze.file_hash(dirs["build"] / "plan.json"),
                       "references_sha256": freeze.file_hash(dirs["build"] / "unscreened-references.json"),
                       "counts_by_status": {"pass": 60}, "counts_by_reason": {},
                       "aslr_disabled": True, "run_prefix": ["/usr/bin/setarch", "x86_64", "-R"]})
    selection = {"minimum_met": True, "counts": {"queries": 120, "groups": 30, "by_stratum": {"S2": 120}},
                 "pins": {"build_directory": str(dirs["build"]), "screen": str(screen),
                          "screen_sha256": freeze.file_hash(screen), "build_files": {}}}
    run.write(dirs["panel"] / "selection.json", selection)
    run.write(dirs["v4-selector"] / "development-queries.json", {"rows": [{"query": {**query, "binary": str(binary)}}]})
    run.write(dirs["v4-panel"] / "panel.json", {"records": []})
    args = ["freeze"]
    for name in ("sources", "build", "panel", "regression"):
        args.extend(["--" + name, str(dirs[name])])
    args.extend(["--screen", str(screen)])
    monkeypatch.setattr("sys.argv", args)
    return dirs, screen


def test_freeze_records_real_counts_all_artifacts_and_checks_later_changes(folder, monkeypatch):
    dirs, screen = freeze_fixture(folder, monkeypatch)
    freeze.main()
    frozen = next(folder.glob("route-b-v5-freeze-*"))
    data = freeze.verify_freeze(frozen)
    assert data["panel"]["counts"] == {"queries": 120, "groups": 30, "by_stratum": {"S2": 120}}
    assert data["screen"]["counts"] == {"by_status": {"pass": 60}, "by_reason": {}}
    for path in (screen, dirs["sources"] / "sources-manifest.json", dirs["panel"] / "fixture.elf",
                 dirs["regression"] / "records.json", dirs["v4-selector"] / "development-queries.json"):
        assert path in [freeze.artifact_path(p) for p in data["artifact_files"]]
    (dirs["sources"] / "sources-manifest.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact changed"):
        label.verify_freeze(frozen)


@pytest.mark.parametrize("change,match", [("minimum", "minimum"), ("screen", "Screen belongs"),
                                         ("v4-pin", "v4 freeze"), ("old-gate", "re-run"),
                                         ("build-source", "another sources manifest"),
                                         ("aslr", "address randomization")])
def test_freeze_rejects_false_metadata_before_writing(folder, monkeypatch, change, match):
    dirs, screen = freeze_fixture(folder, monkeypatch)
    if change == "minimum":
        run.write(dirs["panel"] / "panel.json", {"records": []})
    elif change == "screen":
        data = json.loads(screen.read_bytes())
        data["plan_sha256"] = "0" * 64
        run.write(screen, data)
    elif change == "v4-pin":
        path = dirs["v4-freeze"] / "freeze.json"
        data = json.loads(path.read_bytes())
        del data["pins"][freeze.V4_IDENTICAL[0]]
        run.write(path, data)
    elif change == "old-gate":
        import sys
        monkeypatch.setattr(sys, "argv", [str(dirs["old-gate"]) if value == str(dirs["regression"]) else value
                                        for value in sys.argv])
    elif change == "aslr":
        data = json.loads(screen.read_bytes())
        data.update(aslr_disabled=False, run_prefix=[])
        run.write(screen, data)
        selection = json.loads((dirs["panel"] / "selection.json").read_bytes())
        selection["pins"]["screen_sha256"] = freeze.file_hash(screen)
        run.write(dirs["panel"] / "selection.json", selection)
    elif change == "build-source":
        path = dirs["build"] / "plan.json"
        data = json.loads(path.read_bytes())
        data["selection_inputs"]["sources_manifest"] = str(folder / "other.json")
        run.write(path, data)
        block = json.loads(screen.read_bytes())
        block["plan_sha256"] = freeze.file_hash(path)
        run.write(screen, block)
    with pytest.raises((ValueError, SystemExit), match=match):
        freeze.main()
    assert not list(folder.glob("route-b-v5-freeze-*"))


def test_development_training_uses_two_reversed_single_backend_passes(folder, monkeypatch):
    from src.selective_analysis import v4_selector
    import sys

    fd, sd, pd = frozen_inputs(folder)
    monkeypatch.setattr(label, "SCRATCH", folder)
    cases = [{"id": "dev-a", "features": [0], "query": {}}, {"id": "dev-b", "features": [1], "query": {}}]
    monkeypatch.setattr(label, "development_queries", lambda: cases)
    monkeypatch.setattr(label, "feature_names", lambda: ["feature"])
    monkeypatch.setattr(sys, "argv", ["label", "--freeze", str(fd)])
    calls, fits = [], []

    class Worker:
        replacements = []

        def run(self, request, query, order, budget):
            assert len(order) == 1 and budget == 3.0
            calls.append(request)
            return {"status": "unknown", "admitted": True, "charged_seconds": 0.1, "worker_replaced": False}

        def stop(self):
            pass

    def fit(features, labels):
        fits.append((features, labels))
        return {}

    monkeypatch.setattr(label, "WarmWorker", Worker)
    monkeypatch.setattr(v4_selector, "fit", fit)
    label.main()
    expected = ["%d|%s|%s" % (rep, row["id"], backend) for rep in (0, 1)
                for row in (cases if rep == 0 else list(reversed(cases)))
                for backend in (v4_selector.BACKENDS if rep == 0 else tuple(reversed(v4_selector.BACKENDS)))]
    assert calls == expected
    assert len(fits) == 1 and fits[0][0] == [[0], [1], [0], [1]]
    assert all(entry[backend] == {"decisive": False, "seconds": 3.0}
               for entry in fits[0][1] for backend in v4_selector.BACKENDS)
    output = next(folder.glob("route-b-v5-selector-*"))
    model = json.loads((output / "model.json").read_bytes())
    assert model["freeze_sha256"] == freeze.file_hash(fd / "freeze.json")


def test_source_manifest_pins_nested_headers_and_registered_wren_scope(folder, monkeypatch):
    target = folder / "project"
    (target / "include" / "detail").mkdir(parents=True)
    (target / "unit.c").write_bytes(b"int f(int x) { return x; }\n")
    (target / "include" / "detail" / "config.h").write_bytes(b"#define FLAG 1\n")
    monkeypatch.setattr(prepare, "git", lambda *a, **k: "commit")
    monkeypatch.setattr(prepare, "remove_tree", lambda path: None)
    result = prepare.prepare_project(folder, ("project", "owner/repo", ["."], ["include"], [], None))
    assert "include/detail/config.h" in result["source_files"]
    assert next(p for p in prepare.PROJECTS if p[0] == "wren")[2] == ["src/vm"]


def test_development_manifest_is_79_earlier_and_62_v4_panel_queries(folder, monkeypatch):
    selector, panel_dir = folder / "old-selector", folder / "old-panel"
    selector.mkdir()
    panel_dir.mkdir()
    monkeypatch.setattr(label, "V4_SELECTOR", selector)
    monkeypatch.setattr(label, "V4_PANEL", panel_dir)
    previous = [{"id": "d%d" % n, "query": {"binary": "fixture.elf", "tag": "development"}} for n in range(79)]
    panel_records = [{"case_id": "p%d" % n, "query": {"binary": "fixture.elf", "tag": "panel"}} for n in range(62)]
    run.write(selector / "development-queries.json", {"rows": previous})
    run.write(panel_dir / "panel.json", {"records": panel_records})
    monkeypatch.setattr(label.Query, "from_dict", lambda raw: raw)
    monkeypatch.setattr(label, "extract_features", lambda raw: raw["tag"])
    monkeypatch.setattr(label, "feature_vector", lambda feature: [feature])
    rows = label.development_queries()
    assert len(rows) == 141
    assert sum(r["id"].startswith("v4dev:") for r in rows) == 79
    assert sum(r["id"].startswith("v4panel:") for r in rows) == 62
    run.write(panel_dir / "panel.json", {"records": panel_records[:-1]})
    with pytest.raises(ValueError, match="141 distinct"):
        label.development_queries()


def test_freeze_rejects_replaced_inventory_even_if_build_repinning_would_accept_it(folder, monkeypatch):
    dirs, screen = freeze_fixture(folder, monkeypatch)
    inventory = dirs["sources"] / "inventory.elf"
    inventory.write_bytes(b"original inventory")
    manifest = {"compilation_performed": True, "projects": [
        {"status": "pinned", "dwarf_elf": str(inventory), "dwarf_elf_sha256": freeze.file_hash(inventory)}]}
    run.write(dirs["sources"] / "sources-manifest.json", manifest)
    inventory.write_bytes(b"replacement inventory")
    with pytest.raises(ValueError, match="Inventory differs"):
        freeze.main()
