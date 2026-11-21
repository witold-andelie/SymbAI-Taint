"""Torch-free protocol tests; all temporary artifacts stay inside the clone."""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from scripts import train_type_pilot_v2 as runner
from src.selective_analysis.type_corpus import sha
from src.selective_analysis.type_training import read
from src.selective_analysis import type_training_v2
from src.selective_analysis.type_training_v2 import (ACCESS_WIDTHS, OUTCOMES,
    PREREGISTRATION_SHA256, SEEDS, WIDTHS, decision_rules, detailed_scores,
    load_dev_extension, structural_readout_features, structural_variables)


TEST_OUTPUT = Path(".test-output").resolve()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))


def remove_fixture(path):
    resolved = path.resolve()
    resolved.relative_to(TEST_OUTPUT)
    assert resolved != TEST_OUTPUT
    shutil.rmtree(str(resolved))


def graph(widths, edges, readouts):
    x = []
    for value in widths:
        row = [0.] * 31
        row[5 + WIDTHS.index(str(value))] = 1.
        x.append(row)
    return {"schema": "symbai.type_graph_features.v1", "feature_width": 31,
            "relation_count": 60, "x": x,
            "edge_index": [[e[0] for e in edges], [e[1] for e in edges]],
            "edge_type": [e[2] for e in edges], "readout_nodes": readouts}


def target(identity, cls, vocabulary, rows):
    return {"source_variable_id": identity, "die_offset": 1, "class_id": cls,
            "label": vocabulary[cls], "readout_rows": rows, "per_row_loss_weight": 1. / len(rows)}


def exported_sample(directory, identity, project, split, features, targets):
    supervision = {"schema": "symbai.type_graph_supervision.v1",
                   "labels_in_graph_features": False, "targets": targets}
    item = {"function_id": identity, "project_id": project, "split": split}
    for key, value in (("features", features), ("supervision", supervision)):
        name = identity + "/" + key + ".json"
        write(directory / name, value)
        item[key] = {"path": name, "sha256": sha(directory / name)}
    return item


@pytest.fixture(scope="module")
def reviewed():
    root = TEST_OUTPUT / ("reviewed-v2-" + uuid.uuid4().hex)
    training = root / "training"
    vocabulary = ["type" + str(i) for i in range(75)]
    vocabulary[1:3] = ["char*", "struct*"]
    write(training / "vocabulary.json", vocabulary)
    samples = []
    for split, functions, variables, rows, project in (
            ("train", 26, 129, 1998, "inih"), ("development", 15, 52, 813, "optparse")):
        variable = 0
        for fn in range(functions):
            count = variables // functions + int(fn < variables % functions)
            targets, offset = [], 0
            for _ in range(count):
                size = rows // variables + int(variable < rows % variables)
                cls = 1 + variable % 3
                targets.append(target(split + "-variable-" + str(variable), cls, vocabulary,
                                      list(range(offset, offset + size))))
                offset += size
                variable += 1
            features = graph([64, 8, 32], [(0, 1, 1), (1, 0, 31), (1, 2, 59)], [0] * offset)
            samples.append(exported_sample(training, split + "-fn-" + str(fn), project,
                                           split, features, targets))
    dataset = {"schema": "symbai.type_graph_dataset.v1", "samples": samples,
        "vocabulary": {"path": "vocabulary.json", "sha256": sha(training / "vocabulary.json")},
        "relation_count": 60, "feature_width": 31, "evaluation_projects_executed": False,
        "labels_separate_from_features": True, "training_allowed": False}
    write(training / "dataset.json", dataset)
    write(training / "summary.json", {"prepare_only": False, "completed_functions": 43})
    write(training / "independent-export-audit.json", {"schema": "symbai.type_graph_export_audit.v1",
        "planned_functions": 43, "exported_functions": 41, "admitted_source_variables": 181,
        "supervised_value_rows": 2811, "evaluation_projects_executed": False,
        "training_performed": False, "sha256": {}})
    previous = root / "v1-run"
    write(previous / "summary.json", {"status": "completed", "prepare_only": False,
        "smoke_only": False, "admission": {"dataset_sha256": sha(training / "dataset.json")},
        "evaluation_projects_executed": False})
    for seed in SEEDS:
        for mode in ("graph", "no_messages"):
            write(previous / (mode + "-" + str(seed)) / "metrics.json",
                  {"seed": seed, "mode": mode, "final_state_sha256": "f" * 64})
    try:
        yield training, previous, vocabulary
    finally:
        remove_fixture(root)


def seal_dev(directory, dataset):
    """Update receipts after intentional semantic mutations, not after hash tests."""
    for item in dataset["samples"]:
        for key in ("features", "supervision"):
            item[key]["sha256"] = sha(directory / item[key]["path"])
    write(directory / "dataset.json", dataset)
    names = {"dataset.json", dataset["vocabulary"]["path"], "selection.json"}
    names.update(item[key]["path"] for item in dataset["samples"] for key in ("features", "supervision"))
    targets = [t for item in dataset["samples"]
               for t in read(directory / item["supervision"]["path"])["targets"]]
    write(directory / "independent-export-audit.json", {
        "schema": "symbai.type_dev_graph_export_audit.v1", "evaluation_projects_executed": False,
        "training_performed": False, "admitted_source_variables": len(targets),
        "exported_functions": len(dataset["samples"]),
        "sha256": {name: sha(directory / name) for name in sorted(names)}})


@pytest.fixture
def extension(reviewed, monkeypatch):
    training, previous, vocabulary = reviewed
    root = TEST_OUTPUT / ("case-v2-" + uuid.uuid4().hex)
    directory = root / "development"
    directory.mkdir(parents=True)
    (directory / "vocabulary.json").write_bytes((training / "vocabulary.json").read_bytes())
    write(directory / "selection.json", {"preregistration_sha256": PREREGISTRATION_SHA256})
    samples = [exported_sample(directory, "new-fn-" + str(i), p, "development",
        graph([64, 8], [(0, 1, 1), (1, 0, 31)], [0]),
        [target("new-variable-" + str(i), cls, vocabulary, [0])])
        for i, (p, cls) in enumerate((("sds", 1), ("json_parser", 4)))]
    dataset = {"schema": "symbai.type_dev_graph_dataset.v1", "samples": samples,
        "preregistration_sha256": PREREGISTRATION_SHA256,
        "selection_sha256": sha(directory / "selection.json"),
        "relation_count": 60, "feature_width": 31, "labels_separate_from_features": True,
        "evaluation_projects_executed": False, "admitted_source_variables": 2,
        "supervised_value_rows": 2,
        "vocabulary": {"path": "vocabulary.json", "sha256": sha(directory / "vocabulary.json")}}
    seal_dev(directory, dataset)
    # execute sets cache/temp variables; restore them before deleting its output.
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR",
                "NUMBA_CACHE_DIR", "CUDA_VISIBLE_DEVICES"):
        monkeypatch.setenv(key, os.environ.get(key, ""))
    try:
        yield root, directory, dataset, training, previous
    finally:
        monkeypatch.undo()
        remove_fixture(root)


def test_dev_admission_returns_unchanged_v1_shape(extension, monkeypatch):
    _, directory, dataset, training, _ = extension
    before = runner.pin_tree(directory)
    samples = load_dev_extension(directory, PREREGISTRATION_SHA256, training)
    assert len(samples) == 2
    assert samples[0]["features"] == read(directory / dataset["samples"][0]["features"]["path"])
    assert samples[1]["supervision"]["targets"][0]["source_variable_id"] == "new-variable-1"
    assert runner.pin_tree(directory) == before
    assert "torch" not in sys.modules
    monkeypatch.setattr(type_training_v2, "V1_DATASET", training)
    assert load_dev_extension(directory, PREREGISTRATION_SHA256) == samples


@pytest.mark.parametrize("field,value", [
    ("schema", "wrong"), ("preregistration_sha256", "0" * 64),
    ("selection_sha256", "not-a-hash"), ("relation_count", 59), ("feature_width", 30),
    ("labels_separate_from_features", False), ("evaluation_projects_executed", True),
    ("admitted_source_variables", 3), ("supervised_value_rows", 3)])
def test_dev_contract_fields_are_checked(extension, field, value):
    _, directory, dataset, training, _ = extension
    dataset[field] = value
    seal_dev(directory, dataset)
    with pytest.raises(ValueError):
        load_dev_extension(directory, PREREGISTRATION_SHA256, training)


@pytest.mark.parametrize("field,value", [("schema", "wrong"), ("evaluation_projects_executed", True),
    ("training_performed", True), ("admitted_source_variables", 3), ("exported_functions", 3)])
def test_dev_audit_contract_is_checked(extension, field, value):
    _, directory, _, training, _ = extension
    path = directory / "independent-export-audit.json"
    audit = read(path)
    audit[field] = value
    write(path, audit)
    with pytest.raises(ValueError):
        load_dev_extension(directory, PREREGISTRATION_SHA256, training)


@pytest.mark.parametrize("project", ["inih", "rxi_map", "jsmn", "optparse", "utf8_h", "b64"])
def test_excluded_projects_are_rejected(extension, project):
    _, directory, dataset, training, _ = extension
    dataset["samples"][0]["project_id"] = project
    seal_dev(directory, dataset)
    with pytest.raises(ValueError, match="Excluded"):
        load_dev_extension(directory, PREREGISTRATION_SHA256, training)


@pytest.mark.parametrize("damage", ["train", "evaluation", "duplicate_function", "duplicate_variable",
    "v1_overlap", "vocabulary_bytes", "vocabulary_entry", "supervision_schema", "invalid_graph",
    "duplicate_rows", "sample_hash", "audit_hash", "audit_escape", "sample_escape", "empty",
    "absolute_sample", "absolute_audit"])
def test_dev_identity_hash_and_graph_failures(extension, damage):
    _, directory, dataset, training, _ = extension
    first, second = dataset["samples"]
    if damage in ("train", "evaluation"):
        first["split"] = damage
    elif damage == "duplicate_function":
        second["function_id"] = first["function_id"]
    elif damage in ("duplicate_variable", "v1_overlap", "supervision_schema", "duplicate_rows"):
        path = directory / second["supervision"]["path"]
        supervision = read(path)
        if damage == "supervision_schema":
            supervision["schema"] = "wrong"
        elif damage == "duplicate_rows":
            supervision["targets"][0]["readout_rows"] = [0, 0]
        else:
            supervision["targets"][0]["source_variable_id"] = (
                "new-variable-0" if damage == "duplicate_variable" else "train-variable-0")
        write(path, supervision)
    elif damage == "vocabulary_bytes":
        path = directory / "vocabulary.json"
        path.write_bytes(path.read_bytes() + b" ")
        dataset["vocabulary"]["sha256"] = sha(path)
    elif damage == "vocabulary_entry":
        dataset["vocabulary"]["sha256"] = "0" * 64
    elif damage == "invalid_graph":
        path = directory / first["features"]["path"]
        features = read(path)
        features["edge_type"][0] = 60
        write(path, features)
    elif damage in ("sample_escape", "absolute_sample"):
        first["features"]["path"] = ("../outside.json" if damage == "sample_escape"
                                     else str((directory / first["features"]["path"]).resolve()))
        write(directory / "dataset.json", dataset)
    elif damage == "empty":
        dataset.update(samples=[], admitted_source_variables=0, supervised_value_rows=0)
    if damage not in ("sample_hash", "audit_hash", "audit_escape", "sample_escape", "absolute_sample", "absolute_audit"):
        seal_dev(directory, dataset)
    if damage == "sample_hash":
        first["features"]["sha256"] = "0" * 64
        seal_dev(directory, dataset)
        # Keep the audit valid but deliberately invalidate the dataset receipt.
        dataset["samples"][0]["features"]["sha256"] = "0" * 64
        write(directory / "dataset.json", dataset)
        path = directory / "independent-export-audit.json"
        audit = read(path)
        audit["sha256"]["dataset.json"] = sha(directory / "dataset.json")
        write(path, audit)
    elif damage in ("audit_hash", "audit_escape", "sample_escape", "absolute_sample", "absolute_audit"):
        path = directory / "independent-export-audit.json"
        audit = read(path)
        if damage == "audit_hash":
            audit["sha256"]["selection.json"] = "0" * 64
        elif damage == "audit_escape":
            audit["sha256"]["../outside.json"] = "0" * 64
        elif damage == "absolute_audit":
            audit["sha256"][str((directory / "selection.json").resolve())] = sha(directory / "selection.json")
        else:
            audit["sha256"]["dataset.json"] = sha(directory / "dataset.json")
        write(path, audit)
    with pytest.raises(ValueError):
        load_dev_extension(directory, PREREGISTRATION_SHA256, training)


def feature_bucket(row, block, width_value):
    offset = 8 + block * 20 + ACCESS_WIDTHS.index(str(width_value)) * 5
    return row[offset:offset + 5]


@pytest.mark.parametrize("depth", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("width_value", [8, 16, 32, 64])
def test_a5_distance_and_forward_depth_buckets(depth, width_value):
    edges = [(i, i + 1, 2) for i in range(depth - 1)] + [(depth - 1, depth, 1)]
    row = structural_readout_features(graph([64] * depth + [width_value], edges, [0]))[0]
    expected = [float(i == depth) for i in range(1, 6)]
    assert len(row) == 48 and sum(row) == 9
    assert row[:8] == [0., 0., 0., 0., 1., 0., 0., 0.]
    assert feature_bucket(row, 0, width_value) == expected
    assert feature_bucket(row, 1, width_value) == expected
    for other in set(ACCESS_WIDTHS) - {str(width_value)}:
        assert feature_bucket(row, 0, other) == [0., 0., 0., 0., 1.]
        assert feature_bucket(row, 1, other) == [0., 0., 0., 0., 1.]


def test_a5_forward_excludes_inverse_and_address_traversal_and_handles_cycles():
    features = graph([64, 8, 32, 16, 64],
        [(0, 1, 1), (1, 2, 1), (0, 3, 31), (3, 4, 1), (0, 0, 2), (1, 0, 32)], [0])
    row = structural_readout_features(features)[0]
    assert feature_bucket(row, 0, 32) == [0., 1., 0., 0., 0.]
    assert feature_bucket(row, 1, 8) == [1., 0., 0., 0., 0.]
    assert feature_bucket(row, 1, 32) == [0., 0., 0., 0., 1.]
    assert feature_bucket(row, 1, 64) == [0., 0., 0., 0., 1.]
    # Relation 31 alone never defines an access node.
    assert feature_bucket(row, 0, 16) == [0., 0., 0., 0., 1.]


def test_a5_undirected_edges_minimum_distance_and_zero_distance_excluded():
    features = graph([64, 8, 64, 8, 16],
        [(2, 0, 2), (2, 1, 1), (0, 3, 1), (4, 0, 1)], [0])
    row = structural_readout_features(features)[0]
    assert feature_bucket(row, 0, 8) == [1., 0., 0., 0., 0.]
    assert feature_bucket(row, 0, 64) == [0., 0., 0., 0., 1.]
    assert feature_bucket(row, 1, 64) == [0., 0., 0., 0., 1.]
    reverse = graph([64, 8, 32], [(2, 0, 2), (2, 1, 1)], [0])
    row = structural_readout_features(reverse)[0]
    assert feature_bucket(row, 0, 8) == [0., 1., 0., 0., 0.]
    assert feature_bucket(row, 1, 8) == [0., 0., 0., 0., 1.]


@pytest.mark.parametrize("width_value", WIDTHS)
def test_a5_all_eight_width_flags(width_value):
    row = structural_readout_features(graph([width_value], [], [0]))[0]
    assert row[:8] == [float(width_value == w) for w in WIDTHS]
    assert row[8:] == [0., 0., 0., 0., 1.] * 8


def test_a5_minimum_distances_and_forward_relation_boundary():
    features = graph([64, 64, 8, 64], [(0, 1, 29), (1, 2, 1), (0, 2, 31),
                                      (0, 3, 30), (3, 2, 1), (1, 0, 2)], [0])
    row = structural_readout_features(features)[0]
    assert feature_bucket(row, 0, 8) == [1., 0., 0., 0., 0.]
    assert feature_bucket(row, 1, 8) == [0., 1., 0., 0., 0.]


def test_a5_averages_readout_rows_before_regression_and_ignores_labels():
    features = graph([64, 8, 32], [(0, 1, 1)], [0, 2, 0])
    supervision = {"targets": [{"readout_rows": [0, 1, 2], "class_id": 1, "label": "char*"}]}
    sample = {"features": features, "supervision": supervision, "function_id": "f", "project_id": "sds"}
    before = deepcopy(sample)
    vectors, targets = structural_variables([sample])
    rows = structural_readout_features(features)
    assert vectors[0] == [(rows[0][i] + rows[1][i] + rows[2][i]) / 3 for i in range(48)]
    assert feature_bucket(vectors[0], 0, 8) == pytest.approx([2. / 3, 0, 0, 0, 1. / 3])
    assert targets[0]["function_id"] == "f" and sample == before
    sample["supervision"]["targets"][0].update(label="struct*", class_id=2)
    assert structural_variables([sample])[0] == vectors


@pytest.mark.parametrize("active", [[], [5, 6]])
def test_a5_invalid_width_flags_are_rejected(active):
    features = graph([64], [], [0])
    features["x"][0] = [float(i in active) for i in range(31)]
    with pytest.raises(ValueError, match="width"):
        structural_readout_features(features)


def metric(n, correct, nll):
    return {"source_variables": n, "correct_top1": correct, "mean_nll": nll}


@pytest.mark.parametrize("n,margin", [(1, 3), (59, 3), (60, 3), (61, 4), (100, 5), (101, 6)])
def test_decision_margin_uses_integer_ceiling(n, margin):
    base = {seed: metric(n, 0, 2.) for seed in SEEDS}
    deeper = {seed: metric(n, min(n, margin), 1.) for seed in SEEDS}
    decision = decision_rules(n, base, deeper, metric(n, 0, 3.))
    assert decision["m"] == margin
    assert decision["R1"] == decision["R2"] == (n >= margin)


@pytest.mark.parametrize("kind", ["both", "structure_tie", "nll_tie", "one_seed_fails", "negative", "no_r1_but_r2"])
def test_decision_outcomes_require_every_seed_and_strict_nll(kind):
    base = {seed: metric(100, 30, 2.) for seed in SEEDS}
    deeper = {seed: metric(100, 35, 1.) for seed in SEEDS}
    structural = metric(100, 30, 1.)
    expected = "R1 and R2"
    if kind == "structure_tie":
        structural["correct_top1"] = 35
        expected = "R1 without R2"
    elif kind == "nll_tie":
        deeper[43]["mean_nll"] = 2.
        expected = "No R1"
    elif kind == "one_seed_fails":
        deeper[29]["correct_top1"] = 34
        expected = "No R1"
    elif kind == "negative":
        deeper[17]["correct_top1"] = 29
        expected = "No R1"
    elif kind == "no_r1_but_r2":
        base[17]["correct_top1"] = 40
        expected = "No R1"
    result = decision_rules(100, base, deeper, structural)
    assert result["outcome"] == expected
    assert result["next_step"] == OUTCOMES[expected]
    assert result["outcome_row"] == expected + " | " + OUTCOMES[expected]
    assert result["R1"] == (expected != "No R1")
    assert result["R2"] == (kind in ("both", "nll_tie", "no_r1_but_r2"))
    assert result["per_seed"][0]["A3_minus_A1_correct_top1"] == deeper[17]["correct_top1"] - base[17]["correct_top1"]


@pytest.mark.parametrize("damage", ["zero", "negative_n", "missing_seed", "denominator", "nonfinite", "too_many", "negative_nll"])
def test_invalid_decisions_are_rejected(damage):
    n = 100
    base = {seed: metric(n, 20, 2.) for seed in SEEDS}
    deeper = {seed: metric(n, 25, 1.) for seed in SEEDS}
    if damage == "zero":
        n = 0
    elif damage == "negative_n":
        n = -1
    elif damage == "missing_seed":
        deeper.pop(43)
    elif damage == "denominator":
        deeper[17]["source_variables"] = 99
    elif damage == "nonfinite":
        deeper[17]["mean_nll"] = float("nan")
    elif damage == "too_many":
        deeper[17]["correct_top1"] = 101
    else:
        deeper[17]["mean_nll"] = -1.
    with pytest.raises(ValueError):
        decision_rules(n, base, deeper, metric(100, 10, 3.))


def test_secondary_metrics_retain_unseen_classes_and_named_absent_class(reviewed):
    _, _, vocabulary = reviewed
    targets = [dict(target("one", 1, vocabulary, [0]), project_id="sds"),
               dict(target("two", 4, vocabulary, [0]), project_id="json_parser")]
    scores = [[0.] * 75 for _ in targets]
    scores[0][1], scores[1][1] = 10., 10.
    result = detailed_scores(scores, targets, {1}, vocabulary)
    assert result["source_variables"] == 2 and result["unseen_class_variables"] == 1
    assert result["per_class_recall"]["char*"]["recall"] == 1.
    assert result["per_class_recall"]["struct*"] == {"source_variables": 0, "correct_top1": 0, "recall": None}
    assert result["per_class_recall"][vocabulary[4]]["recall"] == 0.
    assert result["unseen_gold_classes"] == [vocabulary[4]]
    assert result["per_project"]["json_parser"]["unseen_class_variables"] == 1


def test_prepare_only_fixture_pins_sources_and_data_without_torch(extension, monkeypatch):
    root, directory, _, training, previous = extension
    before = runner.pin_tree(directory)
    outputs = []
    execute = runner.execute
    monkeypatch.setattr(runner, "execute", lambda args: outputs.append(execute(args, scratch=root / "runs")))
    runner.main(["--training-dataset", str(training), "--dev-dataset", str(directory),
                 "--v1-run", str(previous), "--prepare-only"])
    output, = outputs
    summary = read(output / "summary.json")
    assert summary["status"] == "prepared" and summary["prepare_only"]
    assert summary["source_and_data_integrity_unchanged"]
    assert not summary["model_training_performed"] and not summary["decisions_computed"]
    assert not summary["evaluation_projects_executed"] and not summary["neural_scheduling_benefit_measured"]
    assert summary["development_admission"]["source_variables"] == 2
    assert summary["configuration"]["arms"]["A3"]["layers"] == 4
    assert summary["configuration"]["arms"]["A5"]["epochs"] == 300
    assert not (output / "decision.json").exists() and "torch" not in sys.modules
    assert (output / "temp").is_dir() and os.environ["CUDA_VISIBLE_DEVICES"] == ""
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME"):
        assert os.environ[key] == str(output / "temp")
    snapshots = {p.name for p in (output / "source_snapshot").iterdir()}
    assert snapshots == {"train_type_pilot_v2.py", "type_training_v2.py", "type_training.py",
                         "type_corpus.py", "train_type_graph_pilot.py", "type_pilot_v2_preregistration.md"}
    pins = read(output / "plan.json")["source_pins"]
    assert all(sha(path) == digest for path, digest in pins.items())
    assert runner.pin_tree(directory) == before
    source = root / "pinned.txt"
    source.write_bytes(b"first")
    pinned = {str(source): sha(source)}
    source.write_bytes(b"changed")
    with pytest.raises(ValueError, match="Pinned"):
        runner.verify_pins(pinned)


def test_prepare_rejects_changed_preregistration_before_output(extension, monkeypatch):
    root, directory, _, training, previous = extension
    monkeypatch.setattr(runner, "PREREGISTRATION_SHA256", "0" * 64)
    args = argparse.Namespace(training_dataset=training, dev_dataset=directory, v1_run=previous,
                              prepare_only=True, smoke_only=False)
    with pytest.raises(ValueError, match="preregistration"):
        runner.execute(args, scratch=root / "runs")
    assert not (root / "runs").exists()


@pytest.mark.parametrize("change_input", [False, True])
def test_reproduction_gate_and_final_integrity_failure_without_torch(extension, monkeypatch, change_input):
    root, directory, _, training, previous = extension
    calls = []
    fake_torch = SimpleNamespace(__version__="test-double",
        set_num_threads=lambda n: calls.append(("threads", n)),
        set_num_interop_threads=lambda n: calls.append(("interop", n)),
        use_deterministic_algorithms=lambda value: calls.append(("deterministic", value)))
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "torch_geometric", SimpleNamespace(__version__="test-double"))
    monkeypatch.setattr(runner, "runtime_contract_layers", lambda torch, n: {"layers": n})
    monkeypatch.setattr(runner, "tensor_batch", lambda samples: {"samples": samples})

    def mismatch(torch, batches, seen, vocabulary, config, seed, messages, output, on_step):
        assert set(batches) == {"train", "development"}
        assert {s["split"] for s in batches["train"]["samples"]} == {"train"}
        assert {s["project_id"] for s in batches["development"]["samples"]} == {"optparse"}
        output.mkdir()
        on_step()
        if change_input:
            selection = directory / "selection.json"
            selection.write_bytes(selection.read_bytes() + b" ")
        return {"final_state_sha256": "0" * 64}

    monkeypatch.setattr(runner, "run_model", mismatch)
    args = argparse.Namespace(training_dataset=training, dev_dataset=directory, v1_run=previous,
                              prepare_only=False, smoke_only=False)
    expected = ValueError if change_input else runner.ReproductionFailed
    with pytest.raises(expected):
        runner.execute(args, scratch=root / "runs")
    output, = (root / "runs").iterdir()
    summary = read(output / "summary.json")
    assert summary["status"] == ("failed" if change_input else "reproduction_failed")
    assert summary["source_and_data_integrity_unchanged"] is (not change_input)
    assert summary["reproduction"]["status"] == "failed"
    assert summary["reproduction"]["expected"] == "f" * 64
    assert summary["reproduction"]["actual"] == "0" * 64
    assert summary["runs"] == [] and "decision" not in summary
    assert not summary["decisions_computed"] and not (output / "decision.json").exists()
    assert not (output / "A0").exists() and not (output / "A3-17").exists()
    assert calls == [("threads", 1), ("interop", 1), ("deterministic", True)]


def test_neural_training_function_is_the_pinned_v1_implementation():
    from scripts.train_type_graph_pilot import run_model
    assert runner.run_model is run_model


def test_tiny_neural_smoke_only_when_torch_imports_in_subprocess(extension):
    root, directory, _, training, previous = extension
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CUDA_VISIBLE_DEVICES="")
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME"):
        env[key] = str(root)
    probe = subprocess.run([sys.executable, "-B", "-c", "import torch"],
                           capture_output=True, env=env, timeout=60)
    if probe.returncode:
        pytest.skip("Torch import failed in isolated subprocess (exit {}): {}".format(
            probe.returncode, probe.stderr.decode("utf-8", errors="replace")[-300:]))
    code = ("import argparse; from pathlib import Path; from scripts.train_type_pilot_v2 import execute; "
            "execute(argparse.Namespace(training_dataset=Path({!r}), dev_dataset=Path({!r}), "
            "v1_run=Path({!r}), prepare_only=False, smoke_only=True), scratch=Path({!r}))").format(
                str(training), str(directory), str(previous), str(root / "smoke"))
    result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True,
                            env=env, timeout=60)
    assert result.returncode == 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    outputs = list((root / "smoke").iterdir())
    assert len(outputs) == 1
    output = outputs[0]
    summary = read(output / "summary.json")
    assert summary["status"] == "completed" and not summary["decisions_computed"]
    assert summary["reproduction"]["status"] == "not_compared_in_smoke"
    assert summary["source_and_data_integrity_unchanged"] and not (output / "decision.json").exists()
    assert {r["arm"] for r in summary["runs"]} == {"A0", "A1", "A2", "A3", "A4", "A5"}
    for name in ("A0", "A1-17", "A2-17", "A3-17", "A4-17", "A5"):
        metrics = read(output / name / "metrics.json")
        assert set(metrics["metrics"]) == {"train", "development", "optparse"}
        assert metrics["metrics"]["development"]["source_variables"] == 2
        assert metrics["metrics"]["optparse"]["inspected"]
        predictions = read(output / name / "predictions.json")
        assert len(predictions["records"]) == 183
        assert predictions["calibrated_probabilities"] is False
        assert all(len(r["raw_scores"]) == 75 and len(r["top3"]) == 3 for r in predictions["records"])
        if name != "A0":
            assert predictions["checkpoint_reload_reproduces_scores"]
            assert metrics["checkpoint_reload_reproduces_scores"]
            assert read(output / name / "history.json")[-1]["epoch"] == 2
    for first, second in (("A1-17", "A2-17"), ("A3-17", "A4-17")):
        assert read(output / first / "metrics.json")["initial_state_sha256"] == read(
            output / second / "metrics.json")["initial_state_sha256"]
