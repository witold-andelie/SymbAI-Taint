"""Torch-free checks for the type pilot v3 data assembly, folds, stacking and decision rules."""
import contextlib
import json
import math
from pathlib import Path
import shutil

import pytest

from src.selective_analysis import type_training_v3 as v3
from src.selective_analysis.type_corpus import sha

ROOT = Path(__file__).resolve().parents[1]
VOCABULARY = ["type" + str(i) for i in range(75)]


@contextlib.contextmanager
def workspace(name):
    root = ROOT / ".test-output" / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value) + "\n").encode("ascii"))
    return sha(path)


def sample_files(function_id, class_id):
    features = {"schema": "symbai.type_graph_features.v1", "feature_width": 31, "relation_count": 60,
                "x": [[1., 0., 0., 0., 0.] + [0.] * 26 for _ in range(3)],
                "edge_index": [[0, 1], [1, 2]], "edge_type": [1, 31], "readout_nodes": [1, 2]}
    supervision = {"schema": "symbai.type_graph_supervision.v1", "labels_in_graph_features": False,
                   "targets": [{"source_variable_id": function_id + ":1", "die_offset": 1, "class_id": class_id,
                                "label": VOCABULARY[class_id], "readout_rows": [0, 1], "per_row_loss_weight": .5}]}
    return features, supervision


def make_export(root, items):
    """items: list of (function_id, project_id, split, class_id)."""
    audit_hashes, samples = {}, []
    vocab_sha = dump(root / "vocabulary.json", VOCABULARY)
    audit_hashes["vocabulary.json"] = vocab_sha
    counts = {"train": [0, 0, 0], "development": [0, 0, 0]}
    for index, (function_id, project, split, cls) in enumerate(items):
        features, supervision = sample_files(function_id, cls)
        entry = {"function_id": function_id, "project_id": project, "split": split}
        for key, value in (("features", features), ("supervision", supervision)):
            rel = "{:03d}/{}.json".format(index, key)
            entry[key] = {"path": rel, "sha256": dump(root / rel, value)}
            audit_hashes[rel] = entry[key]["sha256"]
        samples.append(entry)
        counts[split][0] += 1
        counts[split][1] += 1
        counts[split][2] += 2
    per = lambda i: {k: v[i] for k, v in counts.items()}
    dataset = {"schema": "symbai.type_v3_graph_dataset.v1", "preregistration_sha256": v3.PREREGISTRATION_SHA256,
               "relation_count": 60, "feature_width": 31, "labels_separate_from_features": True,
               "evaluation_projects_executed": False, "vocabulary": {"path": "vocabulary.json", "sha256": vocab_sha},
               "samples": samples, "admitted_source_variables": per(1), "supervised_value_rows": per(2),
               "exported_functions": per(0)}
    audit_hashes["dataset.json"] = dump(root / "dataset.json", dataset)
    dump(root / "independent-export-audit.json", {"schema": "symbai.type_v3_graph_export_audit.v1",
        "sha256": audit_hashes, "admitted_source_variables": per(1), "exported_functions": per(0),
        "evaluation_projects_executed": False, "training_performed": False})
    return vocab_sha


ITEMS = [("hashmap:a:1", "hashmap", "train", 3), ("btree:b:2", "btree", "train", 4),
         ("md4c:c:3", "md4c", "development", 3)]


def test_v3_export_admits_a_valid_fixture():
    with workspace("v3_ok") as root:
        vocab_sha = make_export(root, ITEMS)
        samples = v3.load_v3_export(root, VOCABULARY, vocab_sha, set())
        assert [s["split"] for s in samples] == ["train", "train", "development"]


@pytest.mark.parametrize("damage", ["prereg", "sealed", "reused", "overlap", "hash", "count", "vocab", "cross_split"])
def test_v3_export_rejections(damage):
    with workspace("v3_" + damage) as root:
        items = list(ITEMS)
        if damage == "sealed":
            items[0] = ("utf8_h:a:1", "utf8_h", "train", 3)
        if damage == "reused":
            items[0] = ("sds:a:1", "sds", "train", 3)
        if damage == "cross_split":
            items.append(("hashmap:d:4", "hashmap", "development", 2))
        vocab_sha = make_export(root, items)
        previous = set()
        if damage == "prereg":
            data = json.loads((root / "dataset.json").read_bytes())
            data["preregistration_sha256"] = "0" * 64
            (root / "dataset.json").write_bytes(json.dumps(data).encode("ascii"))
        if damage == "overlap":
            previous = {"btree:b:2:1"}
        if damage == "hash":
            (root / "000/features.json").write_bytes(b"{}")
        if damage == "count":
            data = json.loads((root / "dataset.json").read_bytes())
            data["admitted_source_variables"]["train"] = 99
            audit = json.loads((root / "independent-export-audit.json").read_bytes())
            audit["sha256"]["dataset.json"] = dump(root / "dataset.json", data)
            dump(root / "independent-export-audit.json", audit)
        if damage == "vocab":
            vocab_sha = "f" * 64
        with pytest.raises(ValueError):
            v3.load_v3_export(root, VOCABULARY, vocab_sha, previous)


def fake(project, n):
    return [{"project_id": project, "function_id": project + str(i),
             "supervision": {"targets": [{"source_variable_id": project + str(i)}]}} for i in range(n)]


def test_folds_hold_out_each_project_once_in_first_appearance_order():
    data = fake("a", 2) + fake("b", 1) + fake("a", 1)[:0] + fake("c", 3)
    result = v3.folds(data)
    assert [p for p, _, _ in result] == ["a", "b", "c"]
    for project, kept, held in result:
        assert all(s["project_id"] == project for s in held)
        assert all(s["project_id"] != project for s in kept)
        assert len(kept) + len(held) == len(data)


def test_depth_choice_tie_selects_two():
    assert v3.choose_depth({2: 10, 4: 10}) == 2
    assert v3.choose_depth({2: 10, 4: 11}) == 4
    assert v3.choose_depth({2: 12, 4: 11}) == 2
    with pytest.raises(ValueError):
        v3.choose_depth({2: 1})


def test_stacking_uses_log_softmax_of_mean_logits():
    row = [0.] * 75
    row[3] = 2.
    stacked = v3.stacked_vectors([[1.] * 48], [row])
    assert len(stacked[0]) == 123 and stacked[0][:48] == [1.] * 48
    probabilities = [math.exp(v) for v in stacked[0][48:]]
    assert math.isclose(sum(probabilities), 1., rel_tol=1e-12)
    assert stacked[0][48 + 3] == max(stacked[0][48:])
    with pytest.raises(ValueError):
        v3.stacked_vectors([[1.] * 47], [row])
    with pytest.raises(ValueError):
        v3.stacked_vectors([[1.] * 48], [row[:-1] + [float("nan")]])


def metric(correct, n=200):
    return {"source_variables": n, "correct_top1": correct}


def rules(dg, dgo, d5, ds, n=200):
    seeds = v3.SEEDS
    return v3.decision_rules(n, {s: metric(v, n) for s, v in zip(seeds, dg)},
                             {s: metric(v, n) for s, v in zip(seeds, dgo)}, metric(d5, n),
                             {s: metric(v, n) for s, v in zip(seeds, ds)})


def test_decision_rules_and_margin():
    d = rules([100, 100, 100], [80, 90, 90], 120, [130, 131, 129])
    assert d["m"] == 10 and d["H1"] and not d["H2"] and not d["H3"]
    assert d["outcome"] == "H1 without H2 or H3" and d["typed_arm_scores_for_scheduling"] is None
    d = rules([100, 100, 100], [100, 100, 100], 80, [91, 90, 95])
    assert d["H2"] and d["H3"] and d["outcome"] == "H2 or H3" and d["typed_arm_scores_for_scheduling"] == "DS"
    d = rules([100, 100, 89], [100, 100, 100], 80, [80, 80, 80])
    assert not d["H2"] and d["outcome"] == "Neither"
    d = rules([100, 100, 100], [100, 100, 100], 80, [80, 80, 80])
    assert d["H2"] and not d["H3"] and d["typed_arm_scores_for_scheduling"] == "DG"
    assert v3.decision_rules(30, *[{s: metric(10, 30) for s in v3.SEEDS}] * 2, metric(10, 30),
                             {s: metric(10, 30) for s in v3.SEEDS})["m"] == 3
    with pytest.raises(ValueError):
        v3.decision_rules(200, {17: metric(1)}, {s: metric(1) for s in v3.SEEDS}, metric(1),
                          {s: metric(1) for s in v3.SEEDS})


def test_minimums():
    assert v3.minimum_check({"development": 150, "expanded_training": 600}) == []
    assert len(v3.minimum_check({"development": 149, "expanded_training": 599})) == 2


def test_preregistration_hash_is_frozen():
    assert sha(ROOT / v3.PREREGISTRATION) == v3.PREREGISTRATION_SHA256


def test_accumulation_chunks_are_contiguous_bounded_and_complete():
    from scripts import train_type_pilot_v3 as runner
    samples = [{"function_id": str(i), "features": {"x": [[0.]] * n}} for i, n in enumerate([5, 3, 9, 2, 2, 12])]
    chunks = runner.chunk_samples(samples, budget=10)
    assert [[s["function_id"] for s in c] for c in chunks] == [["0", "1"], ["2"], ["3", "4"], ["5"]]
    assert [s for c in chunks for s in c] == samples
    assert all(sum(len(s["features"]["x"]) for s in c) <= 10 or len(c) == 1 for c in chunks)
