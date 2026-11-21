"""Source-variable evaluation and admission must not turn value rows into samples."""
from copy import deepcopy
import json
import math
from pathlib import Path
import sys

import pytest

from src.selective_analysis.type_training import (frequency_scores, load_reviewed_dataset,
    summarize_scores, validate_sample, safe_file)


def sample():
    features = {"schema": "symbai.type_graph_features.v1", "feature_width": 31,
        "relation_count": 60, "x": [[1.] + [0.] * 30 for _ in range(3)],
        "edge_index": [[0, 1], [1, 2]], "edge_type": [50, 59], "readout_nodes": [1, 2]}
    supervision = {"labels_in_graph_features": False, "targets": [{"class_id": 12,
        "label": "type12", "readout_rows": [0, 1], "per_row_loss_weight": .5}]}
    return features, supervision, ["type" + str(i) for i in range(75)]


def test_high_relation_ids_and_unit_variable_weights_are_admitted():
    f, s, v = sample()
    before = deepcopy((f, s))
    validate_sample(f, s, v)
    assert before == (f, s)


@pytest.mark.parametrize("damage", ["relation_negative", "relation_60", "gold_in_input", "row_weight", "duplicate_rows", "out_of_bounds", "nonfinite", "wrong_class"])
def test_invalid_graph_or_target_is_not_silently_trained(damage):
    f, s, v = sample()
    if damage == "relation_negative":
        f["edge_type"][0] = -1
    elif damage == "relation_60":
        f["edge_type"][0] = 60
    elif damage == "gold_in_input":
        f["targets"] = s["targets"]
    elif damage == "row_weight":
        s["targets"][0]["per_row_loss_weight"] = 1.
    elif damage == "duplicate_rows":
        s["targets"][0]["readout_rows"] = [0, 0]
    elif damage == "out_of_bounds":
        f["edge_index"][0][0] = 3
    elif damage == "nonfinite":
        f["x"][0][0] = float("nan")
    else:
        s["targets"][0]["class_id"] = 13
    with pytest.raises(ValueError):
        validate_sample(f, s, v)


def test_frequency_prior_uses_training_labels_only():
    def row(split, classes):
        return {"split": split, "supervision": {"targets": [{"class_id": c} for c in classes]}}
    scores, seen = frequency_scores([row("train", [1, 1, 2]), row("development", [7] * 100)])
    assert seen == {1, 2} and scores[1] == math.log(3) and scores[7] == math.log(1)


def test_metrics_count_source_variables_and_retain_unseen_classes():
    first, second = [-1000.] * 75, [-1000.] * 75
    first[1], second[1], second[2] = 1000., 1000., 999.
    result = summarize_scores([first, second], [1, 2], {1})
    assert result["source_variables"] == 2 and result["correct_top1"] == 1
    assert result["accuracy"] == .5 and result["top3_accuracy"] == 1.
    assert result["seen_class_variables"] == result["unseen_class_variables"] == 1
    assert result["unseen_class_correct_top1"] == 0 and math.isfinite(result["mean_nll"])


def test_tie_breaking_is_stable_and_invalid_scores_are_rejected():
    result = summarize_scores([[0.] * 75], [0], {0})
    assert result["accuracy"] == 1 and result["mean_nll"] == pytest.approx(math.log(75))
    with pytest.raises(ValueError):
        summarize_scores([[float("nan")] * 75], [1], {1})
    with pytest.raises(ValueError):
        summarize_scores([[0.] * 75], [-1], {1})


def test_artifact_path_cannot_escape_dataset_directory():
    with pytest.raises(ValueError):
        safe_file(Path(__file__).parent, "../../outside-dataset.json")


def test_reviewed_real_dataset_admission_preserves_sealed_source_files():
    directory = Path(__file__).resolve().parents[2] / ".scratch/selective_analysis/route-b-type-graphs-20261119T225215150614Z"
    if not directory.is_dir():
        pytest.skip("Optional reviewed local corpus absent")
    before = (directory / "dataset.json").read_bytes()
    samples, vocabulary, admission = load_reviewed_dataset(directory)
    assert len(samples) == 41 and len(vocabulary) == 75
    assert admission["project_splits"] == {"inih": "train", "rxi_map": "train", "jsmn": "train", "optparse": "development"}
    assert sum(len(s["supervision"]["targets"]) for s in samples) == 181
    assert before == (directory / "dataset.json").read_bytes()
    assert json.loads(before)["training_allowed"] is False


@pytest.mark.skipif(sys.platform == "win32", reason="Neural check uses the existing WSL runtime; Windows Torch DLL initialization fails in this workspace.")
def test_runtime_relation_flow_and_variable_pooling_when_torch_is_available():
    try:
        import torch
        import torch_geometric  # noqa: F401
    except (ImportError, OSError) as error:
        pytest.skip("Torch runtime unavailable: " + str(error))
    from scripts.train_type_graph_pilot import runtime_contract
    from src.selective_analysis.type_training import tensor_batch, pool_variables
    assert runtime_contract(torch)["relation_59_gradient_verified"]
    f, s, _ = sample()
    s["targets"][0].update(source_variable_id="variable", die_offset=1)
    batch = tensor_batch([{"features": f, "supervision": s, "function_id": "function", "project_id": "project"}])
    assert len(batch["arguments"]) == 4
    row_logits = torch.stack([torch.zeros(75), torch.ones(75)]).requires_grad_()
    pooled = pool_variables(row_logits, batch)
    assert pooled.shape == (1, 75) and torch.equal(pooled, torch.full((1, 75), .5))
    pooled.sum().backward()
    assert torch.equal(row_logits.grad, torch.full((2, 75), .5))
