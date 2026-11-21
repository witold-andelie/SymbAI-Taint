"""Relation contracts and synthetic evidence interpretation without model execution."""
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.audit_relation_schema import interpret_toy, relation_table
from src.selective_analysis.checkpoint_metadata import inspect_frozen_checkpoint


def metadata():
    return {"preproc_config": {"all_ops": ["op_" + str(i) for i in range(29)],
        "num_all_ops": 30, "num_edge_ops": 60},
        "relation_layers": [{"parameter_relation_capacity": 44} for _ in range(8)]}


def test_symmetric_declared_domain_is_not_a_symmetric_saved_capacity():
    saved = metadata()
    original = deepcopy(saved)
    result = relation_table(saved, saved["preproc_config"]["all_ops"], {})
    assert len(result["relations"]) == 60
    assert result["outside_saved_domain_ids"] == list(range(44, 60))
    assert all(r["inside_all_saved_layers"] for r in result["relations"] if r["direction"] == "forward")
    assert result["relations"][50]["operation"] == "op_20"
    assert result["training_relation_mapping_proven"] is result["remapping_proposed"] is False
    assert saved == original


@pytest.mark.parametrize("damage", ["vocabulary", "inverse_offset", "layer_capacity", "reduction"])
def test_contract_disagreement_fails_instead_of_synthesizing_a_mapping(damage):
    saved = metadata()
    current = list(saved["preproc_config"]["all_ops"])
    mapping = {}
    if damage == "vocabulary":
        current.reverse()
    elif damage == "inverse_offset":
        saved["preproc_config"]["num_all_ops"] = 22
    elif damage == "layer_capacity":
        saved["relation_layers"][0]["parameter_relation_capacity"] = 60
    else:
        mapping["unknown_operation"] = "not_in_vocabulary"
    with pytest.raises(ValueError):
        relation_table(saved, current, mapping)


def observations():
    names = ("empty", "valid_0", "valid_43", "valid_pair", "negative", "id_44", "id_50", "id_55", "id_59", "valid_plus_50", "valid_plus_55")
    zero, valid, both = [[0.0, 0.0], [0.0, 0.0]], [[0.0, 0.0], [3.0, 3.0]], [[7.0, 7.0], [3.0, 3.0]]
    return [{"name": name, "status": "returned", "output": deepcopy(both if name == "valid_pair" else valid if name.startswith("valid") else zero)} for name in names]


def test_zero_messages_and_mixed_edge_identity_do_not_become_training_proof():
    rows = observations()
    rows[4] = {"name": "negative", "status": "raised", "error": {"type": "IndexError"}}
    result = interpret_toy(rows)
    assert result["single_edge_findings"][0]["behavior"] == "raised"
    assert all(r["behavior"] == "zero_single_edge_message" for r in result["single_edge_findings"][1:])
    assert all(result["mixed_output_equals_valid_only"].values())
    assert "historical training" in result["scope"]


def test_nonzero_unknown_edge_and_changed_mixed_output_remain_visible():
    rows = observations()
    rows[6]["output"] = [[7.0, 7.0], [0.0, 0.0]]
    rows[-2]["output"] = [[7.0, 7.0], [3.0, 3.0]]
    result = interpret_toy(rows)
    assert result["single_edge_findings"][2]["behavior"] == "nonzero_single_edge_message"
    assert result["mixed_output_equals_valid_only"]["valid_plus_50"] is False


@pytest.mark.parametrize("damage", ["no_signal", "incomplete", "positive_raised"])
def test_missing_or_uninformative_controls_block_interpretation(damage):
    rows = observations()
    if damage == "no_signal":
        rows[1]["output"] = rows[0]["output"]
    elif damage == "incomplete":
        rows.pop()
    else:
        rows[2]["status"] = "raised"
    with pytest.raises(ValueError):
        interpret_toy(rows)


MODEL = Path(__file__).resolve().parents[1] / "tygr_original/model/MODEL_base/x64.O0.base.model"


@pytest.mark.skipif(not MODEL.is_file(), reason="Optional frozen local model is absent")
def test_real_saved_basis_shapes_support_reported_capacity_without_importing_torch():
    saved = inspect_frozen_checkpoint(MODEL)
    result = relation_table(saved, saved["preproc_config"]["all_ops"], {"__eq__": "Eq"})
    assert result["relations"][50]["operation"] == "If"
    assert result["relations"][55]["operation"] == "Eq"
    assert all(r["parameter_shapes"]["comp"] == [44, 10] for r in saved["relation_layers"])
