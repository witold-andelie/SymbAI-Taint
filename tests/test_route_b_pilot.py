"""Check the new information-isolation and grouped decision rules."""

import pytest

from src.selective_analysis import route_b_pilot as pilot


def matrix():
    return [
        {"group": group, "query_id": f"{group}_{scope}", "query_hash": f"{group}_{scope}",
         "arm": arm, "budget": budget, "repetition": repetition, "status": "unknown",
         "availability": "available", "initial_checkpoint": "initial",
         "structural_features": {}, "actions": [{"operation": "bounded_paths"}]}
        for group in pilot.GROUPS for scope, _ in pilot.SCOPES for arm in pilot.ARMS
        for budget in pilot.BUDGETS for repetition in range(pilot.REPETITIONS)
    ]


def labels(rows):
    return {row["query_id"]: "excluded_within_scope" for row in rows}


def test_unscored_set_does_not_expose_logits():
    candidates = [{"label": label, "rank": rank, "raw_score": score}
                  for rank, (label, score) in enumerate(
                      [("char*", 5.0), ("i32", 2.0), ("u64", -2.0)], 1)]
    record = {"function_address": 42, "locator_variable_name": "setting",
              "score_kind": "raw_logits", "candidates": candidates}
    views, reason = pilot.project_views([record], 42, "artifact", "model")
    assert reason is None
    assert not views["B"].available
    assert views["C"].labels == ("char*",)
    assert views["K"].labels == views["D"].labels
    assert views["K"].selector_features()["raw_scores"] == {}
    assert views["K"].selector_features()["weighting"] == "uniform_topk_set"
    assert views["K"].weights != views["D"].weights
    assert pilot.project_views([record, record], 42, "artifact", "model")[0].keys() == {"B"}


def test_unavailable_configurations_stay_in_the_planned_denominator():
    rows = matrix()
    for row in rows:
        if row["arm"] != "B":
            row["availability"] = "type_information_unavailable"
    result = pilot.evaluate(rows, labels(rows))
    assert result["decision"] == "insufficient_genuine_coverage"
    d = next(row for row in result["overview"] if row["arm"] == "D")
    assert d["trials"] == d["unavailable"] == d["unknown"] == 24
    with pytest.raises(ValueError, match="Incomplete"):
        pilot.evaluate(rows[:-1], labels(rows))


def test_gain_gate_requires_multiple_groups_and_an_operation_change():
    rows = matrix()
    for row in rows:
        if row["arm"] == "D" and row["group"] in pilot.GROUPS[:2]:
            row["status"] = "excluded_within_scope"
    assert pilot.evaluate(rows, labels(rows))["decision"] == "no_stable_increment_on_this_panel"
    for row in rows:
        if row["arm"] == "D" and row["group"] in pilot.GROUPS[:2]:
            row["actions"] = [{"operation": "expanded_paths"}]
    report = pilot.evaluate(rows, labels(rows))
    assert report["arms_passing_information_gate"] == ["D"]
    assert report["decision"] == "measure_paired_end_to_end_cost_next"
    rows[0]["status"] = "violation"
    assert pilot.evaluate(rows, labels(rows))["decision"] == "review_property_correctness"


def test_control_checks_reject_mismatched_structural_inputs():
    rows = matrix()
    next(row for row in rows if row["arm"] == "C")["initial_checkpoint"] = "different"
    with pytest.raises(ValueError, match="Paired inputs"):
        pilot.evaluate(rows, labels(rows))
