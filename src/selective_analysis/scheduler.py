"""One deterministic B/C/D policy; neural information affects ranking only."""

from .contracts import OPERATIONS


POLICY = {"id": "deterministic-pilot-v2", "type_weight": 0.5,
          "cost_floor_seconds": 0.001, "tie_break": "operation_id",
          "candidate_diversity_target": "definitions", "operation_revision": "exact_prefix_v2"}


def select_action(checkpoint, variant, type_view, cost_estimates=None, structural_features=None):
    if variant not in ("A", "B", "C", "D"):
        raise ValueError("Unknown experiment variant")
    if variant in ("A", "B") and type_view.available:
        raise ValueError("A/B must not receive a type feature view")
    if variant == "C" and (len(type_view.labels) != 1 or type_view.weights or type_view.raw_scores):
        raise ValueError("C must receive exactly one label without scores")
    if variant == "D" and (len(type_view.labels) < 2 or len(type_view.weights) != len(type_view.labels)):
        raise ValueError("D must receive multiple candidates and actual score weights")
    eligible = [op for op in OPERATIONS if op.operation_id not in checkpoint.attempted]
    if not eligible:
        return None, []
    if variant == "A":
        return eligible[0], []
    scores = []
    features = structural_features or {}
    type_features = type_view.selector_features()
    for op in eligible:
        structural = op.structural_utility
        if op.operation_id == "bounded_paths":
            position = features.get("write_index_in_entry_block")
            if position is not None and position >= op.max_steps:
                structural *= 0.15
        if op.operation_id == "definitions" and features.get("entry_has_conditional_branch"):
            structural *= 1.5
        if op.operation_id == "definitions" and "dependencies_observed" in checkpoint.facts:
            structural = 0.0
        support = type_view.role_support(op.type_role)
        disagreement = type_features["candidate_disagreement"]
        # Missing scores in B/C do not imply certainty; no diversity bonus is available.
        information_utility = ((disagreement or 0.0)
                               if op.operation_id == POLICY["candidate_diversity_target"] else 0.0)
        estimate = (cost_estimates or {}).get(op.operation_id, op.estimated_seconds)
        if estimate <= 0:
            raise ValueError("Operation cost estimates must be positive")
        score = (structural + POLICY["type_weight"] * (support + information_utility)) / max(estimate, POLICY["cost_floor_seconds"])
        scores.append({"operation_id": op.operation_id, "structural_utility": structural,
                       "type_support": support, "candidate_disagreement": disagreement,
                       "information_utility": information_utility,
                       "estimated_seconds": estimate, "score": score})
    selected = min(scores, key=lambda s: (-s["score"], s["operation_id"]))
    return next(op for op in eligible if op.operation_id == selected["operation_id"]), scores
