"""A small shared routing diagnostic; no property operation is executed here."""

from dataclasses import asdict
import math
import re

from .contracts import fingerprint
from .location_correspondence import _StaticLoads, UnavailableCorrespondence
from .elf_guard import UnsupportedELFLayout
from .types import TypeView

REVISION = "structural_type_routing_sensitivity_v13"
OPERATIONS = ("frame_bounds", "expanded_paths")
WEIGHTS = (0.0, 0.25, 0.5, 1.0, 2.0)
PRIMARY_WEIGHT = 0.5
POLICY = {"revision": REVISION, "operations": list(OPERATIONS), "expanded_score": 1.0,
          "masked_frame_score": 1.25, "supported_frame_score": 0.75,
          "unsupported_frame_score": 0.0, "tie_break": "operation_id",
          "type_signal": "max_distinct_occurrence_min_pointer_integer_support",
          "label_classifier": "disjoint_tygr_scalar_pointer_v13", "weights": list(WEIGHTS),
          "primary_weight": PRIMARY_WEIGHT}
FEATURE_FIELDS = {"schema", "query_hash", "binary_sha256", "available", "reason",
                  "instruction_count", "address_load_count", "has_immediate_mask"}


def static_routing_features(query):
    """Read binary syntax only; candidates, labels and prior proof are not inputs."""
    features = {"schema": "symbai.routing_features.v1", "query_hash": query.contract_hash,
                "binary_sha256": query.binary_sha256, "available": False, "reason": None,
                "instruction_count": 0, "address_load_count": None, "has_immediate_mask": None}
    walker = None
    try:
        walker = _StaticLoads(query)
        occurrences = walker.walk()
        mask = False
        for step in walker.trace:
            insn = walker.decode(step["address"])
            if (insn.mnemonic == "and" and len(insn.operands) == 2
                    and insn.operands[1].type == walker.x86.X86_OP_IMM):
                mask = True
        features.update(available=True, address_load_count=len(occurrences), has_immediate_mask=mask)
    except (UnavailableCorrespondence, UnsupportedELFLayout) as exc:
        features["reason"] = str(exc)
    if walker is not None:
        features["instruction_count"] = len(walker.trace)
    return features


def validate_features(features):
    if (not isinstance(features, dict) or set(features) != FEATURE_FIELDS
            or features["schema"] != "symbai.routing_features.v1" or type(features["available"]) is not bool
            or type(features["instruction_count"]) is not int or features["instruction_count"] < 0):
        raise ValueError("Invalid type-blind routing features")
    if features["available"]:
        if (type(features["has_immediate_mask"]) is not bool
                or type(features["address_load_count"]) is not int or features["address_load_count"] < 1
                or features["reason"] is not None):
            raise ValueError("Invalid supported-frame routing features")
    elif features["has_immediate_mask"] is not None or features["address_load_count"] is not None:
        raise ValueError("Unavailable syntax must not invent structural features")


def label_kind(label):
    """Disjoint syntactic label families, never semantic type constraints."""
    if not isinstance(label, str) or not label:
        raise ValueError("Invalid candidate label")
    label = label.lower().strip()
    if not label:
        raise ValueError("Invalid candidate label")
    if "*" in label:
        return "pointer"
    if label in ("bool", "char", "int", "size_t") or re.fullmatch(r"[iu](1|8|16|32|64|128)", label):
        return "integer"
    return "other"


def contributor_support(views, group):
    if group not in ("B", "C", "D") or not isinstance(views, dict):
        raise ValueError("Unknown routing group or view container")
    if group == "B":
        if views:
            raise ValueError("B cannot receive type views")
        return 0.0, {}
    if not views:
        raise ValueError("C/D type views are unavailable")
    supports = {}
    for occurrence_id, view in sorted(views.items()):
        if not isinstance(occurrence_id, str) or not occurrence_id or not isinstance(view, TypeView) or not view.available:
            raise ValueError("Invalid per-occurrence type view")
        kinds = [label_kind(label) for label in view.labels]
        if group == "C":
            if len(kinds) != 1 or view.weights or view.raw_scores:
                raise ValueError("C requires Top-1 labels without scores")
            weights = (1.0,)
        else:
            if (len(kinds) < 2 or len(set(view.labels)) != len(kinds)
                    or len(view.weights) != len(kinds) or len(view.raw_scores) != len(kinds)
                    or not all(type(w) in (float, int) and math.isfinite(w) and 0 <= w <= 1 for w in view.weights)
                    or not math.isclose(sum(view.weights), 1.0, abs_tol=1e-12)
                    or not all(type(s) in (float, int) and math.isfinite(s) for s in view.raw_scores)
                    or list(view.raw_scores) != sorted(view.raw_scores, reverse=True)):
                raise ValueError("D requires actual finite candidate scores and conditional weights")
            exp_scores = [math.exp(s - max(view.raw_scores)) for s in view.raw_scores]
            total = sum(exp_scores)
            if not all(math.isclose(weight, score / total, rel_tol=1e-12, abs_tol=1e-12)
                       for weight, score in zip(view.weights, exp_scores)):
                raise ValueError("D weights differ from conditional softmax logits")
            weights = view.weights
        supports[occurrence_id] = {kind: sum(w for k, w in zip(kinds, weights) if k == kind)
                                   for kind in ("pointer", "integer")}
    mixture = max((min(left["pointer"], right["integer"])
                   for i, left in supports.items() for j, right in supports.items() if i != j), default=0.0)
    return mixture, supports


def validate_group_weight(group, type_weight):
    if group not in ("B", "C", "D"):
        raise ValueError("Unknown routing group")
    if type(type_weight) not in (float, int) or not math.isfinite(type_weight) or type_weight < 0:
        raise ValueError("Type weight must be finite and nonnegative")


def select_order(features, group, views, type_weight=PRIMARY_WEIGHT):
    validate_features(features)
    validate_group_weight(group, type_weight)
    mixture, support = contributor_support(views, group)
    structural = (POLICY["masked_frame_score"] if features["has_immediate_mask"] else
                  POLICY["supported_frame_score"]) if features["available"] else POLICY["unsupported_frame_score"]
    frame_score = structural + type_weight * mixture
    scores = {"frame_bounds": frame_score, "expanded_paths": POLICY["expanded_score"]}
    if features["available"] and features["has_immediate_mask"]:
        geometry = {"basis": "structurally_frame_first_for_all_nonnegative_weights", "strict_switch_threshold": None}
    elif features["available"] and mixture == 0:
        geometry = {"basis": "zero_signal_full_first_for_all_finite_nonnegative_weights", "strict_switch_threshold": None}
    else:
        geometry = {"basis": "frame_first_only_above_threshold",
                    "strict_switch_threshold": ((1.0 - structural) / mixture if mixture else None)}
    return {"order": sorted(OPERATIONS, key=lambda op: (-scores[op], op)), "scores": scores,
            "frame_structural_score": structural, "type_weight": float(type_weight),
            "type_signal": mixture, "per_occurrence_support": support, "score_geometry": geometry,
            "features_hash": fingerprint(features), "policy_hash": fingerprint(POLICY),
            "policy_and_weight_hash": fingerprint({"policy": POLICY, "type_weight": float(type_weight)}),
            "operation_catalog_hash": fingerprint(list(OPERATIONS))}


def routing_record(features, group, views, weight, error=None):
    validate_features(features)
    validate_group_weight(group, weight)
    if group == "B" and views:
        raise ValueError("B cannot receive type views")
    base = {"group": group, "type_weight": weight, "primary_weight": weight == PRIMARY_WEIGHT,
            "policy_hash": fingerprint(POLICY), "features_hash": fingerprint(features),
            "policy_and_weight_hash": fingerprint({"policy": POLICY, "type_weight": float(weight)}),
            "operation_catalog_hash": fingerprint(list(OPERATIONS)), "status": "unavailable",
            "reason": error, "order": None}
    if error is None:
        base.update(select_order(features, group, views, weight), status="available", reason=None,
                    view_fingerprint=fingerprint({key: asdict(view) for key, view in sorted(views.items())}))
    return base


def summarize(cases):
    """Complete known-input denominators; no outcome labels or cost replay."""
    if len(cases) != 3 or len({c["case_id"] for c in cases}) != 3:
        raise ValueError("The routing gate requires all three integration cases")
    comparisons = []
    for case in cases:
        rows = case["routing_records"]
        expected = {(group, weight) for group in ("B", "C", "D") for weight in WEIGHTS}
        if len(rows) != len(expected) or {(r["group"], r["type_weight"]) for r in rows} != expected:
            raise ValueError("Incomplete routing group/weight denominator")
        if (len({r["features_hash"] for r in rows}) != 1
                or {r["policy_hash"] for r in rows} != {fingerprint(POLICY)}
                or {r["operation_catalog_hash"] for r in rows} != {fingerprint(list(OPERATIONS))}):
            raise ValueError("Changed features, policy or operations across routing grid")
        for row in rows:
            if (row["status"] not in ("available", "unavailable")
                    or (row["status"] == "available" and (not isinstance(row["order"], list)
                        or len(row["order"]) != len(OPERATIONS) or set(row["order"]) != set(OPERATIONS)))
                    or (row["status"] == "unavailable" and row["order"] is not None)):
                raise ValueError("Invalid routing availability or complete order")
            if row["policy_and_weight_hash"] != fingerprint({"policy": POLICY, "type_weight": float(row["type_weight"])}):
                raise ValueError("Routing policy/weight identity differs")
        for weight in WEIGHTS:
            selected = {r["group"]: r for r in rows if r["type_weight"] == weight}
            if len({r["features_hash"] for r in selected.values()}) != 1 or len({r["policy_and_weight_hash"] for r in selected.values()}) != 1:
                raise ValueError("B/C/D share neither features nor policy")
            b = selected["B"]
            for group in ("C", "D"):
                available = b["status"] == selected[group]["status"] == "available"
                comparisons.append({"case_id": case["case_id"], "group": group, "type_weight": weight,
                                    "available_pair": available,
                                    "order_changed_from_B": b["order"] != selected[group]["order"] if available else None})
    return {"schema": "symbai.routing_comparison.v1", "unique_integration_cases": 3,
            "routing_rows": sum(len(c["routing_records"]) for c in cases),
            "available_comparisons": sum(c["available_pair"] for c in comparisons),
            "unavailable_comparisons": sum(not c["available_pair"] for c in comparisons),
            "changed_orders": sum(c["order_changed_from_B"] is True for c in comparisons),
            "primary_changed_orders": sum(c["order_changed_from_B"] is True and c["type_weight"] == PRIMARY_WEIGHT for c in comparisons),
            "comparisons": comparisons, "property_operations_executed": False,
            "neural_benefit_measured": False, "held_out_evaluation": False,
            "interpretation": "Routing sensitivity on three known integration inputs. Agreement or changes concern this heuristic only; no property correctness or end-to-end gain was measured."}
