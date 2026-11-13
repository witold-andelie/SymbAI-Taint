"""Offline, descriptive evaluation of fixed operation probes; never a runtime selector.

Only the existing twelve generated mechanisms belong to this measurement panel.
Compiled-query mapping proofs are a separate post-hoc audit, not extra trials.
"""

from collections import Counter, defaultdict
from copy import deepcopy
import math
from statistics import median

from .contracts import Checkpoint


PROBES = (
    "bounded_paths", "expanded_paths", "definitions_then_expanded",
    "direct_prefix_then_expanded", "local_bounds",
)
REPETITIONS = (0, 1, 2)
PANEL = "primary_existing_12_mechanisms"
QUERY_IDS = frozenset(f"m{number:02d}" for number in range(1, 13))
DECISIVE = frozenset(("violation", "excluded_within_scope"))
COST_FIELDS = ("setup", "preparation", "execution", "validation", "recording")
WORK_FIELDS = (
    "preparation_steps", "execution_steps", "validation_steps",
    "total_executed_steps", "reused_prefix_steps",
)
UNKNOWN_CATEGORIES = (
    "unsupported", "insufficient_precision", "work_limit", "deadline_or_failure",
)


def _mapping(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _text(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite nonnegative number")
    try:
        valid = math.isfinite(value) and value >= 0
    except (OverflowError, TypeError):
        valid = False
    if not valid:
        raise ValueError(f"{name} must be a finite nonnegative number")


def _count(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _reject_runtime_labels(value):
    """Gold may be joined here, but must not be embedded in a probe record."""
    if isinstance(value, dict):
        if set(value) & {"expected", "expected_status", "gold", "gold_label", "gold_labels"}:
            raise ValueError("Gold labels belong only in the offline gold input")
        for child in value.values():
            _reject_runtime_labels(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            _reject_runtime_labels(child)


def _validate_features(features):
    _mapping(features, "initial_features")
    if "available" in features and not isinstance(features["available"], bool):
        raise ValueError("initial_features.available must be boolean")
    forbidden = {
        "types", "type_features", "type_identity", "type_artifact", "neural_types",
        "predictions", "candidates", "logits", "raw_scores", "input_proof",
        "input_proofs", "proof_artifact", "gold", "expected",
    }
    def inspect(value):
        if isinstance(value, dict):
            if set(value) & forbidden:
                raise ValueError("initial_features must be pre-action and type-blind")
            for child in value.values():
                inspect(child)
        elif isinstance(value, (tuple, list)):
            for child in value:
                inspect(child)
    inspect(features)


def _validate_row(row, labels):
    _mapping(row, "trial")
    _reject_runtime_labels(row)
    if row.get("schema") != "symbai.operation_effect_trial.v1":
        raise ValueError("Unrecognized operation-effect trial schema")
    query_id = _text(row.get("query_id"), "query_id")
    identity = (query_id, _text(row.get("binary_sha256"), "binary_sha256"))
    if identity not in labels:
        raise ValueError("Unmatched trial identity")
    query_hash = _text(row.get("query_hash"), "query_hash")
    if row.get("checkpoint_id") != Checkpoint(query_hash).checkpoint_id:
        raise ValueError("Every probe must start at the canonical fresh-entry checkpoint")
    if type(row.get("repetition")) is not int or row["repetition"] not in REPETITIONS:
        raise ValueError("repetition must be 0, 1, or 2")
    if row.get("probe_id") not in PROBES:
        raise ValueError("Unrecognized probe_id")
    _text(row.get("availability"), "availability")
    _validate_features(row.get("initial_features"))
    result = _mapping(row.get("result"), "result")
    status = result.get("status")
    if status not in DECISIVE | {"unknown"}:
        raise ValueError("Unrecognized result status")
    if "reason" in result and not isinstance(result["reason"], str):
        raise ValueError("result.reason must be a string")
    costs = _mapping(row.get("costs_seconds"), "costs_seconds")
    for field in COST_FIELDS:
        _number(costs.get(field), f"costs_seconds.{field}")
    # Extra diagnostic timings must satisfy the same accounting domain.
    for field, value in costs.items():
        _number(value, f"costs_seconds.{field}")
    _number(row.get("probe_elapsed_seconds"), "probe_elapsed_seconds")
    if "cost_measurement_complete" in row and not isinstance(row["cost_measurement_complete"], bool):
        raise ValueError("cost_measurement_complete must be boolean")
    if row["availability"] in ("not_completed", "not_started") and row.get("cost_measurement_complete", True):
        raise ValueError("Unfinished probes must mark cost measurement incomplete")
    effects = _mapping(row.get("effects"), "effects")
    progress = effects.get("query_decision_progress")
    if not isinstance(progress, bool):
        raise ValueError("query_decision_progress must be boolean")
    if progress != (status in DECISIVE):
        raise ValueError("query_decision_progress must match a validated decisive result")
    _mapping(effects.get("planning_artifacts"), "planning_artifacts")
    work = _mapping(effects.get("prefix_work"), "prefix_work")
    for field in WORK_FIELDS:
        _count(work.get(field), f"prefix_work.{field}")
    if "measurement_complete" in work and not isinstance(work["measurement_complete"], bool):
        raise ValueError("prefix_work.measurement_complete must be boolean")
    if work["total_executed_steps"] != sum(work[field] for field in WORK_FIELDS[:3]):
        raise ValueError("total_executed_steps must sum preparation, execution, and validation")
    if row["probe_id"] == "local_bounds":
        if any(work[field] for field in WORK_FIELDS):
            raise ValueError("local_bounds abstract work cannot be symbolic prefix work")
        for field in ("abstract_instruction_steps", "validation_abstract_instruction_steps"):
            _count(effects.get(field), f"effects.{field}")
    if status in DECISIVE:
        validation = result.get("validation")
        expected_validation = (
            "concrete_input_modeled_reexecution" if status == "violation" else
            "fresh_byte_decoded_abstract_recheck" if row["probe_id"] == "local_bounds" else
            "fresh_state_complete_scope_recheck"
        )
        if validation != expected_validation:
            raise ValueError("Decisive outcome requires recognized fresh validation")
        if row["probe_id"] != "local_bounds" and (
            type(result.get("validation_reused_prefix_steps")) is not int
            or result["validation_reused_prefix_steps"] != 0
        ):
            raise ValueError("Decisive symbolic validation must start fresh without prefix reuse")
    return identity


def _unknown_category(row):
    result = row["result"]
    reason = " ".join((result.get("reason", ""), str(result.get("basis", "")),
                       str(result.get("unsupported", "")),
                       row["availability"])).lower()
    if any(word in reason for word in (
        "deadline", "timeout", "timed_out", "time out", "budget", "expired",
    )):
        return "deadline_or_failure"
    if any(word in reason for word in (
        "work_limit", "step_limit", "step limit", "depth_limit", "depth limit", "state_limit",
        "instruction_limit", "instruction limit", "max_steps", "work cap", "snapshot_limit",
    )):
        return "work_limit"
    if any(word in reason for word in (
        "unsupported", "unmodeled", "unmodelled", "symbolic_control_flow", "missing_ir_block",
        "unhandled", "outside_subset", "non_target_memory_write", "non64_", "segmented_",
        "relocation_coverage_unavailable", "instruction_decode_failed",
    )):
        return "unsupported"
    if any(word in reason for word in (
        "exception", "failure", "failed", "error", "preparation_incomplete", "worker_terminated",
    )):
        return "deadline_or_failure"
    return "insufficient_precision"


def _stats(values):
    values = list(values)
    return {"min": min(values), "max": max(values), "median": median(values)} if values else None


def _work_complete(row):
    return row["effects"]["prefix_work"].get("measurement_complete", True)


def _cost_complete(row):
    return row.get("cost_measurement_complete", True)


def _trial_counts(rows, expected):
    statuses = [row["result"]["status"] for row in rows]
    correct = sum(status == expected for status in statuses)
    unknown = statuses.count("unknown")
    return {"total": len(rows), "resolved": len(rows) - unknown,
            "correct": correct, "wrong": len(rows) - unknown - correct, "unknown": unknown}


def _query_summary(rows, expected):
    statuses = [row["result"]["status"] for row in rows]
    stable = len(set(statuses)) == 1
    complete = [row for row in rows if _work_complete(row)]
    observed_costs = [row for row in rows if _cost_complete(row)]
    abstract = rows[0]["probe_id"] == "local_bounds"
    return {
        "statuses": statuses,
        "stable_status": statuses[0] if stable else None,
        "stable_resolved": stable and statuses[0] in DECISIVE,
        "stable_correct": all(status == expected for status in statuses),
        "stable_wrong": stable and statuses[0] in DECISIVE and statuses[0] != expected,
        "stable_unknown": all(status == "unknown" for status in statuses),
        "trial_counts": _trial_counts(rows, expected),
        "probe_elapsed_seconds": _stats(row["probe_elapsed_seconds"] for row in observed_costs),
        "cost_observation_count": len(observed_costs),
        "costs_seconds": {field: _stats(row["costs_seconds"][field] for row in observed_costs)
                          for field in COST_FIELDS},
        "prefix_work": {field: _stats(row["effects"]["prefix_work"][field] for row in complete)
                        for field in WORK_FIELDS},
        "work_measurements_complete": len(complete),
        "abstract_work": {field: _stats(row["effects"][field] for row in complete)
                          for field in ("abstract_instruction_steps", "validation_abstract_instruction_steps")}
                         if abstract else None,
        "unknown_categories": dict(Counter(_unknown_category(row) for row in rows
                                           if row["result"]["status"] == "unknown")),
    }


def _paired_work(query_id, left, right):
    comparable = _work_complete(left) and _work_complete(right)
    comparable_costs = _cost_complete(left) and _cost_complete(right)
    left_work = left["effects"]["prefix_work"]
    right_work = right["effects"]["prefix_work"]
    return {
        "query_id": query_id, "repetition": left["repetition"],
        "left_status": left["result"]["status"], "expanded_status": right["result"]["status"],
        "work_measurement_complete": comparable,
        "left_prefix_work": {field: left_work[field] for field in WORK_FIELDS} if comparable else None,
        "expanded_prefix_work": {field: right_work[field] for field in WORK_FIELDS} if comparable else None,
        "total_executed_steps_delta": left_work["total_executed_steps"] - right_work["total_executed_steps"]
                                      if comparable else None,
        "cost_measurement_complete": comparable_costs,
        "left_probe_elapsed_seconds": left["probe_elapsed_seconds"] if _cost_complete(left) else None,
        "expanded_probe_elapsed_seconds": right["probe_elapsed_seconds"] if _cost_complete(right) else None,
        "probe_elapsed_seconds_delta": left["probe_elapsed_seconds"] - right["probe_elapsed_seconds"]
                                       if comparable_costs else None,
    }


def evaluate_effects(rows, gold):
    """Join labels offline and return measured operation effects, never policy benefit.

    Unique-query counts mean *any* repetition; these categories may overlap.
    Stable-query counts require all three repetitions to have the same status.
    The mandatory denominator is 12 queries x 5 fixed probes x 3 repetitions.
    """
    _mapping(gold, "gold")
    if gold.get("schema") != "symbai.gold.v1" or gold.get("panel") != PANEL:
        raise ValueError(f"Gold must identify the separate {PANEL} panel")
    gold_rows = gold.get("labels")
    if not isinstance(gold_rows, list) or len(gold_rows) != 12:
        raise ValueError("The primary panel requires exactly twelve existing mechanism labels")
    labels = {}
    for label in gold_rows:
        _mapping(label, "gold label")
        identity = (_text(label.get("query_id"), "gold query_id"),
                    _text(label.get("binary_sha256"), "gold binary_sha256"))
        if identity in labels:
            raise ValueError("Duplicate gold-label identity")
        if label.get("expected") not in DECISIVE:
            raise ValueError("Gold expected must be a decisive property status")
        labels[identity] = label["expected"]
    if {identity[0] for identity in labels} != QUERY_IDS:
        raise ValueError("The primary panel must contain only m01 through m12")
    try:
        rows = list(rows)
    except TypeError as exc:
        raise ValueError("rows must be an iterable of trials") from exc
    groups = defaultdict(list)
    seen = set()
    query_invariants = {}
    available_features = {}
    missing_features = Counter()
    for row in rows:
        identity = _validate_row(row, labels)
        key = (identity, row["probe_id"], row["repetition"])
        if key in seen:
            raise ValueError("Duplicate query/probe/repetition trial")
        seen.add(key)
        invariant = (row["query_hash"], row["checkpoint_id"])
        if identity in query_invariants and query_invariants[identity] != invariant:
            raise ValueError("Query hash and fresh checkpoint must match across probes and repetitions")
        query_invariants[identity] = invariant
        features = row["initial_features"]
        if features.get("available", True):
            if identity in available_features and available_features[identity] != features:
                raise ValueError("Available initial features must match across probes and repetitions")
            available_features[identity] = deepcopy(features)
        else:
            missing_features[identity] += 1
        groups[(identity, row["probe_id"])].append(row)
    required = {(identity, probe, repetition) for identity in labels
                for probe in PROBES for repetition in REPETITIONS}
    if seen != required:
        raise ValueError("Missing fixed query/probe/repetition coverage; failures remain in the denominator")
    for group in groups.values():
        group.sort(key=lambda row: row["repetition"])

    queries = []
    wrong_trials = []
    disagreements = []
    for identity, expected in sorted(labels.items()):
        query_id, binary_sha256 = identity
        summaries = {probe: _query_summary(groups[(identity, probe)], expected) for probe in PROBES}
        decisive_statuses = set()
        for probe in PROBES:
            for row in groups[(identity, probe)]:
                status = row["result"]["status"]
                if status in DECISIVE:
                    decisive_statuses.add(status)
                    if status != expected:
                        wrong_trials.append({"query_id": query_id, "probe_id": probe,
                                             "repetition": row["repetition"], "status": status,
                                             "expected": expected})
        if len(decisive_statuses) > 1:
            disagreements.append({"query_id": query_id, "decisive_statuses": sorted(decisive_statuses)})
        queries.append({"query_id": query_id, "binary_sha256": binary_sha256, "expected": expected,
                        "probes": summaries, "missing_initial_features_trials": missing_features[identity]})

    probes = {}
    for probe in PROBES:
        trial_counts = Counter()
        unique_counts = Counter(total=12)
        stable_counts = Counter(total=12)
        probe_rows = []
        unknown_counts = Counter({category: 0 for category in UNKNOWN_CATEGORIES})
        for identity, expected in labels.items():
            group = groups[(identity, probe)]
            probe_rows.extend(group)
            counts = _trial_counts(group, expected)
            trial_counts.update(counts)
            summary = _query_summary(group, expected)
            for key in ("resolved", "correct", "wrong", "unknown"):
                unique_counts[key] += int(counts[key] > 0)
                stable_counts[key] += int(summary["stable_" + key])
            unknown_counts.update(summary["unknown_categories"])
        probes[probe] = {
            "trial_counts": dict(trial_counts), "unique_query_counts": dict(unique_counts),
            "stable_query_counts": dict(stable_counts),
            "unstable_queries": 12 - sum(stable_counts[key] for key in ("resolved", "unknown")),
            "unknown_categories": dict(unknown_counts),
            "median_probe_elapsed_seconds": median(row["probe_elapsed_seconds"] for row in probe_rows
                                                    if _cost_complete(row))
                                            if any(_cost_complete(row) for row in probe_rows) else None,
            "cost_observation_count": sum(_cost_complete(row) for row in probe_rows),
            "unavailable_trials": sum(row["availability"] != "available" for row in probe_rows),
            "missing_initial_features_trials": sum(not row["initial_features"].get("available", True)
                                                  for row in probe_rows),
            "incomplete_work_measurement_trials": sum(not _work_complete(row) for row in probe_rows),
        }

    cap_pairs, composite_pairs, separated = [], {}, []
    for query in queries:
        identity = (query["query_id"], query["binary_sha256"])
        expanded = groups[(identity, "expanded_paths")]
        for bounded, full in zip(groups[(identity, "bounded_paths")], expanded):
            if bounded["result"]["status"] in DECISIVE and bounded["result"]["status"] == full["result"]["status"]:
                pair = _paired_work(query["query_id"], bounded, full)
                pair["same_executed_steps"] = pair["total_executed_steps_delta"] == 0 if pair["work_measurement_complete"] else None
                pair["interpretation"] = "cap_redundancy_not_speed_evidence" if pair["same_executed_steps"] else "observed_work_difference" if pair["work_measurement_complete"] else "incomplete_work_measurement"
                cap_pairs.append(pair)
        for probe in ("definitions_then_expanded", "direct_prefix_then_expanded"):
            composite_pairs.setdefault(probe, []).extend(
                _paired_work(query["query_id"], candidate, full)
                for candidate, full in zip(groups[(identity, probe)], expanded))
        full_summary = query["probes"]["expanded_paths"]
        for probe in PROBES:
            candidate = query["probes"][probe]
            if (probe != "expanded_paths" and candidate["stable_correct"] and full_summary["stable_correct"]
                    and candidate["cost_observation_count"] == 3 and full_summary["cost_observation_count"] == 3):
                candidate_cost = candidate["probe_elapsed_seconds"]
                full_cost = full_summary["probe_elapsed_seconds"]
                if candidate_cost["max"] < full_cost["min"]:
                    separated.append({"query_id": query["query_id"], "probe_id": probe,
                                      "reference_probe_id": "expanded_paths",
                                      "candidate_max_seconds": candidate_cost["max"],
                                      "reference_min_seconds": full_cost["min"],
                                      "observed_gap_seconds": full_cost["min"] - candidate_cost["max"],
                                      "correct_repetitions_each": 3})

    blocked = bool(wrong_trials or disagreements)
    return {
        "schema": "symbai.operation_effect_evaluation.v1", "panel": PANEL,
        "queries_count": 12, "trials_count": len(rows), "repetitions": list(REPETITIONS),
        "probe_ids": list(PROBES), "probes": probes, "queries": queries,
        "comparisons": {
            "bounded_vs_expanded": {"shared_decisive_pairs": cap_pairs,
                                    "same_work_pairs": sum(pair["same_executed_steps"] is True for pair in cap_pairs),
                                    "interpretation": "Equal observed steps show cap redundancy, not a speed claim."},
            "composites_vs_expanded": composite_pairs,
            "cheaper_alternatives": {"criterion": "all_three_correct_and_candidate_max_below_reference_min",
                                     "label": "empirical_separation_not_statistical_significance",
                                     "pairs": separated, "interpretation_blocked": blocked},
        },
        "correctness_review": {"required": blocked, "wrong_validated_trials": wrong_trials,
                               "disagreeing_decisive_statuses": disagreements},
        "interpretation": {
            "status": "blocked_for_correctness_review" if blocked else "descriptive_operation_effects_only",
            "correctness_review_required": blocked,
            "cost_scope": "Measured probe setup, preparation, execution, fresh validation, and recording.",
            "excluded_costs": ["parent_per_query_worker_startup", "shared_feature_acquisition"],
            "limitations": [
                "Kernel operation times are not deployment-policy or end-to-end costs.",
                "Definitions is a composite; planning graphs and snapshots are not validated property evidence.",
                "Direct-prefix preparation isolates RDA overhead on the same eligible straight-line prefix.",
                "Abstract local-bounds work is separate from symbolic prefix work.",
                "Unique query categories may overlap; stable categories require agreement in all three repetitions.",
                "No selector, neural value, training, or generalization claim is evaluated.",
                "The three compiled genuine-type queries belong to a separate post-hoc mapping-proof audit.",
            ],
        },
    }
