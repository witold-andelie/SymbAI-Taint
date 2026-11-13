"""Retrospective deletion accounting for immutable, validated v15 traces.

No operation, model, mapper, clock or file is consulted.  The calculation holds
other recorded costs fixed; it is not a real-runtime upper bound or a policy.
"""

import math
from statistics import median

from . import cascade_evaluation


FRAME_MODEL = "delete_unknown_attempts_hold_other_costs_fixed"
_METRICS = ("parent_charged_seconds", "optimistic_deletable_attempt_seconds", "retained_charge_seconds")


def _number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(name + " must be a finite nonnegative clock")


def _exceeds(total, interval):
    # Permit only floating-point summation noise, not the v15 receipt's broader
    # diagnostic clock tolerance.  Genuine overlapping/omitted time is rejected.
    return total > interval and not math.isclose(total, interval, rel_tol=1e-12, abs_tol=1e-12)


def _stats(values):
    return {"count": len(values), "total_seconds": math.fsum(values), "median_seconds": median(values),
            "minimum_seconds": min(values), "maximum_seconds": max(values)}


def _validate_clocks(row):
    charge = row["parent_receipt"]["charged_seconds"]
    _number(charge, "parent charged_seconds")
    elapsed = []
    for attempt in row["attempts"]:
        if not isinstance(attempt, dict):
            raise ValueError("An attempt must be a complete ledger object")
        value = attempt.get("elapsed_seconds")
        _number(value, "attempt elapsed_seconds")
        phases = attempt.get("costs_seconds")
        if not isinstance(phases, dict) or not {"preparation", "execution", "validation"} <= set(phases):
            raise ValueError("Missing attempt preparation/execution/validation clocks")
        for phase in phases.values():
            _number(phase, "attempt phase_seconds")
        if _exceeds(math.fsum(phases.values()), value):
            raise ValueError("Attempt phase costs exceed its elapsed clock")
        elapsed.append(value)
    if _exceeds(math.fsum(elapsed), charge):
        raise ValueError("Attempt elapsed clocks exceed the complete parent charge")


def summarize_trace_headroom(records, references, gold):
    """Delete unknown prefixes only after validating the complete 18+3 panel.

    Unknown expanded-only outcomes remain valid.  Every cascade must finish with
    a freshly validated correct decision, and no trial/reference may be failed
    or late.  No neural-acquisition cost is supplied or inferred.
    """
    evaluation = cascade_evaluation.evaluate(records, references, gold)
    if evaluation["interpretation_allowed"] is not True or any(
            method["wrong"] or method["failures"] for method in evaluation["methods"]):
        raise ValueError("The v15 matrix is blocked, wrong or failed; trace deletion is unavailable")
    for row in records + references:
        receipt = row["parent_receipt"]
        process = receipt["process"]
        if receipt["late"] or process["timed_out"] or process["returncode"] != 0:
            raise ValueError("Late or failed records cannot supply trace headroom")
        _validate_clocks(row)

    traces = []
    cascade_rows = sorted((row for row in records if row["method"] == "fixed_cascade"),
                          key=lambda row: (cascade_evaluation.QUERY_IDS.index(row["query_id"]), row["repetition"]))
    for row in cascade_rows:
        attempts = row["attempts"]
        if (not attempts or row["result"]["status"] not in ("excluded_within_scope", "violation")
                or attempts[-1]["result"] != row["result"]
                or any(attempt["result"]["status"] != "unknown" for attempt in attempts[:-1])):
            raise ValueError("Each cascade needs an unknown prefix and final fresh decisive attempt")
        deleted = math.fsum(attempt["elapsed_seconds"] for attempt in attempts[:-1])
        charge = row["parent_receipt"]["charged_seconds"]
        if _exceeds(deleted, charge):
            raise ValueError("Deleted attempts exceed the original parent charge")
        retained = max(0.0, charge - deleted)
        traces.append({"trial_id": f"{row['query_id']}:fixed_cascade:{row['repetition']}",
                       "query_id": row["query_id"], "query_hash": row["query_hash"],
                       "binary_sha256": row["binary_sha256"], "checkpoint_id": row["checkpoint_id"],
                       "method": "fixed_cascade", "repetition": row["repetition"],
                       "parent_charged_seconds": charge,
                       "optimistic_deletable_attempt_seconds": deleted, "retained_charge_seconds": retained,
                       "decisive_operation": attempts[-1]["operation"],
                       "deleted_operations": [attempt["operation"] for attempt in attempts[:-1]],
                       "frame_model": FRAME_MODEL})

    per_query = []
    for query_id in cascade_evaluation.QUERY_IDS:
        selected = [trace for trace in traces if trace["query_id"] == query_id]
        vectors = {metric: [trace[metric] for trace in selected] for metric in _METRICS}
        per_query.append({"query_id": query_id, "query_hash": selected[0]["query_hash"],
                          "binary_sha256": selected[0]["binary_sha256"], "repetitions": [trace["repetition"] for trace in selected],
                          "decisive_operations": [trace["decisive_operation"] for trace in selected],
                          "deleted_operations": [trace["deleted_operations"] for trace in selected], **vectors,
                          "statistics": {metric: _stats(values) for metric, values in vectors.items()}})
    return {"schema": "symbai.trace_headroom.v1", "unique_queries": 3, "cascade_trials": 9,
            "repetitions": 3, "validated_trial_records": 18, "separate_reference_records": 3,
            "validated_v15_interpretation_allowed": True, "frame_model": FRAME_MODEL,
            "accounting_unit": cascade_evaluation.UNIT, "traces": traces, "per_query": per_query,
            "aggregate": {metric: _stats([trace[metric] for trace in traces]) for metric in _METRICS},
            "counterfactual_only": True, "neural_benefit_measured": False, "actual_speedup_measured": False,
            "neural_acquisition_cost_measured": False, "static_baseline_competition_measured": False,
            "real_runtime_upper_bound_claimed": False, "held_out_evaluation": False,
            "limitations": [
                "Revealed-outcome deletion oracle computed offline; never an online feature or deployed policy.",
                "Imports and caches may be shared; deleting an attempt can move initialization costs into a retained attempt.",
                "All other parent costs are held fixed; changed order, extra operations or different checkers can change timings.",
                "Static load/cardinality controls compete with type information but are not measured by this calculation.",
                "No model acquisition or selection cost is estimated; historical acquisition profiles concern different inputs.",
                "Within this fixed-trace deletion model only, an added information/selection cost must be strictly below the deleted cost for a net saving.",
                "Three known inputs with repeated traces are not independent examples or evidence of a stable runtime gain."]}
