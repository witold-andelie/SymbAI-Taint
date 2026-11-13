"""Information-only diagnostic; genuine type artifacts are never charged as free online inference."""

from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import platform
import time

from .contracts import Checkpoint, OPERATIONS, fingerprint
from .scheduler import POLICY, select_action
from .types import TypeInformationUnavailable, TypeView, load_type_view

AD_METHODS = {"info_" + v: v for v in "ABCD"}
FIXED_METHODS = {"info_expanded_only": ("expanded_paths",),
                 "info_bounds_then_expanded": ("local_bounds", "expanded_paths")}
METHODS = tuple(AD_METHODS) + tuple(FIXED_METHODS)
REVISION = "information_value_v6"


def choose_operation(method, checkpoint, view, structural_features):
    if method in AD_METHODS:
        operation, scores = select_action(checkpoint, AD_METHODS[method], view,
                                          structural_features=structural_features)
        return (operation.operation_id, operation.max_steps, scores) if operation else (None, None, scores)
    if method not in FIXED_METHODS or view.available:
        raise ValueError("A fixed information control requires a known method and no type view")
    remaining = [op for op in FIXED_METHODS[method] if op not in checkpoint.attempted]
    return (remaining[0], 128, []) if remaining else (None, None, [])


def run_information_query(query, method, budget_seconds, type_artifact=None,
                          started_at=None, record_event=None):
    if method not in METHODS or budget_seconds <= 0:
        raise ValueError("A known information method and positive budget are required")
    started = time.monotonic() if started_at is None else started_at
    checkpoint = Checkpoint(query.contract_hash)
    costs = {k: 0.0 for k in ("preparation", "type_acquisition", "selection", "execution", "validation", "recording")}
    versions = {"python": platform.python_version()}
    for package in ("angr", "claripy", "pyvex", "capstone", "pyelftools"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "not_installed"
    ledger = []
    def emit(event, **payload):
        before = time.monotonic()
        row = {"event": event, "query_id": query.query_id, "variant": method,
               "elapsed_wall_seconds": before - started, **payload}
        ledger.append(row)
        if record_event:
            record_event(row)
        costs["recording"] += time.monotonic() - before
    emit("run_started", query_hash=query.contract_hash, binary_sha256=query.binary_sha256,
         regime="information_only", budget_seconds=budget_seconds, revision=REVISION,
         policy_hash=fingerprint(POLICY), original_catalog_hash=fingerprint([asdict(op) for op in OPERATIONS]))
    view, identity = TypeView(), {}
    budget_started = None
    availability = "available"
    result = {"status": "unknown", "reason": "preparation_incomplete"}
    try:
        variant = AD_METHODS.get(method, "B")
        view = load_type_view(Path(type_artifact) if type_artifact else None, query, variant)
        if view.available:
            identity = {"artifact_sha256": view.artifact_sha256, "model_sha256": view.model_sha256,
                        "projected_view_hash": fingerprint(asdict(view))}
        from .operations import BinaryChecker, BudgetExpired
        from .local_bounds import LocalBoundsChecker
        # The same common initialization is excluded for all six information methods.
        checker, bound_checker = BinaryChecker(query), LocalBoundsChecker(query)
        structural = checker.structural_features()
        costs["preparation"] = time.monotonic() - started - costs["recording"]
        budget_started = time.monotonic()
        deadline = budget_started + budget_seconds
        emit("information_budget_started", structural_features=structural,
             initial_checkpoint=checkpoint.checkpoint_id, type_identity=identity,
             preparation_seconds=costs["preparation"], preparation_charged=False,
             initial_prefix_cache="empty", common_checkers=["symbolic", "local_bounds"])
        while time.monotonic() < deadline:
            before = time.monotonic()
            operation, steps, scores = choose_operation(method, checkpoint, view, structural)
            costs["selection"] += time.monotonic() - before
            if operation is None:
                result = {"status": "unknown", "reason": "operation_catalog_exhausted"}
                break
            emit("action_selected", operation_id=operation, checkpoint_id=checkpoint.checkpoint_id,
                 scores=scores, type_features=view.selector_features(),
                 remaining_seconds=max(0.0, deadline - time.monotonic()))
            before = time.monotonic()
            execution_seconds = validation_seconds = 0.0
            outcome = None
            error = None
            try:
                if before >= deadline:
                    raise BudgetExpired("Selection exhausted the information budget")
                if operation == "definitions":
                    outcome = {"status": "unknown", "basis": "dependency_preparation_only",
                               **checker.prepare_dependencies(deadline)}
                elif operation == "local_bounds":
                    outcome = bound_checker.check(deadline)
                else:
                    outcome = checker.check(steps, deadline)
                execution_seconds = time.monotonic() - before
                validation_started = time.monotonic()
                if validation_started >= deadline:
                    raise BudgetExpired("Execution exhausted the information budget")
                if operation == "local_bounds":
                    outcome = bound_checker.validate(outcome, deadline)
                elif operation != "definitions":
                    outcome = checker.validate(outcome, steps, deadline)
                validation_seconds = time.monotonic() - validation_started
                if time.monotonic() >= deadline:
                    raise BudgetExpired("Validation exhausted the information budget")
            except Exception as exc:
                error = type(exc).__name__ + ": " + str(exc)
                outcome = {"status": "unknown", "reason": error}
                if execution_seconds:
                    validation_seconds = time.monotonic() - before - execution_seconds
                else:
                    execution_seconds = time.monotonic() - before
            costs["execution"] += execution_seconds
            costs["validation"] += validation_seconds
            facts = ("dependencies_observed",) if "dependencies" in outcome and not error else ()
            prefix = outcome.get("prepared_prefix", {})
            if prefix.get("status") == "ready" and not error:
                facts += ("exact_prefix_prepared:" + prefix["cache_id"],)
            previous = checkpoint.checkpoint_id
            checkpoint = checkpoint.advance(operation, facts)
            emit("action_finished", operation_id=operation, outcome=outcome,
                 execution_seconds=execution_seconds, validation_seconds=validation_seconds,
                 checkpoint_before=previous, checkpoint_after=checkpoint.checkpoint_id)
            result = outcome
            if outcome["status"] in ("violation", "excluded_within_scope"):
                break
        else:
            result = {"status": "unknown", "reason": "information_budget_exhausted"}
    except TypeInformationUnavailable as exc:
        availability = "type_information_unavailable"
        result = {"status": "unknown", "reason": str(exc)}
    except Exception as exc:
        availability = "preparation_or_execution_failed"
        result = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc)}
    if budget_started is None:
        costs["preparation"] = time.monotonic() - started - costs["recording"]
    emit("run_finished", result=result, availability=availability)
    elapsed = time.monotonic() - started
    charged = time.monotonic() - budget_started if budget_started is not None else 0.0
    late_candidate = None
    if charged > budget_seconds and result["status"] != "unknown":
        late_candidate = result
        result = {"status": "unknown", "reason": "recording_exceeded_information_budget"}
    return {"schema": "symbai.run.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "variant": method, "regime": "information_only",
            "budget_seconds": budget_seconds, "accounting_unit": "prepared_single_query_information_budget",
            "availability": availability, "type_source": view.source, "type_identity": identity,
            "costs_seconds": costs, "elapsed_wall_seconds": elapsed, "charged_seconds": charged,
            "policy_id": POLICY["id"] if method in AD_METHODS else method,
            "policy_hash": fingerprint(POLICY) if method in AD_METHODS else fingerprint(FIXED_METHODS[method]),
            "operation_revision": "exact_prefix_v2", "diagnostic_revision": REVISION,
            "runtime_versions": versions, "ledger": ledger, "result": result,
            "late_candidate_result": late_candidate,
            "excluded_costs": ["online_inference", "prior_mapping", "type_artifact_projection", "common_checker_preparation"],
            "limitations": ["one_reviewed_developer_query", "information_only_not_end_to_end",
                            "fixed_controls_use_different_stage_lists", "modeled_or_abstract_validation_not_native_replay"]}
