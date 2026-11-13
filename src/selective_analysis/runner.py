"""Single-query execution, provenance records, and matched A-D selection policy."""

from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import platform
import time

from .contracts import Checkpoint, OPERATIONS, fingerprint
from .scheduler import POLICY, select_action
from .types import TypeInformationUnavailable, load_type_view
from .online_types import TypeAcquisitionTimeout, acquire_type_view


def run_query(query, variant, budget_seconds, regime="information_only", type_artifact=None,
              allow_synthetic=False, started_at=None, record_event=None,
              online_config=None, acquisition_dir=None, within_worker=False):
    if variant not in ("A", "B", "C", "D"):
        raise ValueError("Unknown experimental variant")
    if budget_seconds <= 0 or regime not in ("information_only", "end_to_end"):
        raise ValueError("A positive budget and declared regime are required")
    started = time.monotonic() if started_at is None else started_at
    checkpoint = Checkpoint(query.contract_hash)
    ledger = []
    costs = {"preparation": 0.0, "type_acquisition": 0.0, "selection": 0.0, "execution": 0.0,
             "validation": 0.0, "recording": 0.0}
    runtime_versions = {"python": platform.python_version()}
    for package in ("angr", "claripy", "pyvex"):
        try:
            runtime_versions[package] = version(package)
        except PackageNotFoundError:
            runtime_versions[package] = "not_installed"
    def emit(event, **payload):
        before = time.monotonic()
        row = {"event": event, "query_id": query.query_id, "variant": variant,
               "elapsed_wall_seconds": before - started, **payload}
        ledger.append(row)
        if record_event:
            record_event(row)
        costs["recording"] += time.monotonic() - before
    emit("run_started", query_hash=query.contract_hash, binary_sha256=query.binary_sha256,
         regime=regime, budget_seconds=budget_seconds,
         policy_id=POLICY["id"], operation_revision=POLICY["operation_revision"],
         runtime_versions=runtime_versions,
         policy_hash=fingerprint(POLICY), operation_catalog_hash=fingerprint([asdict(o) for o in OPERATIONS]))
    result = {"status": "unknown", "reason": "no_decisive_evidence"}
    availability = "available"
    type_source = "unavailable"
    type_identity = {}
    acquisition = {}
    preparation_finished = False
    budget_started = started
    try:
        if variant in ("C", "D") and regime == "end_to_end":
            if online_config is None:
                raise TypeInformationUnavailable("Online GNN provider is not configured; precomputed scores cannot be free end-to-end inputs")
            if type_artifact is not None or allow_synthetic or acquisition_dir is None:
                raise TypeInformationUnavailable("Online runs require a fresh acquisition directory and cannot use cached/synthetic types")
            before, recorded_before = time.monotonic(), costs["recording"]
            try:
                type_view, acquisition = acquire_type_view(query, variant, Path(online_config),
                    Path(acquisition_dir), started + budget_seconds, emit, within_worker)
            finally:
                costs["type_acquisition"] += max(0.0, time.monotonic() - before - (costs["recording"] - recorded_before))
        else:
            type_view = load_type_view(Path(type_artifact) if type_artifact else None,
                                       query, variant, allow_synthetic)
        type_source = type_view.source
        if type_view.available:
            type_identity = {"artifact_sha256": type_view.artifact_sha256,
                             "model_sha256": type_view.model_sha256,
                             "projected_view_hash": fingerprint(asdict(type_view))}
        from .operations import BinaryChecker, BudgetExpired
        checker = BinaryChecker(query)
        structural_features = checker.structural_features()
        costs["preparation"] = max(0.0, time.monotonic() - started - costs["recording"] - costs["type_acquisition"])
        preparation_finished = True
        if regime == "information_only":
            budget_started = time.monotonic()
        deadline = budget_started + budget_seconds
        emit("preparation_completed", preparation_seconds=costs["preparation"],
             preparation_charged=regime == "end_to_end", type_source=type_source,
             type_identity=type_identity,
             bounds_source=query.bounds_source, scope=query.scope, structural_features=structural_features)
        while time.monotonic() < deadline:
            before = time.monotonic()
            operation, scores = select_action(checkpoint, variant, type_view,
                                             structural_features=structural_features)
            type_features = type_view.selector_features()
            costs["selection"] += time.monotonic() - before
            if operation is None:
                result = {"status": "unknown", "reason": "operation_catalog_exhausted"}
                break
            emit("action_selected", checkpoint_id=checkpoint.checkpoint_id,
                 operation_id=operation.operation_id, scores=scores,
                 type_features=type_features,
                 remaining_seconds=max(0.0, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                raise BudgetExpired("Selection exhausted the budget")
            before_checkpoint = checkpoint.checkpoint_id
            operation_start = time.monotonic()
            outcome = None
            error = None
            execution_seconds = validation_seconds = 0.0
            try:
                if operation.operation_id == "definitions":
                    prepared = checker.prepare_dependencies(deadline)
                    outcome = {"status": "unknown", "basis": "dependency_preparation_only", **prepared}
                else:
                    outcome = checker.check(operation.max_steps, deadline)
                execution_seconds = time.monotonic() - operation_start
                before = time.monotonic()
                if time.monotonic() >= deadline:
                    raise BudgetExpired("Check exceeded deadline")
                if operation.operation_id != "definitions":
                    outcome = checker.validate(outcome, operation.max_steps, deadline)
                validation_seconds = time.monotonic() - before
                if time.monotonic() >= deadline:
                    raise BudgetExpired("Validation exceeded deadline")
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                outcome = {"status": "unknown", "reason": error}
                if not execution_seconds:
                    execution_seconds = time.monotonic() - operation_start
                else:
                    validation_seconds = time.monotonic() - operation_start - execution_seconds
            costs["execution"] += execution_seconds
            costs["validation"] += validation_seconds
            facts = ("dependencies_observed",) if "dependencies" in outcome and not error else ()
            prefix = outcome.get("prepared_prefix", {})
            if prefix.get("status") == "ready" and not error:
                facts += ("exact_prefix_prepared:" + prefix["cache_id"],)
            checkpoint = checkpoint.advance(operation.operation_id, facts)
            emit("action_finished", checkpoint_before=before_checkpoint,
                 checkpoint_after=checkpoint.checkpoint_id, operation_id=operation.operation_id,
                 execution_seconds=execution_seconds, validation_seconds=validation_seconds,
                 outcome=outcome)
            if outcome["status"] in ("violation", "excluded_within_scope"):
                result = outcome
                break
            if time.monotonic() >= deadline:
                result = {"status": "unknown", "reason": "budget_exhausted"}
                break
        else:
            result = {"status": "unknown", "reason": "budget_exhausted"}
    except TypeAcquisitionTimeout as exc:
        result = {"status": "unknown", "reason": "budget_exhausted_during_type_acquisition", "detail": str(exc)}
    except TypeInformationUnavailable as exc:
        availability = "type_information_unavailable"
        result = {"status": "unknown", "reason": str(exc)}
    except Exception as exc:
        result = {"status": "unknown", "reason": f"{type(exc).__name__}: {exc}"}
    if not preparation_finished:
        costs["preparation"] = max(0.0, time.monotonic() - started - costs["recording"] - costs["type_acquisition"])
    emit("run_finished", result=result, availability=availability)
    elapsed = time.monotonic() - started
    return {"schema": "symbai.run.v1", "query_id": query.query_id,
            "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
            "variant": variant, "regime": regime, "budget_seconds": budget_seconds,
            "accounting_unit": "single_query_cold_run", "availability": availability,
            "type_source": type_source, "result": result, "costs_seconds": costs,
            "type_identity": type_identity, "runtime_versions": runtime_versions,
            "type_acquisition": acquisition,
            "policy_id": POLICY["id"], "operation_revision": POLICY["operation_revision"],
            "elapsed_wall_seconds": elapsed,
            "charged_seconds": elapsed if regime == "end_to_end" else time.monotonic() - budget_started,
            "ledger": ledger,
            "limitations": ["explicit_query_object_bounds", "first_dynamic_visit_scope",
                            "modeled_reexecution_not_native_replay", "development_policy_not_a_novelty_claim"]}
