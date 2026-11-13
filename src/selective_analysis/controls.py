"""Fixed operation controls, separate from the frozen A-D selector and catalog."""

from importlib.metadata import PackageNotFoundError, version
import platform
import time

from .contracts import fingerprint


CONTROL_OPERATIONS = {
    "expanded_only": ("expanded_paths",),
    "bounds_only": ("local_bounds",),
    "bounds_then_expanded": ("local_bounds", "expanded_paths"),
}
REVISION = "operation_choice_gate_v4"


def run_control(query, control, budget_seconds, regime="end_to_end", started_at=None, record_event=None):
    if control not in CONTROL_OPERATIONS or budget_seconds <= 0 or regime not in ("end_to_end", "information_only"):
        raise ValueError("A known control, positive budget and declared regime are required")
    started = time.monotonic() if started_at is None else started_at
    # These controls are intentionally measured end to end; no free loader/preparation seam.
    if regime != "end_to_end":
        raise ValueError("Operation controls currently require end-to-end accounting")
    deadline = started + budget_seconds
    costs = {k: 0.0 for k in ("preparation", "type_acquisition", "selection", "execution", "validation", "recording")}
    ledger = []
    versions = {"python": platform.python_version()}
    for package in ("angr", "claripy", "pyvex", "capstone", "pyelftools"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "not_installed"

    def emit(event, **payload):
        before = time.monotonic()
        row = {"event": event, "query_id": query.query_id, "variant": control,
               "elapsed_wall_seconds": before - started, **payload}
        ledger.append(row)
        if record_event:
            record_event(row)
        costs["recording"] += time.monotonic() - before

    emit("run_started", query_hash=query.contract_hash, binary_sha256=query.binary_sha256,
         budget_seconds=budget_seconds, regime=regime, policy_id=control,
         operation_revision=REVISION, runtime_versions=versions,
         policy_hash=fingerprint({"revision": REVISION, "operations": CONTROL_OPERATIONS[control]}))
    costs["preparation"] = max(0.0, time.monotonic() - started - costs["recording"])
    result = {"status": "unknown", "reason": "operation_catalog_exhausted"}
    for operation in CONTROL_OPERATIONS[control]:
        if time.monotonic() >= deadline:
            result = {"status": "unknown", "reason": "budget_exhausted"}
            break
        emit("action_selected", operation_id=operation, state_basis="fresh_function_entry",
             remaining_seconds=max(0.0, deadline - time.monotonic()))
        phase, before = "preparation", time.monotonic()
        outcome = None
        execution_seconds = validation_seconds = 0.0
        try:
            if operation == "local_bounds":
                from .local_bounds import LocalBoundsChecker
                checker = LocalBoundsChecker(query)
            else:
                from .operations import BinaryChecker
                checker = BinaryChecker(query)
            costs[phase] += time.monotonic() - before
            phase, before = "execution", time.monotonic()
            if before >= deadline:
                raise TimeoutError("Control preparation exhausted the budget")
            outcome = (checker.check(deadline) if operation == "local_bounds" else
                       checker.check(128, deadline, use_prepared=False))
            execution_seconds = time.monotonic() - before
            costs[phase] += execution_seconds
            phase, before = "validation", time.monotonic()
            if before >= deadline:
                raise TimeoutError("Control execution exhausted the budget")
            outcome = (checker.validate(outcome, deadline) if operation == "local_bounds" else
                       checker.validate(outcome, 128, deadline))
            validation_seconds = time.monotonic() - before
            costs[phase] += validation_seconds
            phase = None
            if time.monotonic() >= deadline:
                raise TimeoutError("Control validation exhausted the budget")
        except Exception as exc:
            elapsed = time.monotonic() - before
            if phase is not None:
                costs[phase] += elapsed
                if phase == "execution":
                    execution_seconds = elapsed
                elif phase == "validation":
                    validation_seconds = elapsed
            outcome = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc)}
        emit("action_finished", operation_id=operation, outcome=outcome,
             execution_seconds=execution_seconds, validation_seconds=validation_seconds)
        result = outcome
        if outcome["status"] in ("violation", "excluded_within_scope"):
            break
    emit("run_finished", result=result, availability="available")
    elapsed = time.monotonic() - started
    return {"schema": "symbai.run.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "variant": control, "regime": regime,
            "budget_seconds": budget_seconds, "accounting_unit": "single_query_cold_run",
            "availability": "available", "type_source": "not_used", "type_identity": {},
            "type_acquisition": {}, "runtime_versions": versions, "policy_id": control,
            "operation_revision": REVISION, "result": result, "costs_seconds": costs,
            "elapsed_wall_seconds": elapsed, "charged_seconds": elapsed, "ledger": ledger,
            "limitations": ["restricted_unsigned_instruction_subset", "explicit_query_object_bounds",
                            "first_dynamic_visit_scope", "abstract_recheck_or_modeled_reexecution_not_native_replay",
                            "diagnostic_control_not_a_neural_result"]}
