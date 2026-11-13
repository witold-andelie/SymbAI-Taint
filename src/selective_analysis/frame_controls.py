"""Fixed frame-aware diagnostic controls; the A-D policy/catalog is unchanged."""

from importlib.metadata import version
import time

from .frame_bounds import REVISION

METHODS = {"frame_bounds_only": ("frame_bounds",),
           "frame_bounds_then_expanded": ("frame_bounds", "expanded_paths")}


def run_frame_control(query, method, budget_seconds, regime="end_to_end", started_at=None, record_event=None):
    if method not in METHODS or regime != "end_to_end" or budget_seconds <= 0:
        raise ValueError("Frame controls require a known method and positive end-to-end budget")
    started = time.monotonic() if started_at is None else started_at
    deadline = started + budget_seconds
    costs = {k: 0.0 for k in ("preparation", "type_acquisition", "selection", "execution", "validation", "recording")}
    ledger, reference = [], None

    def emit(event, **payload):
        before = time.monotonic()
        row = {"event": event, "query_id": query.query_id, "variant": method,
               "elapsed_wall_seconds": before - started, **payload}
        ledger.append(row)
        if record_event:
            record_event(row)
        costs["recording"] += time.monotonic() - before

    result = {"status": "unknown", "reason": "no_operation_completed"}
    emit("run_started", query_hash=query.contract_hash, binary_sha256=query.binary_sha256,
         regime=regime, budget_seconds=budget_seconds, operation_revision=REVISION,
         type_inputs="not_accepted", initial_prefix_cache="empty")
    for operation in METHODS[method]:
        if time.monotonic() >= deadline:
            result = {"status": "unknown", "reason": "budget_exhausted"}
            break
        emit("action_selected", operation_id=operation, state_basis="fresh_function_entry_no_prefix",
             remaining_seconds=max(0.0, deadline - time.monotonic()))
        phase, before = "preparation", time.monotonic()
        outcome = None
        execution_seconds = validation_seconds = 0.0
        try:
            from .operations import BinaryChecker
            if reference is None:
                reference = BinaryChecker(query)
            if operation == "frame_bounds":
                from .frame_bounds import FrameBoundsChecker
                checker = FrameBoundsChecker(query, reference)
            else:
                checker = reference
            costs[phase] += time.monotonic() - before
            phase, before = "execution", time.monotonic()
            if before >= deadline:
                raise TimeoutError("Frame-control preparation exhausted the budget")
            outcome = (checker.check(deadline) if operation == "frame_bounds" else
                       checker.check(128, deadline, use_prepared=False))
            execution_seconds = time.monotonic() - before
            costs[phase] += execution_seconds
            phase, before = "validation", time.monotonic()
            if before >= deadline:
                raise TimeoutError("Frame-control execution exhausted the budget")
            outcome = (checker.validate(outcome, deadline) if operation == "frame_bounds" else
                       checker.validate(outcome, 128, deadline))
            validation_seconds = time.monotonic() - before
            costs[phase] += validation_seconds
            phase = None
            if time.monotonic() >= deadline:
                raise TimeoutError("Frame-control validation exhausted the budget")
        except Exception as exc:
            elapsed = time.monotonic() - before
            if phase is not None:
                costs[phase] += elapsed
                if phase == "execution":
                    execution_seconds = elapsed
                elif phase == "validation":
                    validation_seconds = elapsed
            outcome = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc),
                       "incomplete_candidate": outcome}
        emit("action_finished", operation_id=operation, outcome=outcome,
             execution_seconds=execution_seconds, validation_seconds=validation_seconds,
             project_reuse_available=reference is not None, prefix_cache_used=False)
        result = outcome
        if result["status"] in ("violation", "excluded_within_scope"):
            break
    emit("run_finished", result=result, availability="available")
    elapsed = time.monotonic() - started
    return {"schema": "symbai.run.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
        "binary_sha256": query.binary_sha256, "variant": method, "regime": regime,
        "budget_seconds": budget_seconds, "accounting_unit": "single_query_cold_run",
        "availability": "available", "type_source": "not_used", "type_identity": {}, "type_acquisition": {},
        "policy_id": method, "operation_revision": REVISION, "result": result, "costs_seconds": costs,
        "elapsed_wall_seconds": elapsed, "charged_seconds": elapsed, "ledger": ledger,
        "runtime_versions": {"angr": version("angr")},
        "limitations": ["straight_line_canonical_compiler_frame_subset", "explicit_query_object_bounds",
            "first_dynamic_visit_scope", "entry_context_preparation_charged",
            "same_implementation_abstract_recheck_not_native_replay", "not_a_neural_selection_result"]}
