"""Fixed non-neural analysis cascade; existing operation implementations stay frozen."""

from importlib.metadata import version
import math
import sys
import time

from .contracts import Checkpoint, file_hash

REVISION = "fixed_interval_finite_expanded_v15"
METHODS = {"expanded_only": ("expanded",),
           "fixed_cascade": ("interval", "finite_readonly", "expanded")}
REPETITIONS = (0, 1, 2)
BUDGET_SECONDS = 30.0


def runtime_versions():
    return {"python": sys.version, "executable": sys.executable, "platform": sys.platform,
            **{name: version(name) for name in ("angr", "capstone", "pyelftools")}}


def execute_operation(query, operation, deadline):
    """Fresh construction and fresh validation, including failed preparation costs."""
    if operation not in ("interval", "finite_readonly", "expanded"):
        raise ValueError("Unknown fixed operation")
    started = time.monotonic()
    costs = {name: 0.0 for name in ("preparation", "execution", "validation")}
    phase, before, result = "preparation", started, None
    try:
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary identity changed before operation")
        if operation == "interval":
            from .local_bounds import LocalBoundsChecker
            checker = LocalBoundsChecker(query)
        elif operation == "finite_readonly":
            from .readonly_values import FiniteReadonlyChecker
            checker = FiniteReadonlyChecker(query, cardinality_limit=32)
        else:
            from .operations import BinaryChecker
            checker = BinaryChecker(query)
        costs[phase] += time.monotonic() - before
        phase, before = "execution", time.monotonic()
        if before >= deadline:
            raise TimeoutError("Operation preparation exhausted query budget")
        result = checker.check(128, deadline, use_prepared=False) if operation == "expanded" else checker.check(deadline)
        costs[phase] += time.monotonic() - before
        phase, before = "validation", time.monotonic()
        result = checker.validate(result, 128, deadline) if operation == "expanded" else checker.validate(result, deadline)
        if result["status"] != "unknown":
            expected = ("fresh_byte_decoded_abstract_recheck" if operation == "interval" else
                        "fresh_byte_data_abstract_recheck" if operation == "finite_readonly" else
                        "concrete_input_modeled_reexecution" if result["status"] == "violation" else
                        "fresh_state_complete_scope_recheck")
            if (result.get("validation") != expected
                    or result["status"] == "excluded_within_scope" and result.get("complete") is not True
                    or operation != "expanded" and result["status"] != "excluded_within_scope"):
                raise ValueError("Operation returned no recognized fresh validation")
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary identity changed during operation")
        costs[phase] += time.monotonic() - before
        phase = None
        if time.monotonic() >= deadline:
            raise TimeoutError("Operation validation exhausted query budget")
    except Exception as error:
        if phase is not None:
            costs[phase] += time.monotonic() - before
        result = {"status": "unknown", "reason": type(error).__name__ + ": " + str(error),
                  "retained_candidate": result}
    return {"operation": operation, "result": result, "costs_seconds": costs,
            "elapsed_seconds": time.monotonic() - started, "entry_basis": "fresh_function_entry_no_reused_facts"}


def run_query(query, method, repetition, started_at, record_event=None):
    if (method not in (*METHODS, "reference") or type(repetition) is not int
            or repetition not in REPETITIONS or method == "reference" and repetition != 0):
        raise ValueError("Invalid fixed-baseline method or repetition")
    if type(started_at) not in (int, float) or not math.isfinite(started_at) or started_at < 0:
        raise ValueError("Invalid parent start clock")
    deadline = started_at + BUDGET_SECONDS
    costs = {name: 0.0 for name in ("provenance", "preparation", "execution", "validation", "recording")}
    events, attempts = [], []
    def emit(event, **payload):
        before = time.monotonic()
        row = {"event": event, "query_hash": query.contract_hash, "method": method, "repetition": repetition,
               "elapsed_from_parent_start_seconds": before - started_at, **payload}
        events.append(row)
        if record_event:
            record_event(row)
        costs["recording"] += time.monotonic() - before
    before = time.monotonic()
    versions = runtime_versions()
    costs["provenance"] += time.monotonic() - before
    emit("worker_started", checkpoint_id=Checkpoint(query.contract_hash).checkpoint_id,
         runtime_versions=versions, entry_state="fresh", neural_information="not_accepted")
    reference = None
    result = {"status": "unknown", "reason": "query_budget_exhausted_before_execution"}
    if method == "reference":
        before = time.monotonic()
        try:
            if before >= deadline:
                raise TimeoutError("Reference budget exhausted")
            from .literal_reference import reference_query
            reference = reference_query(query, deadline)
            result = reference["result"]
        except Exception as error:
            result = {"status": "unknown", "reason": type(error).__name__ + ": " + str(error)}
        costs["validation"] += time.monotonic() - before
        emit("reference_finished", reference=reference, outcome=result)
    else:
        for operation in METHODS[method]:
            if time.monotonic() >= deadline:
                result = {"status": "unknown", "reason": "shared_query_budget_exhausted"}
                break
            emit("operation_started", operation=operation)
            attempt = execute_operation(query, operation, deadline)
            attempts.append(attempt)
            for phase, elapsed in attempt["costs_seconds"].items():
                costs[phase] += elapsed
            result = attempt["result"]
            emit("operation_finished", attempt=attempt)
            if result["status"] in ("violation", "excluded_within_scope"):
                break
    if time.monotonic() >= deadline:
        result = {"status": "unknown", "reason": "worker_finalization_exceeded_budget", "retained_candidate": result}
    emit("worker_finished", worker_result=result)
    return {"schema": "symbai.cascade_trial.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "checkpoint_id": Checkpoint(query.contract_hash).checkpoint_id,
            "method": method, "repetition": repetition, "worker_result": result, "attempts": attempts,
            "runtime_versions": versions, "worker_costs_seconds": costs, "worker_elapsed_seconds": time.monotonic() - started_at,
            "cost_measurement_complete": True, "ledger": events, "reference": reference,
            "neural_information_used": False, "native_replay": "not_attempted", "revision": REVISION}
