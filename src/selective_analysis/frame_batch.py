"""Three independent queries in one cold process, with parent-owned accounting.

This is an accounting diagnostic around the unchanged controls.  It has no type
or label inputs, and a worker completion is recoverable only after its complete
query row has been emitted.  ``finalize_batch`` reads neither files nor clocks.
"""

from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass
import math
import time

from .contracts import InputRange, Query
from .controls import run_control
from .frame_controls import run_frame_control


METHODS = ("expanded_only", "frame_bounds_only", "frame_bounds_then_expanded")
_REQUEST_FIELDS = {"schema", "batch_id", "variant", "budget_seconds", "started_at", "queries"}
_QUERY_FIELDS = {field.name for field in fields(Query)}
_INPUT_FIELDS = {field.name for field in fields(InputRange)}
_ROW_FIELDS = {"query_id", "query_hash", "binary_sha256", "result", "query_started_offset",
               "query_finished_offset", "query_elapsed_seconds"}
_STATUSES = {"unknown", "violation", "excluded_within_scope"}
_DECISIVE = _STATUSES - {"unknown"}
_UNIT = "three_query_cold_batch"


def _number(value, name, positive=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or value < 0 or (positive and value == 0)):
        raise ValueError(f"{name} must be a finite {'positive' if positive else 'nonnegative'} number")
    return value


def _exact_fields(value, expected, name):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} requires exactly these fields: {sorted(expected)}")


def _query_contract(value):
    """Validate a label-free asdict(Query), without opening its binary."""
    _exact_fields(value, _QUERY_FIELDS, "Runtime query")
    if not isinstance(value["query_id"], str) or not value["query_id"]:
        raise ValueError("A runtime query needs a nonempty string query_id")
    if not isinstance(value["binary"], str) or not value["binary"]:
        raise ValueError("A runtime query needs a binary path")
    digest = value["binary_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("A runtime query needs a SHA-256 content identity")
    for name in ("entry_rva", "write_rva", "object_rva", "capacity"):
        if isinstance(value[name], bool) or not isinstance(value[name], int):
            raise ValueError(f"Runtime query {name} must be an integer")
    if not isinstance(value["inputs"], (list, tuple)):
        raise ValueError("Runtime query inputs must be explicit argument ranges")
    inputs = []
    for item in value["inputs"]:
        _exact_fields(item, _INPUT_FIELDS, "Runtime argument range")
        for name in ("minimum", "maximum"):
            if isinstance(item[name], bool) or not isinstance(item[name], int):
                raise ValueError("Runtime argument bounds must be integers")
        inputs.append(InputRange(**item))
    query = Query(**{**value, "inputs": tuple(inputs)})
    return query


def _validate_request(request):
    _exact_fields(request, _REQUEST_FIELDS, "Batch request")
    if request["schema"] != "symbai.frame_batch_request.v1":
        raise ValueError("Unsupported frame batch request schema")
    if not isinstance(request["batch_id"], str) or not request["batch_id"]:
        raise ValueError("A batch needs a nonempty batch_id")
    if request["variant"] not in METHODS:
        raise ValueError("Unknown frame batch method")
    _number(request["budget_seconds"], "budget_seconds", positive=True)
    _number(request["started_at"], "started_at")
    if not isinstance(request["queries"], (list, tuple)) or len(request["queries"]) != 3:
        raise ValueError("A frame batch requires exactly three query contracts")
    identities = []
    for item in request["queries"]:
        _exact_fields(item, {"query", "query_hash"}, "Batch query entry")
        query = _query_contract(item["query"])
        if item["query_hash"] != query.contract_hash:
            raise ValueError("Batch query hash differs from its contract")
        identities.append({"query_id": query.query_id, "query_hash": query.contract_hash,
                           "binary_sha256": query.binary_sha256})
    if len({item["query_id"] for item in identities}) != 3:
        raise ValueError("A batch must contain each query ID exactly once")
    return identities


def _missing_row(identity, reason):
    return {**identity, "result": {"status": "unknown", "reason": reason},
            "query_started_offset": None, "query_finished_offset": None,
            "query_elapsed_seconds": None}


def run_worker(request, emit):
    """Execute the fixed three-query schedule using the remaining batch budget.

    The caller owns a flushing ``emit`` implementation and the hard process
    limit.  Control-local event offsets are retained separately, while emitted
    event timestamps always use the parent's original batch clock.
    """
    identities = _validate_request(request)
    started = request["started_at"]
    deadline = started + request["budget_seconds"]
    variant = request["variant"]

    def event(name, **payload):
        row = {**payload, "event": name, "batch_id": request["batch_id"], "variant": variant,
               "elapsed_wall_seconds": max(0.0, time.monotonic() - started)}
        emit(deepcopy(row))

    event("batch_started", budget_seconds=request["budget_seconds"], accounting_unit=_UNIT,
          regime="end_to_end", query_order=[item["query_id"] for item in identities],
          type_inputs="not_accepted", cross_query_application_reuse=False,
          library_cache_policy="ordinary_in_process_caches_may_warm")
    rows = []
    for entry, identity in zip(request["queries"], identities):
        query_started = time.monotonic()
        remaining = deadline - query_started
        if remaining <= 0:
            row = _missing_row(identity, "batch_budget_exhausted_before_query")
            rows.append(row)
            event("query_unstarted", **identity, query_result=row, remaining_seconds=0.0)
            continue
        offset = max(0.0, query_started - started)
        event("query_started", **identity, query_started_offset=offset,
              remaining_seconds=remaining, initial_project="fresh", initial_prefix_cache="empty")
        control_record = None
        try:
            # Deliberately reconstruct and hash-check every query here.  Neither
            # Query, checker, project nor prefix objects pass to the next query.
            query = Query.from_dict(deepcopy(entry["query"]))
            control_started = time.monotonic()
            control_budget = deadline - control_started
            if control_budget <= 0:
                result = {"status": "unknown", "reason": "batch_budget_exhausted_during_query_preparation"}
            else:
                def control_event(row):
                    payload = deepcopy(row)
                    name = payload.pop("event")
                    payload["query_elapsed_wall_seconds"] = payload.pop("elapsed_wall_seconds", None)
                    event(name, **payload)

                control = run_control if variant == "expanded_only" else run_frame_control
                control_record = control(query, variant, control_budget, regime="end_to_end",
                                         started_at=control_started, record_event=control_event)
                result = deepcopy(control_record["result"])
        except Exception as exc:
            result = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc)}
        finished = time.monotonic()
        row = {**identity, "result": result, "query_started_offset": offset,
               "query_finished_offset": max(offset, finished - started),
               "query_elapsed_seconds": finished - query_started,
               "remaining_seconds_at_start": remaining}
        if control_record is not None:
            row["control_record"] = control_record
        rows.append(row)
        # This full row is the crash-recovery boundary, before a worker result
        # is assembled or written by the caller.
        event("query_completed", **identity, query_result=row)
    event("batch_finished", query_count=len(rows))
    return {"schema": "symbai.frame_batch_worker.v1", "batch_id": request["batch_id"],
            "variant": variant, "budget_seconds": request["budget_seconds"],
            "accounting_unit": _UNIT, "regime": "end_to_end", "queries": rows,
            "elapsed_wall_seconds": max(0.0, time.monotonic() - started)}


def _validated_row(row, identity, variant, elapsed_seconds):
    if not isinstance(row, dict) or not _ROW_FIELDS <= set(row):
        raise ValueError("Incomplete query result row")
    if any(row.get(name) != value for name, value in identity.items()):
        raise ValueError("Query result identity differs from the request")
    result = row["result"]
    if not isinstance(result, dict) or result.get("status") not in _STATUSES:
        raise ValueError("Invalid query result status")
    if result["status"] in _DECISIVE and "control_record" not in row:
        raise ValueError("A decisive query requires its completed control record")
    start, finish, duration = (row[name] for name in
                              ("query_started_offset", "query_finished_offset", "query_elapsed_seconds"))
    if start is None and finish is None and duration is None:
        if result["status"] != "unknown" or "control_record" in row:
            raise ValueError("An unstarted query cannot have decisive or control evidence")
    else:
        for name, value in (("query_started_offset", start), ("query_finished_offset", finish),
                            ("query_elapsed_seconds", duration)):
            _number(value, name)
        if finish < start or finish > elapsed_seconds + 1e-6 or not math.isclose(
                duration, finish - start, rel_tol=1e-7, abs_tol=1e-6):
            raise ValueError("Query timing differs from the parent batch interval")
    if "control_record" in row:
        control = row["control_record"]
        if (not isinstance(control, dict) or control.get("schema") != "symbai.run.v1" or
                any(control.get(name) != value for name, value in identity.items()) or
                control.get("variant") != variant or control.get("regime") != "end_to_end" or
                control.get("result") != result):
            raise ValueError("Control record differs from its completed query")
        if result["status"] in _DECISIVE:
            if control.get("availability") != "available" or control.get("type_source") != "not_used":
                raise ValueError("A decisive query requires an available type-free control")
            control_elapsed = _number(control.get("elapsed_wall_seconds"), "control elapsed_wall_seconds")
            if control_elapsed > duration + 1e-6:
                raise ValueError("Control elapsed time exceeds its query interval")
            ledger = control.get("ledger")
            if not isinstance(ledger, list) or not ledger:
                raise ValueError("A decisive control requires its completed event ledger")
            last = ledger[-1]
            if (not isinstance(last, dict) or last.get("event") != "run_finished" or
                    last.get("query_id") != identity["query_id"] or last.get("variant") != variant or
                    last.get("result") != result or last.get("availability") != "available"):
                raise ValueError("Control completion event differs from its decisive query")
            last_elapsed = _number(last.get("elapsed_wall_seconds"), "control completion elapsed_wall_seconds")
            if last_elapsed > control_elapsed + 1e-6:
                raise ValueError("Control completion occurs outside its elapsed interval")
    return deepcopy(row)


def _validate_sequential_rows(rows):
    previous_finish, unstarted = None, False
    for row in rows:
        start, finish = row["query_started_offset"], row["query_finished_offset"]
        if start is None:
            unstarted = True
            continue
        if unstarted or (previous_finish is not None and start < previous_finish):
            raise ValueError("Query intervals overlap or violate the sequential schedule")
        previous_finish = finish


def finalize_batch(request, worker_result_or_None, events, process_info, elapsed_seconds):
    """Return a receipt charged to the complete parent interval, without I/O.

    A failed process's result file is untrusted, even if it looks complete.
    Only its flushed, identity-checked query-completed events can be recovered.
    Invalid output is diagnosed without dropping any requested query identity.
    """
    identities = _validate_request(request)
    _number(elapsed_seconds, "elapsed_seconds")
    process = asdict(process_info) if is_dataclass(process_info) else deepcopy(process_info)
    if not isinstance(process, dict) or not {"returncode", "timed_out"} <= set(process):
        raise ValueError("Process information needs returncode and timed_out")
    if (isinstance(process["returncode"], bool) or not isinstance(process["returncode"], int) or
            not isinstance(process["timed_out"], bool)):
        raise ValueError("Invalid process outcome")
    if "elapsed_seconds" in process:
        _number(process["elapsed_seconds"], "process elapsed_seconds")
    if not isinstance(events, (list, tuple)):
        raise ValueError("The event ledger must be a sequence")
    ledger = deepcopy(list(events))
    errors, recovered = [], {}
    by_id = {item["query_id"]: item for item in identities}
    positions = {item["query_id"]: index for index, item in enumerate(identities)}
    previous_position, previous_completion = -1, None
    for index, event in enumerate(ledger):
        try:
            if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                raise ValueError("Invalid event")
            event_elapsed = _number(event.get("elapsed_wall_seconds"), "event elapsed_wall_seconds")
            if event_elapsed > elapsed_seconds + 1e-6:
                raise ValueError("Event occurs outside the parent batch interval")
            if event.get("batch_id", request["batch_id"]) != request["batch_id"] or event.get(
                    "variant", request["variant"]) != request["variant"]:
                raise ValueError("Event batch identity differs from the request")
            if event["event"] != "query_completed":
                continue
            row = event.get("query_result")
            identity = by_id.get(row.get("query_id")) if isinstance(row, dict) else None
            if identity is None:
                raise ValueError("Completed event has an unknown query identity")
            if any(event.get(name, value) != value for name, value in identity.items()):
                raise ValueError("Completed event identity differs from its query row")
            row = _validated_row(row, identity, request["variant"], elapsed_seconds)
            if row["query_finished_offset"] is None or row["query_finished_offset"] > event_elapsed + 1e-6:
                raise ValueError("Completed event has no completed query interval")
            if identity["query_id"] in recovered:
                raise ValueError("Duplicate completed event for one query")
            position = positions[identity["query_id"]]
            if position <= previous_position or (previous_completion is not None and
                    row["query_started_offset"] < previous_completion):
                raise ValueError("Completed events overlap or violate the sequential schedule")
            recovered[identity["query_id"]] = row
            previous_position, previous_completion = position, event_elapsed
        except (ValueError, TypeError) as exc:
            errors.append(f"event[{index}]: {exc}")

    rows = None
    process_ok = process["returncode"] == 0 and not process["timed_out"]
    if process_ok and worker_result_or_None is not None:
        try:
            worker = worker_result_or_None
            if (not isinstance(worker, dict) or worker.get("schema") != "symbai.frame_batch_worker.v1" or
                    any(worker.get(name) != request[name] for name in ("batch_id", "variant", "budget_seconds")) or
                    worker.get("accounting_unit") != _UNIT or worker.get("regime") != "end_to_end" or
                    not isinstance(worker.get("queries"), list) or len(worker["queries"]) != 3):
                raise ValueError("Worker result batch identity or schema differs from the request")
            rows = [_validated_row(row, identity, request["variant"], elapsed_seconds)
                    for row, identity in zip(worker["queries"], identities)]
            _validate_sequential_rows(rows)
        except (ValueError, TypeError) as exc:
            errors.append("worker_result: " + str(exc))
            rows = None
    source = "worker_result" if rows is not None else "query_completed_event"
    recovered_count = 0
    if rows is None:
        reason = ("hard_process_timeout" if process["timed_out"] else
                  f"worker_exit_{process['returncode']}" if process["returncode"] else
                  "missing_or_invalid_worker_result")
        rows = []
        for identity in identities:
            row = recovered.get(identity["query_id"])
            if row is None:
                row = _missing_row(identity, reason)
                row["record_source"] = "missing"
            else:
                row["record_source"] = source
                recovered_count += 1
            rows.append(row)
    else:
        for row in rows:
            row["record_source"] = source
    over_budget = elapsed_seconds > request["budget_seconds"]
    if process["timed_out"] or over_budget:
        reason = "hard_process_timeout" if process["timed_out"] else "finalization_exceeded_batch_budget"
        for row in rows:
            if row["result"]["status"] in _DECISIVE:
                row["late_candidate_result"] = deepcopy(row["result"])
                row["result"] = {"status": "unknown", "reason": reason}
    status = ("timed_out" if process["timed_out"] else "exceeded_budget" if over_budget else
              "completed" if source == "worker_result" else "recovered" if recovered_count else "failed")
    return {"schema": "symbai.frame_batch.v1", "batch_id": request["batch_id"],
            "variant": request["variant"], "budget_seconds": request["budget_seconds"],
            "accounting_unit": _UNIT, "regime": "end_to_end", "queries": rows,
            "event_ledger": ledger, "charged_seconds": elapsed_seconds,
            "elapsed_wall_seconds": elapsed_seconds, "process_wall_seconds": elapsed_seconds,
            "process": process, "batch_status": status, "validation_errors": errors,
            "type_source": "not_used", "cross_query_application_reuse": False,
            "library_cache_policy": "ordinary_in_process_caches_may_warm"}
