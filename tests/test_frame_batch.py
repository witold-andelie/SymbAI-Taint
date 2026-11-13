"""Batch accounting and isolation; ELF fixtures here are unit tests, not pilot inputs."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, DATA, TEXT, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis import frame_batch
from src.selective_analysis.processes import ProcessOutcome


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def batch_queries():
    # Ordinary D: workspace directories avoid the managed Windows tmpdir ACLs.
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("batch-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    queries = []
    for index, transform in enumerate(("48 83 65 e8 07", "48 83 45 e8 04", "48 83 65 e8 03")):
        code = Code()
        code.emit("f3 0f 1e fa 55 48 89 e5 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + transform + " 48 8b 55 f8 48 8b 45 e8 48 01 d0")
        code.write_offset = len(code.data)
        code.emit("c6 00 41 c3")
        path = folder / f"unit-{index}.elf"
        path.write_bytes(elf_bytes(code.finish()))
        queries.append(Query(f"unit-batch-{index}", str(path), file_hash(path), TEXT - BASE,
                             TEXT - BASE + code.write_offset, DATA - BASE, 8,
                             (InputRange("rdi", 0, 15),)))
    return queries


def request_for(queries, variant="frame_bounds_only", budget=15.0, started=100.0):
    return {"schema": "symbai.frame_batch_request.v1", "batch_id": "unit-batch",
            "variant": variant, "budget_seconds": budget, "started_at": started,
            "queries": [{"query": asdict(query), "query_hash": query.contract_hash} for query in queries]}


def completed_row(request, index, status="excluded_within_scope"):
    entry = request["queries"][index]
    query = entry["query"]
    row = {"query_id": query["query_id"], "query_hash": entry["query_hash"],
           "binary_sha256": query["binary_sha256"], "result": {"status": status, "unit_evidence": index},
           "query_started_offset": index + 1.0, "query_finished_offset": index + 1.25,
           "query_elapsed_seconds": 0.25}
    row["control_record"] = control_record(row, request["variant"], row["result"], elapsed=0.1)
    return row


def control_record(identity, variant, result, elapsed=0.0):
    return {"schema": "symbai.run.v1",
            **{key: identity[key] for key in ("query_id", "query_hash", "binary_sha256")},
            "variant": variant, "regime": "end_to_end", "result": result,
            "availability": "available", "type_source": "not_used", "elapsed_wall_seconds": elapsed,
            "ledger": [{"event": "run_finished", "query_id": identity["query_id"], "variant": variant,
                        "elapsed_wall_seconds": elapsed, "availability": "available", "result": result}]}


def worker_for(request):
    return {"schema": "symbai.frame_batch_worker.v1", "batch_id": request["batch_id"],
            "variant": request["variant"], "budget_seconds": request["budget_seconds"],
            "accounting_unit": "three_query_cold_batch", "regime": "end_to_end",
            "queries": [completed_row(request, i) for i in range(3)], "elapsed_wall_seconds": 3.5}


def completed_event(request, row):
    return {"event": "query_completed", "batch_id": request["batch_id"], "variant": request["variant"],
            **{key: row[key] for key in ("query_id", "query_hash", "binary_sha256")},
            "elapsed_wall_seconds": row["query_finished_offset"] + 0.01, "query_result": deepcopy(row)}


def finalize(request, worker=None, events=(), returncode=0, timed_out=False, elapsed=5.0):
    return frame_batch.finalize_batch(request, worker, events, ProcessOutcome(returncode, timed_out, 4.0), elapsed)


@pytest.mark.parametrize("method", frame_batch.METHODS)
def test_real_elf_semantics_and_new_projects_for_every_query(batch_queries, monkeypatch, method):
    from src.selective_analysis.operations import BinaryChecker
    created = []
    original = BinaryChecker.__init__

    def track(checker, query):
        original(checker, query)
        created.append((query.query_id, query, checker.project))
        assert checker._prepared_prefix is None

    monkeypatch.setattr(BinaryChecker, "__init__", track)
    request = request_for(batch_queries, method, budget=20.0, started=time.monotonic())
    events = []
    worker = frame_batch.run_worker(request, events.append)
    elapsed = time.monotonic() - request["started_at"]
    record = finalize(request, worker, events, elapsed=elapsed)
    expected = ["excluded_within_scope", "unknown" if method == "frame_bounds_only" else "violation",
                "excluded_within_scope"]
    assert [row["result"]["status"] for row in record["queries"]] == expected
    assert record["batch_status"] == "completed"
    assert record["validation_errors"] == []
    # Keep the objects alive and compare identity, including validation projects.
    assert len({id(project) for _, _, project in created}) == len(created)
    for query in batch_queries:
        own = [(obj, project) for query_id, obj, project in created if query_id == query.query_id]
        assert own
        assert all(obj is not query for obj, _ in own)
        assert not {id(obj) for obj, _ in own} & {
            id(obj) for other_id, obj, _ in created if other_id != query.query_id}
    completed = [event for event in events if event["event"] == "query_completed"]
    assert [event["query_result"] for event in completed] == worker["queries"]
    assert all(row["control_record"]["type_source"] == "not_used" for row in worker["queries"])
    assert all(row["control_record"]["costs_seconds"]["type_acquisition"] == 0 for row in worker["queries"])
    for row in worker["queries"]:
        control = row["control_record"]
        assert control["budget_seconds"] <= request["budget_seconds"] - row["query_started_offset"]
        assert row["query_elapsed_seconds"] >= control["elapsed_wall_seconds"]
        if method == "frame_bounds_then_expanded" and row["query_id"] == batch_queries[1].query_id:
            assert [e["operation_id"] for e in control["ledger"] if e["event"] == "action_selected"] == [
                "frame_bounds", "expanded_paths"]
            assert row["result"]["reused_prefix_steps"] == row["result"]["validation_reused_prefix_steps"] == 0


@pytest.mark.parametrize("extra", ["expected", "gold", "labels", "type_artifact", "online_config",
                                   "allow_synthetic", "regime"])
def test_request_rejects_every_extra_root_input(batch_queries, extra):
    request = request_for(batch_queries)
    request[extra] = "forbidden"
    with pytest.raises(ValueError, match="exactly"):
        frame_batch.run_worker(request, lambda event: pytest.fail("Invalid request emitted an event"))
    with pytest.raises(ValueError, match="exactly"):
        finalize(request)


@pytest.mark.parametrize("location", ["entry", "query", "input"])
def test_nested_labels_and_type_inputs_are_not_runtime_fields(batch_queries, location):
    request = request_for(batch_queries)
    target = request["queries"][0]
    if location in ("query", "input"):
        target = target["query"]
    if location == "input":
        target = target["inputs"][0]
    target["expected"] = "violation"
    with pytest.raises(ValueError, match="exactly"):
        finalize(request)


@pytest.mark.parametrize("change", ["too_few", "too_many", "duplicate", "wrong_hash", "bad_schema",
                                    "bad_method", "zero_budget", "nan_budget", "bool_budget"])
def test_request_has_fixed_denominator_and_contract_hashes(batch_queries, change):
    request = request_for(batch_queries)
    if change == "too_few":
        request["queries"].pop()
    elif change == "too_many":
        request["queries"].append(deepcopy(request["queries"][0]))
    elif change == "duplicate":
        request["queries"][1] = deepcopy(request["queries"][0])
    elif change == "wrong_hash":
        request["queries"][0]["query_hash"] = "0" * 64
    elif change == "bad_schema":
        request["schema"] = "symbai.run.v1"
    elif change == "bad_method":
        request["variant"] = "A"
    else:
        request["budget_seconds"] = {"zero_budget": 0, "nan_budget": float("nan"), "bool_budget": True}[change]
    with pytest.raises(ValueError):
        finalize(request)


def test_parent_full_time_is_charged_and_finalizer_is_pure(batch_queries, monkeypatch):
    request = request_for(batch_queries)
    worker = worker_for(request)
    events = [completed_event(request, row) for row in worker["queries"]]
    originals = deepcopy((request, worker, events))
    monkeypatch.setattr(frame_batch.time, "monotonic", lambda: pytest.fail("Finalizer read a clock"))
    monkeypatch.setattr(Query, "from_dict", lambda *a, **k: pytest.fail("Finalizer opened a query binary"))
    record = finalize(request, worker, events, elapsed=14.5)
    assert record["charged_seconds"] == record["elapsed_wall_seconds"] == record["process_wall_seconds"] == 14.5
    assert record["charged_seconds"] > worker["elapsed_wall_seconds"]
    assert record["charged_seconds"] > sum(row["query_elapsed_seconds"] for row in record["queries"])
    assert record["schema"] == "symbai.frame_batch.v1"
    assert record["accounting_unit"] == "three_query_cold_batch" and record["regime"] == "end_to_end"
    assert (request, worker, events) == originals


def test_no_worker_and_no_events_preserves_all_request_identities(batch_queries):
    request = request_for(batch_queries)
    record = finalize(request, returncode=-9, timed_out=True, elapsed=15.4)
    assert record["batch_status"] == "timed_out"
    assert record["charged_seconds"] == 15.4
    assert len(record["queries"]) == 3
    for entry, row in zip(request["queries"], record["queries"]):
        assert row["query_id"] == entry["query"]["query_id"]
        assert row["query_hash"] == entry["query_hash"]
        assert row["binary_sha256"] == entry["query"]["binary_sha256"]
        assert row["result"]["status"] == "unknown"
        assert row["query_started_offset"] is row["query_finished_offset"] is None


def test_failed_process_ignores_stale_worker_success_and_recovers_only_flushed_rows(batch_queries):
    request = request_for(batch_queries)
    worker = worker_for(request)
    event = completed_event(request, worker["queries"][1])
    record = finalize(request, worker, [event], returncode=17)
    assert record["batch_status"] == "recovered"
    assert [row["result"]["status"] for row in record["queries"]] == ["unknown", "excluded_within_scope", "unknown"]
    assert record["queries"][1]["record_source"] == "query_completed_event"
    assert record["queries"][0]["record_source"] == record["queries"][2]["record_source"] == "missing"
    assert record["event_ledger"] == [event]


def test_missing_result_and_partial_event_prefix_recovery(batch_queries):
    request = request_for(batch_queries)
    rows = [completed_row(request, 0, "unknown"), completed_row(request, 1, "violation")]
    events = [completed_event(request, row) for row in rows]
    events.append({"event": "query_completed", "elapsed_wall_seconds": 3.3, "query_result": {"query_id": batch_queries[2].query_id}})
    record = finalize(request, events=events)
    assert record["batch_status"] == "recovered"
    assert [row["result"]["status"] for row in record["queries"]] == ["unknown", "violation", "unknown"]
    assert len(record["event_ledger"]) == 3 and len(record["validation_errors"]) == 1


@pytest.mark.parametrize("timed_out,elapsed", [(False, 15.000001), (True, 5.0), (True, 15.4)])
def test_parent_deadline_or_timeout_clears_all_decisive_results(batch_queries, timed_out, elapsed):
    request = request_for(batch_queries)
    worker = worker_for(request)
    worker["queries"][1]["result"].update(status="violation", witness={"rdi": 15})
    worker["queries"][2]["result"].update(status="unknown", reason="unsupported")
    events = [completed_event(request, row) for row in worker["queries"]]
    record = finalize(request, worker, events, timed_out=timed_out, elapsed=elapsed)
    assert all(row["result"]["status"] == "unknown" for row in record["queries"])
    assert [row["late_candidate_result"]["status"] for row in record["queries"][:2]] == [
        "excluded_within_scope", "violation"]
    assert "late_candidate_result" not in record["queries"][2]
    assert record["queries"][2]["result"]["reason"] == "unsupported"
    assert record["charged_seconds"] == elapsed


def test_exact_budget_is_allowed_and_overrun_recovery_is_late(batch_queries):
    request = request_for(batch_queries)
    worker = worker_for(request)
    assert finalize(request, worker, elapsed=15)["queries"][0]["result"]["status"] == "excluded_within_scope"
    event = completed_event(request, worker["queries"][0])
    late = finalize(request, worker, [event], returncode=7, elapsed=16)
    assert late["batch_status"] == "exceeded_budget"
    assert all(row["result"]["status"] == "unknown" for row in late["queries"])
    assert late["queries"][0]["late_candidate_result"] == worker["queries"][0]["result"]
    assert all("late_candidate_result" not in row for row in late["queries"][1:])


@pytest.mark.parametrize("field", ["query_id", "query_hash", "binary_sha256"])
def test_mismatched_completed_identity_cannot_recover_a_decision(batch_queries, field):
    request = request_for(batch_queries)
    row = completed_row(request, 0)
    event = completed_event(request, row)
    event["query_result"][field] = "invalid"
    record = finalize(request, events=[event], returncode=9)
    assert record["batch_status"] == "failed"
    assert all(row["result"]["status"] == "unknown" for row in record["queries"])
    assert record["validation_errors"]


@pytest.mark.parametrize("kind", ["row_identity", "batch_identity", "wrong_schema", "row_order", "control_identity",
                                  "missing_row", "future_finish", "false_unstarted"])
def test_invalid_worker_output_preserves_denominator_and_uses_valid_events(batch_queries, kind):
    request = request_for(batch_queries)
    worker = worker_for(request)
    event = completed_event(request, worker["queries"][2])
    if kind == "row_identity":
        worker["queries"][0]["binary_sha256"] = "0" * 64
    elif kind == "batch_identity":
        worker["batch_id"] = "other-batch"
    elif kind == "wrong_schema":
        worker["schema"] = "symbai.frame_batch.v1"
    elif kind == "row_order":
        worker["queries"].reverse()
    elif kind == "control_identity":
        worker["queries"][0]["control_record"] = {"schema": "symbai.run.v1", "query_id": "other"}
    elif kind == "missing_row":
        worker["queries"].pop()
    elif kind == "future_finish":
        worker["queries"][0].update(query_finished_offset=10.0, query_elapsed_seconds=9.0)
    elif kind == "false_unstarted":
        worker["queries"][0].update(query_started_offset=None, query_finished_offset=None, query_elapsed_seconds=None)
    record = finalize(request, worker, [event])
    assert len(record["queries"]) == 3 and record["batch_status"] == "recovered"
    assert [row["result"]["status"] for row in record["queries"]] == ["unknown", "unknown", "excluded_within_scope"]
    assert any("worker_result" in error for error in record["validation_errors"])


def test_worker_passes_remaining_global_budget_and_parent_clock_events(batch_queries, monkeypatch):
    class Clock:
        now = 110.0

    clock = Clock()
    monkeypatch.setattr(frame_batch.time, "monotonic", lambda: clock.now)
    calls = []

    def control(query, method, budget_seconds, regime, started_at, record_event):
        calls.append((query, budget_seconds, started_at))
        record_event({"event": "action_selected", "query_id": query.query_id, "variant": method,
                      "elapsed_wall_seconds": 0.25, "operation_id": "expanded_paths"})
        clock.now += 2.0
        return control_record({"query_id": query.query_id, "query_hash": query.contract_hash,
                               "binary_sha256": query.binary_sha256}, method,
                              {"status": "excluded_within_scope"}, elapsed=2.0)

    monkeypatch.setattr(frame_batch, "run_control", control)
    monkeypatch.setattr(frame_batch, "run_frame_control", lambda *a, **k: pytest.fail("Wrong control dispatch"))
    request = request_for(batch_queries, "expanded_only", budget=20.0, started=100.0)
    events = []
    worker = frame_batch.run_worker(request, events.append)
    assert [budget for _, budget, _ in calls] == [10.0, 8.0, 6.0]
    assert len({id(query) for query, _, _ in calls}) == 3
    assert [row["query_started_offset"] for row in worker["queries"]] == [10.0, 12.0, 14.0]
    assert [row["query_elapsed_seconds"] for row in worker["queries"]] == [2.0] * 3
    details = [event for event in events if event["event"] == "action_selected"]
    assert [event["elapsed_wall_seconds"] for event in details] == [10.0, 12.0, 14.0]
    assert all(event["query_elapsed_wall_seconds"] == 0.25 for event in details)
    assert finalize(request, worker, events, elapsed=16.5)["validation_errors"] == []


def test_unstarted_queries_keep_identities_and_do_not_create_query_objects(batch_queries, monkeypatch):
    request = request_for(batch_queries, started=100.0, budget=15.0)
    monkeypatch.setattr(frame_batch.time, "monotonic", lambda: 116.0)
    monkeypatch.setattr(Query, "from_dict", lambda *a, **k: pytest.fail("Expired query was prepared"))
    events = []
    worker = frame_batch.run_worker(request, events.append)
    assert len(worker["queries"]) == 3
    assert all(row["result"]["status"] == "unknown" for row in worker["queries"])
    assert [row["query_id"] for row in worker["queries"]] == [query.query_id for query in batch_queries]
    assert all(row["query_started_offset"] is None for row in worker["queries"])
    assert not any(event["event"] == "query_completed" for event in events)


def test_invalid_binary_becomes_unknown_without_removing_other_queries(batch_queries, monkeypatch):
    # An input can change after the parent prepared the request.  Recheck it in
    # its own query and preserve the original declared hash on the failed row.
    request = request_for(batch_queries, started=time.monotonic(), budget=20.0)
    Path(batch_queries[0].binary).write_bytes(b"changed input")

    def control(query, method, budget_seconds, regime, started_at, record_event):
        return {"schema": "symbai.run.v1", "query_id": query.query_id, "query_hash": query.contract_hash,
                "binary_sha256": query.binary_sha256, "variant": method, "regime": regime,
                "result": {"status": "unknown", "reason": "unit_control"}}

    monkeypatch.setattr(frame_batch, "run_frame_control", control)
    events = []
    worker = frame_batch.run_worker(request, events.append)
    assert len(worker["queries"]) == 3
    assert "Binary hash differs" in worker["queries"][0]["result"]["reason"]
    assert worker["queries"][0]["binary_sha256"] == batch_queries[0].binary_sha256
    assert "control_record" not in worker["queries"][0]
    assert all("control_record" in row for row in worker["queries"][1:])
    assert len([event for event in events if event["event"] == "query_completed"]) == 3


def test_completed_event_is_emitted_before_worker_result_can_exist(batch_queries, monkeypatch):
    request = request_for(batch_queries, started=time.monotonic(), budget=20.0)

    def control(query, method, budget_seconds, regime, started_at, record_event):
        return control_record({"query_id": query.query_id, "query_hash": query.contract_hash,
                               "binary_sha256": query.binary_sha256}, method,
                              {"status": "violation", "witness": {"rdi": 15}})

    monkeypatch.setattr(frame_batch, "run_frame_control", control)
    events = []

    def crash_after_flush(event):
        events.append(event)
        if event["event"] == "query_completed":
            raise SystemExit("simulated crash after successful flush")

    with pytest.raises(SystemExit, match="after successful flush"):
        frame_batch.run_worker(request, crash_after_flush)
    record = finalize(request, events=events, returncode=9, elapsed=time.monotonic() - request["started_at"])
    assert [row["result"]["status"] for row in record["queries"]] == ["violation", "unknown", "unknown"]
    assert record["batch_status"] == "recovered"


@pytest.mark.parametrize("source", ["worker", "event"])
@pytest.mark.parametrize("bad_control", ["missing", "truncated", "no_completion", "wrong_completion",
                                        "unavailable", "types_used", "outside_query_interval"])
def test_decisive_rows_require_complete_matching_control_evidence(batch_queries, source, bad_control):
    request = request_for(batch_queries)
    worker = worker_for(request)
    bad = worker["queries"][0]
    if bad_control == "missing":
        del bad["control_record"]
    elif bad_control == "truncated":
        bad["control_record"] = {"schema": "symbai.run.v1"}
    elif bad_control == "no_completion":
        bad["control_record"]["ledger"] = []
    elif bad_control == "wrong_completion":
        bad["control_record"]["ledger"][-1]["query_id"] = batch_queries[1].query_id
    elif bad_control == "unavailable":
        bad["control_record"]["availability"] = "execution_failed"
    elif bad_control == "types_used":
        bad["control_record"]["type_source"] = "neural"
    else:
        bad["control_record"]["elapsed_wall_seconds"] = 1.0
    events = [completed_event(request, worker["queries"][2])]
    if source == "event":
        events.insert(0, completed_event(request, bad))
        worker = None
    record = finalize(request, worker, events)
    assert len(record["queries"]) == 3
    assert [row["result"]["status"] for row in record["queries"]] == [
        "unknown", "unknown", "excluded_within_scope"]
    assert record["validation_errors"] and record["batch_status"] == "recovered"


@pytest.mark.parametrize("kind", ["overlap", "time_inversion", "started_after_unstarted"])
def test_worker_sequential_intervals_reject_invalid_schedule_and_recover_events(batch_queries, kind):
    request = request_for(batch_queries)
    worker = worker_for(request)
    valid = completed_event(request, worker["queries"][0])
    if kind == "overlap":
        worker["queries"][1].update(query_started_offset=1.1, query_finished_offset=1.35)
    elif kind == "time_inversion":
        worker["queries"][1].update(query_started_offset=0.0, query_finished_offset=0.25)
    else:
        worker["queries"][0] = {**{key: worker["queries"][0][key] for key in
                                   ("query_id", "query_hash", "binary_sha256")},
                                "result": {"status": "unknown", "reason": "unstarted"},
                                "query_started_offset": None, "query_finished_offset": None,
                                "query_elapsed_seconds": None}
    record = finalize(request, worker, [valid])
    assert record["batch_status"] == "recovered" and len(record["queries"]) == 3
    assert [row["result"]["status"] for row in record["queries"]] == [
        "excluded_within_scope", "unknown", "unknown"]
    assert any("sequential schedule" in error for error in record["validation_errors"])


@pytest.mark.parametrize("kind", ["overlap", "time_inversion", "event_order_inversion", "before_prior_flush"])
def test_recovery_rejects_overlapping_or_out_of_order_completed_events(batch_queries, kind):
    request = request_for(batch_queries)
    first, second, third = [completed_row(request, index) for index in range(3)]
    if kind == "overlap":
        second.update(query_started_offset=1.1, query_finished_offset=1.35)
    elif kind == "time_inversion":
        second.update(query_started_offset=0.0, query_finished_offset=0.25)
    elif kind == "before_prior_flush":
        second.update(query_started_offset=1.255, query_finished_offset=1.505)
    events = [completed_event(request, row) for row in (first, second, third)]
    if kind == "event_order_inversion":
        events[0], events[1] = events[1], events[0]
    record = finalize(request, events=events, returncode=4)
    expected = (["unknown", "excluded_within_scope", "excluded_within_scope"] if kind == "event_order_inversion"
                else ["excluded_within_scope", "unknown", "excluded_within_scope"])
    assert [row["result"]["status"] for row in record["queries"]] == expected
    assert len(record["queries"]) == 3 and record["batch_status"] == "recovered"
    assert any("sequential schedule" in error for error in record["validation_errors"])
