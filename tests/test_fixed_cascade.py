"""Fixed flow, persistence and failure guards; fabricated clocks are not experiment data."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import make_indirection_mechanisms
from src.selective_analysis.contracts import Query, fingerprint, file_hash
from src.selective_analysis import fixed_cascade as cascade
from scripts import run_fixed_cascade as cli

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("cascade-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    return folder


@pytest.fixture
def cases(tmp_path):
    manifest = make_indirection_mechanisms(tmp_path / "authored")
    return {q["query_id"]: Query.from_dict(q, manifest.parent) for q in cli.read(manifest)["queries"]}


@pytest.fixture
def versions(monkeypatch):
    value = {name: "fabricated-unit" for name in ("python", "executable", "platform", "angr", "capstone", "pyelftools")}
    monkeypatch.setattr(cascade, "runtime_versions", lambda: value)
    return value


@pytest.mark.parametrize("qid,expected,operations", [
    ("scalar_span", "excluded_within_scope", ["interval"]),
    ("readonly_chain", "excluded_within_scope", ["interval", "finite_readonly"]),
    ("readonly_chain_outside", "violation", ["interval", "finite_readonly", "expanded"]),
])
def test_real_authored_mechanisms_take_fixed_validated_fallback(cases, versions, qid, expected, operations):
    row = cascade.run_query(cases[qid], "fixed_cascade", 0, time.monotonic())
    assert row["worker_result"]["status"] == expected
    assert [a["operation"] for a in row["attempts"]] == operations
    assert all(a["entry_basis"] == "fresh_function_entry_no_reused_facts" for a in row["attempts"])
    assert row["runtime_versions"] == versions
    assert sum(row["worker_costs_seconds"].values()) <= row["worker_elapsed_seconds"] + .001
    if expected == "violation":
        assert row["worker_result"]["validation"] == "concrete_input_modeled_reexecution"
        assert row["worker_result"]["validation_reused_prefix_steps"] == 0


def test_unknown_and_failed_attempts_are_paid_and_do_not_stop(cases, versions, monkeypatch):
    def attempt(query, operation, deadline):
        status = "excluded_within_scope" if operation == "expanded" else "unknown"
        return {"operation": operation, "result": {"status": status},
                "costs_seconds": {"preparation": .001, "execution": .002, "validation": .003},
                "elapsed_seconds": .006}
    monkeypatch.setattr(cascade, "execute_operation", attempt)
    row = cascade.run_query(cases["scalar_span"], "fixed_cascade", 2, time.monotonic())
    assert [a["operation"] for a in row["attempts"]] == list(cascade.METHODS["fixed_cascade"])
    assert row["worker_costs_seconds"]["execution"] == pytest.approx(.006)
    assert row["worker_costs_seconds"]["preparation"] == pytest.approx(.003)


def test_no_recognized_validation_remains_unknown(cases, monkeypatch):
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    monkeypatch.setattr(LocalBoundsChecker, "validate", lambda self, result, deadline: {"status": "excluded_within_scope", "complete": True})
    attempt = cascade.execute_operation(cases["scalar_span"], "interval", time.monotonic() + 5)
    assert attempt["result"]["status"] == "unknown"
    assert "fresh validation" in attempt["result"]["reason"]


def test_preparation_exception_is_recorded_as_unknown(cases, monkeypatch):
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    def failed(self, query):
        raise ValueError("authored failure")
    monkeypatch.setattr(LocalBoundsChecker, "__init__", failed)
    attempt = cascade.execute_operation(cases["scalar_span"], "interval", time.monotonic() + 5)
    assert attempt["result"]["status"] == "unknown" and "authored failure" in attempt["result"]["reason"]
    assert attempt["costs_seconds"]["preparation"] > 0


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), -1, True])
def test_invalid_parent_clock_cannot_disable_deadline(cases, versions, clock):
    with pytest.raises(ValueError, match="clock"):
        cascade.run_query(cases["scalar_span"], "fixed_cascade", 0, clock)


def test_exhausted_budget_never_starts_an_operation(cases, versions, monkeypatch):
    monkeypatch.setattr(cascade, "execute_operation", lambda *args: pytest.fail("Execution after deadline"))
    row = cascade.run_query(cases["scalar_span"], "fixed_cascade", 0, time.monotonic() - 31)
    assert row["worker_result"]["status"] == "unknown" and row["attempts"] == []


def request_for(query):
    identity = {"query_hash": query.contract_hash, "method": "fixed_cascade", "repetition": 0}
    return {"schema": "symbai.cascade_request.v1", "query": asdict(query), **identity,
            "started_at": time.monotonic(), "budget_seconds": 30.0, "request_id": fingerprint(identity)}


@pytest.mark.parametrize("change", ["gold", "types", "evidence", "wrong_hash", "wrong_rep", "bad_clock"])
def test_request_rejects_labels_neural_inputs_and_identity_changes(cases, change):
    request = request_for(cases["scalar_span"])
    if change == "wrong_hash":
        request["query_hash"] = "changed"
    elif change == "wrong_rep":
        request["repetition"] = True
    elif change == "bad_clock":
        request["started_at"] = float("nan")
    else:
        request[change] = {"status": "already_known"}
    with pytest.raises(ValueError):
        cli.validate_request(request)


def test_exact_payload_bytes_and_parent_late_demotion_preserve_worker_evidence(tmp_path):
    payload = {"worker_result": {"status": "excluded_within_scope", "certificate": "unit only"},
               "cost_measurement_complete": True, "runtime_versions": {"availability": "unit"}}
    path = tmp_path / "payload.json"
    cli.write(path, payload)
    expected = json.dumps(payload, indent=2).encode("utf-8")
    assert path.read_bytes() == expected
    process = {"returncode": 0, "timed_out": False}
    original = deepcopy(payload)
    row = cli.finalize_payload(payload, process, 30.01, file_hash(path))
    assert row["result"]["status"] == "unknown"
    assert row["worker_result"]["status"] == "excluded_within_scope"
    assert row["parent_receipt"]["late"] is True
    assert row["parent_receipt"]["worker_payload_fingerprint"] == fingerprint(payload)
    assert hashlib.sha256(expected).hexdigest() == row["parent_receipt"]["payload_sha256"]
    assert payload == original


@pytest.mark.parametrize("exitcode,timedout", [(1, False), (0, True)])
def test_worker_failure_or_timeout_is_not_counted_as_resolved(exitcode, timedout):
    row = cli.finalize_payload({"worker_result": {"status": "violation"}, "cost_measurement_complete": True},
                               {"returncode": exitcode, "timed_out": timedout}, 1.0, "a" * 64)
    assert row["result"]["status"] == "unknown"


def test_snapshots_relocate_only_binary_path_and_preserve_all_bytes(tmp_path):
    source = tmp_path / "retained-v14"
    make_indirection_mechanisms(source / "mechanisms")
    output = tmp_path / "new-run"
    output.mkdir()
    queries, hashes = cli.snapshot_inputs(source, output)
    original = [Query.from_dict(q, source / "mechanisms") for q in cli.read(source / "mechanisms/queries.json")["queries"]]
    assert {q.contract_hash for q in queries} == {q.contract_hash for q in original}
    assert len(hashes) == 5
    assert all(file_hash(source / "mechanisms" / name) == file_hash(output / "inputs" / name) == digest for name, digest in hashes.items())
    assert all(Path(q.binary).parent == output / "inputs" for q in queries)


def test_failed_worker_recovers_dict_events_and_ignores_json_scalars(cases, tmp_path, monkeypatch):
    from src.selective_analysis import processes
    query = cases["scalar_span"]
    def failed(command, log_path, timeout):
        event = {"event": "operation_finished", "query_hash": query.contract_hash,
                 "method": "fixed_cascade", "repetition": 0,
                 "attempt": {"operation": "interval", "result": {"status": "unknown"},
                             "costs_seconds": {"preparation": .001, "execution": 0, "validation": 0},
                             "elapsed_seconds": .001}}
        lines = ["[]", "1", "null", "incomplete-json", json.dumps(event),
                 json.dumps({**event, "repetition": 2})]
        (log_path.parent / "events.jsonl").write_text("\n".join(lines), encoding="utf-8")
        return processes.ProcessOutcome(1, False, .01)
    monkeypatch.setattr(processes, "run_bounded", failed)
    row = cli.run_isolated(query, "fixed_cascade", 0, tmp_path / "output")
    assert row["result"]["status"] == "unknown" and row["cost_measurement_complete"] is False
    assert [a["operation"] for a in row["attempts"]] == ["interval"]
    assert row["runtime_versions"]["availability"] == "unavailable"
    assert row["parent_receipt"]["process"]["returncode"] == 1
    payload = {k: v for k, v in row.items() if k not in ("result", "parent_receipt")}
    assert hashlib.sha256(json.dumps(payload, indent=2).encode("utf-8")).hexdigest() == row["parent_receipt"]["payload_sha256"]


@pytest.mark.parametrize("bad", [[], 1, None])
def test_non_object_request_is_explicitly_rejected(bad):
    with pytest.raises(ValueError):
        cli.validate_request(bad)
