"""Parent accounting/recovery tests with fabricated workers, not extra programs."""

from dataclasses import asdict
from pathlib import Path
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import mechanism_bytes
from scripts import run_instruction_provenance as cli
from src.selective_analysis.contracts import fingerprint, InputRange, Query
from src.selective_analysis.instruction_provenance import build_syntax_provenance
from src.selective_analysis.processes import ProcessOutcome
from src.selective_analysis.workspace import SCRATCH


@pytest.fixture
def fixture():
    folder = SCRATCH / "tests" / ("syntax-parent-" + uuid.uuid4().hex)
    folder.mkdir(parents=True)
    blob, target = mechanism_bytes()
    binary = folder / "unit-syntax.elf"
    binary.write_bytes(blob)
    request = {"schema": "symbai.syntax_request.v1", "binary": str(binary),
               "binary_sha256": cli.file_hash(binary), "entry_rva": 4096, "target_store_rva": 4096 + target}
    graph = build_syntax_provenance(request)
    assert graph["status"] == "available"
    return folder, request, {"graph": graph, "runtime": cli.metadata(),
                             "forbidden_runtime_imports": [], "worker_elapsed_seconds": 0.1}


def fake_process(monkeypatch, candidate, *, returncode=0, timeout=False, clock=None):
    def run(command, log, cap, env):
        assert command[0] and 0 < cap <= 30 and command[1] == "-B"
        if candidate is not None:
            destination = Path(command[command.index("--worker-result") + 1])
            cli.write(destination, candidate)
        if clock is not None:
            clock[0] += 0.2
        return ProcessOutcome(returncode, timeout, 0.2)
    monkeypatch.setattr(cli, "run_bounded", run)


def test_payload_bytes_persist_and_hash_before_parent_clock_closes(monkeypatch, fixture):
    folder, request, candidate = fixture
    clock, write = [10.0], cli.write
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    def charged_write(path, value):
        write(path, value)
        if path.name == "request.json": clock[0] += 0.1
        if path.name == "trial-payload.json": clock[0] += 0.4
        if path.name == "receipt.json": clock[0] += 3
    monkeypatch.setattr(cli, "write", charged_write)
    fake_process(monkeypatch, candidate, clock=clock)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    receipt, payload = row["parent_receipt"], row["payload"]
    assert receipt["status"] == "available" and receipt["charged_seconds"] == pytest.approx(0.7)
    assert receipt["payload_fingerprint"] == fingerprint(payload)
    assert receipt["payload_sha256"] == cli.file_hash(folder / "workers/fixture/trial-payload.json")
    assert cli.read(folder / "workers/fixture/trial-payload.json") == payload
    assert cli.read(folder / "workers/fixture/receipt.json") == receipt
    assert receipt["excluded"] == ["final_accounting_receipt_serialization", "aggregate_copying"]


def test_late_payload_persistence_keeps_candidate_but_marks_unavailable(monkeypatch, fixture):
    folder, request, candidate = fixture
    clock, write = [10.0], cli.write
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    def slow_persist(path, value):
        write(path, value)
        if path.name == "trial-payload.json": clock[0] += 31
    monkeypatch.setattr(cli, "write", slow_persist)
    fake_process(monkeypatch, candidate, clock=clock)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert row["parent_receipt"]["late"] and row["parent_receipt"]["status"] == "unavailable"
    assert row["payload"]["worker_candidate"]["graph"]["status"] == "available"


@pytest.mark.parametrize("returncode,timeout", [(1, False), (-1, True)])
def test_process_failure_cannot_promote_an_available_candidate(monkeypatch, fixture, returncode, timeout):
    folder, request, candidate = fixture
    fake_process(monkeypatch, candidate, returncode=returncode, timeout=timeout)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert row["parent_receipt"]["status"] == "unavailable"
    assert row["payload"]["worker_candidate"] == candidate
    assert row["payload"]["process"]["returncode"] == returncode


def test_missing_worker_retains_planned_identity_and_payload(monkeypatch, fixture):
    folder, request, _ = fixture
    fake_process(monkeypatch, None)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert row["case_id"] == row["payload"]["case_id"] == "fixture"
    assert row["payload"]["source_query_hash"] == "q" * 64
    assert row["parent_receipt"]["status"] == "unavailable"
    assert row["payload"]["worker_candidate"]["graph"]["reason"].startswith("worker_recovery_failed:")


@pytest.mark.parametrize("damage", ["identity", "proof", "neural", "compatibility"])
def test_parent_refuses_available_worker_with_wrong_identity_or_scope(monkeypatch, fixture, damage):
    folder, request, candidate = fixture
    graph = candidate["graph"]
    if damage == "identity": graph["identity"]["entry_rva"] += 1
    elif damage == "proof": graph["property_verification_performed"] = True
    elif damage == "neural": graph["neural_information_used"] = True
    else: graph["tygr_readout_compatibility_validated"] = True
    fake_process(monkeypatch, candidate)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert row["parent_receipt"]["status"] == "unavailable"
    assert (folder / "workers/fixture/worker-result.json").is_file()


@pytest.mark.parametrize("damage", ["empty_graph", "fingerprint", "imports", "runtime"])
def test_corrupt_or_unattributed_graph_cannot_receive_available_receipt(monkeypatch, fixture, damage):
    folder, request, candidate = fixture
    if damage == "empty_graph": candidate["graph"]["nodes"] = []
    elif damage == "fingerprint": candidate["graph"]["syntax_fingerprint"] = "0" * 64
    elif damage == "imports": candidate["forbidden_runtime_imports"] = ["angr"]
    else: candidate["runtime"].pop("pyvex")
    fake_process(monkeypatch, candidate)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert row["parent_receipt"]["status"] == "unavailable"
    assert (folder / "workers/fixture/worker-result.json").is_file()


def test_child_budget_deducts_request_serialization(monkeypatch, fixture):
    folder, request, candidate = fixture
    clock, write, caps = [10.0], cli.write, []
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    def slow_request(path, value):
        write(path, value)
        if path.name == "request.json": clock[0] += 2.5
    def run(command, log, cap, env):
        caps.append(cap)
        cli.write(Path(command[command.index("--worker-result") + 1]), candidate)
        return ProcessOutcome(0, False, 0)
    monkeypatch.setattr(cli, "write", slow_request)
    monkeypatch.setattr(cli, "run_bounded", run)
    row = cli.run_case("fixture", request, "q" * 64, folder)
    assert caps == [27.5]
    assert row["parent_receipt"]["charged_seconds"] == 2.5


@pytest.mark.parametrize("field", ["capacity", "entry_rva", "write_rva", "binary"])
def test_same_named_binary_with_changed_query_or_path_is_rejected(field):
    blob, target = mechanism_bytes()
    import hashlib
    contract = asdict(Query("scalar_span", "scalar_span.elf", hashlib.sha256(blob).hexdigest(),
                           4096, 4096 + target, 8192, 1024, (InputRange("rdi", 0, 1023),)))
    assert cli.validate_frozen_contract(contract) == cli.FROZEN_IDENTITIES["scalar_span"][1]
    contract[field] = "../scalar_span.elf" if field == "binary" else contract[field] + 1
    with pytest.raises(ValueError):
        cli.validate_frozen_contract(contract)
