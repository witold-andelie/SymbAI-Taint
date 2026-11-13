"""Authored operation fixtures and independent literal-reference boundaries."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import make_indirection_mechanisms, CASE_IDS
from src.selective_analysis.contracts import Query, InputRange, Checkpoint
from src.selective_analysis.literal_reference import reference_query
from src.selective_analysis.operations import BinaryChecker
from scripts import run_indirection_gate as cli

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("indirection-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


@pytest.fixture
def cases(tmp_path):
    manifest = make_indirection_mechanisms(tmp_path / "authored")
    return {q["query_id"]: Query.from_dict(q, manifest.parent) for q in cli.read(manifest)["queries"]}


def test_mechanisms_are_separate_label_free_queries_with_exact_identities(cases, tmp_path):
    assert set(cases) == set(CASE_IDS) and len({q.contract_hash for q in cases.values()}) == 3
    manifest = cli.read(tmp_path / "authored/queries.json")
    assert all("expected" not in q and "mechanism" not in q for q in manifest["queries"])
    assert cases["scalar_span"].capacity == 1024 and cases["readonly_chain"].capacity == 8
    assert cli.read(tmp_path / "authored/gold.json")["panel"] == "v14_three_authored_capability_mechanisms"


def test_literal_reference_really_uses_literal_ast_registers_and_no_abstract_result(cases, monkeypatch):
    query = replace(cases["readonly_chain"], inputs=(InputRange("rdi", 0, 1),))
    checked = []
    original = BinaryChecker.check
    def spy(self, max_steps, deadline, concrete=None, use_prepared=True):
        assert concrete is not None
        state, symbols = self.new_state(concrete)
        assert all(not symbol.symbolic for symbol in symbols.values())
        assert not state.regs.rdi.symbolic and state.solver.eval(state.regs.rdi) == concrete["rdi"]
        checked.append(dict(concrete))
        return original(self, max_steps, deadline, concrete, use_prepared)
    monkeypatch.setattr(BinaryChecker, "check", spy)
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    monkeypatch.setattr(LocalBoundsChecker, "check", lambda *args: pytest.fail("Abstract output used as reference"))
    result = reference_query(query, time.monotonic() + 15)
    assert result["result"]["status"] == "excluded_within_scope" and result["result"]["complete"] is True
    assert result["reference_mode"] == "exhaustive_literal_BVV_states_and_fresh_rechecks"
    assert len(result["input_receipts"]) == result["domain_cardinality"] == 2
    assert checked == [{"rdi": 0}, {"rdi": 0}, {"rdi": 1}, {"rdi": 1}]
    assert result["native_replay"] == "not_attempted" and result["reference_is_runtime_feature"] is False


def test_negative_pointer_chain_has_freshly_replayed_modeled_witness(cases):
    result = reference_query(replace(cases["readonly_chain_outside"], inputs=(InputRange("rdi", 0, 1),)), time.monotonic() + 15)
    assert result["result"]["status"] == "violation"
    assert result["result"]["witness"] == {"rdi": 1}
    assert result["result"]["validation"] == "concrete_input_modeled_reexecution"


def test_large_domain_reference_remains_fresh_symbolic_complete_scope(cases):
    result = reference_query(cases["scalar_span"], time.monotonic() + 15)
    assert result["reference_mode"] == "fresh_symbolic_expanded"
    assert result["domain_cardinality"] == 1024
    assert result["result"]["status"] == "excluded_within_scope" and result["result"]["complete"] is True


def test_reference_rejects_changed_identity_or_cap(cases):
    q = cases["readonly_chain"]
    with pytest.raises(ValueError):
        reference_query(q, time.monotonic() + 1, enumeration_cap=64)
    with pytest.raises(ValueError, match="identity"):
        reference_query(replace(q, binary_sha256="a" * 64), time.monotonic() + 1)


@pytest.mark.parametrize("change", ["gold", "plan", "proof", "prior_result", "nan_clock"])
def test_worker_rejects_labels_old_proofs_and_invalid_clocks_before_execution(cases, tmp_path, change):
    q = cases["scalar_span"]
    request = {"schema": "symbai.indirection_request.v1", "query": asdict(q), "query_hash": q.contract_hash,
               "method": "interval_only", "started_at": time.monotonic(), "budget_seconds": cli.BUDGET_SECONDS}
    if change == "nan_clock":
        request["started_at"] = float("nan")
    else:
        request[change] = "offline data"
    path = tmp_path / "request.json"
    cli.write(path, request)
    with pytest.raises(ValueError, match="label-free"):
        cli.worker(path, tmp_path / "result.json", tmp_path / "events.jsonl")


def fake_rows(cases):
    gold = {"schema": "symbai.gold.v1", "panel": "v14_three_authored_capability_mechanisms",
            "labels": [{"query_id": q.query_id, "binary_sha256": q.binary_sha256,
                        "expected": "violation" if q.query_id.endswith("outside") else "excluded_within_scope"}
                       for q in cases.values()]}
    references, rows = [], []
    for q in cases.values():
        status = "violation" if q.query_id.endswith("outside") else "excluded_within_scope"
        base = {"query_id": q.query_id, "query_hash": q.contract_hash, "binary_sha256": q.binary_sha256,
                "method": "literal_reference", "result": {"status": status},
                "parent_elapsed_through_recovery_seconds": .25, "checkpoint_id": Checkpoint(q.contract_hash).checkpoint_id}
        references.append(base)
        rows.extend({**deepcopy(base), "method": method, "result": {"status": "unknown"}} for method in cli.METHODS)
    return rows, references, gold


def test_offline_evaluation_preserves_unknowns_and_blocks_an_unsound_exclusion(cases):
    rows, references, gold = fake_rows(cases)
    summary = cli.evaluate(rows, references, gold)
    assert summary["runtime_records"] == 12 and summary["separate_reference_records"] == 3
    assert summary["correctness_review_required"] is False
    assert all(row["unknown"] == 3 for row in summary["comparisons"])
    next(row for row in rows if row["query_id"].endswith("outside"))["result"]["status"] = "excluded_within_scope"
    summary = cli.evaluate(rows, references, gold)
    assert summary["correctness_review_required"] is True
    assert len(summary["wrong_decisions"]) == len(summary["reference_disagreements"]) == 1


@pytest.mark.parametrize("change", ["missing_row", "missing_ref", "duplicate_row", "wrong_hash", "wrong_panel", "unresolved_ref"])
def test_offline_evaluation_rejects_denominator_or_provenance_changes(cases, change):
    rows, refs, gold = fake_rows(cases)
    if change == "missing_row":
        rows.pop()
    elif change == "missing_ref":
        refs.pop()
    elif change == "duplicate_row":
        rows[1] = rows[0]
    elif change == "wrong_hash":
        refs[0]["query_hash"] = "changed"
    elif change == "wrong_panel":
        gold["panel"] = "primary_twelve_mechanisms"
    else:
        refs[0]["result"]["status"] = "unknown"
        assert cli.evaluate(rows, refs, gold)["correctness_review_required"] is True
        return
    with pytest.raises(ValueError):
        cli.evaluate(rows, refs, gold)
