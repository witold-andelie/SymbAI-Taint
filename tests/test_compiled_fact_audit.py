"""Arithmetic and artifact-boundary tests; no new program proofs or model data."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from src.selective_analysis import compiled_fact_audit as audit
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.operand_mapping import operand_id


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("fact-audit-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def query_and_facts(transform=None, minimum=0, maximum=15):
    query = Query("unit-only-arithmetic", "not_loaded_by_pure_math", "a" * 64,
                  0, 1, 0x2000, 8, (InputRange("rdi", minimum, maximum),))
    anchor = {"kind": "entry_input", "register": "rdi"}
    if transform is not None:
        anchor["transform"] = transform
    facts = {"schema": "symbai.operand_program_facts.v1", "query_hash": query.contract_hash,
             "binary_sha256": query.binary_sha256, "relation": "base_plus_index", "index_scale": 1,
             "write_length_bytes": 1, "evidence_fingerprint": "f" * 64,
             "operands": [{"role": role, "operand_id": operand_id(query, role),
                           "storage": {"kind": "cfa_relative", "cfa_offset": offset, "size_bytes": 8},
                           "anchor": {"kind": "object_base"} if role == "base_pointer" else anchor}
                          for role, offset in (("base_pointer", -24), ("index", -40))]}
    return query, facts


@pytest.mark.parametrize("transform,status,witness", [
    (None, "violation", 8),
    ({"operation": "add_constant", "constant": 4}, "violation", 4),
    ({"operation": "and_constant", "constant": 7}, "excluded_within_scope", None),
])
def test_existing_compiled_patterns_have_conditional_arithmetic_decisions(transform, status, witness):
    query, facts = query_and_facts(transform)
    before = deepcopy(facts)
    result = audit.derive_from_facts(facts, query, 0x402000)
    assert result["derived_status"] == status
    assert result["query_decision_available_after_mapping"] is True
    assert result["mapping_acquisition_cost_role"] == "previously_paid_not_free"
    assert result["no_neural_information_used"] is True
    assert result["new_program_validation_performed"] is False
    assert result["deployment_benefit_measured"] is False
    assert "probability" not in json.dumps(result)
    if witness is not None:
        assert result["derived_witness"] == {"rdi": witness}
        assert result["derived_offset"] == 8
        assert result["derived_address"] == 0x402008
    else:
        assert "derived_witness" not in result
        assert result["offset_interval"] == [0, 7]
    assert facts == before


@pytest.mark.parametrize("mutation", [
    lambda f: f.pop("relation"),
    lambda f: f.update(index_scale=2),
    lambda f: f.update(write_length_bytes=True),
    lambda f: f.update(query_hash="wrong"),
    lambda f: f.update(candidate_scores=[1.0]),
    lambda f: f["operands"].pop(),
    lambda f: f["operands"][0].update(anchor={"kind": "unknown"}),
    lambda f: f["operands"][1].update(anchor={"kind": "entry_input", "register": "rsi"}),
    lambda f: f["operands"][1]["anchor"].update(transform={"operation": "multiply", "constant": 2}),
    lambda f: f["operands"][1]["anchor"].update(transform={"operation": "add_constant", "constant": True}),
])
def test_missing_or_unsupported_facts_remain_unknown(mutation):
    query, facts = query_and_facts()
    mutation(facts)
    result = audit.derive_from_facts(facts, query, 0x402000)
    assert result["derived_status"] == "unknown"
    assert result["query_decision_available_after_mapping"] is False
    assert "derived_witness" not in result


def test_modular_addition_wrap_is_not_treated_as_an_ordinary_interval():
    query, facts = query_and_facts({"operation": "add_constant", "constant": 4}, audit.MAX64 - 2, audit.MAX64)
    assert audit.derive_from_facts(facts, query, 0x402000)["derived_status"] == "unknown"


def test_absolute_wrap_and_wrapping_object_are_outside_the_subset():
    query, facts = query_and_facts(None, audit.MAX64 - 2, audit.MAX64)
    assert audit.derive_from_facts(facts, query, 0x402000)["derived_status"] == "unknown"
    assert audit.derive_from_facts(facts, query, audit.MAX64 - 3)["reason"] == "invalid_or_wrapping_object"


def test_imprecise_interval_without_a_concrete_bad_witness_remains_unknown():
    # The interval is conservative; a reported violation still needs an actual
    # transformed input outside the eight-byte object.
    query, facts = query_and_facts({"operation": "and_constant", "constant": 8}, 8, 9)
    result = audit.derive_from_facts(facts, query, 0x402000)
    assert result["derived_status"] == "violation" and result["derived_witness"] == {"rdi": 8}
    # The interval upper bound is 8, but [4,7] & 8 contains only zero. Neither
    # endpoint is bad, so an overapproximation must never manufacture a witness.
    query, facts = query_and_facts({"operation": "and_constant", "constant": 8}, 4, 7)
    query = replace(query, capacity=4)
    facts["query_hash"] = query.contract_hash
    result = audit.derive_from_facts(facts, query, 0x402000)
    assert result["derived_status"] == "unknown" and "derived_witness" not in result


@pytest.fixture
def bundle_case(tmp_path, monkeypatch):
    query, facts = query_and_facts()
    binary = tmp_path / "unit-only-loader-bytes.bin"
    binary.write_bytes(b"\x90\xc6\x00\x41")
    query = replace(query, binary=str(binary), binary_sha256=file_hash(binary))
    facts.update(query_hash=query.contract_hash, binary_sha256=query.binary_sha256)
    for entry in facts["operands"]:
        entry["operand_id"] = operand_id(query, entry["role"])
    # A format-flow test stub, not newly generated program proof evidence.
    evidence = {"validation": "fresh_symbolic_recheck", "prefix_trace": [{"rva": 0, "bytes": "90"}]}
    raw = {"unit_only_integrity_payload": "not used by deduction"}
    bundle = {"schema": "symbai.operand_types.v1", "query_hash": query.contract_hash,
              "binary_sha256": query.binary_sha256, "use_site_id": query.use_site_id,
              "raw_export": raw, "raw_payload_fingerprint": fingerprint(raw),
              "plan": {"unit_only": True}, "evidence": evidence}
    bundle["bundle_fingerprint"] = fingerprint(bundle)
    calls = []

    def project_facts(q, plan, retained):
        calls.append((q, plan, retained))
        return facts

    monkeypatch.setattr(audit, "operand_program_facts", project_facts)
    instruction = SimpleNamespace(mnemonic="nop", bytes=b"\x90", size=1)
    checker = SimpleNamespace(base=0x400000, object_base=0x402000,
        project=SimpleNamespace(factory=SimpleNamespace(block=lambda *a, **k:
            SimpleNamespace(capstone=SimpleNamespace(insns=[instruction])))))
    from src.selective_analysis import operations
    monkeypatch.setattr(operations, "BinaryChecker", lambda q: checker)
    path = tmp_path / "unit-only-bundle.json"
    return query, bundle, path, calls, instruction


def test_bundle_audit_uses_program_facts_and_preserves_source_bytes(bundle_case):
    query, bundle, path, calls, _ = bundle_case
    path.write_text(json.dumps(bundle), encoding="utf-8")
    before = path.read_bytes()
    result = audit.audit_compiled_facts(query, path)
    assert result["derived_status"] == "violation"
    assert result["derived_witness"] == {"rdi": 8}
    assert len(calls) == 1
    assert result["audit_elapsed_seconds"] >= 0
    assert result["static_trace_guard"] == "matched_contiguous_straight_line_bytes"
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", [
    lambda b: b.update(bundle_fingerprint="bad"),
    lambda b: b["raw_export"].update(changed=True),
    lambda b: b.update(raw_payload_fingerprint="bad"),
    lambda b: b.update(query_hash="wrong"),
])
def test_invalid_bundle_integrity_never_reaches_program_facts(bundle_case, mutation):
    query, bundle, path, calls, _ = bundle_case
    mutation(bundle)
    path.write_text(json.dumps(bundle), encoding="utf-8")
    result = audit.audit_compiled_facts(query, path)
    assert result["derived_status"] == "unknown" and not calls


def test_invalid_recorded_proof_remains_unknown(bundle_case, monkeypatch):
    query, bundle, path, _, _ = bundle_case
    path.write_text(json.dumps(bundle), encoding="utf-8")

    def reject(*args):
        raise ValueError("Incomplete previously recorded proof")

    monkeypatch.setattr(audit, "operand_program_facts", reject)
    result = audit.audit_compiled_facts(query, path)
    assert result["derived_status"] == "unknown" and "Incomplete" in result["reason"]


def test_conditional_prefix_is_outside_the_audit_subset(bundle_case):
    query, bundle, path, _, instruction = bundle_case
    instruction.mnemonic = "ja"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert audit.audit_compiled_facts(query, path)["derived_status"] == "unknown"
