"""Compiled-query protocol tests; handcrafted ELF and candidate fixtures are unit data only."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from scripts.run_compiled_queries import offline_summary, validate_export, MODEL_HASH
from src.selective_analysis import compiled_queries as cq
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis.operand_mapping import verify_operand_plan, map_operand_candidates, load_operand_views
from src.selective_analysis.operations import BinaryChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module", params=("add_constant", "and_constant"))
def case(request):
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("compiled-unit-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    operation, constant = request.param, 4 if request.param == "add_constant" else 7
    code = Code()
    code.emit("55 48 89 e5 48 89 7d e8")
    code.emit("48 83 45 e8 04" if operation == "add_constant" else "48 83 65 e8 07")
    code.lea()
    code.emit("48 89 45 f8 48 8b 55 f8 48 8b 45 e8 48 01 d0")
    code.write_offset = len(code.data)
    code.emit("c6 00 41 c3")
    binary = folder / "unit.elf"
    binary.write_bytes(elf_bytes(code.finish()))
    query = Query("unit-" + operation, str(binary), file_hash(binary), TEXT - BASE,
        TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", 0, 15),))
    records = []
    # Deliberately wrong names and pointer predictions for both roles: neither can select the binding.
    for prediction, offset in (("a-index", -40), ("z-base", -24)):
        records.append({"prediction_id": prediction, "locator_variable_name": "misleading_name",
            "function_address": TEXT, "locations": [{"low_pc": TEXT, "high_pc": TEXT + len(code.data),
                "location_class": "CfaLocation", "location_register": None, "location_argument": offset}],
            "score_kind": "raw_logits", "candidates": [
                {"class_id": 0, "rank": 1, "label": "char*", "raw_score": 2.0},
                {"class_id": 1, "rank": 2, "label": "void*", "raw_score": 1.0}]})
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256, "acquisition_id": "unit-nonce",
        "provenance": {"source": "tygr_glowgnn", "model_sha256": MODEL_HASH, "decoder": "independent",
            "locator": "dwarf_assisted", "flatten_vars": True, "ground_truth_labels_supplied_to_model": False},
        "records": records}
    anchor = {"kind": "entry_input", "register": "rdi", "transform": {"operation": operation, "constant": constant}}
    proposals = cq.propose_operand_assignments(query, raw, anchor, "a" * 64, BASE)
    resolution = cq.resolve_operand_assignment(query, proposals, time.monotonic() + 15)
    assert resolution["status"] == "verified", resolution
    return query, raw, anchor, proposals, resolution, folder


def test_unique_assignment_is_verified_with_both_alternatives_retained(case):
    query, raw, anchor, proposals, result, folder = case
    assert [r["evidence"]["status"] for r in result["attempts"]] == ["rejected", "verified"]
    assert result["selected_plan"]["operands"][0]["prediction_id"] == "z-base"
    evidence = result["validated_evidence"]
    assert evidence["verification_passes"] == 2
    assert evidence["checks"]["index_slot_equals_entry_expression"] is True
    assert "index_slot_equals_entry_input" not in evidence["checks"]
    bundle = map_operand_candidates(query, raw, result["selected_plan"], evidence)
    path = folder / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    views = load_operand_views(path, query, "D")
    assert len(views) == 2 and all(v.view.labels == ("char*", "void*") for v in views)
    assert bundle["raw_export"] == raw


def test_false_transform_is_refuted_not_assumed(case):
    query, _, _, _, result, _ = case
    plan = deepcopy(result["selected_plan"])
    plan["operands"][1]["anchor"]["transform"]["constant"] = 0
    proof = verify_operand_plan(query, plan, time.monotonic() + 5)
    assert proof["status"] == "rejected"
    assert proof["reason"] == "satisfiable_negation:index_slot_equals_entry_expression"


def test_instruction_semantics_produce_freshly_validated_query_results(case):
    query, _, anchor, _, _, _ = case
    checker = BinaryChecker(query)
    result = checker.validate(checker.check(128, time.monotonic() + 5), 128, time.monotonic() + 5)
    expected = "violation" if anchor["transform"]["operation"] == "add_constant" else "excluded_within_scope"
    assert result["status"] == expected
    assert result["validation"] != "no_decisive_evidence"


def test_assignment_search_does_not_read_type_content_or_variable_names(case):
    query, raw, anchor, plans, _, _ = case
    changed = deepcopy(raw)
    for record in changed["records"]:
        record["locator_variable_name"] = "pointer" if record["prediction_id"] == "a-index" else "index"
        record["candidates"] = [{"label": "completely changed", "raw_score": -900}]
    changed["records"].reverse()
    assert cq.propose_operand_assignments(query, changed, anchor, "a" * 64, BASE) == plans


def test_missing_physical_candidate_has_no_name_fallback(case):
    query, raw, anchor, _, _, _ = case
    bad = deepcopy(raw)
    bad["records"].pop()
    with pytest.raises(ValueError, match="Exactly two"):
        cq.propose_operand_assignments(query, bad, anchor, "a" * 64, BASE)


@pytest.mark.parametrize("statuses,reason", [
    (("verified", "unknown"), "unresolved_alternative_assignment"),
    (("verified", "verified"), "no_unique_verified_assignment"),
    (("rejected", "rejected"), "no_unique_verified_assignment")])
def test_unresolved_or_multiple_assignments_never_choose_first(monkeypatch, statuses, reason):
    iterator = iter(statuses)
    monkeypatch.setattr(cq, "verify_operand_plan", lambda *args: {"status": next(iterator)})
    def forbidden(*args):
        raise AssertionError("Ambiguous assignment must not be rechecked or selected")
    monkeypatch.setattr(cq, "validate_operand_evidence", forbidden)
    result = cq.resolve_operand_assignment(None, [{}, {}], time.monotonic() + 5)
    assert result["status"] == "unknown" and result["reason"] == reason
    assert "selected_plan" not in result


def test_transform_wraps_as_machine_unsigned_addition(case):
    query, _, anchor, _, result, _ = case
    if anchor["transform"]["operation"] != "add_constant":
        return
    wrapped = replace(query, inputs=(InputRange("rdi", (1 << 64) - 3, (1 << 64) - 1),))
    plan = deepcopy(result["selected_plan"])
    plan.update(query_hash=wrapped.contract_hash, use_site_id=wrapped.use_site_id)
    proof = verify_operand_plan(wrapped, plan, time.monotonic() + 5)
    assert proof["status"] == "verified"


def test_extraction_normalizes_linked_addresses_without_symbol_linked_addr(monkeypatch, case):
    import angr
    query, _, _, _, _, folder = case
    binary = Path(query.binary)
    spec = json.loads((ROOT / "benchmarks/selective_analysis/compiled_queries/cases.json").read_text())["cases"][0]
    symbols = {"case_write": SimpleNamespace(rebased_addr=0x401000, size=32),
               "case_buffer": SimpleNamespace(rebased_addr=0x404000, size=8)}
    obj = type("ELF", (), {"mapped_base": 0x400000, "linked_base": 0,
                          "get_symbol": lambda self, name: symbols[name]})()
    instruction = SimpleNamespace(mnemonic="mov", address=0x401010,
        insn=SimpleNamespace(operands=[SimpleNamespace(type=3, size=1), SimpleNamespace(type=2, imm=0x41)]))
    project = SimpleNamespace(arch=SimpleNamespace(name="AMD64"), loader=SimpleNamespace(main_object=obj),
        factory=SimpleNamespace(block=lambda *args, **kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[instruction]))))
    monkeypatch.setattr(angr, "Project", lambda *args, **kwargs: project)
    extracted, metadata = cq.extract_compiled_query(binary, spec)
    assert extracted.entry_rva == 0x1000 and extracted.object_rva == 0x4000
    assert metadata["linked_function_address"] == 0x1000


def test_gold_fields_cannot_enter_runtime_spec():
    spec = json.loads((ROOT / "benchmarks/selective_analysis/compiled_queries/cases.json").read_text())["cases"][0]
    cq.validate_case_spec(spec)
    spec["expected"] = "violation"
    with pytest.raises(ValueError, match="offline"):
        cq.validate_case_spec(spec)


def test_offline_denominator_preserves_failed_mapping_and_failed_extraction():
    cases = [{"query_id": "one"}, {"query_id": "two"}]
    labels = {"schema": "symbai.compiled_query_labels.v1", "labels": [
        {"query_id": "one", "expected": "violation"}, {"query_id": "two", "expected": "excluded_within_scope"}]}
    rows = [{"query_id": "one", "query": {}, "query_hash": "q", "property": {"status": "violation"},
             "mapping": {"status": "unknown"}}, {"query_id": "two", "failure": "compiler failed"}]
    summary = offline_summary(cases, rows, labels)
    assert summary["planned_queries"] == 2 and summary["correct"] == 1 and summary["unknown"] == 1
    assert summary["verified_mappings"] == 0 and summary["extracted_queries"] == 1
    with pytest.raises(ValueError, match="coverage"):
        offline_summary(cases, rows[:1], labels)


def test_export_nonce_and_model_identity_are_required(case):
    query, raw, _, _, _, _ = case
    validate_export(raw, query, "unit-nonce")
    with pytest.raises(ValueError, match="identity"):
        validate_export(raw, query, "another-nonce")


def test_isolated_worker_cli_records_property_and_mapping_receipts(case):
    from scripts.run_compiled_queries import invoke_stage, write_json
    query, raw, anchor, _, _, parent = case
    folder = parent / "worker-cli"
    folder.mkdir()
    write_json(folder / "raw-types.json", raw)
    environment = os.environ.copy()
    checked = invoke_stage("property", {"query": asdict(query)}, folder, environment)
    assert checked["status"] in ("violation", "excluded_within_scope"), checked
    mapped = invoke_stage("mapping", {"query": asdict(query), "anchor": anchor,
        "linked_base": BASE, "proposal_source_fingerprint": "a" * 64}, folder, environment)
    assert mapped["status"] == "verified", mapped
    assert mapped["view_counts"] == {"A": 0, "B": 0, "C": 2, "D": 2}
    assert (folder / "assignment-search.json").is_file()
    assert len(json.loads((folder / "assignment-attempts.json").read_text())) == 2
