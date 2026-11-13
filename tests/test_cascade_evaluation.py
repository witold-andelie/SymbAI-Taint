"""Fabricated offline receipts; no checkers, files, references or models execute."""

from copy import deepcopy
import hashlib
import json

import pytest

from src.selective_analysis import cascade_evaluation as evaluation
from src.selective_analysis.contracts import Checkpoint, fingerprint


IDS = evaluation.QUERY_IDS
SHA = {query_id: str(index + 1) * 64 for index, query_id in enumerate(IDS)}
QHASH = {query_id: str(index + 4) * 64 for index, query_id in enumerate(IDS)}
CHECKPOINT = {query_id: Checkpoint(QHASH[query_id]).checkpoint_id for query_id in IDS}


def result(query_id, operation="expanded", status=None):
    status = status or ("violation" if query_id == "readonly_chain_outside" else "excluded_within_scope")
    if status == "unknown":
        return {"status": "unknown", "reason": "fabricated unsupported subset"}
    if status == "violation":
        return {"status": status, "witness": {"rdi": 1}, "validation": "concrete_input_modeled_reexecution",
                "reused_prefix_steps": 0, "validation_reused_prefix_steps": 0}
    value = {"status": status, "complete": True, "validation": {
        "interval": "fresh_byte_decoded_abstract_recheck", "finite_readonly": "fresh_byte_data_abstract_recheck",
        "expanded": "fresh_state_complete_scope_recheck"}[operation]}
    if operation != "expanded":
        certificate = {"query_hash": QHASH[query_id], "max_instructions": 128, "trace": []}
        if operation == "finite_readonly":
            value["cardinality_limit"] = certificate["cardinality_limit"] = 32
            certificate["binary_sha256"] = SHA[query_id]
        value.update(certificate=certificate, certificate_sha256=fingerprint(certificate))
    return value


def attempt(operation, outcome):
    return {"operation": operation, "result": outcome, "elapsed_seconds": 0.1,
            "costs_seconds": {"preparation": 0.02, "execution": 0.03, "validation": 0.02}}


def seal(row, charged=None, late=False, returncode=0, timed_out=False):
    previous = row.get("parent_receipt", {})
    payload = {key: value for key, value in row.items() if key not in ("result", "parent_receipt")}
    row["parent_receipt"] = {"charged_seconds": previous.get("charged_seconds", 2.0) if charged is None else charged,
        "budget_seconds": 30, "process": {"returncode": returncode, "timed_out": timed_out}, "late": late,
        "accounting_unit": evaluation.UNIT, "final_status": row["result"]["status"],
        "payload_sha256": hashlib.sha256(json.dumps(payload, indent=2).encode("utf-8")).hexdigest(),
        "worker_payload_fingerprint": fingerprint(payload)}
    return row


def trial(query_id, method, repetition, status=None):
    if method == "expanded_only":
        status = status or ("unknown" if query_id == "readonly_chain" else None)
        attempts = [attempt("expanded", result(query_id, status=status))]
    else:
        decisive = {"scalar_span": "interval", "readonly_chain": "finite_readonly", "readonly_chain_outside": "expanded"}[query_id]
        names = list(("interval", "finite_readonly", "expanded"))
        names = names[:names.index(decisive) + 1]
        attempts = [attempt(operation, result(query_id, operation, status if operation == decisive else "unknown"))
                    for operation in names]
    worker_result = deepcopy(attempts[-1]["result"])
    row = {"schema": "symbai.cascade_trial.v1", "query_id": query_id, "query_hash": QHASH[query_id],
           "binary_sha256": SHA[query_id], "checkpoint_id": CHECKPOINT[query_id], "method": method,
           "repetition": repetition, "worker_result": worker_result, "attempts": attempts,
           "runtime_versions": {"python": "unit-python", "executable": "D:/unit/python.exe", "platform": "unit",
                                "angr": "unit", "capstone": "unit", "pyelftools": "unit"},
           "worker_costs_seconds": {"preparation": 0.1, "execution": 0.2, "validation": 0.1, "recording": 0.1},
           "worker_elapsed_seconds": 1.0, "cost_measurement_complete": True, "result": deepcopy(worker_result)}
    return seal(row, charged=3.0 + repetition if method == "expanded_only" else 2.0 + repetition)


def reference(query_id):
    row = trial(query_id, "expanded_only", 0)
    row["method"], row["attempts"] = "reference", []
    if query_id == "scalar_span":
        final = result(query_id)
        metadata = {"reference_mode": "fresh_symbolic_expanded", "domain_cardinality": 1024}
    else:
        literal = {"status": "excluded_within_scope", "complete": True,
                   "validation": "fresh_literal_state_complete_scope_recheck"}
        if query_id == "readonly_chain":
            final = {"status": "excluded_within_scope", "complete": True, "checked_inputs": 16,
                     "validation": "all_literal_inputs_freshly_rechecked"}
            receipts = [{"input": {"rdi": index}, "result": deepcopy(literal)} for index in range(16)]
        else:
            final = result(query_id)
            receipts = [{"input": {"rdi": 0}, "result": literal}, {"input": {"rdi": 1}, "result": deepcopy(final)}]
        metadata = {"reference_mode": "exhaustive_literal_BVV_states_and_fresh_rechecks",
                    "domain_cardinality": 16, "input_receipts": receipts}
    row["result"], row["worker_result"] = deepcopy(final), deepcopy(final)
    row["reference"] = {"schema": "symbai.indirection_reference.v1", "query_hash": QHASH[query_id],
                        "binary_sha256": SHA[query_id], "reference_is_runtime_feature": False,
                        "native_replay": "not_attempted", "result": deepcopy(final), **metadata}
    return seal(row)


def panel():
    records = [trial(query_id, method, repetition) for query_id in IDS
               for method in evaluation.METHODS for repetition in evaluation.REPETITIONS]
    references = [reference(query_id) for query_id in IDS]
    gold = {"schema": "symbai.gold.v1", "panel": "v14_three_authored_capability_mechanisms",
            "labels": [{"query_id": query_id, "binary_sha256": SHA[query_id],
                        "expected": "violation" if query_id == "readonly_chain_outside" else "excluded_within_scope"}
                       for query_id in IDS]}
    return records, references, gold


def test_complete_panel_reports_unique_stable_coverage_and_only_matched_cost_pairs():
    records, references, gold = panel()
    report = evaluation.evaluate(records, references, gold)
    assert report["interpretation_allowed"] is True and report["blockers"] == []
    assert report["planned_trials"] == 18 and report["unique_queries"] == report["repetitions"] == 3
    full, cascade = report["methods"]
    assert (full["correct"], full["wrong"], full["unknown"]) == (6, 0, 3)
    assert (cascade["correct"], cascade["wrong"], cascade["unknown"]) == (9, 0, 0)
    assert full["stable_correct_unique_queries"] == 2 and cascade["stable_correct_unique_queries"] == 3
    assert len(report["paired_trials"]) == 9 and report["pair_class_counts"] == {"both_correct": 6, "cascade_only": 3}
    costs = report["matched_correct_costs"]
    assert costs["count"] == 6 and len(costs["pairs"]) == 6
    assert {pair["query_id"] for pair in costs["pairs"]} == {"scalar_span", "readonly_chain_outside"}
    assert {pair["repetition"] for pair in costs["pairs"]} == {0, 1, 2}
    assert costs["expanded_only"]["total_seconds"] == 24 and costs["fixed_cascade"]["total_seconds"] == 18
    assert costs["cascade_minus_expanded"]["median_seconds"] == -1
    assert report["neural_benefit_measured"] is report["held_out_evaluation"] is False


def test_evaluation_is_pure_and_parent_charge_includes_failed_attempts_and_first_trial():
    records, references, gold = panel()
    records[0]["parent_receipt"]["charged_seconds"] = 20
    before = deepcopy((records, references, gold))
    report = evaluation.evaluate(records, references, gold)
    assert (records, references, gold) == before
    assert report["matched_correct_costs"]["expanded_only"]["maximum_seconds"] == 20
    assert report["matched_correct_costs"]["expanded_only"]["total_seconds"] == 41
    cascade = report["methods"][1]
    outside = next(vector for vector in cascade["query_vectors"] if vector["query_id"] == "readonly_chain_outside")
    assert outside["attempted_operations"] == [["interval", "finite_readonly", "expanded"]] * 3


@pytest.mark.parametrize("change", ["missing_trial", "duplicate_trial", "method", "repetition", "query",
                                    "query_hash", "binary_hash", "checkpoint", "missing_reference", "duplicate_reference",
                                    "reference_checkpoint", "gold_panel", "gold_duplicate"])
def test_changed_denominators_or_matched_identities_are_rejected(change):
    records, references, gold = panel()
    if change == "missing_trial": records.pop()
    elif change == "duplicate_trial": records[1] = deepcopy(records[0])
    elif change == "method": records[0]["method"] = "neural"
    elif change == "repetition": records[0]["repetition"] = 3
    elif change == "query": records[0]["query_id"] = "favorable-new-case"
    elif change == "query_hash": records[0]["query_hash"] = "f" * 64; seal(records[0])
    elif change == "binary_hash": records[0]["binary_sha256"] = "f" * 64; seal(records[0])
    elif change == "checkpoint": records[0]["checkpoint_id"] = "f" * 64; seal(records[0])
    elif change == "missing_reference": references.pop()
    elif change == "duplicate_reference": references[1] = deepcopy(references[0])
    elif change == "reference_checkpoint": references[0]["checkpoint_id"] = "f" * 64; seal(references[0])
    elif change == "gold_panel": gold["panel"] = "held_out"
    else: gold["labels"][1] = deepcopy(gold["labels"][0])
    with pytest.raises(ValueError): evaluation.evaluate(records, references, gold)


@pytest.mark.parametrize("change", ["payload_bytes", "payload_fingerprint", "receipt_budget", "receipt_unit", "receipt_status",
                                    "missing_fresh_validation", "incomplete_exclusion", "changed_cap", "changed_instruction_cap",
                                    "wrong_stage", "continued_after_decision", "unvalidated_witness", "empty_witness", "prefix_reuse"])
def test_malformed_cost_or_validation_evidence_cannot_count_as_decisive(change):
    records, references, gold = panel()
    row = next(row for row in records if row["query_id"] == "readonly_chain" and row["method"] == "fixed_cascade")
    outcome = row["attempts"][-1]["result"]
    if change == "payload_bytes": row["runtime_versions"]["python"] = "changed"  # Do not reseal.
    elif change == "payload_fingerprint": row["parent_receipt"]["worker_payload_fingerprint"] = "0" * 64
    elif change == "receipt_budget": row["parent_receipt"]["budget_seconds"] = 31
    elif change == "receipt_unit": row["parent_receipt"]["accounting_unit"] = "free_start"
    elif change == "receipt_status": row["parent_receipt"]["final_status"] = "unknown"
    else:
        if change == "missing_fresh_validation": outcome.pop("validation")
        elif change == "incomplete_exclusion": outcome["complete"] = False
        elif change == "changed_cap": outcome["cardinality_limit"] = 64
        elif change == "changed_instruction_cap":
            outcome["certificate"]["max_instructions"] = 256
            outcome["certificate_sha256"] = fingerprint(outcome["certificate"])
        elif change == "wrong_stage": row["attempts"][0]["operation"] = "expanded"
        elif change == "continued_after_decision": row["attempts"].append(attempt("expanded", result("readonly_chain")))
        elif change in ("unvalidated_witness", "empty_witness", "prefix_reuse"):
            row = records[-1]
            outcome = row["attempts"][-1]["result"]
            if change == "unvalidated_witness": outcome["validation"] = "not_reexecuted"
            elif change == "empty_witness": outcome["witness"] = {}
            else: outcome["reused_prefix_steps"] = 1
        row["result"] = row["worker_result"] = deepcopy(outcome)
        seal(row)
    with pytest.raises(ValueError): evaluation.evaluate(records, references, gold)


def test_authoritative_late_unknown_keeps_original_worker_candidate_out_of_cost_comparison():
    records, references, gold = panel()
    row = records[0]
    original = deepcopy(row["worker_result"])
    row["result"] = {"status": "unknown", "reason": "parent_detail_persistence_exceeded_budget"}
    seal(row, charged=30.1, late=True)
    report = evaluation.evaluate(records, references, gold)
    assert row["worker_result"] == original
    assert report["methods"][0]["unknown"] == 4  # Three ordinary unknowns plus late.
    assert report["methods"][0]["failures"] == 1
    assert report["paired_trials"][0]["classification"] == "failure"
    assert report["matched_correct_costs"]["count"] == 5
    assert report["methods"][0]["stable_correct_unique_queries"] == 1


def test_missing_worker_metadata_and_unresolved_reference_block_without_losing_denominator():
    records, references, gold = panel()
    row = records[0]
    row.update(result={"status": "unknown", "reason": "worker crashed"},
               worker_result={"status": "unknown", "reason": "worker crashed"}, attempts=[],
               runtime_versions={"availability": "unavailable", "reason": "no worker payload"},
               worker_costs_seconds=None, worker_elapsed_seconds=None, cost_measurement_complete=False)
    seal(row, returncode=1)
    ref = references[1]
    ref["result"] = ref["worker_result"] = {"status": "unknown", "reason": "reference unresolved"}
    ref["reference"]["result"] = deepcopy(ref["result"])
    seal(ref)
    report = evaluation.evaluate(records, references, gold)
    assert report["planned_trials"] == 18 and len(report["paired_trials"]) == 9
    assert report["interpretation_allowed"] is False
    assert {block["reason"] for block in report["blockers"]} == {"unresolved_or_disagreeing_reference"}
    assert report["pair_class_counts"]["failure"] == 4


def test_wrong_decisive_result_blocks_interpretation_and_never_enters_matched_costs():
    records, references, gold = panel()
    row = records[0]
    wrong = result("scalar_span", status="violation")
    row["attempts"] = [attempt("expanded", wrong)]
    row["result"] = row["worker_result"] = deepcopy(wrong)
    seal(row)
    report = evaluation.evaluate(records, references, gold)
    assert report["interpretation_allowed"] is False and report["methods"][0]["wrong"] == 1
    assert report["paired_trials"][0]["classification"] == "disagreement"
    assert report["matched_correct_costs"]["count"] == 5


@pytest.mark.parametrize("change", ["missing_input", "duplicate_input", "unvalidated_input", "changed_reference_hash",
                                    "wrong_register", "outside_input_domain", "changed_domain_cardinality"])
def test_literal_reference_must_cover_full_domain_with_fresh_input_rechecks(change):
    records, references, gold = panel()
    row = references[1]
    helper = row["reference"]
    if change == "missing_input": helper["input_receipts"].pop()
    elif change == "duplicate_input": helper["input_receipts"][1] = deepcopy(helper["input_receipts"][0])
    elif change == "unvalidated_input": helper["input_receipts"][0]["result"]["validation"] = "reused"
    elif change == "changed_reference_hash": helper["query_hash"] = "0" * 64
    elif change == "wrong_register": helper["input_receipts"][0]["input"] = {"rsi": 0}
    elif change == "outside_input_domain": helper["input_receipts"][0]["input"] = {"rdi": 100}
    else: helper["domain_cardinality"] = 32
    seal(row)
    with pytest.raises(ValueError): evaluation.evaluate(records, references, gold)


def test_full_only_and_both_unknown_are_separate_from_equal_aggregate_counts():
    records, references, gold = panel()
    # Preserve aggregate correct totals while moving a resolution to a different
    # query: only actual same-query decisions belong in latency comparisons.
    for row in records:
        if row["query_id"] == "scalar_span" and row["method"] == "fixed_cascade":
            unknown = result("scalar_span", status="unknown")
            row["attempts"] = [attempt(stage, deepcopy(unknown)) for stage in ("interval", "finite_readonly", "expanded")]
            row["result"] = row["worker_result"] = deepcopy(unknown)
            seal(row)
    report = evaluation.evaluate(records, references, gold)
    assert report["methods"][0]["correct"] == report["methods"][1]["correct"] == 6
    assert report["pair_class_counts"] == {"full_only": 3, "cascade_only": 3, "both_correct": 3}
    assert report["matched_correct_costs"]["count"] == 3
    assert {pair["query_id"] for pair in report["matched_correct_costs"]["pairs"]} == {"readonly_chain_outside"}


def test_both_unknown_is_valid_without_becoming_a_failure_or_interpretation_error():
    records, references, gold = panel()
    row = next(row for row in records if row["query_id"] == "readonly_chain"
               and row["method"] == "fixed_cascade" and row["repetition"] == 1)
    unknown = result("readonly_chain", status="unknown")
    row["attempts"] = [attempt(stage, deepcopy(unknown)) for stage in ("interval", "finite_readonly", "expanded")]
    row["result"] = row["worker_result"] = deepcopy(unknown)
    seal(row)
    report = evaluation.evaluate(records, references, gold)
    assert report["interpretation_allowed"] is True
    assert report["pair_class_counts"] == {"both_correct": 6, "cascade_only": 2, "both_unknown": 1}
    assert report["methods"][1]["unknown"] == 1 and report["methods"][1]["failures"] == 0


def test_same_forged_checkpoint_across_all_controls_cannot_hide_a_spent_state():
    records, references, gold = panel()
    forged = Checkpoint(QHASH["scalar_span"], attempted=("definitions",)).checkpoint_id
    for row in records + references:
        if row["query_id"] == "scalar_span":
            row["checkpoint_id"] = forged
            seal(row)
    with pytest.raises(ValueError, match="fresh empty checkpoint"):
        evaluation.evaluate(records, references, gold)


@pytest.mark.parametrize("change", ["negative_charge", "nan_charge", "infinite_charge", "over_budget_not_late",
                                    "timeout_not_late", "late_decisive", "negative_attempt_cost", "invented_worker_cost",
                                    "neural_input", "reused_attempt_entry", "failed_process_decisive"])
def test_invalid_parent_finalization_or_cost_accounting_is_rejected(change):
    records, references, gold = panel()
    row = records[0]
    if change == "negative_charge": row["parent_receipt"]["charged_seconds"] = -1
    elif change == "nan_charge": row["parent_receipt"]["charged_seconds"] = float("nan")
    elif change == "infinite_charge": row["parent_receipt"]["charged_seconds"] = float("inf")
    elif change == "over_budget_not_late": row["parent_receipt"]["charged_seconds"] = 30.1
    elif change == "timeout_not_late": row["parent_receipt"]["process"]["timed_out"] = True
    elif change == "late_decisive": row["parent_receipt"]["late"] = True
    elif change == "failed_process_decisive": row["parent_receipt"]["process"]["returncode"] = 1
    else:
        if change == "negative_attempt_cost": row["attempts"][0]["costs_seconds"]["execution"] = -1
        elif change == "invented_worker_cost": row["worker_costs_seconds"]["execution"] = 5
        elif change == "neural_input": row["neural_information_used"] = True
        else: row["attempts"][0]["entry_basis"] = "reused_prefix"
        seal(row)
    with pytest.raises(ValueError):
        evaluation.evaluate(records, references, gold)
