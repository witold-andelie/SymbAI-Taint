"""Pure offline evaluation of the fixed v15 developer baseline.

Parent-finalized outcomes and complete persisted-payload costs are authoritative.
Repeated trials retain their original identities and never become new examples.
"""

from collections import Counter
import hashlib
import json
import math
from statistics import median

from .contracts import Checkpoint, fingerprint


QUERY_IDS = ("scalar_span", "readonly_chain", "readonly_chain_outside")
METHODS = ("expanded_only", "fixed_cascade")
REPETITIONS = (0, 1, 2)
STATUSES = ("unknown", "excluded_within_scope", "violation")
UNIT = "query_through_detailed_result_persistence"
_STAGES = {"expanded_only": ("expanded",), "fixed_cascade": ("interval", "finite_readonly", "expanded")}
_TAGS = {"interval": "fresh_byte_decoded_abstract_recheck", "finite_readonly": "fresh_byte_data_abstract_recheck",
         "expanded": "fresh_state_complete_scope_recheck"}


def _digest(value, name):
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(name + " must be a SHA256 identity")


def _number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(name + " must be finite and nonnegative")


def _status(result):
    if not isinstance(result, dict) or result.get("status") not in STATUSES:
        raise ValueError("Invalid finalized result status")
    return result["status"]


def _validated_result(result, operation):
    status = _status(result)
    if status == "unknown":
        return
    if status == "violation":
        if (operation != "expanded" or result.get("validation") != "concrete_input_modeled_reexecution"
                or not isinstance(result.get("witness"), dict) or not result["witness"]
                or any(type(value) is not int or not 0 <= value < (1 << 64) for value in result["witness"].values())):
            raise ValueError("A violation requires a freshly reexecuted expanded witness")
    elif result.get("complete") is not True or result.get("validation") != _TAGS[operation]:
        raise ValueError("A decisive exclusion requires fresh complete validation")
    if operation == "finite_readonly":
        if result.get("cardinality_limit") != 32:
            raise ValueError("Finite readonly evidence must use the fixed cap32")
    certificate = result.get("certificate")
    if status == "excluded_within_scope" and operation in ("interval", "finite_readonly") and certificate is None:
        raise ValueError("An abstract exclusion requires its certified trace")
    if certificate is not None:
        if (not isinstance(certificate, dict) or certificate.get("max_instructions") != 128
                or (operation == "finite_readonly" and certificate.get("cardinality_limit") != 32)):
            raise ValueError("Abstract evidence changes the declared limits")
        if result.get("certificate_sha256") != fingerprint(certificate):
            raise ValueError("Abstract certificate fingerprint differs")
    if operation == "expanded" and (result.get("reused_prefix_steps", 0) != 0 or
                                     result.get("validation_reused_prefix_steps", 0) != 0):
        raise ValueError("Expanded evidence reuses a paid prefix")


def _costs(value, elapsed, name):
    if not isinstance(value, dict) or not {"preparation", "execution", "validation"} <= set(value):
        raise ValueError(name + " requires preparation/execution/validation costs")
    for item in value.values():
        _number(item, name)
    if sum(value.values()) > elapsed + 0.001:
        raise ValueError(name + " exceeds its elapsed interval")


def _row(row, method, repetition):
    required = {"schema", "query_id", "query_hash", "binary_sha256", "checkpoint_id", "method", "repetition",
                "result", "worker_result", "attempts", "runtime_versions", "worker_costs_seconds",
                "worker_elapsed_seconds", "parent_receipt"}
    if (not isinstance(row, dict) or not required <= set(row) or row["schema"] != "symbai.cascade_trial.v1"
            or row["query_id"] not in QUERY_IDS or row["method"] != method or row["repetition"] != repetition
            or type(row["repetition"]) is not int):
        raise ValueError("Unexpected cascade trial identity/schema")
    for name in ("query_hash", "binary_sha256", "checkpoint_id"):
        _digest(row[name], name)
    if row["checkpoint_id"] != Checkpoint(row["query_hash"]).checkpoint_id:
        raise ValueError("Trial does not start at the fresh empty checkpoint")
    if row.get("neural_information_used", False) is not False:
        raise ValueError("The fixed baseline cannot consume neural information")
    status, worker_status = _status(row["result"]), _status(row["worker_result"])
    receipt = row["parent_receipt"]
    if not isinstance(receipt, dict):
        raise ValueError("Missing parent accounting receipt")
    _number(receipt.get("charged_seconds"), "charged_seconds")
    if (receipt.get("budget_seconds") != 30 or type(receipt["budget_seconds"]) not in (int, float)
            or receipt.get("accounting_unit") != UNIT or type(receipt.get("late")) is not bool):
        raise ValueError("Changed parent budget or accounting unit")
    process = receipt.get("process")
    if (not isinstance(process, dict) or type(process.get("returncode")) is not int
            or type(process.get("timed_out")) is not bool):
        raise ValueError("Invalid parent process outcome")
    if ((receipt["charged_seconds"] > 30 or process["timed_out"]) and not receipt["late"]
            or receipt["late"] and status != "unknown"):
        raise ValueError("Late/timed-out conclusions were not finalized as unknown")
    if process["returncode"] != 0 and status != "unknown":
        raise ValueError("Failed process conclusions were not finalized as unknown")
    if receipt.get("final_status", status) != status:
        raise ValueError("Receipt differs from authoritative finalized status")
    payload = {key: value for key, value in row.items() if key not in ("result", "parent_receipt")}
    encoded = json.dumps(payload, indent=2).encode("utf-8")
    if (receipt.get("payload_sha256") != hashlib.sha256(encoded).hexdigest()
            or receipt.get("worker_payload_fingerprint") != fingerprint(payload)):
        raise ValueError("Detailed persisted worker payload identity differs")
    versions = row["runtime_versions"]
    version_keys = ("python", "executable", "platform", "angr", "capstone", "pyelftools")
    metadata_missing = (not isinstance(versions, dict) or not versions or versions.get("availability") == "unavailable"
                        or any(not isinstance(versions.get(key), str) or not versions[key] for key in version_keys)
                        or row["worker_elapsed_seconds"] is None or row["worker_costs_seconds"] is None
                        or row.get("cost_measurement_complete", True) is not True)
    if metadata_missing:
        if status != "unknown":
            raise ValueError("A decisive trial cannot have unavailable worker provenance/costs")
    else:
        _number(row["worker_elapsed_seconds"], "worker_elapsed_seconds")
        _costs(row["worker_costs_seconds"], row["worker_elapsed_seconds"], "worker costs")
        if row["worker_elapsed_seconds"] > receipt["charged_seconds"] + 0.001:
            raise ValueError("Parent charge omits worker elapsed time")
    failure = metadata_missing or process["timed_out"] or process["returncode"] != 0 or receipt["late"]
    attempts = row["attempts"]
    if not isinstance(attempts, list):
        raise ValueError("Attempt ledger must be a list")
    if method != "reference":
        names = [attempt.get("operation") if isinstance(attempt, dict) else None for attempt in attempts]
        if tuple(names) != _STAGES[method][:len(names)] or len(names) > len(_STAGES[method]):
            raise ValueError("Attempt sequence differs from the fixed fresh-entry method")
        decisive_seen = False
        for attempt in attempts:
            if decisive_seen:
                raise ValueError("The method continued after a decisive attempt")
            if attempt.get("entry_basis", "fresh_function_entry_no_reused_facts") != "fresh_function_entry_no_reused_facts":
                raise ValueError("An attempt did not start at the fresh entry checkpoint")
            _number(attempt.get("elapsed_seconds"), "attempt elapsed_seconds")
            _costs(attempt.get("costs_seconds"), attempt["elapsed_seconds"], "attempt costs")
            attempt_status = _status(attempt.get("result"))
            if attempt_status != "unknown":
                if not receipt["late"]:
                    _validated_result(attempt["result"], attempt["operation"])
                    certificate = attempt["result"].get("certificate")
                    if certificate is not None and (certificate.get("query_hash") != row["query_hash"] or
                            certificate.get("binary_sha256", row["binary_sha256"]) != row["binary_sha256"]):
                        raise ValueError("Attempt certificate differs from its query identity")
                decisive_seen = True
                if attempt_status == "violation" and not receipt["late"]:
                    witness = attempt["result"]["witness"]
                    maximum = 1023 if row["query_id"] == "scalar_span" else 15
                    if set(witness) != {"rdi"} or not 0 <= witness["rdi"] <= maximum:
                        raise ValueError("Witness differs from the fixed query input contract")
        if status != "unknown":
            if not attempts or attempts[-1]["result"] != row["result"] or row["worker_result"] != row["result"]:
                raise ValueError("Final decision differs from its freshly validated last attempt")
            _validated_result(row["result"], attempts[-1]["operation"])
        if not metadata_missing and sum(attempt["elapsed_seconds"] for attempt in attempts) > row["worker_elapsed_seconds"] + 0.001:
            raise ValueError("Attempt intervals exceed complete worker time")
    return {"status": status, "worker_status": worker_status, "failure": bool(failure),
            "charged_seconds": receipt["charged_seconds"], "attempts": [attempt.get("operation") for attempt in attempts]}


def _reference(row):
    status = _status(row["result"])
    if status == "unknown":
        return False
    reference = row.get("reference")
    if (not isinstance(reference, dict) or reference.get("schema") != "symbai.indirection_reference.v1"
            or reference.get("query_hash") != row["query_hash"] or reference.get("binary_sha256") != row["binary_sha256"]
            or reference.get("result") != row["result"] or reference.get("reference_is_runtime_feature") is not False):
        raise ValueError("Reference metadata differs from its query/final result")
    mode = reference.get("reference_mode")
    if mode == "fresh_symbolic_expanded":
        if (row["query_id"] != "scalar_span" or type(reference.get("domain_cardinality")) is not int
                or reference["domain_cardinality"] != 1024):
            raise ValueError("Symbolic reference has no large-domain identity")
        _validated_result(row["result"], "expanded")
    elif mode == "exhaustive_literal_BVV_states_and_fresh_rechecks":
        count, receipts = reference.get("domain_cardinality"), reference.get("input_receipts")
        if (row["query_id"] == "scalar_span" or type(count) is not int or count != 16
                or not isinstance(receipts, list) or not receipts):
            raise ValueError("Incomplete literal reference metadata")
        identities = []
        for item in receipts:
            if not isinstance(item, dict) or not isinstance(item.get("input"), dict) or not item["input"]:
                raise ValueError("Missing literal input identity")
            if (set(item["input"]) != {"rdi"} or type(item["input"]["rdi"]) is not int
                    or not 0 <= item["input"]["rdi"] <= 15):
                raise ValueError("Literal input differs from the fixed query input contract")
            identities.append(fingerprint(item["input"]))
            if _status(item.get("result")) == "excluded_within_scope":
                if item["result"].get("complete") is not True or item["result"].get("validation") != "fresh_literal_state_complete_scope_recheck":
                    raise ValueError("A literal input lacks its fresh complete recheck")
            elif item["result"]["status"] == "violation":
                _validated_result(item["result"], "expanded")
                if item["result"]["witness"] != item["input"]:
                    raise ValueError("Literal witness differs from its enumerated input")
            else:
                raise ValueError("A decisive reference contains unresolved literal inputs")
        if len(identities) != len(set(identities)) or len(receipts) > count:
            raise ValueError("Duplicate/excess literal reference inputs")
        if status == "excluded_within_scope":
            if (len(receipts) != count or row["result"].get("checked_inputs") != count
                    or row["result"].get("complete") is not True
                    or row["result"].get("validation") != "all_literal_inputs_freshly_rechecked"
                    or any(item["result"]["status"] != "excluded_within_scope" for item in receipts)):
                raise ValueError("Literal exclusion does not discharge its entire input domain")
        elif receipts[-1]["result"] != row["result"]:
            raise ValueError("Literal witness differs from its last freshly reexecuted input")
    else:
        raise ValueError("Unsupported reference mode")
    return True


def _stats(values):
    return {"count": len(values), "total_seconds": sum(values), "median_seconds": median(values) if values else None,
            "minimum_seconds": min(values) if values else None, "maximum_seconds": max(values) if values else None}


def evaluate(records, references, gold):
    """Evaluate complete immutable records without opening files or running code."""
    if (not isinstance(gold, dict) or gold.get("schema") != "symbai.gold.v1"
            or gold.get("panel") != "v14_three_authored_capability_mechanisms"
            or not isinstance(gold.get("labels"), list) or len(gold["labels"]) != 3):
        raise ValueError("Expected the unchanged three-case authored gold panel")
    labels = {}
    for label in gold["labels"]:
        if (not isinstance(label, dict) or label.get("query_id") not in QUERY_IDS
                or label.get("expected") not in STATUSES[1:] or label["query_id"] in labels):
            raise ValueError("Missing, duplicate or invalid gold identity")
        _digest(label.get("binary_sha256"), "gold binary_sha256")
        labels[label["query_id"]] = label
    if set(labels) != set(QUERY_IDS) or not isinstance(records, list) or len(records) != 18:
        raise ValueError("The fixed eighteen-trial denominator differs")
    if not isinstance(references, list) or len(references) != 3:
        raise ValueError("Exactly three separate fresh references are required")
    indexed, analyzed, identities = {}, {}, {}
    for row in records:
        if not isinstance(row, dict) or row.get("method") not in METHODS or row.get("repetition") not in REPETITIONS:
            raise ValueError("Unknown method or repetition")
        key = (row.get("query_id"), row["method"], row["repetition"])
        if key in indexed:
            raise ValueError("Duplicate trial identity")
        analyzed[key] = _row(row, row["method"], row["repetition"])
        identity = (row["query_hash"], row["binary_sha256"], row["checkpoint_id"])
        if row["binary_sha256"] != labels[row["query_id"]]["binary_sha256"] or identities.get(row["query_id"], identity) != identity:
            raise ValueError("Trial contract/binary/checkpoint differs across controls")
        identities[row["query_id"]] = identity
        indexed[key] = row
    if set(indexed) != {(query, method, repetition) for query in QUERY_IDS for method in METHODS for repetition in REPETITIONS}:
        raise ValueError("Missing trial query/method/repetition")
    blockers, reference_ok, reference_statuses = [], {}, []
    for row in references:
        if not isinstance(row, dict) or row.get("query_id") in reference_ok:
            raise ValueError("Duplicate or malformed reference identity")
        info = _row(row, "reference", 0)
        query_id = row["query_id"]
        if (row["query_hash"], row["binary_sha256"], row["checkpoint_id"]) != identities[query_id]:
            raise ValueError("Reference identity differs from the matched trials")
        resolved = _reference(row)
        reference_ok[query_id] = resolved and not info["failure"] and info["status"] == labels[query_id]["expected"]
        reference_statuses.append({"query_id": query_id, "status": info["status"], "resolved_and_agrees": reference_ok[query_id],
                                   "charged_seconds": info["charged_seconds"], "cost_role": "separate_fresh_validation_panel"})
        if not reference_ok[query_id]:
            blockers.append({"query_id": query_id, "reason": "unresolved_or_disagreeing_reference"})
    if set(reference_ok) != set(QUERY_IDS):
        raise ValueError("Missing separate reference query identity")
    methods = []
    for method in METHODS:
        counts = Counter(correct=0, wrong=0, unknown=0, failures=0)
        vectors, ever_correct, stable_correct = [], 0, 0
        for query_id in QUERY_IDS:
            rows = [analyzed[query_id, method, repetition] for repetition in REPETITIONS]
            expected = labels[query_id]["expected"]
            correct = [row["status"] == expected for row in rows]
            ever_correct += any(correct) and reference_ok[query_id]
            stable_correct += all(correct) and reference_ok[query_id]
            for repetition, row in zip(REPETITIONS, rows):
                category = "unknown" if row["status"] == "unknown" else "correct" if row["status"] == expected else "wrong"
                counts[category] += 1
                counts["failures"] += row["failure"]
                if category == "wrong":
                    blockers.append({"query_id": query_id, "method": method, "repetition": repetition,
                                     "reason": "wrong_decisive_result"})
            vectors.append({"query_id": query_id, "expected": expected, "statuses": [row["status"] for row in rows],
                            "attempted_operations": [row["attempts"] for row in rows], "stable_correct": all(correct) and reference_ok[query_id]})
        methods.append({"method": method, "trials": 9, "unique_queries": 3, **dict(counts),
                        "ever_correct_unique_queries": ever_correct, "stable_correct_unique_queries": stable_correct,
                        "query_vectors": vectors})
    pairs, matched = [], []
    for query_id in QUERY_IDS:
        expected = labels[query_id]["expected"]
        for repetition in REPETITIONS:
            full, cascade = [analyzed[query_id, method, repetition] for method in METHODS]
            if any(row["status"] not in ("unknown", expected) for row in (full, cascade)):
                classification = "disagreement"
            elif not reference_ok[query_id] or full["failure"] or cascade["failure"]:
                classification = "failure"
            elif full["status"] == cascade["status"] == expected:
                classification = "both_correct"
            elif cascade["status"] == expected:
                classification = "cascade_only"
            elif full["status"] == expected:
                classification = "full_only"
            else:
                classification = "both_unknown"
            pair = {"query_id": query_id, "repetition": repetition, "query_hash": identities[query_id][0],
                    "binary_sha256": identities[query_id][1], "checkpoint_id": identities[query_id][2],
                    "classification": classification, "expanded_status": full["status"], "cascade_status": cascade["status"],
                    "expanded_charged_seconds": full["charged_seconds"], "cascade_charged_seconds": cascade["charged_seconds"]}
            pairs.append(pair)
            if classification == "both_correct":
                matched.append({**pair, "cascade_minus_expanded_seconds": cascade["charged_seconds"] - full["charged_seconds"]})
    return {"schema": "symbai.cascade_evaluation.v1", "interpretation_allowed": not blockers, "blockers": blockers,
            "planned_trials": 18, "unique_queries": 3, "repetitions": 3, "methods": methods,
            "reference_statuses": reference_statuses, "paired_trials": pairs,
            "pair_class_counts": dict(Counter(pair["classification"] for pair in pairs)),
            "matched_correct_costs": {"count": len(matched), "pairs": matched,
                "expanded_only": _stats([pair["expanded_charged_seconds"] for pair in matched]),
                "fixed_cascade": _stats([pair["cascade_charged_seconds"] for pair in matched]),
                "cascade_minus_expanded": _stats([pair["cascade_minus_expanded_seconds"] for pair in matched])},
            "accounting_unit": UNIT, "finite_cardinality_limit": 32, "scope": "first_dynamic_visit",
            "neural_benefit_measured": False, "held_out_evaluation": False,
            "interpretation": "Fixed non-neural baseline on three known authored inputs; repetitions are not new examples. Latencies compare only the same correctly resolved query/repetition pairs, including the first. No stable speed or significance claim."}
