"""Post-hoc arithmetic consequences of previously paid operand proofs.

This audit neither reruns program semantics nor measures deployment benefit.
The pure deduction assumes the supplied facts hold throughout the query domain;
the bundle entry point additionally checks the retained proof and straight-line
trace identities. Neural candidates are hashed for integrity, never interpreted.
"""

import hashlib
import json
from pathlib import Path
import time

from .contracts import file_hash, fingerprint
from .operand_mapping import operand_id, operand_program_facts


MAX64 = (1 << 64) - 1
_FACT_FIELDS = {"schema", "query_hash", "binary_sha256", "relation", "index_scale",
                "write_length_bytes", "evidence_fingerprint", "operands"}
_STRAIGHT_LINE = {"push", "mov", "movabs", "lea", "add", "sub", "and", "xor", "nop", "endbr64"}


def _receipt(query):
    return {"schema": "symbai.compiled_fact_audit.v1", "query_id": query.query_id,
            "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
            "use_site_id": query.use_site_id, "derived_status": "unknown",
            "query_decision_available_after_mapping": False,
            "evidence_source": "previously_verified_operand_program_facts",
            "mapping_acquisition_cost_role": "previously_paid_not_free",
            "no_neural_information_used": True,
            "deduction_basis": "conditional_on_previously_paid_program_proof",
            "new_program_validation_performed": False,
            "deployment_benefit_measured": False}


def _uint64(value):
    return type(value) is int and 0 <= value <= MAX64


def derive_from_facts(facts, query, object_base):
    """Deduce a byte-write decision conditional on already established facts.

    An interval proves exclusion only without address wrap. A violation always
    includes a concrete, in-range arithmetic witness; an interval overapproximation
    alone cannot establish one. Unsupported or imprecise cases remain unknown.
    """
    result = _receipt(query)

    def unknown(reason):
        return dict(result, reason=reason)

    if (not isinstance(facts, dict) or set(facts) != _FACT_FIELDS
            or facts.get("schema") != "symbai.operand_program_facts.v1"
            or facts.get("query_hash") != query.contract_hash
            or facts.get("binary_sha256") != query.binary_sha256
            or facts.get("relation") != "base_plus_index"
            or type(facts.get("index_scale")) is not int or facts["index_scale"] != 1
            or type(facts.get("write_length_bytes")) is not int or facts["write_length_bytes"] != 1
            or not isinstance(facts.get("evidence_fingerprint"), str)
            or len(facts["evidence_fingerprint"]) != 64):
        return unknown("unsupported_or_mismatched_program_facts")
    operands = facts["operands"]
    if (not isinstance(operands, list) or len(operands) != 2
            or any(not isinstance(entry, dict) for entry in operands)
            or [entry.get("role") for entry in operands] != ["base_pointer", "index"]
            or any(set(entry) != {"role", "operand_id", "storage", "anchor"} for entry in operands)
            or any(entry["operand_id"] != operand_id(query, entry["role"]) for entry in operands)
            or operands[0]["anchor"] != {"kind": "object_base"}):
        return unknown("unsupported_operand_roles_or_base")
    anchor = operands[1]["anchor"]
    if (not isinstance(anchor, dict) or set(anchor) not in
            ({"kind", "register"}, {"kind", "register", "transform"})
            or anchor.get("kind") != "entry_input"):
        return unknown("unsupported_index_anchor")
    matching = [bounds for bounds in query.inputs if bounds.register == anchor.get("register")]
    if (len(matching) != 1 or not _uint64(matching[0].minimum)
            or not _uint64(matching[0].maximum) or matching[0].minimum > matching[0].maximum):
        return unknown("missing_or_invalid_unsigned_input")
    if (not _uint64(object_base) or type(query.capacity) is not int
            or not 0 < query.capacity <= MAX64 or object_base + query.capacity > MAX64 + 1):
        return unknown("invalid_or_wrapping_object")
    bounds = matching[0]
    low, high = bounds.minimum, bounds.maximum
    operation, constant = "identity", 0
    if "transform" in anchor:
        transform = anchor["transform"]
        if (not isinstance(transform, dict) or set(transform) != {"operation", "constant"}
                or transform.get("operation") not in ("add_constant", "and_constant")
                or not _uint64(transform.get("constant"))):
            return unknown("unsupported_index_transform")
        operation, constant = transform["operation"], transform["constant"]
    if operation == "add_constant":
        if high + constant > MAX64:
            return unknown("index_addition_wrap_outside_audit_subset")
        interval = (low + constant, high + constant)
    elif operation == "and_constant":
        interval = ((low & constant,) * 2 if low == high else (0, min(high, constant)))
    else:
        interval = (low, high)
    result.update(object_base=object_base, offset_interval=list(interval),
                  interval_role="sound_overapproximation_not_a_violation_witness",
                  evidence_fingerprint=facts["evidence_fingerprint"])
    if interval[1] < query.capacity and object_base + interval[1] <= MAX64:
        return dict(result, derived_status="excluded_within_scope",
                    query_decision_available_after_mapping=True,
                    reason="entire_offset_interval_inside_object_without_address_wrap")

    # Seek only a few explicit witnesses. Failure to find one is not exclusion.
    threshold = query.capacity - constant if operation == "add_constant" else query.capacity
    candidates = (max(low, threshold), low, high)
    for candidate in dict.fromkeys(candidates):
        if not low <= candidate <= high:
            continue
        offset = ((candidate + constant) & MAX64 if operation == "add_constant" else
                  candidate & constant if operation == "and_constant" else candidate)
        address = object_base + offset
        if address > MAX64:
            continue  # Wrapped absolute addresses are outside this narrow audit.
        if not object_base <= address < object_base + query.capacity:
            witness = {entry.register: entry.minimum for entry in query.inputs}
            witness[bounds.register] = candidate
            return dict(result, derived_status="violation", derived_witness=witness,
                        derived_offset=offset, derived_address=address, write_length_bytes=1,
                        query_decision_available_after_mapping=True,
                        reason="explicit_in_range_arithmetic_witness_outside_object")
    return unknown("interval_inconclusive_no_supported_concrete_witness")


def _check_straight_line_trace(query, evidence, checker):
    """Match retained bytes without executing a prefix or asking a solver."""
    expected = checker.base + query.entry_rva
    trace = evidence["prefix_trace"]
    for entry in trace:
        if (not isinstance(entry, dict) or set(entry) != {"rva", "bytes"}
                or type(entry["rva"]) is not int or not isinstance(entry["bytes"], str)
                or checker.base + entry["rva"] != expected):
            raise ValueError("Retained prefix is not a contiguous straight-line trace")
        instructions = checker.project.factory.block(expected, num_inst=1).capstone.insns
        if len(instructions) != 1:
            raise ValueError("Retained prefix instruction is unavailable")
        instruction = instructions[0]
        if (instruction.mnemonic not in _STRAIGHT_LINE
                or bytes(instruction.bytes) != bytes.fromhex(entry["bytes"])):
            raise ValueError("Retained prefix has unsupported control flow or mismatched bytes")
        expected += instruction.size
    if expected != checker.base + query.write_rva:
        raise ValueError("Retained prefix does not end at the declared write")


def audit_compiled_facts(query, bundle_path):
    """Audit an existing bundle; do not acquire types or revalidate program proofs."""
    started = time.monotonic()
    result = _receipt(query)
    try:
        path = Path(bundle_path)
        payload = path.read_bytes()
        bundle = json.loads(payload)
        if not isinstance(bundle, dict):
            raise ValueError("Operand bundle must be an object")
        body = {key: value for key, value in bundle.items() if key != "bundle_fingerprint"}
        if (bundle.get("schema") != "symbai.operand_types.v1"
                or bundle.get("bundle_fingerprint") != fingerprint(body)
                or bundle.get("raw_payload_fingerprint") != fingerprint(bundle.get("raw_export"))
                or bundle.get("query_hash") != query.contract_hash
                or bundle.get("binary_sha256") != query.binary_sha256
                or bundle.get("use_site_id") != query.use_site_id):
            raise ValueError("Operand bundle identity or integrity failed")
        # This existing API checks the recorded plan/proof identities and claims;
        # it neither executes the program nor reads neural candidates.
        facts = operand_program_facts(query, bundle["plan"], bundle["evidence"])
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary differs from the previously proved query")
        from .operations import BinaryChecker
        checker = BinaryChecker(query)  # Loader/decoder only: no state or solver call.
        _check_straight_line_trace(query, bundle["evidence"], checker)
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary changed during the audit")
        result = derive_from_facts(facts, query, checker.object_base)
        result.update(bundle_path=str(path.resolve()), bundle_sha256=hashlib.sha256(payload).hexdigest(),
                      bundle_fingerprint=bundle["bundle_fingerprint"],
                      raw_payload_fingerprint=bundle["raw_payload_fingerprint"],
                      program_facts_fingerprint=fingerprint(facts),
                      static_trace_guard="matched_contiguous_straight_line_bytes",
                      retained_program_proof_validation=bundle["evidence"]["validation"])
    except Exception as exc:
        result.update(derived_status="unknown", query_decision_available_after_mapping=False,
                      reason=type(exc).__name__ + ": " + str(exc))
    result["audit_elapsed_seconds"] = time.monotonic() - started
    return result
