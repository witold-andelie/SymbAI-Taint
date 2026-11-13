"""Small compiled-query extraction and bounded physical-operand assignment search."""

from copy import deepcopy
from itertools import permutations
import time

from .contracts import InputRange, Query, file_hash
from .operand_mapping import (ROLES, LOCATION_FIELDS, operand_id, validate_plan,
                              verify_operand_plan, validate_operand_evidence)


def validate_case_spec(case):
    fields = {"query_id", "source", "function_symbol", "object_symbol", "capacity", "input", "index_transform"}
    if set(case) != fields:
        raise ValueError("Unexpected compiled-query fields; result labels are offline only")
    if (not all(isinstance(case[k], str) and case[k] for k in ("query_id", "source", "function_symbol", "object_symbol"))
            or case["capacity"] != 8 or set(case["input"]) != {"register", "minimum", "maximum"}
            or case["input"] != {"register": "rdi", "minimum": 0, "maximum": 15}):
        raise ValueError("Unsupported compiled-query specification")
    transform = case["index_transform"]
    if (set(transform) != {"operation", "constant"}
            or transform["operation"] not in ("add_constant", "and_constant")
            or type(transform["constant"]) is not int or not 0 <= transform["constant"] < (1 << 64)):
        raise ValueError("Unsupported compiled-query index transform")


def extract_compiled_query(binary, case):
    validate_case_spec(case)
    import angr
    project = angr.Project(str(binary), auto_load_libs=False)
    if project.arch.name != "AMD64" or project.loader.main_object.__class__.__name__ != "ELF":
        raise ValueError("Compiled query requires AMD64 ELF")
    main = project.loader.main_object
    function, obj = main.get_symbol(case["function_symbol"]), main.get_symbol(case["object_symbol"])
    if not function or not obj or not 0 < function.size <= 4096 or obj.size != case["capacity"]:
        raise ValueError("Function/object symbols are missing or object capacity differs")
    instructions = project.factory.block(function.rebased_addr, size=function.size).capstone.insns
    targets = []
    for instruction in instructions:
        operands = instruction.insn.operands
        if (instruction.mnemonic == "mov" and len(operands) == 2 and operands[0].type == 3
                and operands[0].size == 1 and operands[1].type == 2 and operands[1].imm == 0x41):
            targets.append(instruction.address)
    if len(targets) != 1:
        raise ValueError("Compiled function must have exactly one declared constant byte write")
    query = Query(case["query_id"], str(binary.resolve()), file_hash(binary),
                  function.rebased_addr - main.mapped_base, targets[0] - main.mapped_base,
                  obj.rebased_addr - main.mapped_base, case["capacity"], (InputRange(**case["input"]),))
    return query, {"linked_image_base": main.linked_base,
                   "linked_function_address": main.linked_base + query.entry_rva,
                   "linked_object_address": main.linked_base + query.object_rva, "function_size": function.size,
                   "write_rva": query.write_rva, "basis": "ELF symbols and unique byte-store instruction"}


def propose_operand_assignments(query, raw, index_anchor, source_fingerprint, linked_base):
    """Enumerate two metadata assignments without looking at candidate labels or scores."""
    if raw.get("binary_sha256") != query.binary_sha256:
        raise ValueError("Raw locations belong to another binary")
    records = raw.get("records", [])
    if len({r["prediction_id"] for r in records}) != len(records):
        raise ValueError("Duplicate raw prediction identity")
    linked_entry, linked_write = linked_base + query.entry_rva, linked_base + query.write_rva
    eligible = []
    for record in records:
        locations = record.get("locations", [])
        if record.get("function_address") != linked_entry or len(locations) != 1:
            continue
        location = locations[0]
        if (location.get("location_class") == "CfaLocation" and location.get("location_register") is None
                and type(location.get("location_argument")) is int
                and type(location.get("low_pc")) is int and type(location.get("high_pc")) is int
                and location["low_pc"] <= linked_write < location["high_pc"]):
            eligible.append(record)
    if len(eligible) != 2:
        raise ValueError("Exactly two eligible CFA prediction locations are required; no name fallback")
    eligible.sort(key=lambda r: r["prediction_id"])
    proposals = []
    for assigned in permutations(eligible):
        operands = []
        for role, record in zip(ROLES, assigned):
            location = record["locations"][0]
            operands.append({"role": role, "operand_id": operand_id(query, role), "prediction_id": record["prediction_id"],
                "expected_identity": {"function_address": record["function_address"],
                    "locations": [{k: location.get(k) for k in LOCATION_FIELDS}]},
                "storage": {"kind": "cfa_relative", "cfa_offset": location["location_argument"], "size_bytes": 8},
                "anchor": {"kind": "object_base"} if role == "base_pointer" else deepcopy(index_anchor),
                "binding_basis": "bounded physical-location permutation; no human review claimed",
                "evidence": "Accept only after unique symbolic assignment verification and a fresh recheck."})
        plan = {"schema": "symbai.operand_plan.v2", "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "use_site_id": query.use_site_id, "address_space": "elf_linked_vaddr",
            "relation": "base_plus_index", "index_scale": 1, "write_length_bytes": 1,
            "cfa_rule": "entry_rsp_plus_8", "proposal_source_fingerprint": source_fingerprint, "operands": operands}
        validate_plan(query, plan)
        proposals.append(plan)
    return proposals


def resolve_operand_assignment(query, proposals, deadline, on_attempt=None):
    if len(proposals) != 2:
        raise ValueError("The compiled diagnostic expects exactly two physical assignments")
    attempts = []
    for plan in proposals:
        proof = verify_operand_plan(query, plan, deadline)
        attempts.append({"plan": plan, "evidence": proof})
        if on_attempt:
            on_attempt(deepcopy(attempts))
    verified = [r for r in attempts if r["evidence"]["status"] == "verified"]
    result = {"status": "unknown", "attempts": attempts}
    if len(verified) != 1:
        result["reason"] = "no_unique_verified_assignment"
        return result
    if any(r["evidence"]["status"] not in ("verified", "rejected") for r in attempts):
        result["reason"] = "unresolved_alternative_assignment"
        return result
    selected = verified[0]
    try:
        if time.monotonic() >= deadline:
            raise TimeoutError("Assignment search exhausted its mapping budget")
        checked = validate_operand_evidence(query, selected["plan"], selected["evidence"], deadline)
        result.update(status="verified", selected_plan=selected["plan"], validated_evidence=checked)
    except Exception as exc:
        result["reason"] = type(exc).__name__ + ": " + str(exc)
    return result
