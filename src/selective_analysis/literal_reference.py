"""Separate label-free modeled references; no neural types or abstract certificates."""

from itertools import product
import time

from .operations import BinaryChecker
from .contracts import file_hash


def reference_query(query, deadline, enumeration_cap=32):
    if type(enumeration_cap) is not int or enumeration_cap != 32:
        raise ValueError("The declared exhaustive reference cap is 32")
    if file_hash(query.binary) != query.binary_sha256:
        raise ValueError("Reference binary differs from the query identity")
    cardinality = 1
    for bounds in query.inputs:
        cardinality *= bounds.maximum - bounds.minimum + 1
    checker = BinaryChecker(query)
    if cardinality > enumeration_cap:
        result = checker.validate(checker.check(128, deadline, use_prepared=False), 128, deadline)
        return {"schema": "symbai.indirection_reference.v1", "query_hash": query.contract_hash,
                "binary_sha256": query.binary_sha256, "domain_cardinality": cardinality,
                "reference_mode": "fresh_symbolic_expanded", "result": result,
                "reference_is_runtime_feature": False, "native_replay": "not_attempted"}

    # Concrete values are literal register ASTs, not BVS expressions constrained to
    # one value. The inherited store observer still checks the exact target property.
    def literal_state(concrete=None):
        if not isinstance(concrete, dict) or set(concrete) != {b.register for b in query.inputs}:
            raise ValueError("A complete literal input assignment is required")
        state = checker.project.factory.call_state(checker.entry, ret_addr=checker.return_address)
        def mark(current):
            current.globals["precision_loss"] = tuple(current.globals.get("precision_loss", ())) + ("address_concretization",)
            raise ValueError("Literal reference cannot use address concretization")
        state.inspect.b("address_concretization", when=checker.angr.BP_BEFORE, action=mark)
        literals = {}
        for bounds in query.inputs:
            value = concrete[bounds.register]
            if type(value) is not int or not bounds.minimum <= value <= bounds.maximum:
                raise ValueError("Literal input lies outside the fixed query domain")
            literal = checker.claripy.BVV(value, 64)
            setattr(state.regs, bounds.register, literal)
            literals[bounds.register] = literal
        return state, literals
    checker.new_state = literal_state
    observe = checker._write_observation
    def literal_observation(state, write_deadline):
        captured = observe(state, write_deadline)
        if captured[1].symbolic or captured[2].symbolic or captured[0].globals.get("precision_loss"):
            raise ValueError("Literal reference target is not fully concrete")
        return captured
    checker._write_observation = literal_observation
    receipts = []
    mode = "exhaustive_literal_BVV_states_and_fresh_rechecks"
    values = product(*(range(bounds.minimum, bounds.maximum + 1) for bounds in query.inputs))
    for assignment in values:
        if time.monotonic() >= deadline:
            raise TimeoutError("Literal reference exceeded its deadline")
        concrete = dict(zip((b.register for b in query.inputs), assignment))
        result = checker.check(128, deadline, concrete=concrete, use_prepared=False)
        if result["status"] == "violation":
            result = checker.validate(result, 128, deadline)
            receipts.append({"input": concrete, "result": result})
            return {"schema": "symbai.indirection_reference.v1", "query_hash": query.contract_hash,
                    "binary_sha256": query.binary_sha256, "domain_cardinality": cardinality,
                    "reference_mode": mode, "result": result, "input_receipts": receipts,
                    "reference_is_runtime_feature": False, "native_replay": "not_attempted"}
        if result["status"] == "excluded_within_scope":
            replay = checker.check(128, deadline, concrete=concrete, use_prepared=False)
            if replay["status"] != "excluded_within_scope" or not replay["complete"]:
                raise ValueError("Literal exclusion failed fresh-state recheck")
            result = dict(result, validation="fresh_literal_state_complete_scope_recheck",
                          validation_executed_prefix_steps=replay["executed_prefix_steps"])
        receipts.append({"input": concrete, "result": result})
    complete = len(receipts) == cardinality and all(r["result"]["status"] == "excluded_within_scope" for r in receipts)
    return {"schema": "symbai.indirection_reference.v1", "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "domain_cardinality": cardinality,
            "reference_mode": mode, "input_receipts": receipts,
            "result": {"status": "excluded_within_scope" if complete else "unknown", "complete": complete,
                       "checked_inputs": len(receipts), "validation": "all_literal_inputs_freshly_rechecked" if complete else "incomplete_literal_reference"},
            "reference_is_runtime_feature": False, "native_replay": "not_attempted"}
