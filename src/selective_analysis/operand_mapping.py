"""Role-qualified type views, backed by program relations rather than neural assumptions."""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import time

from .contracts import file_hash, fingerprint
from .types import TypeInformationUnavailable, TypeView, project_type_candidates

REVISION = "affine_cfa_operands_v7"
TRANSFORM_REVISION = "transformed_cfa_operands_v8"
ROLES = ("base_pointer", "index")
LOCATION_FIELDS = ("low_pc", "high_pc", "location_class", "location_register", "location_argument")
CLAIMS = ("target_state_satisfiable", "base_slot_equals_object_base", "index_slot_equals_entry_input",
          "write_address_equals_base_plus_index", "write_length_equals_one")


def _revision(plan):
    return REVISION if plan["schema"] == "symbai.operand_plan.v1" else TRANSFORM_REVISION


def _claims(plan):
    return CLAIMS if plan["schema"] == "symbai.operand_plan.v1" else (
        CLAIMS[0], CLAIMS[1], "index_slot_equals_entry_expression", CLAIMS[3], CLAIMS[4])


def operand_id(query, role):
    if role not in ROLES:
        raise ValueError("Unsupported operand role")
    return query.use_site_id + ":" + role


def _locations(record):
    return [{field: loc.get(field) for field in LOCATION_FIELDS} for loc in record.get("locations", [])]


def validate_plan(query, plan):
    source_field = "proposal_source_fingerprint" if plan.get("schema") == "symbai.operand_plan.v2" else "review_source_sha256"
    root_fields = {"schema", "query_hash", "binary_sha256", "use_site_id", "address_space", "relation",
                   "index_scale", "write_length_bytes", "cfa_rule", "operands", source_field}
    if (set(plan) != root_fields or plan["schema"] not in ("symbai.operand_plan.v1", "symbai.operand_plan.v2")
            or plan["query_hash"] != query.contract_hash or plan["binary_sha256"] != query.binary_sha256
            or plan["use_site_id"] != query.use_site_id or plan["address_space"] != "elf_linked_vaddr"
            or plan["relation"] != "base_plus_index" or plan["index_scale"] != 1
            or plan["write_length_bytes"] != 1 or plan["cfa_rule"] != "entry_rsp_plus_8"
            or len(plan[source_field]) != 64):
        raise ValueError("Invalid, mismatched or unsupported operand plan")
    entries = plan["operands"]
    if [e.get("role") for e in entries] != list(ROLES):
        raise ValueError("Exactly one ordered base_pointer and index are required")
    if len({e.get("prediction_id") for e in entries}) != len(ROLES):
        raise ValueError("Independent operands require distinct prediction identities")
    for entry in entries:
        basis_field = "binding_basis" if plan["schema"] == "symbai.operand_plan.v2" else "reviewed_by"
        if set(entry) != {"role", "operand_id", "prediction_id", "expected_identity", "storage", "anchor", basis_field, "evidence"}:
            raise ValueError("Unexpected operand-plan fields; type scores are not proof inputs")
        if entry["operand_id"] != operand_id(query, entry["role"]) or not entry["prediction_id"] or not entry[basis_field] or not entry["evidence"]:
            raise ValueError("Operand identity or review provenance is missing")
        storage = entry["storage"]
        if (set(storage) != {"kind", "cfa_offset", "size_bytes"} or storage["kind"] != "cfa_relative"
                or storage["size_bytes"] != 8 or type(storage["cfa_offset"]) is not int
                or not -4096 <= storage["cfa_offset"] < 4096):
            raise ValueError("Unsupported operand storage")
        expected = entry["expected_identity"]
        if set(expected) != {"function_address", "locations"} or len(expected["locations"]) != 1:
            raise ValueError("One explicit function/location identity is required")
        location = expected["locations"][0]
        if (set(location) != set(LOCATION_FIELDS) or location["location_class"] != "CfaLocation"
                or location["location_register"] is not None
                or location["location_argument"] != storage["cfa_offset"]
                or type(location["low_pc"]) is not int or type(location["high_pc"]) is not int
                or not 0 <= location["low_pc"] < location["high_pc"]):
            raise ValueError("CFA storage and locator identity differ")
        anchor = entry["anchor"]
        if entry["role"] == "base_pointer":
            if anchor != {"kind": "object_base"}:
                raise ValueError("The base operand requires the declared object anchor")
        else:
            fields = {"kind", "register"} if plan["schema"] == "symbai.operand_plan.v1" else {"kind", "register", "transform"}
            if set(anchor) != fields or anchor["kind"] != "entry_input" or anchor["register"] not in {r.register for r in query.inputs}:
                raise ValueError("The index requires an explicit query entry-input anchor")
            if "transform" in anchor:
                transform = anchor["transform"]
                if (set(transform) != {"operation", "constant"}
                        or transform["operation"] not in ("add_constant", "and_constant")
                        or type(transform["constant"]) is not int or not 0 <= transform["constant"] < (1 << 64)):
                    raise ValueError("Unsupported index-anchor expression")


def make_probe_plan(query, raw, review_source_sha256):
    """Use the probe's existing physical review, never variable names or predicted labels."""
    # This proposal factory is intentionally narrower than the verifier's ELF subset.
    if (query.contract_hash != "3d2a4a0103efffea4c649986f265a32e6518fc79c15218c6a6b045a598e0299c"
            or query.binary_sha256 != "0fb55db6be585f4c71134f6a9483828292f5a73f529420bc21a753a62a7c81a5"
            or query.entry_rva != 0x1129 or query.write_rva != 0x114b
            or [(r.register, r.minimum, r.maximum) for r in query.inputs] != [("rdi", 0, 15)]):
        raise ValueError("The probe proposal factory requires its existing reviewed binary/query")
    entries = []
    for role, offset in zip(ROLES, (-24, -40)):
        matches = [r for r in raw["records"] if r.get("function_address") == query.entry_rva
                   and len(r.get("locations", [])) == 1
                   and r["locations"][0].get("location_class") == "CfaLocation"
                   and r["locations"][0].get("location_argument") == offset]
        if len(matches) != 1:
            raise ValueError("Physical probe location is absent or ambiguous")
        record = matches[0]
        entries.append({"role": role, "operand_id": operand_id(query, role), "prediction_id": record["prediction_id"],
            "expected_identity": {"function_address": record["function_address"], "locations": _locations(record)},
            "storage": {"kind": "cfa_relative", "cfa_offset": offset, "size_bytes": 8},
            "anchor": {"kind": "object_base"} if role == "base_pointer" else {"kind": "entry_input", "register": "rdi"},
            "reviewed_by": "existing one-case assembly/CFA review plus fresh symbolic verification",
            "evidence": "Existing physical slot review; verify the binding and address relation independently of neural candidates."})
    plan = {"schema": "symbai.operand_plan.v1", "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "use_site_id": query.use_site_id,
            "address_space": "elf_linked_vaddr", "relation": "base_plus_index", "index_scale": 1,
            "write_length_bytes": 1, "cfa_rule": "entry_rsp_plus_8", "operands": entries,
            "review_source_sha256": review_source_sha256}
    validate_plan(query, plan)
    return plan


def verify_operand_plan(query, plan, deadline, max_steps=64):
    """Fresh single-successor program evidence. No candidate label or score is accepted."""
    validate_plan(query, plan)
    evidence = {"schema": "symbai.operand_evidence.v1", "revision": _revision(plan),
                "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
                "plan_fingerprint": fingerprint(plan), "status": "unknown", "checks": {}, "prefix_trace": [],
                "scope": "declared_query_domain_first_visit_single_successor_prefix"}
    try:
        from .operations import BinaryChecker
        def remaining():
            if time.monotonic() >= deadline:
                raise TimeoutError("Operand verification exhausted its deadline")
            return max(1, int((deadline - time.monotonic()) * 1000))
        remaining()
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Operand binary differs from its query hash")
        if type(max_steps) is not int or not 0 < max_steps <= 64:
            raise ValueError("Operand verification supports at most 64 prefix instructions")
        checker = BinaryChecker(query)
        linked_base = checker.project.loader.main_object.linked_base
        linked_entry, linked_write = linked_base + query.entry_rva, linked_base + query.write_rva
        for entry in plan["operands"]:
            expected = entry["expected_identity"]
            location = expected["locations"][0]
            if expected["function_address"] != linked_entry or not location["low_pc"] <= linked_write < location["high_pc"]:
                raise ValueError("Operand locator does not cover the query function/use site")
        state, symbols = checker.new_state()
        state.solver._solver.timeout = remaining()
        if not state.solver.unique(state.regs.rsp):
            raise ValueError("Entry CFA is not concrete")
        cfa = state.solver.eval(state.regs.rsp) + 8
        if cfa >= 1 << 64:
            raise ValueError("Entry CFA wraps")
        while state.addr != checker.write:
            state.solver._solver.timeout = remaining()
            if len(evidence["prefix_trace"]) >= max_steps:
                raise ValueError("Operand prefix work limit")
            if state.globals.get("precision_loss") or checker.project.is_hooked(state.addr):
                raise ValueError("Operand prefix precision loss or unmodeled hook")
            block = checker.project.factory.block(state.addr, num_inst=1)
            evidence["prefix_trace"].append({"rva": state.addr - checker.base, "bytes": bytes(block.bytes).hex()})
            successors = checker.project.factory.successors(state, num_inst=1)
            if len(successors.flat_successors) != 1 or successors.unconstrained_successors or successors.artifacts.get("irsb") is None:
                raise ValueError("Operand prefix is not an exact single successor")
            state = successors.flat_successors[0]
            if str(state.history.jumpkind).startswith(("Ijk_Sys", "Ijk_Call")) or state.globals.get("precision_loss"):
                raise ValueError("Operand prefix has an unsupported call or precision loss")
        snapshot, address, length, _unused_bad_condition = checker._write_observation(state, deadline)
        snapshot.solver._solver.timeout = remaining()
        if not snapshot.solver.satisfiable():
            raise ValueError("Operand target state is empty; vacuous proof refused")
        evidence["checks"]["target_state_satisfiable"] = True
        values = {}
        for entry in plan["operands"]:
            position = cfa + entry["storage"]["cfa_offset"]
            if not 0 <= position <= (1 << 64) - 8:
                raise ValueError("Operand storage wraps")
            values[entry["role"]] = snapshot.memory.load(position, 8, endness=snapshot.arch.memory_endness)
        index_register = plan["operands"][1]["anchor"]["register"]
        expression = symbols[index_register]
        transform = plan["operands"][1]["anchor"].get("transform")
        if transform:
            expression = (expression + transform["constant"] if transform["operation"] == "add_constant"
                          else expression & transform["constant"])
        negations = (
            ("base_slot_equals_object_base", values["base_pointer"] != checker.object_base),
            (_claims(plan)[2], values["index"] != expression),
            ("write_address_equals_base_plus_index", address != values["base_pointer"] + values["index"]),
            ("write_length_equals_one", length != 1))
        for name, negation in negations:
            snapshot.solver._solver.timeout = remaining()
            holds = not snapshot.solver.satisfiable(extra_constraints=(negation,))
            remaining()
            evidence["checks"][name] = holds
            if not holds:
                evidence.update(status="rejected", reason="satisfiable_negation:" + name)
                return evidence
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Operand binary changed during verification")
        remaining()
        evidence.update(status="verified", linked_image_base=linked_base,
                        linked_function_address=linked_entry, linked_write_address=linked_write,
                        proof_method="UNSAT_of_binding_and_address_negations", prefix_steps=len(evidence["prefix_trace"]))
    except Exception as exc:
        evidence.update(status="unknown", reason=type(exc).__name__ + ": " + str(exc))
    return evidence


def validate_operand_evidence(query, plan, evidence, deadline):
    if evidence.get("status") != "verified" or any(evidence.get("checks", {}).get(k) is not True for k in _claims(plan)):
        raise ValueError("Complete verified operand evidence is required")
    replay = verify_operand_plan(query, plan, deadline)
    if fingerprint(replay) != fingerprint(evidence):
        raise ValueError("Operand evidence failed fresh symbolic recheck")
    return {**deepcopy(evidence), "proof_fingerprint": fingerprint(evidence),
            "validation": "fresh_symbolic_recheck", "verification_passes": 2}


def _validate_evidence(query, plan, evidence):
    validate_plan(query, plan)
    proof_body = {key: value for key, value in evidence.items()
                  if key not in ("proof_fingerprint", "validation", "verification_passes")}
    if (evidence.get("schema") != "symbai.operand_evidence.v1" or evidence.get("revision") != _revision(plan)
            or evidence.get("status") != "verified" or evidence.get("query_hash") != query.contract_hash
            or evidence.get("binary_sha256") != query.binary_sha256
            or evidence.get("plan_fingerprint") != fingerprint(plan)
            or evidence.get("validation") != "fresh_symbolic_recheck" or evidence.get("verification_passes") != 2
            or evidence.get("proof_fingerprint") != fingerprint(proof_body)
            or evidence.get("scope") != "declared_query_domain_first_visit_single_successor_prefix"
            or evidence.get("proof_method") != "UNSAT_of_binding_and_address_negations"
            or any(evidence.get("checks", {}).get(k) is not True for k in _claims(plan))):
        raise ValueError("Operand evidence is incomplete, stale or not freshly rechecked")
    linked_base = evidence.get("linked_image_base")
    if (type(linked_base) is not int or evidence.get("linked_function_address") != linked_base + query.entry_rva
            or evidence.get("linked_write_address") != linked_base + query.write_rva
            or not isinstance(evidence.get("prefix_trace"), list)
            or evidence.get("prefix_steps") != len(evidence["prefix_trace"]) or len(evidence["prefix_trace"]) > 64):
        raise ValueError("Operand evidence lacks coherent linked addresses or prefix trace")
    return linked_base


def operand_program_facts(query, plan, evidence):
    """Common non-neural facts for every future policy arm; never includes candidate types."""
    _validate_evidence(query, plan, evidence)
    return {"schema": "symbai.operand_program_facts.v1", "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "relation": plan["relation"], "index_scale": 1,
            "write_length_bytes": 1, "evidence_fingerprint": evidence["proof_fingerprint"],
            "operands": [{"role": e["role"], "operand_id": e["operand_id"],
                          "storage": deepcopy(e["storage"]), "anchor": deepcopy(e["anchor"])}
                         for e in plan["operands"]]}


def _bindings(query, raw, plan, evidence):
    linked_base = _validate_evidence(query, plan, evidence)
    provenance = raw.get("provenance", {})
    if (raw.get("schema") != "symbai.tygr_raw.v1" or raw.get("binary_sha256") != query.binary_sha256
            or provenance.get("source") != "tygr_glowgnn" or len(provenance.get("model_sha256", "")) != 64
            or provenance.get("decoder") != "independent" or provenance.get("ground_truth_labels_supplied_to_model") is not False):
        raise ValueError("Operand mapping requires matching genuine unlabeled raw export")
    records = {record["prediction_id"]: record for record in raw["records"]}
    if len(records) != len(raw["records"]):
        raise ValueError("Duplicate raw prediction identity")
    bindings = []
    for entry in plan["operands"]:
        record = records[entry["prediction_id"]]
        expected = entry["expected_identity"]
        location = expected["locations"][0]
        if (expected["function_address"] != linked_base + query.entry_rva
                or not location["low_pc"] <= linked_base + query.write_rva < location["high_pc"]
                or record.get("function_address") != expected["function_address"] or _locations(record) != expected["locations"]):
            raise ValueError("Raw prediction physical identity differs from the operand plan")
        bindings.append({"role": entry["role"], "operand_id": entry["operand_id"],
                         "prediction_id": entry["prediction_id"], "raw_record_fingerprint": fingerprint(record)})
    return bindings


def map_operand_candidates(query, raw, plan, evidence):
    bindings = _bindings(query, raw, plan, evidence)
    body = {"schema": "symbai.operand_types.v1", "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256, "use_site_id": query.use_site_id,
            "raw_export": deepcopy(raw), "raw_payload_fingerprint": fingerprint(raw),
            "plan": deepcopy(plan), "evidence": deepcopy(evidence), "bindings": bindings}
    return {**body, "bundle_fingerprint": fingerprint(body)}


@dataclass(frozen=True)
class OperandTypeView:
    role: str
    operand_id: str
    prediction_id: str
    view: TypeView

    def selector_features(self):
        return {"role": self.role, "operand_id": self.operand_id, "prediction_id": self.prediction_id,
                "type_features": self.view.selector_features()}


def load_operand_views(path, query, variant):
    if variant in ("A", "B"):
        return ()
    if variant not in ("C", "D"):
        raise TypeInformationUnavailable("Operand projection requires an A-D view")
    data_bytes = path.read_bytes()
    bundle = json.loads(data_bytes)
    body = {key: value for key, value in bundle.items() if key != "bundle_fingerprint"}
    if (bundle.get("schema") != "symbai.operand_types.v1" or bundle.get("bundle_fingerprint") != fingerprint(body)
            or bundle.get("query_hash") != query.contract_hash or bundle.get("binary_sha256") != query.binary_sha256
            or bundle.get("use_site_id") != query.use_site_id
            or bundle.get("raw_payload_fingerprint") != fingerprint(bundle.get("raw_export"))):
        raise TypeInformationUnavailable("Operand bundle identity or integrity failed")
    try:
        bindings = _bindings(query, bundle["raw_export"], bundle["plan"], bundle["evidence"])
    except (ValueError, KeyError, TypeError) as exc:
        raise TypeInformationUnavailable("Invalid operand binding: " + str(exc)) from exc
    if bindings != bundle["bindings"]:
        raise TypeInformationUnavailable("Operand bindings differ from their raw records")
    raw = bundle["raw_export"]
    records = {r["prediction_id"]: r for r in raw["records"]}
    provenance, result = raw["provenance"], []
    for binding in bindings:
        record = records[binding["prediction_id"]]
        view = project_type_candidates(record.get("candidates", []), record.get("score_kind"), variant,
            provenance["source"], hashlib.sha256(data_bytes).hexdigest(), provenance["model_sha256"])
        result.append(OperandTypeView(binding["role"], binding["operand_id"], binding["prediction_id"], view))
    return tuple(result)
