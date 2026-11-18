"""Paired information-only pilot on a fixed panel of bounded toy programs."""

from io import BytesIO
import time

from .contracts import Checkpoint, InputRange, Query, file_hash
from .scheduler import select_action
from .types import TypeView, project_type_candidates


GROUPS = ("clip", "lanes", "palette", "mirror", "grid", "cadence")
SCOPES = (("short", 31), ("full", 255))
ARMS = ("B", "C", "K", "D")
BUDGETS = (0.15, 0.5)
PRIMARY_BUDGET = 0.15
REPETITIONS = 2


def extract_queries(binary, group):
    """Bind the fixed fixture's single marked store to its declared output object."""
    import capstone
    from elftools.elf.elffile import ELFFile

    if group not in GROUPS or binary.name != group + ".elf":
        raise ValueError("Expected a compiled member of the fixed route B panel")
    elf = ELFFile(BytesIO(binary.read_bytes()))
    if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
            or elf["e_type"] != "ET_DYN" or not elf.has_dwarf_info(strict=True)):
        raise ValueError("Expected a DWARF-carrying AMD64 PIE fixture")
    loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
    if not loads or min(segment["p_vaddr"] for segment in loads) != 0:
        raise ValueError("Expected zero linked base")
    symbols = elf.get_section_by_name(".symtab")
    if symbols is None:
        raise ValueError("Expected fixture symbols")
    function, = symbols.get_symbol_by_name("route_b_step") or ()
    obj, = symbols.get_symbol_by_name("route_b_output") or ()
    entry, size, base, capacity = (int(function["st_value"]), int(function["st_size"]),
                                  int(obj["st_value"]), int(obj["st_size"]))
    if (function["st_info"]["type"] != "STT_FUNC" or obj["st_info"]["type"] != "STT_OBJECT"
            or not 0 < size <= 4096 or capacity != 64):
        raise ValueError("Fixture symbol types or sizes differ")
    segment, = (segment for segment in loads if segment["p_flags"] & 1
                and segment["p_vaddr"] <= entry
                and entry + size <= segment["p_vaddr"] + segment["p_filesz"])
    if sum(bool(segment["p_flags"] & 2) and segment["p_vaddr"] <= base
           and base + capacity <= segment["p_vaddr"] + segment["p_memsz"]
           for segment in loads) != 1:
        raise ValueError("Expected one writable segment for the fixture object")
    offset = entry - segment["p_vaddr"]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(segment.data()[offset:offset + size], entry))
    if sum(insn.size for insn in instructions) != size:
        raise ValueError("Fixture instruction coverage is incomplete")
    stores = [insn for insn in instructions if insn.mnemonic == "mov" and len(insn.operands) == 2
              and insn.operands[0].type == capstone.CS_OP_MEM and insn.operands[0].size == 1
              and insn.operands[1].type == capstone.CS_OP_IMM and insn.operands[1].imm == 0x41]
    store, = stores
    digest = file_hash(binary)
    return tuple(Query(f"{group}_{scope}", str(binary), digest, entry, store.address,
                       base, capacity, (InputRange("rdi", 0, limit),))
                 for scope, limit in SCOPES)


class UnscoredCandidates(TypeView):
    """Use uniform weights on a genuine Top-K set without exposing any scores."""

    def selector_features(self):
        features = super().selector_features()
        count = len(self.labels)
        return {**features, "weighting": "uniform_topk_set",
                "conditional_entropy": None,
                "candidate_disagreement": 1.0 - 1.0 / count}


def project_views(records, entry, artifact_hash, model_hash):
    """Bind to the single source parameter selected before scoring any operation."""
    matched = [r for r in records if r["function_address"] == entry
               and r.get("locator_variable_name") == "setting"]
    if len(matched) != 1:
        return {"B": TypeView()}, "missing_or_ambiguous_declared_parameter"
    record, = matched
    args = (record["candidates"], record["score_kind"])
    provenance = ("tygr_glowgnn", artifact_hash, model_hash)
    c = project_type_candidates(*args, "C", *provenance)
    d = project_type_candidates(*args, "D", *provenance)
    uniform = (1.0 / len(d.labels),) * len(d.labels)
    return {"B": TypeView(), "C": c,
            "K": UnscoredCandidates(d.labels, uniform, *provenance), "D": d}, None


def trial_order(group_index, scope_index, budget_index, repetition):
    offset = (group_index + scope_index + budget_index + 2 * repetition) % len(ARMS)
    return ARMS[offset:] + ARMS[:offset]


def run_trial(query, arm, view, budget, repetition, group, unavailable_reason=None):
    from .operations import BinaryChecker, BudgetExpired

    row = {"group": group, "query_id": query.query_id, "query_hash": query.contract_hash,
           "arm": arm, "budget": budget, "repetition": repetition, "actions": [],
           "status": "unknown", "reason": unavailable_reason, "charged_seconds": 0.0}
    if view is None:
        row["availability"] = "type_information_unavailable"
        return row
    row["availability"] = "available"
    row["type_view"] = view.selector_features()
    row["type_artifact_sha256"] = view.artifact_sha256 or None
    setup = time.monotonic()
    try:
        checker = BinaryChecker(query)
        structural = checker.structural_features()
    except Exception as error:
        row.update(availability="checker_setup_failed", reason=type(error).__name__)
        return row
    checkpoint = Checkpoint(query.contract_hash)
    row.update(preparation_seconds=time.monotonic() - setup, structural_features=structural,
               initial_checkpoint=checkpoint.checkpoint_id)
    started = time.monotonic()
    deadline = started + budget
    while time.monotonic() < deadline:
        operation, scores = select_action(checkpoint, "D" if arm == "K" else arm, view,
                                          structural_features=structural)
        if operation is None:
            row["reason"] = "operations_exhausted"
            break
        op = operation.operation_id
        before = time.monotonic()
        facts = ()
        status, reason = "unknown", None
        try:
            if before >= deadline:
                raise BudgetExpired()
            if op == "definitions":
                evidence = checker.prepare_dependencies(deadline)
                facts = ("dependencies_observed",)
                prefix = evidence.get("prepared_prefix", {})
                if prefix.get("status") == "ready":
                    facts += ("exact_prefix_prepared:" + prefix["cache_id"],)
                reason = "dependency_preparation_only"
            else:
                evidence = checker.check(operation.max_steps, deadline)
                evidence = checker.validate(evidence, operation.max_steps, deadline)
                status, reason = evidence["status"], evidence.get("reason")
        except Exception as error:
            status, reason = "unknown", type(error).__name__
        checkpoint = checkpoint.advance(op, facts)
        elapsed = time.monotonic() - started
        row["actions"].append({"operation": op, "scores": scores, "status": status,
                               "reason": reason, "elapsed_seconds": elapsed,
                               "operation_seconds": time.monotonic() - before})
        if elapsed > budget:
            row["reason"] = "information_budget_exhausted"
            break
        row.update(status=status, reason=reason)
        if status != "unknown":
            break
    if time.monotonic() > deadline:
        row.update(status="unknown", reason="information_budget_exhausted")
    row["charged_seconds"] = time.monotonic() - started
    return row


def evaluate(rows, labels):
    """Keep every planned query in the denominator and count gains by program group."""
    groups = {f"{group}_{scope}": group for group in GROUPS for scope, _ in SCOPES}
    if set(labels) != set(groups) or set(labels.values()) != {"excluded_within_scope"}:
        raise ValueError("Expected the separate bounded-fixture reference labels")
    key = lambda row: (row["query_id"], row["budget"], row["repetition"], row["arm"])
    by_key = {key(row): row for row in rows}
    expected = {(query_id, budget, repetition, arm) for query_id in groups
                for budget in BUDGETS for repetition in range(REPETITIONS) for arm in ARMS}
    if len(by_key) != len(rows) or set(by_key) != expected:
        raise ValueError("Incomplete or duplicate paired experiment")
    for row in rows:
        if row["status"] not in ("excluded_within_scope", "unknown", "violation"):
            raise ValueError("Unrecognized outcome")
        if groups[row["query_id"]] != row["group"]:
            raise ValueError("Incorrect program grouping")
        peer = by_key[(row["query_id"], row["budget"], row["repetition"], "B")]
        if row["query_hash"] != peer["query_hash"]:
            raise ValueError("Paired query identities differ")
        if row["availability"] == peer["availability"] == "available":
            if any(row[name] != peer[name] for name in ("initial_checkpoint", "structural_features")):
                raise ValueError("Paired inputs or structural features differ")

    def correct(row):
        return int(row["status"] == labels[row["query_id"]])

    overview = []
    for budget in BUDGETS:
        for arm in ARMS:
            trials = [row for row in rows if row["budget"] == budget and row["arm"] == arm]
            overview.append({"budget_seconds": budget, "arm": arm, "trials": len(trials),
                             "correct": sum(map(correct, trials)),
                             "unknown": sum(row["status"] == "unknown" for row in trials),
                             "wrong": sum(row["status"] == "violation" for row in trials),
                             "unavailable": sum(row["availability"] != "available" for row in trials)})

    comparisons = {}
    for baseline, arm in (("B", "C"), ("B", "K"), ("B", "D"), ("C", "K"), ("K", "D")):
        outcomes, unavailable, routing_gain_groups = {}, [], []
        first_action_changes = 0
        for group in GROUPS:
            pairs = [(by_key[(f"{group}_{scope}", PRIMARY_BUDGET, repetition, baseline)],
                      by_key[(f"{group}_{scope}", PRIMARY_BUDGET, repetition, arm)])
                     for repetition in range(REPETITIONS) for scope, _ in SCOPES]
            if any(a["availability"] != "available" or b["availability"] != "available" for a, b in pairs):
                unavailable.append(group)
                continue
            outcomes[group] = [sum(correct(b) - correct(a) for a, b in pairs
                                   if a["repetition"] == repetition)
                               for repetition in range(REPETITIONS)]
            first_action_changes += sum(bool(a["actions"] and b["actions"])
                                        and a["actions"][0]["operation"] != b["actions"][0]["operation"]
                                        for a, b in pairs)
            for repetition in range(REPETITIONS):
                same_repeat = [(a, b) for a, b in pairs if a["repetition"] == repetition]
                if not any(correct(b) > correct(a)
                           and any(x["operation"] != y["operation"]
                                   for x, y in zip(a["actions"], b["actions"]))
                           for a, b in same_repeat):
                    break
            else:
                if min(outcomes[group]) > 0:
                    routing_gain_groups.append(group)
        losses = [g for g, deltas in outcomes.items() if min(deltas) < 0]
        comparisons[f"{arm}_vs_{baseline}"] = {"available_group_deltas_by_repetition": outcomes,
                            "unavailable_groups": unavailable,
                            "consistent_gain_groups_with_order_change": routing_gain_groups,
                            "groups_with_any_loss": losses, "first_action_changes": first_action_changes}
    wrong = any(item["wrong"] for item in overview)
    versus_b = {arm: comparisons[f"{arm}_vs_B"] for arm in ARMS[1:]}
    passes = [arm for arm, comp in versus_b.items()
              if len(comp["available_group_deltas_by_repetition"]) >= 4
              and len(comp["consistent_gain_groups_with_order_change"]) >= 2
              and not comp["groups_with_any_loss"]]
    if wrong:
        decision = "review_property_correctness"
    elif passes:
        decision = "measure_paired_end_to_end_cost_next"
    elif all(len(comp["available_group_deltas_by_repetition"]) < 4 for comp in versus_b.values()):
        decision = "insufficient_genuine_coverage"
    else:
        decision = "no_stable_increment_on_this_panel"
    return {"schema": "symbai.route_b_information_summary.v1", "program_groups": len(GROUPS),
            "queries": len(groups), "repetitions": REPETITIONS, "primary_budget_seconds": PRIMARY_BUDGET,
            "overview": overview, "primary_paired_comparisons": comparisons,
            "arms_passing_information_gate": [] if wrong else passes, "decision": decision,
            "acquisition_and_common_preparation_charged": False, "variant_e_evaluated": False}
