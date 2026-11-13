"""Fresh-checkpoint operation probes; no type, label or mapping-proof inputs."""

from copy import deepcopy
import time

from .contracts import Checkpoint, Query, fingerprint

PROBES = ("bounded_paths", "expanded_paths", "definitions_then_expanded",
          "direct_prefix_then_expanded", "local_bounds")
REVISION = "operation_evidence_gate_v11"


def initial_features(query):
    from .operations import BinaryChecker
    checker = BinaryChecker(query)
    block = checker.project.factory.block(checker.entry)
    masks = [int(i.insn.operands[1].imm) for i in block.capstone.insns
             if i.mnemonic == "and" and len(i.insn.operands) == 2 and i.insn.operands[1].type == 2]
    features = {"available": True, **checker.structural_features(),
        "entry_has_call": any(i.mnemonic == "call" for i in block.capstone.insns),
        "entry_has_unsigned_branch": any(i.mnemonic in ("ja", "jae", "jb", "jbe") for i in block.capstone.insns),
        "entry_immediate_and_masks": masks, "capacity": query.capacity,
        "input_ranges": [{"register": r.register, "minimum": r.minimum, "maximum": r.maximum} for r in query.inputs]}
    return features


def structural_first_hint(features):
    if not features.get("available"):
        return "expanded_paths"
    if features["entry_immediate_and_masks"] or features["entry_has_unsigned_branch"]:
        return "local_bounds"
    position = features["write_index_in_entry_block"]
    return "bounded_paths" if position is not None and position < 8 else "expanded_paths"


def prepare_direct_prefix(checker, deadline):
    """Paid exact execution only; no CFG/RDA and no instruction skipping."""
    checker._prepared_prefix = None
    addresses = list(checker.project.factory.block(checker.entry).instruction_addrs)
    report = {"status": "not_prepared", "build_steps": 0, "backend": "direct_entry_prefix_without_rda"}
    if checker.write not in addresses:
        return dict(report, reason="target_not_in_entry_block")
    prefix = addresses[:addresses.index(checker.write)]
    if len(prefix) > 64:
        return dict(report, reason="prefix_snapshot_limit")
    state, symbols = checker.new_state()
    snapshots = [state.copy()]
    for address in prefix:
        if time.monotonic() >= deadline:
            raise TimeoutError("Direct prefix preparation exhausted its deadline")
        if state.addr != address or checker.project.is_hooked(address):
            return dict(report, reason="unsupported_prefix_location")
        state.solver._solver.timeout = max(1, int((deadline - time.monotonic()) * 1000))
        successors = checker.project.factory.successors(state, num_inst=1)
        report["build_steps"] += 1
        if (len(successors.flat_successors) != 1 or successors.unconstrained_successors
                or successors.artifacts.get("irsb") is None):
            return dict(report, reason="prefix_not_exact_single_successor")
        state = successors.flat_successors[0]
        if state.globals.get("precision_loss") or str(state.history.jumpkind).startswith(("Ijk_Sys", "Ijk_Call")):
            return dict(report, reason="unsupported_prefix_behavior")
        snapshots.append(state.copy())
    if state.addr != checker.write:
        return dict(report, reason="prefix_did_not_reach_target")
    if time.monotonic() >= deadline:
        raise TimeoutError("Direct prefix preparation exhausted its deadline")
    cache_id = fingerprint({"query_hash": checker.query.contract_hash,
        "kind": "direct_entry_prefix_without_rda", "depth": len(prefix)})
    checker._prepared_prefix = {"query_hash": checker.query.contract_hash, "symbols": symbols,
                               "snapshots": snapshots, "cache_id": cache_id}
    return dict(report, status="ready", reason="exact_single_successor_prefix", cache_id=cache_id,
                deepest_depth=len(prefix))


def missing_probe(query, probe_id, repetition, features, reason, availability="not_started", observed_seconds=0.0):
    return {"schema": "symbai.operation_effect_trial.v1", "query_id": query.query_id,
        "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
        "checkpoint_id": Checkpoint(query.contract_hash).checkpoint_id, "repetition": repetition,
        "probe_id": probe_id, "initial_features": deepcopy(features), "availability": availability,
        "result": {"status": "unknown", "reason": reason},
        "costs_seconds": {k: 0.0 for k in ("setup", "preparation", "execution", "validation", "recording")},
        "cost_measurement_complete": False,
        "probe_elapsed_seconds": observed_seconds,
        "effects": {"query_decision_progress": False, "planning_artifacts": {},
            "abstract_instruction_steps": 0, "validation_abstract_instruction_steps": 0,
            "prefix_work": {"preparation_steps": 0, "execution_steps": 0, "validation_steps": 0,
                "total_executed_steps": 0, "reused_prefix_steps": 0, "measurement_complete": False}}}


def probe_operation(query, probe_id, repetition, features, deadline):
    if probe_id not in PROBES:
        raise ValueError("Unknown operation-evidence probe")
    started = time.monotonic()
    row = missing_probe(query, probe_id, repetition, features, "operation_incomplete", "available")
    costs = row["costs_seconds"]
    effects, phase, before = row["effects"], "setup", started
    prepared, preparation_complete = None, True
    try:
        if before >= deadline:
            raise TimeoutError("Operation probe deadline reached")
        # Each alternative independently rechecks the binary and creates its own checker.
        from dataclasses import asdict
        checked_query = Query.from_dict(asdict(query))
        if probe_id == "local_bounds":
            from .local_bounds import LocalBoundsChecker
            checker = LocalBoundsChecker(checked_query)
        else:
            from .operations import BinaryChecker
            checker = BinaryChecker(checked_query)
        costs[phase] += time.monotonic() - before
        phase, before = "preparation", time.monotonic()
        reuse = False
        if probe_id in ("definitions_then_expanded", "direct_prefix_then_expanded"):
            try:
                if probe_id == "definitions_then_expanded":
                    prepared = checker.prepare_dependencies(deadline)
                    summary = prepared["prepared_prefix"]
                    dependencies = prepared["dependencies"]
                    effects["planning_artifacts"] = {"backend": dependencies["backend"],
                        "definition_count": dependencies["definition_count"], "edge_count": dependencies["edge_count"],
                        "target_slice_definition_count": len(dependencies["target_slice_definition_ids"]),
                        "completeness": dependencies["completeness"], "prepared_prefix": summary}
                else:
                    summary = prepare_direct_prefix(checker, deadline)
                    effects["planning_artifacts"] = {"backend": "direct_entry_prefix_without_rda", "prepared_prefix": summary}
                effects["prefix_work"]["preparation_steps"] = summary["build_steps"]
                reuse = summary["status"] == "ready"
            except Exception as exc:
                # Preserve failed preparation and still pay/check from a fresh state.
                effects["planning_artifacts"]["error"] = type(exc).__name__ + ": " + str(exc)
                preparation_complete = False
        costs[phase] += time.monotonic() - before
        phase, before = "execution", time.monotonic()
        if before >= deadline:
            raise TimeoutError("Preparation exhausted the operation probe deadline")
        steps = 8 if probe_id == "bounded_paths" else 128
        outcome = (checker.check(deadline) if probe_id == "local_bounds" else
                   checker.check(steps, deadline, use_prepared=reuse))
        if probe_id == "local_bounds":
            effects["abstract_instruction_steps"] = outcome.get("abstract_instructions", 0)
        else:
            effects["prefix_work"]["execution_steps"] = outcome["executed_prefix_steps"]
            effects["prefix_work"]["reused_prefix_steps"] = outcome["reused_prefix_steps"]
        costs[phase] += time.monotonic() - before
        phase, before = "validation", time.monotonic()
        if before >= deadline:
            raise TimeoutError("Execution exhausted the operation probe deadline")
        outcome = checker.validate(outcome, deadline) if probe_id == "local_bounds" else checker.validate(outcome, steps, deadline)
        row["result"] = outcome
        if (outcome["status"] == "unknown" and outcome.get("remaining_states", 0) > 0
                and not outcome.get("unsupported")):
            outcome["reason"] = "instruction_depth_limit"
        if probe_id == "local_bounds":
            if outcome["status"] != "unknown":
                effects["validation_abstract_instruction_steps"] = outcome["abstract_instructions"]
        else:
            effects["prefix_work"]["validation_steps"] = outcome.get("validation_executed_prefix_steps", 0)
        costs[phase] += time.monotonic() - before
        phase = None
        if time.monotonic() >= deadline:
            row["late_candidate_result"] = outcome
            raise TimeoutError("Validation exhausted the operation probe deadline")
        effects["query_decision_progress"] = outcome["status"] != "unknown"
        effects["prefix_work"]["measurement_complete"] = preparation_complete
    except Exception as exc:
        if phase is not None:
            costs[phase] += time.monotonic() - before
        row["result"] = {"status": "unknown", "reason": type(exc).__name__ + ": " + str(exc)}
        effects["query_decision_progress"] = False
        row["availability"] = "failed"
    work = effects["prefix_work"]
    work["total_executed_steps"] = work["preparation_steps"] + work["execution_steps"] + work["validation_steps"]
    recording_started = time.monotonic()
    # Serialize a full provisional record inside the observed probe interval.
    import json
    json.dumps(row)
    costs["recording"] += time.monotonic() - recording_started
    row.update(probe_elapsed_seconds=time.monotonic() - started, cost_measurement_complete=True)
    return row
