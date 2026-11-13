#!/usr/bin/env python3
"""Validate the frozen OPM DOT profile; optionally regenerate its SVG previews.

This validates architecture artifacts, not an executable scheduler or full OPM semantics.
Requires Graphviz on PATH. No application dependencies or network access are used.
"""

import argparse
from collections import defaultdict, deque
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "docs" / "architecture"
PROTOCOL_ID = "symbai-selective-analysis-pilot-v1"
RELATIONS = {
    "instrument": ("object", "process", "requires", "odot"),
    "consumption": ("object", "process", "consumes", "normal"),
    "result": ("process", "object", "yields", "onormal"),
    "effect": ("object", "process", "affects", "normal"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def workspace_environment():
    """Keep task-created process/cache files on the shared workspace drive."""
    scratch = ROOT.parent / ".scratch" / "architecture"
    scratch.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        env[key] = str(scratch)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def check_contract():
    contract = json.loads((MODELS / "pilot_contract.json").read_text(encoding="utf-8"))
    require(contract["protocol_id"] == PROTOCOL_ID, "Unexpected protocol ID")
    require(contract["implementation_status"] in {
        "target_design_not_implemented", "partial_development_prototype"
    }, "Unsupported implementation claim")
    if contract["implementation_status"] == "partial_development_prototype":
        require((ROOT / contract.get("implementation_evidence", "missing")).is_file(),
                "Partial implementation requires an evidence guide")
        if "operand_mapping_and_projection_implemented" in contract.get("completed_capabilities", []):
            require((ROOT / "src/selective_analysis/operand_mapping.py").is_file()
                    and (ROOT / "scripts/review_operand_mapping.py").is_file(),
                    "Operand-mapping claim requires verifier/projector and review entry")
            diagnostic = contract.get("operand_mapping_diagnostic", {})
            require(diagnostic.get("roles") == ["base_pointer", "index"]
                    and diagnostic.get("common_program_facts") is True
                    and diagnostic.get("selector_integration") is False,
                    "Operand projection must keep independent roles, shared facts and its separate diagnostic scope")
        if "compiled_query_diagnostic_implemented" in contract.get("completed_capabilities", []):
            diagnostic = contract.get("compiled_query_diagnostic", {})
            require((ROOT / "scripts/run_compiled_queries.py").is_file()
                    and diagnostic.get("planned_queries") == 2
                    and diagnostic.get("selector_integration") is False
                    and diagnostic.get("held_out_evaluation") is False,
                    "Compiled-query diagnostic must retain its two developer-query scope")
            require("compiled_query_genuine_acquisition_and_mapping_validation" in contract.get("pending_capabilities", [])
                    or "two_compiled_queries_genuine_acquisition_and_mapping_validated" in contract.get("completed_capabilities", []),
                    "Do not confuse compiled-query implementation with genuine WSL validation")
        if "frame_bounds_checker_implemented" in contract.get("completed_capabilities", []):
            diagnostic = contract.get("frame_bounds_diagnostic", {})
            require((ROOT / "src/selective_analysis/frame_bounds.py").is_file()
                    and (ROOT / "scripts/run_frame_bounds_gate.py").is_file()
                    and diagnostic.get("unique_queries") == 3
                    and diagnostic.get("planned_records") == 27
                    and diagnostic.get("neural_information_used") is False,
                    "Frame checking must remain a separate three-query, type-free diagnostic")
        if "shared_process_batch_diagnostic_implemented" in contract.get("completed_capabilities", []):
            batch = contract.get("batch_cost_diagnostic", {})
            require((ROOT / "src/selective_analysis/frame_batch.py").is_file()
                    and (ROOT / "scripts/run_frame_batch.py").is_file()
                    and batch.get("accounting_unit") == "three_query_cold_batch"
                    and batch.get("planned_batches") == 9 and batch.get("planned_query_outcomes") == 27
                    and batch.get("neural_information_used") is False,
                    "Batch accounting must preserve its distinct unit and all planned outcomes")
        if "operation_evidence_gate_implemented" in contract.get("completed_capabilities", []):
            effects = contract.get("operation_evidence_diagnostic", {})
            require((ROOT / "scripts/run_operation_effects.py").is_file()
                    and effects.get("primary_unique_queries") == 12
                    and effects.get("planned_probe_records") == 180
                    and effects.get("compiled_panel_pooled") is False
                    and effects.get("neural_selection_measured") is False,
                    "Operation effects must preserve the fixed primary panel and separate proof audit")
        if "location_correspondence_implemented" in contract.get("completed_capabilities", []):
            location = contract.get("location_correspondence_diagnostic", {})
            require((ROOT / "src/selective_analysis/location_correspondence.py").is_file()
                    and (ROOT / "scripts/run_location_correspondence.py").is_file()
                    and location.get("bundle_schema") == "symbai.location_type_bundle.v1"
                    and location.get("planned_cases") == 3
                    and location.get("property_verification_performed") is False
                    and location.get("selector_integration") is False,
                    "Location correspondence must remain separate from property proofs and selection")
        if "routing_sensitivity_implemented" in contract.get("completed_capabilities", []):
            routing = contract.get("routing_sensitivity_diagnostic", {})
            require((ROOT / "src/selective_analysis/routing_sensitivity.py").is_file()
                    and (ROOT / "scripts/run_routing_sensitivity.py").is_file()
                    and routing.get("planned_cases") == 3 and routing.get("planned_rows") == 45
                    and routing.get("operations") == ["frame_bounds", "expanded_paths"]
                    and routing.get("groups") == ["B", "C", "D"]
                    and routing.get("property_operations_executed") is False
                    and routing.get("frozen_selector_changed") is False
                    and routing.get("held_out_evaluation") is False,
                    "Routing sensitivity must remain a three-input order diagnostic, not executed benefit")
        if "readonly_indirection_mechanism_implemented" in contract.get("completed_capabilities", []):
            indirect = contract.get("readonly_indirection_diagnostic", {})
            require((ROOT / "src/selective_analysis/readonly_values.py").is_file()
                    and (ROOT / "src/selective_analysis/literal_reference.py").is_file()
                    and (ROOT / "scripts/run_indirection_gate.py").is_file()
                    and indirect.get("unique_mechanism_queries") == 3
                    and indirect.get("runtime_records") == 12
                    and indirect.get("separate_reference_records") == 3
                    and indirect.get("cardinality_limit") == 32
                    and indirect.get("neural_selection_measured") is False
                    and indirect.get("pooled_with_existing_panels") is False,
                    "Readonly indirection must preserve its separate authored panel and non-neural boundary")
        if "fixed_complete_cascade_implemented" in contract.get("completed_capabilities", []):
            cascade = contract.get("fixed_cascade_diagnostic", {})
            require((ROOT / "src/selective_analysis/fixed_cascade.py").is_file()
                    and (ROOT / "scripts/run_fixed_cascade.py").is_file()
                    and cascade.get("unique_queries") == 3 and cascade.get("planned_records") == 18
                    and cascade.get("separate_references") == 3 and cascade.get("repetitions") == 3
                    and cascade.get("neural_information_used") is False
                    and cascade.get("methods") == {"expanded_only": ["expanded"],
                        "fixed_cascade": ["interval", "finite_readonly", "expanded"]},
                    "Fixed cascade must keep three known inputs, common checkers and non-neural controls")
        if "type_information_collision_audit_implemented" in contract.get("completed_capabilities", []):
            info = contract.get("type_information_diagnostic", {})
            require((ROOT / "scripts/audit_type_information.py").is_file()
                and (ROOT / "src/selective_analysis/type_information.py").is_file()
                and info.get("unique_queries") == 3 and info.get("identity_free_whole_function_groups") is True
                and info.get("representations") == ["Top1", "TopK_scores", "full_retained_logits"]
                and all(info.get(key) is False for key in ("new_model_inference", "new_property_execution", "new_selector_evaluated", "held_out_evaluation")),
                "Type-information audit must preserve the known panel and remain separate from execution/selection")
        if "DWARF4_location_base_adapter_implemented" in contract.get("completed_capabilities", []):
            repair = contract.get("location_repair_diagnostic", {})
            require(all((ROOT / name).is_file() for name in (
                "scripts/run_location_repair.py", "scripts/export_location_repair.py", "scripts/tygr_location_adapter.py"))
                and repair.get("planned_queries") == 3 and repair.get("retained_binaries") == 1
                and repair.get("new_compilations") == repair.get("new_property_controls") == 0
                and repair.get("original_tygr_files_modified") is False
                and repair.get("pre_forward_saved_domain_guard") is True
                and repair.get("supported_entry_layouts") == [4, 6]
                and repair.get("detailed_location_errors_recorded") is True
                and repair.get("neural_benefit_measured") is False,
                "Location repair must retain the same ELF, original files and guard without a benefit claim")
        if "compiled_typed_complementarity_implemented" in contract.get("completed_capabilities", []):
            typed = contract.get("typed_complementarity_diagnostic", {})
            require((ROOT / "scripts/run_typed_complementarity.py").is_file()
                    and (ROOT / "scripts/export_typed_complementarity.py").is_file()
                    and typed.get("planned_queries") == 3 and typed.get("compiled_binaries") == 1
                    and typed.get("separate_references") == 3
                    and typed.get("pre_forward_saved_domain_guard") is True
                    and typed.get("new_selector_evaluated") is False
                    and typed.get("neural_benefit_measured") is False,
                    "Typed readiness must keep one three-query binary, guarded inputs and fixed controls without selector claims")
        if "native_readout_correspondence_implemented" in contract.get("completed_capabilities", []):
            readout = contract.get("native_readout_diagnostic", {})
            require((ROOT / "scripts/run_native_readout_correspondence.py").is_file()
                    and (ROOT / "src/selective_analysis/native_readout_correspondence.py").is_file()
                    and (ROOT / "src/selective_analysis/native_readout_frontier.py").is_file()
                    and readout.get("planned_queries") == 3
                    and readout.get("planned_address_load_occurrences") == 6
                    and readout.get("binding_scope") == "CFA_location_to_original_variable_group"
                    and readout.get("exact_event_verified") is False
                    and readout.get("semantic_roles_verified") is False
                    and readout.get("model_forward_performed") is False
                    and readout.get("prediction_aggregation_changed") is False,
                    "Native readout must separate coarse storage/graph evidence from exact event and semantic role claims")
        if "native_preprocessing_capture_implemented" in contract.get("completed_capabilities", []):
            native = contract.get("native_preprocessing_diagnostic", {})
            require((ROOT / "scripts/run_native_preprocessing.py").is_file()
                    and (ROOT / "scripts/capture_tygr_preprocessing.py").is_file()
                    and (ROOT / "src/selective_analysis/native_input_validation.py").is_file()
                    and native.get("planned_cases") == 3
                    and native.get("panel") == "existing_v12_compiled_native_integration"
                    and native.get("parent_owned_budget_seconds") == 60
                    and native.get("model_forward_authorized") is False
                    and native.get("v17_projection_validated") is False
                    and native.get("neural_benefit_measured") is False,
                    "Native preprocessing must keep its fixed compiled panel, parent budget and no-forward scope")
        if "frozen_model_interface_audit_implemented" in contract.get("completed_capabilities", []):
            interface = contract.get("model_interface_diagnostic", {})
            require((ROOT / "src/selective_analysis/checkpoint_metadata.py").is_file()
                    and (ROOT / "src/selective_analysis/model_interface.py").is_file()
                    and (ROOT / "scripts/audit_tygr_interface.py").is_file()
                    and interface.get("unique_queries") == 3
                    and interface.get("passive_metadata_only") is True
                    and interface.get("feature_tensor_created") is False
                    and interface.get("inference_performed") is False,
                    "Frozen model interface must remain a passive three-query audit without adapted inputs or prediction")
        if "instruction_syntax_provenance_implemented" in contract.get("completed_capabilities", []):
            syntax = contract.get("instruction_provenance_diagnostic", {})
            require((ROOT / "src/selective_analysis/instruction_provenance.py").is_file()
                    and (ROOT / "src/selective_analysis/provenance_validation.py").is_file()
                    and (ROOT / "scripts/run_instruction_provenance.py").is_file()
                    and syntax.get("planned_cases") == 3
                    and syntax.get("property_verification_performed") is False
                    and syntax.get("tygr_readout_compatibility_validated") is False
                    and syntax.get("neural_information_used") is False,
                    "Instruction provenance must remain a three-case syntax prerequisite, not type/property evidence")
        if "information_readiness_gate_implemented" in contract.get("completed_capabilities", []):
            readiness = contract.get("information_readiness_diagnostic", {})
            require((ROOT / "scripts/audit_information_readiness.py").is_file()
                    and (ROOT / "src/selective_analysis/information_readiness.py").is_file()
                    and (ROOT / "src/selective_analysis/trace_headroom.py").is_file()
                    and readiness.get("unique_complementary_queries") == 3
                    and readiness.get("frozen_export_queries") == 3
                    and readiness.get("mode") == "retrospective_offline_gate"
                    and readiness.get("new_model_or_property_execution") is False
                    and readiness.get("counterfactual_is_real_runtime_upper_bound") is False,
                    "Readiness must stay an offline three-by-three inventory with conditional trace accounting")
        if "information_value_diagnostic_implemented" in contract.get("completed_capabilities", []):
            require((ROOT / "scripts/run_information_value.py").is_file()
                    and (ROOT / "src/selective_analysis/information_value.py").is_file(),
                    "Information diagnostic claim requires runner and executable entry")
            require(contract.get("information_diagnostic", {}).get("regime") == "information_only"
                    and contract["information_diagnostic"].get("shared_policy") == contract["selector_revision"],
                    "Information diagnostic must preserve its accounting and shared-policy boundary")
        if "CPU_acquisition_stage_profiling_implemented" in contract.get("completed_capabilities", []):
            require((ROOT / "scripts/profile_neural_acquisition.py").is_file(),
                    "Profiling implementation claim requires its executable entry")
            require("profiled_real_TYGR_acquisition_validation" in contract.get("pending_capabilities", [])
                    or "profiled_real_TYGR_acquisition_validated" in contract.get("completed_capabilities", []),
                    "Separate profiling implementation from genuine-model validation")
        if "online_C_D_provider_implemented" in contract.get("completed_capabilities", []):
            require((ROOT / "src/selective_analysis/online_types.py").is_file()
                    and (ROOT / "scripts/run_end_to_end_probe.py").is_file(),
                    "Online implementation claim requires provider and entry files")
            require("online_C_D_end_to_end_validation" in contract.get("pending_capabilities", [])
                    or "one_query_A_D_end_to_end" in contract.get("completed_capabilities", []),
                    "Separate online implementation from actual model validation")
        else:
            require("online_C_D_end_to_end_provider" in contract.get("pending_capabilities", []),
                    "Unimplemented provider must remain pending")
    expected = {
        "A": {"selector": "fixed_order", "type_view": "none"},
        "B": {"selector": "shared_property_directed", "type_view": "none"},
        "C": {"selector": "shared_property_directed", "type_view": "gnn_top1_label"},
        "D": {"selector": "shared_property_directed", "type_view": "gnn_topk_and_model_scores"},
    }
    require(contract["variants"] == expected, "A-D freeze changed; version the protocol first")
    required_shared = {
        "selector_implementation", "selector_parameters", "non_type_features", "query_manifest",
        "operation_universe", "eligibility_rules", "checker", "evidence_validator",
        "stop_rules", "budget_accounting",
    }
    require(set(contract["shared_between_B_C_D"]) == required_shared, "B/C/D controls incomplete")
    require(set(contract["budget_regimes"]) == {"information_only", "end_to_end"},
            "Both information value and deployment cost must be modeled")
    require(contract["neural_information_role"] == "selection_only", "Neural boundary changed")
    require(contract["gold_labels_role"] == "offline_evaluation_only", "Label boundary changed")
    require(contract["candidate_generation"] == "type_and_label_blind", "Candidate pool changed")
    require(set(contract["query_outcomes"]) == {"violation", "excluded_within_scope", "unknown"},
            "Query outcome contract changed")
    require(contract["proposal_policy"] == "parent_workspace_local_only", "Proposal policy changed")
    return contract


def read_model(path, dot, env):
    result = subprocess.run([dot, "-Tjson", str(path)], env=env, capture_output=True,
                            encoding="utf-8", timeout=30, check=True)
    require(not result.stderr.strip(), f"{path.name}: Graphviz warning: {result.stderr.strip()}")
    return json.loads(result.stdout)


def check_model(model, filename):
    require(model.get("protocol") == PROTOCOL_ID, f"{filename}: missing frozen protocol")
    nodes = {node["name"]: node for node in model.get("objects", [])}
    ids = {node["_gvid"]: node for node in nodes.values()}
    require(bool(nodes), f"{filename}: empty model")
    adjacency = defaultdict(list)
    edges = model.get("edges", [])
    for name, node in nodes.items():
        kind = node.get("kind")
        require(kind in ("object", "process"), f"{filename}: {name} needs an explicit kind")
        require(node.get("label") not in (None, "", "\\N"),
                f"{filename}: implicit or unlabeled entity {name}")
        require(node.get("shape") == ("box" if kind == "object" else "ellipse"),
                f"{filename}: incorrect shape for {name}")
        if kind == "process":
            require(node.get("zone") in ("runtime", "evaluation"), f"{name}: missing zone")
            require(bool(node.get("role")), f"{name}: missing process role")
        if node.get("stateful") == "true":
            require(bool(node.get("states")), f"{name}: stateful object needs states")

    for edge in edges:
        source, target = ids[edge["tail"]], ids[edge["head"]]
        relation = edge.get("relation")
        require(relation in RELATIONS, f"{filename}: unlabeled/unsupported OPM relation")
        source_kind, target_kind, label, arrowhead = RELATIONS[relation]
        require((source["kind"], target["kind"]) == (source_kind, target_kind),
                f"{filename}: invalid {relation} endpoints {source['name']} -> {target['name']}")
        require(edge.get("label") == label and edge.get("arrowhead") == arrowhead,
                f"{filename}: incorrect {relation} rendering")
        if relation == "effect":
            require(source.get("stateful") == "true", "Effect target must be stateful")
            require(edge.get("dir") == "both" and edge.get("arrowtail") == "onormal",
                    "Effect must show suppressed input/output state change")
            # An effect also allows updated object state to be observed subsequently.
            adjacency[target["name"]].append(source["name"])
        else:
            require(edge.get("dir", "forward") == "forward", "Unexpected reverse link")
        if relation == "consumption":
            require(source.get("consumable") == "true", "Only transient work items are consumed")
        if source.get("information_role") == "type_view":
            allowed = {"analysis_running"} if model["view"] == "system" else {"selecting"}
            require(target.get("role") in allowed, "Type view leaked outside operation selection")
            require(relation == "instrument", "Type view must be an immutable instrument")
        adjacency[source["name"]].append(target["name"])

    for node in nodes.values():
        if node.get("information_role") == "routing_raw_candidates":
            queue, seen = deque([node["name"]]), set()
            while queue:
                name = queue.popleft()
                if name in seen:
                    continue
                seen.add(name)
                require(nodes[name].get("role") != "routing_features_capturing"
                        and nodes[name].get("routing_arm") != "B",
                        "Raw candidates reached B or type-blind routing features")
                queue.extend(adjacency[name])
        if node.get("information_role") == "location_raw_candidates":
            queue, seen = deque([node["name"]]), set()
            while queue:
                name = queue.popleft()
                if name in seen:
                    continue
                seen.add(name)
                require(nodes[name].get("role") not in {"location_corresponding", "location_binding"},
                        "Type candidate values reached static location matching")
                queue.extend(adjacency[name])
        if node.get("information_role") == "retained_mapping_proof":
            queue, seen = deque([node["name"]]), set()
            while queue:
                name = queue.popleft()
                if name in seen:
                    continue
                seen.add(name)
                require(nodes[name].get("zone") != "runtime", "Paid mapping proof leaked into pre-action probes")
                queue.extend(adjacency[name])
        if node.get("information_role") == "raw_operand_candidates":
            queue, seen = deque([node["name"]]), set()
            while queue:
                name = queue.popleft()
                if name in seen:
                    continue
                seen.add(name)
                require(nodes[name].get("role") not in {"operand_proving", "operand_rechecking", "operand_facts_projecting"},
                        "Neural candidate route reaches operand proof or common program facts")
                queue.extend(adjacency[name])
        if node.get("data_role") != "evaluation_only":
            continue
        queue, seen = deque([node["name"]]), set()
        while queue:
            name = queue.popleft()
            if name in seen:
                continue
            seen.add(name)
            require(nodes[name].get("zone") != "runtime", "Gold-label route reaches runtime")
            queue.extend(adjacency[name])

    for name, node in nodes.items():
        if node["kind"] == "process":
            transforms = [edge for edge in edges if
                          (edge["tail"] == node["_gvid"] and edge["relation"] == "result") or
                          (edge["head"] == node["_gvid"] and edge["relation"] in ("consumption", "effect"))]
            require(bool(transforms), f"{filename}: {name} transforms no object")
    return nodes, edges, ids


def check_interfaces(models):
    parent_nodes, parent_edges, parent_ids = models["system"][1:]
    for view in ("scheduling", "evaluation"):
        model, nodes, _, _ = models[view]
        process_name = model.get("refines")
        require(process_name in parent_nodes, f"{view}: missing parent process")
        parent_id = parent_nodes[process_name]["_gvid"]
        required_inputs = {parent_ids[e["tail"]]["name"] for e in parent_edges
                           if e["head"] == parent_id and e["relation"] == "instrument"}
        required_outputs = {parent_ids[e["head"]]["name"] for e in parent_edges
                            if e["tail"] == parent_id and e["relation"] == "result"}
        declared_inputs = {name for name, n in nodes.items() if n.get("interface") == "input"}
        declared_outputs = {name for name, n in nodes.items() if n.get("interface") == "output"}
        require(declared_inputs == required_inputs, f"{view}: parent/child input mismatch")
        require(declared_outputs == required_outputs, f"{view}: parent/child output mismatch")
        for name in declared_inputs | declared_outputs:
            for attribute in ("kind", "shape", "label", "information_role", "data_role", "stateful", "states"):
                require(nodes[name].get(attribute) == parent_nodes[name].get(attribute),
                        f"{view}: inconsistent {name}.{attribute}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="regenerate validated SVG previews")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    env = workspace_environment()
    dot = shutil.which("dot")
    require(dot is not None, "Graphviz 'dot' is required on PATH")
    check_contract()
    models = {}
    for name in ("system", "scheduling", "evaluation", "operation_controls", "information_value", "operand_mapping", "compiled_queries", "frame_bounds", "frame_batch", "operation_effects", "location_correspondence", "routing_sensitivity", "indirection_gate", "fixed_cascade", "information_readiness", "instruction_provenance", "model_interface", "native_preprocessing", "native_readout", "typed_readiness", "location_repair", "type_information"):
        model = read_model(MODELS / f"{name}.dot", dot, env)
        require(model.get("view") == name, f"Incorrect view ID: {name}")
        models[name] = (model, *check_model(model, f"{name}.dot"))
    check_interfaces(models)
    if args.render:
        for name in models:
            subprocess.run([dot, "-Tsvg", str(MODELS / f"{name}.dot"), "-o",
                            str(MODELS / f"{name}.svg")], env=env, capture_output=True,
                           encoding="utf-8", check=True, timeout=30)
    count_nodes = sum(len(item[1]) for item in models.values())
    count_edges = sum(len(item[2]) for item in models.values())
    print(f"PASS: frozen A-D contract; {len(models)} DOT views; {count_nodes} view-local nodes; "
          f"{count_edges} OPM links; matching interfaces; label and type routing.")
    if args.render:
        print("Rendered " + ", ".join(name + ".svg" for name in models) + " next to their DOT sources.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.SubprocessError, OSError) as exc:
        print(f"Architecture validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
