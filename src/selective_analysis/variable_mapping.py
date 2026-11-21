"""Independent CFA-slot/graph/readout correspondence checks; no type labels as input."""
from .type_corpus import text


def offline_facts(binary, address, selected_offsets):
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    from elftools.dwarf.callframe import FDE
    with open(binary, "rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64":
            raise ValueError("Mapping scope requires x86-64 ELF")
        dwarf = elf.get_dwarf_info()
        functions = [(cu, die) for cu in dwarf.iter_CUs() for die in cu.iter_DIEs()
            if die.tag == "DW_TAG_subprogram" and die.attributes.get("DW_AT_low_pc")
            and die.attributes["DW_AT_low_pc"].value == address]
        if len(functions) != 1:
            raise ValueError("Expected one concrete target function")
        cu, function = functions[0]
        if cu["version"] != 4:
            raise ValueError("Mapping probe requires DWARF4")
        parser = DWARFExprParser(cu.structs)
        frame = parser.parse_expr(function.attributes["DW_AT_frame_base"].value)
        if [op.op_name for op in frame] != ["DW_OP_call_frame_cfa"]:
            raise ValueError("This bounded probe requires a CFA frame base")
        high = function.attributes["DW_AT_high_pc"]
        end = high.value if high.form == "DW_FORM_addr" else address + high.value
        entries = [entry for entry in dwarf.EH_CFI_entries() if isinstance(entry, FDE)
            and entry["initial_location"] <= address < entry["initial_location"] + entry["address_range"]]
        if len(entries) != 1:
            raise ValueError("Unique entry CFI is required")
        state = max((row for row in entries[0].get_decoded().table if row["pc"] <= address), key=lambda row: row["pc"])
        cfa = state["cfa"]
        if cfa.reg != 7 or cfa.offset != 8 or cfa.expr is not None:
            raise ValueError("Expected x86-64 entry CFA = RSP + 8")
        pending, descendants = list(function.iter_children()), {}
        while pending:
            die = pending.pop()
            descendants[die.offset] = die
            pending.extend(die.iter_children())
        variables = []
        for offset in selected_offsets:
            die = descendants[offset]
            if die.tag not in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
                raise ValueError("Selected DIE is not a variable")
            location = die.attributes["DW_AT_location"]
            if location.form != "DW_FORM_exprloc":
                raise ValueError("Initial probe supports exprloc slots only")
            ops = parser.parse_expr(location.value)
            if len(ops) != 1 or ops[0].op_name != "DW_OP_fbreg":
                raise ValueError("Initial probe supports fixed CFA slots only")
            variables.append({"die_offset": offset, "name": text(die.attributes["DW_AT_name"].value),
                "cfa_offset": int(ops[0].args[0]), "range": [address, end],
                "expression_hex": bytes(location.value).hex()})
        return {"function_address": address, "function_high_pc": end,
            "function_name": text(function.attributes["DW_AT_name"].value),
            "entry_cfa_register": "rsp", "entry_cfa_offset": 8, "variables": variables,
            "reference_type_attributes_used": False, "scope": "Fixed O0 CFA slots; no optimized location lists or complete semantic use-site proof."}


def matching_nodes(graph, address, bounds):
    nodes = {node["id"]: node for node in graph["nodes"]}
    result = set()
    for edge in graph["edges"]:
        if "mem_loc" not in edge["labels"]:
            continue
        source, target = nodes[edge["source"]], nodes[edge["target"]]
        try:
            value = int(source["value"], 0)
        except (TypeError, ValueError):
            continue
        pc = target["annotation_address"]
        if value == address and isinstance(pc, int) and bounds[0] <= pc < bounds[1]:
            result.add(target["id"])
    return result


def review_mapping(payload, facts):
    if (payload["status"] != "captured" or payload["model_loaded"] or payload["model_load_attempts"]
            or payload["model_forward_attempts"] or not payload["original_sources_rechecked"]):
        raise ValueError("Incomplete model-free mapping capture")
    if payload["function_address"] != facts["function_address"]:
        raise ValueError("Function identity differs")
    if ({key: payload["data_contract"][key] for key in ("feature_width", "declared_relation_count", "type_count")}
            != {"feature_width": 31, "declared_relation_count": 60, "type_count": 75}):
        raise ValueError("Fresh preprocessing configuration differs")
    stage = payload["stage"]
    splice, = stage["splices"]
    native = payload["native_input"]
    batch = native["batch"]
    post = {int(key): value for key, value in splice["mapping"].items()}
    before_nodes = {row["id"]: row for row in splice["before"]["nodes"]}
    after_nodes = {row["id"]: row for row in splice["after"]["nodes"]}
    if (len(set(post.values())) != len(post) or set(post.values()) != set(after_nodes)
            or any({k: v for k, v in before_nodes[node].items() if k != "id"} !=
                   {k: v for k, v in after_nodes[mapped].items() if k != "id"} for node, mapped in post.items())):
        raise ValueError("Splice node identity/normalization differs")
    expected_edges = sorted((post[e["source"]], post[e["target"]], tuple(e["labels"]))
        for e in splice["before"]["edges"] if e["source"] in post and e["target"] in post)
    if expected_edges != sorted((e["source"], e["target"], tuple(e["labels"])) for e in splice["after"]["edges"]):
        raise ValueError("Splice changed retained topology")
    expected_groups = [[node] for var in native["variables"] for node in var["original_value_nodes"]]
    groups_ok = (expected_groups == native["prepared"]["var_nodes"]
        and batch["var_gather"]["values"] == [group[0] for group in expected_groups]
        and batch["var_scatter"]["values"] == list(range(len(expected_groups)))
        and batch["num_vars"] == [len(expected_groups)] and batch["labels_supplied_to_model"] is False)
    n = len(native["graph_node_order"])
    row_order_ok = native["graph_node_order"] == list(range(n))
    features_ok = (batch["node_labels"]["shape"] == [n, 31]
        and all(row[:5] == [1.0, 0.0, 0.0, 0.0, 0.0] for row in batch["node_labels"]["values"]))
    relations_ok = all(type(value) is int and 0 <= value < 60 for value in batch["edge_labels"]["values"])
    rows = []
    for variable in facts["variables"]:
        address = payload["configured_initial_sp"] + facts["entry_cfa_offset"] + variable["cfa_offset"]
        expected = matching_nodes(splice["before"], address, variable["range"])
        lookup = [row for row in payload["lookup_calls"] if row["name"] == variable["name"]
            and row["prepared_locations"] == [{"low_pc": variable["range"][0], "high_pc": variable["range"][1], "form": "addr", "value": address}]]
        vars_found = [row for row in native["variables"] if row["locator_variable_name"] == variable["name"]
            and any(loc["location_class"] == "CfaLocation" and loc["location_argument"] == variable["cfa_offset"]
                    and [loc["low_pc"], loc["high_pc"]] == variable["range"] for loc in row["locations"])]
        reasons = []
        if len(lookup) != 1 or set(lookup[0]["pre_splice_nodes"]) != expected:
            reasons.append("lookup_location_or_membership_differs")
        if not expected:
            reasons.append("no_nodes_at_declared_location")
        if len(vars_found) != 1 or {post[node] for node in expected if node in post} != set(vars_found[0]["original_value_nodes"]):
            reasons.append("variable_to_post_graph_membership_differs")
        if not expected.issubset(post):
            reasons.append("located_value_removed_by_splicing")
        if not groups_ok:
            reasons.append("value_readout_rows_differ")
        if not row_order_ok:
            reasons.append("graph_node_order_not_feature_row_order")
        if not features_ok or not relations_ok:
            reasons.append("fresh_60_relation_data_contract_differs")
        if stage["step_exceptions"]:
            reasons.append("execution_step_exceptions_recorded")
        rows.append({"die_offset": variable["die_offset"], "name": variable["name"],
            "status": "location_readout_consistent" if not reasons else "unresolved", "reasons": reasons,
            "expected_stack_address": address, "pre_splice_nodes": sorted(expected),
            "post_splice_nodes": sorted(post[node] for node in expected if node in post),
            "flattened_rows": vars_found[0]["flattened_output_rows"] if len(vars_found) == 1 else []})
    return {"variables": rows, "consistent_variables": sum(row["status"] == "location_readout_consistent" for row in rows),
        "node_feature_row_order_aligned": row_order_ok, "readout_groups_consistent": groups_ok,
        "scope": "Location/range/topology and readout correspondence in recorded partial execution; not value equivalence on all paths or full semantic use-site correctness."}
