"""Use angr's temporary-aware reaching definitions; do not reuse the legacy DFG."""

import time

from .contracts import fingerprint


def inspect_dependencies(project, query, deadline=None):
    started = time.monotonic()
    def check_time():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Dependency preparation exceeded its deadline")
    check_time()
    address = project.loader.main_object.mapped_base + query.entry_rva
    write = project.loader.main_object.mapped_base + query.write_rva
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[address],
                                   force_segment=True, exclude_sparse_regions=False)
    function = cfg.kb.functions.function(addr=address)
    if function is None:
        raise ValueError("Entry function was not recovered")
    check_time()
    result = project.analyses.ReachingDefinitions(subject=function, track_tmps=True,
                                                observe_all=True, dep_graph=True,
                                                max_iterations=8, interfunction_level=1)
    graph = result.dep_graph.graph
    check_time()
    definitions = []
    ordered = sorted(graph.nodes, key=lambda d: (str(d.codeloc), str(d.atom)))
    identifiers = {definition: "d" + str(i) for i, definition in enumerate(ordered)}
    for definition in ordered:
        location = definition.codeloc
        definitions.append({"definition_id": identifiers[definition], "atom": str(definition.atom),
                            "instruction": getattr(location, "ins_addr", None),
                            "block": getattr(location, "block_addr", None),
                            "statement": getattr(location, "stmt_idx", None)})
    edges = sorted((identifiers[source], identifiers[target]) for source, target in graph.edges)
    # A local backward slice is a planning hint, never a proof of irrelevance.
    relevant = {definition for definition in ordered if getattr(definition.codeloc, "ins_addr", None) == write}
    pending = list(relevant)
    while pending:
        for predecessor in graph.predecessors(pending.pop()):
            if predecessor not in relevant:
                relevant.add(predecessor)
                pending.append(predecessor)
    block_addresses = list(project.factory.block(address).instruction_addrs)
    prefix = []
    reason = "target_not_in_straight_line_entry_block"
    if relevant and write in block_addresses:
        prefix = [pc - project.loader.main_object.mapped_base
                  for pc in block_addresses[:block_addresses.index(write)]]
        reason = "entry_block_target_with_observed_dependencies"
    elif not relevant:
        reason = "no_target_definition_observed"
    plan = {"query_hash": query.contract_hash, "instruction_rvas": prefix,
            "target_rva": query.write_rva, "eligible": bool(relevant and write in block_addresses),
            "basis": reason, "allows_instruction_skipping": False}
    plan["plan_id"] = fingerprint(plan)
    check_time()
    return {"backend": "angr_reaching_definitions", "track_tmps": True,
            "definition_count": len(graph), "edge_count": graph.number_of_edges(),
            "definitions": definitions,
            "edges": [{"source": source, "target": target} for source, target in edges],
            "target_slice_definition_ids": sorted(identifiers[d] for d in relevant),
            "prefix_plan": plan, "elapsed_seconds": time.monotonic() - started,
            "completeness": "local_approximation_not_a_relevance_proof"}
