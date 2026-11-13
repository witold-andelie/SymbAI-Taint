"""Validate the persisted v17 graph's shape and event-time provenance consistency.

This is a parent-side consistency check, not an instruction/IR semantic-equivalence
proof, a property analysis, or a TYGR compatibility check. It neither lifts code nor
reads binary/data values. Instruction semantics and Capstone correspondence still need
the recording kernel and independent audit. Only the standard library and the neutral
JSON fingerprint helper are used here.
"""

from .contracts import fingerprint


_REVISION = "instruction_syntax_register_bytes_v17"
_MASK64 = (1 << 64) - 1
_COMMON = {"id", "kind", "instruction_rva", "statement_index", "width_bits", "operands"}
_FIELDS = {
    "entry_byte": {"register_offset", "entry_identity"},
    "register_read": {"register_offset", "register_name", "byte_sources", "offset_space"},
    "register_write": {"register_offset", "register_name", "value", "offset_space"},
    "temporary_definition": {"temporary", "value"},
    "temporary_read": {"temporary"},
    "constant": {"constant"},
    "expression": {"operation"},
    "load": {"address", "value_semantics", "endness"},
    "store": {"address", "data", "endness"},
}
_VALUE_KINDS = {"constant", "expression", "load", "register_read", "temporary_read"}


def _require(condition, message):
    if not condition:
        raise ValueError("Invalid syntax graph: " + message)


def _integer(value, minimum=0, maximum=None):
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def _record(value, fields):
    return isinstance(value, dict) and set(value) == fields


def _same_event(parent, child):
    return (parent["instruction_rva"], parent["statement_index"]) == (
        child["instruction_rva"], child["statement_index"])


def _affine(nodes, root, pc):
    """Recompute only the recorded address DAG; a Get is always a terminal event."""
    cached = {}

    def literal(identifier, depth):
        _require(depth < 128, "address literal depth")
        node = nodes[identifier]
        if node["kind"] == "constant":
            return node["constant"]
        if node["kind"] in ("temporary_definition", "temporary_read"):
            return literal(node["operands"][0], depth + 1)
        raise ValueError("Invalid syntax graph: nonliteral address shift")

    def visit(identifier, depth=0):
        _require(depth < 128, "address expression depth")
        if identifier in cached:
            return cached[identifier]
        node = nodes[identifier]
        _require(node["width_bits"] == 64 and node["instruction_rva"] == pc,
                 "address operand width or instruction")
        kind = node["kind"]
        if kind == "constant":
            result = ({}, node["constant"] & _MASK64)
        elif kind == "register_read":
            result = ({identifier: 1}, 0)
        elif kind in ("temporary_definition", "temporary_read"):
            result = visit(node["operands"][0], depth + 1)
        else:
            operation = node.get("operation")
            _require(kind == "expression" and len(node["operands"]) == 2 and operation in (
                "Iop_Add64", "Iop_Sub64", "Iop_Mul64", "Iop_Shl64"), "non-affine address syntax")
            left, right = node["operands"]
            lterms, lconstant = visit(left, depth + 1)
            if operation == "Iop_Shl64":
                amount = literal(right, depth + 1)
                _require(0 <= amount < 64, "address shift amount")
                factor = 1 << amount
                result = ({key: value * factor & _MASK64 for key, value in lterms.items()},
                          lconstant * factor & _MASK64)
            else:
                rterms, rconstant = visit(right, depth + 1)
                if operation == "Iop_Mul64":
                    _require(not (lterms and rterms), "non-affine address product")
                    factor, terms, constant = ((lconstant, rterms, rconstant) if not lterms
                                               else (rconstant, lterms, lconstant))
                    result = ({key: value * factor & _MASK64 for key, value in terms.items()},
                              constant * factor & _MASK64)
                else:
                    sign = -1 if operation == "Iop_Sub64" else 1
                    terms = dict(lterms)
                    for key, coefficient in rterms.items():
                        terms[key] = (terms.get(key, 0) + sign * coefficient) & _MASK64
                    result = ({key: value for key, value in terms.items() if value},
                              (lconstant + sign * rconstant) & _MASK64)
        cached[identifier] = result
        return result

    return visit(root)


def _validate(graph, request):
    _require(_record(request, {"schema", "binary", "binary_sha256", "entry_rva", "target_store_rva"}),
             "request fields")
    _require(request["schema"] == "symbai.syntax_request.v1"
             and isinstance(request["binary"], str) and bool(request["binary"])
             and isinstance(request["binary_sha256"], str) and len(request["binary_sha256"]) == 64
             and all(c in "0123456789abcdef" for c in request["binary_sha256"])
             and _integer(request["entry_rva"]) and _integer(request["target_store_rva"])
             and request["target_store_rva"] >= request["entry_rva"], "request identity")
    _require(isinstance(graph, dict), "graph object")
    required = {
        "schema": "symbai.instruction_provenance.v1", "revision": _REVISION,
        "status": "available", "reason": None, "scope": "linear_instruction_syntax_only",
        "register_offset_space": "vex_register_bytes", "temporary_scope": "instruction_rva",
        "memory_value_provenance": "opaque_no_dereference_or_store_to_load_forwarding",
    }
    _require(all(key in graph and graph[key] == value for key, value in required.items()), "scope metadata")
    _require(graph.get("complete") is True and all(graph.get(name) is False for name in (
        "property_verification_performed", "neural_information_used", "tygr_readout_compatibility_validated")),
        "completion or analysis flags")
    _require(type(graph.get("max_nodes")) is int and graph["max_nodes"] == 4096
             and type(graph.get("max_instructions")) is int and graph["max_instructions"] == 64,
             "declared limits")
    identity = graph.get("identity")
    _require(_record(identity, {"binary_sha256", "entry_rva", "target_store_rva"})
             and isinstance(identity["binary_sha256"], str)
             and _integer(identity["entry_rva"]) and _integer(identity["target_store_rva"])
             and identity == {key: request[key] for key in identity}, "graph identity")

    instructions = graph["instructions"]
    _require(isinstance(instructions, list) and 0 < len(instructions) <= 64, "instruction count")
    instruction_map, pc = {}, request["entry_rva"]
    for instruction in instructions:
        _require(_record(instruction, {"rva", "length", "bytes", "mnemonic", "operands_text", "vex_statement_count"}),
                 "instruction fields")
        _require(_integer(instruction["rva"]) and instruction["rva"] == pc
                 and _integer(instruction["length"], 1, 15)
                 and _integer(instruction["vex_statement_count"], 1), "instruction sequence or size")
        raw = instruction["bytes"]
        _require(isinstance(raw, str) and len(raw) == instruction["length"] * 2
                 and all(c in "0123456789abcdef" for c in raw), "instruction hex bytes")
        _require(instruction["mnemonic"] in {"and", "lea", "mov", "movabs", "add", "sub", "xor", "nop"}
                 and isinstance(instruction["operands_text"], str), "instruction syntax")
        instruction_map[pc] = instruction
        pc += instruction["length"]
    _require(instructions[-1]["rva"] == request["target_store_rva"], "target instruction absent or not last")

    sequence = graph["nodes"]
    _require(isinstance(sequence, list) and 0 < len(sequence) <= 4096, "node count")
    nodes, byte_versions, temporaries, effects, seen_pcs = {}, {}, {}, [], set()
    previous_event = (-1, -1)
    instruction_order = {value["rva"]: index for index, value in enumerate(instructions)}
    for index, node in enumerate(sequence):
        _require(isinstance(node, dict) and isinstance(node.get("kind"), str)
                 and node["kind"] in _FIELDS, "node kind")
        kind = node["kind"]
        _require(set(node) == _COMMON | _FIELDS[kind] and node["id"] == "n" + str(index), "node fields or identity")
        bits, operands = node["width_bits"], node["operands"]
        _require(type(bits) is int and bits in {1, 8, 16, 32, 64, 128, 256, 512, 1024}, "node width")
        _require(isinstance(operands, list) and all(isinstance(source, str) and source in nodes for source in operands),
                 "dependency is not a prior node")
        if kind == "entry_byte":
            offset = node["register_offset"]
            _require(bits == 8 and not operands and _integer(offset) and offset not in byte_versions
                     and node["entry_identity"] is True and node["instruction_rva"] is None
                     and node["statement_index"] is None, "entry byte identity")
            byte_versions[offset] = node["id"]
        else:
            node_pc, statement = node["instruction_rva"], node["statement_index"]
            _require(_integer(node_pc) and node_pc in instruction_map and _integer(statement)
                     and statement <= instruction_map[node_pc]["vex_statement_count"], "node instruction or statement")
            event = (instruction_order[node_pc], statement)
            _require(event >= previous_event, "node event order")
            previous_event = event
            seen_pcs.add(node_pc)
            if kind in ("register_write", "temporary_definition", "store"):
                _require(statement < instruction_map[node_pc]["vex_statement_count"], "statement effect after IR end")
            if kind in ("register_read", "register_write"):
                offset = node["register_offset"]
                _require(_integer(offset) and bits % 8 == 0 and bits <= 512
                         and isinstance(node["register_name"], str) and bool(node["register_name"])
                         and node["offset_space"] == "vex_register_bytes", "register span")
            if kind == "register_read":
                sources = node["byte_sources"]
                expected = [{"offset": byte, "definition": byte_versions.get(byte)}
                            for byte in range(offset, offset + bits // 8)]
                _require(isinstance(sources, list) and all(_record(source, {"offset", "definition"})
                         and _integer(source["offset"]) and isinstance(source["definition"], str) for source in sources)
                         and sources == expected and all(source["definition"] in nodes for source in sources),
                         "register byte versions")
                _require(operands == list(dict.fromkeys(source["definition"] for source in sources)),
                         "register version dependencies")
            elif kind in ("temporary_definition", "temporary_read"):
                _require(_integer(node["temporary"]) and len(operands) == 1, "temporary fields")
                key, value = (node_pc, node["temporary"]), nodes[operands[0]]
                _require(value["width_bits"] == bits, "temporary width")
                if kind == "temporary_definition":
                    _require(key not in temporaries and node["value"] == operands[0]
                             and value["kind"] in _VALUE_KINDS and _same_event(node, value), "temporary definition")
                    temporaries[key] = node["id"]
                else:
                    _require(temporaries.get(key) == operands[0] and value["kind"] == "temporary_definition"
                             and value["instruction_rva"] == node_pc and value["statement_index"] < statement,
                             "temporary read scope or prior definition")
            elif kind == "constant":
                _require(not operands and _integer(node["constant"], 0, (1 << bits) - 1), "constant value")
            elif kind == "expression":
                _require(isinstance(node["operation"], str) and node["operation"].startswith("Iop_")
                         and len(node["operation"]) > 4 and len(operands) in (1, 2), "expression operation or arity")
            elif kind == "register_write":
                _require(operands == [node["value"]] and nodes[operands[0]]["width_bits"] == bits,
                         "register write value")
                for byte in range(offset, offset + bits // 8):
                    byte_versions[byte] = node["id"]
            elif kind in ("load", "store"):
                expected = [node["address"]] if kind == "load" else [node["address"], node["data"]]
                _require(operands == expected and bits % 8 == 0 and node["endness"] == "little"
                         and nodes[node["address"]]["width_bits"] == 64, "memory node operands or width")
                if kind == "load":
                    _require(node["value_semantics"] == "opaque_not_dereferenced", "nonopaque load")
                else:
                    _require(nodes[node["data"]]["width_bits"] == bits, "store data width")
                effects.append(node)
            if kind in ("expression", "load", "store", "register_write"):
                _require(all(nodes[source]["kind"] in _VALUE_KINDS and _same_event(node, nodes[source])
                             for source in operands), "expression value event or kind")
        nodes[node["id"]] = node
    _require(seen_pcs == set(instruction_map), "instruction without recorded nodes")

    edges = graph["edges"]
    _require(isinstance(edges, list) and all(_record(edge, {"source", "target", "operand_index"})
             and isinstance(edge["source"], str) and isinstance(edge["target"], str)
             and _integer(edge["operand_index"]) for edge in edges), "edge fields")
    _require(edges == [{"source": source, "target": node["id"], "operand_index": index}
                      for node in sequence for index, source in enumerate(node["operands"])], "edge dependencies")

    accesses, memory_pcs = graph["accesses"], set()
    _require(isinstance(accesses, list) and len(accesses) == len(effects), "memory access count")
    for access, effect in zip(accesses, effects):
        _require(_record(access, {"direction", "node", "address_node", "width_bits", "instruction_rva",
                                 "memory_operand_index", "address_formula", "register_bindings", "correspondence"}),
                 "memory access fields")
        pc, direction = effect["instruction_rva"], "read" if effect["kind"] == "load" else "write"
        _require(access["node"] == effect["id"] and access["direction"] == direction
                 and _integer(access["instruction_rva"]) and access["instruction_rva"] == pc
                 and access["address_node"] == effect["address"] and type(access["width_bits"]) is int
                 and access["width_bits"] == effect["width_bits"] and pc not in memory_pcs
                 and _integer(access["memory_operand_index"], 0 if direction == "write" else 1)
                 and (direction != "write" or access["memory_operand_index"] == 0)
                 and access["correspondence"] == "restricted_affine_instruction_syntax_only", "memory access identity")
        memory_pcs.add(pc)
        terms, constant = _affine(nodes, effect["address"], pc)
        formula = access["address_formula"]
        _require(_record(formula, {"constant", "terms"}) and _integer(formula["constant"], 0, _MASK64)
                 and isinstance(formula["terms"], list), "address formula fields")
        _require(all(_record(term, {"read_node", "register_offset", "coefficient"})
                     and isinstance(term["read_node"], str) and _integer(term["register_offset"])
                     and _integer(term["coefficient"], 1, _MASK64) for term in formula["terms"]), "address terms")
        expected = {"constant": constant, "terms": [
            {"read_node": key, "register_offset": nodes[key]["register_offset"], "coefficient": value}
            for key, value in sorted(terms.items())]}
        _require(formula == expected, "address formula differs from recorded DAG")
        bindings = access["register_bindings"]
        _require(isinstance(bindings, list) and len(bindings) == len(terms) <= 2, "address binding count")
        roles, offsets, reads = set(), set(), set()
        for binding in bindings:
            _require(_record(binding, {"role", "register_name", "register_offset", "read_node", "scale"}),
                     "address binding fields")
            role, read = binding["role"], binding["read_node"]
            _require(isinstance(role, str) and role in ("base", "index") and role not in roles
                     and isinstance(read, str) and read in terms and read not in reads
                     and _integer(binding["register_offset"]) and binding["register_offset"] not in offsets
                     and _integer(binding["scale"], 1) and binding["scale"] in ((1,) if role == "base" else (1, 2, 4, 8)),
                     "address binding role or scale")
            node = nodes[read]
            _require(node["kind"] == "register_read" and node["instruction_rva"] == pc and node["width_bits"] == 64
                     and binding["register_offset"] == node["register_offset"]
                     and binding["register_name"] == node["register_name"]
                     and binding["scale"] == terms[read], "address binding read identity")
            roles.add(role)
            offsets.add(binding["register_offset"])
            reads.add(read)
    target_effects = [effect for effect in effects if effect["instruction_rva"] == request["target_store_rva"]]
    _require(len(target_effects) == 1 and target_effects[0]["kind"] == "store", "target is not one ordinary store")
    _require(graph["syntax_fingerprint"] == fingerprint({key: graph[key] for key in ("nodes", "instructions", "accesses")}),
             "syntax fingerprint")


def validate_syntax_graph(graph, request):
    """Return None for a complete consistent v17 graph; otherwise raise ValueError.

    Worker runtime metadata and blocked imports belong to the enclosing worker-result
    validator. This function checks only the graph and its minimal request identity.
    """
    try:
        _validate(graph, request)
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError, OverflowError) as error:
        raise ValueError("Invalid syntax graph: malformed field or dependency") from error
