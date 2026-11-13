"""Straight-line instruction syntax and event-time register-byte provenance.

This is a new provenance representation, not a TYGR readout adapter or an analysis of
memory contents, paths, aliases, object bounds or type correctness.
"""

from io import BytesIO
from pathlib import Path

from .contracts import file_hash, fingerprint
from .elf_guard import check_relocation_coverage, UnsupportedELFLayout

REVISION = "instruction_syntax_register_bytes_v17"
MASK64 = (1 << 64) - 1
MAX_INSTRUCTIONS, MAX_NODES = 64, 4096


class UnsupportedProvenance(ValueError):
    pass


def _lift_instruction(data, address, arch):
    import pyvex
    return pyvex.IRSB(data, address, arch, opt_level=0, num_inst=1,
                      strict_block_end=True, cross_insn_opt=False)


def validate_request(request):
    if (not isinstance(request, dict) or set(request) != {"schema", "binary", "binary_sha256", "entry_rva", "target_store_rva"}
            or request["schema"] != "symbai.syntax_request.v1"
            or not isinstance(request["binary"], str) or not request["binary"]
            or any(type(request[k]) is not int or request[k] < 0 for k in ("entry_rva", "target_store_rva"))
            or request["target_store_rva"] < request["entry_rva"]
            or not isinstance(request["binary_sha256"], str) or len(request["binary_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in request["binary_sha256"])):
        raise ValueError("Invalid syntax-only request; property/type/evidence fields are not accepted")
    try:
        digest = file_hash(request["binary"])
    except OSError as error:
        raise ValueError("Syntax binary cannot be read") from error
    if digest != request["binary_sha256"]:
        raise ValueError("Syntax input binary hash differs")


class _Builder:
    def __init__(self, request):
        import archinfo
        import capstone
        from elftools.elf.elffile import ELFFile
        self.request = request
        self.nodes, self.instructions, self.accesses = [], [], []
        self.by_id, self.register_bytes, self.temps = {}, {}, {}
        self.current_rva, self.statement_index, self.memory_effects = None, None, []
        self.arch = archinfo.ArchAMD64()
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.x86 = capstone.x86_const
        elf = ELFFile(BytesIO(Path(request["binary"]).read_bytes()))
        if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
                or elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
            raise UnsupportedProvenance("unsupported_elf_format")
        loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        if not loads:
            raise UnsupportedProvenance("missing_load_segments")
        spans = sorted((s["p_vaddr"], s["p_vaddr"] + s["p_memsz"]) for s in loads)
        if any(end > following for (_, end), (following, _) in zip(spans, spans[1:])):
            raise UnsupportedProvenance("overlapping_load_segments")
        self.base = min(start for start, _ in spans)
        relocations = [s for s in elf.iter_sections() if s["sh_type"] in ("SHT_REL", "SHT_RELA")]
        check_relocation_coverage(elf, loads, relocations)
        self.code = [(s["p_vaddr"], s.data()) for s in loads if s["p_flags"] & 1]

    def node(self, kind, bits, operands=(), **fields):
        if len(self.nodes) >= MAX_NODES or not 0 < bits <= 1024:
            raise UnsupportedProvenance("graph_limit_or_unsupported_width")
        value = {"id": "n" + str(len(self.nodes)), "kind": kind, "instruction_rva": self.current_rva,
                 "statement_index": self.statement_index, "width_bits": bits, "operands": list(operands), **fields}
        if any(source not in self.by_id for source in operands):
            raise UnsupportedProvenance("non_prior_or_missing_dependency")
        self.nodes.append(value)
        self.by_id[value["id"]] = value
        return value["id"]

    def register_read(self, offset, bits):
        if type(offset) is not int or offset < 0 or bits % 8 or bits > 512:
            raise UnsupportedProvenance("unsupported_register_span")
        sources = []
        for byte in range(offset, offset + bits // 8):
            if byte not in self.register_bytes:
                self.register_bytes[byte] = self.node("entry_byte", 8, register_offset=byte,
                                                      entry_identity=True, instruction_rva=None, statement_index=None)
            sources.append({"offset": byte, "definition": self.register_bytes[byte]})
        return self.node("register_read", bits, list(dict.fromkeys(s["definition"] for s in sources)),
                         register_offset=offset, register_name=self.arch.translate_register_name(offset, bits // 8),
                         byte_sources=sources, offset_space="vex_register_bytes")

    def expression(self, expr, tyenv, depth=0):
        if depth >= 64:
            raise UnsupportedProvenance("expression_depth_limit")
        tag, bits = expr.tag, expr.result_size(tyenv)
        if tag == "Iex_Const":
            return self.node("constant", bits, constant=int(expr.con.value))
        if tag == "Iex_Get":
            return self.register_read(expr.offset, bits)
        if tag == "Iex_RdTmp":
            if expr.tmp not in self.temps:
                raise UnsupportedProvenance("temporary_read_without_prior_definition")
            source = self.temps[expr.tmp]
            if self.by_id[source]["width_bits"] != bits:
                raise UnsupportedProvenance("temporary_width_mismatch")
            return self.node("temporary_read", bits, (source,), temporary=expr.tmp)
        if tag in ("Iex_Binop", "Iex_Unop"):
            args = [self.expression(arg, tyenv, depth + 1) for arg in expr.args]
            return self.node("expression", bits, args, operation=str(expr.op))
        if tag == "Iex_Load":
            if str(expr.end) != "Iend_LE" or bits % 8:
                raise UnsupportedProvenance("unsupported_load_endness_or_width")
            address = self.expression(expr.addr, tyenv, depth + 1)
            result = self.node("load", bits, (address,), address=address,
                               value_semantics="opaque_not_dereferenced", endness="little")
            self.memory_effects.append({"direction": "read", "node": result, "address_node": address, "width_bits": bits})
            return result
        raise UnsupportedProvenance("unsupported_expression:" + tag)

    def affine(self, identifier, depth=0):
        if depth >= 128:
            raise UnsupportedProvenance("address_expression_depth_limit")
        node = self.by_id[identifier]
        kind = node["kind"]
        if node["width_bits"] != 64:
            raise UnsupportedProvenance("non_64_bit_direct_address")
        if kind == "constant":
            return {}, node["constant"] & MASK64
        if kind == "register_read":
            if node["instruction_rva"] != self.current_rva:
                raise UnsupportedProvenance("prior_instruction_in_direct_address")
            return {identifier: 1}, 0
        if kind in ("temporary_definition", "temporary_read"):
            return self.affine(node["operands"][0], depth + 1)
        if kind == "expression" and node["operation"] in ("Iop_Add64", "Iop_Sub64", "Iop_Shl64", "Iop_Mul64"):
            left, right = node["operands"]
            lterms, lconst = self.affine(left, depth + 1)
            op = node["operation"]
            if op == "Iop_Shl64":
                amount = self.literal(right)
                if not 0 <= amount < 64:
                    raise UnsupportedProvenance("unsupported_address_shift")
                return {key: value * (1 << amount) & MASK64 for key, value in lterms.items()}, lconst * (1 << amount) & MASK64
            rterms, rconst = self.affine(right, depth + 1)
            if op == "Iop_Mul64":
                if lterms and rterms:
                    raise UnsupportedProvenance("non_affine_direct_address")
                if not lterms:
                    return {key: value * lconst & MASK64 for key, value in rterms.items()}, rconst * lconst & MASK64
                return {key: value * rconst & MASK64 for key, value in lterms.items()}, lconst * rconst & MASK64
            sign = -1 if op == "Iop_Sub64" else 1
            terms = dict(lterms)
            for key, coefficient in rterms.items():
                terms[key] = (terms.get(key, 0) + sign * coefficient) & MASK64
            return {key: value for key, value in terms.items() if value}, (lconst + sign * rconst) & MASK64
        raise UnsupportedProvenance("unsupported_direct_address_syntax")

    def literal(self, identifier, depth=0):
        if depth >= 128:
            raise UnsupportedProvenance("literal_expression_depth_limit")
        node = self.by_id[identifier]
        if node["kind"] == "constant":
            return node["constant"]
        if node["kind"] in ("temporary_read", "temporary_definition", "register_write"):
            return self.literal(node["operands"][0], depth + 1)
        if node["kind"] == "register_read" and node["register_offset"] == self.arch.ip_offset:
            sources = {s["definition"] for s in node["byte_sources"]}
            if len(sources) == 1:
                return self.literal(next(iter(sources)), depth + 1)
        raise UnsupportedProvenance("non_literal_control_or_shift")

    def bind_address(self, insn, effect, memory):
        if (insn.addr_size != 8 or memory.segment or effect["width_bits"] != insn.operands[self.memory_operand].size * 8
                or memory.base and memory.base == memory.index):
            raise UnsupportedProvenance("unsupported_address_width_segment_or_repeated_register")
        terms, constant = self.affine(effect["address_node"])
        expected, bindings = {}, []
        displacement = memory.disp
        for role, reg, scale in (("base", memory.base, 1), ("index", memory.index, memory.scale)):
            if not reg:
                continue
            name = insn.reg_name(reg)
            if name == "rip" and role == "base":
                displacement += insn.address + insn.size
                continue
            info = self.arch.registers.get(name)
            if not info or info[1] != 8:
                raise UnsupportedProvenance("non_64_bit_address_register")
            matching = [key for key in terms if self.by_id[key]["register_offset"] == info[0]]
            if len(matching) != 1 or terms[matching[0]] != scale:
                raise UnsupportedProvenance("ambiguous_or_mismatched_address_register")
            expected[matching[0]] = scale
            bindings.append({"role": role, "register_name": name, "register_offset": info[0],
                             "read_node": matching[0], "scale": scale})
        if terms != expected or constant != displacement & MASK64:
            raise UnsupportedProvenance("capstone_vex_address_formula_mismatch")
        return {**effect, "instruction_rva": self.current_rva, "memory_operand_index": self.memory_operand,
                "address_formula": {"constant": constant,
                                    "terms": [{"read_node": key, "register_offset": self.by_id[key]["register_offset"],
                                               "coefficient": value} for key, value in sorted(terms.items())]},
                "register_bindings": bindings, "correspondence": "restricted_affine_instruction_syntax_only"}

    def walk(self):
        pc = self.base + self.request["entry_rva"]
        target = self.base + self.request["target_store_rva"]
        allowed = {"and", "lea", "mov", "movabs", "add", "sub", "xor", "nop"}
        for _ in range(MAX_INSTRUCTIONS):
            if pc > target:
                raise UnsupportedProvenance("target_not_instruction_boundary")
            segments = [(start, data) for start, data in self.code if start <= pc < start + len(data)]
            if len(segments) != 1:
                raise UnsupportedProvenance("instruction_not_in_unique_file_backed_executable_segment")
            start, data = segments[0]
            raw = data[pc - start:pc - start + 15]
            insn = next(self.decoder.disasm(raw, pc, count=1), None)
            if insn is None or insn.mnemonic not in allowed or any(p not in (0, 0x66) for p in insn.prefix):
                raise UnsupportedProvenance("unsupported_or_undecodable_instruction")
            block = _lift_instruction(raw[:insn.size], pc, self.arch)
            marks = [s for s in block.statements if s.tag == "Ist_IMark"]
            if (len(marks) != 1 or marks[0].addr != pc or marks[0].len != insn.size or marks[0].delta != 0
                    or block.size != insn.size or block.jumpkind != "Ijk_Boring"):
                raise UnsupportedProvenance("single_instruction_lift_or_control_mismatch")
            self.current_rva, self.temps, self.memory_effects = pc - self.base, {}, []
            for index, statement in enumerate(block.statements):
                self.statement_index = index
                tag = statement.tag
                if tag in ("Ist_IMark", "Ist_NoOp"):
                    continue
                if tag == "Ist_WrTmp":
                    if statement.tmp in self.temps:
                        raise UnsupportedProvenance("duplicate_temporary_definition")
                    value = self.expression(statement.data, block.tyenv)
                    self.temps[statement.tmp] = self.node("temporary_definition", self.by_id[value]["width_bits"],
                                                         (value,), temporary=statement.tmp, value=value)
                elif tag == "Ist_Put":
                    value = self.expression(statement.data, block.tyenv)
                    bits = self.by_id[value]["width_bits"]
                    if bits % 8 or not 0 < bits <= 512 or statement.offset < 0:
                        raise UnsupportedProvenance("unsupported_register_write_span")
                    node = self.node("register_write", bits, (value,), register_offset=statement.offset,
                                     register_name=self.arch.translate_register_name(statement.offset, bits // 8),
                                     value=value, offset_space="vex_register_bytes")
                    for byte in range(statement.offset, statement.offset + bits // 8):
                        self.register_bytes[byte] = node
                elif tag == "Ist_Store":
                    if str(statement.end) != "Iend_LE":
                        raise UnsupportedProvenance("unsupported_store_endness")
                    address = self.expression(statement.addr, block.tyenv)
                    value = self.expression(statement.data, block.tyenv)
                    bits = self.by_id[value]["width_bits"]
                    if bits % 8:
                        raise UnsupportedProvenance("unsupported_store_width")
                    node = self.node("store", bits, (address, value), address=address, data=value, endness="little")
                    self.memory_effects.append({"direction": "write", "node": node, "address_node": address, "width_bits": bits})
                else:
                    raise UnsupportedProvenance("unsupported_statement:" + tag)
            self.statement_index = len(block.statements)
            next_node = self.expression(block.next, block.tyenv)
            if self.literal(next_node) != pc + insn.size:
                raise UnsupportedProvenance("non_fallthrough_next_pc")
            memory_operands = [i for i, op in enumerate(insn.operands) if op.type == self.x86.X86_OP_MEM]
            expected_memory = [] if insn.mnemonic == "lea" else memory_operands
            if len(expected_memory) != len(self.memory_effects) or len(expected_memory) > 1:
                raise UnsupportedProvenance("unsupported_or_mismatched_memory_effects")
            bound = []
            if expected_memory:
                self.memory_operand = expected_memory[0]
                effect = self.memory_effects[0]
                expected_direction = "write" if self.memory_operand == 0 else "read"
                if effect["direction"] != expected_direction:
                    raise UnsupportedProvenance("memory_direction_mismatch")
                bound = [self.bind_address(insn, effect, insn.operands[self.memory_operand].mem)]
            self.instructions.append({"rva": self.current_rva, "length": insn.size, "bytes": bytes(insn.bytes).hex(),
                                      "mnemonic": insn.mnemonic, "operands_text": insn.op_str,
                                      "vex_statement_count": len(block.statements)})
            self.accesses.extend(bound)
            if pc == target:
                if len(bound) != 1 or bound[0]["direction"] != "write":
                    raise UnsupportedProvenance("target_is_not_one_ordinary_store")
                return
            pc += insn.size
        raise UnsupportedProvenance("instruction_limit")


def build_syntax_provenance(request):
    validate_request(request)
    builder, reason = None, None
    try:
        builder = _Builder(request)
        builder.walk()
    except Exception as error:
        # Preserve already-built syntax on decoder/lifter/library failures as well.
        # None of these failures can produce an available/complete graph.
        reason = type(error).__name__ + ": " + str(error)
    try:
        unchanged = file_hash(request["binary"]) == request["binary_sha256"]
    except OSError as error:
        raise ValueError("Syntax binary disappeared while recording") from error
    if not unchanged:
        raise ValueError("Syntax binary changed while recording")
    graph = {"nodes": builder.nodes if builder else [], "instructions": builder.instructions if builder else [],
             "accesses": builder.accesses if builder else []}
    edges = [{"source": source, "target": node["id"], "operand_index": index}
             for node in graph["nodes"] for index, source in enumerate(node["operands"])]
    return {"schema": "symbai.instruction_provenance.v1", "revision": REVISION,
            "status": "available" if reason is None else "unavailable", "reason": reason,
            "identity": {k: request[k] for k in ("binary_sha256", "entry_rva", "target_store_rva")},
            **graph, "edges": edges, "syntax_fingerprint": fingerprint(graph),
            "complete": reason is None, "max_instructions": MAX_INSTRUCTIONS, "max_nodes": MAX_NODES,
            "register_offset_space": "vex_register_bytes", "temporary_scope": "instruction_rva",
            "memory_value_provenance": "opaque_no_dereference_or_store_to_load_forwarding",
            "property_verification_performed": False, "neural_information_used": False,
            "tygr_readout_compatibility_validated": False, "scope": "linear_instruction_syntax_only"}
