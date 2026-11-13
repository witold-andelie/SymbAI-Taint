"""Restricted straight-line compiler-frame bounds proofs; no neural inputs."""

from importlib.metadata import version
import time

from .contracts import file_hash, fingerprint
from .local_bounds import LocalBoundsChecker, UnsupportedBounds, MAX64, modular_interval

REVISION = "compiler_frame_bounds_v10_loader_consistency"
WINDOW = 4096
RED_ZONE = 128


class FrameBoundsChecker(LocalBoundsChecker):
    """A bounded slot interpreter with entry RSP taken from the actual reference model."""

    def __init__(self, query, reference_checker=None):
        super().__init__(query)
        from .operations import BinaryChecker
        self.reference = reference_checker if reference_checker is not None else BinaryChecker(query)
        if self.reference.query != query or file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Reference checker differs from the frame query")
        if self.reference.base != self.base:
            raise UnsupportedBounds("reference_image_base_mismatch")
        state, _ = self.reference.new_state()
        values = state.solver.eval_upto(state.regs.rsp, 2)
        if len(values) != 1 or not WINDOW + 8 <= values[0] <= MAX64 - 8:
            raise UnsupportedBounds("entry_stack_not_unique_or_wraps")
        self.entry_sp = values[0]
        self.frame_base = self.entry_sp - 8
        low, high = self.frame_base - WINDOW, self.entry_sp
        for segment in self.reference.project.loader.main_object.segments:
            if segment.memsize and low < segment.vaddr + segment.memsize and segment.vaddr < high:
                raise UnsupportedBounds("stack_window_overlaps_program_image")
        if low < self.object + query.capacity and self.object < high:
            raise UnsupportedBounds("stack_window_overlaps_declared_object")
        self.entry_context = {"query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
            "entry_rsp": self.entry_sp, "stack_window": [low, high], "frame_base": self.frame_base,
            "source": "fresh_BinaryChecker_call_state", "angr_version": version("angr"),
            "image_and_object_disjoint": True, "prefix_execution_used": False}

    def decode(self, pc):
        instruction = super().decode(pc)
        if hasattr(self, "reference"):
            loaded = self.reference.project.loader.memory.load(pc, instruction.size)
            if loaded != bytes(instruction.bytes):
                raise UnsupportedBounds("loaded_instruction_bytes_differ_from_file")
        return instruction

    def _numeric_register(self, insn, operand):
        name, bits = self.register(insn.reg_name(operand.reg))
        if name in ("rsp", "rbp"):
            raise UnsupportedBounds("frame_register_escape_or_overwrite")
        return name, bits

    def _numeric_value(self, insn, operand, registers, bits):
        if operand.type == self.x86.X86_OP_REG:
            self._numeric_register(insn, operand)
        return self.value(insn, operand, registers, bits)

    def _numeric_address(self, insn, operand, registers):
        for reg in (operand.mem.base, operand.mem.index):
            if reg and insn.reg_name(reg) != "rip":
                name, _ = self.register(insn.reg_name(reg))
                if name in ("rbp", "rsp"):
                    raise UnsupportedBounds("frame_address_escape_or_target")
        return self.address(insn, operand, registers)

    def _slot(self, insn, operand, allocation):
        mem = operand.mem
        if (insn.addr_size != 8 or mem.segment or mem.index or insn.reg_name(mem.base) != "rbp"
                or operand.size != 8 or mem.disp % 8 or not -WINDOW <= mem.disp <= -8):
            raise UnsupportedBounds("partial_overlapping_or_noncanonical_stack_access")
        if mem.disp < -allocation - RED_ZONE:
            raise UnsupportedBounds("stack_slot_outside_allocation_and_red_zone")
        return mem.disp

    @staticmethod
    def _arithmetic(mnemonic, left, right, bits):
        if mnemonic == "and" and right[0] == right[1]:
            return ((left[0] & right[0],) * 2 if left[0] == left[1] else (0, min(left[1], right[0])))
        if mnemonic == "add":
            return modular_interval(left[0] + right[0], left[1] + right[1], bits)
        if mnemonic == "sub":
            return modular_interval(left[0] - right[1], left[1] - right[0], bits)
        raise UnsupportedBounds("frame_arithmetic_outside_subset")

    def check(self, deadline, max_instructions=128):
        if type(max_instructions) is not int or not 0 < max_instructions <= 128:
            raise ValueError("Frame checks require an instruction cap in [1,128]")
        registers = {r.register: (r.minimum, r.maximum) for r in self.query.inputs}
        slots, trace = {}, []
        phase, allocation, allocation_open = "entry", 0, False
        pc = self.base + self.query.entry_rva
        try:
            while len(trace) < max_instructions:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Frame bounds exhausted the budget")
                insn = self.decode(pc)
                trace.append({"rva": pc - self.base, "bytes": bytes(insn.bytes).hex(), "phase": phase,
                    "register_intervals": {k: list(v) for k, v in sorted(registers.items())},
                    "slot_intervals": {str(k): list(v) for k, v in sorted(slots.items())}, "allocation_bytes": allocation})
                mnemonic, ops = insn.mnemonic, insn.operands
                if pc == self.target:
                    if phase != "body":
                        raise UnsupportedBounds("target_before_canonical_frame")
                    (low, high) = self._numeric_address(insn, ops[0], registers)
                    _, size = self._target_write(insn, registers)
                    if not self.object <= low <= high or high + size > self.object + self.query.capacity:
                        raise UnsupportedBounds("write_interval_not_proved_inside_object")
                    if file_hash(self.query.binary) != self.query.binary_sha256:
                        raise ValueError("Binary changed during frame check")
                    certificate = {"query_hash": self.query.contract_hash, "operation_revision": REVISION,
                        "entry_context": self.entry_context, "max_instructions": max_instructions,
                        "trace": trace, "discharged_writes": [{"address_interval": [low, high], "length": size}]}
                    return {"status": "excluded_within_scope", "complete": True, "operation_revision": REVISION,
                        "abstract_instructions": len(trace), "certificate": certificate,
                        "certificate_sha256": fingerprint(certificate),
                        "basis": "straight_line_frame_first_write_interval_inside_declared_bounds"}
                if mnemonic in ("nop", "endbr64"):
                    pc += insn.size
                    continue
                if phase == "entry":
                    if mnemonic != "push" or len(ops) != 1 or insn.op_str != "rbp":
                        raise UnsupportedBounds("canonical_push_rbp_required")
                    phase = "pushed"
                elif phase == "pushed":
                    if mnemonic != "mov" or insn.op_str != "rbp, rsp":
                        raise UnsupportedBounds("canonical_frame_establishment_required")
                    phase, allocation_open = "body", True
                elif mnemonic == "sub" and len(ops) == 2 and ops[0].type == self.x86.X86_OP_REG and insn.reg_name(ops[0].reg) == "rsp":
                    if (not allocation_open or ops[1].type != self.x86.X86_OP_IMM
                            or not 0 < ops[1].imm <= WINDOW or ops[1].imm % 8):
                        raise UnsupportedBounds("stack_allocation_outside_subset")
                    allocation, allocation_open = ops[1].imm, False
                else:
                    allocation_open = False
                    if mnemonic not in ("mov", "movabs", "lea", "xor", "and", "add", "sub") or len(ops) != 2:
                        raise UnsupportedBounds("unsupported_frame_instruction:" + mnemonic)
                    if ops[0].type == self.x86.X86_OP_MEM:
                        slot = self._slot(insn, ops[0], allocation)
                        right = self._numeric_value(insn, ops[1], registers, 64)
                        if mnemonic == "mov":
                            value = right
                        else:
                            if slot not in slots:
                                raise UnsupportedBounds("uninitialized_stack_slot")
                            value = self._arithmetic(mnemonic, slots[slot], right, 64)
                        slots[slot] = value
                    elif ops[0].type == self.x86.X86_OP_REG:
                        _, bits = self._numeric_register(insn, ops[0])
                        if mnemonic in ("mov", "movabs"):
                            if ops[1].type == self.x86.X86_OP_MEM:
                                slot = self._slot(insn, ops[1], allocation)
                                if slot not in slots or bits != 64:
                                    raise UnsupportedBounds("uninitialized_or_partial_stack_load")
                                value = slots[slot]
                            else:
                                value = self._numeric_value(insn, ops[1], registers, bits)
                        elif mnemonic == "lea":
                            if bits != 64 or ops[1].type != self.x86.X86_OP_MEM:
                                raise UnsupportedBounds("frame_lea_outside_subset")
                            value = self._numeric_address(insn, ops[1], registers)
                        elif mnemonic == "xor" and ops[1].type == self.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
                            value = (0, 0)
                        else:
                            left = self.read_register(insn, ops[0], registers)
                            right = self._numeric_value(insn, ops[1], registers, bits)
                            value = self._arithmetic(mnemonic, left, right, bits)
                        self.assign(insn, ops[0], registers, value)
                    else:
                        raise UnsupportedBounds("frame_destination_outside_subset")
                pc += insn.size
            raise UnsupportedBounds("frame_instruction_limit")
        except UnsupportedBounds as exc:
            return {"status": "unknown", "reason": str(exc), "operation_revision": REVISION,
                "abstract_instructions": len(trace)}

    def validate(self, result, deadline):
        if result["status"] == "unknown":
            return dict(result, validation="no_decisive_evidence")
        certificate = result.get("certificate", {})
        if (result.get("status") != "excluded_within_scope" or certificate.get("query_hash") != self.query.contract_hash
                or certificate.get("operation_revision") != REVISION
                or result.get("certificate_sha256") != fingerprint(certificate)):
            raise ValueError("Invalid or mismatched frame-bound certificate")
        replay = FrameBoundsChecker(self.query).check(deadline, certificate["max_instructions"])
        if replay["status"] != "excluded_within_scope" or replay["certificate_sha256"] != result["certificate_sha256"]:
            raise ValueError("Frame-bound certificate failed fresh entry-context and byte recheck")
        if time.monotonic() >= deadline:
            raise TimeoutError("Frame-bound validation exhausted the budget")
        return dict(result, validation="fresh_entry_context_and_byte_decoded_recheck", native_replay="not_attempted")
