"""Conservative byte-decoded interval checks; optional type information is never an input."""

from collections import deque
from io import BytesIO
from pathlib import Path
import time

from .contracts import file_hash, fingerprint


MAX64 = (1 << 64) - 1
REVISION = "unsigned_local_bounds_v10_relocation_guard"


class UnsupportedBounds(ValueError):
    pass


def modular_interval(low, high, bits=64):
    modulus = 1 << bits
    if low // modulus != high // modulus:
        return (0, modulus - 1)
    return (low % modulus, high % modulus)


class LocalBoundsChecker:
    """A small abstract interpreter, not a general x86 or alias-analysis implementation."""

    def __init__(self, query):
        import capstone
        from elftools.elf.elffile import ELFFile
        self.query = query
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary hash differs from query contract")
        elf = ELFFile(BytesIO(Path(query.binary).read_bytes()))
        if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
                or elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
            raise ValueError("Local bounds require a little-endian AMD64 ELF")
        loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        if not loads:
            raise ValueError("ELF has no loadable segments")
        spans = sorted((s["p_vaddr"], s["p_vaddr"] + s["p_memsz"]) for s in loads)
        if any(end > following for (_, end), (following, _) in zip(spans, spans[1:])):
            raise UnsupportedBounds("overlapping_load_segments_outside_subset")
        linked_base = min(s["p_vaddr"] for s in loads) & ~0xFFF
        if linked_base != min(s["p_vaddr"] for s in loads):
            raise UnsupportedBounds("unaligned_linked_base_outside_subset")
        if elf["e_type"] == "ET_DYN" and linked_base != 0:
            raise ValueError("Nonzero linked PIE base is outside the local-bound subset")
        self.base = 0x400000 if elf["e_type"] == "ET_DYN" else linked_base
        bias = self.base - linked_base
        self.segments = [(s["p_vaddr"] + bias, s.data()) for s in loads if s["p_flags"] & 1]
        relocations = [s for s in elf.iter_sections() if s["sh_type"] in ("SHT_REL", "SHT_RELA")]
        if any(s["p_type"] == "PT_DYNAMIC" for s in elf.iter_segments()) and not relocations:
            raise UnsupportedBounds("dynamic_relocation_coverage_unavailable")
        from .elf_guard import check_relocation_coverage, UnsupportedELFLayout
        try:
            check_relocation_coverage(elf, loads, relocations)
        except UnsupportedELFLayout as exc:
            raise UnsupportedBounds(str(exc)) from exc
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.x86 = capstone.x86_const
        self.object = self.base + query.object_rva
        if self.object + query.capacity > (1 << 64):
            raise ValueError("Object bounds wrap the address space")
        self.target = self.base + query.write_rva
        self._target_write(self.decode(self.target), {})  # Reject an invalid query even if unreachable.

    def decode(self, pc):
        matches = [(start, data) for start, data in self.segments if start <= pc < start + len(data)]
        if len(matches) != 1:
            raise UnsupportedBounds("instruction_outside_unique_executable_segment")
        start, data = matches[0]
        insn = next(self.decoder.disasm(data[pc - start:pc - start + 15], pc, count=1), None)
        if insn is None:
            raise UnsupportedBounds("instruction_decode_failed")
        if insn.mnemonic != "endbr64" and any(insn.prefix):
            raise UnsupportedBounds("instruction_prefix_outside_subset")
        return insn

    @staticmethod
    def register(name):
        classic = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                   "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}
        if name in classic:
            return classic[name], 32
        if name in classic.values():
            return name, 64
        if name in {"r" + str(n) for n in range(8, 16)}:
            return name, 64
        if name in {"r" + str(n) + "d" for n in range(8, 16)}:
            return name[:-1], 32
        raise UnsupportedBounds("register_width_outside_subset")

    def read_register(self, insn, operand, registers):
        name, bits = self.register(insn.reg_name(operand.reg))
        low, high = registers.get(name, (0, MAX64))
        return modular_interval(low, high, bits)

    def value(self, insn, operand, registers, bits):
        if operand.type == self.x86.X86_OP_IMM:
            value = operand.imm % (1 << bits)
            return (value, value)
        if operand.type == self.x86.X86_OP_REG:
            return self.read_register(insn, operand, registers)
        raise UnsupportedBounds("memory_read_outside_subset")

    def assign(self, insn, operand, registers, value):
        if operand.type != self.x86.X86_OP_REG:
            raise UnsupportedBounds("non_target_memory_write")
        name, bits = self.register(insn.reg_name(operand.reg))
        if name == "rsp":
            raise UnsupportedBounds("stack_modification_outside_subset")
        registers[name] = modular_interval(*value, bits)

    def address(self, insn, operand, registers):
        if insn.addr_size != 8 or operand.mem.segment:
            raise UnsupportedBounds("segmented_or_non64_address")
        low = high = operand.mem.disp
        for reg, scale in ((operand.mem.base, 1), (operand.mem.index, operand.mem.scale)):
            if not reg:
                continue
            name = insn.reg_name(reg)
            if name == "rip":
                part = (insn.address + insn.size,) * 2
            else:
                canonical, bits = self.register(name)
                if bits != 64:
                    raise UnsupportedBounds("non64_address_register")
                part = registers.get(canonical, (0, MAX64))
            low += part[0] * scale
            high += part[1] * scale
        return modular_interval(low, high)

    def _target_write(self, insn, registers):
        ops = insn.operands
        if (insn.mnemonic != "mov" or len(ops) != 2 or ops[0].type != self.x86.X86_OP_MEM
                or ops[1].type not in (self.x86.X86_OP_IMM, self.x86.X86_OP_REG)
                or ops[0].size not in (1, 2, 4, 8)):
            raise UnsupportedBounds("target_write_outside_subset")
        return self.address(insn, ops[0], registers), ops[0].size

    def check(self, deadline, max_instructions=128):
        if max_instructions <= 0:
            raise ValueError("A positive abstract work limit is required")
        initial = {r.register: (r.minimum, r.maximum) for r in self.query.inputs}
        active = deque([(self.base + self.query.entry_rva, initial, None)])
        trace, writes, returns, seen = [], [], 0, set()
        try:
            while active:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Local bounds exhausted the budget")
                if len(trace) >= max_instructions:
                    raise UnsupportedBounds("abstract_instruction_limit")
                pc, registers, comparison = active.popleft()
                identity = (pc, tuple(sorted(registers.items())), comparison)
                if identity in seen:
                    raise UnsupportedBounds("cycle_without_termination_proof")
                seen.add(identity)
                insn = self.decode(pc)
                trace.append({"rva": pc - self.base, "bytes": bytes(insn.bytes).hex(),
                              "register_intervals": {k: list(v) for k, v in sorted(registers.items())},
                              "comparison": comparison})
                if pc == self.target:
                    (low, high), size = self._target_write(insn, registers)
                    if not (self.object <= low <= high and high + size <= self.object + self.query.capacity):
                        raise UnsupportedBounds("write_interval_not_proved_inside_object")
                    writes.append({"address_interval": [low, high], "length": size})
                    continue  # Scope ends at the first dynamic visit.
                mnemonic, ops, after = insn.mnemonic, insn.operands, pc + insn.size
                next_comparison = None
                if mnemonic in ("nop", "endbr64"):
                    pass
                elif mnemonic == "ret" and not ops:
                    returns += 1
                    continue
                elif mnemonic == "jmp" and len(ops) == 1 and ops[0].type == self.x86.X86_OP_IMM:
                    active.append((ops[0].imm, registers, None))
                    continue
                elif mnemonic in ("jae", "ja", "jb", "jbe") and comparison is not None:
                    if len(ops) != 1 or ops[0].type != self.x86.X86_OP_IMM:
                        raise UnsupportedBounds("non_direct_conditional_branch")
                    name, bound = comparison
                    low, high = registers.get(name, (0, MAX64))
                    cut = bound + (mnemonic in ("ja", "jbe"))
                    less, greater = (low, min(high, cut - 1)), (max(low, cut), high)
                    taken, fallthrough = (less, greater) if mnemonic in ("jb", "jbe") else (greater, less)
                    for dest, interval in ((ops[0].imm, taken), (after, fallthrough)):
                        if interval[0] <= interval[1]:
                            active.append((dest, {**registers, name: interval}, None))
                    continue
                elif mnemonic == "cmp" and len(ops) == 2 and ops[0].type == self.x86.X86_OP_REG and ops[1].type == self.x86.X86_OP_IMM:
                    name, bits = self.register(insn.reg_name(ops[0].reg))
                    if bits != 64:
                        raise UnsupportedBounds("non64_compare")
                    next_comparison = (name, ops[1].imm % (1 << 64))
                elif mnemonic in ("mov", "movabs", "lea", "xor", "and", "add", "sub") and len(ops) == 2:
                    if ops[0].type != self.x86.X86_OP_REG:
                        raise UnsupportedBounds("non_target_memory_write")
                    _, bits = self.register(insn.reg_name(ops[0].reg))
                    if mnemonic == "lea":
                        if bits != 64 or ops[1].type != self.x86.X86_OP_MEM:
                            raise UnsupportedBounds("lea_outside_subset")
                        value = self.address(insn, ops[1], registers)
                    elif mnemonic in ("mov", "movabs"):
                        value = self.value(insn, ops[1], registers, bits)
                    elif mnemonic == "xor" and ops[1].type == self.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
                        value = (0, 0)
                    else:
                        left = self.read_register(insn, ops[0], registers)
                        right = self.value(insn, ops[1], registers, bits)
                        if mnemonic == "and" and right[0] == right[1]:
                            value = ((left[0] & right[0],) * 2 if left[0] == left[1]
                                     else (0, min(left[1], right[0])))
                        elif mnemonic == "add":
                            value = modular_interval(left[0] + right[0], left[1] + right[1], bits)
                        elif mnemonic == "sub":
                            value = modular_interval(left[0] - right[1], left[1] - right[0], bits)
                        else:
                            raise UnsupportedBounds("arithmetic_outside_subset")
                    registers = dict(registers)
                    self.assign(insn, ops[0], registers, value)
                else:
                    raise UnsupportedBounds("unsupported_instruction:" + mnemonic)
                active.append((after, registers, next_comparison))
        except UnsupportedBounds as error:
            return {"status": "unknown", "reason": str(error), "abstract_instructions": len(trace),
                    "operation_revision": REVISION}
        certificate = {"query_hash": self.query.contract_hash, "operation_revision": REVISION,
                       "max_instructions": max_instructions, "trace": trace,
                       "discharged_writes": writes, "returns_before_target": returns}
        return {"status": "excluded_within_scope", "complete": True,
                "abstract_instructions": len(trace), "certificate": certificate,
                "certificate_sha256": fingerprint(certificate), "operation_revision": REVISION,
                "basis": "all_abstract_first_visit_obligations_inside_declared_bounds_or_returned"}

    def validate(self, result, deadline):
        if result["status"] == "unknown":
            return dict(result, validation="no_decisive_evidence")
        certificate = result.get("certificate", {})
        if (result["status"] != "excluded_within_scope" or certificate.get("query_hash") != self.query.contract_hash
                or result.get("certificate_sha256") != fingerprint(certificate)):
            raise ValueError("Invalid or mismatched local-bound certificate")
        replay = LocalBoundsChecker(self.query).check(deadline, certificate["max_instructions"])
        if replay["status"] != "excluded_within_scope" or replay["certificate_sha256"] != result["certificate_sha256"]:
            raise ValueError("Local-bound certificate failed fresh byte-decoded recheck")
        if time.monotonic() >= deadline:
            raise TimeoutError("Local-bound validation exhausted the budget")
        return dict(result, validation="fresh_byte_decoded_abstract_recheck", native_replay="not_attempted")
