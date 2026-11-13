"""Bounded finite AMD64 values and immutable file-backed qword indirections.

This operation has no paths, solver, type inputs or witness claim.  Cartesian
products deliberately lose correlations and saturate to Top rather than sample.
"""

import hashlib
from io import BytesIO
from itertools import product
from pathlib import Path
import time

from .contracts import file_hash, fingerprint
from .elf_guard import check_relocation_coverage
from .local_bounds import LocalBoundsChecker, UnsupportedBounds, MAX64


REVISION = "finite_readonly_values_v14"
CARDINALITY_LIMIT = 32
_RELOCATION_WIDTHS = {0: 0, 1: 8, 6: 8, 7: 8, 8: 8}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class FiniteReadonlyChecker:
    def __init__(self, query, cardinality_limit=CARDINALITY_LIMIT):
        if type(cardinality_limit) is not int or not 1 <= cardinality_limit <= CARDINALITY_LIMIT:
            raise ValueError("Finite readonly cardinality must be an integer in [1,32]")
        self.query, self.cardinality_limit = query, cardinality_limit
        # Composition avoids LocalBoundsChecker's constructor dispatching into
        # an incompletely initialized derived decoder or target interpreter.
        self.local = LocalBoundsChecker(query)
        self.base, self.object, self.target = self.local.base, self.local.object, self.local.target
        self.x86 = self.local.x86
        from elftools.elf.elffile import ELFFile
        data = Path(query.binary).read_bytes()
        if _sha(data) != query.binary_sha256:
            raise ValueError("Binary changed during readonly preparation")
        elf = ELFFile(BytesIO(data))
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        linked_base = min(segment["p_vaddr"] for segment in loads)
        bias = self.base - linked_base
        sections = [section for section in elf.iter_sections() if section["sh_type"] in ("SHT_REL", "SHT_RELA")]
        check_relocation_coverage(elf, loads, sections)
        self.segments = []
        executable = []
        for segment in loads:
            start, size, file_size = segment["p_vaddr"] + bias, segment["p_memsz"], segment["p_filesz"]
            if (not 0 <= start <= MAX64 or not 0 <= file_size <= size or start + size > MAX64 + 1
                    or segment["p_offset"] + file_size > len(data)):
                raise UnsupportedBounds("invalid_readonly_segment_span")
            contents = segment.data()
            if len(contents) != file_size:
                raise UnsupportedBounds("unbacked_segment_file_bytes")
            item = {"start": start, "memory_size": size, "bytes": contents,
                    "flags": segment["p_flags"], "sha256": _sha(contents)}
            self.segments.append(item)
            if segment["p_flags"] & 1:
                executable.append((start, contents))
        if executable != self.local.segments:
            raise ValueError("Executable bytes changed during readonly preparation")
        self.relocations = []
        for section in sections:
            for relocation in section.iter_relocations():
                width = _RELOCATION_WIDTHS.get(relocation["r_info_type"])
                if width is None:
                    raise UnsupportedBounds("relocation_write_width_outside_subset")
                if width:
                    start = relocation["r_offset"] + bias
                    if start < 0 or start + width > MAX64 + 1:
                        raise UnsupportedBounds("wrapping_relocation_span")
                    self.relocations.append((start, start + width))

    def _bounded(self, values, reason):
        result = set()
        for value in values:
            result.add(value & MAX64)
            if len(result) > self.cardinality_limit:
                self.saturations.append({"reason": reason, "observed_distinct_lower_bound": len(result),
                                         "cardinality_limit": self.cardinality_limit})
                return None
        return frozenset(result)

    def _register(self, insn, operand):
        if operand.type != self.x86.X86_OP_REG:
            raise UnsupportedBounds("non_target_memory_write")
        name, bits = self.local.register(insn.reg_name(operand.reg))
        if bits != 64 or operand.size != 8:
            raise UnsupportedBounds("non64_register_outside_subset")
        return name

    def _address(self, insn, operand, registers, readonly=False):
        if operand.type != self.x86.X86_OP_MEM or insn.addr_size != 8 or operand.mem.segment:
            raise UnsupportedBounds("segmented_or_non64_address")
        parts = []
        for reg, scale in ((operand.mem.base, 1), (operand.mem.index, operand.mem.scale)):
            if not reg:
                continue
            name = insn.reg_name(reg)
            if name == "rip":
                values = frozenset((insn.address + insn.size,))
            else:
                name, bits = self.local.register(name)
                if bits != 64:
                    raise UnsupportedBounds("non64_address_register")
                values = registers.get(name)
            if values is None:
                return None
            parts.append(tuple(value * scale for value in values))

        def sums():
            for combination in product(*parts):
                value = operand.mem.disp + sum(combination)
                if readonly and not 0 <= value <= MAX64:
                    raise UnsupportedBounds("readonly_address_wrap")
                yield value

        return self._bounded(sums(), "address_cardinality_exceeds_cap")

    def _read(self, insn, operand, registers):
        if operand.size != 8:
            raise UnsupportedBounds("readonly_load_width_outside_subset")
        addresses = self._address(insn, operand, registers, readonly=True)
        if addresses is None:
            raise UnsupportedBounds("readonly_address_is_top")
        values = []
        for address in sorted(addresses):
            if address + 8 > MAX64 + 1:
                raise UnsupportedBounds("readonly_span_wrap")
            matches = [segment for segment in self.segments if segment["start"] <= address
                       and address < segment["start"] + segment["memory_size"]]
            if len(matches) != 1:
                raise UnsupportedBounds("readonly_address_unmapped_or_ambiguous")
            segment = matches[0]
            if segment["flags"] & 2 or not segment["flags"] & 4:
                raise UnsupportedBounds("mutable_or_unreadable_memory_load")
            offset = address - segment["start"]
            if offset + 8 > len(segment["bytes"]) or offset + 8 > segment["memory_size"]:
                raise UnsupportedBounds("readonly_span_unbacked_or_cross_segment")
            if any(address < end and start < address + 8 for start, end in self.relocations):
                raise UnsupportedBounds("readonly_span_overlaps_relocation")
            data = segment["bytes"][offset:offset + 8]
            value = int.from_bytes(data, "little")
            self.readonly_reads.append({"instruction_rva": insn.address - self.base, "address": address,
                                        "size_bytes": 8, "bytes": data.hex(), "sha256": _sha(data),
                                        "segment_start": segment["start"], "segment_sha256": segment["sha256"],
                                        "value": value})
            values.append(value)
        return self._bounded(values, "loaded_value_cardinality_exceeds_cap")

    def _value(self, insn, operand, registers, load=False):
        if operand.type == self.x86.X86_OP_IMM:
            return frozenset((operand.imm & MAX64,))
        if operand.type == self.x86.X86_OP_REG:
            return registers.get(self._register(insn, operand))
        if load and operand.type == self.x86.X86_OP_MEM:
            return self._read(insn, operand, registers)
        raise UnsupportedBounds("value_operand_outside_subset")

    def _arithmetic(self, mnemonic, left, right):
        if mnemonic == "and" and (left is None or right is None):
            masks = right if left is None else left
            if masks is None:
                return None
            values = set()
            for mask in masks:
                if (1 << mask.bit_count()) > self.cardinality_limit:
                    self.saturations.append({"reason": "mask_image_exceeds_cap", "mask": mask,
                                             "cardinality_limit": self.cardinality_limit})
                    return None
                submask = mask
                while True:
                    values.add(submask)
                    if len(values) > self.cardinality_limit:
                        return self._bounded(values, "mask_union_exceeds_cap")
                    if submask == 0:
                        break
                    submask = (submask - 1) & mask
            return frozenset(values)
        if left is None or right is None:
            return None
        operation = {"add": lambda a, b: a + b, "sub": lambda a, b: a - b,
                     "and": lambda a, b: a & b, "xor": lambda a, b: a ^ b}[mnemonic]
        return self._bounded((operation(a, b) for a in left for b in right), "arithmetic_cardinality_exceeds_cap")

    @staticmethod
    def _render(registers):
        return {name: "Top" if values is None else sorted(values) for name, values in sorted(registers.items())}

    def check(self, deadline, max_instructions=128):
        if type(max_instructions) is not int or not 1 <= max_instructions <= 128:
            raise ValueError("Finite readonly checks require an instruction cap in [1,128]")
        self.saturations, self.readonly_reads = [], []
        registers = {}
        for bound in self.query.inputs:
            size = bound.maximum - bound.minimum + 1
            if size > self.cardinality_limit:
                registers[bound.register] = None
                self.saturations.append({"reason": "input_cardinality_exceeds_cap", "register": bound.register,
                                         "input_cardinality": size, "cardinality_limit": self.cardinality_limit})
            else:
                registers[bound.register] = frozenset(range(bound.minimum, bound.maximum + 1))
        trace, pc = [], self.base + self.query.entry_rva
        try:
            while len(trace) < max_instructions:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Finite readonly check exhausted the budget")
                insn = self.local.decode(pc)
                trace.append({"rva": pc - self.base, "bytes": bytes(insn.bytes).hex(),
                              "register_values": self._render(registers)})
                ops, mnemonic = insn.operands, insn.mnemonic
                if pc == self.target:
                    addresses = self._address(insn, ops[0], registers)
                    size = ops[0].size
                    if addresses is None or not addresses or any(
                            not self.object <= address or address + size > self.object + self.query.capacity
                            or address + size > MAX64 + 1 for address in addresses):
                        raise UnsupportedBounds("finite_target_addresses_not_proved_inside_object")
                    if file_hash(self.query.binary) != self.query.binary_sha256:
                        raise ValueError("Binary changed during finite readonly check")
                    certificate = {"query_hash": self.query.contract_hash, "binary_sha256": self.query.binary_sha256,
                                   "operation_revision": REVISION, "cardinality_limit": self.cardinality_limit,
                                   "max_instructions": max_instructions, "trace": trace,
                                   "readonly_reads": self.readonly_reads, "saturations": self.saturations,
                                   "discharged_writes": [{"addresses": sorted(addresses), "length": size}]}
                    return {"status": "excluded_within_scope", "complete": True, "operation_revision": REVISION,
                            "cardinality_limit": self.cardinality_limit, "abstract_instructions": len(trace),
                            "saturations": self.saturations, "readonly_reads": self.readonly_reads,
                            "certificate": certificate, "certificate_sha256": fingerprint(certificate),
                            "basis": "all_finite_first_visit_target_byte_spans_inside_declared_object"}
                if mnemonic in ("nop", "endbr64") and not ops:
                    pc += insn.size
                    continue
                if mnemonic not in ("mov", "movabs", "lea", "add", "sub", "and", "xor") or len(ops) != 2:
                    raise UnsupportedBounds("unsupported_instruction:" + mnemonic)
                name = self._register(insn, ops[0])
                if name == "rsp":
                    raise UnsupportedBounds("stack_modification_outside_subset")
                if mnemonic in ("mov", "movabs"):
                    value = self._value(insn, ops[1], registers, load=True)
                elif mnemonic == "lea":
                    value = self._address(insn, ops[1], registers)
                elif mnemonic == "xor" and ops[1].type == self.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
                    value = frozenset((0,))
                else:
                    value = self._arithmetic(mnemonic, registers.get(name), self._value(insn, ops[1], registers))
                registers[name] = value
                pc += insn.size
                if pc > self.target:
                    raise UnsupportedBounds("target_not_on_straight_line_instruction_boundary")
            raise UnsupportedBounds("finite_instruction_limit")
        except UnsupportedBounds as exc:
            return {"status": "unknown", "reason": str(exc), "operation_revision": REVISION,
                    "cardinality_limit": self.cardinality_limit, "abstract_instructions": len(trace),
                    "trace": trace, "saturations": self.saturations, "readonly_reads": self.readonly_reads}

    def validate(self, result, deadline):
        if result.get("status") == "unknown":
            return dict(result, validation="no_decisive_evidence")
        certificate = result.get("certificate", {})
        if (result.get("status") != "excluded_within_scope" or result.get("operation_revision") != REVISION
                or result.get("cardinality_limit") != self.cardinality_limit
                or certificate.get("query_hash") != self.query.contract_hash
                or certificate.get("binary_sha256") != self.query.binary_sha256
                or certificate.get("operation_revision") != REVISION
                or certificate.get("cardinality_limit") != self.cardinality_limit
                or result.get("certificate_sha256") != fingerprint(certificate)):
            raise ValueError("Invalid or mismatched finite readonly certificate")
        replay = FiniteReadonlyChecker(self.query, self.cardinality_limit).check(deadline, certificate["max_instructions"])
        if replay["status"] != "excluded_within_scope" or replay["certificate_sha256"] != result["certificate_sha256"]:
            raise ValueError("Finite readonly certificate failed fresh byte/data recheck")
        if time.monotonic() >= deadline:
            raise TimeoutError("Finite readonly validation exhausted the budget")
        return dict(result, validation="fresh_byte_data_abstract_recheck", native_replay="not_attempted")
