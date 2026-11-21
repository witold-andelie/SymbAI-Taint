"""Check bounded AMD64 path certificates against a single byte-write query."""

from dataclasses import dataclass
from pathlib import Path
import time

import z3

from src.selective_analysis.contracts import file_hash
from src.selective_analysis.local_bounds import LocalBoundsChecker


SCHEMA = "symbai.amd64_first_write_paths.v1"
PROVEN = "excluded_within_scope"
MAX_STEPS = 128
MAX_PATHS = 64
MAX_TREE_NODES = 2048
LOW_BYTE_REGISTERS = {
    "al": "rax",
    "cl": "rcx",
    "dl": "rdx",
    "bl": "rbx",
    "sil": "rsi",
    "dil": "rdi",
    "spl": "rsp",
    "bpl": "rbp",
    **{f"r{index}b": f"r{index}" for index in range(8, 16)},
}


class Rejected(ValueError):
    pass


@dataclass(frozen=True)
class ResultFlags:
    zero: z3.BoolRef
    sign: z3.BoolRef | None = None


def cast(value, bits):
    width = value.size()
    if width > bits:
        return z3.Extract(bits - 1, 0, value)
    if width < bits:
        return z3.ZeroExt(bits - width, value)
    return value


class PathChecker:
    """Rebuild state per path prefix and check that no feasible edge was omitted."""

    def __init__(self, query):
        (bounds,) = query.inputs
        if bounds.register != "rdi":
            raise Rejected("unsupported_entry_contract")
        self.contract = query
        self.decoder = LocalBoundsChecker(query)
        self.base = self.decoder.base
        self.target = self.decoder.target
        self.object = self.decoder.object
        self.x86 = self.decoder.x86
        self.argument = z3.BitVec("entry_rdi", 64)
        self.domain = z3.And(
            z3.UGE(self.argument, bounds.minimum), z3.ULE(self.argument, bounds.maximum)
        )
        self.obligations = []
        self.omitted = 0
        self.nodes = 0

    def named_register(self, name, registers):
        register = LOW_BYTE_REGISTERS.get(name)
        if register is None:
            register, bits = self.decoder.register(name)
        else:
            bits = 8
        if register not in registers:
            raise Rejected("entry_register_not_defined")
        return cast(registers[register], bits)

    def value(self, insn, op, width, registers):
        if op.type == self.x86.X86_OP_IMM:
            return z3.BitVecVal(op.imm, width)
        if op.type == self.x86.X86_OP_REG:
            return cast(self.named_register(insn.reg_name(op.reg), registers), width)
        raise Rejected("source_operand_outside_subset")

    def address(self, insn, op, registers):
        if op.type != self.x86.X86_OP_MEM or insn.addr_size != 8 or op.mem.segment:
            raise Rejected("address_operand_outside_subset")
        result = z3.BitVecVal(op.mem.disp, 64)
        for reg, scale in ((op.mem.base, 1), (op.mem.index, op.mem.scale)):
            if not reg:
                continue
            name = insn.reg_name(reg)
            if name == "rip":
                part = z3.BitVecVal(insn.address + insn.size, 64)
            else:
                _, bits = self.decoder.register(name)
                if bits != 64:
                    raise Rejected("non64_address_register")
                part = self.named_register(name, registers)
            result = result + part * scale
        return result

    def _bit_scan_edges(self, insn, registers, guard):
        ops = insn.operands
        if len(ops) != 2 or any(op.type != self.x86.X86_OP_REG for op in ops):
            raise Rejected("bsr_requires_two_register_operands")
        destination, bits = self.decoder.register(insn.reg_name(ops[0].reg))
        if destination == "rsp" or any(op.size * 8 != bits for op in ops):
            raise Rejected("destination_outside_subset")
        source = self.value(insn, ops[1], bits, registers)
        zero = source == 0
        # BSR leaves the destination undefined on zero. Acceptance requires
        # proof that this case is infeasible at every scanned prefix.
        self.obligations.append(z3.And(guard, zero))
        highest = z3.BitVecVal(0, bits)
        for bit in range(bits):
            highest = z3.If(
                z3.Extract(bit, bit, source) == 1, z3.BitVecVal(bit, bits), highest
            )
        state = {**registers, destination: cast(highest, 64)}
        return [(insn.address + insn.size, state, ResultFlags(zero), z3.BoolVal(True))]

    def semantics(self, insn, registers, comparison):
        ops, mnemonic = insn.operands, insn.mnemonic
        after = insn.address + insn.size
        if mnemonic in ("nop", "endbr64"):
            return [(after, registers, None, z3.BoolVal(True))]
        if mnemonic == "jmp" and len(ops) == 1 and ops[0].type == self.x86.X86_OP_IMM:
            return [(ops[0].imm, registers, None, z3.BoolVal(True))]
        if mnemonic in (
            "ja",
            "jae",
            "jb",
            "jbe",
            "jg",
            "jge",
            "jl",
            "jle",
            "je",
            "jne",
            "js",
            "jns",
        ):
            if (
                comparison is None
                or len(ops) != 1
                or ops[0].type != self.x86.X86_OP_IMM
            ):
                raise Rejected("comparison_or_target_unsupported")
            if ops[0].imm == after:
                return [(after, registers, None, z3.BoolVal(True))]
            if isinstance(comparison, ResultFlags):
                if mnemonic in ("je", "jne"):
                    taken = (
                        comparison.zero if mnemonic == "je" else z3.Not(comparison.zero)
                    )
                elif mnemonic in ("js", "jns") and comparison.sign is not None:
                    taken = (
                        comparison.sign if mnemonic == "js" else z3.Not(comparison.sign)
                    )
                else:
                    raise Rejected("branch_flags_outside_subset")
            else:
                if mnemonic in ("js", "jns"):
                    raise Rejected("branch_flags_outside_subset")
                a, b = comparison
                conditions = {
                    "ja": z3.UGT(a, b),
                    "jae": z3.UGE(a, b),
                    "jb": z3.ULT(a, b),
                    "jbe": z3.ULE(a, b),
                    "jg": a > b,
                    "jge": a >= b,
                    "jl": a < b,
                    "jle": a <= b,
                    "je": a == b,
                    "jne": a != b,
                }
                taken = conditions[mnemonic]
            return [
                (ops[0].imm, registers, None, taken),
                (after, registers, None, z3.Not(taken)),
            ]
        if mnemonic == "test" and len(ops) == 2 and ops[0].type == self.x86.X86_OP_REG:
            bits = ops[0].size * 8
            if bits not in (8, 32, 64):
                raise Rejected("test_width_outside_subset")
            left = self.value(insn, ops[0], bits, registers)
            right = self.value(insn, ops[1], bits, registers)
            if bits == 64 and ops[1].type == self.x86.X86_OP_IMM:
                right = z3.SignExt(32, cast(right, 32))
            return [
                (after, registers, ResultFlags((left & right) == 0), z3.BoolVal(True))
            ]
        if mnemonic == "cdqe" and not ops:
            value = z3.SignExt(32, self.named_register("eax", registers))
            return [(after, {**registers, "rax": value}, None, z3.BoolVal(True))]
        if not ops or ops[0].type != self.x86.X86_OP_REG:
            raise Rejected("unsupported_instruction:" + mnemonic)
        target, bits = self.decoder.register(insn.reg_name(ops[0].reg))
        if target == "rsp" or ops[0].size * 8 != bits:
            raise Rejected("destination_outside_subset")
        if mnemonic == "cmp" and len(ops) == 2:
            left = self.value(insn, ops[0], bits, registers)
            right = self.value(insn, ops[1], bits, registers)
            return [(after, registers, (left, right), z3.BoolVal(True))]
        if mnemonic in ("mov", "movabs") and len(ops) == 2:
            value = self.value(insn, ops[1], bits, registers)
        elif mnemonic == "movsxd" and len(ops) == 2 and ops[1].size == 4 and bits == 64:
            value = z3.SignExt(32, self.value(insn, ops[1], 32, registers))
        elif mnemonic == "lea" and len(ops) == 2:
            value = cast(self.address(insn, ops[1], registers), bits)
        elif (
            mnemonic == "imul" and len(ops) == 3 and ops[2].type == self.x86.X86_OP_IMM
        ):
            value = self.value(insn, ops[1], bits, registers) * self.value(
                insn, ops[2], bits, registers
            )
        elif (
            mnemonic in ("add", "sub", "xor", "and", "or", "shr", "sar", "shl", "ror")
            and len(ops) == 2
        ):
            left = self.value(insn, ops[0], bits, registers)
            right = self.value(insn, ops[1], bits, registers)
            if mnemonic in ("shr", "sar", "shl", "ror"):
                right = right & (bits - 1)
            transfer = {
                "add": lambda: left + right,
                "sub": lambda: left - right,
                "xor": lambda: left ^ right,
                "and": lambda: left & right,
                "or": lambda: left | right,
                "shr": lambda: z3.LShR(left, right),
                "sar": lambda: left >> right,
                "shl": lambda: left << right,
                "ror": lambda: z3.RotateRight(left, right),
            }
            value = transfer[mnemonic]()
        else:
            raise Rejected("unsupported_instruction:" + mnemonic)
        flags = None
        if mnemonic == "sub":
            flags = ResultFlags(value == 0, z3.Extract(bits - 1, bits - 1, value) == 1)
        return [
            (after, {**registers, target: cast(value, 64)}, flags, z3.BoolVal(True))
        ]

    def visit(self, pc, node, registers, comparison, guard, deadline):
        if time.monotonic() >= deadline:
            raise TimeoutError("certificate deadline")
        self.nodes += 1
        insn = self.decoder.decode(pc)
        if pc == self.target:
            if node or insn.mnemonic != "mov" or insn.operands[0].size != 1:
                raise Rejected("invalid_target_leaf")
            address = self.address(insn, insn.operands[0], registers)
            upper = self.object + self.contract.capacity - 1
            self.obligations.append(
                z3.And(
                    guard, z3.Or(z3.ULT(address, self.object), z3.UGT(address, upper))
                )
            )
            return
        if insn.mnemonic == "bsr":
            edges = self._bit_scan_edges(insn, registers, guard)
        else:
            edges = self.semantics(insn, registers, comparison)
        if not set(node) <= {item[0] for item in edges}:
            raise Rejected("recorded_edge_not_in_binary")
        for successor, state, cmp, condition in edges:
            branch = z3.And(guard, condition)
            if successor not in node:
                self.obligations.append(branch)
                self.omitted += 1
            else:
                self.visit(successor, node[successor], state, cmp, branch, deadline)

    def validate(self, proof, deadline):
        if time.monotonic() >= deadline:
            raise TimeoutError("certificate deadline")
        if (
            type(proof) is not dict
            or set(proof) != {"schema", "query_hash", "binary_sha256", "paths"}
            or proof["schema"] != SCHEMA
            or proof["query_hash"] != self.contract.contract_hash
            or proof["binary_sha256"] != self.contract.binary_sha256
        ):
            raise Rejected("proof_identity")
        paths = proof["paths"]
        entry = self.base + self.contract.entry_rva
        if type(paths) is not list or not 1 <= len(paths) <= MAX_PATHS:
            raise Rejected("path_count_outside_subset")
        trie = {}
        tree_nodes = 1
        seen = set()
        for path in paths:
            if (
                type(path) is not list
                or not 1 <= len(path) <= MAX_STEPS
                or any(type(pc) is not int for pc in path)
                or path[0] != entry
                or path[-1] != self.target
                or tuple(path) in seen
            ):
                raise Rejected("invalid_or_duplicate_path")
            seen.add(tuple(path))
            branch = trie
            for pc in path[1:]:
                # Repeated addresses denote distinct nodes under different prefixes.
                if pc not in branch:
                    tree_nodes += 1
                    if tree_nodes > MAX_TREE_NODES:
                        raise Rejected("certificate_tree_limit")
                    branch[pc] = {}
                branch = branch[pc]
        self.obligations.clear()
        self.omitted = 0
        self.nodes = 0
        self.visit(
            entry, trie, {"rdi": self.argument}, None, z3.BoolVal(True), deadline
        )
        solver = z3.Solver()
        solver.add(self.domain, z3.Or(*self.obligations))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("certificate deadline")
        solver.set(timeout=max(1, int(remaining * 1000)))
        outcome = solver.check()
        if outcome != z3.unsat:
            raise Rejected("proof_obligation_not_discharged:" + str(outcome))
        if time.monotonic() >= deadline:
            raise TimeoutError("certificate deadline")
        if file_hash(Path(self.contract.binary)) != self.contract.binary_sha256:
            raise Rejected("binary_identity_changed")
        return {
            "status": PROVEN,
            "checked_nodes": self.nodes,
            "omitted_edges": self.omitted,
            "obligations": len(self.obligations),
            "solver_checks": 1,
        }
