"""Label-free static structural features for Route B v4 arm L.

Reads only fixture bytes and the query contract. Capstone disassembly plus
the ELF program headers are the only inputs; no labels, outcomes, references,
solvers or timings.
"""

from __future__ import annotations

from collections import OrderedDict
from io import BytesIO
import math
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


FEATURE_SCHEMA = "symbai.route_b_structural_features.v1"
MAX_INSTRUCTIONS = 20000
MAX_CALL_DEPTH = 8

FEATURE_NAMES = (
    "instruction_count",
    "basic_block_count",
    "conditional_branch_count",
    "unconditional_branch_count",
    "back_edge_count",
    "direct_call_count",
    "indirect_call_count",
    "distinct_callee_count",
    "ret_count",
    "stack_load_count",
    "stack_store_count",
    "rip_load_count",
    "rip_store_count",
    "other_load_count",
    "other_store_count",
    "multiply_count",
    "divide_count",
    "shift_count",
    "bit_test_scan_count",
    "compare_count",
    "test_count",
    "store_has_base",
    "store_has_index",
    "store_scale",
    "store_disp_magnitude",
    "store_index_masked",
    "domain_size",
    "log2_domain_size",
    "capacity",
    "log2_capacity",
    "input_register_count",
    "truncated",
    "indirect_transfer_seen",
    "store_site_found",
)

_MUL = frozenset(("mul", "imul"))
_DIV = frozenset(("div", "idiv"))
_SHIFT = frozenset(("shl", "shr", "sar", "sal", "shld", "shrd"))
_BIT = frozenset(("bt", "bts", "btr", "btc", "bsf", "bsr", "tzcnt", "lzcnt"))
_NO_FALL = frozenset(("jmp", "ret", "retf", "iret", "iretd", "iretq", "hlt", "ud2"))
_NOT_MEM = frozenset(("lea", "nop", "endbr64"))
_REG64 = {
    "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
    "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
    "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
    "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
    "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
    "ip": "rip", "eip": "rip", "rip": "rip",
}


def feature_names():
    return list(FEATURE_NAMES)


def feature_vector(features):
    return [float(features[name]) for name in FEATURE_NAMES]


def extract_features(query, elf_bytes=None):
    """Return the v1 structural feature dict for one query.

    elf_bytes supplies the fixture image. When omitted the bytes are read
    from query.binary. No other path is opened.
    """
    if elf_bytes is None:
        try:
            elf_bytes = Path(query.binary).read_bytes()
        except OSError as exc:
            raise ValueError("Malformed ELF") from exc
    image = _Image(elf_bytes)
    entry = image.base + int(query.entry_rva)
    write = image.base + int(query.write_rva)
    if image.span(entry) is None or image.span(write) is None:
        raise ValueError("RVA outside executable segment")
    recovered = _recover(image, entry)
    counts = _count_instructions(recovered["insns"])
    counts["basic_block_count"] = _basic_blocks(recovered["functions"])
    counts["back_edge_count"] = _back_edges(recovered["functions"])
    counts["direct_call_count"] = recovered["direct_calls"]
    counts["indirect_call_count"] = recovered["indirect_calls"]
    counts["distinct_callee_count"] = len(recovered["callees"])
    counts.update(_store_site(image, write, recovered))
    counts.update(_contract_features(query))
    counts["truncated"] = bool(recovered["truncated"])
    counts["indirect_transfer_seen"] = bool(recovered["indirect_transfers"])
    return _pack(counts)


class _Image(object):
    def __init__(self, data):
        try:
            elf = ELFFile(BytesIO(data))
        except Exception as exc:
            raise ValueError("Malformed ELF") from exc
        if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
                or elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
            raise ValueError("Malformed ELF")
        loads = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
        if not loads:
            raise ValueError("Malformed ELF")
        linked = min(seg["p_vaddr"] for seg in loads) & ~0xFFF
        self.base = 0x400000 if elf["e_type"] == "ET_DYN" else linked
        bias = self.base - linked
        self.exec_spans = []
        for seg in loads:
            if not (seg["p_flags"] & 1):
                continue
            blob = bytes(seg.data())
            if not blob:
                continue
            self.exec_spans.append((seg["p_vaddr"] + bias, blob))
        if not self.exec_spans:
            raise ValueError("Malformed ELF")
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.x86 = capstone.x86_const

    def span(self, va):
        hits = [(start, blob) for start, blob in self.exec_spans
                if start <= va < start + len(blob)]
        if len(hits) != 1:
            return None
        return hits[0]

    def decode(self, va):
        hit = self.span(va)
        if hit is None:
            return None
        start, blob = hit
        offset = va - start
        insn = next(self.decoder.disasm(blob[offset:offset + 15], va, count=1), None)
        if insn is None or insn.address != va or insn.size < 1:
            return None
        if offset + insn.size > len(blob):
            return None
        return insn


def _canon(name):
    if not name:
        return None
    name = name.lower()
    if name in _REG64:
        return _REG64[name]
    if len(name) >= 2 and name[0] == "r" and name[1].isdigit():
        body = name[1:]
        if body.endswith(("b", "w", "d")) and body[:-1].isdigit():
            return "r" + body[:-1]
        if body.isdigit():
            return "r" + body
    return name


def _is_call(insn):
    return insn.mnemonic == "call" or insn.group(capstone.CS_GRP_CALL)


def _is_ret(insn):
    return insn.mnemonic in ("ret", "retf", "iret", "iretd", "iretq") or insn.group(capstone.CS_GRP_RET)


def _is_cond(insn):
    name = insn.mnemonic
    if name in ("jmp", "call") or name.startswith("ret") or name.startswith("iret"):
        return False
    if name.startswith("loop") or name in ("jcxz", "jecxz", "jrcxz"):
        return True
    return name.startswith("j") and insn.group(capstone.CS_GRP_JUMP)


def _direct_target(insn):
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == capstone.x86_const.X86_OP_IMM:
        return int(op.imm)
    return None


def _mem_kind(insn, op):
    base = _canon(insn.reg_name(op.mem.base) if op.mem.base else None)
    if base == "rip":
        return "rip"
    if base in ("rbp", "rsp"):
        return "stack"
    return "other"


def _recover(image, entry):
    insns = {}
    functions = OrderedDict()
    callees = OrderedDict()
    direct_calls = 0
    indirect_calls = 0
    indirect_transfers = False
    truncated = False
    pending_funcs = [(entry, 0)]
    queued = {entry: 0}

    def budget():
        return len(insns) >= MAX_INSTRUCTIONS

    while pending_funcs:
        func_entry, depth = pending_funcs.pop()
        if func_entry in functions:
            continue
        if depth > MAX_CALL_DEPTH:
            truncated = True
            continue
        if budget():
            truncated = True
            break
        work = [func_entry]
        seen = set()
        body = OrderedDict()
        while work:
            va = work.pop()
            if va in seen:
                continue
            seen.add(va)
            insn = image.decode(va)
            if insn is None:
                continue
            if va not in insns and budget():
                truncated = True
                break
            insns[va] = insn
            body[va] = insn
            name = insn.mnemonic
            if _is_ret(insn):
                continue
            if _is_call(insn):
                target = _direct_target(insn)
                if target is None:
                    indirect_calls += 1
                    indirect_transfers = True
                else:
                    direct_calls += 1
                    callees[target] = True
                    if image.span(target) is not None:
                        prev = queued.get(target)
                        if prev is None or depth + 1 < prev:
                            queued[target] = depth + 1
                            pending_funcs.append((target, depth + 1))
                fall = va + insn.size
                if image.span(fall) is not None:
                    work.append(fall)
                continue
            if name == "jmp" or _is_cond(insn):
                target = _direct_target(insn)
                if target is None:
                    indirect_transfers = True
                else:
                    if image.span(target) is not None:
                        work.append(target)
                if name != "jmp":
                    fall = va + insn.size
                    if image.span(fall) is not None:
                        work.append(fall)
                continue
            if name not in _NO_FALL:
                fall = va + insn.size
                if image.span(fall) is not None:
                    work.append(fall)
        functions[func_entry] = body
        if truncated and budget():
            break

    return {
        "insns": insns,
        "functions": functions,
        "callees": callees,
        "direct_calls": direct_calls,
        "indirect_calls": indirect_calls,
        "indirect_transfers": indirect_transfers,
        "truncated": truncated,
    }


def _count_instructions(insns):
    counts = {name: 0 for name in FEATURE_NAMES}
    x86 = capstone.x86_const
    for insn in insns.values():
        counts["instruction_count"] += 1
        name = insn.mnemonic
        if _is_cond(insn):
            counts["conditional_branch_count"] += 1
        elif name == "jmp":
            counts["unconditional_branch_count"] += 1
        if _is_ret(insn):
            counts["ret_count"] += 1
        if name in _MUL:
            counts["multiply_count"] += 1
        if name in _DIV:
            counts["divide_count"] += 1
        if name in _SHIFT:
            counts["shift_count"] += 1
        if name in _BIT:
            counts["bit_test_scan_count"] += 1
        if name == "cmp":
            counts["compare_count"] += 1
        if name == "test":
            counts["test_count"] += 1
        if name == "push":
            counts["stack_store_count"] += 1
        elif name == "pop":
            counts["stack_load_count"] += 1
        if name in _NOT_MEM or name.startswith("prefetch"):
            continue
        for op in insn.operands:
            if op.type != x86.X86_OP_MEM:
                continue
            kind = _mem_kind(insn, op)
            if op.access & capstone.CS_AC_READ:
                counts[kind + "_load_count"] += 1
            if op.access & capstone.CS_AC_WRITE:
                counts[kind + "_store_count"] += 1
    return counts


def _basic_blocks(functions):
    total = 0
    for func_entry, body in functions.items():
        if not body:
            continue
        addrs = set(body)
        leaders = set()
        if func_entry in body:
            leaders.add(func_entry)
        else:
            leaders.add(min(body))
        for va, insn in body.items():
            name = insn.mnemonic
            control = name == "jmp" or _is_cond(insn) or _is_call(insn) or _is_ret(insn)
            if not control:
                continue
            target = _direct_target(insn)
            if target is not None and target in addrs:
                leaders.add(target)
            fall = va + insn.size
            if name != "jmp" and not _is_ret(insn) and fall in addrs:
                leaders.add(fall)
        visited = set()
        for leader in sorted(leaders):
            if leader not in body or leader in visited:
                continue
            total += 1
            va = leader
            while va in body:
                visited.add(va)
                insn = body[va]
                name = insn.mnemonic
                if name == "jmp" or _is_cond(insn) or _is_call(insn) or _is_ret(insn):
                    break
                nxt = va + insn.size
                if nxt in leaders:
                    break
                va = nxt
    return total


def _back_edges(functions):
    total = 0
    for body in functions.values():
        addrs = set(body)
        for va, insn in body.items():
            if insn.mnemonic != "jmp" and not _is_cond(insn):
                continue
            target = _direct_target(insn)
            if target is not None and target in addrs and target <= va:
                total += 1
    return total


def _writes_mask(insn, index_name):
    if insn.mnemonic not in ("movzx", "and") or len(insn.operands) < 2:
        return False
    dest, src = insn.operands[0], insn.operands[1]
    if dest.type != capstone.x86_const.X86_OP_REG:
        return False
    if _canon(insn.reg_name(dest.reg)) != index_name:
        return False
    if insn.mnemonic == "and":
        return src.type == capstone.x86_const.X86_OP_IMM
    return True


def _store_site(image, write, recovered):
    x86 = image.x86
    result = {
        "store_has_base": 0,
        "store_has_index": 0,
        "store_scale": 0,
        "store_disp_magnitude": 0,
        "store_index_masked": 0,
        "store_site_found": False,
    }
    insn = recovered["insns"].get(write) or image.decode(write)
    if insn is None:
        return result
    mem = None
    for op in insn.operands:
        if op.type == x86.X86_OP_MEM and (op.access & capstone.CS_AC_WRITE):
            mem = op
            break
    if mem is None or insn.mnemonic in _NOT_MEM:
        return result
    result["store_site_found"] = True
    memop = mem.mem
    result["store_has_base"] = 1 if memop.base else 0
    result["store_has_index"] = 1 if memop.index else 0
    result["store_scale"] = int(memop.scale)
    result["store_disp_magnitude"] = abs(int(memop.disp))
    if not memop.index:
        return result
    index_name = _canon(insn.reg_name(memop.index))
    previous = []
    for body in recovered["functions"].values():
        if write in body:
            previous = [body[addr] for addr in sorted(addr for addr in body if addr < write)][-8:]
            break
    if not previous:
        previous = [recovered["insns"][addr]
                    for addr in sorted(addr for addr in recovered["insns"] if addr < write)][-8:]
    result["store_index_masked"] = int(any(_writes_mask(prev, index_name) for prev in previous))
    return result


def _contract_features(query):
    domain = 1
    for item in query.inputs:
        domain *= (item.maximum - item.minimum + 1)
    capacity = int(query.capacity)
    return {
        "domain_size": int(domain),
        "log2_domain_size": float(math.log2(domain)) if domain > 0 else 0.0,
        "capacity": capacity,
        "log2_capacity": float(math.log2(capacity)) if capacity > 0 else 0.0,
        "input_register_count": len(query.inputs),
    }


def _pack(counts):
    packed = OrderedDict()
    packed["schema"] = FEATURE_SCHEMA
    for name in FEATURE_NAMES:
        packed[name] = counts[name]
    return packed
