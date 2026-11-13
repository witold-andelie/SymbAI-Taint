"""Fixed small compiled readiness panel; no selector or neural assumptions."""

from dataclasses import asdict
from io import BytesIO
from pathlib import Path

from .contracts import Query, InputRange, file_hash

CASE_IDS = ("typed_scalar_span", "typed_readonly_table", "typed_readonly_table_outside")
METHODS = {"interval_only": ("interval",), "finite_readonly_only": ("finite_readonly",),
           "expanded_only": ("expanded",), "fixed_cascade": ("interval", "finite_readonly", "expanded")}


def validate_specs(specs):
    if (not isinstance(specs, dict) or set(specs) != {"schema", "cases"}
            or specs["schema"] != "symbai.typed_complementarity_specs.v1"
            or not isinstance(specs["cases"], list) or len(specs["cases"]) != 3):
        raise ValueError("Expected the fixed three-case specification")
    for index, case in enumerate(specs["cases"]):
        expected = {"case_id": CASE_IDS[index], "function_symbol": CASE_IDS[index],
            "object_symbol": ("scalar_output", "table_output", "outside_output")[index],
            "capacity": 1024 if index == 0 else 8,
            "input": {"register": "rdi", "minimum": 0, "maximum": 1023 if index == 0 else 15}}
        if case != expected or type(case.get("capacity")) is not int:
            raise ValueError("Case scope differs or unexpected runtime labels/features were supplied")
        if any(type(case["input"][key]) is not int for key in ("minimum", "maximum")):
            raise ValueError("Integer entry-input bounds required")
    return specs["cases"]


def extract_typed_queries(binary, specs):
    """Extract fixed symbol identities and unique byte stores, without a property engine."""
    import capstone
    from elftools.elf.elffile import ELFFile
    cases = validate_specs(specs)
    binary = Path(binary).resolve()
    data = binary.read_bytes()
    elf = ELFFile(BytesIO(data))
    if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
            or elf["e_type"] != "ET_DYN"
            or any(elf.get_section_by_name(name) is None or not elf.get_section_by_name(name).data()
                   for name in (".debug_info", ".debug_abbrev"))):
        raise ValueError("Expected an AMD64 PIE ELF with DWARF")
    loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
    if not loads or min(segment["p_vaddr"] for segment in loads) != 0:
        raise ValueError("Expected zero linked PIE base")
    symbols = elf.get_section_by_name(".symtab")
    if symbols is None:
        raise ValueError("Missing full symbol table")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    queries, metadata = [], []
    for case in cases:
        functions = symbols.get_symbol_by_name(case["function_symbol"]) or []
        objects = symbols.get_symbol_by_name(case["object_symbol"]) or []
        if len(functions) != 1 or len(objects) != 1:
            raise ValueError("Missing or ambiguous function/object symbols")
        function, obj = functions[0], objects[0]
        address, size = int(function["st_value"]), int(function["st_size"])
        if (function["st_shndx"] == "SHN_UNDEF" or obj["st_shndx"] == "SHN_UNDEF"
                or function["st_info"]["type"] != "STT_FUNC" or not 0 < size <= 4096
                or obj["st_info"]["type"] != "STT_OBJECT" or obj["st_size"] != case["capacity"]):
            raise ValueError("Function/object type, size or declared capacity differs")
        object_spans = [segment for segment in loads if segment["p_flags"] & 2
            and segment["p_vaddr"] <= obj["st_value"]
            and obj["st_value"] + case["capacity"] <= segment["p_vaddr"] + segment["p_memsz"]]
        if len(object_spans) != 1:
            raise ValueError("Declared object is not uniquely writable/mapped")
        spans = [segment for segment in loads if segment["p_flags"] & 1
                 and segment["p_vaddr"] <= address and address + size <= segment["p_vaddr"] + segment["p_filesz"]]
        if len(spans) != 1:
            raise ValueError("Function bytes not uniquely executable/file-backed")
        segment, = spans
        start = address - segment["p_vaddr"]
        code = segment.data()[start:start + size]
        instructions = list(decoder.disasm(code, address))
        if sum(insn.size for insn in instructions) != size:
            raise ValueError("Function disassembly incomplete")
        stores = [insn for insn in instructions if insn.mnemonic == "mov" and len(insn.operands) == 2
            and insn.operands[0].type == capstone.x86_const.X86_OP_MEM and insn.operands[0].size == 1
            and insn.operands[1].type == capstone.x86_const.X86_OP_IMM and insn.operands[1].imm == 0x41]
        if len(stores) != 1:
            raise ValueError("Expected one constant byte store per declared function")
        query = Query(case["case_id"], str(binary), file_hash(binary), address, stores[0].address,
                      int(obj["st_value"]), case["capacity"], (InputRange(**case["input"]),))
        queries.append(asdict(query))
        metadata.append({"case_id": case["case_id"], "linked_base": 0, "function_address": address,
            "function_size": size, "object_address": int(obj["st_value"]), "write_rva": stores[0].address,
            "disassembly": [{"rva": insn.address, "bytes": bytes(insn.bytes).hex(), "mnemonic": insn.mnemonic,
                             "operands": insn.op_str} for insn in instructions]})
    if file_hash(binary) != queries[0]["binary_sha256"]:
        raise ValueError("Binary changed during extraction")
    return {"schema": "symbai.typed_complementarity_queries.v1", "queries": queries, "metadata": metadata}
