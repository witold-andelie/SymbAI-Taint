"""Static CFA/load correspondence, without executing or proving a target property.

Only the canonical straight-line AMD64 frame subset declared in v12 is supported.
Origins describe syntactic loads used by an address, not semantic pointer/index roles.
"""

from copy import deepcopy
from dataclasses import asdict
from io import BytesIO
from pathlib import Path

from .contracts import Query, file_hash, fingerprint
from .elf_guard import check_relocation_coverage, UnsupportedELFLayout
from .types import TypeInformationUnavailable, project_type_candidates

REVISION = "static_cfa_load_correspondence_v12"
SCHEMA = "symbai.location_type_bundle.v1"
MAX_INSTRUCTIONS = 64
WINDOW = 4096


class UnavailableCorrespondence(ValueError):
    pass


def _raw_identity(query, raw):
    allowed = {"schema", "binary_sha256", "acquisition_id", "provenance", "measured_export_seconds", "records"}
    if (not isinstance(raw, dict) or set(raw) - allowed or raw.get("schema") != "symbai.tygr_raw.v1"
            or raw.get("binary_sha256") != query.binary_sha256):
        raise ValueError("Raw export schema or binary identity differs")
    provenance = raw.get("provenance", {})
    model = provenance.get("model_sha256")
    if (provenance.get("source") != "tygr_glowgnn" or provenance.get("locator") != "dwarf_assisted"
            or provenance.get("ground_truth_labels_supplied_to_model") is not False
            or not isinstance(model, str) or len(model) != 64
            or any(c not in "0123456789abcdef" for c in model)):
        raise ValueError("Missing genuine raw export provenance")
    records = raw.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("Missing raw prediction records")
    ids = [r.get("prediction_id") if isinstance(r, dict) else None for r in records]
    if any(not isinstance(i, str) or not i for i in ids) or len(ids) != len(set(ids)):
        raise ValueError("Missing or duplicate raw prediction identity")


class _StaticLoads:
    def __init__(self, query):
        import capstone
        from elftools.elf.elffile import ELFFile
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary identity differs")
        elf = ELFFile(BytesIO(Path(query.binary).read_bytes()))
        if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64"
                or elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
            raise UnavailableCorrespondence("unsupported_elf_format")
        loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        if not loads:
            raise UnavailableCorrespondence("missing_load_segments")
        spans = sorted((s["p_vaddr"], s["p_vaddr"] + s["p_memsz"]) for s in loads)
        if any(end > following for (_, end), (following, _) in zip(spans, spans[1:])):
            raise UnavailableCorrespondence("overlapping_load_segments")
        self.base = min(start for start, _ in spans)
        if self.base % 4096 or (elf["e_type"] == "ET_DYN" and self.base != 0):
            raise UnavailableCorrespondence("unsupported_linked_base")
        relocations = [s for s in elf.iter_sections() if s["sh_type"] in ("SHT_REL", "SHT_RELA")]
        if any(s["p_type"] == "PT_DYNAMIC" for s in elf.iter_segments()) and not relocations:
            raise UnavailableCorrespondence("dynamic_relocation_coverage_unavailable")
        check_relocation_coverage(elf, loads, relocations)
        self.segments = [(s["p_vaddr"], s.data()) for s in loads if s["p_flags"] & 1]
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.x86 = capstone.x86_const
        self.query = query
        self.trace = []
        self.origins = {}
        self.registers = {}
        self.loaded_slots = set()
        self.written_slots = set()
        self.allocation = 0

    def decode(self, pc):
        matches = [(start, data) for start, data in self.segments if start <= pc < start + len(data)]
        if len(matches) != 1:
            raise UnavailableCorrespondence("instruction_outside_unique_executable_bytes")
        start, data = matches[0]
        instruction = next(self.decoder.disasm(data[pc - start:pc - start + 15], pc, count=1), None)
        if instruction is None or pc + instruction.size > start + len(data):
            raise UnavailableCorrespondence("instruction_decode_failed")
        if instruction.mnemonic != "endbr64" and any(instruction.prefix):
            raise UnavailableCorrespondence("instruction_prefix_outside_subset")
        return instruction

    def register(self, insn, operand):
        if operand.type != self.x86.X86_OP_REG or operand.size != 8:
            raise UnavailableCorrespondence("partial_or_non_register_operand")
        name = insn.reg_name(operand.reg)
        if name not in {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", *["r" + str(n) for n in range(8, 16)]}:
            raise UnavailableCorrespondence("frame_register_escape_or_overwrite")
        return name

    def reg_value(self, name):
        # Unknown incoming values remain explicitly unlocated; they are never
        # silently erased from a later address dependency.
        return self.registers.get(name, (frozenset(), True))

    @staticmethod
    def union(values):
        return (frozenset().union(*(v[0] for v in values)), any(v[1] for v in values))

    def slot(self, insn, operand):
        mem = operand.mem
        if (operand.type != self.x86.X86_OP_MEM or operand.size != 8 or insn.addr_size != 8
                or mem.segment or mem.index or insn.reg_name(mem.base) != "rbp"
                or mem.disp % 8 or not -WINDOW <= mem.disp <= -8
                or mem.disp < -self.allocation - 128):
            raise UnavailableCorrespondence("partial_or_noncanonical_slot")
        return mem.disp

    def value(self, insn, operand):
        if operand.type == self.x86.X86_OP_IMM:
            return frozenset(), False
        if operand.type == self.x86.X86_OP_REG:
            return self.reg_value(self.register(insn, operand))
        if operand.type == self.x86.X86_OP_MEM:
            slot = self.slot(insn, operand)
            if slot not in self.written_slots:
                raise UnavailableCorrespondence("slot_read_without_local_store")
            self.loaded_slots.add(slot)
            origin = (insn.address, slot)
            occurrence_id = self.query.use_site_id + f":load@{insn.address - self.base:x}:cfa{slot - 16:+d}"
            self.origins[origin] = {"occurrence_id": occurrence_id, "cfa_offset": slot - 16,
                                    "load_rva": insn.address - self.base, "load_address": insn.address,
                                    "use_rva": self.query.write_rva,
                                    "use_address": self.base + self.query.write_rva,
                                    "size_bytes": 8}
            return frozenset((origin,)), False
        raise UnavailableCorrespondence("unsupported_value_operand")

    def address_origins(self, insn, operand):
        mem = operand.mem
        if operand.type != self.x86.X86_OP_MEM or insn.addr_size != 8 or mem.segment:
            raise UnavailableCorrespondence("unsupported_address")
        values = []
        for register in (mem.base, mem.index):
            if not register:
                continue
            name = insn.reg_name(register)
            if name == "rip":
                continue  # Static address syntax, not interpreted as an object fact.
            if name in ("rbp", "rsp"):
                raise UnavailableCorrespondence("frame_address_escape_or_target")
            # Capstone supplies address registers; require full 64-bit names.
            if name not in {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", *["r" + str(n) for n in range(8, 16)]}:
                raise UnavailableCorrespondence("non64_address_register")
            values.append(self.reg_value(name))
        return self.union(values)

    def walk(self):
        pc, phase, allocation_open = self.base + self.query.entry_rva, "entry", False
        while len(self.trace) < MAX_INSTRUCTIONS:
            insn = self.decode(pc)
            self.trace.append({"rva": pc - self.base, "address": pc, "bytes": bytes(insn.bytes).hex(),
                               "mnemonic": insn.mnemonic, "operands": insn.op_str})
            ops, mnemonic = insn.operands, insn.mnemonic
            if pc == self.base + self.query.write_rva:
                if (phase != "body" or mnemonic != "mov" or len(ops) != 2
                        or ops[0].type != self.x86.X86_OP_MEM or ops[0].size != 1
                        or ops[1].type not in (self.x86.X86_OP_IMM, self.x86.X86_OP_REG)):
                    raise UnavailableCorrespondence("target_not_supported_byte_store")
                origins, unknown = self.address_origins(insn, ops[0])
                if unknown or not origins:
                    raise UnavailableCorrespondence("missing_address_load_origins")
                return [self.origins[o] for o in sorted(origins)]
            if mnemonic in ("nop", "endbr64"):
                if insn.op_str:
                    raise UnavailableCorrespondence("nontrivial_nop_outside_subset")
                pc += insn.size
                continue
            if phase == "entry":
                if mnemonic != "push" or insn.op_str != "rbp":
                    raise UnavailableCorrespondence("canonical_push_rbp_required")
                phase = "pushed"
            elif phase == "pushed":
                if mnemonic != "mov" or insn.op_str != "rbp, rsp":
                    raise UnavailableCorrespondence("canonical_mov_rbp_rsp_required")
                phase, allocation_open = "body", True
            elif (allocation_open and mnemonic == "sub" and len(ops) == 2
                  and insn.reg_name(ops[0].reg) == "rsp" and ops[1].type == self.x86.X86_OP_IMM):
                if ops[0].type != self.x86.X86_OP_REG or ops[0].size != 8 or not 0 < ops[1].imm <= WINDOW or ops[1].imm % 8:
                    raise UnavailableCorrespondence("unsupported_stack_allocation")
                self.allocation, allocation_open = ops[1].imm, False
            else:
                allocation_open = False
                if mnemonic == "mov" and len(ops) == 2:
                    if ops[0].type == self.x86.X86_OP_MEM:
                        slot = self.slot(insn, ops[0])
                        if slot in self.loaded_slots:
                            raise UnavailableCorrespondence("slot_changed_after_origin_load")
                        if ops[1].type == self.x86.X86_OP_REG:
                            self.register(insn, ops[1])
                        elif ops[1].type != self.x86.X86_OP_IMM:
                            raise UnavailableCorrespondence("unsupported_slot_store")
                        self.written_slots.add(slot)
                    else:
                        self.registers[self.register(insn, ops[0])] = self.value(insn, ops[1])
                elif mnemonic == "lea" and len(ops) == 2:
                    self.registers[self.register(insn, ops[0])] = self.address_origins(insn, ops[1])
                elif mnemonic in ("add", "sub", "and", "or", "xor") and len(ops) == 2:
                    if ops[0].type == self.x86.X86_OP_MEM:
                        slot = self.slot(insn, ops[0])
                        if slot in self.loaded_slots or slot not in self.written_slots or ops[1].type != self.x86.X86_OP_IMM:
                            raise UnavailableCorrespondence("ambiguous_slot_update")
                    else:
                        name = self.register(insn, ops[0])
                        right = self.value(insn, ops[1])
                        if mnemonic == "xor" and ops[1].type == self.x86.X86_OP_REG and ops[0].reg == ops[1].reg:
                            self.registers[name] = frozenset(), False
                        else:
                            self.registers[name] = self.union((self.reg_value(name), right))
                else:
                    raise UnavailableCorrespondence("unsupported_instruction:" + mnemonic)
            pc += insn.size
            if pc > self.base + self.query.write_rva:
                raise UnavailableCorrespondence("target_not_on_static_instruction_boundary")
        raise UnavailableCorrespondence("static_instruction_cap")


def _associate(raw, occurrences, entry_address):
    bindings = []
    for occurrence in occurrences:
        matches = []
        for record in raw["records"]:
            if record.get("function_address") != entry_address:
                continue
            for location in record.get("locations", []):
                if (location.get("location_class") != "CfaLocation"
                        or type(location.get("location_value")) is not int
                        or location["location_value"] != occurrence["cfa_offset"]):
                    continue
                low, high = location.get("low_pc"), location.get("high_pc")
                if (type(low) is not int or type(high) is not int or not low < high
                        or location.get("location_register") is not None
                        or location.get("location_argument") != location["location_value"]):
                    continue
                if all(low <= occurrence[key] < high for key in ("load_address", "use_address")):
                    matches.append(record["prediction_id"])
        if len(matches) != 1:
            raise UnavailableCorrespondence("missing_or_ambiguous_raw_location")
        bindings.append({**occurrence, "prediction_id": matches[0]})
    return bindings


def build_location_bundle(query, raw):
    """Bind raw locations to syntactic load occurrences; no property check occurs."""
    _raw_identity(query, raw)
    bundle = {"schema": SCHEMA, "revision": REVISION, "semantics": "location_correspondence_only",
              "property_verification_performed": False, "query": asdict(query),
              "query_hash": query.contract_hash, "binary_sha256": query.binary_sha256,
              "use_site_id": query.use_site_id, "model_sha256": raw["provenance"]["model_sha256"],
              "raw_export": deepcopy(raw), "raw_payload_fingerprint": fingerprint(raw),
              "status": "unavailable", "reason": None, "static_trace": [], "occurrences": [], "bindings": []}
    walker = None
    try:
        walker = _StaticLoads(query)
        occurrences = walker.walk()
        bindings = _associate(raw, occurrences, walker.base + query.entry_rva)
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary changed during static correspondence")
        bundle.update(status="available", occurrences=occurrences, bindings=bindings,
                      linked_base=walker.base, cfa_convention="canonical_rbp_plus_16")
    except (UnavailableCorrespondence, UnsupportedELFLayout) as exc:
        bundle["reason"] = str(exc)
    if walker is not None:
        bundle["static_trace"] = walker.trace
    bundle["bundle_fingerprint"] = fingerprint(bundle)
    return bundle


def project_location_views(bundle, group):
    """Keep predictions independent, with a fresh static identity recheck for C/D."""
    if group not in ("A", "B", "C", "D") or bundle.get("schema") != SCHEMA:
        raise TypeInformationUnavailable("Unsupported location projection")
    if group in ("A", "B"):
        return {}
    payload = {k: v for k, v in bundle.items() if k != "bundle_fingerprint"}
    if bundle.get("bundle_fingerprint") != fingerprint(payload) or bundle.get("status") != "available":
        raise TypeInformationUnavailable("Unavailable or changed location bundle")
    try:
        query = Query.from_dict(bundle["query"])
        checked = build_location_bundle(query, bundle["raw_export"])
        if checked != bundle:
            raise ValueError("Static correspondence recheck differs")
        records = {r["prediction_id"]: r for r in bundle["raw_export"]["records"]}
        return {binding["occurrence_id"]: project_type_candidates(
                    records[binding["prediction_id"]].get("candidates", []),
                    records[binding["prediction_id"]].get("score_kind"), group,
                    "tygr_glowgnn", bundle["raw_payload_fingerprint"], bundle["model_sha256"])
                for binding in bundle["bindings"]}
    except (KeyError, ValueError, OSError) as exc:
        raise TypeInformationUnavailable(str(exc)) from exc
