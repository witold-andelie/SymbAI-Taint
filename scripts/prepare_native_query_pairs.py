#!/usr/bin/env python3
"""Build code-identical native debug/stripped query pairs from a frozen manifest."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
WORKSPACE = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def within(path, root):
    path = Path(path).resolve()
    if not path.is_relative_to(Path(root).resolve()):
        raise ValueError(f"Path leaves the allowed workspace: {path}")
    return path


def load_manifest(path):
    path = within(path, WORKSPACE)
    manifest = json.loads(path.read_bytes())
    if manifest.get("schema") != "symbai.native_pair_sources.v1":
        raise ValueError("Unsupported native-pair source manifest")
    if manifest.get("native_builder_sha256") != digest(__file__):
        raise ValueError("Native builder differs from the frozen source manifest")
    if len({case["case_id"] for case in manifest["cases"]}) != len(manifest["cases"]):
        raise ValueError("Duplicate case identifiers")
    for case in manifest["cases"]:
        for name in ("source", "reference"):
            target = within(path.parent / case[name], path.parent)
            if digest(target) != case[name + "_sha256"]:
                raise ValueError(f"Frozen {name} differs: {case['case_id']}")
    return path, manifest


def image(path):
    from elftools.elf.elffile import ELFFile
    with Path(path).open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
            raise ValueError("Expected a little-endian AMD64 ELF")
        allocated = {}
        for section in elf.iter_sections():
            if int(section["sh_flags"]) & 2:
                allocated[section.name] = {
                    "address": int(section["sh_addr"]), "size": int(section["sh_size"]),
                    "flags": int(section["sh_flags"]), "type": section["sh_type"],
                    "sha256": hashlib.sha256(section.data()).hexdigest()
                    if section["sh_type"] != "SHT_NOBITS" else None,
                }
        segments = [(int(s["p_vaddr"]), int(s["p_memsz"]), int(s["p_flags"]))
                    for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        return {"machine": elf["e_machine"], "entry": int(elf["e_entry"]),
                "allocated_sections": allocated, "load_geometry": segments,
                "debug_info": elf.get_section_by_name(".debug_info") is not None,
                "symbol_table": elf.get_section_by_name(".symtab") is not None}


def compare_pair(debug, stripped):
    a, b = image(debug), image(stripped)
    if not a["debug_info"] or b["debug_info"] or b["symbol_table"]:
        raise ValueError("Expected debug metadata on one side and fully stripped metadata on its twin")
    for name in ("machine", "entry", "allocated_sections", "load_geometry"):
        if a[name] != b[name]:
            raise ValueError(f"Program identity differs: {name}")
    if ".text" not in a["allocated_sections"]:
        raise ValueError("Executable text is missing")
    return {"program_code_and_data_identical": True, "instruction_addresses_identical": True,
            "debug_sha256": digest(debug), "stripped_sha256": digest(stripped),
            "debug_metadata_present": True, "stripped_debug_and_symtab_absent": True,
            "allocated_sections": a["allocated_sections"], "load_geometry": a["load_geometry"]}


def attribute(die, name):
    for _ in range(8):
        if name in die.attributes:
            return die.attributes[name]
        parent = "DW_AT_abstract_origin" if "DW_AT_abstract_origin" in die.attributes else "DW_AT_specification"
        if parent not in die.attributes:
            return None
        die = die.get_DIE_from_attribute(parent)
    return None


def argument_binding(elf, entry, instructions, parameter_name="x"):
    from elftools.dwarf.locationlists import LocationParser
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    dwarf = elf.get_dwarf_info()
    ranges = []
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            low = die.attributes.get("DW_AT_low_pc")
            if die.tag != "DW_TAG_subprogram" or low is None or low.value != entry:
                continue
            for param in die.iter_children():
                name = attribute(param, "DW_AT_name")
                if param.tag != "DW_TAG_formal_parameter" or name is None or name.value != parameter_name.encode("utf-8"):
                    continue
                location = attribute(param, "DW_AT_location")
                if location is None:
                    continue
                parser = LocationParser(dwarf.location_lists())
                options = {"die": param} if "die" in inspect.signature(parser.parse_from_attribute).parameters else {}
                parsed = parser.parse_from_attribute(location, cu["version"], **options)
                if hasattr(parsed, "loc_expr"):
                    records = [(entry, None, parsed.loc_expr)]
                else:
                    base = cu.get_top_DIE().attributes.get("DW_AT_low_pc")
                    base = base.value if base is not None else 0
                    records = []
                    for item in parsed:
                        if hasattr(item, "base_address"):
                            base = item.base_address
                        elif hasattr(item, "loc_expr"):
                            offset = 0 if getattr(item, "is_absolute", False) else base
                            records.append((offset + item.begin_offset, offset + item.end_offset, item.loc_expr))
                for low_pc, high_pc, expression in records:
                    ops = DWARFExprParser(dwarf.structs).parse_expr(expression)
                    ranges.append({"low_pc": low_pc, "high_pc": high_pc,
                                   "operations": [op.op_name for op in ops],
                                   "expression_hex": bytes(expression).hex()})
    first_read = None
    for insn in instructions:
        reads, writes = insn.regs_access()
        aliases = {"rdi", "edi", "di", "dil"}
        if {insn.reg_name(reg) for reg in reads} & aliases:
            first_read = {"address": insn.address, "instruction": insn.mnemonic + " " + insn.op_str,
                          "bytes": bytes(insn.bytes).hex()}
            break
        if {insn.reg_name(reg) for reg in writes} & aliases:
            break
    matched = [r for r in ranges if first_read is not None and r["low_pc"] <= first_read["address"]
               and (r["high_pc"] is None or first_read["address"] < r["high_pc"])
               and r["operations"] == ["DW_OP_reg5"]]
    return {"status": "verified" if matched else "unavailable", "parameter": parameter_name, "abi_register": "rdi",
            "first_read": first_read, "location_ranges": ranges,
            "reference_type_attributes_read": False,
            "scope": "Entry argument and first architectural register read only; full def-use and property mapping are not established."}


def describe_query(debug, stripped, template):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
    from elftools.elf.elffile import ELFFile
    with Path(debug).open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        entry, = symbols.get_symbol_by_name("benchmark_step")
        obj, = symbols.get_symbol_by_name("evaluation_output")
        address, size = int(entry["st_value"]), int(entry["st_size"])
        segment, = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                     and int(s["p_vaddr"]) <= address < int(s["p_vaddr"]) + int(s["p_filesz"])]
        start = address - int(segment["p_vaddr"])
        code = segment.data()[start:start+size]
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(code, address))
        writes = [i for i in instructions if i.mnemonic == "mov" and len(i.operands) == 2
                  and i.operands[0].type == x86_const.X86_OP_MEM and i.operands[0].size == 1
                  and i.operands[1].type == x86_const.X86_OP_IMM and i.operands[1].imm == 0x41]
        if len(writes) != 1 or int(obj["st_size"]) != template["capacity"]:
            raise ValueError("Marker-write or object-size extraction is ambiguous")
        base = min(int(s["p_vaddr"]) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
        query = dict(template, binary=str(stripped), binary_sha256=digest(stripped),
                     entry_rva=address-base, write_rva=writes[0].address-base,
                     object_rva=int(obj["st_value"])-base)
        binding = argument_binding(elf, address, instructions)
        return query, binding


def build(manifest_path, manifest, output):
    if sys.platform != "linux":
        raise RuntimeError("Native execution checks require Linux; run this command in the existing WSL environment")
    output = within(output, WORKSPACE)
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / "tmp"
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary), PYTHONDONTWRITEBYTECODE="1")
    tools = {name: shutil.which(name) for name in ("gcc", "strip")}
    if not all(tools.values()):
        raise RuntimeError(f"Existing compiler or strip tool missing: {tools}")
    flags = ["-std=gnu11", "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pie", "-no-pie"]
    write(output / "plan.json", {"schema": "symbai.native_pair_build.v1", "manifest_sha256": digest(manifest_path),
          "script_sha256": digest(__file__), "flags": flags, "debug_flags": ["-g", "-gdwarf-4"],
          "tools": tools, "python": platform.python_version(),
          "parser_versions": {name: importlib.metadata.version(name) for name in ("pyelftools", "capstone")},
          "versions": {name: subprocess.check_output([path, "--version"], text=True).splitlines()[0] for name, path in tools.items()},
          "scope": "Code/data-identical pairs, native output equivalence and entry-argument binding. No neural inference or baseline timing."})
    results = []
    def run(stage, command):
        log = output / (stage + ".log")
        with log.open("w", encoding="utf-8") as stream:
            subprocess.run([str(arg) for arg in command], cwd=output, env=environment,
                           stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90)
        return log.read_text(encoding="utf-8")
    for case in manifest["cases"]:
        name = case["case_id"]
        native = output / (name + ".native")
        try:
            source = manifest_path.parent / case["source"]
            expected = json.loads((manifest_path.parent / case["reference"]).read_bytes())
            run(name + "-native-build", [tools["gcc"], *flags, "-DCHECK_NATIVE", source, "-o", native])
            values = [int(line) for line in run(name + "-native-values", [native]).splitlines()]
            if values != expected["indices"]:
                raise ValueError("Native values differ from the frozen independent reference")
            debug, stripped = output / (name + ".debug.elf"), output / (name + ".stripped.elf")
            run(name + "-debug-build", [tools["gcc"], *flags, "-g", "-gdwarf-4", "-nostdlib",
                "-Wl,-e,benchmark_step", "-Wl,--build-id=none", source, "-o", debug])
            run(name + "-strip", [tools["strip"], "--strip-all", "-o", stripped, debug])
            identity = compare_pair(debug, stripped)
            query, binding = describe_query(debug, stripped, case["query_template"])
            record = {"case_id": name, "status": "verified", "native_inputs_checked": len(values),
                      "identity": identity, "query": query, "entry_argument_binding": binding}
            write(output / (name + ".json"), record)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record = {"case_id": name, "status": "failed", "reason": f"{type(error).__name__}: {error}"}
        finally:
            native.unlink(missing_ok=True)
        results.append(record)
        write(output / "records.json", results)
        print(name + ": " + record["status"], flush=True)
    load_manifest(manifest_path)
    if not any(temporary.iterdir()):
        temporary.rmdir()
    summary = {"schema": "symbai.native_pair_summary.v1", "planned_cases": len(manifest["cases"]),
        "verified_pairs": sum(r["status"] == "verified" for r in results),
        "entry_argument_bindings_verified": sum(r.get("entry_argument_binding", {}).get("status") == "verified" for r in results),
        "failed_cases": [r for r in results if r["status"] != "verified"],
        "model_inference_performed": False, "full_use_site_mapping_validated": False,
        "baseline_timing_performed": False, "source_integrity_unchanged": True, "output": str(output)}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    return not summary["failed_cases"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-manifest", action="store_true")
    args = parser.parse_args()
    path, manifest = load_manifest(args.manifest)
    if args.check_manifest:
        print(f"Verified {len(manifest['cases'])} frozen source/reference pairs; no compiler or model invoked.")
        return
    output = args.output or path.parent / ("native-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    if not build(path, manifest, output):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
