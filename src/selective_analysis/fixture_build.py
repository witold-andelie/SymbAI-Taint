"""Native-only Route B fixture construction. No runtime reference reader lives here."""

from dataclasses import asdict
import json
from pathlib import Path
import struct
import subprocess

from .contracts import InputRange, Query, file_hash


BASE = 0x400000
FLAGS = ("-std=gnu11", "-O1", "-ffreestanding", "-fno-builtin",
         "-fno-stack-protector")


class FixtureBuildError(RuntimeError):
    def __init__(self, stage, error):
        self.stage = stage
        super().__init__("%s: %s" % (stage, error))


def write_text(path, value):
    """All generated text is ASCII with LF, including on Windows."""
    with open(str(path), "w", encoding="ascii", newline="\n") as stream:
        stream.write(value)


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def cmd(args, output, log=None, log_stdout=True):
    result = subprocess.run([str(a) for a in args], cwd=str(output),
                            capture_output=True, text=True, timeout=40)
    if log is not None:
        with open(str(log), "a", encoding="ascii", errors="backslashreplace",
                  newline="\n") as stream:
            stream.write("$ " + subprocess.list2cmdline([str(a) for a in args]) + "\n")
            if log_stdout:
                stream.write(result.stdout.replace("\r\n", "\n"))
            stream.write(result.stderr.replace("\r\n", "\n"))
            stream.write("exit: %d\n" % result.returncode)
    if result.returncode:
        raise RuntimeError("%s exited %d: %s" %
                           (args[0], result.returncode, result.stderr.strip()))
    return result.stdout


def extract(spec, sources):
    if "definition" in spec:
        return spec["definition"]
    return "\n".join(sources[spec["source"]].decode("utf-8").splitlines()[
        spec["first"] - 1:spec["last"]])


def adapter(spec, sources, capacity):
    """Archive template; native mode prints uint64 indices without a bounds veto."""
    if spec.get("kind") == "juliet":
        return juliet_adapter(spec, capacity)
    definition = extract(spec, sources)
    for edit in ([spec["head"]] if spec.get("head") else []) + list(spec.get("edit", ())):
        if definition.count(edit["old"]) != 1:
            raise ValueError("Frozen source specialization does not match")
        definition = definition.replace(edit["old"], edit["new"], 1)
    if "wrap" in spec:
        definition = "%s%s\n}" % (spec["wrap"], definition)
    dependencies = "\n".join(extract(part, sources) for part in spec.get("dependencies", ()))
    return """#include <limits.h>
#include <stdint.h>
#ifdef CHECK_NATIVE
#include <stdio.h>
#endif
%s
%s

%s

static inline __attribute__((always_inline)) uint64_t probe_index(uint64_t x) {
    %s
    return %s;
}
#ifdef CHECK_NATIVE
int main(void) {
    for (uint64_t x = %d; x <= %d; ++x) {
        uint64_t index = probe_index(x);
        printf("%%llu\\n", (unsigned long long)index);
    }
    return 0;
}
#else
volatile unsigned char evaluation_output[%d];
__attribute__((sysv_abi, used, noinline))
void benchmark_step(uint64_t x) {
    evaluation_output[probe_index(x)] = 0x41;
}
#endif
""" % (spec.get("preamble", ""), dependencies, definition, spec.get("setup", ""),
       spec["call"], spec["min"], spec["max"], capacity)


def juliet_adapter(spec, capacity):
    return """#include <stdint.h>
#ifdef CHECK_NATIVE
#include <stdio.h>
static uint64_t native_index;
static int native_visited;
#define QUERY_STORE(i) (native_index = (uint64_t)(i), native_visited = 1)
#else
volatile unsigned char evaluation_output[%d];
#define QUERY_STORE(i) (evaluation_output[(uint64_t)(i)] = 0x41)
#endif
__attribute__((sysv_abi, used, noinline))
void benchmark_step(uint64_t x) %s
#ifdef CHECK_NATIVE
int main(void) {
    for (uint64_t x = %d; x <= %d; ++x) {
        native_visited = 0;
        benchmark_step(x);
        if (native_visited) printf("%%llu\\n", (unsigned long long)native_index);
        else puts("-");
    }
    return 0;
}
#endif
""" % (capacity, spec["body"], spec["min"], spec["max"])


def derive_outcome(indices, capacity, minimum=0):
    if not 0 < capacity < (1 << 64):
        raise ValueError("Capacity must be positive and uint64")
    if not indices or any(i is not None and not 0 <= i < (1 << 64) for i in indices):
        raise ValueError("Expected a complete, nonempty uint64 reference")
    for offset, index in enumerate(indices):
        if index is not None and index >= capacity:
            return {"outcome": "violation", "witness": {"rdi": minimum + offset}}
    return {"outcome": "safe"}


def s2_capacities(indices):
    if not indices or any(i is None or not 0 <= i < (1 << 64) for i in indices):
        raise ValueError("S2 requires one uint64 index for every input")
    maximum = max(indices)
    if maximum >= 65536:
        return [65536]
    return [maximum + 1, maximum] if maximum >= 1 else [1]


def native_reference(spec, source, output, flags=FLAGS, log=None):
    native = output / (spec["id"] + "-native.exe")
    try:
        cmd(["gcc"] + list(flags) + ["-DCHECK_NATIVE", source.name, "-o", native.name], output, log)
        lines = cmd([str(native.resolve())], output, log, log_stdout=False).splitlines()
        indices = [None if line == "-" else int(line) for line in lines]
        if len(indices) != spec["max"] - spec["min"] + 1:
            raise ValueError("Native enumeration did not cover the whole domain")
        derive_outcome(indices, 1, spec["min"])
        return indices
    finally:
        if native.exists():
            native.unlink()


def file_from_loaded_image(exe, entry, data_address, capacity):
    """The archived PE section loader, ELF layout and marker detection, unchanged."""
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86_const as x86

    image = pefile.PE(data=exe.read_bytes())
    assert image.FILE_HEADER.Machine == 0x8664 and image.OPTIONAL_HEADER.ImageBase == BASE
    assert image.OPTIONAL_HEADER.AddressOfEntryPoint + BASE == entry
    if getattr(image, "DIRECTORY_ENTRY_IMPORT", ()) or getattr(image, "DIRECTORY_ENTRY_BASERELOC", ()):
        raise ValueError("Fixture linker left runtime imports or base relocations")
    loads = []
    code = None
    code_address = None
    for section in image.sections:
        name = section.Name.rstrip(b"\0")
        if name not in (b".text", b".data", b".rdata", b".bss"):
            continue
        address = BASE + section.VirtualAddress
        memory_size = section.Misc_VirtualSize
        flags = ((4 if section.Characteristics & 0x40000000 else 0)
                 | (2 if section.Characteristics & 0x80000000 else 0)
                 | (1 if section.Characteristics & 0x20000000 else 0))
        data = section.get_data(length=min(memory_size, section.SizeOfRawData)) if section.SizeOfRawData else b""
        if len(data) > memory_size or address % 4096:
            raise ValueError("Invalid mapped section size or alignment")
        if name == b".text":
            code_address, code = address, data
        loads.append((address, memory_size, flags, data))
    if code is None or not code_address <= entry < code_address + len(code):
        raise ValueError("Entrypoint is not in initialized executable bytes")
    if sum(bool(flags & 2) and address <= data_address and data_address + capacity <= address + size
           for address, size, flags, _ in loads) != 1:
        raise ValueError("Declared output is not fully inside one writable section")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    code_offset = entry - code_address
    matches = [i for i in decoder.disasm(code[code_offset:], entry)
               if i.mnemonic == "mov" and len(i.operands) == 2 and i.operands[0].type == x86.X86_OP_MEM
               and i.operands[0].size == 1 and i.operands[1].type == x86.X86_OP_IMM and i.operands[1].imm == 0x41]
    store, = matches
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, entry, 64, 0, 0, 64, 56, len(loads) + 1, 0, 0, 0)
    segments = [struct.pack("<IIQQQQQQ", 1, 4, 0, BASE, BASE, 4096, 4096, 4096)]
    payload = bytearray()
    cursor = 4096
    for address, size, flags, data in sorted(loads):
        segments.append(struct.pack("<IIQQQQQQ", 1, flags, cursor, address, address, len(data), size, 4096))
        padding = (-len(data)) % 4096
        payload.extend(data + b"\0" * padding)
        cursor += len(data) + padding
    return (header + b"".join(segments)).ljust(4096, b"\0") + payload, store.address


def link_fixture(spec, source, output, capacity, flags=FLAGS, log=None):
    image = output / (spec["id"] + "-linked.exe")
    try:
        cmd(["gcc"] + list(flags) + ["-nostdlib", source.name,
            "-Wl,--image-base,0x400000,-e,benchmark_step", "-o", image.name], output, log)
        symbols = {}
        for line in cmd(["nm", "-P", "--defined-only", image.name], output, log).splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] in ("benchmark_step", "evaluation_output"):
                symbols[fields[0]] = int(fields[2], 16)
        entry, data = symbols["benchmark_step"], symbols["evaluation_output"]
        blob, store_pc = file_from_loaded_image(image, entry, data, capacity)
        target = output / (spec["id"] + ".elf")
        target.write_bytes(blob)
        return Query(spec["id"], target.name, file_hash(target), entry - BASE,
                     store_pc - BASE, data - BASE, capacity,
                     (InputRange("rdi", spec["min"], spec["max"]),))
    finally:
        if image.exists():
            image.unlink()


def compile_case(spec, sources, output, capacity=65536, flags=FLAGS):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    source = output / (spec["id"] + "-adapter.c")
    log = output / (spec["id"] + "-build.log")
    write_text(log, "")
    write_text(source, adapter(spec, sources, capacity))
    # Link first: non-freestanding candidates are rejected before native execution.
    try:
        query = link_fixture(spec, source, output, capacity, flags, log)
    except RuntimeError as error:
        raise FixtureBuildError("freestanding_link", error) from error
    try:
        indices = native_reference(spec, source, output, flags, log)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise FixtureBuildError("native_reference", error) from error
    reference = {"input_minimum": spec["min"], "input_maximum": spec["max"],
                 "indices": indices}
    reference.update(derive_outcome(indices, capacity, spec["min"]))
    return asdict(query), reference


def write_panel(output, records, references):
    allowed = {"case_id", "stratum", "project", "binary_group", "query"}
    if any(set(row) != allowed for row in records):
        raise ValueError("Runtime records must contain only panel metadata and Query")
    for row in records:
        query = row["query"]
        if Path(query["binary"]).is_absolute() or ".." in Path(query["binary"]).parts:
            raise ValueError("Runtime binary must be relative to the panel")
        Query.from_dict(query, output)
    write_json(output / "panel.json", {"schema": "symbai.route_b_v4_panel.v1", "records": records})
    write_json(output / "offline-references.json", {
        "schema": "symbai.route_b_v4_offline_references.v1", "references": references})
