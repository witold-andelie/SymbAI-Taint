"""Build twelve tiny x86-64 ELF mechanisms without requiring a native Linux compiler.

These are deliberately transparent machine-code fixtures. Object bounds and argument ranges
are explicit query assumptions, not automatically inferred source types. No GNN data is made.
"""

from dataclasses import asdict
import json
from pathlib import Path
import struct

from src.selective_analysis.contracts import InputRange, Query, file_hash


BASE, TEXT, DATA = 0x400000, 0x401000, 0x402000


class Code:
    def __init__(self):
        self.data = bytearray()
        self.labels = {}
        self.fixups = []
        self.write_offset = None

    def emit(self, value):
        self.data.extend(bytes.fromhex(value))

    def label(self, name):
        self.labels[name] = len(self.data)

    def jump(self, opcode, name):
        self.emit(opcode)
        self.fixups.append((len(self.data), name))
        self.data.extend(b"\0" * 4)

    def lea(self, offset=0):
        self.emit("48 8d 05")
        delta = DATA + offset - (TEXT + len(self.data) + 4)
        self.data.extend(struct.pack("<i", delta))

    def write(self, index="rdi"):
        self.write_offset = len(self.data)
        self.emit("c6 04 38 41" if index == "rdi" else "c6 04 10 41")

    def finish(self):
        for position, label in self.fixups:
            self.data[position:position + 4] = struct.pack("<i", self.labels[label] - position - 4)
        return bytes(self.data)


def elf_bytes(code):
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, TEXT, 64, 0, 0,
                         64, 56, 2, 0, 0, 0)
    first = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, 0x1000 + len(code), 0x1000 + len(code), 0x1000)
    second = struct.pack("<IIQQQQQQ", 1, 6, 0x2000, DATA, DATA, 8, 0x1000, 0x1000)
    return (header + first + second).ljust(0x1000, b"\0") + code + b"\0" * (0x1000 - len(code)) + b"\0" * 8


def make_mechanisms(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    queries, labels = [], []
    descriptions = ["direct index", "unsigned bound", "inclusive bound", "signed guard",
                    "branch join", "index masking", "register alias with long prefix",
                    "direct call", "overwritten input", "unreachable write", "stack spill",
                    "interior pointer"]
    for number in range(1, 13):
        c = Code()
        if number in (2, 3, 4, 12):
            c.emit("48 83 ff 08")  # cmp rdi, 8
            c.jump({2: "0f 83", 3: "0f 87", 4: "0f 8d", 12: "0f 83"}[number], "done")
        if number == 5:
            c.emit("48 85 f6")  # test rsi, rsi
            c.jump("0f 84", "zero")
            c.jump("e9", "join")
            c.label("zero")
            c.emit("31 ff")
            c.label("join")
        if number == 6:
            c.emit("48 83 e7 07")
        if number == 7:
            c.emit("90 " * 12)
            c.emit("48 89 fa")  # mov rdx, rdi
        if number == 8:
            c.jump("e8", "callee")
            c.emit("c3")
            c.label("callee")
        if number == 9:
            c.emit("31 ff")
        if number == 10:
            c.jump("e9", "done")
        if number == 11:
            c.emit("48 83 ec 08 48 89 3c 24 48 8b 14 24 48 83 c4 08")
        c.lea(4 if number == 12 else 0)
        c.write("rdx" if number in (7, 11) else "rdi")
        c.label("done")
        c.emit("c3")
        case_id = f"m{number:02d}"
        binary = output / f"{case_id}.elf"
        binary.write_bytes(elf_bytes(c.finish()))
        inputs = (InputRange("rdi", 0, (1 << 64) - 1 if number == 4 else 15), InputRange("rsi", 0, 1))
        query = Query(case_id, str(binary.resolve()), file_hash(binary), TEXT - BASE,
                      TEXT - BASE + c.write_offset, DATA - BASE, 8, inputs)
        payload = asdict(query)
        payload["binary"] = binary.name
        queries.append(payload)
        labels.append({"query_id": case_id, "binary_sha256": query.binary_sha256,
                       "expected": "excluded_within_scope" if number in (2, 6, 9, 10) else "violation",
                       "mechanism": descriptions[number - 1]})
    manifest = output / "queries.json"
    manifest.write_text(json.dumps({"schema": "symbai.queries.v1", "queries": queries}, indent=2), encoding="utf-8")
    (output / "gold.json").write_text(json.dumps({"schema": "symbai.gold.v1", "labels": labels}, indent=2), encoding="utf-8")
    return manifest
