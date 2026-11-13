"""Three authored capability mechanisms, separate from the original primary panel."""

from dataclasses import asdict
import json
from pathlib import Path
import struct

from .mechanisms import BASE, TEXT, DATA, Code
from src.selective_analysis.contracts import InputRange, Query, file_hash

READONLY = 0x403000
CASE_IDS = ("scalar_span", "readonly_chain", "readonly_chain_outside")


def mechanism_bytes(chain=False, last_offset=6):
    code = Code()
    if chain:
        code.emit("48 83 e7 01 48 8d 15")  # and rdi,1; lea rdx,[rip+readonly]
        code.data.extend(struct.pack("<i", READONLY - (TEXT + len(code.data) + 4)))
        code.emit("48 8b 04 fa 48 8b 38")  # rax=[rdx+rdi*8]; rdi=[rax]
    code.lea()
    code.write()
    code.emit("c3")
    text = code.finish()
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, TEXT, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    segments = [(1, 5, 0, BASE, BASE, 0x1000 + len(text), 0x1000 + len(text), 0x1000),
                (1, 6, 0x2000, DATA, DATA, 1024, 0x1000, 0x1000),
                (1, 4, 0x3000, READONLY, READONLY, 64, 64, 0x1000)]
    blob = bytearray(header + b"".join(struct.pack("<IIQQQQQQ", *row) for row in segments))
    blob.extend(b"\0" * (0x3040 - len(blob)))
    blob[0x1000:0x1000 + len(text)] = text
    blob[0x3000:0x3010] = struct.pack("<QQ", READONLY + 32, READONLY + 40)
    blob[0x3020:0x3030] = struct.pack("<QQ", 2, last_offset)
    return bytes(blob), code.write_offset


def make_indirection_mechanisms(output):
    """Generate all cases irrespective of analysis or predicted type outcomes."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    queries, labels = [], []
    for case_id in CASE_IDS:
        chain = case_id != "scalar_span"
        outside = case_id == "readonly_chain_outside"
        blob, write = mechanism_bytes(chain, 12 if outside else 6)
        binary = output / (case_id + ".elf")
        binary.write_bytes(blob)
        query = Query(case_id, str(binary.resolve()), file_hash(binary), TEXT - BASE,
                      TEXT - BASE + write, DATA - BASE, 8 if chain else 1024,
                      (InputRange("rdi", 0, 15 if chain else 1023),))
        contract = asdict(query)
        contract["binary"] = binary.name
        queries.append(contract)
        labels.append({"query_id": case_id, "binary_sha256": query.binary_sha256,
                       "expected": "violation" if outside else "excluded_within_scope"})
    manifest = output / "queries.json"
    manifest.write_text(json.dumps({"schema": "symbai.queries.v1", "queries": queries}, indent=2), encoding="utf-8")
    (output / "gold.json").write_text(json.dumps({"schema": "symbai.gold.v1", "panel": "v14_three_authored_capability_mechanisms",
                                               "labels": labels}, indent=2), encoding="utf-8")
    return manifest
