"""File/loaded-instruction consistency regressions; unit-only ELF layouts."""

from pathlib import Path
import struct
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis.frame_bounds import FrameBoundsChecker
from src.selective_analysis.local_bounds import LocalBoundsChecker, UnsupportedBounds
from src.selective_analysis.operations import BinaryChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("elf-guard-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def dynamic_case(folder, section_address=0x300, section_offset=0x300, section_size=24,
                 relocation_address=0x1004, relocation_type=8):
    code = bytearray.fromhex('55 48 89 e5 90 90 90 90 90 90 90 90 48 89 7d f8 48 8d 05 00 00 00 00 48 8b 55 f8')
    code[19:23] = struct.pack('<i', DATA - (TEXT + 23))
    code += bytes.fromhex('48 01 d0')
    write = len(code)
    code += bytes.fromhex('c6 00 41 c3')
    strings = b'\0.text\0.dynamic\0.dynstr\0.dynsym\0.rela.dyn\0.shstrtab\0'
    blob = bytearray(0x2400)
    blob[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + b'\0' * 9,
        3, 62, 1, 0x1000, 64, 0x2200, 0, 64, 56, 4, 64, 7, 6)
    segments = [(1, 6, 0, 0, 0, 0x1000, 0x1000, 0x1000),
        (1, 5, 0x1000, 0x1000, 0x1000, len(code), len(code), 0x1000),
        (1, 6, 0x2000, 0x2000, 0x2000, 8, 0x1000, 0x1000),
        (2, 6, 0x200, 0x200, 0x200, 0x80, 0x80, 8)]
    for i, row in enumerate(segments):
        blob[64 + 56 * i:120 + 56 * i] = struct.pack('<IIQQQQQQ', *row)
    tags = [(7, 0x300), (8, 24), (9, 24), (5, 0x320), (10, 1), (6, 0x330), (11, 24), (0, 0)]
    for i, row in enumerate(tags):
        blob[0x200 + 16 * i:0x210 + 16 * i] = struct.pack('<qQ', *row)
    # Reference loading can turn the nops after the frame establishment into inc rdi.
    replacement = int.from_bytes(bytes.fromhex('48 ff c7 90 90 90 90 90'), 'little')
    addend = (replacement - BASE) & ((1 << 64) - 1)
    if addend >= 1 << 63:
        addend -= 1 << 64
    blob[0x300:0x318] = struct.pack('<QQq', relocation_address, relocation_type, addend)
    blob[0x1000:0x1000 + len(code)] = code
    blob[0x2100:0x2100 + len(strings)] = strings
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (strings.index(b'.text'), 1, 6, 0x1000, 0x1000, len(code), 0, 0, 16, 0),
        (strings.index(b'.dynamic'), 6, 3, 0x200, 0x200, 0x80, 3, 0, 8, 16),
        (strings.index(b'.dynstr'), 3, 2, 0x320, 0x320, 1, 0, 0, 1, 0),
        (strings.index(b'.dynsym'), 11, 2, 0x330, 0x330, 24, 3, 0, 8, 24),
        (strings.index(b'.rela.dyn'), 4, 2, section_address, section_offset, section_size, 4, 0, 8, 24),
        (strings.index(b'.shstrtab'), 3, 0, 0, 0x2100, len(strings), 0, 0, 1, 0)]
    for i, row in enumerate(sections):
        blob[0x2200 + 64 * i:0x2240 + 64 * i] = struct.pack('<IIQQQQIIQQ', *row)
    path = folder / ('dynamic-' + uuid.uuid4().hex[:8] + '.elf')
    path.write_bytes(blob)
    return Query('unit-layout', str(path), file_hash(path), 0x1000, 0x1000 + write, 0x2000,
        1, (InputRange('rdi', 0, 0),))


def test_dynamic_table_cannot_hide_behind_empty_relocation_section(tmp_path):
    query = dynamic_case(tmp_path, section_address=0x360, section_offset=0x360, section_size=0)
    reference = BinaryChecker(query)
    assert reference.project.loader.memory.load(TEXT + 4, 3) == bytes.fromhex('48 ff c7')
    result = reference.validate(reference.check(128, time.monotonic() + 5), 128, time.monotonic() + 5)
    assert result['status'] == 'violation'
    for checker in (LocalBoundsChecker, FrameBoundsChecker):
        with pytest.raises(UnsupportedBounds, match='section_coverage_unproved'):
            checker(query)


def test_section_and_program_header_table_bytes_must_match(tmp_path):
    query = dynamic_case(tmp_path, section_offset=0x360)
    with pytest.raises(UnsupportedBounds, match='file_bytes_differ'):
        LocalBoundsChecker(query)


@pytest.mark.parametrize('offset', (0x1004, 0xffc))
def test_complete_relocation_span_must_not_overlap_executable_memory(tmp_path, offset):
    query = dynamic_case(tmp_path, relocation_address=offset)
    with pytest.raises(UnsupportedBounds, match='executable_relocation'):
        LocalBoundsChecker(query)


def test_unknown_relocation_width_retains_unknown_layout(tmp_path):
    query = dynamic_case(tmp_path, relocation_address=0x2040, relocation_type=5)
    with pytest.raises(UnsupportedBounds, match='write_width'):
        LocalBoundsChecker(query)


def test_covered_data_relocations_still_allow_reference_consistent_frame_proof(tmp_path):
    query = dynamic_case(tmp_path, relocation_address=0x2040)
    checker = FrameBoundsChecker(query)
    result = checker.validate(checker.check(time.monotonic() + 5), time.monotonic() + 5)
    assert result['status'] == 'excluded_within_scope'
    assert BinaryChecker(query).check(128, time.monotonic() + 5)['status'] == 'excluded_within_scope'


def test_frame_decode_compares_actual_reference_bytes(tmp_path):
    code = Code()
    code.emit('55 48 89 e5 90 48 89 7d f8')
    code.lea()
    code.emit('48 8b 55 f8 48 01 d0')
    code.write_offset = len(code.data)
    code.emit('c6 00 41 c3')
    path = tmp_path / 'unit-frame.elf'
    path.write_bytes(elf_bytes(code.finish()))
    query = Query('unit-loader-check', str(path), file_hash(path), TEXT - BASE,
        TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange('rdi', 0, 0),))
    reference = BinaryChecker(query)
    reference.project.loader.memory.store(TEXT + 4, b'\xcc')
    result = FrameBoundsChecker(query, reference).check(time.monotonic() + 5)
    assert result['status'] == 'unknown' and result['reason'] == 'loaded_instruction_bytes_differ_from_file'
