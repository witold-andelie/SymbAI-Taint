"""Authored finite-domain unit mechanisms; no modeled execution or neural inputs."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import struct
import sys
import time
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import READONLY, mechanism_bytes
from benchmarks.selective_analysis.mechanisms import BASE, DATA, TEXT, Code
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.local_bounds import LocalBoundsChecker, UnsupportedBounds
from src.selective_analysis.readonly_values import FiniteReadonlyChecker


ROOT = Path(__file__).resolve().parents[1]
MAX64 = (1 << 64) - 1


@pytest.fixture
def make_case():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("readonly-unit-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)

    def make(prefix=None, chain=False, last=6, inputs=None, capacity=8, mutate=None):
        blob, write = mechanism_bytes(chain, last)
        blob = bytearray(blob)
        if prefix is not None:
            code = Code()
            code.emit(prefix)
            code.lea()
            code.write()
            code.emit("c3")
            text, write = code.finish(), code.write_offset
            blob[0x1000:0x2000] = b"\0" * 0x1000
            blob[0x1000:0x1000 + len(text)] = text
            struct.pack_into("<QQ", blob, 96, 0x1000 + len(text), 0x1000 + len(text))
        if mutate:
            mutate(blob)
        binary = folder / (uuid.uuid4().hex[:8] + ".elf")
        binary.write_bytes(blob)
        return Query("unit-readonly", str(binary), file_hash(binary), TEXT - BASE,
                     TEXT - BASE + write, DATA - BASE, capacity,
                     inputs if inputs is not None else (InputRange("rdi", 0, 15),))

    return make


def deadline():
    return time.monotonic() + 5


def direct_read(address=READONLY + 32, displacement=0):
    move = "48 ba " + struct.pack("<Q", address).hex(" ")
    load = "48 8b 3a" if not displacement else "48 8b 7a " + struct.pack("<b", displacement).hex()
    return move + " " + load


def add_relocation(blob, address):
    blob.extend(b"\0" * (0x3280 - len(blob)))
    struct.pack_into("<QQq", blob, 0x3100, address, 1, 0)
    struct.pack_into("<Q", blob, 40, 0x3200)
    struct.pack_into("<HHH", blob, 58, 64, 2, 0)
    struct.pack_into("<IIQQQQIIQQ", blob, 0x3240, 0, 4, 0, 0, 0x3100, 24, 0, 0, 8, 24)


def test_declared_capability_shapes_are_complementary_without_abstract_witnesses(make_case):
    scalar = make_case(inputs=(InputRange("rdi", 0, 1023),), capacity=1024)
    safe, unsafe = make_case(chain=True), make_case(chain=True, last=12)
    assert LocalBoundsChecker(scalar).check(deadline())["status"] == "excluded_within_scope"
    assert FiniteReadonlyChecker(scalar).check(deadline())["status"] == "unknown"
    assert LocalBoundsChecker(safe).check(deadline())["status"] == "unknown"
    good = FiniteReadonlyChecker(safe).check(deadline())
    assert good["status"] == "excluded_within_scope"
    assert good["certificate"]["discharged_writes"] == [{"addresses": [DATA + 2, DATA + 6], "length": 1}]
    assert [row["value"] for row in good["readonly_reads"]] == [READONLY + 32, READONLY + 40, 2, 6]
    bad_checker = FiniteReadonlyChecker(unsafe)
    bad = bad_checker.check(deadline())
    assert bad["status"] == "unknown" and "not_proved_inside_object" in bad["reason"]
    assert bad_checker.validate(bad, deadline())["validation"] == "no_decisive_evidence"


def test_top_mask_refinement_remains_enabled_for_pointer_chain(make_case):
    query = make_case(chain=True, inputs=(InputRange("rdi", 0, MAX64),))
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == "excluded_within_scope"
    assert result["saturations"][0]["input_cardinality"] == 1 << 64
    states = result["certificate"]["trace"]
    assert states[0]["register_values"]["rdi"] == "Top"
    assert states[1]["register_values"]["rdi"] == [0, 1]


@pytest.mark.parametrize("mask,status", [(0, "excluded_within_scope"), (1, "excluded_within_scope"),
                                         (5, "excluded_within_scope"), (31, "excluded_within_scope"), (63, "unknown")])
def test_top_constant_mask_uses_complete_bit_image_or_saturates(make_case, mask, status):
    query = make_case(prefix=f"48 83 e7 {mask:02x}", inputs=(InputRange("rdi", 0, MAX64),), capacity=64)
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == status
    if status != "unknown":
        assert result["certificate"]["trace"][1]["register_values"]["rdi"] == [
            value for value in range(mask + 1) if value & mask == value]
    else:
        assert any(row["reason"] == "mask_image_exceeds_cap" for row in result["saturations"])


def test_finite_cartesian_products_saturate_instead_of_sampling(make_case):
    query = make_case(prefix="48 01 f7", inputs=(InputRange("rdi", 0, 31), InputRange("rsi", 0, 31)), capacity=64)
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == "unknown"
    assert any(row["reason"] == "arithmetic_cardinality_exceeds_cap" for row in result["saturations"])
    assert result["trace"][-1]["register_values"]["rdi"] == "Top"


@pytest.mark.parametrize("prefix,minimum,maximum", [("48 83 c7 01", MAX64, MAX64),
                                                   ("48 83 ef 01 48 83 c7 01", 0, 0),
                                                   ("48 31 ff", 0, MAX64),
                                                   ("48 83 f7 01", 0, 1)])
def test_machine_width_arithmetic_and_xor_are_conservative(make_case, prefix, minimum, maximum):
    query = make_case(prefix=prefix, inputs=(InputRange("rdi", minimum, maximum),))
    assert FiniteReadonlyChecker(query).check(deadline())["status"] == "excluded_within_scope"


@pytest.mark.parametrize("prefix,reason", [("eb 00", "unsupported_instruction"), ("e8 00 00 00 00", "unsupported_instruction"),
                                         ("c6 02 00", "non_target_memory_write"), ("89 ff", "non64_register"),
                                         ("48 83 ec 08", "stack_modification"), ("48 8b 3a", "readonly_address_is_top")])
def test_unsupported_effects_and_unknown_addresses_do_not_exclude(make_case, prefix, reason):
    result = FiniteReadonlyChecker(make_case(prefix=prefix)).check(deadline())
    assert result["status"] == "unknown" and reason in result["reason"]


@pytest.mark.parametrize("change,reason", [("mutable", "mutable"), ("unbacked", "unbacked"),
                                         ("unmapped", "unmapped"), ("cross_span", "cross_segment"),
                                         ("span_wrap", "span_wrap"), ("address_wrap", "address_wrap")])
def test_readonly_load_requires_entire_immutable_initialized_nonwrapping_span(make_case, change, reason):
    mutate = None
    address, displacement = READONLY + 32, 0
    if change == "mutable":
        mutate = lambda blob: struct.pack_into("<I", blob, 64 + 2 * 56 + 4, 6)
    elif change == "unbacked":
        address = READONLY + 64
        mutate = lambda blob: struct.pack_into("<Q", blob, 64 + 2 * 56 + 40, 128)
    elif change == "unmapped":
        address = READONLY + 1024
    elif change == "cross_span":
        address = READONLY + 60
    elif change == "span_wrap":
        address = MAX64 - 3
    else:
        address, displacement = MAX64, 1
    result = FiniteReadonlyChecker(make_case(prefix=direct_read(address, displacement), mutate=mutate)).check(deadline())
    assert result["status"] == "unknown" and reason in result["reason"]


@pytest.mark.parametrize("offset,status", [(-7, "unknown"), (0, "unknown"), (7, "unknown"), (8, "excluded_within_scope")])
def test_complete_read_span_is_checked_against_relocation_write_spans(make_case, offset, status):
    query = make_case(prefix=direct_read(), mutate=lambda blob: add_relocation(blob, READONLY + 32 + offset))
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == status
    if status == "unknown":
        assert "overlaps_relocation" in result["reason"]


def test_overlapping_elf_segments_are_rejected_before_analysis(make_case):
    def overlap(blob):
        struct.pack_into("<Q", blob, 64 + 2 * 56 + 16, DATA)
    with pytest.raises(UnsupportedBounds, match="overlapping"):
        FiniteReadonlyChecker(make_case(chain=True, mutate=overlap))


@pytest.mark.parametrize("index,status", [(0, "excluded_within_scope"), (1, "unknown")])
def test_all_target_access_bytes_must_fit_not_only_the_start_address(make_case, index, status):
    def qword_target(blob):
        # The scalar fixture's target follows its seven-byte RIP-relative LEA.
        blob[0x1007:0x1010] = bytes.fromhex("48 c7 04 38 01 00 00 00 c3")
        struct.pack_into("<QQ", blob, 96, 0x1010, 0x1010)
    query = make_case(inputs=(InputRange("rdi", index, index),), mutate=qword_target)
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == status
    if status == "excluded_within_scope":
        assert result["certificate"]["discharged_writes"][0]["length"] == 8


def test_cartesian_correlation_loss_is_retained_as_an_overapproximation(make_case):
    # RDI-RDI is concretely zero.  This independent-set transfer retains all
    # combinations rather than guessing a relational equality it does not track.
    query = make_case(prefix="48 29 ff", inputs=(InputRange("rdi", 0, 2),))
    result = FiniteReadonlyChecker(query).check(deadline())
    assert result["status"] == "unknown"
    assert result["trace"][1]["register_values"]["rdi"] == [0, 1, 2, MAX64 - 1, MAX64]


def test_fresh_validation_rebuilds_decoder_data_and_full_certificate(make_case, monkeypatch):
    query = make_case(chain=True)
    checker = FiniteReadonlyChecker(query)
    result = checker.check(deadline())
    monkeypatch.setattr(checker.local, "decode", lambda pc: pytest.fail("Reused original decoder"))
    checker.segments.clear()
    validated = checker.validate(result, deadline())
    assert validated["status"] == "excluded_within_scope"
    assert validated["validation"] == "fresh_byte_data_abstract_recheck"
    assert validated["native_replay"] == "not_attempted"
    assert all(len(row["sha256"]) == len(row["segment_sha256"]) == 64 for row in result["readonly_reads"])


def test_changed_data_or_forged_certificate_fails_fresh_validation(make_case):
    query = make_case(chain=True)
    checker = FiniteReadonlyChecker(query)
    result = checker.check(deadline())
    bad = deepcopy(result)
    bad["certificate"]["readonly_reads"][0]["value"] = 0
    bad["certificate_sha256"] = fingerprint(bad["certificate"])
    with pytest.raises(ValueError, match="fresh byte/data"):
        checker.validate(bad, deadline())
    binary = Path(query.binary)
    blob = bytearray(binary.read_bytes())
    struct.pack_into("<Q", blob, 0x3028, 12)
    binary.write_bytes(blob)
    with pytest.raises(ValueError, match="Binary hash differs"):
        checker.validate(result, deadline())


def test_query_cap_and_work_limit_identities_are_validated(make_case):
    query = make_case(chain=True)
    checker = FiniteReadonlyChecker(query)
    result = checker.check(deadline())
    with pytest.raises(ValueError, match="mismatched"):
        FiniteReadonlyChecker(replace(query, capacity=4)).validate(result, deadline())
    with pytest.raises(ValueError, match="mismatched"):
        FiniteReadonlyChecker(query, 16).validate(result, deadline())
    assert FiniteReadonlyChecker(query, 1).check(deadline())["status"] == "unknown"
    assert checker.check(deadline(), max_instructions=1)["status"] == "unknown"
    with pytest.raises(TimeoutError):
        checker.check(time.monotonic() - 1)
    for value in (0, 33, True, 2.5):
        with pytest.raises(ValueError):
            FiniteReadonlyChecker(query, value)


def test_no_case_id_switch_or_property_engine_import(make_case):
    query = make_case(chain=True)
    before = set(sys.modules)
    first = FiniteReadonlyChecker(query).check(deadline())
    second = FiniteReadonlyChecker(replace(query, query_id="opposite-gold-label")).check(deadline())
    assert first["status"] == second["status"] == "excluded_within_scope"
    assert first["certificate"]["discharged_writes"] == second["certificate"]["discharged_writes"]
    assert not [name for name in set(sys.modules) - before if name.split(".")[0] in ("angr", "claripy", "z3")]
