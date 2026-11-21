"""Bounded prefix coverage tests for the independent byte-write checker."""

import time
from uuid import uuid4

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, DATA, TEXT, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash
from src.selective_analysis import path_certificate as certificate
from src.selective_analysis.workspace import SCRATCH


@pytest.fixture
def make_proof():
    workspace = SCRATCH / f"path-certificate-test-{uuid4().hex}"
    workspace.mkdir(parents=True)
    binaries = []

    def build(code, paths, minimum, maximum, capacity=8):
        binary = workspace / f"case-{len(binaries)}.elf"
        binaries.append(binary)
        binary.write_bytes(elf_bytes(code.finish()))
        query = Query(
            binary.stem,
            str(binary),
            file_hash(binary),
            TEXT - BASE,
            TEXT + code.write_offset - BASE,
            DATA - BASE,
            capacity,
            (InputRange("rdi", minimum, maximum),),
        )
        proof = {
            "schema": certificate.SCHEMA,
            "query_hash": query.contract_hash,
            "binary_sha256": query.binary_sha256,
            "paths": paths,
        }
        return query, proof

    try:
        yield build
    finally:
        for binary in binaries:
            binary.unlink(missing_ok=True)
        workspace.rmdir()


@pytest.mark.parametrize(
    ("instruction", "minimum", "maximum", "capacity", "accepted"),
    [
        ("0f bd d7", 1, 255, 8, True),
        ("0f bd d7", 0, 255, 8, False),
        ("0f bd d7", 128, 128, 7, False),
        ("48 0f bd d7", 1 << 40, 1 << 40, 40, False),
    ],
)
def test_bit_scan_requires_valid_source_and_bounds(
    make_proof, instruction, minimum, maximum, capacity, accepted
):
    code = Code()
    code.emit("48 c7 c2 ff ff ff ff")  # mov rdx, -1
    scan = TEXT + len(code.data)
    code.emit(instruction)  # bsr edx, edi or bsr rdx, rdi
    address = TEXT + len(code.data)
    code.lea()
    code.write("rdx")
    target = TEXT + code.write_offset
    query, proof = make_proof(
        code, [[TEXT, scan, address, target]], minimum, maximum, capacity
    )
    checker = certificate.PathChecker(query)
    if accepted:
        assert (
            checker.validate(proof, time.monotonic() + 5)["status"]
            == certificate.PROVEN
        )
    else:
        with pytest.raises(
            certificate.Rejected, match="proof_obligation_not_discharged:sat"
        ):
            checker.validate(proof, time.monotonic() + 5)


def branch_write_paths(code, opcode):
    branch = TEXT + len(code.data)
    code.jump(opcode, "taken")
    fallthrough = TEXT + len(code.data)
    code.emit("ba 00 00 00 00")  # mov edx, 0
    join_jump = TEXT + len(code.data)
    code.jump("e9", "join")
    code.label("taken")
    taken = TEXT + len(code.data)
    code.emit("ba 01 00 00 00")  # mov edx, 1
    code.label("join")
    join = TEXT + len(code.data)
    code.lea()
    code.write("rdx")
    target = TEXT + code.write_offset
    return [TEXT, branch, fallthrough, join_jump, join, target], [
        TEXT,
        branch,
        taken,
        join,
        target,
    ]


@pytest.mark.parametrize(
    ("opcode", "input_value", "taken"),
    [
        ("0f 88", 0, True),  # js after unsigned wrap
        ("0f 88", 0x80000000, False),  # js after signed overflow
        ("0f 84", 1, True),  # je
        ("0f 85", 2, True),  # jne
    ],
)
def test_subtraction_branch_uses_fixed_width_result(
    make_proof, opcode, input_value, taken
):
    code = Code()
    code.emit("83 ef 01")  # sub edi, 1
    fallthrough, taken_path = branch_write_paths(code, opcode)
    path = taken_path if taken else fallthrough
    query, proof = make_proof(code, [path], input_value, input_value)
    assert (
        certificate.PathChecker(query).validate(proof, time.monotonic() + 5)["status"]
        == certificate.PROVEN
    )


@pytest.mark.parametrize(
    ("instruction", "input_value", "taken"),
    [
        ("85 ff", 1 << 32, True),  # test edi, edi
        ("40 f6 c7 80", 0x180, False),  # test dil, 0x80
    ],
)
def test_register_test_reads_only_operand_width(
    make_proof, instruction, input_value, taken
):
    code = Code()
    code.emit(instruction)
    fallthrough, taken_path = branch_write_paths(code, "0f 84")  # je
    path = taken_path if taken else fallthrough
    query, proof = make_proof(code, [path], input_value, input_value)
    assert (
        certificate.PathChecker(query).validate(proof, time.monotonic() + 5)["status"]
        == certificate.PROVEN
    )


@pytest.fixture
def countdown(make_proof):
    # Each supported input reaches the same byte write after a different number
    # of iterations. Repeated PCs have different register states.
    code = Code()
    code.label("test")
    entry = TEXT
    code.emit("48 83 ff 00")  # cmp rdi, 0
    branch = TEXT + len(code.data)
    code.jump("0f 84", "done")
    decrement = TEXT + len(code.data)
    code.emit("48 83 ef 01")  # sub rdi, 1
    backedge = TEXT + len(code.data)
    code.jump("e9", "test")
    code.label("done")
    address = TEXT + len(code.data)
    code.lea()
    code.write()
    target = TEXT + code.write_offset
    code.emit("c3")
    traced_iteration = [entry, branch, decrement, backedge]
    paths = [traced_iteration * n + [entry, branch, address, target] for n in range(4)]
    return make_proof(code, paths, 0, 3)


def test_every_bounded_iteration_is_verified(countdown):
    query, proof = countdown
    checker = certificate.PathChecker(query)
    result = checker.validate(proof, time.monotonic() + 5)
    assert result["status"] == certificate.PROVEN
    assert result["checked_nodes"] > len(set(proof["paths"][-1]))
    assert checker.validate(proof, time.monotonic() + 5) == result


def test_omitted_feasible_iteration_is_rejected(countdown):
    query, proof = countdown
    truncated = {**proof, "paths": proof["paths"][:-1]}
    with pytest.raises(
        certificate.Rejected, match="proof_obligation_not_discharged:sat"
    ):
        certificate.PathChecker(query).validate(truncated, time.monotonic() + 5)


@pytest.mark.parametrize(
    ("limit", "value", "message"),
    [
        ("MAX_PATHS", 3, "path_count_outside_subset"),
        ("MAX_STEPS", 8, "invalid_or_duplicate_path"),
        ("MAX_TREE_NODES", 3, "certificate_tree_limit"),
    ],
)
def test_resource_limit_leaves_certificate_unverified(
    countdown, monkeypatch, limit, value, message
):
    query, proof = countdown
    monkeypatch.setattr(certificate, limit, value)
    with pytest.raises(certificate.Rejected, match=message):
        certificate.PathChecker(query).validate(proof, time.monotonic() + 5)


def test_expired_deadline_leaves_certificate_unverified(countdown):
    query, proof = countdown
    with pytest.raises(TimeoutError, match="certificate deadline"):
        certificate.PathChecker(query).validate(proof, time.monotonic() - 1)
