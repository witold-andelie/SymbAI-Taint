"""Frame proofs on real machine-code fixtures, not additional evaluation cases."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from src.selective_analysis.contracts import InputRange, Query, file_hash, fingerprint
from src.selective_analysis.frame_bounds import FrameBoundsChecker
from src.selective_analysis.local_bounds import LocalBoundsChecker, UnsupportedBounds
from src.selective_analysis.operations import BinaryChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def make_case():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("frame-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    def make(extra="", transform="48 83 65 e8 07", allocation="", minimum=0, maximum=15):
        code = Code()
        code.emit("f3 0f 1e fa 55 48 89 e5 " + allocation + " 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + extra + " " + transform + " 48 8b 55 f8 48 8b 45 e8 48 01 d0")
        code.write_offset = len(code.data)
        code.emit("c6 00 41 c3")
        path = folder / (uuid.uuid4().hex[:8] + ".elf")
        path.write_bytes(elf_bytes(code.finish()))
        return Query("unit-frame", str(path), file_hash(path), TEXT - BASE,
            TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", minimum, maximum),))
    return make


def test_mask_proof_and_fresh_context_validation(make_case, monkeypatch):
    query = make_case()
    checker = FrameBoundsChecker(query)
    result = checker.check(time.monotonic() + 5)
    assert result["status"] == "excluded_within_scope"
    context = result["certificate"]["entry_context"]
    assert context["prefix_execution_used"] is False and context["image_and_object_disjoint"] is True
    monkeypatch.setattr(checker, "decode", lambda pc: pytest.fail("Reused frame decoder"))
    validated = checker.validate(result, time.monotonic() + 5)
    assert validated["validation"] == "fresh_entry_context_and_byte_decoded_recheck"
    assert validated["native_replay"] == "not_attempted"
    assert BinaryChecker(query).check(128, time.monotonic() + 5)["status"] == "excluded_within_scope"
    assert LocalBoundsChecker(query).check(time.monotonic() + 5)["reason"] == "unsupported_instruction:push"


def test_unsafe_interval_is_unknown_not_a_witness(make_case):
    query = make_case(transform="48 83 45 e8 04")
    checker = FrameBoundsChecker(query)
    result = checker.check(time.monotonic() + 5)
    assert result["status"] == "unknown" and "not_proved_inside_object" in result["reason"]
    assert checker.validate(result, time.monotonic() + 5)["validation"] == "no_decisive_evidence"
    reference = BinaryChecker(query)
    assert reference.validate(reference.check(128, time.monotonic() + 5), 128, time.monotonic() + 5)["status"] == "violation"


@pytest.mark.parametrize("extra,reason", [
    ("c6 45 e8 00", "partial_overlapping"),
    ("48 89 7d ec", "partial_overlapping"),
    ("48 8b 4d f0", "uninitialized"),
    ("48 89 e9", "frame_register_escape"),
    ("48 8d 4d e8", "frame_address_escape"),
    ("48 89 fd", "frame_register_escape"),
    ("48 83 ec 20", "stack_allocation_outside_subset"),
    ("e8 00 00 00 00", "unsupported_frame_instruction:call"),
    ("eb 00", "unsupported_frame_instruction:jmp"),
    ("c3", "unsupported_frame_instruction:ret"),
    ("48 8b 0f", "partial_overlapping"),
    ("48 89 07", "partial_overlapping"),
    ("48 8b 4d 00", "partial_overlapping"),
    ("48 8b 4d 08", "partial_overlapping"),
    ("48 89 85 78 ff ff ff", "outside_allocation_and_red_zone"),
])
def test_unsupported_effects_never_produce_exclusions(make_case, extra, reason):
    result = FrameBoundsChecker(make_case(extra=extra)).check(time.monotonic() + 5)
    assert result["status"] == "unknown" and reason in result["reason"]


def test_known_full_width_overwrite_replaces_old_slot_value(make_case):
    query = make_case(extra="48 c7 45 e8 00 00 00 00", transform="")
    checker = FrameBoundsChecker(query)
    result = checker.validate(checker.check(time.monotonic() + 5), time.monotonic() + 5)
    assert result["status"] == "excluded_within_scope"
    assert BinaryChecker(query).check(128, time.monotonic() + 5)["status"] == "excluded_within_scope"


@pytest.mark.parametrize("allocation", ("48 83 ec 20", "48 81 ec 00 10 00 00"))
def test_bounded_immediate_allocation_keeps_rbp_slots_stable(make_case, allocation):
    query = make_case(allocation=allocation)
    result = FrameBoundsChecker(query).check(time.monotonic() + 5)
    assert result["status"] == "excluded_within_scope"
    assert BinaryChecker(query).check(128, time.monotonic() + 5)["status"] == "excluded_within_scope"


def test_unsigned_wrap_is_checked_with_machine_width(make_case):
    query = make_case(transform="48 83 45 e8 01", minimum=(1 << 64) - 1, maximum=(1 << 64) - 1)
    result = FrameBoundsChecker(query).check(time.monotonic() + 5)
    assert result["status"] == "excluded_within_scope"
    assert BinaryChecker(query).check(128, time.monotonic() + 5)["status"] == "excluded_within_scope"
    broad = replace(query, inputs=(InputRange("rdi", (1 << 64) - 2, (1 << 64) - 1),))
    assert FrameBoundsChecker(broad).check(time.monotonic() + 5)["status"] == "unknown"


def test_stack_window_must_be_disjoint_from_declared_object(make_case):
    query = make_case()
    reference = BinaryChecker(query)
    state, _ = reference.new_state()
    overlap = replace(query, object_rva=state.solver.eval(state.regs.rsp) - reference.base - 16)
    with pytest.raises(UnsupportedBounds, match="overlaps_declared_object"):
        FrameBoundsChecker(overlap)


@pytest.mark.parametrize("kind", ("symbolic", "program_image"))
def test_entry_stack_uncertainty_or_image_alias_is_rejected(make_case, monkeypatch, kind):
    query = make_case()
    reference = BinaryChecker(query)
    original = reference.new_state
    def changed():
        state, symbols = original()
        state.regs.rsp = (reference.claripy.BVS("uncertain_entry_rsp", 64) if kind == "symbolic" else TEXT + 256)
        return state, symbols
    monkeypatch.setattr(reference, "new_state", changed)
    with pytest.raises(UnsupportedBounds, match="not_unique|overlaps_program_image"):
        FrameBoundsChecker(query, reference)


def test_certificate_contents_and_query_are_independently_rechecked(make_case):
    query = make_case()
    checker = FrameBoundsChecker(query)
    result = checker.check(time.monotonic() + 5)
    bad = deepcopy(result)
    bad["certificate"]["entry_context"]["entry_rsp"] += 8
    bad["certificate_sha256"] = fingerprint(bad["certificate"])
    with pytest.raises(ValueError, match="fresh entry-context"):
        checker.validate(bad, time.monotonic() + 5)
    with pytest.raises(ValueError, match="mismatched"):
        FrameBoundsChecker(replace(query, capacity=4)).validate(result, time.monotonic() + 5)
    with pytest.raises(TimeoutError, match="budget"):
        checker.check(time.monotonic() - 1)
    assert checker.check(time.monotonic() + 5, max_instructions=3)["status"] == "unknown"


def test_fixed_frame_fallback_pays_for_unknown_and_uses_fresh_symbolic_state(make_case):
    from src.selective_analysis.frame_controls import run_frame_control
    query = make_case(transform="48 83 45 e8 04")
    record = run_frame_control(query, "frame_bounds_then_expanded", 5)
    actions = [e for e in record["ledger"] if e["event"] == "action_finished"]
    assert [e["operation_id"] for e in actions] == ["frame_bounds", "expanded_paths"]
    assert actions[0]["outcome"]["status"] == "unknown"
    assert record["result"]["status"] == "violation"
    assert record["result"]["reused_prefix_steps"] == record["result"]["validation_reused_prefix_steps"] == 0
    assert record["costs_seconds"]["preparation"] > 0
    assert record["costs_seconds"]["type_acquisition"] == 0
    assert sum(record["costs_seconds"].values()) <= record["charged_seconds"] + 0.001


def test_frame_control_stops_after_freshly_validated_exclusion(make_case):
    from src.selective_analysis.frame_controls import run_frame_control
    record = run_frame_control(make_case(), "frame_bounds_then_expanded", 5)
    assert record["result"]["status"] == "excluded_within_scope"
    assert [e["operation_id"] for e in record["ledger"] if e["event"] == "action_selected"] == ["frame_bounds"]
    assert record["result"]["validation"] == "fresh_entry_context_and_byte_decoded_recheck"


def test_frame_controls_reject_information_accounting(make_case):
    from src.selective_analysis.frame_controls import run_frame_control
    with pytest.raises(ValueError, match="end-to-end"):
        run_frame_control(make_case(), "frame_bounds_only", 5, regime="information_only")


def test_frame_worker_cli_uses_existing_hard_budget_and_recording(make_case):
    from scripts.run_selective_pilot import run_isolated
    query = make_case()
    record = run_isolated(query, "frame_bounds_only", 5, "end_to_end", Path(query.binary).parent / "runs")
    assert record["result"]["status"] == "excluded_within_scope", record
    assert record["charged_seconds"] == record["elapsed_wall_seconds"] == record["process_wall_seconds"]
    assert record["type_source"] == "not_used"
    rejected = run_isolated(query, "frame_bounds_then_expanded", 5, "end_to_end", Path(query.binary).parent / "bad-runs",
                            type_artifact=Path(query.binary))
    assert rejected["result"]["status"] == "unknown" and rejected["availability"] == "execution_failed"
