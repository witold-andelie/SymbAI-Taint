"""Batch orchestration tests; fabricated timings are unit fixtures, never measurements."""

from copy import deepcopy
import json
from pathlib import Path
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
from scripts.run_frame_batch import read_events, run_batch_isolated, summarize_batches
from src.selective_analysis.contracts import InputRange, Query, file_hash

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("frame-batch-cli-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def make_queries(folder):
    result = []
    for name, transform in (("direct", ""), ("offset", "48 83 45 e8 04"), ("mask", "48 83 65 e8 07")):
        code = Code()
        code.emit("55 48 89 e5 48 89 7d e8")
        code.lea()
        code.emit("48 89 45 f8 " + transform + " 48 8b 55 f8 48 8b 45 e8 48 01 d0")
        code.write_offset = len(code.data)
        code.emit("c6 00 41 c3")
        binary = folder / (name + ".elf")
        binary.write_bytes(elf_bytes(code.finish()))
        result.append(Query("unit-" + name, str(binary), file_hash(binary), TEXT - BASE,
            TEXT - BASE + code.write_offset, DATA - BASE, 8, (InputRange("rdi", 0, 15),)))
    return result


def test_real_isolated_batch_charges_shared_startup_and_keeps_all_outcomes(tmp_path):
    queries = make_queries(tmp_path)
    batch = run_batch_isolated(queries, "frame_bounds_then_expanded", 0, tmp_path, budget=10)
    assert [q["result"]["status"] for q in batch["queries"]] == ["violation", "violation", "excluded_within_scope"], batch
    assert [q["query_id"] for q in batch["queries"]] == [q.query_id for q in queries]
    assert batch["accounting_unit"] == "three_query_cold_batch"
    assert sum(q["query_elapsed_seconds"] for q in batch["queries"]) <= batch["charged_seconds"]
    assert 0 < batch["charged_seconds"] < batch["budget_seconds"]
    assert len(list((tmp_path / "batches").glob("*/provisional-receipt.json"))) == 1


def test_hard_batch_deadline_preserves_three_unknown_identities(tmp_path):
    queries = make_queries(tmp_path)
    batch = run_batch_isolated(queries, "frame_bounds_then_expanded", 0, tmp_path, budget=1e-8)
    assert len(batch["queries"]) == 3
    assert all(q["result"]["status"] == "unknown" for q in batch["queries"])
    assert batch["process"]["timed_out"] is True
    assert batch["charged_seconds"] > batch["budget_seconds"]


def test_incomplete_jsonl_preserves_completed_prefix(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event":"query_completed"}\n{"event":', encoding="utf-8")
    assert read_events(path) == [{"event": "query_completed"}]


def mock_batches():
    names = ("one", "two", "three")
    methods = ("expanded_only", "frame_bounds_only", "frame_bounds_then_expanded")
    gold = {"labels": [{"query_id": name, "binary_sha256": str(i) * 64,
        "expected": "excluded_within_scope" if i == 2 else "violation"} for i, name in enumerate(names)]}
    batches = []
    for repetition in range(3):
        for method in methods:
            rows = [{"query_id": label["query_id"], "binary_sha256": label["binary_sha256"],
                "query_elapsed_seconds": 0.1, "result": {"status": "unknown" if method == "frame_bounds_only" and i != 2 else label["expected"]}}
                    for i, label in enumerate(gold["labels"])]
            batches.append({"batch_id": method + str(repetition), "variant": method, "repetition": repetition,
                "queries": rows, "charged_seconds": 1.0, "budget_seconds": 15,
                "process": {"timed_out": False}, "batch_status": "completed"})
    return batches, gold


def test_summary_uses_full_batch_cost_not_free_query_durations():
    batches, gold = mock_batches()
    report = summarize_batches(batches, gold)
    full = next(r for r in report["comparisons"] if r["variant"] == "expanded_only")
    assert full["total_batch_wall_seconds"] == 3.0
    assert full["median_batch_wall_seconds"] == 1.0
    assert full["batch_records"][0]["query_local_seconds"] == pytest.approx(0.3)
    assert full["batch_records"][0]["outside_completed_query_intervals_seconds"] == pytest.approx(0.7)
    frame = next(r for r in report["comparisons"] if r["variant"] == "frame_bounds_only")
    assert frame["resolved"] == 3 and frame["unknown"] == 6


@pytest.mark.parametrize("kind", ("missing_batch", "duplicate_batch", "missing_query", "wrong_binary"))
def test_summary_rejects_denominator_changes(kind):
    batches, gold = mock_batches()
    if kind == "missing_batch":
        batches.pop()
    elif kind == "duplicate_batch":
        batches[1] = deepcopy(batches[0])
    elif kind == "missing_query":
        batches[0]["queries"].pop()
    else:
        batches[0]["queries"][0]["binary_sha256"] = "x" * 64
    with pytest.raises(ValueError):
        summarize_batches(batches, gold)
