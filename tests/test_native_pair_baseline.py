"""Baseline accounting and cross-platform bootstrap of retained experiment code."""
import importlib.util
import json

import pytest

from scripts import measure_native_pair_baseline as baseline
from scripts.measure_native_pair_baseline import case_costs


def row(case, status="excluded_within_scope", start=10.0, end=10.8):
    events = [{"event": "policy_choice", "backend": "concrete_enumeration"}]
    if start is not None:
        events.append({"event": "attempt_event", "payload": {"event": "operation_opened", "time": start}})
    if end is not None:
        events.append({"event": "attempt_event", "payload": {"event": "discard_cleanup_finished", "time": end}})
    return {"case": case, "status": status, "events": events, "query_wall_seconds": 1.5}


def test_unavailable_predictions_and_unknown_queries_remain_in_cost_denominator():
    costs = case_costs([row("without_types"), row("with_types", "unknown")],
                      {"without_types": False, "with_types": True, "not_run": False})
    assert costs["without_types"]["trials"] == costs["without_types"]["resolved"] == 1
    assert costs["with_types"]["trials"] == costs["with_types"]["unknown"] == 1
    assert costs["with_types"]["resolved"] == 0
    assert costs["not_run"]["trials"] == 0
    assert costs["not_run"]["median_query_wall_seconds"] is None


def test_pre_fallback_elapsed_requires_ordered_discard_receipts():
    costs = case_costs([row("valid"), row("missing", end=None), row("reversed", end=9.0)],
                      {"valid": True, "missing": True, "reversed": True})
    assert abs(costs["valid"]["observed_pre_fallback_seconds"][0] - 0.8) < 1e-12
    assert costs["missing"]["fallback_trials"] == costs["reversed"]["fallback_trials"] == 1
    assert costs["missing"]["observed_pre_fallback_seconds"] == []
    assert costs["reversed"]["observed_pre_fallback_seconds"] == []


@pytest.mark.skipif(not (baseline.LEGACY / "run.py").is_file(), reason="Local frozen receipts required")
def test_full_archived_bootstrap_accepts_foreign_path_dictionary_keys(monkeypatch):
    """Reverse the host's key spelling while exercising the actual archived import chain."""
    original_loads = json.loads
    original_spec = importlib.util.spec_from_file_location

    def foreign_keys(value):
        if isinstance(value, dict):
            def other_style(key):
                if baseline.os.name == "nt" and key[:3].lower() in ("d:/", "d:\\"):
                    return "/mnt/d/" + key[3:].replace("\\", "/")
                if baseline.sys.platform.startswith("linux") and key.startswith("/mnt/d/"):
                    return "D:\\" + key[7:].replace("/", "\\")
                return key
            return {other_style(key): foreign_keys(item) for key, item in value.items()}
        if isinstance(value, list):
            return [foreign_keys(item) for item in value]
        return value

    def foreign_loads(*args, **kwargs):
        return foreign_keys(original_loads(*args, **kwargs))

    monkeypatch.setattr(json, "loads", foreign_loads)
    # Bootstrap only reads receipts; no temporary output directory is necessary.
    panel = baseline.controller(baseline.SCRATCH / "path-key-bootstrap-regression").batch.iso.load_panel()
    assert panel.PROVEN == "excluded_within_scope"
    assert importlib.util.spec_from_file_location is original_spec
    assert json.loads is foreign_loads


def test_archive_key_lookup_preserves_recorded_data_and_rejects_ambiguity():
    value = {"hashes": {"D:\\work\\run.py": "a" * 64}, "binary": "D:\\work\\program.elf"}
    adapted = baseline.portable_archive_keys(value)
    assert adapted["hashes"]["/mnt/d/work/run.py"] == "a" * 64
    assert json.dumps(adapted, sort_keys=True) == json.dumps(value, sort_keys=True)
    assert adapted["binary"] == value["binary"]
    with pytest.raises(KeyError):
        adapted["hashes"]["/mnt/d/work/another.py"]
    with pytest.raises(ValueError, match="Ambiguous"):
        baseline.portable_archive_keys({"D:\\work\\run.py": "a", "/mnt/d/work/run.py": "b"})


@pytest.mark.skipif(not (baseline.LEGACY / "run.py").is_file(), reason="Local frozen receipts required")
def test_full_archived_bootstrap_still_rejects_a_wrong_recorded_hash(monkeypatch):
    original_loads = json.loads

    def wrong_digest(*args, **kwargs):
        value = original_loads(*args, **kwargs)
        if isinstance(value, dict) and isinstance(value.get("hashes"), dict):
            for name in value["hashes"]:
                if baseline.archive_path_identity(name) == baseline.archive_path_identity(
                        baseline.linux_path(baseline.ARCHIVE_READER)):
                    value["hashes"][name] = "0" * 64
        return value

    monkeypatch.setattr(json, "loads", wrong_digest)
    with pytest.raises(ValueError, match="Archived worker changed"):
        baseline.controller(baseline.SCRATCH / "path-key-wrong-hash-regression").batch.iso.load_panel()
