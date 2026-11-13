"""Mechanism and isolation checks; synthetic type inputs do not represent GNN results."""

from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import time
import uuid

import pytest

from benchmarks.selective_analysis.mechanisms import make_mechanisms
from src.selective_analysis.contracts import Checkpoint, Query
from src.selective_analysis.operations import BinaryChecker, BudgetExpired
from src.selective_analysis.runner import run_query
from src.selective_analysis.scheduler import select_action
from src.selective_analysis.types import TypeInformationUnavailable, TypeView, load_type_view


ROOT = Path(__file__).resolve().parents[1]


class WorkspaceTempFactory:
    """Use normal workspace directory permissions on the Windows sandbox."""
    def mktemp(self, name):
        path = ROOT.parent / ".scratch" / "selective_analysis" / "tests" / (name + "-" + uuid.uuid4().hex[:12])
        path.mkdir(parents=True)
        return path


@pytest.mark.parametrize("index", range(12))
def test_local_bounds_only_proves_valid_exclusions_on_existing_cases(cases, index):
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    query = cases[0][index]
    checker = LocalBoundsChecker(query)
    result = checker.check(time.monotonic() + 5)
    expected = cases[1]["labels"][index]["expected"]
    assert result["status"] == ("excluded_within_scope" if expected == "excluded_within_scope" else "unknown")
    if result["status"] == "excluded_within_scope":
        validated = checker.validate(result, time.monotonic() + 5)
        assert validated["validation"] == "fresh_byte_decoded_abstract_recheck"
        assert validated["native_replay"] == "not_attempted"


def local_bounds_fixture(tmp_path, prefix, minimum=0, maximum=15):
    from benchmarks.selective_analysis.mechanisms import BASE, TEXT, DATA, Code, elf_bytes
    from src.selective_analysis.contracts import InputRange, file_hash
    code = Code()
    code.emit(prefix)
    code.lea()
    code.write()
    code.emit("c3")
    path = tmp_path / "unit-only.elf"
    path.write_bytes(elf_bytes(code.finish()))
    return Query("unit-only", str(path), file_hash(path), TEXT - BASE,
                 TEXT - BASE + code.write_offset, DATA - BASE, 8,
                 (InputRange("rdi", minimum, maximum),))


@pytest.mark.parametrize("prefix,minimum,maximum", [
    ("48 83 ef 01", 0, 7),  # Underflow must not turn 0..7 minus one into an in-bounds range.
    ("66 31 ff", 1 << 32, (1 << 32) + 7),  # Clearing DI does not clear upper RDI bits.
    ("48 83 c4 08", 0, 7),  # A modified return stack cannot be discharged as a normal return.
    ("48 83 ff 08 48 83 c6 01 73 0b", 0, 15),  # ADD changes CF: JAE skips the write, not just zero bytes.
])
def test_local_bounds_retains_unknown_on_unsound_shortcuts(tmp_path, prefix, minimum, maximum):
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    query = local_bounds_fixture(tmp_path, prefix, minimum, maximum)
    assert LocalBoundsChecker(query).check(time.monotonic() + 5)["status"] == "unknown"


def test_local_bounds_handles_exact_wrap_and_32bit_zero_extension(tmp_path):
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    # MAX64 + 1 is exactly zero, rather than a negative or an unbounded mathematical integer.
    query = local_bounds_fixture(tmp_path, "48 83 c7 01", (1 << 64) - 1, (1 << 64) - 1)
    assert LocalBoundsChecker(query).check(time.monotonic() + 5)["status"] == "excluded_within_scope"
    query = local_bounds_fixture(tmp_path, "31 ff", 1 << 32, (1 << 32) + 7)
    assert LocalBoundsChecker(query).check(time.monotonic() + 5)["status"] == "excluded_within_scope"


def test_local_bounds_certificates_are_query_bound_and_recomputed(cases, monkeypatch):
    from copy import deepcopy
    from src.selective_analysis.contracts import fingerprint
    from src.selective_analysis.local_bounds import LocalBoundsChecker
    checker = LocalBoundsChecker(cases[0][1])
    result = checker.check(time.monotonic() + 5)
    # Validation reconstructs decoding and state instead of trusting the analysis object.
    monkeypatch.setattr(checker, "decode", lambda pc: pytest.fail("Reused analysis decoder"))
    assert checker.validate(result, time.monotonic() + 5)["status"] == "excluded_within_scope"
    altered = deepcopy(result)
    altered["certificate"]["discharged_writes"][0]["address_interval"][1] += 1
    altered["certificate_sha256"] = fingerprint(altered["certificate"])
    with pytest.raises(ValueError, match="fresh byte-decoded"):
        checker.validate(altered, time.monotonic() + 5)
    with pytest.raises(ValueError, match="mismatched"):
        LocalBoundsChecker(cases[0][5]).validate(result, time.monotonic() + 5)
    with pytest.raises(TimeoutError, match="budget"):
        LocalBoundsChecker(cases[0][1]).check(time.monotonic() - 1)


def test_controls_use_fresh_full_check_and_pay_for_failed_bounds(cases):
    from src.selective_analysis.controls import run_control
    positive = cases[0][0]
    combined = run_control(positive, "bounds_then_expanded", 5)
    assert combined["result"]["status"] == "violation"
    assert combined["result"]["validation_reused_prefix_steps"] == 0
    assert [e["operation_id"] for e in combined["ledger"] if e["event"] == "action_selected"] == ["local_bounds", "expanded_paths"]
    assert combined["costs_seconds"]["type_acquisition"] == 0
    assert sum(combined["costs_seconds"].values()) <= combined["charged_seconds"] + 0.001
    expanded = run_control(positive, "expanded_only", 5)
    assert [e["operation_id"] for e in expanded["ledger"] if e["event"] == "action_selected"] == ["expanded_paths"]
    assert expanded["result"]["reused_prefix_steps"] == 0


def test_bounds_control_does_not_construct_symbolic_checker(cases, monkeypatch):
    from src.selective_analysis.controls import run_control
    monkeypatch.setattr(BinaryChecker, "__init__", lambda *a, **k: pytest.fail("Loaded full checker"))
    result = run_control(cases[0][1], "bounds_only", 5)
    assert result["result"]["status"] == "excluded_within_scope"
    assert result["result"]["validation"] == "fresh_byte_decoded_abstract_recheck"


@pytest.fixture(scope="module")
def tmp_path_factory():
    return WorkspaceTempFactory()


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp("case")


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    path = make_mechanisms(tmp_path_factory.mktemp("elf-mechanisms"))
    raw = json.loads(path.read_text())
    queries = [Query.from_dict(q, path.parent) for q in raw["queries"]]
    gold = json.loads((path.parent / "gold.json").read_text())
    return queries, gold


def test_runtime_contract_rejects_gold_and_changed_binary(cases):
    query = cases[0][0]
    with pytest.raises(ValueError, match="Unexpected runtime"):
        Query.from_dict({**asdict(query), "expected": "violation"})
    with pytest.raises(ValueError, match="hash differs"):
        Query.from_dict({**asdict(query), "binary_sha256": "0" * 64})
    with pytest.raises(ValueError, match="scope"):
        replace(query, scope="whole_program")


@pytest.mark.parametrize("index", range(12))
def test_actual_binary_bounds_checks_and_fresh_validation(cases, index):
    queries, gold = cases
    checker = BinaryChecker(queries[index])
    result = checker.check(128, time.monotonic() + 10)
    assert result["status"] == gold["labels"][index]["expected"]
    checked = checker.validate(result, 128, time.monotonic() + 10)
    assert checked["validation"] != "no_decisive_evidence"
    if result["status"] == "violation":
        assert checked["native_replay"] == "not_attempted"
        assert result["length"] == 1


def test_incomplete_exploration_is_not_exclusion(cases):
    checker = BinaryChecker(cases[0][6])
    partial = checker.check(8, time.monotonic() + 10)
    assert partial["status"] == "unknown"
    assert not partial["complete"]
    assert checker.check(128, time.monotonic() + 10)["status"] == "violation"
    with pytest.raises(BudgetExpired):
        checker.check(128, time.monotonic() - 1)


def test_query_target_must_really_be_a_store(cases):
    with pytest.raises(ValueError, match="VEX Store"):
        BinaryChecker(replace(cases[0][0], write_rva=cases[0][0].entry_rva))


def test_angr_dependency_adapter_tracks_temporaries(cases):
    from src.selective_analysis.dependencies import inspect_dependencies
    query = cases[0][4]
    result = inspect_dependencies(BinaryChecker(query).project, query)
    assert result["backend"] == "angr_reaching_definitions"
    assert result["track_tmps"]
    assert result["definition_count"] > 0 and result["edge_count"] > 0
    assert result["completeness"] == "local_approximation_not_a_relevance_proof"
    ids = {d["definition_id"] for d in result["definitions"]}
    assert len(ids) == result["definition_count"]
    assert len(result["edges"]) == result["edge_count"]
    assert all(edge["source"] in ids and edge["target"] in ids for edge in result["edges"])
    assert not result["prefix_plan"]["allows_instruction_skipping"]


def test_shared_selector_has_a_functional_no_type_baseline(cases):
    checkpoint = Checkpoint(cases[0][0].contract_hash)
    b, b_scores = select_action(checkpoint, "B", TypeView())
    c, _ = select_action(checkpoint, "C", TypeView(("char*",), (), "synthetic_test"))
    d, _ = select_action(checkpoint, "D", TypeView(("char*", "i64"), (0.5, 0.5), "synthetic_test"))
    assert b.operation_id == "bounded_paths"
    assert c.operation_id == "definitions"
    assert d.operation_id == "bounded_paths"
    assert all(s["structural_utility"] > 0 and s["type_support"] == 0 for s in b_scores)
    with pytest.raises(ValueError, match="A/B"):
        select_action(checkpoint, "B", TypeView(("char*",)))
    with pytest.raises(ValueError, match="without scores"):
        select_action(checkpoint, "C", TypeView(("char*",), (1.0,)))


def test_structural_baseline_recognizes_a_long_straight_line(cases):
    checker = BinaryChecker(cases[0][6])
    features = checker.structural_features()
    assert features["write_index_in_entry_block"] >= 8
    operation, _ = select_action(Checkpoint(cases[0][6].contract_hash), "B", TypeView(),
                                 structural_features=features)
    assert operation.operation_id == "expanded_paths"


def type_artifact(tmp_path, query):
    data = {"schema": "symbai.mapped_types.v1", "provenance": {"source": "synthetic_test"},
            "records": [{"use_site_id": query.use_site_id, "binary_sha256": query.binary_sha256,
                         "mapping_status": "reviewed", "score_kind": "raw_logits",
                         "candidates": [{"label": "char*", "rank": 1, "raw_score": 1.0},
                                        {"label": "i64", "rank": 2, "raw_score": 0.99}]}]}
    path = tmp_path / "synthetic-types.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path, data


def test_type_views_enforce_provenance_mapping_and_real_score_kind(cases, tmp_path):
    query = cases[0][0]
    path, data = type_artifact(tmp_path, query)
    with pytest.raises(TypeInformationUnavailable, match="not genuine"):
        load_type_view(path, query, "D")
    c = load_type_view(path, query, "C", allow_synthetic=True)
    d = load_type_view(path, query, "D", allow_synthetic=True)
    assert c.labels == ("char*",) and not c.weights
    from src.selective_analysis.contracts import file_hash
    assert c.artifact_sha256 == d.artifact_sha256 == file_hash(path)
    assert len(d.weights) == 2 and sum(d.weights) == pytest.approx(1.0)
    assert not load_type_view(tmp_path / "missing", query, "B").available
    data["records"][0]["score_kind"] = "legacy_fixed_confidence"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(TypeInformationUnavailable, match="raw logits"):
        load_type_view(path, query, "D", allow_synthetic=True)
    with pytest.raises(TypeInformationUnavailable, match="mapping"):
        load_type_view(path, cases[0][1], "C", allow_synthetic=True)


def test_missing_model_is_retained_as_unknown(cases):
    for variant in ("C", "D"):
        run = run_query(cases[0][0], variant, 1)
        assert run["availability"] == "type_information_unavailable"
        assert run["result"]["status"] == "unknown"
        assert not any(e["event"] == "action_selected" for e in run["ledger"])


def test_cached_types_cannot_masquerade_as_end_to_end_inference(cases, tmp_path):
    path, _ = type_artifact(tmp_path, cases[0][0])
    run = run_query(cases[0][0], "D", 1, "end_to_end", path, allow_synthetic=True)
    assert run["availability"] == "type_information_unavailable"
    assert "Online GNN" in run["result"]["reason"]


def test_real_operation_ledger_and_type_free_checker(cases):
    query = cases[0][0]
    run = run_query(query, "A", 5)
    assert run["result"]["status"] == "violation"
    selected = [e for e in run["ledger"] if e["event"] == "action_selected"]
    finished = [e for e in run["ledger"] if e["event"] == "action_finished"]
    assert selected[0]["operation_id"] == "definitions"
    assert len(selected) == len(finished)
    assert len({e["checkpoint_after"] for e in finished}) == len(finished)
    assert all(e["execution_seconds"] >= 0 and e["validation_seconds"] >= 0 for e in finished)
    assert finished[-1]["outcome"]["validation"] == "concrete_input_modeled_reexecution"


def test_hard_timeout_has_a_result_record_and_preserves_denominator(cases, tmp_path):
    script = load_script("run_selective_pilot")
    run = script.run_isolated(cases[0][0], "B", 0.001, "end_to_end", tmp_path)
    assert run["result"]["status"] == "unknown"
    assert run["availability"] == "execution_failed"
    assert run["result"]["reason"] == "hard_process_timeout"
    # Killed workers still pay parent cleanup and result recovery, just like successes.
    assert run["charged_seconds"] == run["elapsed_wall_seconds"] == run["process_wall_seconds"]
    assert len(list(tmp_path.glob("*/result.json"))) == 1


def test_offline_evaluation_rejects_dropped_queries_and_duplicates():
    evaluator = load_script("evaluate_selective_pilot")
    gold = {"labels": [{"query_id": "q", "binary_sha256": "h", "expected": "violation"}]}
    run = {"query_id": "q", "binary_sha256": "h", "variant": "D", "regime": "information_only",
           "budget_seconds": 1, "result": {"status": "unknown"}, "availability": "type_information_unavailable",
           "elapsed_wall_seconds": 0.1, "type_source": "unavailable"}
    report = evaluator.evaluate([run], gold)["comparisons"][0]
    assert report["queries"] == report["unknown"] == report["unavailable"] == 1
    assert report["coverage"] == 0
    with pytest.raises(ValueError, match="duplicate"):
        evaluator.evaluate([run, run], gold)
    gold["labels"].append({"query_id": "q2", "binary_sha256": "h2", "expected": "violation"})
    with pytest.raises(ValueError, match="Missing fixed queries"):
        evaluator.evaluate([run], gold)


def test_raw_logit_export_preserves_source_values_and_review_is_required(cases):
    exporter = load_script("export_tygr_candidates")
    mapper = load_script("map_tygr_candidates")
    packed = exporter.pack_logits([[2.0, 1.0, -1.0], [0.0, 3.0, 1.0]], ["i64", "char*", "f32"], 2)
    assert packed["raw_value_node_logits"][0] == [2.0, 1.0, -1.0]
    assert packed["candidates"][0]["label"] == "char*"
    assert packed["candidates"][0]["raw_score"] == 2.0
    with pytest.raises(ValueError, match="Non-finite"):
        exporter.pack_logits([[float("nan")]], ["i64"], 1)
    query = cases[0][0]
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256,
           "provenance": {"source": "tygr_glowgnn"}, "records": [{"prediction_id": "p", **packed}]}
    with pytest.raises(ValueError, match="review"):
        mapper.map_candidates(raw, [query], {"mappings": [{"use_site_id": query.use_site_id, "prediction_id": "p"}]})


def test_tygr_fetch_supplies_pinned_host_trust_before_clone(tmp_path, monkeypatch):
    """Replay the reported Git failure at the actual fetch/subprocess boundary."""
    import base64
    import hashlib
    import shlex
    import subprocess
    script = load_script("run_wsl_pilot")
    monkeypatch.setattr(script, "ROOT", tmp_path)
    output = tmp_path / "run with spaces"
    output.mkdir()

    class HostTrustReady(Exception):
        pass

    def clone_probe(command, **kwargs):
        assert command[0:2] == ["git", "clone"]
        words = shlex.split(kwargs["env"]["GIT_SSH_COMMAND"])
        options = dict(words[i + 1].split("=", 1) for i, word in enumerate(words) if word == "-o")
        if options.get("StrictHostKeyChecking") != "yes" or "UserKnownHostsFile" not in options:
            # Captured symptom: the noninteractive first clone has no trusted host entry.
            kwargs["stdout"].write("Host key verification failed.\n")
            raise subprocess.CalledProcessError(128, command, stderr="Host key verification failed.")
        hostfile = Path(options["UserKnownHostsFile"].strip('"'))
        hostname, algorithm, encoded = hostfile.read_text(encoding="ascii").split()
        assert hostname == "github.com" and algorithm == "ssh-ed25519"
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(encoded)).digest()).decode().rstrip("=")
        assert fingerprint == "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
        assert options["HostKeyAlgorithms"] == "ssh-ed25519"
        assert hostfile.is_relative_to(output)
        raise HostTrustReady()  # Stop before authentication/network access in this regression.

    monkeypatch.setattr(script.subprocess, "run", clone_probe)
    with pytest.raises(HostTrustReady):
        script.fetch_tygr(output)


def test_tygr_host_key_pin_is_checked_before_writing(tmp_path, monkeypatch):
    script = load_script("run_wsl_pilot")
    monkeypatch.setattr(script, "GITHUB_ED25519_FINGERPRINT", "SHA256:incorrect", raising=False)
    with pytest.raises(ValueError, match="fingerprint"):
        script.github_ssh_command(tmp_path)
    assert not (tmp_path / "known_hosts").exists()


@pytest.mark.parametrize("signature", ("tuple", "expanded"))
def test_tygr_forward_never_supplies_ground_truth_labels(signature):
    exporter = load_script("export_tygr_candidates")
    prepared = object()
    graph_features = (1, 2, 3, 4, 5, 6)

    def collate(inputs):
        assert inputs == [prepared]
        return graph_features

    class TupleModel:
        def forward(self, batch):
            assert batch == graph_features + (None,)
            return "genuine_model_result"

        __call__ = forward

    class ExpandedModel:
        def forward(self, a, b, c, d, e, f, labels):
            assert (a, b, c, d, e, f) == graph_features
            assert labels is None
            return "genuine_model_result"

        __call__ = forward

    model = TupleModel() if signature == "tuple" else ExpandedModel()
    assert exporter.forward_unlabeled(model, prepared, collate, "cpu") == "genuine_model_result"


@pytest.mark.parametrize("index", range(12))
def test_dependency_preparation_preserves_existing_mechanism_outcomes(cases, index):
    checker = BinaryChecker(cases[0][index])
    fresh = checker.check(128, time.monotonic() + 10, use_prepared=False)
    evidence = checker.prepare_dependencies(time.monotonic() + 10)
    cached = checker.check(128, time.monotonic() + 10)
    assert cached["status"] == fresh["status"] == cases[1]["labels"][index]["expected"]
    checked = checker.validate(cached, 128, time.monotonic() + 10)
    assert checked["validation_reused_prefix_steps"] == 0
    if evidence["prepared_prefix"]["status"] == "ready":
        assert cached["executed_prefix_steps"] == 0
        assert cached["reused_prefix_steps"] == evidence["prepared_prefix"]["deepest_depth"]
    else:
        assert cached["reused_prefix_steps"] == 0


def test_prefix_cache_reuses_steps_without_expanding_the_precision_cap(cases):
    checker = BinaryChecker(cases[0][6])
    prepared = checker.prepare_dependencies(time.monotonic() + 10)
    assert prepared["prepared_prefix"]["status"] == "ready"
    cached = checker.check(8, time.monotonic() + 10)
    fresh = checker.check(8, time.monotonic() + 10, use_prepared=False)
    assert cached["status"] == fresh["status"] == "unknown"
    assert cached["steps"] == fresh["steps"] == 8
    assert cached["executed_prefix_steps"] == 0 and cached["reused_prefix_steps"] == 8
    assert fresh["executed_prefix_steps"] == 8 and fresh["reused_prefix_steps"] == 0


def test_exclusion_validation_does_not_consume_the_prepared_state(cases):
    checker = BinaryChecker(cases[0][5])
    prepared = checker.prepare_dependencies(time.monotonic() + 10)
    assert prepared["prepared_prefix"]["status"] == "ready"
    cached = checker.check(128, time.monotonic() + 10)
    assert cached["status"] == "excluded_within_scope"
    checker._prepared_prefix["snapshots"] = []  # Invalid cache must not affect the fresh validator.
    validated = checker.validate(cached, 128, time.monotonic() + 10)
    assert validated["validation_reused_prefix_steps"] == 0
    assert validated["validation_executed_prefix_steps"] > 0


def test_prepared_prefix_rejects_a_different_query(cases):
    checker = BinaryChecker(cases[0][0])
    checker.prepare_dependencies(time.monotonic() + 10)
    assert checker._prepared_prefix is not None
    checker.query = replace(checker.query, capacity=16)
    with pytest.raises(ValueError, match="another query"):
        checker.check(128, time.monotonic() + 10)


def test_candidate_identity_and_disagreement_survive_same_family_projection(cases):
    c = TypeView(("char*",), (), "synthetic_test")
    d = TypeView(("char*", "struct*", "void**"), (0.8, 0.15, 0.05), "synthetic_test",
                 raw_scores=(3.0, 1.0, 0.0))
    c_features, d_features = c.selector_features(), d.selector_features()
    assert c.role_support("pointer") == pytest.approx(d.role_support("pointer"))
    assert c_features["candidate_disagreement"] is None  # No scores means unknown diversity.
    assert d_features["candidate_disagreement"] == pytest.approx(0.335)
    assert d_features["label_weights"] == {"char*": 0.8, "struct*": 0.15, "void**": 0.05}
    assert d_features["raw_score_margin"] == 2.0
    checkpoint = Checkpoint(cases[0][0].contract_hash)
    _, c_scores = select_action(checkpoint, "C", c)
    _, d_scores = select_action(checkpoint, "D", d)
    c_defs = next(row for row in c_scores if row["operation_id"] == "definitions")
    d_defs = next(row for row in d_scores if row["operation_id"] == "definitions")
    assert d_defs["score"] > c_defs["score"]
    assert not TypeView().selector_features()["available"]


def test_top1_selector_view_rejects_raw_model_scores(cases):
    with pytest.raises(ValueError, match="without scores"):
        select_action(Checkpoint(cases[0][0].contract_hash), "C",
                      TypeView(("char*",), source="synthetic_test", raw_scores=(2.0,)))


def test_expired_preparation_cannot_install_a_prefix(cases):
    checker = BinaryChecker(cases[0][0])
    with pytest.raises(TimeoutError, match="deadline"):
        checker.prepare_dependencies(time.monotonic() - 1)
    assert checker._prepared_prefix is None


def online_provider_fixture(tmp_path, query, mode="normal"):
    """Controlled process fixture, never an empirical neural result."""
    from src.selective_analysis.contracts import file_hash
    import sys
    source = tmp_path / "fixture_tygr/src/methods/glow/preproc.py"
    source.parent.mkdir(parents=True)
    source.write_text("# test fixture only\n", encoding="utf-8")
    model = tmp_path / "fixture_weights"
    model.write_bytes(b"controlled process test, not trained weights")
    location = {"low_pc": query.entry_rva, "high_pc": query.write_rva + 8,
                "location_class": "CfaLocation", "location_register": None, "location_argument": -24}
    mapping = {"mappings": [{"prediction_id": "fixture", "use_site_id": query.use_site_id,
                            "reviewed_by": "test fixture", "evidence": "controlled location",
                            "expected_identity": {"function_address": query.entry_rva, "locations": [location]}}]}
    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(json.dumps(mapping), encoding="utf-8")
    config = {"schema": "symbai.online_tygr.v1", "python": sys.executable,
              "tygr_root": str(source.parents[3]), "model": str(model), "model_sha256": file_hash(model),
              "mapping": str(mapping_file), "top_k": 2, "device": "cpu"}
    path = tmp_path / "online.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    stub = tmp_path / "controlled_export.py"
    stub.write_text('''import json,sys,time
from pathlib import Path
output,nonce,template,mode=sys.argv[1:]
if mode=="slow": time.sleep(5)
data=json.loads(template)
data["acquisition_id"]="stale" if mode=="stale" else nonce
if mode=="relocated": data["records"][0]["locations"][0]["location_argument"]=-32
Path(output).write_text(json.dumps(data),encoding="utf-8")
''', encoding="utf-8")
    raw = {"schema": "symbai.tygr_raw.v1", "binary_sha256": query.binary_sha256,
           "provenance": {"source": "tygr_glowgnn", "model_sha256": config["model_sha256"],
                          "decoder": "independent", "ground_truth_labels_supplied_to_model": False},
           "records": [{"prediction_id": "fixture", "function_address": query.entry_rva,
                        "locations": [location], "score_kind": "raw_logits",
                        "candidates": [{"label": "char*", "rank": 1, "raw_score": 3.0},
                                       {"label": "i64", "rank": 2, "raw_score": 1.0}]}]}
    def command(config, query, raw_path, scratch, nonce):
        return [sys.executable, "-B", str(stub), str(raw_path), nonce, json.dumps(raw), mode]
    return path, command


def test_online_provider_runs_a_fresh_process_and_projects_variant_views(cases, tmp_path, monkeypatch):
    from src.selective_analysis import online_types
    config, command = online_provider_fixture(tmp_path, cases[0][0])
    monkeypatch.setattr(online_types, "_export_command", command)
    events = []
    emit = lambda event, **payload: events.append((event, payload))
    d, first = online_types.acquire_type_view(cases[0][0], "D", config, tmp_path / "first",
                                            time.monotonic() + 5, emit)
    c, second = online_types.acquire_type_view(cases[0][0], "C", config, tmp_path / "second",
                                             time.monotonic() + 5, emit)
    assert first["acquisition_id"] != second["acquisition_id"]
    assert len(d.weights) == 2 and len(d.raw_scores) == 2
    assert c.labels == ("char*",) and not c.weights and not c.raw_scores
    assert first["elapsed_seconds"] >= first["export_wall_seconds"] > 0
    assert sum(event == "type_export_started" for event, _ in events) == 2
    assert (tmp_path / "first/raw-types.json").is_file()


@pytest.mark.parametrize("mode", ("stale", "relocated"))
def test_online_provider_rejects_stale_or_relocated_predictions(cases, tmp_path, monkeypatch, mode):
    from src.selective_analysis import online_types
    config, command = online_provider_fixture(tmp_path, cases[0][0], mode)
    monkeypatch.setattr(online_types, "_export_command", command)
    error = TypeInformationUnavailable if mode == "stale" else ValueError
    with pytest.raises(error, match="identity"):
        online_types.acquire_type_view(cases[0][0], "D", config, tmp_path / "attempt",
                                      time.monotonic() + 5, lambda *args, **kwargs: None)
    assert not (tmp_path / "attempt/mapped-types.json").exists()


def test_online_acquisition_timeout_is_unknown_and_paid(cases, tmp_path, monkeypatch):
    from src.selective_analysis import online_types
    config, command = online_provider_fixture(tmp_path, cases[0][0], "slow")
    monkeypatch.setattr(online_types, "_export_command", command)
    result = run_query(cases[0][0], "D", 0.1, "end_to_end",
                       online_config=config, acquisition_dir=tmp_path / "attempt")
    assert result["result"]["status"] == "unknown"
    assert result["result"]["reason"] == "budget_exhausted_during_type_acquisition"
    assert result["costs_seconds"]["type_acquisition"] > 0
    assert result["charged_seconds"] >= result["costs_seconds"]["type_acquisition"]
    assert not any(event["event"] == "action_selected" for event in result["ledger"])


def test_no_type_baseline_does_not_read_online_model_configuration(cases, tmp_path):
    result = run_query(cases[0][0], "B", 5, "end_to_end",
                       online_config=tmp_path / "does-not-exist.json")
    assert result["result"]["status"] == "violation"
    assert result["costs_seconds"]["type_acquisition"] == 0
    assert not result["type_identity"]
    assert not any(event["event"] == "type_export_started" for event in result["ledger"])


def test_online_provider_requires_a_location_anchor_before_export(cases, tmp_path, monkeypatch):
    from src.selective_analysis import online_types
    config, _ = online_provider_fixture(tmp_path, cases[0][0])
    mapping = json.loads((tmp_path / "mapping.json").read_text())
    del mapping["mappings"][0]["expected_identity"]
    (tmp_path / "mapping.json").write_text(json.dumps(mapping))
    def forbidden(*args, **kwargs):
        raise AssertionError("No export should start before review validation")
    monkeypatch.setattr(online_types, "_export_command", forbidden)
    with pytest.raises(TypeInformationUnavailable, match="anchor"):
        online_types.acquire_type_view(cases[0][0], "D", config, tmp_path / "attempt",
                                      time.monotonic() + 5, lambda *args, **kwargs: None)


@pytest.mark.parametrize("variant", ("C", "D"))
def test_end_to_end_query_includes_acquisition_before_selecting(cases, tmp_path, monkeypatch, variant):
    from src.selective_analysis import online_types
    config, command = online_provider_fixture(tmp_path, cases[0][0])
    monkeypatch.setattr(online_types, "_export_command", command)
    result = run_query(cases[0][0], variant, 5, "end_to_end",
                       online_config=config, acquisition_dir=tmp_path / "attempt")
    assert result["result"]["status"] == "violation"
    assert result["type_source"] == "tygr_glowgnn"  # Controlled fixture provenance, not a neural experiment.
    assert result["costs_seconds"]["type_acquisition"] > 0
    assert sum(result["costs_seconds"].values()) <= result["charged_seconds"] + 0.001
    events = [row["event"] for row in result["ledger"]]
    assert events.index("type_mapping_finished") < events.index("action_selected")
    if variant == "C":
        selected = next(row for row in result["ledger"] if row["event"] == "action_selected")
        assert selected["type_features"]["raw_scores"] == {}


@pytest.mark.parametrize("invalid", ("cached_config", "changed_model"))
def test_online_provider_rejects_cached_config_or_changed_model(cases, tmp_path, invalid):
    from src.selective_analysis import online_types
    config, _ = online_provider_fixture(tmp_path, cases[0][0])
    value = json.loads(config.read_text())
    if invalid == "cached_config":
        value["cached_types"] = "old.json"
        config.write_text(json.dumps(value))
    else:
        Path(value["model"]).write_bytes(b"changed weights")
    with pytest.raises(TypeInformationUnavailable):
        online_types.acquire_type_view(cases[0][0], "D", config, tmp_path / "attempt",
                                      time.monotonic() + 5, lambda *args, **kwargs: None)
    assert not (tmp_path / "attempt/raw-types.json").exists()


def test_hard_timeout_never_appears_as_free_model_acquisition():
    evaluator = load_script("evaluate_selective_pilot")
    gold = {"labels": [{"query_id": "q", "binary_sha256": "h", "expected": "violation"}]}
    run = {"query_id": "q", "binary_sha256": "h", "variant": "D", "regime": "end_to_end",
           "budget_seconds": 1, "result": {"status": "unknown", "reason": "hard_process_timeout"},
           "availability": "execution_failed", "elapsed_wall_seconds": 1.1, "type_source": "unknown",
           "online_acquisition_requested": True}
    row = evaluator.evaluate([run], gold)["comparisons"][0]
    assert row["timeouts"] == row["unknown"] == row["queries"] == 1
    assert row["type_acquisition_seconds"] is None
