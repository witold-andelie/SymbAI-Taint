"""Prospective panel scope, real instruction decoding and pre-forward input guards."""

import ast
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from scripts import export_typed_complementarity as exporter
from scripts import run_typed_complementarity as cli
from scripts.export_tygr_candidates import pack_logits
from src.selective_analysis import typed_complementarity as panel
from src.selective_analysis.workspace import SCRATCH

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def root():
    path = SCRATCH / "tests" / ("typed-v21-" + uuid.uuid4().hex)
    path.mkdir(parents=True)
    return path


@pytest.fixture
def specs():
    return cli.read(REPO / cli.PANEL / "cases.json")


@pytest.mark.parametrize("change", ["order", "gold", "capacity", "bounds", "boolean", "extra_root"])
def test_fixed_three_case_scope_rejects_outcome_or_scope_changes(specs, change):
    if change == "order": specs["cases"].reverse()
    elif change == "gold": specs["cases"][0]["expected"] = "excluded_within_scope"
    elif change == "capacity": specs["cases"][0]["capacity"] = 8
    elif change == "bounds": specs["cases"][1]["input"]["maximum"] = 127
    elif change == "boolean": specs["cases"][0]["input"]["minimum"] = False
    else: specs["gold"] = {}
    with pytest.raises(ValueError): panel.validate_specs(specs)


class Segment(dict):
    def data(self):
        return self.contents


@pytest.fixture
def elf_environment(root, specs, monkeypatch):
    from elftools.elf import elffile
    # Only the ELF facade is mocked. Actual Capstone decodes all test instruction bytes.
    text = Segment(p_type="PT_LOAD", p_flags=5, p_vaddr=0x1000, p_filesz=12, p_memsz=12)
    text.contents = bytes.fromhex("c60741c3" * 3)
    data = Segment(p_type="PT_LOAD", p_flags=6, p_vaddr=0x2000, p_filesz=0x1000, p_memsz=0x1000)
    data.contents = b"\0" * 0x1000
    header = Segment(p_type="PT_LOAD", p_flags=4, p_vaddr=0, p_filesz=64, p_memsz=64)
    symbols = {}
    for index, case in enumerate(specs["cases"]):
        symbols[case["function_symbol"]] = {"st_value": 0x1000 + 4 * index, "st_size": 4,
            "st_info": {"type": "STT_FUNC"}, "st_shndx": 1}
        symbols[case["object_symbol"]] = {"st_value": 0x2000 + (0 if index == 0 else 0x400 + (index - 1) * 8),
            "st_size": case["capacity"], "st_info": {"type": "STT_OBJECT"}, "st_shndx": 2}
    sections = {".debug_info": SimpleNamespace(data=lambda: b"unit debug contents"),
        ".debug_abbrev": SimpleNamespace(data=lambda: b"unit abbreviations"),
        ".symtab": SimpleNamespace(get_symbol_by_name=lambda name: [symbols[name]] if name in symbols else None)}
    class ELF(dict):
        elfclass, little_endian = 64, True
        def iter_segments(self): return iter([header, text, data])
        def get_section_by_name(self, name): return sections.get(name)
    elf = ELF(e_type="ET_DYN", e_machine="EM_X86_64")
    monkeypatch.setattr(elffile, "ELFFile", lambda _: elf)
    binary = root / "fixture.elf"
    binary.write_bytes(b"unit ELF facade, real decoded text")
    return binary, elf, symbols, sections, text, data


def test_extracts_three_queries_without_property_engine(specs, elf_environment):
    binary, *_ = elf_environment
    result = panel.extract_typed_queries(binary, specs)
    assert [query["query_id"] for query in result["queries"]] == list(panel.CASE_IDS)
    assert [query["write_rva"] for query in result["queries"]] == [0x1000, 0x1004, 0x1008]
    assert [query["capacity"] for query in result["queries"]] == [1024, 8, 8]
    assert all(query["binary_sha256"] == cli.file_hash(binary) for query in result["queries"])


@pytest.mark.parametrize("damage", ["no_dwarf", "empty_dwarf", "non_pie", "wrong_arch", "missing_symbol",
    "wrong_capacity", "undefined_function", "unmapped_object", "unexecutable", "not_store", "partial_decode"])
def test_extraction_boundaries(specs, elf_environment, damage):
    binary, elf, symbols, sections, text, data = elf_environment
    if damage == "no_dwarf": sections.pop(".debug_info")
    elif damage == "empty_dwarf": sections[".debug_info"] = SimpleNamespace(data=lambda: b"")
    elif damage == "non_pie": elf["e_type"] = "ET_EXEC"
    elif damage == "wrong_arch": elf["e_machine"] = "EM_386"
    elif damage == "missing_symbol": symbols.pop("typed_scalar_span")
    elif damage == "wrong_capacity": symbols["scalar_output"]["st_size"] = 8
    elif damage == "undefined_function": symbols["typed_scalar_span"]["st_shndx"] = "SHN_UNDEF"
    elif damage == "unmapped_object": data["p_flags"] = 4
    elif damage == "unexecutable": text["p_flags"] = 4
    elif damage == "not_store": text.contents = bytes.fromhex("909090c3" * 3)
    else: text.contents = b"\x0f" * 12
    with pytest.raises((ValueError, IndexError)): panel.extract_typed_queries(binary, specs)


def native():
    def tensor(values, shape, dtype="torch.int64"):
        return {"device": "cpu", "dtype": dtype, "shape": shape, "values": values}
    prepared = {"node_labels": tensor([[0.0] * 31 for _ in range(2)], [2, 31], "torch.float32"),
        "edge_labels": tensor([7, 37], [2]), "edges": tensor([[0, 1], [1, 0]], [2, 2]), "var_nodes": [[1]]}
    return {"function_address": 0x1000, "variables": [{"prediction_id": "1000:0", "original_value_nodes": [1],
        "flattened_output_rows": [0], "locations": []}], "prepared": prepared,
        "batch": {**deepcopy(prepared), "num_vars": [1], "var_gather": tensor([1], [1]),
                  "var_scatter": tensor([0], [1]), "labels_supplied_to_model": False}}


def contract():
    return {"feature_width": 31, "type_count": 75, "declared_relation_count": 60, "layer_relation_capacities": [44] * 8}


def test_guard_allows_actual_saved_domain_with_unlabeled_cpu_batch():
    assert exporter.guard_native_input(native(), contract())["observed_relation_ids"] == [7, 37]


@pytest.mark.parametrize("damage", ["capacity_id", "negative_id", "gpu", "width", "nan", "endpoint", "gather", "scatter", "gold", "collation", "model"])
def test_guard_refuses_inputs_before_forward(damage):
    value, config = native(), contract()
    if damage == "capacity_id": value["batch"]["edge_labels"]["values"][1] = 53
    elif damage == "negative_id": value["batch"]["edge_labels"]["values"][0] = -1
    elif damage == "gpu": value["batch"]["node_labels"]["device"] = "cuda:0"
    elif damage == "width": value["batch"]["node_labels"]["shape"][1] = 32
    elif damage == "nan": value["batch"]["node_labels"]["values"][0][0] = float("nan")
    elif damage == "endpoint": value["batch"]["edges"]["values"][0][0] = 2
    elif damage == "gather": value["batch"]["var_gather"]["values"][0] = 2
    elif damage == "scatter": value["batch"]["var_scatter"]["values"][0] = 1
    elif damage == "gold": value["batch"]["labels_supplied_to_model"] = True
    elif damage == "collation": value["prepared"]["edge_labels"]["values"][0] = 1
    else: config["layer_relation_capacities"][0] = 60
    with pytest.raises(ValueError): exporter.guard_native_input(value, config)


def acquisition():
    n, c = native(), contract()
    packed = pack_logits([[float(i) / 10 for i in range(75)]], ["type" + str(i) for i in range(75)], 3)
    packed.update(function_address=0x1000, prediction_id="1000:0", locations=[], value_nodes=[1])
    return {"parent_receipt": {"status": "completed", "charged_seconds": 5.0}, "payload": {"candidate": {
        "status": "completed", "binary_sha256": "a" * 64, "model_sha256": cli.MODEL_HASH,
        "ground_truth_labels_supplied_to_model": False, "identities_rechecked": True,
        "provenance": {"source": "tygr_glowgnn", "locator": "dwarf_assisted", "decoder": "independent",
            "datagen_predict_phase": False, "ground_truth_labels_supplied_to_model": False},
        "forward_calls_attempted": 1, "forward_calls_completed": 1, "model_contract": c,
        "functions": [{"function_address": 0x1000, "native_input": n, "status": "completed",
            "forward_completed": True, "input_guard": exporter.guard_native_input(n, c)}], "records": [packed]}}}


def test_genuine_output_rechecks_raw_logits_and_whole_group_identity():
    assert cli.validated_acquisition(acquisition(), "a" * 64) == {0x1000: 1}


@pytest.mark.parametrize("damage", ["partial", "late", "model", "labels", "logits", "nodes", "duplicate", "forward_count"])
def test_failed_or_changed_acquisition_cannot_create_coverage(damage):
    data = acquisition()
    payload = data["payload"]["candidate"]
    if damage == "partial": payload["status"] = "collecting"
    elif damage == "late": data["parent_receipt"]["status"] = "failed"
    elif damage == "model": payload["model_sha256"] = "0" * 64
    elif damage == "labels": payload["ground_truth_labels_supplied_to_model"] = True
    elif damage == "logits": payload["records"][0]["candidates"][0]["raw_score"] += 1
    elif damage == "nodes": payload["records"][0]["value_nodes"] = [0]
    elif damage == "duplicate": payload["records"] *= 2
    else: payload["forward_calls_completed"] = 0
    with pytest.raises(ValueError): cli.validated_acquisition(data, "a" * 64)


def test_parent_keeps_missing_queries_in_denominator():
    labels = cli.read(REPO / cli.PANEL / "gold.json")
    rows = [{"case_id": name, "operations": {}} for name in panel.CASE_IDS]
    summary = cli.summarize(rows, None, labels)
    assert summary["planned_queries"] == 3 and summary["genuine_function_coverage"] == summary["typed_capability_overlap"] == 0
    assert all(not row["query_extracted"] for row in summary["cases"])
    assert summary["cold_acquisition_parent_seconds"] is None and not summary["neural_benefit_measured"]


def readiness_rows():
    labels = cli.read(REPO / cli.PANEL / "gold.json")
    rows = []
    for index, label in enumerate(labels["labels"]):
        identity = "query" + str(index)
        outcomes = ({"interval_only": "excluded_within_scope", "finite_readonly_only": "unknown", "expanded_only": "excluded_within_scope"}
                    if index == 0 else {"interval_only": "unknown", "finite_readonly_only": "excluded_within_scope" if index == 1 else "unknown",
                                       "expanded_only": "unknown" if index == 1 else "violation"})
        outcomes.update(fixed_cascade=label["expected"], reference=label["expected"])
        rows.append({"case_id": label["query_id"], "query_hash": identity,
            "query": {"entry_rva": 0x1000 + index, "binary_sha256": "a" * 64},
            "operations": {method: {"parent_receipt": {"status": "completed", "charged_seconds": 1.0},
                "payload": {"candidate": {"complete": True, "query_hash": identity, "binary_sha256": "a" * 64,
                    "method": method, "result": {"status": status}}}} for method, status in outcomes.items()}})
    return rows, labels


def test_readiness_joins_eligible_function_outputs_with_complete_operation_controls(monkeypatch):
    rows, labels = readiness_rows()
    monkeypatch.setattr(cli, "validated_acquisition", lambda *_: {0x1000 + i: 1 for i in range(3)})
    summary = cli.summarize(rows, acquisition(), labels)
    assert summary["genuine_function_coverage"] == summary["typed_capability_overlap"] == 3
    assert summary["completed_control_and_reference_trials"] == 15 and summary["wrong_decisions_including_separate_reference"] == 0
    assert summary["cold_acquisition_parent_seconds"] == 5 and summary["cold_acquisition_amortized_per_query_seconds"] == 5 / 3
    assert summary["total_fixed_control_parent_seconds"] == 3 and not summary["neural_benefit_measured"]


@pytest.mark.parametrize("damage", ["timeout", "missing", "wrong_query", "wrong_method"])
def test_incomplete_controls_cannot_manufacture_capability_overlap(monkeypatch, damage):
    rows, labels = readiness_rows()
    monkeypatch.setattr(cli, "validated_acquisition", lambda *_: {0x1000 + i: 1 for i in range(3)})
    trial = rows[0]["operations"]["finite_readonly_only"]
    if damage == "timeout": trial["parent_receipt"]["status"] = "failed"
    elif damage == "missing": rows[0]["operations"].pop("finite_readonly_only")
    elif damage == "wrong_query": trial["payload"]["candidate"]["query_hash"] = "wrong"
    else: trial["payload"]["candidate"]["method"] = "expanded_only"
    summary = cli.summarize(rows, acquisition(), labels)
    assert summary["genuine_function_coverage"] == 3 and summary["typed_capability_overlap"] == 2
    assert summary["completed_control_and_reference_trials"] == 14


def test_separate_reference_disagreement_is_reported_instead_of_masked():
    rows, labels = readiness_rows()
    rows[0]["operations"]["reference"]["payload"]["candidate"]["result"] = {"status": "violation"}
    assert cli.summarize(rows, None, labels)["wrong_decisions_including_separate_reference"] == 1


@pytest.mark.parametrize("late", [False, True])
def test_parent_clock_charges_persisted_payload_and_rejects_late_complete_worker(root, monkeypatch, late):
    clock = [0.0]
    original_write = cli.write
    def execute(command, log, cap, **_):
        assert cap == 30
        original_write(Path(command[-1]), {"complete": True, "result": {"status": "unknown"}})
        clock[0] += 1.0
        return cli.ProcessOutcome(0, False, 1.0)
    def write(path, value):
        original_write(path, value)
        if path.name == "payload.json": clock[0] += 30 if late else 1
    monkeypatch.setattr(cli, "write", write)
    monkeypatch.setattr(cli, "run_bounded", execute)
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    result = cli.run_stage(["unit-python"], {"schema": "unit"}, root / "worker", 30)
    assert result["parent_receipt"]["charged_seconds"] == (31.0 if late else 2.0)
    assert result["parent_receipt"]["status"] == ("failed" if late else "completed")


def test_native_worker_remains_python38_compatible_and_framework_free_on_import():
    tree = ast.parse(Path(exporter.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))
    imports = [alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names]
    assert "torch" not in imports and "angr" not in imports


def test_complete_prepare_path_queries_package_versions_without_starting_workers(root, specs, monkeypatch):
    fake_repo = root / "repo"
    files = ["src/selective_analysis/__init__.py", "src/__init__.py", "scripts/__init__.py",
        "scripts/run_typed_complementarity.py", "scripts/export_typed_complementarity.py",
        "scripts/capture_tygr_preprocessing.py", "scripts/export_tygr_candidates.py",
        "docs/architecture/pilot_revision_v21.md", "tygr_original/src/__init__.py",
        "tygr_original/model/MODEL_base/x64.O0.base.model",
        *[cli.PANEL + "/" + name for name in ("cases.c", "constants.c", "gold.json")]]
    for filename in files:
        path = fake_repo / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unit preparation input, never executed or loaded")
    cli.write(fake_repo / cli.PANEL / "cases.json", specs)
    monkeypatch.setattr(cli, "ROOT", fake_repo)
    monkeypatch.setattr(cli, "MODEL_HASH", cli.file_hash(fake_repo / "tygr_original/model/MODEL_base/x64.O0.base.model"))
    monkeypatch.setattr(cli, "configure_workspace", lambda: root)
    monkeypatch.setattr(cli, "version", lambda name: "unit-" + name)
    monkeypatch.setattr(cli.sys, "argv", ["run_typed_complementarity.py", "--prepare-only"])
    def never_start(*_, **__):
        raise AssertionError("Preparation must not start compilation/model/control workers")
    monkeypatch.setattr(cli, "run_bounded", never_start)
    cli.main()
    output, = root.glob("typed-complementarity-v21-*")
    summary, plan = cli.read(output / "preflight-summary.json"), cli.read(output / "run-plan.json")
    assert summary["native_workers_launched"] == summary["compiled_binaries"] == 0
    assert summary["native_predictions_performed"] is False and summary["Linux_collection_pending"] is True
    assert plan["runtime"]["angr"] == "unit-angr"
    assert summary["changed_sources"] == summary["changed_copied_sources"] == []
