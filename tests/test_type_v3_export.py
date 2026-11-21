"""Portable v3 boundary tests using two audited v2 captures, never live workers."""
import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
REAL = ROOT.parent / ".scratch/selective_analysis/route-b-type-dev-graphs-20261120T195202135627Z"
SPEC = importlib.util.spec_from_file_location("type_v3_exporter", ROOT / "scripts/export_type_v3_graphs.py")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)
RUN = subprocess.run


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    exporter.write(path, value)


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())


@pytest.fixture
def panel(request, monkeypatch):
    # The only disposable directory is inside this clone. Never use OS temp paths.
    # Keep paths below Windows MAX_PATH even for long parametrized test names.
    name = "v3-" + hashlib.sha256(request.node.nodeid.encode("ascii")).hexdigest()[:12]
    base = ROOT / ".test-output" / name
    base.resolve().relative_to((ROOT / ".test-output").resolve())
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    try:
        repo = base / "work/repo"
        scratch = repo.parent / ".scratch/selective_analysis"
        inventory = scratch / "route-b-type-corpus-v3-fixture/labels-fixture"
        inventory.mkdir(parents=True)
        for _, name in exporter.WORKER_FILES:
            copy_file(ROOT / "scripts" / name, repo / "scripts" / name)
        for name in ("type_graph_dataset.py", "variable_mapping.py", "type_corpus.py"):
            copy_file(ROOT / "src/selective_analysis" / name, repo / "src/selective_analysis" / name)
        copy_file(ROOT / "scripts/verify_type_v3_export.py", repo / "scripts/verify_type_v3_export.py")
        preregistration = repo / "benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md"
        copy_file(exporter.PREREGISTRATION, preregistration)
        upstream = repo / "tygr_original/src/evidence.py"
        upstream.parent.mkdir(parents=True)
        upstream.write_bytes(b"# Source-inventory fixture; never executed.\n")
        sources = {"src/evidence.py": exporter.sha(upstream)}
        mapping = scratch / "route-b-type-mapping-fixture"
        save(mapping / "inih/request.json", {"source_inventory": sources})
        save(mapping / "plan.json", {"pins": {exporter.linux(upstream): exporter.sha(upstream)}})
        save(mapping / "independent-audit.json", {"reviewed_functions": 4,
            "location_readout_consistent_source_variables": 8, "evaluation_projects_executed": False,
            "model_loaded": False, "sha256": {"inih/request.json": exporter.sha(mapping / "inih/request.json")}})
        assert REAL.is_dir(), "Required audited local v2 fixture is absent"
        vocabulary = exporter.read(REAL / "vocabulary.json")
        copy_file(REAL / "vocabulary.json", scratch / exporter.V1_DATASET / "vocabulary.json")
        save(scratch / exporter.V1_DATASET / "dataset.json", {
            "vocabulary": {"path": "vocabulary.json", "sha256": exporter.sha(REAL / "vocabulary.json")}})
        cases, locations, raw_by_address, artifacts = [], {}, {}, {}
        for project, split, directory in (("hashmap", "train", "046-sds-404110"),
                                           ("parson", "development", "048-sds-404157")):
            # Preserve the complete real raw/features/supervision artifacts locally.
            staged = base / "copied-v2" / directory
            for name in ("offline-source.json", "request.json", "raw.json", "features.json", "supervision.json"):
                copy_file(REAL / directory / name, staged / name)
            source = exporter.read(staged / "offline-source.json")
            case = deepcopy(source["case"])
            case.pop("role")
            case.update(project_id=project, split=split,
                        function_id=source["case"]["function_id"].replace("sds:", project + ":", 1))
            binary = inventory / (project + "-O0.elf")
            copy_file(exporter.runtime_path(source["case"]["binary"]), binary)
            case["binary"] = exporter.linux(binary)
            variables = deepcopy(source["variables"])
            for variable in variables:
                variable["function_id"] = case["function_id"]
            save(inventory / (project + "-O0.labels.json"), {"binary_sha256": case["binary_sha256"],
                "functions": [{"function_id": case["function_id"], "name": case["function_name"],
                               "address": case["function_address"], "split": split}], "variables": variables})
            cases.append(case)
            locations[case["function_address"]] = source["locations"]
            raw_by_address[case["function_address"]] = exporter.read(staged / "raw.json")
            artifacts[case["function_id"]] = staged
        selection = {"preregistration_sha256": exporter.PREREGISTRATION_SHA256}
        save(inventory.parent / "selection.json", selection)
        manifest = {"selection_sha256": exporter.sha(inventory.parent / "selection.json")}
        save(inventory.parent / "manifest.json", manifest)
        scope = {"schema": "symbai.type_v3_export_scope.v1", "cases": cases,
            "capped_out_functions": [], "excluded_clone_functions": [],
            "candidate_functions": {"train": 1, "development": 1},
            "candidate_source_variable_records": {"train": 1, "development": 1},
            "preregistration_sha256": exporter.PREREGISTRATION_SHA256,
            "manifest_sha256": exporter.sha(inventory.parent / "manifest.json"),
            "evaluation_projects_selected": False, "labels_in_scope": False}
        save(inventory / "export-scope.json", scope)
        save(inventory / "summary.json", {"schema": "symbai.type_v3_inventory.v1", "planned_builds": 2,
                                         "inventoried_builds": 2, "failed_builds": 0})
        monkeypatch.setattr(exporter, "ROOT", repo)
        monkeypatch.setattr(exporter, "PREREGISTRATION", preregistration)
        monkeypatch.setattr(exporter, "UpstreamLabels", lambda _: SimpleNamespace(vocabulary=deepcopy(vocabulary)))
        monkeypatch.setattr(exporter, "source_facts", lambda binary, address, variables: deepcopy(locations[address]))
        # Exercise the real v1/v2 admit_supervision on the copied native captures.
        calls = []

        def worker(command, **kwargs):
            calls.append((command, kwargs))
            request_path = Path(command[command.index("--request") + 1])
            output_path = Path(command[command.index("--output") + 1])
            capture_request = exporter.read(request_path)
            save(output_path, raw_by_address[capture_request["function_address"]])
            return subprocess.CompletedProcess(command, 0)

        monkeypatch.setattr(exporter.subprocess, "run", worker)
        monkeypatch.setattr(exporter.sys, "platform", "linux")
        for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
            monkeypatch.setenv(key, str(base))
        yield SimpleNamespace(base=base, repo=repo, scratch=scratch, inventory=inventory, mapping=mapping,
                              scope=scope, calls=calls, raw=raw_by_address, artifacts=artifacts)
    finally:
        shutil.rmtree(base)


def collect(panel, monkeypatch, prepare=False):
    args = ["export_type_v3_graphs.py", "--inventory", str(panel.inventory), "--mapping", str(panel.mapping),
            "--tygr-python", sys.executable, "--function-timeout", "17"]
    if prepare:
        args.append("--prepare-only")
    monkeypatch.setattr(sys, "argv", args)
    exporter.main()
    output, = panel.scratch.glob("route-b-type-v3-graphs-*")
    return output


def audit(output):
    # Run the actual standalone verifier as an isolated Windows Python process.
    return RUN([sys.executable, "-I", "-B", str(output / "verify_type_v3_export.py")],
               cwd=output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)


def test_scope_and_mapping_valid(panel):
    assert exporter.validate_mapping(panel.mapping, panel.scratch) == panel.mapping.resolve()
    inventory, extension, scope, rows = exporter.validate_scope(panel.inventory, panel.scratch)
    assert inventory == panel.inventory.resolve() and extension == inventory.parent
    assert scope == panel.scope and len(rows) == 2
    assert exporter.sha(exporter.PREREGISTRATION) == exporter.PREREGISTRATION_SHA256


@pytest.mark.parametrize("damage", ["reviewed_functions", "location_count", "evaluation", "model", "evidence", "pin", "sources", "outside"])
def test_mapping_rejections(panel, damage):
    path = panel.mapping / "independent-audit.json"
    review = exporter.read(path)
    if damage == "reviewed_functions":
        review["reviewed_functions"] = 3
    elif damage == "location_count":
        review["location_readout_consistent_source_variables"] = 7
    elif damage in ("evaluation", "model"):
        review["evaluation_projects_executed" if damage == "evaluation" else "model_loaded"] = True
    elif damage == "evidence":
        review["sha256"]["inih/request.json"] = "0" * 64
    elif damage == "pin":
        save(panel.mapping / "plan.json", {"pins": {exporter.linux(exporter.PREREGISTRATION): "0" * 64}})
    elif damage == "sources":
        extra = panel.repo / "tygr_original/src/added.py"
        extra.write_bytes(b"# added\n")
    save(path, review)
    with pytest.raises(ValueError):
        exporter.validate_mapping(panel.mapping, panel.scratch / "elsewhere" if damage == "outside" else panel.scratch)


SCOPE_DAMAGE = ["preregistration_bytes", "selection_preregistration", "scope_preregistration", "selection_hash",
    "manifest_hash", "scope_schema", "inventory_schema", "evaluation_flag", "labels_flag", "failed_builds",
    "incomplete_builds", "planned_not_int", "inventoried_not_int", "failed_not_int", "planned_negative",
    "evaluation_split", "profile", "duplicate_function", "function_id", "function_name", "function_address",
    "labels_split", "source_count", "mapped_count", "labels_binary_hash", "binary_bytes", "binary_path",
    "function_denominator_train", "function_denominator_development", "variable_denominator_train",
    "variable_denominator_development", "denominator_shape", "denominator_type", "scope_lists", "outside",
    "inventory_directory", "corpus_directory", "project_crosses_split", "project_path"]


@pytest.mark.parametrize("damage", SCOPE_DAMAGE)
def test_scope_rejections(panel, damage):
    scope = deepcopy(panel.scope)
    case = scope["cases"][0]
    labels_path = panel.inventory / "hashmap-O0.labels.json"
    labels = exporter.read(labels_path)
    summary = exporter.read(panel.inventory / "summary.json")
    selection_path, manifest_path = panel.inventory.parent / "selection.json", panel.inventory.parent / "manifest.json"
    selection, manifest = exporter.read(selection_path), exporter.read(manifest_path)
    inventory, scratch = panel.inventory, panel.scratch
    if damage == "preregistration_bytes":
        exporter.PREREGISTRATION.write_bytes(b"changed\n")
    elif damage == "selection_preregistration":
        selection["preregistration_sha256"] = "0" * 64
    elif damage == "scope_preregistration":
        scope["preregistration_sha256"] = "0" * 64
    elif damage == "scope_schema":
        scope["schema"] = "symbai.type_dev_export_scope.v1"
    elif damage == "inventory_schema":
        summary["schema"] = "wrong"
    elif damage in ("evaluation_flag", "labels_flag"):
        scope["evaluation_projects_selected" if damage == "evaluation_flag" else "labels_in_scope"] = True
    elif damage == "failed_builds":
        summary["failed_builds"] = 1
    elif damage == "incomplete_builds":
        summary["inventoried_builds"] = 1
    elif damage in ("planned_not_int", "inventoried_not_int", "failed_not_int"):
        summary[damage.split("_")[0] + "_builds"] = True
    elif damage == "planned_negative":
        summary["planned_builds"] = summary["inventoried_builds"] = -1
    elif damage == "evaluation_split":
        case["split"] = "evaluation"
    elif damage == "profile":
        case["profile"] = "O2"
    elif damage == "duplicate_function":
        scope["cases"].append(deepcopy(case))
    elif damage in ("function_id", "function_name", "function_address"):
        case[damage] = 1 if damage == "function_address" else "different"
    elif damage == "labels_split":
        labels["functions"][0]["split"] = "development"
    elif damage in ("source_count", "mapped_count"):
        case["source_variable_records" if damage == "source_count" else "mapped_source_variable_records"] = 2
    elif damage == "labels_binary_hash":
        labels["binary_sha256"] = "0" * 64
    elif damage == "binary_bytes":
        exporter.runtime_path(case["binary"]).write_bytes(b"changed\n")
    elif damage == "binary_path":
        case["binary"] = scope["cases"][1]["binary"]
    elif damage.startswith(("function_denominator_", "variable_denominator_")):
        field = "candidate_functions" if damage.startswith("function") else "candidate_source_variable_records"
        scope[field][damage.rsplit("_", 1)[1]] += 1
    elif damage == "denominator_shape":
        scope["candidate_functions"] = 2
    elif damage == "denominator_type":
        scope["candidate_functions"]["train"] = True
    elif damage == "scope_lists":
        scope["cases"] = {}
    elif damage == "outside":
        scratch = scratch / "elsewhere"
    elif damage in ("inventory_directory", "corpus_directory"):
        inventory = scratch / "route-b-type-corpus-v3-fixture/wrong" if damage == "inventory_directory" else scratch / "wrong/labels-fixture"
        inventory.mkdir(parents=True)
    elif damage == "project_crosses_split":
        scope["cases"][1]["project_id"] = "hashmap"
    elif damage == "project_path":
        case["project_id"] = "../escape"
    save(labels_path, labels)
    save(panel.inventory / "summary.json", summary)
    save(selection_path, selection)
    manifest["selection_sha256"] = "0" * 64 if damage == "selection_hash" else exporter.sha(selection_path)
    save(manifest_path, manifest)
    scope["manifest_sha256"] = "0" * 64 if damage == "manifest_hash" else exporter.sha(manifest_path)
    save(panel.inventory / "export-scope.json", scope)
    with pytest.raises(ValueError):
        exporter.validate_scope(inventory, scratch)
    assert list(panel.scratch.glob("route-b-type-v3-graphs-*")) == []


@pytest.mark.parametrize("project", sorted(exporter.FORBIDDEN_PROJECTS))
def test_forbidden_project_rejected_before_any_labels_or_binary_open(panel, monkeypatch, project):
    scope = deepcopy(panel.scope)
    scope["cases"][0]["project_id"] = project
    save(panel.inventory / "export-scope.json", scope)
    original_read = exporter.read

    def guarded(path):
        assert str(path).endswith(("manifest.json", "selection.json", "export-scope.json", "summary.json"))
        return original_read(path)

    monkeypatch.setattr(exporter, "read", guarded)
    with pytest.raises(ValueError, match="Invalid v3 case"):
        exporter.validate_scope(panel.inventory, panel.scratch)


def test_dataset_summary_worker_and_passive_verifier(panel, monkeypatch):
    output = collect(panel, monkeypatch)
    dataset, summary, plan = (exporter.read(output / name) for name in ("dataset.json", "summary.json", "plan.json"))
    assert dataset["schema"] == "symbai.type_v3_graph_dataset.v1"
    assert summary["schema"] == "symbai.type_v3_graph_dataset_summary.v1"
    assert plan["schema"] == "symbai.type_v3_graph_dataset_plan.v1"
    assert dataset["projects"] == {"train": ["hashmap"], "development": ["parson"]}
    assert dataset["preregistration_sha256"] == exporter.PREREGISTRATION_SHA256
    assert dataset["selection_sha256"] == exporter.sha(panel.inventory.parent / "selection.json")
    assert dataset["relation_count"] == 60 and dataset["feature_width"] == 31
    for key, values in (("exported_functions", {"train": 1, "development": 1}),
                        ("admitted_source_variables", {"train": 1, "development": 1}),
                        ("supervised_value_rows", {"train": 3, "development": 3})):
        assert dataset[key] == summary[key] == values
    for key in ("planned_functions", "completed_functions", "candidate_source_variables"):
        assert summary[key] == {"train": 1, "development": 1}
    assert summary["projects"] == dataset["project_counts"]
    for project, split in (("hashmap", "train"), ("parson", "development")):
        assert summary["projects"][project] == {"split": split, "planned_functions": 1, "completed_functions": 1,
            "exported_functions": 1, "candidate_source_variables": 1, "admitted_source_variables": 1,
            "supervised_value_rows": 3}
    assert summary["development_minimum_met"] is False and summary["new_training_admitted"] == 1
    assert summary["exclusion_reasons"] == {} and summary["exclusion_reasons_by_split"] == {"train": {}, "development": {}}
    for key in ("evaluation_projects_executed", "model_loaded", "training_performed"):
        assert summary[key] is False
    assert summary["source_integrity_unchanged"] is True
    assert dataset["training_allowed"] is False and dataset["labels_separate_from_features"] is True
    assert dataset["evaluation_projects_executed"] is False
    assert len(panel.calls) == 2
    for command, kwargs in panel.calls:
        assert command[0] == sys.executable and command[1] == "-B"
        assert command[2].endswith("/source_snapshot/capture_type_mapping.py")
        assert command[3] == "--request" and command[5] == "--output"
        assert kwargs["check"] is True and kwargs["timeout"] == 17
        assert kwargs["cwd"] == output and kwargs["stderr"] == subprocess.STDOUT
    for sample in dataset["samples"]:
        directory = output / Path(sample["features"]["path"]).parent
        assert {"offline-source.json", "request.json", "raw.json", "features.json", "supervision.json"}.issubset(
            {p.name for p in directory.iterdir()})
        # Features and supervision are the original audited v2 content, apart
        # from the required source-variable function identity in supervision.
        staged = panel.artifacts[sample["function_id"]]
        assert exporter.read(directory / "features.json") == exporter.read(staged / "features.json")
        original_targets = exporter.read(staged / "supervision.json")
        original_targets["targets"][0]["source_variable_id"] = sample["function_id"] + ":" + str(original_targets["targets"][0]["die_offset"])
        assert exporter.read(directory / "supervision.json") == original_targets
    result = audit(output)
    assert result.returncode == 0, result.stdout
    independent = exporter.read(output / "independent-export-audit.json")
    assert independent["schema"] == "symbai.type_v3_graph_export_audit.v1"
    assert independent["admitted_source_variables"] == {"train": 1, "development": 1}
    assert independent["supervised_value_rows"] == {"train": 3, "development": 3}
    assert independent["exported_functions"] == {"train": 1, "development": 1}
    assert independent["projects"] == dataset["projects"] and independent["failed_or_empty_functions"] == []
    assert independent["frameworks_imported"] == []
    assert independent["evaluation_projects_executed"] is independent["training_performed"] is False
    assert not any("histogram" in k for k in independent)
    assert "dataset.json" in independent["sha256"] and independent["external_sha256"]
    assert all(not Path(p).is_absolute() for p in independent["sha256"])
    for path in output.rglob("*.json"):
        assert b"\r" not in path.read_bytes()


@pytest.mark.parametrize("damage", ["hash", "split", "scope_split", "duplicate_source_id", "duplicate_record_id",
    "duplicate_sample", "split_count", "project_count", "dataset_project_count", "missing_record", "new_training_count"])
def test_passive_verifier_rejects_damage(panel, monkeypatch, damage):
    output = collect(panel, monkeypatch)
    dataset, summary, records = (exporter.read(output / p) for p in ("dataset.json", "summary.json", "records.json"))
    if damage == "hash":
        path = output / dataset["samples"][0]["features"]["path"]
        path.write_bytes(path.read_bytes() + b" ")
    elif damage == "split":
        dataset["samples"][0]["split"] = "development"
    elif damage == "scope_split":
        records[0]["split"] = "development"
        dataset["samples"][0]["split"] = "development"
    elif damage == "duplicate_source_id":
        path = output / dataset["samples"][1]["supervision"]["path"]
        targets = exporter.read(path)
        first = exporter.read(output / dataset["samples"][0]["supervision"]["path"])
        targets["targets"][0]["source_variable_id"] = first["targets"][0]["source_variable_id"]
        save(path, targets)
        dataset["samples"][1]["supervision"]["sha256"] = exporter.sha(path)
    elif damage == "duplicate_record_id":
        records[1]["variables"][0]["source_variable_id"] = records[0]["variables"][0]["source_variable_id"]
    elif damage == "duplicate_sample":
        dataset["samples"].append(deepcopy(dataset["samples"][0]))
    elif damage == "split_count":
        summary["admitted_source_variables"]["train"] = 2
    elif damage == "project_count":
        summary["projects"]["parson"]["supervised_value_rows"] = 4
    elif damage == "dataset_project_count":
        dataset["project_counts"]["hashmap"]["supervised_value_rows"] = 4
    elif damage == "missing_record":
        records.pop()
    elif damage == "new_training_count":
        summary["new_training_admitted"] = 2
    save(output / "dataset.json", dataset)
    save(output / "summary.json", summary)
    save(output / "records.json", records)
    result = audit(output)
    assert result.returncode != 0 and "AssertionError" in result.stdout, result.stdout
    assert not (output / "independent-export-audit.json").exists()


@pytest.mark.parametrize("mode", ["worker_failure", "empty_targets", "source_failure"])
def test_failed_and_empty_functions_stay_in_denominators(panel, monkeypatch, mode):
    if mode == "worker_failure":
        def fail(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        monkeypatch.setattr(exporter.subprocess, "run", fail)
    elif mode == "source_failure":
        def fail(*args):
            raise ValueError("unsupported source fixture")
        monkeypatch.setattr(exporter, "source_facts", fail)
    else:
        original = exporter.admit_supervision

        def empty(payload, source, variables, vocabulary):
            source = deepcopy(source)
            source["exclusions"] = {str(v["variable_die_offset"]): "fixture_exclusion" for v in variables}
            return original(payload, source, variables, vocabulary)
        monkeypatch.setattr(exporter, "admit_supervision", empty)
    with pytest.raises(SystemExit) as failure:
        collect(panel, monkeypatch)
    assert failure.value.code == 1
    output, = panel.scratch.glob("route-b-type-v3-graphs-*")
    records, summary = exporter.read(output / "records.json"), exporter.read(output / "summary.json")
    assert len(records) == 2 and summary["candidate_source_variables"] == {"train": 1, "development": 1}
    assert summary["exported_functions"] == {"train": 0, "development": 0}
    reason = "fixture_exclusion" if mode == "empty_targets" else "function_capture_or_review_failed"
    assert summary["exclusion_reasons"] == {reason: 2}
    result = audit(output)
    assert result.returncode == 0, result.stdout
    assert len(exporter.read(output / "independent-export-audit.json")["failed_or_empty_functions"]) == 2


def test_prepare_only_writes_plan_without_workers(panel, monkeypatch):
    output = collect(panel, monkeypatch, prepare=True)
    assert panel.calls == [] and exporter.read(output / "records.json") == []
    summary = exporter.read(output / "summary.json")
    assert summary["prepare_only"] is True
    assert summary["planned_functions"] == {"train": 1, "development": 1}
    assert summary["completed_functions"] == {"train": 0, "development": 0}
    assert summary["exported_functions"] == {"train": 0, "development": 0}
    assert all(not p.exists() for p in output.glob("*/raw.json"))


def test_vocabulary_must_byte_match_before_output_creation(panel, monkeypatch):
    monkeypatch.setattr(exporter, "UpstreamLabels", lambda _: SimpleNamespace(vocabulary=["type" + str(i) for i in range(75)]))
    with pytest.raises(ValueError, match="Vocabulary differs"):
        collect(panel, monkeypatch)
    assert list(panel.scratch.glob("route-b-type-v3-graphs-*")) == [] and panel.calls == []


@pytest.mark.parametrize("timeout", ["0", "-1", "601", "nan"])
def test_timeout_rejected_before_any_work(monkeypatch, timeout):
    monkeypatch.setattr(sys, "argv", ["export", "--inventory", ".", "--mapping", ".", "--function-timeout", timeout])
    with pytest.raises(SystemExit) as failure:
        exporter.main()
    assert failure.value.code == 2


def test_created_python_is_ascii_lf_and_python38_compatible():
    for relative in ("scripts/export_type_v3_graphs.py", "scripts/verify_type_v3_export.py", "tests/test_type_v3_export.py"):
        data = (ROOT / relative).read_bytes()
        assert b"\r" not in data
        ast.parse(data.decode("ascii"), filename=relative, feature_version=(3, 8))
    tree = ast.parse((ROOT / "scripts/verify_type_v3_export.py").read_bytes())
    imports = {node.names[0].name.split(".")[0] if isinstance(node, ast.Import) else node.module.split(".")[0]
               for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))}
    assert imports <= {"collections", "hashlib", "json", "math", "os", "pathlib", "sys"}
    # The reviewed mapping prerequisite must remain exactly the v2 procedure.
    functions = []
    for relative in ("scripts/export_type_dev_graphs.py", "scripts/export_type_v3_graphs.py"):
        module = ast.parse((ROOT / relative).read_bytes())
        function, = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "validate_mapping"]
        functions.append(ast.dump(function))
    assert functions[0] == functions[1]
