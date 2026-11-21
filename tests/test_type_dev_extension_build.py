"""Development-extension builder: pin checks, plan order, v1 compile command, label-free scope."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts import build_type_dev_extension as builder
from src.selective_analysis import type_corpus as corpus

ROOT = Path(__file__).resolve().parents[1]
TEST_OUTPUT = ROOT / ".test-output"
V1_BUILDER = ROOT / "scripts/build_type_corpus.py"


@contextlib.contextmanager
def workspace(name):
    root = TEST_OUTPUT / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return corpus.sha(path)


def dump(path, value):
    put(path, json.dumps(value, indent=2, allow_nan=False) + "\n")
    return corpus.sha(path)


def load(path):
    return json.loads(path.read_bytes())


DEVELOPMENT = (
    ("sds", "primary", "antirez/sds", ["sds.c"], ["sds.h"]),
    ("tiny_regex_c", "primary", "kokke/tiny-regex-c", ["re.c"], ["re.h"]),
    ("json_parser", "primary", "json-parser/json-parser", ["json.c"], ["json.h"]),
    ("parson", "backup", "kgabis/parson", ["parson.c"], ["parson.h"]),
)
TRAINING = (
    ("inih", "benhoyt/inih", ["ini.c"], ["ini.h"], None),
    ("rxi_map", "rxi/map", ["src/map.c"], ["src/map.h"], None),
    ("jsmn", "zserge/jsmn", [], ["jsmn.h"], "jsmn-unit.c"),
)


def make_extension(root):
    extension = root / "extension"
    extension.mkdir()
    prereg = root / "preregistration.md"
    prereg_sha = put(prereg, "# fixture type pilot v2 preregistration\n")
    pin = root / "prepare_type_dev_extension.py"
    pin_sha = put(pin, "print('fixture pin')\n")
    parent = root / "parent_corpus"
    parent.mkdir()
    harness = parent / "intake-main.c"
    harness_sha = put(harness, "int main(void) { return 0; }\n")
    bridge = parent / "jsmn-unit.c"
    bridge_sha = put(bridge, "int jsmn_bridge(void) { return 1; }\n")
    parent_manifest = parent / "manifest.json"
    parent_sha = dump(parent_manifest, {"schema": "symbai.type_corpus_manifest.v1", "projects": []})
    development_rows = []
    for project_id, role, family, units, headers in DEVELOPMENT:
        directory = extension / "sources" / project_id
        files = {}
        for name in units:
            files[name] = put(directory / name, "int %s_unit(void) { return 0; }\n" % project_id)
        for name in headers:
            files[name] = put(directory / name, "/* %s header */\n" % project_id)
        development_rows.append({
            "project_id": project_id, "family": family, "split": "development", "role": role,
            "status": "pinned", "source_directory": str(directory), "source_files": files,
            "translation_units": list(units), "headers": list(headers),
            "bridge": None, "bridge_sha256": None,
        })
    training_rows = []
    for project_id, family, units, headers, bridge_name in TRAINING:
        directory = root / "parent_sources" / project_id
        files = {}
        for name in units:
            files[name] = put(directory / name, "int %s_unit(void) { return 0; }\n" % project_id)
        for name in headers:
            files[name] = put(directory / name, "/* %s header */\n" % project_id)
        training_rows.append({
            "project_id": project_id, "family": family, "split": "train",
            "status": "pinned", "source_directory": str(directory), "source_files": files,
            "translation_units": list(units), "headers": list(headers),
            "bridge": bridge_name, "bridge_sha256": bridge_sha if bridge_name else None,
            "corpus_directory": str(parent),
        })
    selection = {
        "schema": "symbai.type_dev_extension_selection.v1",
        "preregistration_sha256": prereg_sha,
        "parent_manifest_sha256": parent_sha,
        "projects": [{"project_id": row["project_id"], "family": row["family"],
                      "split": "development", "role": row["role"]} for row in development_rows],
    }
    selection_sha = dump(extension / "selection.json", selection)
    dump(extension / "manifest.json", {
        "schema": "symbai.type_dev_extension_manifest.v1",
        "selection_sha256": selection_sha,
        "development_projects": development_rows,
        "training_projects": training_rows,
        "compiler_profiles": ["O0", "O1"],
        "harness": str(harness),
        "harness_sha256": harness_sha,
        "implementation_pins": {str(pin): pin_sha, str(prereg): prereg_sha},
    })
    return extension, prereg, prereg_sha


def refresh_selection_hash(extension):
    manifest = load(extension / "manifest.json")
    manifest["selection_sha256"] = corpus.sha(extension / "selection.json")
    dump(extension / "manifest.json", manifest)


def apply_damage(root, extension, prereg, damage):
    manifest = load(extension / "manifest.json")
    selection = load(extension / "selection.json")
    if damage == "schema":
        manifest["schema"] = "symbai.type_corpus_manifest.v1"
        dump(extension / "manifest.json", manifest)
    elif damage == "selection_sha":
        manifest["selection_sha256"] = "0" * 64
        dump(extension / "manifest.json", manifest)
    elif damage == "selection_prereg":
        selection["preregistration_sha256"] = "0" * 64
        dump(extension / "selection.json", selection)
        refresh_selection_hash(extension)
    elif damage == "prereg_file":
        put(prereg, "# mutated preregistration\n")
    elif damage == "implementation_pins":
        pin = Path(next(path for path in manifest["implementation_pins"] if path.endswith(".py")))
        put(pin, "print('mutated pin')\n")
    elif damage == "development_ids":
        manifest["development_projects"][3]["project_id"] = "other"
        dump(extension / "manifest.json", manifest)
    elif damage == "development_roles":
        manifest["development_projects"][3]["role"] = "primary"
        dump(extension / "manifest.json", manifest)
    elif damage == "development_status":
        manifest["development_projects"][0]["status"] = "failed"
        dump(extension / "manifest.json", manifest)
    elif damage == "development_split":
        manifest["development_projects"][0]["split"] = "evaluation"
        dump(extension / "manifest.json", manifest)
    elif damage == "development_source":
        put(Path(manifest["development_projects"][0]["source_directory"]) / "sds.c", "int mutated(void) { return 1; }\n")
    elif damage == "training_ids":
        manifest["training_projects"][2]["project_id"] = "other"
        dump(extension / "manifest.json", manifest)
    elif damage == "training_split":
        manifest["training_projects"][0]["split"] = "development"
        dump(extension / "manifest.json", manifest)
    elif damage == "training_source":
        put(Path(manifest["training_projects"][0]["source_directory"]) / "ini.c", "int mutated(void) { return 1; }\n")
    elif damage == "training_bridge":
        put(Path(manifest["training_projects"][2]["corpus_directory"]) / "jsmn-unit.c", "int mutated_bridge(void) { return 2; }\n")
    elif damage == "parent_manifest":
        dump(Path(manifest["training_projects"][0]["corpus_directory"]) / "manifest.json", {"schema": "mutated"})
    elif damage == "harness":
        put(Path(manifest["harness"]), "int main(void) { return 1; }\n")
    elif damage == "families":
        manifest["development_projects"][0]["family"] = "BENHOYT/inih"
        dump(extension / "manifest.json", manifest)
    else:
        raise AssertionError("unknown damage " + damage)


VALIDATION_CASES = (
    ("schema", "Unexpected extension manifest schema"),
    ("selection_sha", "selection.json does not match the pinned digest"),
    ("selection_prereg", "selection preregistration digest mismatch"),
    ("prereg_file", "preregistration file digest mismatch"),
    ("implementation_pins", "Pinned implementation or original type rules changed"),
    ("development_ids", "Unexpected development projects or roles"),
    ("development_roles", "Unexpected development projects or roles"),
    ("development_status", "Development project is not pinned"),
    ("development_split", "Development project split is not development"),
    ("development_source", "Pinned source changed"),
    ("training_ids", "Unexpected training projects"),
    ("training_split", "Training project split is not train"),
    ("training_source", "Pinned source changed"),
    ("training_bridge", "Header bridge changed"),
    ("parent_manifest", "Parent corpus manifest digest mismatch"),
    ("harness", "Link-only harness changed"),
    ("families", "Development families overlap training families"),
)


@pytest.mark.parametrize("damage,message", VALIDATION_CASES)
def test_validate_extension_rejects_broken_inputs(damage, message):
    with workspace("validate_" + damage) as root:
        extension, prereg, digest = make_extension(root)
        apply_damage(root, extension, prereg, damage)
        with pytest.raises(ValueError, match=message):
            builder.validate_extension(extension, prereg, digest)


def test_validate_extension_accepts_a_pinned_fixture():
    with workspace("validate_ok") as root:
        extension, prereg, digest = make_extension(root)
        manifest, selection = builder.validate_extension(extension, prereg, digest)
        assert manifest["schema"] == "symbai.type_dev_extension_manifest.v1"
        assert selection["preregistration_sha256"] == digest


def _plan_ids(plan):
    return [(row["project_id"], row["profile"], row["purpose"]) for row in plan]


def test_build_plan_order_without_backup():
    with workspace("plan_no_backup") as root:
        extension, prereg, digest = make_extension(root)
        manifest, _selection = builder.validate_extension(extension, prereg, digest)
        plan = builder.build_plan(manifest, include_backup=False)
        assert _plan_ids(plan) == [
            ("sds", "O0", "development_inventory"),
            ("sds", "O1", "development_inventory"),
            ("tiny_regex_c", "O0", "development_inventory"),
            ("tiny_regex_c", "O1", "development_inventory"),
            ("json_parser", "O0", "development_inventory"),
            ("json_parser", "O1", "development_inventory"),
            ("inih", "O0", "clone_screen_reference"),
            ("rxi_map", "O0", "clone_screen_reference"),
            ("jsmn", "O0", "clone_screen_reference"),
        ]
        assert all(row["purpose"] == "clone_screen_reference" for row in plan if row["split"] == "train")
        assert "parson" not in [row["project_id"] for row in plan]


def test_build_plan_order_with_backup():
    with workspace("plan_backup") as root:
        extension, prereg, digest = make_extension(root)
        manifest, _selection = builder.validate_extension(extension, prereg, digest)
        plan = builder.build_plan(manifest, include_backup=True)
        assert _plan_ids(plan) == [
            ("sds", "O0", "development_inventory"),
            ("sds", "O1", "development_inventory"),
            ("tiny_regex_c", "O0", "development_inventory"),
            ("tiny_regex_c", "O1", "development_inventory"),
            ("json_parser", "O0", "development_inventory"),
            ("json_parser", "O1", "development_inventory"),
            ("parson", "O0", "development_inventory"),
            ("parson", "O1", "development_inventory"),
            ("inih", "O0", "clone_screen_reference"),
            ("rxi_map", "O0", "clone_screen_reference"),
            ("jsmn", "O0", "clone_screen_reference"),
        ]


def test_compile_command_matches_v1():
    compiler, profile = "gcc", "O0"
    directory = Path("/src/proj")
    units = [Path("/src/proj/a.c"), Path("/src/bridge.c")]
    harness = Path("/src/intake-main.c")
    binary = Path("/out/proj-O0.elf")
    expected = [compiler, "-std=gnu99", "-" + profile, "-g3", "-gdwarf-4", "-fno-omit-frame-pointer",
                "-fno-inline", "-fkeep-inline-functions", "-fno-builtin", "-no-pie", "-I", str(directory)]
    expected += [str(path) for path in units] + [str(harness), "-o", str(binary)]
    assert builder.compile_command(compiler, profile, directory, units, harness, binary) == expected
    source = V1_BUILDER.read_text(encoding="utf-8")
    start = source.index('"-std=gnu99"')
    fragment = source[start:source.index("str(directory)]", start)]
    for token in ("-std=gnu99", "-g3", "-gdwarf-4", "-fno-omit-frame-pointer", "-fno-inline",
                  "-fkeep-inline-functions", "-fno-builtin", "-no-pie"):
        assert token in fragment
        fragment = fragment[fragment.index(token) + len(token):]


def _inventory(project_id, role, split, profile, binary, functions, variables, digest=None):
    return {
        "project_id": project_id, "role": role, "split": split, "profile": profile,
        "binary": binary, "binary_sha256": digest or (project_id + profile).ljust(64, "0")[:64],
        "functions": functions, "variables": variables,
    }


def _function(function_id, name, address, split, fingerprints=None):
    return {"function_id": function_id, "name": name, "address": address, "split": split,
            "fingerprints": fingerprints, "source": name + ".c", "source_line": 1}


def _variable(function_id, name, status="mapped", label="i32", class_id=7):
    row = {"function_id": function_id, "name": name, "status": status, "role": "DW_TAG_variable",
           "location_attribute_present": True}
    if status == "mapped":
        row.update(label=label, class_id=class_id, before_normalization="int")
    return row


def walk_forbidden(value, path=""):
    forbidden_keys = {"label", "class_id", "before_normalization", "mapped_label_histogram",
                      "label_histogram", "label_source"}
    forbidden_text = {"i32", "char*", "u64", "void**", "int", "array<void>"}
    if isinstance(value, dict):
        for key, item in value.items():
            assert key not in forbidden_keys, "label key leaked at %s.%s" % (path, key)
            walk_forbidden(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            walk_forbidden(item, "%s[%d]" % (path, index))
    elif isinstance(value, str):
        assert value not in forbidden_text, "type text leaked at %s: %s" % (path, value)


def test_export_scope_excludes_cross_split_clones_and_leaks_no_labels():
    first = 'int f(int x) { const char *s="}"; /* } */ if(x) { x += 1; } return x; }'
    second = 'int g(int y) { const char *s="}"; if(y) { y += 1; } return y; }'
    cloned_dev = corpus.function_fingerprints(first, 1, "f")
    cloned_train = corpus.function_fingerprints(second, 1, "g")
    inventories = [
        _inventory("sds", "primary", "development", "O0", "sds-O0.elf", [
            _function("sds:keep", "keep", 32, "development"),
            _function("sds:clone", "copied", 16, "development", cloned_dev),
        ], [
            _variable("sds:keep", "n", label="i32", class_id=7),
            _variable("sds:clone", "p", label="char*", class_id=3),
        ]),
        _inventory("inih", None, "train", "O0", "inih-O0.elf", [
            _function("inih:clone", "copied_train", 48, "train", cloned_train),
        ], [
            _variable("inih:clone", "q", status="unmapped"),
        ]),
        _inventory("json_parser", "primary", "development", "O0", "json_parser-O0.elf", [
            _function("json:one", "parse", 1, "development"),
        ], []),
        _inventory("sds", "primary", "development", "O1", "sds-O1.elf", [
            _function("sds:o1", "keep", 99, "development"),
        ], [
            _variable("sds:o1", "n", label="i32", class_id=7),
        ]),
    ]
    groups = corpus.cross_split_clones(
        inventories[0]["functions"] + inventories[1]["functions"] + inventories[2]["functions"])
    assert groups
    scope = builder.export_scope(inventories, groups, "p" * 64, "m" * 64, False)
    assert scope["schema"] == "symbai.type_dev_export_scope.v1"
    assert [row["function_id"] for row in scope["cases"]] == ["sds:keep", "json:one"]
    keep = scope["cases"][0]
    assert keep["function_name"] == "keep" and keep["function_address"] == 32
    assert keep["split"] == "development" and keep["profile"] == "O0" and keep["role"] == "primary"
    assert keep["source_variable_records"] == 1 and keep["mapped_source_variable_records"] == 1
    assert scope["cases"][1]["project_id"] == "json_parser"
    assert scope["cases"][1]["source_variable_records"] == 0
    assert len(scope["excluded_clone_functions"]) == 1
    excluded = scope["excluded_clone_functions"][0]
    assert excluded["function_id"] == "sds:clone"
    assert excluded["clone_groups"]
    assert "train" in excluded["clone_groups"][0]["splits"]
    assert scope["candidate_functions"] == 2
    assert scope["candidate_source_variable_records"] == 1
    assert scope["preregistration_sha256"] == "p" * 64
    assert scope["manifest_sha256"] == "m" * 64
    assert scope["backup_included"] is False
    assert scope["evaluation_projects_selected"] is False
    assert scope["labels_in_scope"] is False
    walk_forbidden(scope)
    dumped = json.dumps(scope)
    assert '"label"' not in dumped
    assert "class_id" not in dumped
    assert "before_normalization" not in dumped
    assert "i32" not in dumped
    assert "char*" not in dumped


def test_prepare_only_writes_plan_and_vocabulary_without_compiling(monkeypatch):
    with workspace("prepare_only") as root:
        extension, prereg, digest = make_extension(root)
        output = extension / "labels-test"

        def boom(*args, **kwargs):
            raise AssertionError("compile invoked during prepare-only")

        monkeypatch.setattr(builder.subprocess, "run", boom)
        previous = {key: os.environ.get(key) for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME")}
        try:
            builder.run_inventory(extension, output, prepare_only=True, include_backup=False,
                                  preregistration=prereg, expected_sha=digest)
            assert (output / "plan.json").is_file()
            assert (output / "label-vocabulary.json").is_file()
            assert not (output / "summary.json").exists()
            assert not (output / "records.json").exists()
            assert not (output / "dev-export-scope.json").exists()
            assert not (output / "compiler-version.txt").exists()
            assert list(output.glob("*.elf")) == []
            assert list(output.glob("*.build.log")) == []
            plan = load(output / "plan.json")
            assert plan["compiler"] is None
            assert plan["include_backup"] is False
            assert len(plan["builds"]) == 9
            vocabulary = load(output / "label-vocabulary.json")
            assert len(vocabulary) == 75 and len(set(vocabulary)) == 75
            assert os.environ["TEMP"] == str(output / "temp")
            assert os.environ["TMPDIR"] == str(output / "temp")
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def test_replacement_requires_recorded_primary_failure_and_swaps_in_backup():
    with workspace("replacement") as root:
        extension, prereg, digest = make_extension(root)
        manifest, _selection = builder.validate_extension(extension, prereg, digest)
        evidence = extension / "labels-failed"
        rows = [{"project_id": "json_parser", "purpose": "development_inventory", "profile": p,
                 "status": "failed", "error": {"type": "CalledProcessError", "message": "link"}} for p in ("O0", "O1")]
        rows.append({"project_id": "sds", "purpose": "development_inventory", "profile": "O0", "status": "inventoried"})
        dump(evidence / "records.json", rows)
        replacement = builder.failed_primary_evidence(extension, evidence, "json_parser")
        assert replacement["replaced_primary"] == "json_parser"
        assert len(replacement["primary_failure"]["failures"]) == 2 and replacement["backup_failure"] is None
        with pytest.raises(ValueError):
            builder.failed_primary_evidence(extension, evidence, "json_parser", evidence)
        backup = extension / "labels-backup-failed"
        dump(backup / "records.json", [{"project_id": "parson", "purpose": "development_inventory",
                                         "profile": "O0", "status": "failed", "error": {}}])
        both = builder.failed_primary_evidence(extension, evidence, "json_parser", backup)
        assert both["backup_failure"]["project_id"] == "parson"
        remaining = [row["project_id"] for row in builder.build_plan(manifest, False, "json_parser")]
        assert "parson" not in remaining and "json_parser" not in remaining
        plan = builder.build_plan(manifest, True, "json_parser")
        ids = [row["project_id"] for row in plan]
        assert "json_parser" not in ids and ids.count("parson") == 2
        for primary in ("sds", "parson", "unknown"):
            with pytest.raises(ValueError):
                builder.failed_primary_evidence(extension, evidence, primary)
        with pytest.raises(ValueError):
            builder.failed_primary_evidence(extension, root / "outside", "json_parser")
