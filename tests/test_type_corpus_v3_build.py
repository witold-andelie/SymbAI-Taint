"""Type-corpus v3 builder: pin checks, plan order, recipe v3, cap, clone screen, label-free scope."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from scripts import build_type_corpus_v3 as builder
from scripts import build_type_dev_extension as v2_builder
from src.selective_analysis import type_corpus as corpus

ROOT = Path(__file__).resolve().parents[1]
TEST_OUTPUT = ROOT / ".test-output"
V2_BUILDER = ROOT / "scripts/build_type_dev_extension.py"

NEW_TRAINING = (
    ("hashmap", "tidwall/hashmap.c", ["hashmap.c"], ["hashmap.h"], "."),
    ("btree", "tidwall/btree.c", ["btree.c"], ["btree.h"], "."),
)
NEW_DEVELOPMENT = (
    ("md4c", "mity/md4c", ["src/md4c.c"], ["src/md4c.h"], "src"),
)
REUSED_DEVELOPMENT = (
    ("json_parser", "json-parser/json-parser", ["json.c"], ["json.h"], "."),
    ("parson", "kgabis/parson", ["parson.c"], ["parson.h"], "."),
)
REUSED_TRAINING = (
    ("inih", "train"),
    ("rxi_map", "train"),
    ("jsmn", "train"),
    ("optparse", "development"),
    ("sds", "development"),
    ("tiny_regex_c", "development"),
)


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


def pin_project(directory, project_id, family, split, units, headers, include_directory, role=None):
    files = {}
    for name in units:
        files[name] = put(directory / name, "int %s_unit(void) { return 0; }\n" % project_id)
    for name in headers:
        files[name] = put(directory / name, "/* %s header */\n" % project_id)
    return {
        "project_id": project_id, "family": family, "split": split, "role": role,
        "status": "pinned", "source_directory": str(directory), "source_files": files,
        "translation_units": list(units), "headers": list(headers),
        "include_directory": include_directory, "bridge": None, "bridge_sha256": None,
    }


def stub_labels(project_id, split, function_id=None):
    function_id = function_id or (project_id + ":stub")
    return {
        "binary_sha256": (project_id + "O0").ljust(64, "0")[:64],
        "functions": [{
            "function_id": function_id, "name": project_id + "_stub", "address": 16,
            "split": split, "fingerprints": None, "source": project_id + ".c", "source_line": 1,
        }],
        "variables": [],
    }


def make_corpus(root):
    corpus_dir = root / "corpus"
    corpus_dir.mkdir()
    prereg = root / "preregistration.md"
    prereg_sha = put(prereg, "# fixture type pilot v3 preregistration\n")
    pin = root / "prepare_type_corpus_v3.py"
    pin_sha = put(pin, "print('fixture pin')\n")
    harness = root / "intake-main.c"
    harness_sha = put(harness, "int main(void) { return 0; }\n")
    v1_export = root / "exports" / "v1"
    v2_export = root / "exports" / "v2"
    v1_dataset_sha = dump(v1_export / "dataset.json", {"schema": "fixture.v1.dataset", "cases": []})
    v1_audit_sha = dump(v1_export / "independent-export-audit.json", {"schema": "fixture.v1.audit"})
    v2_dataset_sha = dump(v2_export / "dataset.json", {"schema": "fixture.v2.dataset", "cases": []})
    v2_audit_sha = dump(v2_export / "independent-export-audit.json", {"schema": "fixture.v2.audit"})
    labels_v1 = root / "labels_v1"
    labels_v2 = root / "labels_v2"
    reused_training_ids = []
    for project_id, split in REUSED_TRAINING:
        reused_training_ids.append(project_id)
        directory = labels_v1 if project_id in builder.REUSED_V1_PROJECTS else labels_v2
        dump(directory / (project_id + "-O0.labels.json"), stub_labels(project_id, split))
    reused_inventories = (
        (labels_v1, builder.REUSED_V1_PROJECTS),
        (labels_v2, builder.REUSED_V2_PROJECTS),
    )
    new_rows = []
    selection_new = []
    for project_id, family, units, headers, include in NEW_TRAINING:
        row = pin_project(corpus_dir / "sources" / project_id, project_id, family, "train",
                          units, headers, include)
        new_rows.append(row)
        selection_new.append({"project_id": project_id, "repository": family, "family": family,
                              "split": "train"})
    for project_id, family, units, headers, include in NEW_DEVELOPMENT:
        row = pin_project(corpus_dir / "sources" / project_id, project_id, family, "development",
                          units, headers, include, role="primary")
        new_rows.append(row)
        selection_new.append({"project_id": project_id, "repository": family, "family": family,
                              "split": "development"})
    reused_dev_rows = []
    for project_id, family, units, headers, include in REUSED_DEVELOPMENT:
        reused_dev_rows.append(pin_project(corpus_dir / "sources" / project_id, project_id, family,
                                           "development", units, headers, include, role="primary"))
    reused_exports = {
        "v1_reviewed_export": {
            "directory": str(v1_export), "dataset_sha256": v1_dataset_sha, "audit_sha256": v1_audit_sha,
        },
        "v2_development_export": {
            "directory": str(v2_export), "dataset_sha256": v2_dataset_sha, "audit_sha256": v2_audit_sha,
        },
    }
    selection = {
        "schema": "symbai.type_corpus_v3_selection.v1",
        "preregistration_sha256": prereg_sha,
        "new_projects": selection_new,
        "reused_development_projects": ["json_parser", "parson"],
        "reused_training_projects": list(reused_training_ids),
        "reused_exports": reused_exports,
        "author_families": {
            "train": ["tidwall", "benhoyt", "rxi", "zserge", "skeeto", "antirez", "kokke"],
            "development": ["json-parser", "kgabis", "mity"],
            "sealed": ["sheredom", "jwerle"],
        },
    }
    selection_sha = dump(corpus_dir / "selection.json", selection)
    dump(corpus_dir / "manifest.json", {
        "schema": "symbai.type_corpus_v3_manifest.v1",
        "selection_sha256": selection_sha,
        "new_projects": new_rows,
        "reused_development_projects": reused_dev_rows,
        "reused_exports": reused_exports,
        "harness": str(harness),
        "harness_sha256": harness_sha,
        "compiler_profiles": ["O0"],
        "link_libraries": ["-lm"],
        "implementation_pins": {str(pin): pin_sha, str(prereg): prereg_sha},
        "compilation_performed": False,
        "labels_extracted": False,
        "graph_extraction_performed": False,
        "training_allowed": False,
        "evaluation_projects_selected": False,
    })
    return corpus_dir, prereg, prereg_sha, reused_inventories


def refresh_selection_hash(corpus_dir):
    manifest = load(corpus_dir / "manifest.json")
    manifest["selection_sha256"] = corpus.sha(corpus_dir / "selection.json")
    dump(corpus_dir / "manifest.json", manifest)


def apply_damage(root, corpus_dir, prereg, reused_inventories, damage):
    manifest = load(corpus_dir / "manifest.json")
    selection = load(corpus_dir / "selection.json")
    if damage == "schema":
        manifest["schema"] = "symbai.type_corpus_manifest.v1"
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "selection_sha":
        manifest["selection_sha256"] = "0" * 64
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "selection_prereg":
        selection["preregistration_sha256"] = "0" * 64
        dump(corpus_dir / "selection.json", selection)
        refresh_selection_hash(corpus_dir)
    elif damage == "prereg_file":
        put(prereg, "# mutated preregistration\n")
    elif damage == "implementation_pins":
        pin = Path(next(path for path in manifest["implementation_pins"] if path.endswith(".py")))
        put(pin, "print('mutated pin')\n")
    elif damage == "new_status":
        manifest["new_projects"][0]["status"] = "failed"
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "new_source":
        put(Path(manifest["new_projects"][0]["source_directory"]) / "hashmap.c",
            "int mutated(void) { return 1; }\n")
    elif damage == "reused_dev_source":
        put(Path(manifest["reused_development_projects"][0]["source_directory"]) / "json.c",
            "int mutated(void) { return 1; }\n")
    elif damage == "new_training_ids":
        manifest["new_projects"][0]["project_id"] = "other"
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "new_development_id":
        manifest["new_projects"][2]["project_id"] = "other"
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "reused_development_ids":
        manifest["reused_development_projects"][1]["project_id"] = "other"
        dump(corpus_dir / "manifest.json", manifest)
    elif damage == "reused_training_ids":
        selection["reused_training_projects"] = list(selection["reused_training_projects"])[:-1]
        dump(corpus_dir / "selection.json", selection)
        refresh_selection_hash(corpus_dir)
    elif damage == "harness":
        put(Path(manifest["harness"]), "int main(void) { return 1; }\n")
    elif damage == "reused_export_dataset":
        put(Path(manifest["reused_exports"]["v1_reviewed_export"]["directory"]) / "dataset.json",
            "{\"mutated\": true}\n")
    elif damage == "reused_export_audit":
        put(Path(manifest["reused_exports"]["v2_development_export"]["directory"])
            / "independent-export-audit.json", "{\"mutated\": true}\n")
    elif damage == "reused_inventory":
        (reused_inventories[0][0] / "inih-O0.labels.json").unlink()
    elif damage == "families":
        selection["author_families"]["train"] = list(selection["author_families"]["train"]) + ["mity"]
        dump(corpus_dir / "selection.json", selection)
        refresh_selection_hash(corpus_dir)
    else:
        raise AssertionError("unknown damage " + damage)


VALIDATION_CASES = (
    ("schema", "Unexpected corpus manifest schema"),
    ("selection_sha", "selection.json does not match the pinned digest"),
    ("selection_prereg", "selection preregistration digest mismatch"),
    ("prereg_file", "preregistration file digest mismatch"),
    ("implementation_pins", "Pinned implementation or original type rules changed"),
    ("new_status", "New project is not pinned"),
    ("new_source", "Pinned source changed"),
    ("reused_dev_source", "Pinned source changed"),
    ("new_training_ids", "Split sets do not match the selection"),
    ("new_development_id", "Split sets do not match the selection"),
    ("reused_development_ids", "Split sets do not match the selection"),
    ("reused_training_ids", "Split sets do not match the selection"),
    ("harness", "Link-only harness changed"),
    ("reused_export_dataset", "Reused export digest mismatch"),
    ("reused_export_audit", "Reused export digest mismatch"),
    ("reused_inventory", "Reused inventory labels file missing"),
    ("families", "Development families overlap training families"),
)


@pytest.mark.parametrize("damage,message", VALIDATION_CASES)
def test_validate_corpus_rejects_broken_inputs(damage, message):
    with workspace("v3_validate_" + damage) as root:
        corpus_dir, prereg, digest, reused = make_corpus(root)
        apply_damage(root, corpus_dir, prereg, reused, damage)
        with pytest.raises(ValueError, match=message):
            builder.validate_corpus(corpus_dir, prereg, digest, reused)


def test_validate_corpus_accepts_a_pinned_fixture():
    with workspace("v3_validate_ok") as root:
        corpus_dir, prereg, digest, reused = make_corpus(root)
        manifest, selection = builder.validate_corpus(corpus_dir, prereg, digest, reused)
        assert manifest["schema"] == "symbai.type_corpus_v3_manifest.v1"
        assert selection["preregistration_sha256"] == digest
        assert tuple(selection["reused_training_projects"]) == builder.EXPECTED_REUSED_TRAINING_IDS


def _plan_ids(plan):
    return [(row["project_id"], row["profile"], row["purpose"]) for row in plan]


def test_build_plan_order():
    with workspace("v3_plan_order") as root:
        corpus_dir, prereg, digest, reused = make_corpus(root)
        manifest, _selection = builder.validate_corpus(corpus_dir, prereg, digest, reused)
        plan = builder.build_plan(manifest)
        assert _plan_ids(plan) == [
            ("hashmap", "O0", "training_inventory"),
            ("btree", "O0", "training_inventory"),
            ("md4c", "O0", "development_inventory"),
            ("json_parser", "O0", "development_inventory"),
            ("parson", "O0", "development_inventory"),
        ]
        assert [row["profile"] for row in plan] == ["O0"] * 5
        assert plan[2]["include_directory"] == "src"
        assert plan[0]["include_directory"] == "."
        md4c_dir = Path(plan[2]["source_directory"])
        _directory, include, units = builder.unit_paths(plan[2])
        assert include == md4c_dir / "src"
        assert units == [md4c_dir / "src/md4c.c"]


def test_compile_command_is_v2_plus_lm():
    compiler, profile = "gcc", "O0"
    directory = Path("/src/proj")
    units = [Path("/src/proj/a.c"), Path("/src/proj/src/b.c")]
    harness = Path("/src/intake-main.c")
    binary = Path("/out/proj-O0.elf")
    expected = v2_builder.compile_command(compiler, profile, directory, units, harness, binary)
    expected = expected + ["-lm"]
    assert builder.compile_command(compiler, profile, directory, units, harness, binary) == expected
    assert expected[-1] == "-lm"
    assert expected[-3:-1] == ["-o", str(binary)]
    source = V2_BUILDER.read_text(encoding="utf-8")
    start = source.index('"-std=gnu99"')
    fragment = source[start:source.index("str(directory)]", start)]
    for token in ("-std=gnu99", "-g3", "-gdwarf-4", "-fno-omit-frame-pointer", "-fno-inline",
                  "-fkeep-inline-functions", "-fno-builtin", "-no-pie"):
        assert token in fragment
        fragment = fragment[fragment.index(token) + len(token):]


def _inventory(project_id, split, profile, binary, functions, variables, digest=None):
    return {
        "project_id": project_id, "split": split, "profile": profile,
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


def test_apply_cap_keeps_all_when_at_most_limit():
    functions = [_function("p:f%d" % i, "f%d" % i, i * 8, "train") for i in range(60)]
    kept, capped = builder.apply_cap("p", functions)
    assert kept == functions
    assert capped == []
    kept_short, capped_short = builder.apply_cap("p", functions[:59])
    assert kept_short == functions[:59]
    assert capped_short == []
    assert builder.apply_cap("p", []) == ([], [])


def test_apply_cap_selects_smallest_name_hash_in_address_order():
    functions = [_function("proj:n%d" % i, "n%d" % i, 1000 - i, "train") for i in range(70)]
    kept, capped = builder.apply_cap("proj", functions, 60)
    ranked = sorted(functions, key=lambda row: hashlib.sha256(
        ("proj:" + row["name"]).encode("utf-8")).hexdigest())
    expected_ids = [row["function_id"] for row in ranked[:60]]
    assert [row["function_id"] for row in kept] == [
        row["function_id"] for row in sorted(
            [row for row in functions if row["function_id"] in expected_ids],
            key=lambda row: row["address"])]
    assert len(kept) == 60
    assert capped == [row["function_id"] for row in functions if row["function_id"] not in expected_ids]
    assert set(capped) == set(row["function_id"] for row in ranked[60:])
    kept_again, capped_again = builder.apply_cap("proj", functions, 60)
    assert kept == kept_again and capped == capped_again
    assert [row["address"] for row in kept] == sorted(row["address"] for row in kept)


def test_reused_training_split_override_makes_cross_split_clones():
    first = 'int f(int x) { const char *s="}"; /* } */ if(x) { x += 1; } return x; }'
    second = 'int g(int y) { const char *s="}"; if(y) { y += 1; } return y; }'
    cloned_dev = corpus.function_fingerprints(first, 1, "f")
    cloned_reused = corpus.function_fingerprints(second, 1, "g")
    with workspace("v3_reused_split") as root:
        labels_v1 = root / "labels_v1"
        labels_v2 = root / "labels_v2"
        dump(labels_v1 / "inih-O0.labels.json", stub_labels("inih", "train"))
        dump(labels_v1 / "rxi_map-O0.labels.json", stub_labels("rxi_map", "train"))
        dump(labels_v1 / "jsmn-O0.labels.json", stub_labels("jsmn", "train"))
        dump(labels_v1 / "optparse-O0.labels.json", {
            "binary_sha256": "o" * 64,
            "functions": [_function("optparse:clone", "copied_opt", 8, "development", cloned_reused)],
            "variables": [],
        })
        dump(labels_v2 / "sds-O0.labels.json", stub_labels("sds", "development"))
        dump(labels_v2 / "tiny_regex_c-O0.labels.json", stub_labels("tiny_regex_c", "development"))
        reused = ((labels_v1, builder.REUSED_V1_PROJECTS), (labels_v2, builder.REUSED_V2_PROJECTS))
        loaded = builder.load_reused_training_functions(reused)
        assert loaded
        assert all(row["split"] == "train" for row in loaded)
        assert any(row["function_id"] == "optparse:clone" for row in loaded)
        inventories = [_inventory("md4c", "development", "O0", "md4c-O0.elf", [
            _function("md4c:clone", "copied_md", 32, "development", cloned_dev),
            _function("md4c:keep", "keep", 48, "development"),
        ], [])]
        without_override = corpus.cross_split_clones(inventories[0]["functions"] + [
            _function("optparse:clone", "copied_opt", 8, "development", cloned_reused)])
        assert without_override == []
        groups = builder.clone_screen(inventories, reused)
        assert groups
        assert any("train" in group["splits"] and "development" in group["splits"] for group in groups)
        assert any("optparse:clone" in group["function_ids"] for group in groups)


def test_clone_screen_excludes_development_and_keeps_training():
    first = 'int f(int x) { const char *s="}"; /* } */ if(x) { x += 1; } return x; }'
    second = 'int g(int y) { const char *s="}"; if(y) { y += 1; } return y; }'
    cloned_dev = corpus.function_fingerprints(first, 1, "f")
    cloned_train = corpus.function_fingerprints(second, 1, "g")
    inventories = [
        _inventory("hashmap", "train", "O0", "hashmap-O0.elf", [
            _function("hashmap:keep", "keep_train", 40, "train"),
            _function("hashmap:clone", "copied_train", 24, "train", cloned_train),
        ], [
            _variable("hashmap:keep", "n", label="i32", class_id=7),
            _variable("hashmap:clone", "p", label="char*", class_id=3),
        ]),
        _inventory("md4c", "development", "O0", "md4c-O0.elf", [
            _function("md4c:keep", "keep_dev", 64, "development"),
            _function("md4c:clone", "copied_dev", 16, "development", cloned_dev),
        ], [
            _variable("md4c:keep", "n", label="i32", class_id=7),
            _variable("md4c:clone", "p", status="unmapped"),
        ]),
        _inventory("json_parser", "development", "O0", "json_parser-O0.elf", [
            _function("json:one", "parse", 8, "development"),
        ], []),
    ]
    groups = corpus.cross_split_clones(
        inventories[0]["functions"] + inventories[1]["functions"] + inventories[2]["functions"])
    assert groups
    scope = builder.export_scope(inventories, groups, "p" * 64, "m" * 64,
                                 ["hashmap", "md4c", "json_parser"])
    case_ids = [row["function_id"] for row in scope["cases"]]
    assert "hashmap:clone" in case_ids
    assert "hashmap:keep" in case_ids
    assert "md4c:keep" in case_ids
    assert "json:one" in case_ids
    assert "md4c:clone" not in case_ids
    assert [row["function_id"] for row in scope["excluded_clone_functions"]] == ["md4c:clone"]
    assert scope["excluded_clone_functions"][0]["clone_groups"]
    assert "train" in scope["excluded_clone_functions"][0]["clone_groups"][0]["splits"]


def test_export_scope_caps_orders_and_leaks_no_labels():
    first = 'int f(int x) { const char *s="}"; /* } */ if(x) { x += 1; } return x; }'
    second = 'int g(int y) { const char *s="}"; if(y) { y += 1; } return y; }'
    cloned_dev = corpus.function_fingerprints(first, 1, "f")
    cloned_train = corpus.function_fingerprints(second, 1, "g")
    over = [_function("btree:n%d" % i, "n%d" % i, 200 + i, "train") for i in range(61)]
    inventories = [
        _inventory("btree", "train", "O0", "btree-O0.elf", over, [
            _variable("btree:n0", "n", label="i32", class_id=7),
        ]),
        _inventory("hashmap", "train", "O0", "hashmap-O0.elf", [
            _function("hashmap:clone", "copied_train", 24, "train", cloned_train),
            _function("hashmap:keep", "keep_train", 40, "train"),
        ], [
            _variable("hashmap:clone", "p", label="char*", class_id=3),
        ]),
        _inventory("md4c", "development", "O0", "md4c-O0.elf", [
            _function("md4c:clone", "copied_dev", 16, "development", cloned_dev),
            _function("md4c:keep", "keep_dev", 64, "development"),
        ], [
            _variable("md4c:clone", "p", label="char*", class_id=3),
            _variable("md4c:keep", "q", status="unmapped"),
        ]),
        _inventory("parson", "development", "O0", "parson-O0.elf", [
            _function("parson:one", "parse", 4, "development"),
        ], []),
        _inventory("json_parser", "development", "O0", "json_parser-O0.elf", [
            _function("json:one", "parse", 12, "development"),
        ], []),
    ]
    groups = corpus.cross_split_clones(
        inventories[1]["functions"] + inventories[2]["functions"])
    order = ["hashmap", "btree", "md4c", "json_parser", "parson"]
    scope = builder.export_scope(inventories, groups, "p" * 64, "m" * 64, order)
    assert scope["schema"] == "symbai.type_v3_export_scope.v1"
    case_ids = [row["function_id"] for row in scope["cases"]]
    train_ids = [row["function_id"] for row in scope["cases"] if row["split"] == "train"]
    development_ids = [row["function_id"] for row in scope["cases"] if row["split"] == "development"]
    btree_kept, btree_capped = builder.apply_cap("btree", over)
    assert train_ids[:2] == ["hashmap:clone", "hashmap:keep"]
    assert train_ids[2:] == [row["function_id"] for row in btree_kept]
    assert development_ids == ["md4c:keep", "json:one", "parson:one"]
    assert case_ids.index("hashmap:keep") < case_ids.index(btree_kept[0]["function_id"])
    assert case_ids.index(btree_kept[-1]["function_id"]) < case_ids.index("md4c:keep")
    assert case_ids.index("md4c:keep") < case_ids.index("json:one") < case_ids.index("parson:one")
    assert "md4c:clone" not in case_ids
    assert [row["function_id"] for row in scope["excluded_clone_functions"]] == ["md4c:clone"]
    btree_cap = scope["capped_out_functions"]["btree"]
    assert btree_cap["total_functions"] == 61
    assert btree_cap["kept"] == 60
    assert btree_cap["capped_out_function_ids"] == btree_capped
    assert len(btree_cap["capped_out_function_ids"]) == 1
    assert scope["candidate_functions"]["train"] == 2 + 60
    assert scope["candidate_functions"]["development"] == 3
    btree_n0_kept = any(row["function_id"] == "btree:n0" for row in btree_kept)
    assert scope["candidate_source_variable_records"]["train"] == 1 + int(btree_n0_kept)
    assert scope["candidate_source_variable_records"]["development"] == 1
    assert scope["preregistration_sha256"] == "p" * 64
    assert scope["manifest_sha256"] == "m" * 64
    assert scope["evaluation_projects_selected"] is False
    assert scope["labels_in_scope"] is False
    walk_forbidden(scope)
    dumped = json.dumps(scope)
    assert '"label"' not in dumped
    assert "class_id" not in dumped
    assert "before_normalization" not in dumped
    assert "i32" not in dumped
    assert "char*" not in dumped
    for row in scope["cases"]:
        assert set(row) == {
            "function_id", "project_id", "split", "function_name", "function_address",
            "binary", "binary_sha256", "profile", "source_variable_records",
            "mapped_source_variable_records",
        }
        assert row["profile"] == "O0"
        assert row["split"] in ("train", "development")


def test_prepare_only_writes_plan_and_vocabulary_without_compiling(monkeypatch):
    with workspace("v3_prepare_only") as root:
        corpus_dir, prereg, digest, reused = make_corpus(root)
        output = corpus_dir / "labels-test"

        def boom(*args, **kwargs):
            raise AssertionError("compile invoked during prepare-only")

        monkeypatch.setattr(builder.subprocess, "run", boom)
        previous = {key: os.environ.get(key) for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME")}
        try:
            builder.run_inventory(corpus_dir, output, prepare_only=True, preregistration=prereg,
                                  expected_sha=digest, reused_inventories=reused)
            assert (output / "plan.json").is_file()
            assert (output / "label-vocabulary.json").is_file()
            assert not (output / "summary.json").exists()
            assert not (output / "records.json").exists()
            assert not (output / "export-scope.json").exists()
            assert not (output / "compiler-version.txt").exists()
            assert not (output / "cross-split-clone-review.json").exists()
            assert list(output.glob("*.elf")) == []
            assert list(output.glob("*.build.log")) == []
            plan = load(output / "plan.json")
            assert plan["compiler"] is None
            assert plan["function_cap"] == 60
            assert plan["schema"] == "symbai.type_v3_build_plan.v1"
            assert [row["project_id"] for row in plan["builds"]] == [
                "hashmap", "btree", "md4c", "json_parser", "parson"]
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
