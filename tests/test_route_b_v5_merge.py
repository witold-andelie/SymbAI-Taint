"""Compiled-manifest merger tests; all outputs stay under .test-output."""
import json
from pathlib import Path
import shutil
import uuid

import pytest

from scripts import merge_route_b_v5_sources as merger


@pytest.fixture
def folder():
    Path(".test-output").mkdir(exist_ok=True)
    path = Path(".test-output") / ("v5-merge-" + uuid.uuid4().hex)
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(str(path))


def manifests(folder):
    docs = [{"schema": merger.SCHEMA, "compilation_performed": True,
             "juliet": {"directory": "juliet", "files": {"case.c": "a" * 64}},
             "projects": [{"project_id": "p1", "status": "pinned", "dwarf_elf": "p1.elf",
                           "source_files": {"unit.c": "b" * 64}, "custom": [1, 2]}],
             "pins": {"design.md": "d" * 64, "a1.md": "1" * 64}},
            {"schema": merger.SCHEMA, "compilation_performed": True, "juliet": None,
             "projects": [{"project_id": "p2", "status": "dropped", "drop_reason": "compile_failed"}],
             "pins": {"design.md": "d" * 64, "a2.md": "2" * 64}}]
    paths = [folder / name for name in ("base.json", "amendment.json")]
    for path, doc in zip(paths, docs):
        write(path, doc)
    return paths, docs


def write(path, doc):
    path.write_bytes((json.dumps(doc) + "\n").encode("ascii"))


def output(folder):
    # The output itself must be a new, direct child of .test-output.
    return folder.with_name(folder.name + "-merged")


def cleanup(path):
    if path.exists():
        (path / "sources-manifest.json").unlink()
        path.rmdir()


def test_merge_preserves_projects_juliet_pins_and_inputs(folder):
    paths, docs = manifests(folder)
    before = [p.read_bytes() for p in paths]
    target = output(folder)
    try:
        assert merger.main(["--base", str(paths[0]), "--amendment", str(paths[1]), "--output", str(target)]) is None
        data = (target / "sources-manifest.json").read_bytes()
        result = json.loads(data)
        assert result["juliet"] == docs[0]["juliet"]
        assert result["projects"] == docs[0]["projects"] + docs[1]["projects"]
        assert result["compilation_performed"] is True
        assert result["merged_from"] == [merger.relative(p) for p in paths]
        assert result["pins"] == {**docs[0]["pins"], **docs[1]["pins"],
                                  **{merger.relative(p): merger.sha(b) for p, b in zip(paths, before)}}
        assert [p.read_bytes() for p in paths] == before
        assert b"\r" not in data
        data.decode("ascii")
    finally:
        cleanup(target)


@pytest.mark.parametrize("change,match", [("schema", "compiled"), ("uncompiled", "compiled"),
                                         ("truthy", "compiled"), ("duplicate", "Duplicate"),
                                         ("case_duplicate", "Duplicate"), ("conflict", "Conflicting"),
                                         ("juliet", "Juliet")])
def test_invalid_inputs_fail_before_output(folder, change, match):
    paths, docs = manifests(folder)
    if change == "schema":
        docs[1]["schema"] = "other"
    elif change == "uncompiled":
        docs[1]["compilation_performed"] = False
    elif change == "truthy":
        docs[1]["compilation_performed"] = 1
    elif change in ("duplicate", "case_duplicate"):
        docs[1]["projects"][0]["project_id"] = "p1" if change == "duplicate" else "P1"
    elif change == "conflict":
        docs[1]["pins"]["design.md"] = "e" * 64
    elif change == "juliet":
        docs[1]["juliet"] = {}
    write(paths[1], docs[1])
    target = output(folder)
    with pytest.raises(ValueError, match=match):
        merger.merge(paths[0], paths[1], target)
    assert not target.exists()


def test_output_is_new_and_confined(folder):
    paths, docs = manifests(folder)
    for target in (folder, Path(".test-output"), folder / "nested", folder / ".." / ".." / "escape"):
        with pytest.raises(ValueError, match="new child"):
            merger.merge(paths[0], paths[1], target)


def test_manifest_pin_cannot_be_overwritten(folder):
    paths, docs = manifests(folder)
    docs[0]["pins"][merger.relative(paths[1])] = "0" * 64
    write(paths[0], docs[0])
    with pytest.raises(ValueError, match="manifest pin"):
        merger.merge(paths[0], paths[1], output(folder))
