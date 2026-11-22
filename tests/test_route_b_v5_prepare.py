"""Header pinning stays within the declared v5 source scope."""
from pathlib import Path
import shutil
import uuid

import pytest

from scripts import prepare_route_b_v5_sources as prepare


@pytest.mark.parametrize("includes", [["include"], [".", "include"]])
def test_header_recursion_and_excluded_directories(monkeypatch, includes):
    workspace = Path(".test-output") / ("v5-prepare-" + uuid.uuid4().hex)
    target = workspace / "fixture"
    assert workspace.resolve().parent == Path(".test-output").resolve()
    try:
        files = ["root.h", "src/unit.c", "src/unit.h", "src/private/nested.h",
                 "ordinary/nested.h", "nested/test/include/stddef.h", "include/detail/x.h"]
        files.extend("include/%s-fixtures/include/stddef.h" % word
                     for word in prepare.EXCLUDED_DIR_WORDS)
        for name in files:
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"/* synthetic source */\n")
        (target / ".git").mkdir()
        calls = []

        def git(*args, **kwargs):
            calls.append(args)
            return "main" if "--abbrev-ref" in args else "1" * 40

        monkeypatch.setattr(prepare, "git", git)
        entry = prepare.prepare_project(workspace, ("fixture", "fixture/repository", ["src"],
                                                    includes, [], None))
        assert entry["status"] == "pinned"
        assert entry["translation_units"] == ["src/unit.c"]
        assert set(entry["source_files"]) == {"root.h", "src/unit.c", "src/unit.h",
                                              "include/detail/x.h"}
        assert entry["source_files"]["root.h"] == prepare.sha(target / "root.h")
        assert entry["include_directories"] == [".", "include", "src"]
        assert len(calls) == 3
    finally:
        if workspace.exists():
            shutil.rmtree(str(workspace))
