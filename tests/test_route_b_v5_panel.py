"""Native-only v5 construction and screened selection; no held-out builds."""

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

import pytest

from scripts import build_route_b_v5_panel as builder
from src.selective_analysis import fixture_build as fixture


ROOT = Path(__file__).resolve().parents[1]
FREEZE = (ROOT.parent / ".scratch/selective_analysis"
          / "route-b-v4-freeze-20261121T073634943739Z/freeze.json")
_spec = importlib.util.spec_from_file_location("route_b_v5_test_v4_helpers",
                                              str(ROOT / "tests/test_route_b_v4_panel.py"))
v4_tests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v4_tests)


@pytest.fixture(scope="module", autouse=True)
def native_temporary_directory():
    path = ROOT / ".test-output/temp"
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    previous = {key: os.environ.get(key) for key in ("TEMP", "TMP")}
    os.environ.update(TEMP=str(path), TMP=str(path))
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if not existed:
            path.rmdir()


@contextlib.contextmanager
def workspace(name):
    path = ROOT / ".test-output" / name
    assert path.resolve().parent == (ROOT / ".test-output").resolve()
    if path.exists():
        shutil.rmtree(str(path))
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(str(path))


def load(path):
    return json.loads(path.read_bytes())


def empty_plan():
    return {"hashes": {}, "candidates": [], "rejections": [],
            "overlap_check": {"projects": {}, "juliet_files": {}}}


def juliet_manifest(directory):
    return {"directory": builder.relative(directory), "archive_sha256": "a" * 64,
            "files": {path.name: fixture.file_hash(path) for path in directory.glob("*.c")}}


def copy_juliet(directory, count=6):
    directory.mkdir(parents=True, exist_ok=True)
    paths = sorted((ROOT / "benchmarks/juliet/cases").glob("*CWE129*.c"))
    assert len(paths) == 6
    copies = []
    for index, path in enumerate(paths[:count]):
        name = "CWE124_Buffer_Underwrite__CWE839_copy%d_01.c" % index
        target = directory / name
        fixture.write_text(target, path.read_text(encoding="utf-8-sig").replace(path.stem, target.stem))
        copies.append(target)
    return copies


@pytest.mark.parametrize("name,eligible", [
    ("CWE121_Stack__CWE129_fgets_01.c", True),
    ("CWE122_Heap__CWE839_rand_01.c", True),
    ("CWE124_Underwrite__CWE839_fscanf_01.c", True),
    ("CWE123_Anything__CWE129_fgets_01.c", False),
    ("CWE121_Stack__CWE129_fgets_02.c", False),
    ("CWE124_Underwrite__CWE789_fgets_01.c", False),
    ("CWE124_Underwrite__CWE839_fgets_01.cpp", False),
    ("nested/CWE124_Underwrite__CWE839_fgets_01.c", False),
])
def test_s1_eligibility(name, eligible):
    assert builder.eligible_juliet(name) is eligible


def test_s1_copies_v4_exclusion_unsupported_and_manifest_mismatch():
    with workspace("route-b-v5-juliet") as root:
        directory = root / "juliet"
        copies = copy_juliet(directory)
        frozen = sorted((ROOT / "benchmarks/juliet/cases").glob("*CWE129*.c"))
        for path in frozen:
            shutil.copyfile(str(path), str(directory / path.name))
        unsupported = directory / "CWE124_Buffer_Underwrite__CWE839_socket_01.c"
        fixture.write_text(unsupported, "/* Unsupported native input source. */\n")
        plan = empty_plan()
        manifest = juliet_manifest(directory)
        builder.select_juliet(plan, manifest, set())
        assert len(plan["candidates"]) == 18
        assert {row["binary_group"] for row in plan["candidates"]} == {path.name for path in copies}
        assert all(row["spec"] == builder.v4.juliet_spec(ROOT / row["source"],
                                                       row["case_id"].rsplit("-", 1)[-1])
                   for row in plan["candidates"])
        rejections = plan["rejections"]
        assert {row["binary_group"] for row in rejections if row["reason"] == "v4_juliet_file"} == {
            path.name for path in frozen}
        assert [row["reason"] for row in rejections if row["binary_group"] == unsupported.name] == [
            "source_extraction_failed"] * 3
        manifest["files"]["CWE123_False__CWE839_fake_01.c"] = "0" * 64
        with pytest.raises(ValueError, match="eligibility mismatch"):
            builder.select_juliet(empty_plan(), manifest, set())
        del manifest["files"]["CWE123_False__CWE839_fake_01.c"]
        del manifest["files"][copies[0].name]
        with pytest.raises(ValueError, match="eligibility mismatch"):
            builder.select_juliet(empty_plan(), manifest, set())


def test_s1_admission_rejections_do_not_make_a_finished_build_incomplete(monkeypatch):
    with workspace("route-b-v5-s1-admission") as root:
        directory = root / "juliet"
        directory.mkdir()
        for path in (ROOT / "benchmarks/juliet/cases").glob("*CWE129*.c"):
            shutil.copyfile(str(path), str(directory / path.name))
        fixture.write_text(directory / "CWE124_Underwrite__CWE839_unsupported_01.c", "/* unsupported */\n")
        manifest = root / "sources.json"
        fixture.write_json(manifest, {"schema": "symbai.route_b_v5_sources.v1",
                                     "juliet": juliet_manifest(directory), "projects": []})
        output = root / "build"
        cmd = fixture.cmd

        def version_only(args, *rest, **kwargs):
            assert args in (["gcc", "--version"], ["gcc", "-dumpmachine"])
            return cmd(args, *rest, **kwargs)

        monkeypatch.setattr(fixture, "cmd", version_only)
        assert builder.main(["--plan-only", "--sources-manifest", builder.relative(manifest),
                             "--output", builder.relative(output)]) == 0
        assert builder.main(["--build", "--output", builder.relative(output)]) == 0
        plan = load(output / "plan.json")
        assert plan["build_complete"] and plan["build_finished"]
        assert not plan["candidates"]
        assert len(plan["rejections"]) == 9


def tiny_manifest(root):
    if not shutil.which("gcc") or not shutil.which("nm"):
        pytest.skip("MinGW gcc and nm are required for synthetic DWARF fixtures")
    projects = []
    for suffix in ("a", "b"):
        name = "v5_tiny_" + suffix
        directory = root / "sources" / name
        (directory / "include").mkdir(parents=True)
        (directory / "config").mkdir()
        header = directory / "include/fixture.h"
        fixture.write_text(header, "#ifndef V5_MASK\n#error manifest define missing\n#endif\n")
        source = directory / "unit.c"
        text = ("#include \"fixture.h\"\n"
                "int first(int x) { return x & V5_MASK; }\n"
                "int second(int x) { return (x & V5_MASK) + 1; }\n"
                "double wrong_return(int x) { return x; }\n"
                "int link_failure(int x) { extern int absent(int); return absent(x); }\n")
        fixture.write_text(source, text.replace("extern int absent(int); return absent(x);", "return x;"))
        driver = root / (name + "-driver.c")
        fixture.write_text(driver, "int main(void) { return 0; }\n")
        executable = root / (name + "-debug.exe")
        binary = root / (name + "-debug.elf")
        try:
            fixture.cmd(["gcc", "-O0", "-g", "-gdwarf-4", "-I", str(header.parent),
                         "-DV5_MASK=3", str(source), str(driver), "-o", str(executable)], ROOT)
            v4_tests.debug_elf_from_pe(executable, binary)
        except (OSError, RuntimeError) as error:
            pytest.skip("Cannot construct MinGW synthetic DWARF ELF: " + str(error))
        fixture.write_text(source, text)
        projects.append({"project_id": name, "status": "pinned", "repository": "https://example.invalid/team/" + name,
                         "commit": "1" * 40, "source_directory": builder.relative(directory),
                         "source_files": {"unit.c": fixture.file_hash(source),
                                          "include/fixture.h": fixture.file_hash(header)},
                         "translation_units": ["unit.c"], "include_directories": ["include", "config", "."],
                         "defines": ["-DV5_MASK=3"], "dwarf_elf": builder.relative(binary),
                         "dwarf_elf_sha256": fixture.file_hash(binary)})
    juliet = root / "juliet"
    copy_juliet(juliet, count=1)
    manifest = root / "sources.json"
    fixture.write_json(manifest, {"schema": "symbai.route_b_v5_sources.v1", "juliet": juliet_manifest(juliet),
                                 "projects": projects + [{"project_id": "v5_dropped", "status": "dropped",
                                                           "drop_reason": "no_compiling_unit"}]})
    return manifest, projects


def screen_file(root, plan, exclusions=()):
    path = root / "screen.json"
    build_dir = root if (root / "plan.json").is_file() else root / "build"
    fixture.write_json(path, {"schema": "symbai.route_b_v5_sanitizer_screen.v1",
        "plan_sha256": fixture.file_hash(build_dir / "plan.json"),
        "references_sha256": fixture.file_hash(build_dir / "unscreened-references.json"), "kernels": [
        {"kernel_id": row["case_id"], "status": "excluded" if row["case_id"] in exclusions else "pass",
         "reason": "native_undefined_behavior" if row["case_id"] in exclusions else None}
        for row in plan["candidates"] if row["status"] == "built"]})
    return path


def test_tiny_two_project_plan_build_finalize(monkeypatch):
    with workspace("route-b-v5-native") as root:
        manifest, projects = tiny_manifest(root)
        output = root / "build"
        cmd = fixture.cmd

        def version_only(args, *rest, **kwargs):
            assert args in (["gcc", "--version"], ["gcc", "-dumpmachine"])
            return cmd(args, *rest, **kwargs)

        monkeypatch.setattr(fixture, "cmd", version_only)
        assert builder.main(["--plan-only", "--sources-manifest", builder.relative(manifest),
                             "--output", builder.relative(output)]) == 0
        plan = load(output / "plan.json")
        assert sorted(path.name for path in output.iterdir()) == ["plan.json"]
        assert len(plan["candidates"]) == 9
        expected = [builder.DESIGN, builder.AMENDMENT, builder.V4_PATH,
                    ROOT / "src/selective_analysis/fixture_build.py", Path(builder.__file__), manifest]
        for project in projects:
            expected.append(ROOT / project["dwarf_elf"])
            expected.extend(ROOT / project["source_directory"] / name for name in project["source_files"])
        for path in expected:
            assert plan["hashes"][builder.relative(path)] == fixture.file_hash(path)
        assert any(row["reason"] == "no_compiling_unit" for row in plan["rejections"])
        for row in plan["candidates"]:
            if row["stratum"] == "S2":
                assert "-DV5_MASK=3" in row["spec"]["flags"]
                assert any(value.endswith("/config") for value in row["spec"]["include_directories"])
        pinned = ROOT / projects[0]["source_directory"] / "include/fixture.h"
        original = pinned.read_bytes()
        pinned.write_bytes(original + b"\n")
        with pytest.raises(SystemExit) as error:
            builder.main(["--build", "--output", builder.relative(output)])
        assert error.value.code == 1
        assert sorted(path.name for path in output.iterdir()) == ["plan.json"]
        pinned.write_bytes(original)
        monkeypatch.setattr(fixture, "cmd", cmd)
        monkeypatch.setattr(builder, "make_plan", lambda *args: pytest.fail("build must reuse its plan"))
        assert builder.main(["--build", "--output", builder.relative(output)]) == 0
        built = load(output / "plan.json")
        assert built["build_finished"] and built["build_complete"]
        assert built["hashes"] == plan["hashes"]
        assert len(load(output / "unscreened-panel.json")["records"]) == 11
        assert not (output / "panel.json").exists()
        assert not (output / "offline-references.json").exists()
        assert sum(row["reason"] == "freestanding_link_failed" for row in built["rejections"]) == 2
        excluded = next(row["case_id"] for row in built["candidates"]
                        if row.get("name") == "second" and row["project"] == "v5_tiny_a")
        screen = screen_file(root, built, [excluded])

        def forbidden(*args, **kwargs):
            pytest.fail("finalize must not compile or enumerate")

        monkeypatch.setattr(fixture, "cmd", forbidden)
        monkeypatch.setattr(fixture, "compile_case", forbidden)
        monkeypatch.setattr(fixture, "native_reference", forbidden)
        final = root / "final"
        assert builder.main(["--finalize", "--build-dir", builder.relative(output), "--screen",
                             builder.relative(screen), "--output", builder.relative(final)]) == 0
        runtime = load(final / "panel.json")
        assert runtime["schema"] == "symbai.route_b_v5_panel.v1"
        assert len(runtime["records"]) == 6
        assert all(not row["case_id"].startswith(excluded + "-cap") for row in runtime["records"])
        for row in runtime["records"]:
            assert set(row) == builder.RUNTIME_KEYS
            fixture.Query.from_dict(row["query"], final)
            assert (final / row["query"]["binary"]).read_bytes() == (output / row["query"]["binary"]).read_bytes()
        assert load(final / "offline-references.json")["schema"] == "symbai.route_b_v5_offline_references.v1"
        for word in ("outcome", "indices", "witness", "safe", "violation"):
            assert word not in (final / "panel.json").read_text()
        selection = load(final / "selection.json")
        assert selection["minimum_met"] is False
        assert selection["counts"] == {"queries": 6, "groups": 2, "by_stratum": {"S2": 6},
                                       "by_group": {"v5_tiny_a": 2, "v5_tiny_b": 4}}
        assert selection["pins"]["screen_sha256"] == fixture.file_hash(screen)
        assert selection["pins"]["build_files"] == builder.directory_pins(output)


def synthetic_build(root, project_count=2, kernel_count=6, juliet_count=8, capacities=(1, 2)):
    """Selection-only test doubles. Real ELF construction is tested above."""
    output = root / "build"
    output.mkdir()
    binary = output / "synthetic.elf"
    binary.write_bytes(b"\x7fELF selection-only test double\n")
    plan = dict(empty_plan(), schema="symbai.route_b_v5_plan.v1", mode="build", build_finished=True)
    builder.pin(plan, ROOT / "scripts/build_route_b_v5_panel.py")
    records, references = [], {}

    def add(key, stratum, group, caps):
        plan["candidates"].append({"case_id": key, "stratum": stratum, "binary_group": group,
                                   "project": group if stratum == "S2" else "Juliet", "status": "built"})
        for capacity in caps:
            query_id = key + "-cap%d" % capacity if stratum == "S2" else key
            query = {"query_id": query_id, "binary": binary.name, "binary_sha256": fixture.file_hash(binary),
                     "entry_rva": 0, "write_rva": 1, "object_rva": 2, "capacity": capacity,
                     "inputs": [{"register": "rdi", "minimum": 0, "maximum": 255}]}
            records.append({"case_id": query_id, "stratum": stratum, "project": group if stratum == "S2" else "Juliet",
                            "binary_group": group, "query": query})
            references[query_id] = {"indices": [0] * 256, "outcome": "safe"}

    for project in range(project_count):
        group = "project_%02d" % project
        for kernel in range(kernel_count):
            add(group + "-kernel_%d-L%d" % (kernel, kernel + 1), "S2", group, capacities)
    for index in range(juliet_count):
        name = "CWE124_Underwrite__CWE839_%02d_01" % index
        for variant in builder.VARIANTS:
            add(name + "-" + variant, "S1", name + ".c", (10,))
    builder.write_panel(output, records, references)
    plan["build_artifacts"] = builder.directory_pins(output)
    fixture.write_json(output / "plan.json", plan)
    return output, plan


def test_caps_exact_survivors_and_all_capacities_removed():
    with workspace("route-b-v5-caps") as root:
        output, plan = synthetic_build(root)
        s2 = [row for row in plan["candidates"] if row["stratum"] == "S2"]
        # Exclude the first hash-ranked kernel, so the fifth passes the cap.
        excluded = min((row["case_id"] for row in s2 if row["project"] == "project_00"),
                       key=builder.digest_order)
        screen = screen_file(root, plan, [excluded])
        final = root / "final"
        selection = builder.finalize(output, screen, final)
        runtime = load(final / "panel.json")["records"]
        expected_kernels = set()
        for project in ("project_00", "project_01"):
            keys = [row["case_id"] for row in s2 if row["project"] == project and row["case_id"] != excluded]
            expected_kernels.update(sorted(keys, key=lambda key: hashlib.sha256(key.encode()).hexdigest())[:4])
        # Sixteen S2 queries allow five S1 queries, hence only one triple.
        first_file = min({row["binary_group"] for row in plan["candidates"] if row["stratum"] == "S1"},
                         key=lambda name: hashlib.sha256(name.encode()).hexdigest())
        expected = {key + "-cap%d" % cap for key in expected_kernels for cap in (1, 2)}
        expected.update(first_file[:-2] + "-" + variant for variant in builder.VARIANTS)
        assert {row["case_id"] for row in runtime} == expected
        assert all(not row["case_id"].startswith(excluded + "-cap") for row in runtime)
        assert selection["s1_query_limit"] == 5
        assert selection["counts"]["by_stratum"] == {"S1": 3, "S2": 16}
        assert len([row for row in selection["decisions"] if row["stage"] == "s2_cap"]) == 11
        assert len([row for row in selection["decisions"] if row["stage"] == "s1_cap"]) == 8
        assert selection["minimum_met"] is False


def test_screen_excluded_s1_variant_keeps_no_partial_file():
    with workspace("route-b-v5-s1-screen") as root:
        output, plan = synthetic_build(root, project_count=2, kernel_count=4, juliet_count=1)
        excluded = next(row["case_id"] for row in plan["candidates"] if row["stratum"] == "S1")
        selection = builder.finalize(output, screen_file(root, plan, [excluded]), root / "final")
        assert selection["counts"]["by_stratum"] == {"S2": 16}
        assert any(row.get("reason") == "incomplete_or_excluded_file" for row in selection["decisions"])


def test_screen_can_be_added_to_build_directory_and_output_can_be_empty():
    with workspace("route-b-v5-screen-in-build") as root:
        output, plan = synthetic_build(root, project_count=1, kernel_count=1, juliet_count=0)
        screen = screen_file(output, plan)
        final = root / "final"
        final.mkdir()
        selection = builder.finalize(output, screen, final)
        assert selection["counts"]["queries"] == 2
        assert selection["pins"]["build_files"]["screen.json"] == fixture.file_hash(screen)
        with pytest.raises(ValueError, match="new or empty"):
            builder.finalize(output, screen, final)


@pytest.mark.parametrize("kind", ["missing", "duplicate", "bad_status", "changed_input", "changed_elf", "changed_panel"])
def test_finalize_rejects_missing_invalid_screen_and_changed_pins(kind):
    with workspace("route-b-v5-invalid-" + kind) as root:
        output, plan = synthetic_build(root)
        screen = screen_file(root, plan)
        if kind in ("missing", "duplicate", "bad_status"):
            data = load(screen)
            if kind == "missing":
                data["kernels"].pop()
            elif kind == "duplicate":
                data["kernels"].append(data["kernels"][0])
            else:
                data["kernels"][0]["status"] = "unknown"
            fixture.write_json(screen, data)
        elif kind == "changed_input":
            changed = root / "pinned.c"
            fixture.write_text(changed, "int before;\n")
            builder.pin(plan, changed)
            fixture.write_json(output / "plan.json", plan)
            fixture.write_text(changed, "int after;\n")
        elif kind == "changed_elf":
            (output / "synthetic.elf").write_bytes(b"changed")
        else:
            fixture.write_text(output / "unscreened-panel.json", "{}\n")
        final = root / "final"
        with pytest.raises(ValueError, match="screen entry|Input changed|pin changed"):
            builder.finalize(output, screen, final)
        assert not final.exists()


@pytest.mark.parametrize("field", ["plan_sha256", "references_sha256"])
@pytest.mark.parametrize("change", ["missing", "mismatch", "stale_build"])
def test_finalize_requires_screen_hashes_for_current_build(field, change, capsys):
    with workspace("route-b-v5-screen-hash-%s-%s" % (field, change)) as root:
        output, plan = synthetic_build(root)
        screen = screen_file(root, plan)
        data = load(screen)
        if change == "missing":
            del data[field]
        elif change == "mismatch":
            data[field] = "0" * 64
        elif field == "plan_sha256":
            plan["instrument_note"] = "plan changed after the screen"
            fixture.write_json(output / "plan.json", plan)
        else:
            path = output / "unscreened-references.json"
            references = load(path)
            references["instrument_note"] = "references changed after the screen"
            fixture.write_json(path, references)
            plan["build_artifacts"][path.name] = fixture.file_hash(path)
            fixture.write_json(output / "plan.json", plan)
            # Match the changed plan so only the stale references pin is tested.
            data["plan_sha256"] = fixture.file_hash(output / "plan.json")
        fixture.write_json(screen, data)
        final = root / "final"
        with pytest.raises(SystemExit) as error:
            builder.main(["--finalize", "--build-dir", builder.relative(output),
                          "--screen", builder.relative(screen), "--output", builder.relative(final)])
        assert error.value.code == 1
        assert field in capsys.readouterr().err
        assert not final.exists()


@pytest.mark.parametrize("change", ["missing", "mismatch"])
@pytest.mark.parametrize("overlap", [False, True])
def test_plan_only_requires_each_pinned_dwarf_inventory_hash(monkeypatch, capsys, change, overlap):
    with workspace("route-b-v5-dwarf-hash-%s-%s" % (change, overlap)) as root:
        projects = []
        for index in range(2):
            directory = root / ("project_%d" % index)
            directory.mkdir()
            dwarf = directory / "inventory.elf"
            dwarf.write_bytes(b"synthetic DWARF inventory\n")
            projects.append({"project_id": "inventory_%d" % index, "status": "pinned",
                             "source_directory": builder.relative(directory), "source_files": {},
                             "translation_units": [], "dwarf_elf": builder.relative(dwarf),
                             "dwarf_elf_sha256": fixture.file_hash(dwarf)})
        if change == "missing":
            del projects[1]["dwarf_elf_sha256"]
        else:
            projects[1]["dwarf_elf_sha256"] = "0" * 64
        juliet = root / "juliet"
        juliet.mkdir()
        manifest = root / "sources.json"
        fixture.write_json(manifest, {"schema": "symbai.route_b_v5_sources.v1",
                                     "projects": projects, "juliet": juliet_manifest(juliet)})

        def compiler_version(args, cwd):
            assert args in (["gcc", "--version"], ["gcc", "-dumpmachine"])
            return "synthetic gcc\n" if "--version" in args else "synthetic-target\n"

        monkeypatch.setattr(fixture, "cmd", compiler_version)

        def overlap_inventory(plan):
            plan["overlap_check"] = {"projects": {}, "juliet_files": {}}
            return {"inventory_1"} if overlap else set(), set()

        monkeypatch.setattr(builder, "overlap_inventory", overlap_inventory)
        output = root / "plan"
        with pytest.raises(SystemExit) as error:
            builder.main(["--plan-only", "--sources-manifest", builder.relative(manifest),
                          "--output", builder.relative(output)])
        assert error.value.code == 1
        assert "DWARF inventory hash differs" in capsys.readouterr().err
        assert not output.exists()


@pytest.mark.parametrize("projects,kernels,capacities,queries,groups,minimum", [
    (30, 2, (1, 2), 120, 30, True),
    (29, 4, (1, 2), 232, 29, False),
    (30, 1, (1, 2), 60, 30, False),
    (30, 4, (65536,), 120, 30, True),
    (0, 0, (1,), 0, 0, False),
])
def test_minimum_boundaries(projects, kernels, capacities, queries, groups, minimum):
    with workspace("route-b-v5-minimum-%d-%d" % (projects, kernels)) as root:
        output, plan = synthetic_build(root, project_count=projects, kernel_count=kernels,
                                       juliet_count=0, capacities=capacities)
        selection = builder.finalize(output, screen_file(root, plan), root / "final")
        assert selection["counts"]["queries"] == queries
        assert selection["counts"]["groups"] == groups
        assert selection["minimum_met"] is minimum


def test_overlap_inventory_includes_type_manifests_v4_plan_and_juliet_names():
    with workspace("route-b-v5-overlap") as root:
        scratch = root / "history"
        (scratch / "route-b-type-corpus").mkdir(parents=True)
        (scratch / "route-b-v4-panel").mkdir()
        fixture.write_json(scratch / "route-b-type-corpus/manifest.json",
                           {"new_projects": [{"project_id": "PreviousTypeProject"}]})
        juliet = root / "juliet"
        filename = copy_juliet(juliet, count=1)[0].name
        fixture.write_json(scratch / "route-b-v4-panel/plan.json",
                           {"candidates": [{"project": "PreviousV4Project", "binary_group": filename}]})
        plan = empty_plan()
        projects, files = builder.overlap_inventory(plan, scratch)
        assert {"previoustypeproject", "previousv4project"} <= projects
        assert filename in files
        builder.select_projects(plan, [{"project_id": "PreviousTypeProject"},
                                       {"project_id": "PreviousV4Project"}, {"project_id": "b64"}], projects)
        assert [row["reason"] for row in plan["rejections"]] == ["project_overlap", "project_overlap", "sealed_project"]
        assert len(plan["hashes"]) == 2
        builder.select_juliet(plan, juliet_manifest(juliet), files)
        assert not plan["candidates"]
        assert plan["rejections"][-1]["reason"] == "file_overlap"
        assert plan["overlap_check"]["juliet_files"][filename] == {"overlap": True}


def test_translation_unit_filters_and_dropped_overlap_reason(monkeypatch):
    with workspace("route-b-v5-translation-units") as root:
        directory = root / "sources"
        (directory / "examples").mkdir(parents=True)
        contents = {"unit.c": "int f(int x) { return x; }\n", "test_unit.c": "int t(int x) { return x; }\n",
                    "examples/example.c": "int e(int x) { return x; }\n",
                    "main.c": "int main(void) { return 0; }\n", "unit.h": "int f(int);\n"}
        for name, text in contents.items():
            fixture.write_text(directory / name, text)
        dwarf = root / "inventory.elf"
        dwarf.write_bytes(b"inventory test double\n")
        project = {"project_id": "v5_unit_filters", "status": "pinned", "source_directory": builder.relative(directory),
                   "source_files": {name: fixture.file_hash(directory / name) for name in contents},
                   "translation_units": [name for name in contents if name.endswith(".c")],
                   "include_directories": ["."], "defines": [], "dwarf_elf": builder.relative(dwarf),
                   "dwarf_elf_sha256": fixture.file_hash(dwarf)}
        admitted = []

        def select(plan, projects, previous):
            admitted.extend(projects)

        monkeypatch.setattr(builder.v4, "select_projects", select)
        plan = empty_plan()
        builder.select_projects(plan, [project, {"project_id": "old_dropped", "status": "dropped",
                                                "drop_reason": "no_compiling_unit"}], {"old_dropped"})
        assert len(admitted) == 1
        assert set(admitted[0]["source_files"]) == {"unit.c", "unit.h"}
        assert sum(row["reason"] == "translation_unit_ineligible" for row in plan["rejections"]) == 3
        assert plan["rejections"][-1]["reason"] == "no_compiling_unit"
        assert plan["overlap_check"]["projects"]["old_dropped"] == {"overlap": True}


def test_sealed_source_is_rejected_before_opening_any_source(monkeypatch):
    with workspace("route-b-v5-sealed-path") as root:
        project = {"project_id": "v5_forbidden_input", "status": "pinned", "source_directory": builder.relative(root),
                   "source_files": {"ordinary.c": "0" * 64, "utf8.h": "1" * 64}}

        def forbidden(*args):
            pytest.fail("sealed input validation must precede source hashing")

        monkeypatch.setattr(fixture, "file_hash", forbidden)
        with pytest.raises(ValueError, match="Sealed project source"):
            builder.select_projects(empty_plan(), [project], set())


def test_output_confinement_and_cli_modes():
    for path in (".", "..", ".test-output", ".test-output/../outside"):
        with pytest.raises(SystemExit) as error:
            builder.main(["--plan-only", "--sources-manifest", "absent.json", "--output", path])
        assert error.value.code == 1
    with workspace("route-b-v5-cli") as root:
        for args in (["--build"], ["--plan-only"], ["--finalize"]):
            with pytest.raises(SystemExit) as error:
                builder.main(args + ["--output", builder.relative(root)])
            assert error.value.code == 1


@pytest.mark.parametrize("name", ["scripts/build_route_b_v4_panel.py", "src/selective_analysis/fixture_build.py"])
def test_v4_frozen_files_are_byte_identical(name):
    expected = load(FREEZE)["pins"][name]
    actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert actual == expected, "%s: actual %s != v4 freeze %s" % (name, actual, expected)
