"""Sanitizer screen for Route B v5 panels, and a screened re-score of v4."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from scripts import rescore_route_b_v4_screened as rescore
from scripts import screen_route_b_v5_sanitizers as screen


ROOT = Path(__file__).resolve().parents[1]
PANEL_NAME = "route-b-v4-panel-20261121T073950924Z"
RUN_NAME = "route-b-v4-run-20261121T074927114386Z"
V4_SCHEMA = "symbai.route_b_v4_plan.v1"
V5_SCHEMA = "symbai.route_b_v5_plan.v1"
SANITIZER_TAIL = [
    "-DCHECK_NATIVE",
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-fno-omit-frame-pointer",
]


class Result(object):
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class MockEngine(object):
    def __init__(self, stdout="", stderr="", returncode=0, compile_returncode=0,
                 compile_stderr="", timeout=False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.compile_returncode = compile_returncode
        self.compile_stderr = compile_stderr
        self.timeout = timeout
        self.compile_commands = []
        self.run_commands = []
        self.run_envs = []
        self.run_timeouts = []

    def compiler(self, args, cwd):
        args = [str(part) for part in args]
        if "--version" in args:
            return Result(stdout="gcc (GCC) 9.4.0\nCopyright (C) 2019 Free Software Foundation, Inc.\n")
        if "-dumpmachine" in args:
            return Result(stdout="x86_64-linux-gnu\n")
        self.compile_commands.append({"args": args, "cwd": str(cwd)})
        return Result(returncode=self.compile_returncode, stderr=self.compile_stderr)

    def runner(self, args, cwd, env, timeout):
        args = [str(part) for part in args]
        self.run_commands.append({"args": args, "cwd": str(cwd)})
        self.run_envs.append(dict(env))
        self.run_timeouts.append(timeout)
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout,
                                            output=self.stdout, stderr=self.stderr)
        return Result(returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


class MappedStdoutEngine(MockEngine):
    def __init__(self, stdout_for):
        MockEngine.__init__(self)
        self.stdout_for = stdout_for

    def runner(self, args, cwd, env, timeout):
        kernel_id = Path(args[-1]).name
        self.stdout = self.stdout_for[kernel_id]
        self.stderr = ""
        self.returncode = 0
        self.timeout = False
        return MockEngine.runner(self, args, cwd, env, timeout)


@contextlib.contextmanager
def workspace(name):
    path = ROOT / ".test-output" / (name + "-" + uuid.uuid4().hex)
    assert path.resolve().parent == (ROOT / ".test-output").resolve()
    if path.exists():
        shutil.rmtree(str(path))
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(str(path))


def write_ascii(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path), "w", encoding="ascii", newline="\n") as stream:
        stream.write(text)


def write_json_file(path, value):
    write_ascii(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def candidate(case_id, stratum="S1", project="Juliet", binary_group="case.c",
              spec_id=None, flags=None, include_directories=None, minimum=0, maximum=2,
              status="built"):
    spec = {"id": spec_id or case_id, "min": minimum, "max": maximum,
            "flags": flags or ["-std=gnu11", "-O0", "-ffreestanding", "-fno-builtin",
                               "-fno-stack-protector"]}
    if include_directories is not None:
        spec["include_directories"] = include_directories
    return {"case_id": case_id, "stratum": stratum, "project": project,
            "binary_group": binary_group, "status": status, "spec": spec}


def make_build(directory, schema, candidates, references, extra_refs=None):
    write_json_file(directory / "plan.json", {"schema": schema, "candidates": candidates})
    name = screen.PLAN_REFERENCES[schema]
    write_json_file(directory / name, {"references": references})
    if extra_refs is not None:
        other = ("unscreened-references.json" if name == "offline-references.json"
                 else "offline-references.json")
        write_json_file(directory / other, {"references": extra_refs})
    for row in candidates:
        write_ascii(directory / (row["spec"]["id"] + "-adapter.c"),
                    "int main(void) { return 0; }\n")


def run_screen(directory, engine, timeout=20, output_name="screen.json"):
    output = directory / output_name
    document = screen.screen_panel(directory, output, gcc="gcc", timeout=timeout,
                                   compiler=engine.compiler, runner=engine.runner)
    assert json.loads(output.read_bytes()) == json.loads(json.dumps(document))
    return document


def contains_subsequence(args, needle):
    for index in range(len(args) - len(needle) + 1):
        if args[index:index + len(needle)] == needle:
            return True
    return False


def locate_data(name, marker):
    candidates = [
        Path("..") / ".scratch" / "selective_analysis" / name,
        ROOT.parent / ".scratch" / "selective_analysis" / name,
    ]
    cursor = ROOT
    for _ in range(8):
        candidates.append(cursor / ".scratch" / "selective_analysis" / name)
        candidates.append(cursor / "selective_analysis" / name)
        cursor = cursor.parent
    seen = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError):
            continue
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        if (resolved / marker).is_file():
            return resolved
    return None


def real_panel():
    path = locate_data(PANEL_NAME, "plan.json")
    if path is None or not (path / "offline-references.json").is_file():
        pytest.skip("real v4 panel directory is unavailable")
    return path


def real_run():
    path = locate_data(RUN_NAME, "records.json")
    if path is None or not (path / "summary.json").is_file():
        pytest.skip("real v4 run directory is unavailable")
    return path


def test_pass_v4_and_v5_schemas():
    indices = [0, None, 2]
    stdout = screen.format_indices(indices)
    for schema in (V4_SCHEMA, V5_SCHEMA):
        with workspace("screen-pass-" + schema.split(".")[-1]) as folder:
            make_build(folder, schema, [candidate("case-bad")],
                       {"case-bad": {"indices": indices}},
                       extra_refs={"case-bad": {"indices": [9, 9, 9]}})
            engine = MockEngine(stdout=stdout)
            document = run_screen(folder, engine)
            assert document["schema"] == screen.SCHEMA
            assert document["gcc_version"] == "gcc (GCC) 9.4.0"
            assert document["gcc_dumpmachine"] == "x86_64-linux-gnu"
            assert document["sanitizer_flags"] == list(screen.SANITIZER_FLAGS)
            assert document["plan_sha256"] == screen.sha256_file(folder / "plan.json")
            ref_name = screen.PLAN_REFERENCES[schema]
            assert document["references_sha256"] == screen.sha256_file(folder / ref_name)
            row = document["kernels"][0]
            assert row["kernel_id"] == "case-bad"
            assert row["status"] == "pass"
            assert row["reason"] is None
            assert row["class"] is None
            assert document["counts_by_status"] == {"pass": 1}
            assert document["counts_by_reason"] == {}
            assert engine.run_envs[0]["ASAN_OPTIONS"] == screen.ASAN_OPTIONS
            assert engine.run_envs[0]["UBSAN_OPTIONS"] == screen.UBSAN_OPTIONS


def test_v5_reads_unscreened_references():
    with workspace("screen-v5-refs") as folder:
        make_build(folder, V5_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [1, 2]}},
                   extra_refs={"case-bad": {"indices": [8, 8]}})
        engine = MockEngine(stdout=screen.format_indices([1, 2]))
        document = run_screen(folder, engine)
        assert document["kernels"][0]["status"] == "pass"
        engine_wrong = MockEngine(stdout=screen.format_indices([8, 8]))
        document_wrong = run_screen(folder, engine_wrong, output_name="wrong.json")
        assert document_wrong["kernels"][0]["reason"] == "reference_disagreement"


def test_linux_disables_aslr_once_for_every_executable(monkeypatch):
    monkeypatch.setattr(screen.platform, "system", lambda: "Linux")
    monkeypatch.setattr(screen.platform, "machine", lambda: "x86_64")
    detections = []

    def which(name):
        detections.append(name)
        return "/usr/bin/setarch"

    monkeypatch.setattr(screen.shutil, "which", which)
    with workspace("screen-linux-aslr") as folder:
        rows = [candidate("first"), candidate("second")]
        make_build(folder, V5_SCHEMA, rows,
                   {row["case_id"]: {"indices": [0]} for row in rows})
        engine = MockEngine(stdout="0\n")
        document = run_screen(folder, engine)
        prefix = ["/usr/bin/setarch", "x86_64", "-R"]
        assert detections == ["setarch"]
        assert document["aslr_disabled"] is True
        assert document["run_prefix"] == prefix
        for compiled, ran in zip(engine.compile_commands, engine.run_commands):
            args = compiled["args"]
            assert ran["args"] == prefix + [args[args.index("-o") + 1]]
        assert all(row["status"] == "pass" for row in document["kernels"])


def test_linux_requires_setarch(monkeypatch):
    monkeypatch.setattr(screen.platform, "system", lambda: "Linux")
    monkeypatch.setattr(screen.shutil, "which", lambda name: None)
    with workspace("screen-linux-no-setarch") as folder:
        make_build(folder, V5_SCHEMA, [candidate("case")], {"case": {"indices": [0]}})
        engine = MockEngine(stdout="0\n")
        with pytest.raises(RuntimeError, match="setarch"):
            run_screen(folder, engine)
        assert not (folder / "screen.json").exists()
        assert engine.compile_commands == engine.run_commands == []


@pytest.mark.parametrize("timed_out", [False, True])
def test_deadlysignal_without_asan_error_aborts_screen(timed_out):
    with workspace("screen-deadlysignal-%s" % timed_out) as folder:
        make_build(folder, V5_SCHEMA, [candidate("first"), candidate("second")],
                   {"first": {"indices": [0]}, "second": {"indices": [0]}})
        engine = MockEngine(stderr="AddressSanitizer:DEADLYSIGNAL\n" * 3,
                            returncode=-11, timeout=timed_out)
        with pytest.raises(RuntimeError, match="instrument failure.*DEADLYSIGNAL"):
            run_screen(folder, engine)
        assert len(engine.run_commands) == 1
        assert not (folder / "screen.json").exists()
        assert not list(folder.glob("route-b-v5-screen-*"))


def test_deadlysignal_with_real_asan_error_classifies_normally():
    with workspace("screen-deadlysignal-error") as folder:
        make_build(folder, V5_SCHEMA, [candidate("case")], {"case": {"indices": [0]}})
        stderr = ("AddressSanitizer:DEADLYSIGNAL\n"
                  "==11==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff\n"
                  "AddressSanitizer:DEADLYSIGNAL\n")
        document = run_screen(folder, MockEngine(stderr=stderr, returncode=1))
        row = document["kernels"][0]
        assert row["status"] == "excluded"
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "stack-buffer-overflow"


def test_timeout_without_deadlysignal_still_classifies_as_timeout():
    with workspace("screen-genuine-timeout") as folder:
        make_build(folder, V5_SCHEMA, [candidate("case")], {"case": {"indices": [0]}})
        document = run_screen(folder, MockEngine(stderr="still working\n", timeout=True))
        row = document["kernels"][0]
        assert row["status"] == "excluded"
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "timeout"


def test_sanitizer_build_failed():
    with workspace("screen-build-failed") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0]}})
        engine = MockEngine(compile_returncode=1, compile_stderr="error: sanitizer unknown\n",
                            stdout="0\n")
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["status"] == "excluded"
        assert row["reason"] == "sanitizer_build_failed"
        assert row["class"] is None
        assert "sanitizer unknown" in row["detail"]
        assert engine.run_commands == []
        assert document["counts_by_reason"] == {"sanitizer_build_failed": 1}


def test_native_undefined_behavior_asan():
    stderr = "==11==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff\n"
    with workspace("screen-asan") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0]}})
        engine = MockEngine(stdout="0\n", stderr=stderr, returncode=1)
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["status"] == "excluded"
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "stack-buffer-overflow"


def test_native_undefined_behavior_ubsan():
    stderr = "adapter.c:4:5: runtime error: signed integer overflow: 2147483647 + 1\n"
    with workspace("screen-ubsan") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0]}})
        engine = MockEngine(stdout="0\n", stderr=stderr, returncode=1)
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "ubsan:signed integer overflow: 2147483647 + 1"


def test_abnormal_exit():
    with workspace("screen-abnormal") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0]}})
        engine = MockEngine(stdout="0\n", stderr="died\n", returncode=9)
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "abnormal_exit:9"


def test_timeout():
    with workspace("screen-timeout") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0]}})
        engine = MockEngine(timeout=True)
        document = run_screen(folder, engine, timeout=7)
        row = document["kernels"][0]
        assert row["status"] == "excluded"
        assert row["reason"] == "native_undefined_behavior"
        assert row["class"] == "timeout"
        assert engine.run_timeouts == [7]


def test_reference_disagreement_dash():
    with workspace("screen-dash") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad", minimum=4, maximum=6)],
                   {"case-bad": {"indices": [None, 1, None]}})
        engine = MockEngine(stdout="0\n1\n-\n")
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["reason"] == "reference_disagreement"
        assert row["class"] == "input:4"
        assert "expected -" in row["detail"]
        assert "got 0" in row["detail"]


def test_reference_disagreement_count():
    with workspace("screen-count") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0, 1, 2]}})
        engine = MockEngine(stdout="0\n1\n")
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["reason"] == "reference_disagreement"
        assert row["class"] == "input:2"
        assert "<missing>" in row["detail"]


def test_reference_disagreement_value():
    with workspace("screen-value") as folder:
        make_build(folder, V4_SCHEMA, [candidate("case-bad")],
                   {"case-bad": {"indices": [0, 1, 2]}})
        engine = MockEngine(stdout="0\n9\n2\n")
        document = run_screen(folder, engine)
        row = document["kernels"][0]
        assert row["reason"] == "reference_disagreement"
        assert row["class"] == "input:1"
        assert "expected 1" in row["detail"]
        assert "got 9" in row["detail"]


@pytest.mark.parametrize("stderr,expected", [
    ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n",
     "heap-buffer-overflow"),
    ("==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x2\n",
     "stack-use-after-return"),
    ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n", "SEGV"),
    ("==1==ERROR: AddressSanitizer: double-free on address 0x4\n", "double-free"),
    ("note: runtime error: load of misaligned address 0x1\n",
     "ubsan:load of misaligned address 0x1"),
])
def test_asan_and_ubsan_class_parsing(stderr, expected):
    status, reason, klass, _detail = screen.classify_run("0\n", stderr, 1, False, [0], 0)
    assert status == "excluded"
    assert reason == "native_undefined_behavior"
    assert klass == expected


def test_asan_takes_priority_over_ubsan_and_timeout():
    stderr = ("runtime error: signed integer overflow: 1 + 1\n"
              "==9==ERROR: AddressSanitizer: heap-use-after-free on address 0x8\n")
    _status, _reason, klass, _detail = screen.classify_run("", stderr, 1, True, [0], 0)
    assert klass == "heap-use-after-free"


def test_kernel_query_mapping_s1_and_s2():
    references = {
        "juliet-bad": {"indices": [None, 1]},
        "proj-fn-L10-cap4": {"indices": [2, 2]},
        "proj-fn-L10-cap3": {"indices": [2, 2]},
        "proj-fn-L10-cap30": {"indices": [2, 2]},
        "proj-fn-L100-cap1": {"indices": [9]},
        "other-cap1": {"indices": [8]},
    }
    assert screen.query_keys("juliet-bad", references) == ["juliet-bad"]
    assert screen.kernel_indices("juliet-bad", references) == [None, 1]
    assert sorted(screen.query_keys("proj-fn-L10", references)) == [
        "proj-fn-L10-cap3", "proj-fn-L10-cap30", "proj-fn-L10-cap4"]
    assert screen.kernel_indices("proj-fn-L10", references) == [2, 2]
    with pytest.raises(ValueError, match="No reference queries"):
        screen.query_keys("missing", references)


def test_inconsistent_indices_within_a_kernel():
    with workspace("screen-inconsistent") as folder:
        row = candidate("proj-fn-L10", stratum="S2", project="proj", binary_group="proj")
        make_build(folder, V4_SCHEMA, [row], {
            "proj-fn-L10-cap3": {"indices": [1, 2]},
            "proj-fn-L10-cap2": {"indices": [1, 9]},
        })
        engine = MockEngine(stdout="1\n2\n")
        with pytest.raises(ValueError, match="Inconsistent indices"):
            run_screen(folder, engine)


def test_s1_and_s2_kernel_to_queries_in_panel():
    with workspace("screen-s1-s2") as folder:
        s1 = candidate("file-bad", stratum="S1", project="Juliet", binary_group="file.c")
        s2 = candidate("proj-fn-L4", stratum="S2", project="proj", binary_group="proj",
                       flags=["-std=gnu11", "-O1", "-ffreestanding", "-fno-builtin",
                              "-fno-stack-protector", "-ffunction-sections"])
        make_build(folder, V4_SCHEMA, [s1, s2], {
            "file-bad": {"indices": [None, 0]},
            "proj-fn-L4-cap2": {"indices": [3, 3]},
            "proj-fn-L4-cap1": {"indices": [3, 3]},
        })
        stdout_for = {
            "file-bad": screen.format_indices([None, 0]),
            "proj-fn-L4": screen.format_indices([3, 3]),
        }
        engine = MappedStdoutEngine(stdout_for)
        document = run_screen(folder, engine)
        ids = [row["kernel_id"] for row in document["kernels"]]
        assert ids == ["file-bad", "proj-fn-L4"]
        assert all(row["status"] == "pass" for row in document["kernels"])
        assert len(engine.compile_commands) == 2
        assert len(engine.run_commands) == 2


def test_compile_command_flags_and_relative_includes():
    with workspace("screen-compile-flags") as folder:
        flags = ["-std=gnu11", "-O1", "-ffreestanding", "-fno-builtin",
                 "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                 "-Wl,--gc-sections"]
        row = candidate("proj-fn-L8", stratum="S2", project="proj", binary_group="proj",
                        flags=flags, include_directories=["includes/demo"])
        make_build(folder, V4_SCHEMA, [row], {"proj-fn-L8-cap2": {"indices": [0, 1]}})
        engine = MockEngine(stdout=screen.format_indices([0, 1]))
        document = run_screen(folder, engine)
        assert document["kernels"][0]["status"] == "pass"
        args = engine.compile_commands[0]["args"]
        assert args[0] == "gcc"
        assert contains_subsequence(args, SANITIZER_TAIL)
        for flag in flags:
            assert flag in args
        expected_include = os.path.relpath(str(ROOT / "includes" / "demo"), str(folder))
        assert "-I" in args
        assert args[args.index("-I") + 1] == expected_include
        assert args[args.index("-I") + 1] != str(ROOT / "includes" / "demo")
        assert "proj-fn-L8-adapter.c" in args
        assert args[args.index("-o") + 1]
        exe = args[args.index("-o") + 1]
        assert Path(exe).parent.parent.resolve() == folder.resolve()
        assert not Path(exe).exists()
        assert Path(engine.compile_commands[0]["cwd"]).resolve() == folder.resolve()
        assert Path(engine.run_commands[0]["cwd"]).resolve() == folder.resolve()


def test_dry_run_real_v4_panel():
    panel = real_panel()
    plan = json.loads((panel / "plan.json").read_bytes())
    references = json.loads((panel / "offline-references.json").read_bytes())["references"]
    stdout_for = {}
    strata = {"S1": 0, "S2": 0}
    query_counts = {"S1": 0, "S2": 0}
    for row in plan["candidates"]:
        if row.get("status") != "built":
            continue
        strata[row["stratum"]] = strata.get(row["stratum"], 0) + 1
        keys = screen.query_keys(row["case_id"], references)
        query_counts[row["stratum"]] = query_counts.get(row["stratum"], 0) + len(keys)
        stdout_for[row["case_id"]] = screen.format_indices(screen.kernel_indices(row["case_id"], references))
    with workspace("screen-v4-dry") as folder:
        output = folder / "screen.json"
        engine = MappedStdoutEngine(stdout_for)
        document = screen.screen_panel(panel, output, gcc="gcc", timeout=20,
                                       compiler=engine.compiler, runner=engine.runner)
        assert len(document["kernels"]) == sum(strata.values())
        assert strata["S1"] == 18
        assert strata["S2"] == 26
        assert query_counts["S1"] == 18
        assert query_counts["S2"] == 44
        assert all(row["status"] == "pass" for row in document["kernels"])
        assert document["counts_by_status"] == {"pass": 44}
        assert len(engine.compile_commands) == 44
        assert len(engine.run_commands) == 44
        for command in engine.compile_commands:
            assert contains_subsequence(command["args"], SANITIZER_TAIL)
            assert Path(command["cwd"]).resolve() == panel.resolve()
        print("v4 dry-run kernels: S1=%d S2=%d total=%d; queries S1=%d S2=%d"
              % (strata["S1"], strata["S2"], sum(strata.values()),
                 query_counts["S1"], query_counts["S2"]))


def test_rescore_empty_screen_matches_summary():
    run = real_run()
    with workspace("rescore-empty") as folder:
        screen_path = folder / "screen.json"
        write_json_file(screen_path, {"schema": screen.SCHEMA, "kernels": []})
        output = folder / "rescore.json"
        document = rescore.rescore(run, screen_path, output)
        summary = json.loads((run / "summary.json").read_bytes())
        for key, value in document["all"].items():
            if key in summary:
                assert json.loads(json.dumps(value)) == json.loads(json.dumps(summary[key])), key
        assert document["excluded_kernels"] == []
        assert document["screened"] == document["all"]
        print("rescore all: " + json.dumps({
            "queries": document["all"]["queries"],
            "groups": document["all"]["groups"],
            "records": document["all"]["records"],
            "M1_verified": document["all"]["M1_verified"],
            "M2_charged_seconds": document["all"]["M2_charged_seconds"],
            "best_fixed": document["all"]["best_fixed"],
            "M2_best_fixed_minus_L_bootstrap95": document["all"]["M2_best_fixed_minus_L_bootstrap95"],
            "oracle": document["all"]["oracle"],
            "wrong_decisions": document["all"]["wrong_decisions"],
            "decision": document["all"]["decision"],
        }, sort_keys=True))


def test_rescore_excludes_sds_alloc_size():
    run = real_run()
    with workspace("rescore-sds") as folder:
        screen_path = folder / "screen.json"
        write_json_file(screen_path, {
            "schema": screen.SCHEMA,
            "kernels": [{
                "kernel_id": "sds-sdsAllocSize-L300",
                "stratum": "S2",
                "project": "sds",
                "binary_group": "sds",
                "status": "excluded",
                "reason": "native_undefined_behavior",
                "class": "stack-buffer-overflow",
                "detail": "s[-1]",
            }],
        })
        output = folder / "rescore.json"
        document = rescore.rescore(run, screen_path, output)
        assert document["excluded_kernels"] == ["sds-sdsAllocSize-L300"]
        assert document["all"]["wrong_decisions"]
        assert document["screened"]["wrong_decisions"] == []
        assert document["screened"]["positive_claim_blocked_by_wrong_decisions"] is False
        assert document["screened"]["queries"] == document["all"]["queries"] - 2
        assert document["screened"]["records"] == document["all"]["records"] - 12
        remaining = {row["case"] for row in json.loads((run / "records.json").read_bytes())
                     if rescore.case_kernel(row["case"]) != "sds-sdsAllocSize-L300"}
        assert "sds-sdsAllocSize-L300-cap3" not in remaining
        assert "sds-sdsAllocSize-L300-cap2" not in remaining
        print("rescore without sds-sdsAllocSize-L300: " + json.dumps({
            "queries": document["screened"]["queries"],
            "groups": document["screened"]["groups"],
            "records": document["screened"]["records"],
            "M1_verified": document["screened"]["M1_verified"],
            "M2_charged_seconds": document["screened"]["M2_charged_seconds"],
            "best_fixed": document["screened"]["best_fixed"],
            "M2_best_fixed_minus_L_bootstrap95": document["screened"]["M2_best_fixed_minus_L_bootstrap95"],
            "oracle": document["screened"]["oracle"],
            "wrong_decisions": document["screened"]["wrong_decisions"],
            "decision": document["screened"]["decision"],
        }, sort_keys=True))
