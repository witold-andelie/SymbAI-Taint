#!/usr/bin/env python3
"""Sanitizer screen for Route B v5 (and v4) native-reference adapters.

Compiles each built kernel's CHECK_NATIVE adapter with AddressSanitizer and UBSan,
runs it over the input domain, and classifies the kernel. Never opens analysis
backends, panel.json, or sealed sources.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


SCHEMA = "symbai.route_b_v5_sanitizer_screen.v1"
PLAN_REFERENCES = {
    "symbai.route_b_v4_plan.v1": "offline-references.json",
    "symbai.route_b_v5_plan.v1": "unscreened-references.json",
}
DEFAULT_FLAGS = ("-std=gnu11", "-O1", "-ffreestanding", "-fno-builtin",
                 "-fno-stack-protector")
CHECK_NATIVE = "-DCHECK_NATIVE"
SANITIZER_FLAGS = (
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-fno-omit-frame-pointer",
)
ASAN_OPTIONS = "detect_leaks=0:halt_on_error=1"
UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"
DETAIL_LIMIT = 2000
COMPILE_TIMEOUT = 40
MISSING = object()


def write_json(path, value):
    text = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    with open(str(path), "w", encoding="ascii", newline="\n") as stream:
        stream.write(text)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_of(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def clip(value):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if len(text) > DETAIL_LIMIT:
        return text[:DETAIL_LIMIT]
    return text


def invoke_compiler(compiler, args, cwd):
    if compiler is None:
        return subprocess.run([str(part) for part in args], cwd=str(cwd),
                              capture_output=True, text=True, timeout=COMPILE_TIMEOUT)
    return compiler(args, cwd)


def invoke_runner(runner, args, cwd, env, timeout):
    if runner is None:
        return subprocess.run([str(part) for part in args], cwd=str(cwd), env=env,
                              capture_output=True, text=True, timeout=timeout)
    return runner(args, cwd, env, timeout)


def probe_gcc(gcc, compiler, cwd):
    version = invoke_compiler(compiler, [gcc, "--version"], cwd)
    if getattr(version, "returncode", 0):
        raise RuntimeError("gcc --version failed: " + text_of(getattr(version, "stderr", "")))
    lines = text_of(version.stdout).splitlines()
    if not lines:
        raise ValueError("gcc --version produced no output")
    machine = invoke_compiler(compiler, [gcc, "-dumpmachine"], cwd)
    if getattr(machine, "returncode", 0):
        raise RuntimeError("gcc -dumpmachine failed: " + text_of(getattr(machine, "stderr", "")))
    return lines[0], text_of(machine.stdout).strip()


def spec_flags(spec, build_dir, root=ROOT):
    """Mirror scripts/build_route_b_v4_panel.py build_panel flag construction."""
    flags = list(spec.get("flags", DEFAULT_FLAGS))
    for directory in spec.get("include_directories", []):
        flags.extend(["-I", os.path.relpath(str(root / directory), str(build_dir))])
    return flags


def compile_command(gcc, spec, build_dir, exe, root=ROOT):
    spec_id = spec.get("id")
    if not spec_id:
        raise ValueError("Kernel spec is missing id")
    flags = spec_flags(spec, build_dir, root)
    return ([gcc] + flags + [CHECK_NATIVE] + list(SANITIZER_FLAGS)
            + [spec_id + "-adapter.c", "-o", str(exe)])


def query_keys(kernel_id, references):
    """S1: exact kernel_id. S2: kernel_id plus -cap<digits>."""
    prefix = kernel_id + "-cap"
    keys = []
    for key in references:
        if key == kernel_id:
            keys.append(key)
        elif key.startswith(prefix) and key[len(prefix):].isdigit():
            keys.append(key)
    if not keys:
        raise ValueError("No reference queries for kernel " + kernel_id)
    return keys


def kernel_indices(kernel_id, references):
    keys = query_keys(kernel_id, references)
    indices = references[keys[0]]["indices"]
    for key in keys[1:]:
        if references[key]["indices"] != indices:
            raise ValueError("Inconsistent indices for kernel %s (%s vs %s)"
                             % (kernel_id, keys[0], key))
    return indices


def address_sanitizer_kind(stderr):
    marker = "ERROR: AddressSanitizer:"
    for line in text_of(stderr).splitlines():
        index = line.find(marker)
        if index < 0:
            continue
        rest = line[index + len(marker):].strip()
        if " on " in rest:
            rest = rest.split(" on ", 1)[0].strip()
        return rest
    return None


def ubsan_message(stderr):
    marker = "runtime error:"
    for line in text_of(stderr).splitlines():
        index = line.find(marker)
        if index < 0:
            continue
        return line[index + len(marker):].strip()
    return None


def undefined_behavior_class(stderr, returncode, timed_out):
    kind = address_sanitizer_kind(stderr)
    if kind:
        return kind
    message = ubsan_message(stderr)
    if message is not None:
        return "ubsan:" + message
    if timed_out:
        return "timeout"
    if returncode not in (0, None):
        return "abnormal_exit:%s" % returncode
    return None


def parse_printed_indices(stdout):
    values = []
    for line in text_of(stdout).splitlines():
        if line == "-":
            values.append(None)
        else:
            try:
                values.append(int(line, 10))
            except ValueError:
                values.append(line)
    return values


def first_disagreement(expected, actual, minimum):
    limit = min(len(expected), len(actual))
    for offset in range(limit):
        if expected[offset] != actual[offset]:
            return minimum + offset, expected[offset], actual[offset]
    if len(expected) == len(actual):
        return None
    offset = limit
    if len(actual) < len(expected):
        return minimum + offset, expected[offset], MISSING
    return minimum + offset, MISSING, actual[offset]


def format_index(value):
    if value is MISSING:
        return "<missing>"
    if value is None:
        return "-"
    return str(value)


def format_indices(indices):
    if not indices:
        return ""
    lines = ["-" if value is None else str(value) for value in indices]
    return "\n".join(lines) + "\n"


def classify_run(stdout, stderr, returncode, timed_out, expected, input_minimum):
    stderr_text = text_of(stderr)
    if (any(line.strip() == "AddressSanitizer:DEADLYSIGNAL" for line in stderr_text.splitlines())
            and "ERROR: AddressSanitizer:" not in stderr_text):
        raise RuntimeError("Sanitizer instrument failure: AddressSanitizer:DEADLYSIGNAL "
                           "without an ERROR: AddressSanitizer: line")
    ub_class = undefined_behavior_class(stderr, returncode, timed_out)
    if ub_class is not None:
        detail = text_of(stderr).strip() or ub_class
        return "excluded", "native_undefined_behavior", ub_class, clip(detail)
    printed = parse_printed_indices(stdout)
    disagreement = first_disagreement(expected, printed, input_minimum)
    if disagreement is not None:
        value, expected_index, actual_index = disagreement
        detail = "input %s: expected %s, got %s" % (
            value, format_index(expected_index), format_index(actual_index))
        return "excluded", "reference_disagreement", "input:%s" % value, clip(detail)
    return "pass", None, None, None


def kernel_record(row, status, reason, klass, detail):
    return {
        "kernel_id": row["case_id"],
        "stratum": row["stratum"],
        "project": row["project"],
        "binary_group": row["binary_group"],
        "status": status,
        "reason": reason,
        "class": klass,
        "detail": clip(detail),
    }


def run_environment():
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = ASAN_OPTIONS
    env["UBSAN_OPTIONS"] = UBSAN_OPTIONS
    return env


def screen_kernel(row, indices, build_dir, gcc, timeout, temp_dir, compiler, runner, root,
                  run_prefix):
    spec = row["spec"]
    kernel_id = row["case_id"]
    exe = Path(temp_dir) / kernel_id
    command = compile_command(gcc, spec, build_dir, exe, root)
    try:
        compiled = invoke_compiler(compiler, command, build_dir)
    except subprocess.TimeoutExpired as error:
        return kernel_record(row, "excluded", "sanitizer_build_failed", None,
                             clip("compile timeout: " + text_of(error)))
    except OSError as error:
        return kernel_record(row, "excluded", "sanitizer_build_failed", None, clip(error))
    if getattr(compiled, "returncode", 0):
        detail = (text_of(getattr(compiled, "stderr", "")).strip()
                  or text_of(getattr(compiled, "stdout", "")).strip()
                  or "compiler exited %s" % compiled.returncode)
        return kernel_record(row, "excluded", "sanitizer_build_failed", None, clip(detail))
    env = run_environment()
    timed_out = False
    stdout = stderr = ""
    returncode = None
    try:
        ran = invoke_runner(runner, run_prefix + [str(exe)], build_dir, env, timeout)
        stdout = text_of(getattr(ran, "stdout", ""))
        stderr = text_of(getattr(ran, "stderr", ""))
        returncode = getattr(ran, "returncode", 0)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = text_of(error.stdout or getattr(error, "output", ""))
        stderr = text_of(error.stderr)
        returncode = None
    status, reason, klass, detail = classify_run(
        stdout, stderr, returncode, timed_out, indices, spec.get("min", 0))
    return kernel_record(row, status, reason, klass, detail)


def load_plan(build_dir):
    path = Path(build_dir) / "plan.json"
    plan = json.loads(path.read_bytes())
    schema = plan.get("schema")
    if schema not in PLAN_REFERENCES:
        raise ValueError("Unsupported plan schema: %s" % schema)
    return path, plan, PLAN_REFERENCES[schema]


def screen_panel(build_dir, output, gcc="gcc", timeout=20, compiler=None, runner=None,
                 root=None):
    build_dir = Path(build_dir)
    output = Path(output)
    if root is None:
        root = ROOT
    plan_path, plan, references_name = load_plan(build_dir)
    references_path = build_dir / references_name
    if not references_path.is_file():
        raise ValueError("Missing references file: " + references_name)
    references = json.loads(references_path.read_bytes())["references"]
    jobs = []
    for row in plan.get("candidates", []):
        if row.get("status") != "built":
            continue
        jobs.append((row, kernel_indices(row["case_id"], references)))
    run_prefix = []
    if platform.system() == "Linux":
        setarch = shutil.which("setarch")
        if setarch is None:
            raise RuntimeError("Sanitizer instrument failure: setarch is required on Linux")
        run_prefix = [setarch, platform.machine(), "-R"]
    gcc_version, gcc_machine = probe_gcc(gcc, compiler, build_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    kernels = []
    temp_dir = (output.parent / ("route-b-v5-screen-" + uuid.uuid4().hex)).resolve()
    temp_dir.relative_to(output.parent.resolve())
    temp_dir.mkdir()
    try:
        for row, indices in jobs:
            kernels.append(screen_kernel(row, indices, build_dir, gcc, timeout, temp_dir,
                                         compiler, runner, root, run_prefix))
    finally:
        shutil.rmtree(str(temp_dir))
    kernels.sort(key=lambda item: item["kernel_id"])
    document = {
        "schema": SCHEMA,
        "gcc_version": gcc_version,
        "gcc_dumpmachine": gcc_machine,
        "aslr_disabled": bool(run_prefix),
        "run_prefix": run_prefix,
        "sanitizer_flags": list(SANITIZER_FLAGS),
        "plan_sha256": sha256_file(plan_path),
        "references_sha256": sha256_file(references_path),
        "kernels": kernels,
        "counts_by_status": dict(sorted(Counter(item["status"] for item in kernels).items())),
        "counts_by_reason": dict(sorted(Counter(item["reason"] for item in kernels
                                                if item["reason"]).items())),
    }
    write_json(output, document)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args(argv)
    try:
        document = screen_panel(args.build_dir, args.output, gcc=args.gcc, timeout=args.timeout)
        print(json.dumps({"kernels": len(document["kernels"]),
                          "counts_by_status": document["counts_by_status"],
                          "counts_by_reason": document["counts_by_reason"]},
                         indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
        parser.exit(1, "%s: %s\n" % (type(error).__name__, error))


if __name__ == "__main__":
    sys.exit(main())
