#!/usr/bin/env python3
"""Route B v5 step 2b: build one DWARF candidate-inventory ELF per pinned S2 project (WSL).

Compiles every recorded translation unit with plain `gcc -std=gnu11 -O0 -g -c`, the project's
include directories and preprocessor definitions, and links the objects into one inventory ELF
(unresolved symbols ignored; nothing is ever executed). A unit
that fails to compile is recorded and dropped; a project with no compiling unit is dropped.
Nothing is linked into an executable, run or analyzed. Updates sources-manifest.json in place
after keeping the fetch-time manifest as sources-manifest.fetch.json.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
BASE_FLAGS = ["-std=gnu11", "-O0", "-g", "-gdwarf-4", "-c", "-w"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def relative(path):
    return Path(os.path.relpath(str(Path(path).resolve()), str(ROOT))).as_posix()


def run(args, cwd=None, timeout=180):
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def source_child(source, value):
    path = Path(value)
    if path.is_absolute() or path.drive or "\\" in str(value) or ".." in path.parts:
        raise ValueError("Invalid source-relative path: " + str(value))
    target = (source / path).resolve()
    target.relative_to(source.resolve())
    return target


def verify_project(project):
    source = (ROOT / project["source_directory"]).resolve()
    source.relative_to(SCRATCH)
    if not project["project_id"] or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                        for c in project["project_id"]):
        raise ValueError("Invalid project id")
    for name, expected in project["source_files"].items():
        if any(word in name.lower() for word in ("utf8", "b64", "base64")):
            raise ValueError("Sealed source is forbidden")
        if sha(source_child(source, name)) != expected:
            raise ValueError("Pinned source changed: %s/%s" % (project["project_id"], name))
    for unit in project["translation_units"]:
        if unit not in project["source_files"]:
            raise ValueError("Unpinned translation unit: " + unit)
    for directory in project["include_directories"]:
        source_child(source, directory)
    if any(not flag.startswith("-D") for flag in project["defines"]):
        raise ValueError("Expected -D definitions")
    return source


def inventory_elf(path):
    if not path.is_file():
        return False
    with path.open("rb") as stream:
        header = stream.read(18)
    # ET_EXEC/ET_DYN, never a COFF output or an ELF relocatable with unapplied debug relocations.
    return (len(header) == 18 and header[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(header[16:18], "little") in (2, 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True, help="route-b-v5-sources-* directory")
    args = parser.parse_args()
    output = args.sources.resolve()
    output.relative_to(SCRATCH)
    manifest_path = output / "sources-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("schema") != "symbai.route_b_v5_sources.v1" or manifest.get("compilation_performed"):
        raise SystemExit("Expected a fetch-time v5 sources manifest")
    for project in manifest["projects"]:
        if project["status"] == "pinned":
            verify_project(project)
    shutil.copyfile(str(manifest_path), str(output / "sources-manifest.fetch.json"))
    dwarf = output / "dwarf"
    objects_root = output / "dwarf-objects"
    dwarf.mkdir(exist_ok=True)
    objects_root.mkdir(exist_ok=True)
    gcc = run(["gcc", "--version"]).stdout.splitlines()[0]
    machine = run(["gcc", "-dumpmachine"]).stdout.strip()
    ld = run(["ld", "--version"]).stdout.splitlines()[0]
    for project in manifest["projects"]:
        if project["status"] != "pinned":
            continue
        source = verify_project(project)
        includes = []
        for directory in project["include_directories"]:
            includes += ["-I", str((source / directory).resolve())]
        objects, compiled, failed = [], [], []
        target = objects_root / project["project_id"]
        target.mkdir()
        for index, unit in enumerate(project["translation_units"]):
            obj = target / ("%03d.o" % index)
            try:
                result = run(["gcc"] + BASE_FLAGS + includes + project["defines"]
                             + [str(source / unit), "-o", str(obj)], cwd=str(source))
                ok = result.returncode == 0
                detail = result.stderr[-1500:]
            except subprocess.TimeoutExpired:
                ok, detail = False, "timeout"
            if ok:
                objects.append(obj)
                compiled.append(unit)
            else:
                failed.append({"unit": unit, "reason": "compile_failed", "detail": detail})
        project.update(compiled_units=compiled, failed_units=failed)
        if objects:
            elf = dwarf / (project["project_id"] + "-O0.elf")
            # A fully linked inventory: the linker applies every relocation, including TLS ones in
            # .debug_info that pyelftools cannot apply to a relocatable object.
            result = run(["ld", "--allow-multiple-definition", "--unresolved-symbols=ignore-all",
                          "--noinhibit-exec", "-e", "0", "-o", str(elf)] + [str(o) for o in objects])
            if inventory_elf(elf):
                project.update(dwarf_elf=relative(elf), dwarf_elf_sha256=sha(elf),
                               inventory_link={"exit": result.returncode, "stderr_tail": result.stderr[-800:]})
            else:
                project.update(status="dropped", drop_reason="inventory_link_failed",
                               detail=result.stderr[-1500:])
        else:
            project.update(status="dropped", drop_reason="no_compiling_unit")
        shutil.rmtree(str(target))
        print("{:18} {:8} compiled={:3} failed={:3}".format(project["project_id"], project["status"],
              len(compiled), len(failed)), flush=True)
    objects_root.rmdir()
    manifest.update(compilation_performed=True,
                    dwarf_build={"gcc": gcc, "machine": machine, "ld": ld, "flags": BASE_FLAGS,
                                 "merge": "ld --allow-multiple-definition --unresolved-symbols=ignore-all --noinhibit-exec -e 0",
                                 "script": relative(Path(__file__)), "script_sha256": sha(Path(__file__))})
    manifest_path.write_bytes((json.dumps(manifest, indent=2) + "\n").encode("ascii"))
    pinned = [p for p in manifest["projects"] if p["status"] == "pinned"]
    print(json.dumps({"pinned_with_dwarf": len(pinned),
                      "dropped": {p["project_id"]: p.get("drop_reason") for p in manifest["projects"]
                                  if p["status"] != "pinned"}}, indent=2))


if __name__ == "__main__":
    main()
