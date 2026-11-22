#!/usr/bin/env python3
"""Plan, build, then finalize a screened Route B v5 panel (native only)."""

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis import fixture_build as fixture


V4_PATH = ROOT / "scripts/build_route_b_v4_panel.py"
_loader = importlib.util.spec_from_file_location("route_b_v5_frozen_v4", str(V4_PATH))
v4 = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(v4)
DESIGN = ROOT / "benchmarks/selective_analysis/route_b/cascade_headroom_v5_design.md"
AMENDMENT = DESIGN.with_name("cascade_headroom_v5_amendment_1.md")
VARIANTS = ("bad", "goodG2B", "goodB2G")
EXCLUDED_FAMILIES = set("benhoyt rxi zserge skeeto antirez kokke tidwall fragglet "
                        "attractivechaos cesanta troydhanson json-parser kgabis mity "
                        "sheredom jwerle".split())
EXCLUDED_PROJECTS = set("lua xxhash stb miniz utf8proc libpng jansson cjson lz4 bzip2 xz brotli".split())
RUNTIME_KEYS = {"case_id", "stratum", "project", "binary_group", "query"}
relative = v4.relative
read_json = v4.read_json


def sealed(value):
    return any(word in str(value).lower() for word in ("utf8", "b64", "base64"))


def root_path(value):
    path = Path(value)
    if path.is_absolute() or path.drive or "\\" in str(value):
        raise ValueError("Expected a repository-relative POSIX path: " + str(value))
    return ROOT / path


def child_path(directory, value):
    root_path(value)
    target = directory / value
    if ".." in Path(value).parts or not v4.inside(target, directory):
        raise ValueError("Path must stay in its source directory: " + str(value))
    return target


def pin(plan, path):
    if sealed(relative(path)):
        raise ValueError("Sealed input is forbidden: " + relative(path))
    return v4.pin(plan, path)


def eligible_juliet(name):
    return (Path(name).name == name and name.startswith(("CWE121", "CWE122", "CWE124"))
            and ("CWE129" in name or "CWE839" in name) and name.endswith("_01.c"))


def overlap_inventory(plan, scratch=None):
    scratch = v4.SCRATCH if scratch is None else scratch
    previous = v4.overlap_inventory(plan, scratch)
    files = set()
    inventory = plan["overlap_check"]["inventories"]

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("project_id", "project", "family") and isinstance(item, str):
                    previous.add(item.lower())
                visit(key)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            files.update(re.findall(r"CWE(?:121|122|124)[A-Za-z0-9_]*\.c", value))

    # v4's cohorts omit projects which only occur in type manifests and the v4
    # plan. Read metadata only; historical source paths are never dereferenced.
    for directory in sorted(scratch.glob("route-b-*")):
        if directory.name.startswith("route-b-v5-") or not directory.is_dir():
            continue
        for name in ("cohort.json", "manifest.json", "plan.json", "panel.json", "sources.json"):
            path = directory / name
            if path.is_file():
                pin(plan, path)
                if relative(path) not in inventory:
                    inventory.append(relative(path))
                visit(read_json(path))
    check = plan["overlap_check"]
    check.update(previous_projects=sorted(previous), previous_juliet_files=sorted(files),
                 juliet_files={})
    return previous, files


def select_juliet(plan, juliet, previous_files):
    directory = root_path(juliet["directory"])
    if sealed(relative(directory)):
        raise ValueError("Sealed Juliet directory")
    manifest_files = juliet["files"]
    if any(not eligible_juliet(name) for name in manifest_files):
        raise ValueError("Juliet manifest eligibility mismatch")
    frozen = {path.name for path in (ROOT / "benchmarks/juliet/cases").glob("*CWE129*.c")}
    paths = {}
    for path in sorted(directory.rglob("*.c")):
        if eligible_juliet(path.name):
            if path.name in paths:
                raise ValueError("Ambiguous Juliet file name: " + path.name)
            paths[path.name] = path
    if set(paths) - frozen != set(manifest_files) - frozen or not set(manifest_files) <= set(paths):
        raise ValueError("Juliet directory and manifest eligibility mismatch")
    plan["juliet_archive_sha256"] = juliet["archive_sha256"]
    for name, path in sorted(paths.items()):
        base = {"case_id": path.stem, "stratum": "S1", "project": "Juliet",
                "binary_group": name, "source": relative(path)}
        overlap = name in previous_files or name in frozen
        plan["overlap_check"]["juliet_files"][name] = {"overlap": overlap}
        if name in manifest_files and pin(plan, path) != manifest_files[name]:
            raise ValueError("Pinned Juliet source hash differs: " + relative(path))
        if overlap:
            v4.reject(plan, base, "v4_juliet_file" if name in frozen else "file_overlap")
            continue
        for variant in VARIANTS:
            row = dict(base, case_id=path.stem + "-" + variant)
            try:
                row["spec"] = v4.juliet_spec(path, variant)
                row["status"] = "pending_build"
                plan["candidates"].append(row)
            except ValueError as error:
                v4.reject(plan, row, "source_extraction_failed", error)


def select_projects(plan, projects, previous):
    names = set()
    for project in projects:
        name = project["project_id"]
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", name) or name.lower() in names:
            raise ValueError("Invalid or duplicate project id: " + name)
        names.add(name.lower())
        base = {"case_id": name, "stratum": "S2", "project": name, "binary_group": name}
        overlap = name.lower() in previous
        plan["overlap_check"]["projects"][name] = {"overlap": overlap}
        if project.get("status") == "dropped":
            v4.reject(plan, base, project["drop_reason"])
            continue
        repository = project.get("repository", "").lower().rstrip("/")
        owner = repository.split("/")[-2] if "/" in repository else ""
        reason = ("project_overlap" if overlap else "sealed_project" if sealed(name)
                  else "excluded_project_family" if name.lower() in EXCLUDED_PROJECTS
                  or owner in EXCLUDED_FAMILIES else None)
        if project.get("status") == "pinned":
            directory = root_path(project["source_directory"])
            files = project["source_files"]
            # Validate every path before reading any source, including headers.
            paths = {key: child_path(directory, key) for key in files}
            if any(sealed(relative(path)) for path in paths.values()):
                raise ValueError("Sealed project source")
            dwarf = root_path(project["dwarf_elf"])
            if pin(plan, dwarf) != project.get("dwarf_elf_sha256"):
                raise ValueError("DWARF inventory hash differs from manifest: " + relative(dwarf))
        if reason:
            v4.reject(plan, base, reason)
            continue
        if project["status"] != "pinned":
            raise ValueError("Expected pinned or dropped project: " + name)
        for key, path in sorted(paths.items()):
            if pin(plan, path) != files[key]:
                raise ValueError("Pinned source hash differs: " + relative(path))
        includes = [relative(child_path(directory, value))
                    for value in project.get("include_directories", [])]
        defines = project.get("defines", [])
        if any(not isinstance(flag, str) or not flag.startswith("-D") for flag in defines):
            raise ValueError("Project defines must be -D flags")
        omitted = set()
        for unit in project["translation_units"]:
            if unit not in files:
                raise ValueError("Translation unit is not pinned: " + unit)
            path = paths[unit]
            ineligible = (any(word in path.name.lower() for word in ("test", "utf8", "b64", "base64"))
                          or any(any(word in part.lower() for word in
                                     ("test", "example", "bench", "fuzz", "demo", "tool"))
                                 for part in Path(unit).parts[:-1]))
            if not ineligible:
                ineligible = bool(re.search(r"\bmain\s*\([^;{}]*\)\s*\{",
                                            v4.masked(path.read_text(encoding="utf-8-sig"))))
            if ineligible:
                omitted.add(unit)
                v4.reject(plan, dict(base, source=relative(path)), "translation_unit_ineligible")
        admitted = dict(project, source_files={key: value for key, value in files.items()
                                              if key not in omitted})
        if not set(project["translation_units"]) - omitted:
            v4.reject(plan, base, "no_eligible_translation_unit")
            continue
        first = len(plan["candidates"])
        v4.select_projects(plan, [admitted], previous)
        for row in plan["candidates"][first:]:
            spec = row["spec"]
            spec["include_directories"] = list(dict.fromkeys(spec["include_directories"] + includes))
            spec["flags"].extend(defines)


def make_plan(manifest_path):
    plan = {"schema": "symbai.route_b_v5_plan.v1", "mode": "plan-only", "hashes": {},
            "candidates": [], "rejections": [], "domain": {"minimum": 0, "maximum": 255},
            "compiler": {"version": fixture.cmd(["gcc", "--version"], ROOT).splitlines()[0],
                         "target": fixture.cmd(["gcc", "-dumpmachine"], ROOT).strip(),
                         "default_flags": list(fixture.FLAGS)},
            "selection_inputs": {"sources_manifest": relative(manifest_path)},
            "selection": "v4 extraction and native build; screen before SHA-256 caps",
            "juliet_absent_write": "null index means the original guard did not reach the query store"}
    for path in (DESIGN, AMENDMENT, V4_PATH, Path(__file__),
                 ROOT / "src/selective_analysis/fixture_build.py",
                 ROOT / "src/selective_analysis/contracts.py", manifest_path):
        pin(plan, path)
    plan["design_sha256"] = plan["hashes"][relative(DESIGN)]
    plan["amendment_sha256"] = plan["hashes"][relative(AMENDMENT)]
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "symbai.route_b_v5_sources.v1":
        raise ValueError("Expected symbai.route_b_v5_sources.v1")
    plan["selection_inputs"]["juliet_directory"] = relative(root_path(manifest["juliet"]["directory"]))
    previous, files = overlap_inventory(plan)
    select_juliet(plan, manifest["juliet"], files)
    select_projects(plan, manifest["projects"], previous)
    ids = [row["case_id"] for row in plan["candidates"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case identifiers")
    plan["summary"] = v4.summary(plan)
    v4.verify_pins(plan)
    return plan


def write_panel(output, records, references, screened=False):
    if any(set(row) != RUNTIME_KEYS for row in records):
        raise ValueError("Runtime records must contain only panel metadata and Query")
    for row in records:
        binary = child_path(output, row["query"]["binary"])
        if binary.suffix != ".elf":
            raise ValueError("Expected fixture ELF")
        fixture.Query.from_dict(row["query"], output)
    if set(references) != {row["case_id"] for row in records}:
        raise ValueError("Reference and runtime case ids differ")
    fixture.write_json(output / ("panel.json" if screened else "unscreened-panel.json"),
                       {"schema": "symbai.route_b_v5_panel.v1" if screened else
                        "symbai.route_b_v5_unscreened_panel.v1", "records": records})
    fixture.write_json(output / ("offline-references.json" if screened else "unscreened-references.json"),
                       {"schema": "symbai.route_b_v5_offline_references.v1" if screened else
                        "symbai.route_b_v5_unscreened_references.v1", "references": references})


class _BuildFixture:
    """Delegate the frozen builder's fixture calls, changing only output names."""

    def __getattr__(self, name):
        return getattr(fixture, name)

    write_panel = staticmethod(write_panel)


v4.fixture = _BuildFixture()


def directory_pins(directory):
    pins = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            parts = path.relative_to(directory).parts
            if (any(part.lower() in v4.SEALED or part.lower().endswith(".b64") for part in parts)
                    or not v4.inside(path, directory)):
                raise ValueError("Forbidden build artifact: " + relative(path))
            pins[path.relative_to(directory).as_posix()] = fixture.file_hash(path)
    return pins


def build_panel(plan, output):
    v4.output_directory(relative(output))
    first_build_rejection = len(plan["rejections"])
    failures = v4.build_panel(plan, output)
    # Amendment 1 explicitly admits unsupported S1 sources as selection
    # rejections. Only failures encountered by the v4 build loop affect build
    # completeness; S2 link failures remain ordinary admission rejections.
    plan["build_complete"] = not any(
        row["reason"] in ("native_reference_failed", "fixture_conversion_failed")
        or row["stratum"] == "S1"
        for row in plan["rejections"][first_build_rejection:])
    plan["build_artifacts"] = {key: value for key, value in directory_pins(output).items()
                               if key != "plan.json"}
    plan["build_finished"] = True
    fixture.write_json(output / "plan.json", plan)
    return failures


def digest_order(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest(), value


def finalize(build_dir, screen_path, output):
    v4.output_directory(relative(output))
    if (output.exists() and (not output.is_dir() or any(output.iterdir()))
            or v4.inside(output, build_dir) or v4.inside(build_dir, output)):
        raise ValueError("Finalize output must be new or empty, separate from the build")
    plan = read_json(build_dir / "plan.json")
    if (plan.get("schema") != "symbai.route_b_v5_plan.v1" or plan.get("mode") != "build"
            or not plan.get("build_finished")):
        raise ValueError("Expected a finished v5 build")
    v4.verify_pins(plan)
    build_pins = directory_pins(build_dir)
    if any(build_pins.get(key) != value for key, value in plan["build_artifacts"].items()):
        raise ValueError("Build artifact pin changed")
    screen_pin = fixture.file_hash(screen_path)
    screen = read_json(screen_path)
    if screen.get("schema") != "symbai.route_b_v5_sanitizer_screen.v1":
        raise ValueError("Expected symbai.route_b_v5_sanitizer_screen.v1")
    for field, name in (("plan_sha256", "plan.json"),
                        ("references_sha256", "unscreened-references.json")):
        if screen.get(field) != build_pins[name]:
            raise ValueError("Screen %s differs from current build: %s" % (field, name))
    entries = {}
    for entry in screen["kernels"]:
        key = entry["kernel_id"]
        if key in entries or entry["status"] not in ("pass", "excluded") or "reason" not in entry:
            raise ValueError("Invalid or duplicate screen entry: " + key)
        entries[key] = entry
    runtime = read_json(build_dir / "unscreened-panel.json")
    offline = read_json(build_dir / "unscreened-references.json")
    if (runtime.get("schema") != "symbai.route_b_v5_unscreened_panel.v1" or
            offline.get("schema") != "symbai.route_b_v5_unscreened_references.v1"):
        raise ValueError("Expected v5 unscreened artifacts")
    by_query = {}
    kernels = {}
    for row in plan["candidates"]:
        if row["status"] == "built":
            key = row["case_id"]
            if key in kernels:
                raise ValueError("Duplicate built kernel")
            kernels[key] = dict(row, records=[])
            if key not in entries:
                raise ValueError("Missing screen entry: " + key)
    for row in runtime["records"]:
        key = row["case_id"]
        kernel = key if row["stratum"] == "S1" else re.sub(r"-cap[0-9]+$", "", key)
        if key in by_query or kernel not in kernels or set(row) != RUNTIME_KEYS:
            raise ValueError("Runtime record differs from built kernel inventory")
        for field in ("stratum", "project", "binary_group"):
            if row[field] != kernels[kernel][field]:
                raise ValueError("Runtime metadata differs from plan")
        child_path(build_dir, row["query"]["binary"])
        fixture.Query.from_dict(row["query"], build_dir)
        by_query[key] = kernel
        kernels[kernel]["records"].append(row)
    if (set(offline["references"]) != set(by_query)
            or any(not row["records"] for row in kernels.values())):
        raise ValueError("Incomplete built kernel records or references")
    decisions = []
    passed = set()
    for key, row in sorted(kernels.items()):
        entry = entries[key]
        decisions.append({"stage": "screen", "kernel_id": key, "decision": entry["status"],
                          "reason": entry["reason"], "query_ids": [r["case_id"] for r in row["records"]]})
        if entry["status"] == "pass":
            passed.add(key)
    kept = set()
    groups = defaultdict(list)
    for key in passed:
        if kernels[key]["stratum"] == "S2":
            groups[kernels[key]["project"]].append(key)
    for project, keys in sorted(groups.items()):
        for rank, key in enumerate(sorted(keys, key=digest_order)):
            keep = rank < 4
            decisions.append({"stage": "s2_cap", "kernel_id": key, "project": project,
                              "sha256": digest_order(key)[0], "rank": rank + 1,
                              "decision": "kept" if keep else "excluded", "reason": "project_kernel_cap"})
            if keep:
                kept.add(key)
    s2_queries = sum(len(kernels[key]["records"]) for key in kept)
    s1_limit = s2_queries // 3
    s1_groups = defaultdict(list)
    for key, row in kernels.items():
        if row["stratum"] == "S1":
            s1_groups[row["binary_group"]].append(key)
    s1_kept = 0
    for name, keys in sorted(s1_groups.items(), key=lambda item: digest_order(item[0])):
        complete = ({key.rsplit("-", 1)[-1] for key in keys} == set(VARIANTS)
                    and len(keys) == 3 and all(key in passed for key in keys))
        keep = complete and s1_kept + 3 <= s1_limit
        reason = "file_query_cap" if complete else "incomplete_or_excluded_file"
        decisions.append({"stage": "s1_cap", "binary_group": name, "kernel_ids": sorted(keys),
                          "sha256": digest_order(name)[0], "decision": "kept" if keep else "excluded",
                          "reason": reason})
        if keep:
            kept.update(keys)
            s1_kept += 3
    records = [row for row in runtime["records"] if by_query[row["case_id"]] in kept]
    references = {row["case_id"]: offline["references"][row["case_id"]] for row in records}
    # All checks precede the first output write. No compiler or backend is called.
    if fixture.file_hash(screen_path) != screen_pin or directory_pins(build_dir) != build_pins:
        raise ValueError("Build or screen changed during finalization")
    v4.verify_pins(plan)
    output.mkdir(parents=True, exist_ok=True)
    for row in records:
        source = child_path(build_dir, row["query"]["binary"])
        target = child_path(output, row["query"]["binary"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(str(source), str(target))
    write_panel(output, records, references, screened=True)
    counts = {"queries": len(records), "groups": len({row["binary_group"] for row in records}),
              "by_stratum": dict(sorted(Counter(row["stratum"] for row in records).items())),
              "by_group": dict(sorted(Counter(row["binary_group"] for row in records).items()))}
    selection = {"schema": "symbai.route_b_v5_selection.v1", "counts": counts,
                 "minimum_met": counts["queries"] >= 120 and counts["groups"] >= 30,
                 "s1_query_limit": s1_limit, "decisions": decisions,
                 "build_rejections": plan["rejections"],
                 "pins": {"build_directory": relative(build_dir), "build_files": build_pins,
                          "screen": relative(screen_path), "screen_sha256": screen_pin}}
    fixture.write_json(output / "selection.json", selection)
    return selection


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true", help="pin inputs and extract candidates; compile nothing")
    mode.add_argument("--build", action="store_true", help="build the saved plan into unscreened native fixtures")
    mode.add_argument("--finalize", action="store_true", help="apply the sanitizer screen and caps; compile nothing")
    parser.add_argument("--sources-manifest", help="repository-relative symbai.route_b_v5_sources.v1 manifest")
    parser.add_argument("--build-dir", help="repository-relative completed unscreened build directory")
    parser.add_argument("--screen", help="repository-relative symbai.route_b_v5_sanitizer_screen.v1 JSON (kernels list)")
    parser.add_argument("--output", required=True, help="child of ../.scratch/selective_analysis or .test-output")
    args = parser.parse_args(argv)
    try:
        root_path(args.output)
        output = v4.output_directory(args.output)
        if args.finalize:
            if not args.build_dir or not args.screen or args.sources_manifest:
                raise ValueError("--finalize requires --build-dir and --screen only")
            selection = finalize(root_path(args.build_dir), root_path(args.screen), output)
            print(json.dumps({"counts": selection["counts"], "minimum_met": selection["minimum_met"]}, sort_keys=True))
            return 0
        if args.build_dir or args.screen:
            raise ValueError("--build-dir and --screen require --finalize")
        if args.plan_only:
            if not args.sources_manifest:
                raise ValueError("--plan-only requires --sources-manifest")
            if output.exists() and any(output.iterdir()):
                raise ValueError("Plan output must be empty")
            plan = make_plan(root_path(args.sources_manifest))
            output.mkdir(parents=True, exist_ok=True)
            fixture.write_json(output / "plan.json", plan)
            failures = []
        else:
            if args.sources_manifest or not output.is_dir() or sorted(p.name for p in output.iterdir()) != ["plan.json"]:
                raise ValueError("--build requires only an output directory containing a plan-only plan.json")
            plan = read_json(output / "plan.json")
            if plan.get("schema") != "symbai.route_b_v5_plan.v1" or plan.get("mode") != "plan-only":
                raise ValueError("Expected a plan-only v5 plan")
            v4.verify_pins(plan)
            if (plan["compiler"]["version"] != fixture.cmd(["gcc", "--version"], ROOT).splitlines()[0]
                    or plan["compiler"]["target"] != fixture.cmd(["gcc", "-dumpmachine"], ROOT).strip()):
                raise ValueError("Compiler differs from the pinned plan")
            plan["mode"] = "build"
            failures = build_panel(plan, output)
        print(json.dumps(plan["summary"], sort_keys=True))
        if failures:
            print("Recorded build rejections: " + ", ".join(failures))
        return 1 if args.build and not plan["build_complete"] else 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, "%s: %s\n" % (type(error).__name__, error))


if __name__ == "__main__":
    sys.exit(main())
