#!/usr/bin/env python3
"""Plan or build the Route B v4 held-out panel, using native references only."""

import argparse
from collections import Counter
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis import fixture_build as fixture
from src.selective_analysis.contracts import file_hash


SCRATCH = ROOT.parent / ".scratch/selective_analysis"
DESIGN = ROOT / "benchmarks/selective_analysis/route_b/structural_selection_v4_design.md"
V3 = "route-b-type-corpus-v3-20261120T203240742242Z"
V2 = "route-b-type-dev-extension-20261120T192757085592Z"
V1 = "route-b-type-corpus-20261119T195435581328Z"
SEALED = {"utf8_h", "utf8.h", "b64"}
TOKEN = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def relative(path):
    return Path(os.path.relpath(str(Path(path).resolve()), str(ROOT))).as_posix()


def inside(path, parent):
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def output_directory(value):
    path = Path(value).resolve()
    if not any(inside(path, parent) and path != parent.resolve()
               for parent in (SCRATCH, ROOT / ".test-output")):
        raise ValueError("--output must be a child of ../.scratch/selective_analysis or .test-output")
    return path


def read_json(path):
    return json.loads(path.read_bytes())


def pin(plan, path):
    path = Path(path)
    # Refuse sealed source paths even when supplied by a custom manifest.
    if any(part.lower() in SEALED or part.lower().endswith(".b64") for part in path.parts):
        raise ValueError("Sealed input is forbidden")
    digest = file_hash(path)
    key = relative(path)
    if key in plan["hashes"] and plan["hashes"][key] != digest:
        raise ValueError("Input changed during planning: " + key)
    plan["hashes"][key] = digest
    return digest


def reject(plan, candidate, reason, detail=None):
    row = dict(candidate, status="rejected", reason=reason)
    if detail:
        row["detail"] = str(detail)
    plan["rejections"].append(row)


def overlap_inventory(plan, scratch=SCRATCH):
    previous = set()
    inventory = []
    for path in sorted(scratch.glob("route-b-*/cohort.json")):
        data = read_json(path)
        names = {case.get("project", case.get("family", "")).lower()
                 for case in data.get("cases", [])}
        previous.update(names - {""})
        inventory.append(relative(path))
        pin(plan, path)
    # prepare_cohort.py also includes this pre-cohort inventory.
    external = scratch / "route-b-external-kernels-20261118T170504629Z/sources.json"
    if external.exists():
        previous.update(name.lower() for name in read_json(external))
        inventory.append(relative(external))
        pin(plan, external)
    plan["overlap_check"] = {"previous_projects": sorted(previous), "inventories": inventory,
                             "projects": {}}
    return previous


def masked(source):
    """Hide comments and literals while retaining offsets and line boundaries."""
    return TOKEN.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), source)


def uncomment(source):
    return TOKEN.sub(lambda match: re.sub(r"[^\n]", " ", match.group())
                     if match.group().startswith(("/*", "//")) else match.group(), source)


def closing(text, start, left="{", right="}"):
    depth = 0
    for offset in range(start, len(text)):
        if text[offset] == left:
            depth += 1
        elif text[offset] == right:
            depth -= 1
            if depth == 0:
                return offset + 1
    raise ValueError("Unbalanced source delimiter")


def definition_span(source, name, line):
    text = masked(source)
    anchor = sum(len(part) for part in source.splitlines(True)[:line - 1])
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    matches = list(pattern.finditer(text))
    matches.sort(key=lambda item: abs(item.start() - anchor))
    for match in matches:
        left = text.index("(", match.start())
        right = closing(text, left, "(", ")")
        brace = right
        while brace < len(text) and text[brace].isspace():
            brace += 1
        if brace >= len(text) or text[brace] != "{":
            continue
        # DWARF decl_line is the declaration, including multiline return types.
        start = source.rfind("\n", 0, min(anchor, match.start())) + 1
        if any(c in text[start:match.start()] for c in ";{}"):
            continue
        return start, closing(text, brace)
    raise ValueError("Cannot locate source definition: " + name)


def juliet_spec(path, variant):
    source = uncomment(path.read_text(encoding="utf-8-sig"))
    name = path.stem + "_bad" if variant == "bad" else variant
    match = re.search(r"\b" + re.escape(name) + r"\s*\(\s*(?:void)?\s*\)\s*\{", source)
    if not match:
        raise ValueError("Juliet variant is missing")
    brace = source.index("{", match.start())
    body = source[brace:closing(masked(source), brace)]
    data_type = re.search(r"\b((?:unsigned\s+|signed\s+)?(?:int|char|short|long))\s+data\s*;", body)
    if not data_type:
        raise ValueError("Juliet data type is missing")
    edits = []

    def edit(pattern, replacement, description, expected=None):
        nonlocal body
        body, count = re.subn(pattern, replacement, body, flags=re.S)
        if expected is not None and count != expected:
            raise ValueError("Juliet edit boundary differs: " + description)
        if count:
            edits.append({"edit": description, "count": count})

    external = "data = (%s)x;" % data_type.group(1)
    edit(r"\{\s*char\s+inputBuffer\[CHAR_ARRAY_SIZE\].*?\n    \}", external,
         "Replace the complete fgets/atoi input block by a cast of x")
    edit(r"data\s*=\s*(?:RAND32|rand)\(\)\s*;", external,
         "Replace the random source by a cast of x")
    # Delete only local allocation, initialization and output scaffolding. Keep data
    # declarations, all constant assignments, and the original sink predicates.
    edit(r"for\s*\(\s*i\s*=\s*0;\s*i\s*<\s*10;\s*i\+\+\s*\)\s*\{\s*(?:printIntLine\(buffer\[i\]\);|buffer\[i\]\s*=\s*0;)\s*\}",
         "", "Remove buffer initialization / printing loops")
    edit(r"\bprintLine\(\"(?:\\.|[^\"\\])*\"\);", "", "Remove diagnostic printing")
    edit(r"int\s+\*\s*buffer\s*=\s*\(int\s*\*\)malloc\(10\s*\*\s*sizeof\(int\)\);", "",
         "Replace heap buffer allocation with the declared evaluation object")
    edit(r"if\s*\(buffer\s*==\s*NULL\)\s*\{exit\(-1\);\}", "", "Remove allocation-failure exit")
    edit(r"int\s+buffer\[10\]\s*=\s*\{\s*0\s*\};", "",
         "Replace stack buffer with the declared evaluation object")
    edit(r"\bint\s+i\s*;|\bfree\(buffer\);", "", "Remove unused loop variable / free")
    edit(r"buffer\[data\]\s*=\s*1;", "QUERY_STORE(data);", "Replace the single query store", 1)
    if re.search(r"\b(?:buffer|fgets|atoi|rand|RAND32|printLine|printIntLine|malloc|free|exit)\b", body):
        raise ValueError("Unremoved Juliet scaffolding")
    return {"id": path.stem + "-" + variant, "kind": "juliet", "body": body,
            "min": 0, "max": 255, "capacity": 10, "edits": edits,
            # O0 retains the physical guarded write even for the constant bad source
            # rejected by goodB2G. The guard itself remains exactly as written.
            "flags": ["-O0" if flag == "-O1" else flag for flag in fixture.FLAGS]}


def select_juliet(plan, directory, previous):
    for path in sorted(directory.glob("*CWE129*.c")):
        pin(plan, path)
        for variant in ("bad", "goodG2B", "goodB2G"):
            row = {"case_id": path.stem + "-" + variant, "stratum": "S1",
                   "project": "Juliet", "binary_group": path.name, "source": relative(path)}
            if "juliet" in previous:
                reject(plan, row, "project_overlap")
                continue
            try:
                row["spec"] = juliet_spec(path, variant)
                row["status"] = "pending_build"
                plan["candidates"].append(row)
            except ValueError as error:
                reject(plan, row, "source_extraction_failed", error)


def decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def referenced_type(die):
    return die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None


def unqualified(die):
    while die is not None and die.tag in ("DW_TAG_typedef", "DW_TAG_const_type",
                                         "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        die = referenced_type(die)
    return die


def integer_type(die):
    die = unqualified(die)
    return die is not None and (die.tag == "DW_TAG_enumeration_type" or
        (die.tag == "DW_TAG_base_type" and die.attributes.get("DW_AT_encoding") is not None
         and die.attributes["DW_AT_encoding"].value in (2, 5, 6, 7, 8)))


def c_type(die):
    if die.tag == "DW_TAG_typedef":
        return decode(die.attributes["DW_AT_name"].value)
    if die.tag == "DW_TAG_const_type":
        return "const " + c_type(referenced_type(die))
    if die.tag in ("DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        return c_type(referenced_type(die))
    if die.tag == "DW_TAG_pointer_type":
        return c_type(referenced_type(die)) + " *"
    if die.tag == "DW_TAG_enumeration_type":
        if "DW_AT_name" not in die.attributes:
            raise ValueError("Anonymous enum has no C cast spelling")
        return "enum " + decode(die.attributes["DW_AT_name"].value)
    if die.tag == "DW_TAG_base_type":
        name = decode(die.attributes["DW_AT_name"].value)
        return "_Bool" if name == "bool" else name
    raise ValueError("Unsupported C cast spelling")


def parameter_kind(die):
    if integer_type(die):
        return "integer"
    plain = unqualified(die)
    if plain is not None and plain.tag == "DW_TAG_pointer_type":
        target = referenced_type(plain)
        while target is not None and target.tag in ("DW_TAG_typedef", "DW_TAG_const_type"):
            target = referenced_type(target)
        if (target is not None and target.tag == "DW_TAG_base_type"
                and decode(target.attributes["DW_AT_name"].value) == "char"):
            return "string"
    return None


def dwarf_source(dwarf, cu, die, files):
    attr = die.attributes.get("DW_AT_decl_file")
    if attr is None:
        return None
    line_program = dwarf.line_program_for_CU(cu)
    if line_program is None:
        return None
    # The pinned corpora use DWARF4; support DWARF5's zero-based file table too.
    zero_based = line_program.header.version >= 5
    entry = line_program.header["file_entry"][attr.value if zero_based else attr.value - 1]
    name = decode(entry.name).replace("\\", "/")
    index = entry.dir_index
    directories = line_program.header["include_directory"]
    directory = decode(directories[index if zero_based else index - 1]) if index or zero_based else ""
    if not directory:
        comp = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
        directory = decode(comp.value) if comp else ""
    full = (directory.replace("\\", "/") + "/" + name).lower()
    matches = [path for path in files if full.endswith("/sources/" + files[path].lower())
               or full == path.resolve().as_posix().lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def dwarf_functions(binary, files):
    """Return source-owned definitions, including signatures rejected by S2."""
    from elftools.elf.elffile import ELFFile

    records = []
    seen = set()
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        if not elf.has_dwarf_info():
            raise ValueError("Candidate inventory ELF has no DWARF")
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                source = dwarf_source(dwarf, cu, die, files)
                if source is None or "DW_AT_name" not in die.attributes:
                    continue
                name = decode(die.attributes["DW_AT_name"].value)
                line = die.attributes.get("DW_AT_decl_line")
                if line is None:
                    continue
                key = (source, name, line.value)
                if key in seen:
                    continue
                seen.add(key)
                params = [p for p in die.iter_children() if p.tag == "DW_TAG_formal_parameter"]
                variadic = any(p.tag == "DW_TAG_unspecified_parameters" for p in die.iter_children())
                row = {"name": name, "source": relative(source), "line": line.value,
                       "external": bool(die.attributes.get("DW_AT_external") and
                                        die.attributes["DW_AT_external"].value)}
                if len(params) != 1 or variadic:
                    row["rejection"] = "signature_parameter_count"
                elif not integer_type(referenced_type(die)):
                    row["rejection"] = "signature_return_type"
                else:
                    param = referenced_type(params[0])
                    kind = parameter_kind(param)
                    if not kind:
                        row["rejection"] = "signature_parameter_type"
                    else:
                        try:
                            row.update(parameter_kind=kind, cast=c_type(param))
                        except ValueError as error:
                            row.update(rejection="signature_cast_unavailable", detail=str(error))
                records.append(row)
    return sorted(records, key=lambda row: (row["source"], row["line"], row["name"]))


def default_projects(plan):
    projects = {}
    for cohort in (V3, V2, V1):
        manifest_path = SCRATCH / cohort / "manifest.json"
        pin(plan, manifest_path)
        manifest = read_json(manifest_path)
        rows = [row for key in ("new_projects", "reused_development_projects", "development_projects",
                                "training_projects", "projects") for row in manifest.get(key, [])]
        for row in rows:
            project = row["project_id"]
            if project in projects:
                continue
            if project.lower() in SEALED:
                projects[project] = {"project_id": project}
                continue
            # Historical absolute paths are provenance only. Relocate by the pinned
            # corpus directory and sources/<project>, never by basename alone.
            owner = (V2 if project in ("json_parser", "parson", "sds", "tiny_regex_c")
                     else V1 if project in ("inih", "rxi_map", "jsmn", "optparse") else cohort)
            directory = SCRATCH / owner / "sources" / project
            binaries = sorted((SCRATCH / cohort).glob("labels-*/" + project + "-O0.elf"))
            if not binaries:
                raise ValueError("No existing DWARF ELF for " + project)
            projects[project] = dict(row, source_directory=relative(directory),
                                     dwarf_elf=relative(binaries[-1]))
    return [projects[name] for name in sorted(projects)]


def load_projects(plan, manifest_path):
    if manifest_path is None:
        return default_projects(plan)
    pin(plan, manifest_path)
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "symbai.route_b_v4_sources.v1":
        raise ValueError("Custom sources manifest must use symbai.route_b_v4_sources.v1")
    return manifest["projects"]


def declaration_context(source, spans, selected, extra_names=(), static_names=()):
    """Retain only referenced file declarations and original macro conditions.

    This is a lexical extraction, not an alternate C implementation. In particular,
    unrelated platform I/O headers and state must not make a scalar kernel fail to
    compile. The compiler and freestanding linker remain the admission check.
    """
    text = masked(source)
    working = list(text)
    for first, last in spans.values():
        working[first:last] = " " * (last - first)
    directives = list(re.finditer(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*(?:\n|$)", text, re.M))
    for match in directives:
        working[match.start():match.end()] = " " * (match.end() - match.start())
    flattened = "".join(working)
    declarations = []
    start, braces, parens = 0, 0, 0
    for offset, char in enumerate(flattened):
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == ";" and braces == 0 and parens == 0:
            first = start
            while first < offset and flattened[first].isspace():
                first += 1
            statement = flattened[first:offset + 1]
            provided = set(re.findall(r"\b(?:struct|enum|union)\s+(\w+)", statement))
            if re.match(r"\s*typedef\b", statement):
                tail = statement.rsplit("}", 1)[-1]
                callback = re.search(r"\(\s*\*\s*(\w+)\s*\)", tail)
                provided.add(callback.group(1) if callback else re.findall(r"\b\w+\b", tail)[-1])
            else:
                declaration_head = statement.split("=", 1)[0].split("{", 1)[0]
                binding = re.search(r"\b(\w+)\s*(?:\[|\(|;|$)", declaration_head.strip())
                if binding:
                    provided.add(binding.group(1))
            declarations.append((first, offset + 1, provided))
            start = offset + 1
    names = set(extra_names)
    for name in selected:
        first, last = spans[name]
        names.update(re.findall(r"\b[A-Za-z_]\w*\b", text[first:last]))
    # Macro bodies may name static tables or other macros. Keep their source text
    # under the original #if/#else structure, and include their identifier closure.
    macros = []
    for match in directives:
        value = source[match.start():match.end()]
        macro = re.match(r"\s*#\s*define\s+(\w+)\b", value)
        if macro:
            macros.append((macro.group(1), value))
    chosen = set()
    while True:
        before = len(names), len(chosen)
        for name, value in macros:
            if name in names:
                names.update(re.findall(r"\b[A-Za-z_]\w*\b", masked(value)))
        for name in set(static_names) & names:
            if name not in spans:
                raise ValueError("Cannot extract a source-owned static dependency: " + name)
            selected.add(name)
            first, last = spans[name]
            names.update(re.findall(r"\b[A-Za-z_]\w*\b", text[first:last]))
        for first, last, provided in declarations:
            if provided & names:
                chosen.add((first, last))
                names.update(re.findall(r"\b[A-Za-z_]\w*\b", text[first:last]))
        if before == (len(names), len(chosen)):
            break
    keep = [(first, last) for name, (first, last) in spans.items() if name in selected]
    keep.extend(chosen)
    standard = {"assert.h", "ctype.h", "float.h", "inttypes.h", "limits.h", "math.h",
                "stdbool.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "string.h"}
    for match in directives:
        value = source[match.start():match.end()]
        include = re.match(r'\s*#\s*include\s*([<"])([^>"]+)', value)
        if include is None or include.group(1) == '"' or include.group(2) in standard:
            keep.append((match.start(), match.end()))
    # Slices are merged because directives can occur within selected definitions.
    merged = []
    for first, last in sorted(keep):
        if merged and first <= merged[-1][1]:
            merged[-1] = merged[-1][0], max(last, merged[-1][1])
        else:
            merged.append((first, last))
    return "\n".join(source[first:last] for first, last in merged)


def extracted_spec(row, functions, source_files):
    """Extract the definition and recursive, source-owned static dependencies.

    Keep the required preprocessor/type context and referenced static data.
    External unresolved calls are left intact for the mandatory freestanding link.
    """
    path = ROOT / row["source"]
    source = path.read_text(encoding="utf-8-sig")
    local = [item for item in functions if item["source"] == row["source"]]
    spans = {}
    for item in local:
        try:
            spans[item["name"]] = definition_span(source, item["name"], item["line"])
        except ValueError:
            if item["name"] == row["name"]:
                raise
    if row["name"] not in spans:
        raise ValueError("No extractable definition")
    selected = {row["name"]}
    while True:
        names = set()
        for name in selected:
            first, last = spans[name]
            names.update(re.findall(r"\b[A-Za-z_]\w*\b", masked(source[first:last])))
        more = {item["name"] for item in local if not item["external"] and item["name"] in names}
        if more <= selected:
            break
        if not more <= set(spans):
            raise ValueError("Cannot extract a source-owned static dependency")
        selected.update(more)
    definition = uncomment(declaration_context(source, spans, selected,
                           re.findall(r"\b\w+\b", row["cast"]),
                           {item["name"] for item in local if not item["external"]}))
    # Includes remain source-owned or standard headers; use original source paths
    # through include flags. No alternate implementations or libc stubs are supplied.
    includes = sorted({relative(path.parent) for path in source_files})
    flags = list(fixture.FLAGS) + ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
    setup = "char s[2] = {(char)x, 0};" if row["parameter_kind"] == "string" else ""
    call = row["name"] + ("(s)" if setup else "((%s)x)" % row["cast"])
    return {"id": row["case_id"], "definition": definition, "call": call,
            "setup": setup, "min": 0, "max": 255, "flags": flags,
            "include_directories": includes,
            "preamble": "#include <stddef.h>\n#include <stdbool.h>",
            "static_dependencies": sorted(selected - {row["name"]})}


def select_projects(plan, projects, previous):
    for project in projects:
        name = project["project_id"]
        base = {"case_id": name, "project": name, "binary_group": name, "stratum": "S2"}
        if name.lower() in SEALED:
            reject(plan, base, "sealed_project")
            continue
        overlap = name.lower() in previous
        plan["overlap_check"]["projects"][name] = {"overlap": overlap}
        if overlap:
            reject(plan, base, "project_overlap")
            continue
        directory = ROOT / project["source_directory"]
        files = {}
        for name_in_project, expected in sorted(project["source_files"].items()):
            source = directory / name_in_project
            if pin(plan, source) != expected:
                raise ValueError("Pinned source hash differs: " + relative(source))
            files[source] = name + "/" + name_in_project.replace("\\", "/")
        binary = ROOT / project["dwarf_elf"]
        pin(plan, binary)
        functions = dwarf_functions(binary, files)
        if not functions:
            reject(plan, base, "no_source_owned_dwarf_definitions")
        for function in functions:
            row = dict(base, **function)
            row["case_id"] = "%s-%s-L%d" % (name, function["name"], function["line"])
            if "rejection" in row:
                reason = row.pop("rejection")
                reject(plan, row, reason)
                continue
            try:
                row["spec"] = extracted_spec(row, functions, files)
                row["status"] = "pending_freestanding_link"
                plan["candidates"].append(row)
            except (ValueError, UnicodeError) as error:
                reject(plan, row, "source_extraction_failed", error)


def verify_pins(plan):
    for path, expected in plan["hashes"].items():
        if file_hash(ROOT / path) != expected:
            raise ValueError("Input changed after planning: " + path)


def summary(plan):
    counts = Counter(row["stratum"] for row in plan["candidates"])
    projects = Counter({project: 0 for project in plan["overlap_check"]["projects"]})
    projects.update(row["project"] for row in plan["candidates"])
    rejections = Counter(row["reason"] for row in plan["rejections"])
    return {"candidates_by_stratum": dict(sorted(counts.items())),
            "candidates_by_project": dict(sorted(projects.items())),
            "rejections_by_reason": dict(sorted(rejections.items())),
            "candidate_statuses": dict(sorted(Counter(row["status"] for row in plan["candidates"]).items()))}


def make_plan(juliet, manifest=None):
    plan = {"schema": "symbai.route_b_v4_plan.v1", "hashes": {}, "candidates": [],
            "rejections": [], "domain": {"minimum": 0, "maximum": 255},
            "compiler": {"version": fixture.cmd(["gcc", "--version"], ROOT).splitlines()[0],
                         "target": fixture.cmd(["gcc", "-dumpmachine"], ROOT).strip(),
                         "default_flags": list(fixture.FLAGS)},
            "selection": "S1: six CWE129 files, three variants; S2: DWARF signatures then freestanding link",
            "selection_inputs": {"juliet_directory": relative(juliet),
                                 "sources_manifest": relative(manifest) if manifest else None},
            "purity_in_plan_only": "Deferred: no compiler or native enumeration is run in plan-only mode",
            "juliet_absent_write": "null index means the original guard did not reach the query store"}
    for path in (DESIGN, Path(__file__), ROOT / "src/selective_analysis/fixture_build.py",
                 ROOT / "src/selective_analysis/contracts.py"):
        pin(plan, path)
    plan["design_sha256"] = plan["hashes"][relative(DESIGN)]
    previous = overlap_inventory(plan)
    plan["overlap_check"]["projects"]["Juliet"] = {"overlap": "juliet" in previous}
    select_juliet(plan, juliet, previous)
    select_projects(plan, load_projects(plan, manifest), previous)
    ids = [row["case_id"] for row in plan["candidates"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case identifiers")
    plan["summary"] = summary(plan)
    verify_pins(plan)
    return plan


def build_panel(plan, output):
    verify_pins(plan)
    records, references = [], {}
    failures = []
    for row in plan["candidates"]:
        spec = row["spec"]
        flags = list(spec.get("flags", fixture.FLAGS))
        for directory in spec.get("include_directories", []):
            flags.extend(["-I", os.path.relpath(str(ROOT / directory), str(output))])
        try:
            kernel_records, kernel_references = [], {}
            capacity = spec.get("capacity", 65536)
            query, reference = fixture.compile_case(spec, {}, output, capacity, flags)
            capacities = [capacity] if row["stratum"] == "S1" else fixture.s2_capacities(reference["indices"])
            for capacity in capacities:
                case_id = row["case_id"] if row["stratum"] == "S1" else row["case_id"] + "-cap%d" % capacity
                if capacity != query["capacity"]:
                    # Rebuild the declared physical object, using the same native
                    # index list: CHECK_NATIVE never accesses evaluation_output.
                    target_spec = dict(spec, id=case_id)
                    source = output / (case_id + "-adapter.c")
                    log = output / (case_id + "-build.log")
                    fixture.write_text(source, fixture.adapter(target_spec, {}, capacity))
                    fixture.write_text(log, "")
                    try:
                        built = fixture.link_fixture(target_spec, source, output, capacity, flags, log)
                    except RuntimeError as error:
                        raise fixture.FixtureBuildError("freestanding_link", error) from error
                    current = asdict(built)
                else:
                    current = dict(query, query_id=case_id)
                kernel_records.append({"case_id": case_id, "stratum": row["stratum"], "project": row["project"],
                                       "binary_group": row["binary_group"], "query": current})
                offline = dict(reference)
                offline.pop("outcome", None)
                offline.pop("witness", None)
                offline.update(fixture.derive_outcome(reference["indices"], capacity, spec["min"]))
                kernel_references[case_id] = offline
            records.extend(kernel_records)
            references.update(kernel_references)
            row["status"] = "built"
        except (OSError, ValueError, RuntimeError, KeyError, AssertionError, subprocess.TimeoutExpired) as error:
            reason = ("freestanding_link_failed" if getattr(error, "stage", None) == "freestanding_link"
                      else "native_reference_failed" if getattr(error, "stage", None) == "native_reference"
                      else "fixture_conversion_failed")
            reject(plan, {key: value for key, value in row.items() if key != "spec"}, reason, error)
            row["status"] = "rejected"
            failures.append(row["case_id"])
        fixture.write_panel(output, records, references)
        fixture.write_json(output / "plan.json", plan)
    verify_pins(plan)
    fixture.write_panel(output, records, references)
    plan["build_complete"] = not any(
        row["reason"] in ("native_reference_failed", "fixture_conversion_failed")
        or (row["stratum"] == "S1" and row["reason"] != "project_overlap")
        for row in plan["rejections"])
    plan["runtime_queries"] = len(records)
    plan["summary"] = summary(plan)
    fixture.write_json(output / "plan.json", plan)
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true", help="write candidates and rejections; compile nothing")
    mode.add_argument("--build", action="store_true", help="freestanding link, native enumeration, and panel output")
    parser.add_argument("--output", required=True, help="child of ../.scratch/selective_analysis or .test-output")
    parser.add_argument("--juliet-dir", help="CWE129 input directory (default: benchmarks/juliet/cases)")
    parser.add_argument("--sources-manifest", help="optional symbai.route_b_v4_sources.v1 fixture manifest; paths relative to repository")
    args = parser.parse_args(argv)
    try:
        output = output_directory(args.output)
        if output.exists() and any(output.iterdir()):
            if not args.build or sorted(path.name for path in output.iterdir()) != ["plan.json"]:
                raise ValueError("Output must be empty, or contain only a plan-only plan for --build")
            plan = read_json(output / "plan.json")
            if plan.get("schema") != "symbai.route_b_v4_plan.v1" or plan.get("mode") != "plan-only":
                raise ValueError("Only a plan-only v4 plan can be built")
            verify_pins(plan)
            compiler = plan["compiler"]
            if (compiler["version"] != fixture.cmd(["gcc", "--version"], ROOT).splitlines()[0]
                    or compiler["target"] != fixture.cmd(["gcc", "-dumpmachine"], ROOT).strip()):
                raise ValueError("Compiler differs from the pinned plan")
            for value, key in ((args.juliet_dir, "juliet_directory"), (args.sources_manifest, "sources_manifest")):
                if value is not None and relative(ROOT / value) != plan["selection_inputs"][key]:
                    raise ValueError("Selection arguments differ from the pinned plan")
        else:
            plan = make_plan(ROOT / (args.juliet_dir or "benchmarks/juliet/cases"),
                             ROOT / args.sources_manifest if args.sources_manifest else None)
        output.mkdir(parents=True, exist_ok=True)
        plan["mode"] = "plan-only" if args.plan_only else "build"
        fixture.write_json(output / "plan.json", plan)
        failures = build_panel(plan, output) if args.build else []
        plan["summary"] = summary(plan)
        fixture.write_json(output / "plan.json", plan)
        print(json.dumps(plan["summary"], sort_keys=True))
        if failures:
            print("Recorded build rejections: " + ", ".join(failures))
        return 1 if args.build and not plan["build_complete"] else 0
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, "%s: %s\n" % (type(error).__name__, error))


if __name__ == "__main__":
    sys.exit(main())
