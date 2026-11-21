"""Project-split DWARF label inventory, separate from all learned model inputs."""
import __future__
import ast
from collections import Counter
import hashlib
from pathlib import Path
import re
from types import SimpleNamespace


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_path(value):
    value = str(value)
    import os
    if os.name == "nt" and value.startswith("/mnt/d/"):
        return Path("D:/" + value[7:])
    if os.name != "nt" and value[:3].lower() in ("d:/", "d:\\"):
        return Path("/mnt/d/" + value[3:].replace("\\", "/"))
    return Path(value)


def validate_splits(projects):
    families, ids = {}, set()
    for row in projects:
        if row["project_id"] in ids or row["split"] not in ("train", "development", "evaluation"):
            raise ValueError("Duplicate project or invalid corpus split")
        ids.add(row["project_id"])
        family = row["family"].casefold()
        if family in families and families[family] != row["split"]:
            raise ValueError("Project family crosses a split")
        families[family] = row["split"]
    if set(families.values()) != {"train", "development", "evaluation"}:
        raise ValueError("All three project-level splits are required")


class UpstreamLabels:
    """Use pinned upstream pure-Python classes/rules without importing torch or angr.

    Only unchanged class definitions and the original conversion function execute.
    Tensor-producing TypeSet methods are neither evaluated nor called.
    """
    def __init__(self, root):
        root = Path(root)

        def definitions(relative, select, namespace):
            path = root / relative
            tree = ast.parse(path.read_bytes(), filename=str(path))
            tree.body = [node for node in tree.body if select(node)]
            exec(compile(tree, str(path), "exec", flags=__future__.annotations.compiler_flag), namespace)

        types = {"__name__": "_symbai_original_label_types"}
        definitions("src/analysis/types/types.py", lambda node: isinstance(node, ast.ClassDef), types)
        self.types = SimpleNamespace(**types)
        dwarf = {"__name__": "_symbai_original_dwarf_types", "our_types": self.types}
        definitions("src/analysis/dwarf/types.py", lambda node: isinstance(node, ast.ClassDef)
            or (isinstance(node, ast.FunctionDef) and node.name == "dwarf_type_to_type")
            or (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "base_type_tbl" for t in node.targets)), dwarf)
        self.dwarf = SimpleNamespace(**dwarf)
        normalizer = dict(types)
        definitions("src/analysis/types/type_set.py", lambda node: isinstance(node, ast.ClassDef)
                    and node.name in ("TypeSet", "ReducedStdTypeSet"), normalizer)
        self.normalizer = normalizer["ReducedStdTypeSet"]()
        self.vocabulary = [str(value) for value in self.normalizer.types]
        if len(self.vocabulary) != 75 or len(set(self.vocabulary)) != 75:
            raise ValueError("The pinned source no longer defines the frozen 75-label vocabulary")

    def label(self, descriptor):
        value = self.dwarf.dwarf_type_to_type(descriptor)
        if value is None:
            raise ValueError("Upstream converter returned no type")
        index = self.normalizer.index_of_type(value)
        return {"class_id": index, "label": self.vocabulary[index], "before_normalization": str(value)}


def attr_owner(die, name):
    seen = set()
    for _ in range(16):
        if id(die) in seen:
            break
        seen.add(id(die))
        if name in die.attributes:
            return die, die.attributes[name]
        parent = "DW_AT_abstract_origin" if "DW_AT_abstract_origin" in die.attributes else "DW_AT_specification"
        if parent not in die.attributes:
            break
        die = die.get_DIE_from_attribute(parent)
    return None, None


def attribute(die, name, default=None):
    _, value = attr_owner(die, name)
    return value.value if value is not None else default


def text(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def type_descriptor(die, labels, active=()):
    if die is None:
        return None
    if len(active) > 64 or die.offset in active:
        raise ValueError("DWARF type recursion/cycle")
    active = (*active, die.offset)
    tag = die.tag
    classes = labels.dwarf
    name = text(attribute(die, "DW_AT_name", ""))
    if tag == "DW_TAG_base_type":
        bits = attribute(die, "DW_AT_bit_size")
        if bits is None:
            size = attribute(die, "DW_AT_byte_size")
            bits = size * 8 if size is not None else None
        return classes.BaseType(attribute(die, "DW_AT_encoding"), bits)
    if tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        return classes.StructType(name, [])
    if tag == "DW_TAG_union_type":
        return classes.UnionType(name, [])
    if tag == "DW_TAG_enumeration_type":
        return classes.EnumType(name)
    owner, inner = attr_owner(die, "DW_AT_type")
    inner_die = owner.get_DIE_from_attribute("DW_AT_type") if inner is not None else None
    value = type_descriptor(inner_die, labels, active)
    constructors = {"DW_TAG_pointer_type": "PointerType", "DW_TAG_reference_type": "ReferenceType",
        "DW_TAG_rvalue_reference_type": "RValueReferenceType", "DW_TAG_rval_reference_type": "RValueReferenceType",
        "DW_TAG_const_type": "ConstType", "DW_TAG_volatile_type": "VolatileType", "DW_TAG_restrict_type": "RestrictType",
        "DW_TAG_packed_type": "PackedType", "DW_TAG_array_type": "ArrayType"}
    if tag in constructors:
        return getattr(classes, constructors[tag])(value)
    if tag == "DW_TAG_typedef":
        return classes.TypedefType(name, value)
    if tag == "DW_TAG_subroutine_type":
        return classes.SubroutineType(name, value)
    raise ValueError("Unsupported DWARF type tag: " + tag)


def declaration_path(die, dwarf, cu):
    number = attribute(die, "DW_AT_decl_file")
    if number is None:
        return None
    line = dwarf.line_program_for_CU(cu)
    if line is None or not 1 <= number <= len(line.header["file_entry"]):
        return None
    entry = line.header["file_entry"][number - 1]
    name = runtime_path(text(entry.name))
    if name.is_absolute():
        return name.resolve()
    directory = runtime_path(text(attribute(cu.get_top_DIE(), "DW_AT_comp_dir", "")))
    if entry.dir_index:
        directory = directory / runtime_path(text(line.header["include_directory"][entry.dir_index - 1]))
    return (directory / name).resolve()


_TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?|[^\s]', re.S)
_KEYWORDS = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Imaginary".split())


def function_fingerprints(source, line, name):
    data = "\n".join(source.splitlines()[max(0, line - 1):])
    tokens = [token for token in _TOKENS.findall(data) if not token.startswith(("//", "/*"))]
    prefix, body, depth = [], [], 0
    for token in tokens:
        if not body:
            if token == ";":
                return None
            if token != "{":
                prefix.append(token)
                continue
            if name not in prefix:
                return None
        body.append(token)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                break
    if not body or depth != 0:
        return None
    normalized = ["ID" if re.fullmatch(r"[A-Za-z_]\w*", token) and token not in _KEYWORDS else token for token in body]
    fingerprint = lambda values: hashlib.sha256(" ".join(values).encode()).hexdigest()
    return {"body_tokens": len(body), "exact_body_sha256": fingerprint(body),
            "identifier_normalized_body_sha256": fingerprint(normalized)}


def inspect_binary(binary, project, labels):
    from elftools.elf.elffile import ELFFile
    directory = runtime_path(project["source_directory"]).resolve()
    allowed = {(directory / relative).resolve() for relative in project["source_files"]}
    binary_hash = sha(binary)
    functions, variables = [], []
    with Path(binary).open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64" or not elf.has_dwarf_info():
            raise ValueError("Expected a native x86-64 ELF with DWARF")
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            if cu["version"] != 4:
                raise ValueError("The readiness profile requires DWARF4")
            for function in cu.iter_DIEs():
                if function.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in function.attributes:
                    continue
                path = declaration_path(function, dwarf, cu)
                if path not in allowed:
                    continue
                name = text(attribute(function, "DW_AT_name", ""))
                if name == "main":
                    continue
                key = f"{project['project_id']}:{binary_hash[:16]}:{function.offset:x}"
                line = int(attribute(function, "DW_AT_decl_line", 0))
                fingerprint = function_fingerprints(path.read_text(encoding="utf-8", errors="replace"), line, name) if line else None
                functions.append({"function_id": key, "name": name, "source": str(path),
                    "source_line": line, "address": function.attributes["DW_AT_low_pc"].value,
                    "fingerprints": fingerprint, "split": project["split"]})
                pending = list(function.iter_children())
                while pending:
                    variable = pending.pop()
                    if variable.tag in ("DW_TAG_subprogram", "DW_TAG_inlined_subroutine"):
                        continue
                    if variable.tag not in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
                        pending.extend(variable.iter_children())
                        continue
                    if attribute(variable, "DW_AT_artificial", False):
                        continue
                    row = {"function_id": key, "variable_die_offset": variable.offset,
                        "name": text(attribute(variable, "DW_AT_name", "")), "role": variable.tag,
                        "location_attribute_present": attr_owner(variable, "DW_AT_location")[1] is not None,
                        "label_source": "DWARF_type_reference_with_original_TYGR_conversion_rules"}
                    try:
                        owner, kind = attr_owner(variable, "DW_AT_type")
                        if kind is None:
                            raise ValueError("Variable type reference missing")
                        row.update(labels.label(type_descriptor(owner.get_DIE_from_attribute("DW_AT_type"), labels)), status="mapped")
                    except Exception as error:
                        # Upstream conversion raises generic Exception for unsupported encodings.
                        row.update(status="unmapped", error={"type": type(error).__name__, "message": str(error)})
                    variables.append(row)
    return {"binary_sha256": binary_hash, "functions": functions, "variables": variables,
        "mapped_label_histogram": dict(Counter(row["label"] for row in variables if row["status"] == "mapped")),
        "scope": "True DWARF label inventory only. Attribute presence is not a validated use-site/graph readout mapping."}


def cross_split_clones(records):
    groups = {}
    for row in records:
        fingerprints = row.get("fingerprints")
        if not fingerprints or fingerprints["body_tokens"] < 12:
            continue
        for field in ("exact_body_sha256", "identifier_normalized_body_sha256"):
            groups.setdefault((field, fingerprints[field]), []).append(row)
    return [{"fingerprint_kind": key[0], "sha256": key[1],
        "function_ids": sorted({row["function_id"] for row in rows}),
        "splits": sorted({row["split"] for row in rows}), "requires_review": True}
        for key, rows in groups.items() if len({row["split"] for row in rows}) > 1]
