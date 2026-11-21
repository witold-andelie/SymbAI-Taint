"""True type-label rules, split isolation, source clones and real retained DWARF."""
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import uuid

import pytest

from src.selective_analysis import type_corpus as corpus

ROOT = Path(__file__).resolve().parents[1]
TYGR = ROOT / "tygr_original"


def rules():
    if not (TYGR / "src/analysis/types/types.py").is_file():
        pytest.skip("Optional pinned upstream source absent")
    return corpus.UpstreamLabels(TYGR)


@pytest.mark.parametrize("encoding,bits,label", [(5,32,"i32"),(7,64,"u64"),(5,8,"i8"),
    (7,8,"u8"),(6,8,"char"),(8,8,"char"),(2,8,"bool"),(4,64,"f64")])
def test_original_rules_distinguish_real_encodings(encoding, bits, label):
    mapper = rules()
    result = mapper.label(mapper.dwarf.BaseType(encoding,bits))
    assert result["label"] == label and mapper.vocabulary[result["class_id"]] == label


def test_original_pointer_array_normalization_and_unsupported_types_are_explicit():
    mapper = rules()
    integer = mapper.dwarf.BaseType(5,32)
    assert mapper.label(mapper.dwarf.PointerType(mapper.dwarf.BaseType(6,8)))["label"] == "char*"
    assert mapper.label(mapper.dwarf.PointerType(mapper.dwarf.PointerType(integer)))["label"] == "void**"
    assert mapper.label(mapper.dwarf.ArrayType(integer))["label"] == "array<void>"
    # The upstream converter has no volatile branch. Do not invent a class-zero label.
    with pytest.raises(ValueError, match="returned no type"):
        mapper.label(mapper.dwarf.VolatileType(integer))


def test_project_family_and_compiler_variants_cannot_cross_splits():
    rows = [{"project_id": "a", "family": "org/a", "split": "train"},
        {"project_id": "b", "family": "org/b", "split": "development"},
        {"project_id": "c", "family": "org/c", "split": "evaluation"}]
    corpus.validate_splits(rows)
    rows.append({"project_id": "a-O1", "family": "ORG/A", "split": "evaluation"})
    with pytest.raises(ValueError, match="family crosses"):
        corpus.validate_splits(rows)


def test_c_fingerprints_ignore_comment_braces_and_detect_renamed_bodies():
    first = 'int f(int x) { const char *s="}"; /* } */ if(x) { x += 1; } return x; }'
    second = 'int g(int y) { const char *s="}"; if(y) { y += 1; } return y; }'
    a, b = corpus.function_fingerprints(first,1,"f"), corpus.function_fingerprints(second,1,"g")
    assert a["exact_body_sha256"] != b["exact_body_sha256"]
    assert a["identifier_normalized_body_sha256"] == b["identifier_normalized_body_sha256"]
    assert corpus.function_fingerprints('int f(int x);\nint other(void) { return 2; }',1,"f") is None
    rows = [{"function_id":"a", "fingerprints":a, "split":"train"},
            {"function_id":"b", "fingerprints":b, "split":"evaluation"}]
    findings = corpus.cross_split_clones(rows)
    assert len(findings)==1 and findings[0]["fingerprint_kind"]=="identifier_normalized_body_sha256"
    rows[1]["split"]="train"
    assert corpus.cross_split_clones(rows)==[]


def test_dwarf_reference_resolution_detects_cycles_without_fake_labels():
    mapper = rules()
    value = SimpleNamespace(offset=1, tag="DW_TAG_typedef", attributes={"DW_AT_type":SimpleNamespace(value=1)})
    value.get_DIE_from_attribute=lambda _:value
    with pytest.raises(ValueError, match="recursion/cycle"):
        corpus.type_descriptor(value,mapper)


def test_real_retained_elf_exports_the_declared_entry_label():
    bundle = ROOT.parent / ".scratch/selective_analysis/route-b-native-pairs-20261119T151706Z"
    binary = bundle / "native-20261119T153127809228Z/utf8proc_byte_class_n256.debug.elf"
    source = bundle / "utf8proc_byte_class_n256.c"
    if not binary.is_file() or not source.is_file():
        pytest.skip("Optional retained integration ELF absent")
    project = {"project_id":"retained_integration", "source_directory":str(bundle), "split":"train",
               "source_files":{source.name:corpus.sha(source)}}
    result = corpus.inspect_binary(binary,project,rules())
    entry, = [row for row in result["functions"] if row["name"]=="benchmark_step"]
    variable, = [row for row in result["variables"] if row["function_id"]==entry["function_id"] and row["name"]=="x"]
    assert variable["status"]=="mapped" and variable["label"]=="u64" and variable["class_id"]==20
    assert variable["location_attribute_present"] is True
    assert entry["fingerprints"] is not None


def test_pinned_b64_recipe_links_the_actual_upstream_translation_units():
    """Catch source-closure errors that a syntax-only test cannot detect."""
    from scripts.prepare_type_corpus import PROJECTS
    bundle = ROOT.parent / ".scratch/selective_analysis/route-b-type-corpus-20261119T195435581328Z"
    source = bundle / "sources/b64"
    compiler = shutil.which("gcc")
    if compiler is None or not (source / "buffer.c").is_file():
        pytest.skip("Optional local compiler/source closure unavailable")
    units, = [row[3] for row in PROJECTS if row[0] == "b64"]
    scratch = ROOT.parent / ".scratch/selective_analysis/temp" / ("b64-link-" + uuid.uuid4().hex)
    scratch.mkdir(parents=True)
    binary = scratch / "link-check.exe"
    try:
        command = [compiler, "-std=gnu99", "-O0", "-I", str(source)]
        command += [str(source / name) for name in units] + [str(bundle / "intake-main.c"), "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
    finally:
        if binary.exists():
            binary.unlink()
        scratch.rmdir()
