#!/usr/bin/env python3
"""Route B v5 step 2a: fetch and pin the held-out sources (no compilation, no analysis).

Windows host with git on PATH. Clones every S2 candidate of the v5 design and amendment 1 at its
default-branch HEAD (depth 1, no submodules), applies the amendment's translation-unit rules,
writes header-only implementation stubs, hashes every selected file, and extracts the eligible
Juliet 1.3 files from the official NIST SARD archive. Writes sources-manifest.json
(symbai.route_b_v5_sources.v1) with "dwarf_elf" left empty for the WSL DWARF step.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRATCH = (ROOT.parent / ".scratch/selective_analysis").resolve()
DESIGN = ROOT / "benchmarks/selective_analysis/route_b/cascade_headroom_v5_design.md"
AMENDMENT = ROOT / "benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_1.md"
JULIET_URL = ("https://samate.nist.gov/SARD/downloads/test-suites/"
              "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip")
V4_JULIET = {"CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.c",
             "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c",
             "CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_01.c",
             "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_fgets_01.c",
             "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_01.c",
             "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_01.c"}

# (project_id, repository, unit roots (non-recursive unless "**"), extra include dirs, defines, stub)
PROJECTS = (
    ("http_parser", "nodejs/http-parser", ["."], [], [], None),
    ("picohttpparser", "h2o/picohttpparser", ["."], [], [], None),
    ("mpaland_printf", "mpaland/printf", ["."], [], [], None),
    ("tinyexpr", "codeplea/tinyexpr", ["."], [], [], None),
    ("crypto_algorithms", "B-Con/crypto-algorithms", ["."], [], [], None),
    ("sc", "tezc/sc", ["**"], [], [], None),
    ("littlefs", "littlefs-project/littlefs", ["."], [], [], None),
    ("mujs", "ccxvii/mujs", ["."], [], [], None),
    ("zlib", "madler/zlib", ["."], [], [], None),
    ("zstd", "facebook/zstd", ["lib/common", "lib/compress", "lib/decompress"], ["lib", "lib/common"],
     ["-DZSTD_DISABLE_ASM"], None),
    ("libart", "armon/libart", ["src"], [], [], None),
    ("mbedtls", "Mbed-TLS/mbedtls", ["library"], ["include", "library"], [], None),
    ("nanopb", "nanopb/nanopb", ["."], [], [], None),
    ("protobuf_c", "protobuf-c/protobuf-c", ["protobuf-c"], ["."], [], None),
    ("parg", "jibsen/parg", ["."], [], [], None),
    ("argparse", "cofyc/argparse", ["."], [], [], None),
    ("wren", "wren-lang/wren", ["src/vm"], ["src/include"], [], None),
    ("mpc", "orangeduck/mpc", ["."], [], [], None),
    ("berry", "berry-lang/berry", ["src"], ["default"], [], None),
    ("libtommath", "libtom/libtommath", ["."], [], [], None),
    ("monocypher", "LoupVaillant/Monocypher", ["src", "src/optional"], [], [], None),
    ("blake2", "BLAKE2/BLAKE2", ["ref"], [], [], None),
    ("tinyobjloader_c", "syoyo/tinyobjloader-c", [], [], [],
     ("TINYOBJ_LOADER_C_IMPLEMENTATION", "tinyobj_loader_c.h")),
    ("libyaml", "yaml/libyaml", ["src"], ["include"],
     ["-DYAML_VERSION_MAJOR=0", "-DYAML_VERSION_MINOR=2", "-DYAML_VERSION_PATCH=5",
      '-DYAML_VERSION_STRING="0.2.5"'], None),
    ("mxml", "michaelrsweet/mxml", ["."], [], [], None),
    # amendment 1
    ("libdeflate", "ebiggers/libdeflate", ["lib", "lib/x86", "lib/arm"], ["."], [], None),
    ("heatshrink", "atomicobject/heatshrink", ["."], [], [], None),
    ("lzfse", "lzfse/lzfse", ["src"], [], [], None),
    ("cwalk", "likle/cwalk", ["src"], ["include"], [], None),
    ("libfixmath", "PetteriAimonen/libfixmath", ["libfixmath"], [], [], None),
    ("ryu", "ulfjack/ryu", ["ryu"], ["."], [], None),
    ("nanoprintf", "charlesnicholson/nanoprintf", [], [], [], ("NANOPRINTF_IMPLEMENTATION", "nanoprintf.h")),
    ("tinycbor", "intel/tinycbor", ["src"], [], [], None),
    ("yyjson", "ibireme/yyjson", ["src"], [], [], None),
    ("tomlc99", "cktan/tomlc99", ["."], [], [], None),
    ("tinycrypt", "intel/tinycrypt", ["lib/source"], ["lib/include"], [], None),
    ("picoc", "jpoirier/picoc", [".", "cstdlib", "platform"], [], ["-DUNIX_HOST"], None),
    ("ed25519_orlp", "orlp/ed25519", ["src"], [], [], None),
    ("siphash", "veorq/SipHash", ["."], [], [], None),
    ("t1ha", "erthink/t1ha", ["src"], ["."], [], None),
)
# amendment 2 (fetched into its own sources directory with --amendment 2)
PROJECTS_A2 = (
    ('streamvbyte', 'lemire/streamvbyte', ['src'], ['include'], [], None),
    ('croaring', 'RoaringBitmap/CRoaring', ['src', 'src/containers', 'src/art'], ['include'], [], None),
    ('fastlz', 'ariya/FastLZ', ['.'], [], [], None),
    ('shoco', 'Ed-von-Schleck/shoco', ['.'], [], [], None),
    ('libhydrogen', 'jedisct1/libhydrogen', ['.'], [], [], None),
    ('poly1305_donna', 'floodyberry/poly1305-donna', ['.'], [], [], None),
    ('curve25519_donna', 'agl/curve25519-donna', ['.'], [], [], None),
    ('blake3', 'BLAKE3-team/BLAKE3', ['c'], [], [], None),
    ('argon2', 'P-H-C/phc-winner-argon2', ['src', 'src/blake2'], ['include'], [], None),
    ('sha3iuf', 'brainhub/SHA3IUF', ['.'], [], [], None),
    ('secp256k1', 'bitcoin-core/secp256k1', ['src'], ['include'], [], None),
    ('trezor_crypto', 'trezor/trezor-crypto', ['.'], [], [], None),
    ('cifra', 'ctz/cifra', ['src'], ['src/ext'], [], None),
    ('hoedown', 'hoedown/hoedown', ['src'], [], [], None),
    ('flatcc_runtime', 'dvidelabs/flatcc', ['src/runtime'], ['include'], [], None),
    ('cmp', 'camgunz/cmp', ['.'], [], [], None),
    ('mpack', 'ludocode/mpack', ['src/mpack'], ['src'], [], None),
    ('argtable3', 'argtable/argtable3', ['src'], [], [], None),
    ('hashmap_dl', 'DavidLeeds/hashmap', ['src'], ['include'], [], None),
    ('collections_c', 'srdja/Collections-C', ['src'], ['src/include'], [], None),
    ('libyuarel', 'jacketizer/libyuarel', ['.'], [], [], None),
    ('coremark', 'eembc/coremark', ['.', 'posix'], ['posix'], [], None),
    ('chibicc', 'rui314/chibicc', ['.'], [], [], None),
    ('clox', 'munificent/craftinginterpreters', ['c'], [], [], None),
    ('tinyprintf', 'cjlano/tinyprintf', ['.'], [], [], None),
    ('lwjson', 'MaJerle/lwjson', ['lwjson/src/lwjson'], ['lwjson/src/include'], [], None),
    ('lmdb', 'LMDB/lmdb', ['libraries/liblmdb'], [], [], None),
    ('unqlite', 'symisc/unqlite', ['.'], [], [], None),
    ('janet', 'janet-lang/janet', ['src/core'], ['src/include', 'src/conf'], [], None),
    ('dr_libs', 'mackron/dr_libs', [], [], [], [('DR_FLAC_IMPLEMENTATION', 'dr_flac.h'), ('DR_WAV_IMPLEMENTATION', 'dr_wav.h'), ('DR_MP3_IMPLEMENTATION', 'dr_mp3.h')]),
    ('minimp3', 'lieff/minimp3', [], [], [], [('MINIMP3_IMPLEMENTATION', 'minimp3.h')]),
    ('libsais', 'IlyaGrebnov/libsais', ['src'], ['include'], [], None),
    ('zopfli', 'google/zopfli', ['src/zopfli'], [], [], None),
    ('snappy_c', 'andikleen/snappy-c', ['.'], [], [], None),
    ('kcp', 'skywind3000/kcp', ['.'], [], [], None),
    ('pbc', 'cloudwu/pbc', ['src'], ['.'], [], None),
    ('libcsv', 'rgamble/libcsv', ['.'], [], [], None),
    ('semver_c', 'h2non/semver.c', ['.'], [], [], None),
    ('nanosvg', 'memononen/nanosvg', [], ['src'], [], [('NANOSVG_IMPLEMENTATION', 'src/nanosvg.h')]),
    ('pdfgen', 'AndreRenaud/PDFGen', ['.'], [], [], None),
    ('qrcodegen', 'nayuki/QR-Code-generator', ['c'], [], [], None),
    ('qrcode_ricmoo', 'ricmoo/QRCode', ['src'], [], [], None),
    ('spiffs', 'pellepl/spiffs', ['src'], ['src/default'], [], None),
    ('dhara', 'dlbeer/dhara', ['dhara'], ['.'], [], None),
    ('zf_log', 'wonder-mice/zf_log', ['zf_log'], [], [], None),
    ('iniparser', 'ndevilla/iniparser', ['src'], [], [], None),
    ('jsonsl', 'mnunberg/jsonsl', ['.'], [], [], None),
    ('ezxml', 'lxfontes/ezxml', ['.'], [], [], None),
    ('sxml', 'capmar/sxml', ['.'], [], [], None),
    ('keccak_tiny', 'coruus/keccak-tiny', ['.'], [], [], None),
    ('libcrc', 'lammertb/libcrc', ['src'], ['include'], [], None),
    ('huffman', 'drichardson/huffman', ['.'], [], [], None),
    ('libbloom', 'jvirkki/libbloom', ['.', 'murmur2'], ['murmur2'], [], None),
    ('hdrhistogram_c', 'HdrHistogram/HdrHistogram_c', ['src'], ['include', 'include/hdr'], [], None),
    ('kissfft', 'mborgerding/kissfft', ['.'], [], [], None),
    ('qoi', 'phoboslab/qoi', [], [], [], [('QOI_IMPLEMENTATION', 'qoi.h')]),
    ('libebur128', 'jiixyj/libebur128', ['ebur128'], ['ebur128/queue'], [], None),
    ('bstrlib', 'websnarf/bstrlib', ['.'], [], [], None),
    ('md5_c', 'Zunawe/md5-c', ['.'], [], [], None),
    ('libpqueue', 'vy/libpqueue', ['src'], [], [], None),
)
AMENDMENT_2 = ROOT / "benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_2.md"
EXCLUDED_DIR_WORDS = ("test", "example", "bench", "fuzz", "demo", "tool")
EXCLUDED_NAME_WORDS = ("test", "utf8", "b64", "base64")
SEALED_NAME_WORDS = ("utf8", "b64", "base64")
MAIN = re.compile(r"\bmain\s*\([^;{}]*\)\s*\{", re.M)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))


def relative(path):
    return Path(os.path.relpath(str(Path(path).resolve()), str(ROOT))).as_posix()


def git(*args, cwd=None):
    return subprocess.run(["git"] + list(args), cwd=cwd, check=True, capture_output=True, text=True,
                          timeout=900).stdout.strip()


def unit_exclusion(rel, text):
    parts = [p.lower() for p in Path(rel).parts]
    if any(word in part for part in parts[:-1] for word in EXCLUDED_DIR_WORDS):
        return "excluded_directory"
    if any(word in parts[-1] for word in EXCLUDED_NAME_WORDS):
        return "excluded_file_name"
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    " ", text, flags=re.S)
    if MAIN.search(masked):
        return "defines_main"
    return None


def remove_tree(path):
    def onerror(function, target, _):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    shutil.rmtree(str(path), onerror=onerror)


def prepare_project(sources, row):
    project_id, repository, roots, includes, defines, stub = row
    entry = {"project_id": project_id, "repository": "https://github.com/" + repository,
             "family": repository.split("/")[0].lower(), "unit_roots": roots}
    target = sources / project_id
    try:
        git("clone", "-q", "--depth", "1", "--single-branch", "--no-tags",
            "https://github.com/" + repository + ".git", str(target))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        entry.update(status="dropped", drop_reason="fetch_failed",
                     detail=str(getattr(error, "stderr", error))[-500:])
        return entry
    entry["commit"] = git("rev-parse", "HEAD", cwd=str(target))
    entry["branch"] = git("rev-parse", "--abbrev-ref", "HEAD", cwd=str(target))
    remove_tree(target / ".git")
    units, rejected = [], []
    candidates = set()
    for root in roots:
        pattern = "**/*.c" if root == "**" else "*.c"
        base = target if root in (".", "**") else target / root
        candidates.update(p for p in base.glob(pattern) if p.is_file())
    for path in sorted(candidates):
        rel = path.relative_to(target).as_posix()
        path.resolve().relative_to(target.resolve())
        reason = unit_exclusion(rel, "")
        if not reason:
            reason = unit_exclusion(rel, path.read_text(encoding="utf-8", errors="replace"))
        if reason:
            rejected.append({"unit": rel, "reason": reason})
        else:
            units.append(rel)
    if stub:
        pairs = [stub] if isinstance(stub, tuple) else list(stub)
        name = "symbai_v5_" + project_id + "_impl.c"
        text = "".join("#define %s\n" % macro for macro, _ in pairs)
        text += "".join("#include \"%s\"\n" % header for _, header in pairs)
        (target / name).write_bytes(text.encode("ascii"))
        units.append(name)
        entry["header_only_stub"] = {"file": name, "pairs": [list(pair) for pair in pairs]}
    include_dirs = sorted({str(Path(u).parent.as_posix()) for u in units} | set(includes) | {"."})
    headers = set()
    for directory in include_dirs:
        pattern = "**/*.h" if directory in includes and Path(directory) != Path(".") else "*.h"
        headers.update(p for p in (target / directory).glob(pattern)
                       if p.is_file() and not any(word in part.lower()
                           for part in p.relative_to(target).parts[:-1]
                           for word in EXCLUDED_DIR_WORDS))
    sealed = [p.relative_to(target).as_posix() for p in headers
              if any(w in p.name.lower() for w in SEALED_NAME_WORDS)]
    files = {u: sha(target / u) for u in units}
    for path in headers:
        path.resolve().relative_to(target.resolve())
    files.update({p.relative_to(target).as_posix(): sha(p) for p in sorted(headers)
                  if p.relative_to(target).as_posix() not in sealed})
    licenses = {p.name: sha(p) for p in target.iterdir()
                if p.is_file() and re.match(r"(?i)(license|licence|copying|unlicense)", p.name)}
    entry.update(source_directory=relative(target), translation_units=units,
                 rejected_units=rejected, include_directories=include_dirs, defines=defines,
                 source_files=files, excluded_sealed_headers=sealed, license_evidence=licenses,
                 dwarf_elf=None, status="pinned" if units else "dropped")
    if not units:
        entry["drop_reason"] = "no_translation_unit"
    return entry


def prepare_juliet(output):
    archive = output / "juliet-1.3.zip"
    # urllib is refused by the site's CDN (HTTP 403); curl is not.
    subprocess.run(["curl", "-sS", "-f", "-L", "--max-time", "1800", "-o", str(archive), JULIET_URL],
                   check=True, timeout=1900)
    eligible = re.compile(r"^(CWE121|CWE122|CWE124)\w*(CWE129|CWE839)\w*_01\.c$")
    directory = output / "juliet" / "testcases"
    directory.mkdir(parents=True)
    files, seen = {}, {}
    with zipfile.ZipFile(str(archive)) as bundle:
        for info in bundle.infolist():
            name = info.filename.rsplit("/", 1)[-1]
            if not eligible.match(name) or name in V4_JULIET:
                continue
            if name in seen:
                raise ValueError("Duplicate Juliet file name: " + name)
            seen[name] = info.filename
            (directory / name).write_bytes(bundle.read(info))
            files[name] = sha(directory / name)
    result = {"url": JULIET_URL, "archive_sha256": sha(archive), "archive_bytes": archive.stat().st_size,
              "directory": relative(directory), "files": dict(sorted(files.items())),
              "archive_members": dict(sorted(seen.items())), "excluded_v4_files": sorted(V4_JULIET)}
    archive.unlink()
    return result


def fetch_amendment_2(pins):
    pins[relative(AMENDMENT_2)] = sha(AMENDMENT_2)
    output = SCRATCH / ("route-b-v5-sources-a2-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    sources = output / "sources"
    sources.mkdir(parents=True)
    print("Sources output:", output, flush=True)
    projects = []
    for row in PROJECTS_A2:
        entry = prepare_project(sources, row)
        entry["amendment"] = 2
        projects.append(entry)
        print("{:18} {:8} units={:3} {}".format(entry["project_id"], entry["status"],
              len(entry.get("translation_units", [])), entry.get("commit", entry.get("drop_reason"))), flush=True)
    write(output / "sources-manifest.json", {"schema": "symbai.route_b_v5_sources.v1",
          "created_utc": datetime.now(timezone.utc).isoformat(), "pins": pins, "juliet": None,
          "projects": projects, "compilation_performed": False, "held_out_built": False})
    print(json.dumps({"pinned": sum(p["status"] == "pinned" for p in projects),
                      "dropped": [p["project_id"] for p in projects if p["status"] != "pinned"]}, indent=2))


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", type=Path, help="earlier output whose projects are complete; fetch Juliet only")
    parser.add_argument("--amendment", type=int, choices=(2,), help="fetch only the amendment-2 projects (no Juliet)")
    args = parser.parse_args()
    pins = {relative(p): sha(p) for p in (DESIGN, AMENDMENT, Path(__file__))}
    if args.amendment == 2:
        return fetch_amendment_2(pins)
    projects = []
    if args.resume:
        output = args.resume.resolve()
        output.relative_to(SCRATCH)
        projects = json.loads((output / "sources-manifest.partial.json").read_bytes())["projects"]
        if [p["project_id"] for p in projects] != [row[0] for row in PROJECTS]:
            raise ValueError("Resumed output does not hold every project")
        pins["resumed_from_fetch_of"] = sha(output / "sources-manifest.partial.json")
    else:
        output = SCRATCH / ("route-b-v5-sources-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        (output / "sources").mkdir(parents=True)
    sources = output / "sources"
    print("Sources output:", output, flush=True)
    for row in PROJECTS if not args.resume else ():
        entry = prepare_project(sources, row)
        projects.append(entry)
        print("{:18} {:8} units={:3} {}".format(entry["project_id"], entry["status"],
              len(entry.get("translation_units", [])), entry.get("commit", entry.get("drop_reason"))), flush=True)
        write(output / "sources-manifest.partial.json", {"projects": projects})
    juliet = prepare_juliet(output)
    print("Juliet eligible files:", len(juliet["files"]), flush=True)
    manifest = {"schema": "symbai.route_b_v5_sources.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
                "pins": pins, "juliet": juliet, "projects": projects,
                "compilation_performed": False, "held_out_built": False}
    write(output / "sources-manifest.json", manifest)
    (output / "sources-manifest.partial.json").unlink()
    print(json.dumps({"pinned": sum(p["status"] == "pinned" for p in projects),
                      "dropped": [p["project_id"] for p in projects if p["status"] != "pinned"],
                      "juliet_files": len(juliet["files"])}, indent=2))


if __name__ == "__main__":
    main()
