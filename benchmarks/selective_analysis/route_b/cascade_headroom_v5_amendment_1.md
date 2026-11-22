# Route B v5, amendment 1 (22 November 2026, before any v5 fetch)

This amendment is made before any v5 source has been fetched, and before any held-out candidate
has been enumerated, built, screened or timed. It changes only where the held-out sources come
from and how many candidates there are. The questions, arms, margins, statistics and decision
rules of `cascade_headroom_v5_design.md` are unchanged. It is pinned in the v5 freeze together
with the design.

## Reasons

1. The repository's Juliet directory (`benchmarks/juliet/cases`) holds only a 38-file selection.
   Its only CWE129 files are the six already used by v4, and it contains no CWE124 file. S1 can
   therefore be built only from the official suite.
2. In v4, about 1 in 15 DWARF functions met the kernel signature rule, and 17 of 61 candidates
   failed the freestanding link. Six S1 groups plus at most 25 S2 projects leaves little margin
   for the 30-group minimum.

## Changes

- **S1 source.** S1 uses the official Juliet C/C++ 1.3 archive from NIST SARD. Its SHA-256 is
  recorded in the sources manifest. Eligible files are `testcases/CWE121*`, `CWE122*` and `CWE124*`
  files whose names contain `CWE129` or `CWE839` and end in `_01.c`, minus the six v4 files.
  Whether a file is used is decided by the unchanged v4 Juliet specializer: unsupported input
  sources, such as sockets or `fscanf`, are recorded as `source_extraction_failed`.
- **S2 candidates.** The following 15 projects are appended to the list. They follow the same
  family exclusions and file-name exclusions and the same build and pinning rules:

  | Project | Repository |
  | --- | --- |
  | libdeflate | ebiggers/libdeflate (lib) |
  | heatshrink | atomicobject/heatshrink |
  | lzfse | lzfse/lzfse (src) |
  | cwalk | likle/cwalk |
  | libfixmath | PetteriAimonen/libfixmath (libfixmath) |
  | ryu | ulfjack/ryu (ryu, C files) |
  | nanoprintf | charlesnicholson/nanoprintf |
  | tinycbor | intel/tinycbor (src) |
  | yyjson | ibireme/yyjson (src) |
  | tomlc99 | cktan/tomlc99 |
  | tinycrypt | intel/tinycrypt (lib/source) |
  | picoc | jpoirier/picoc |
  | ed25519_orlp | orlp/ed25519 (src) |
  | siphash | veorq/SipHash |
  | t1ha | erthink/t1ha (src) |

- **Header-only libraries.** For header-only candidates (nanoprintf, tinyobjloader_c), the
  translation unit is a one-line file that defines the library's documented implementation macro
  and includes the header. Each such file is recorded in the sources manifest.
- **Translation units.** In every project, a translation unit is excluded if any of these holds:
  - it defines `main`;
  - its path contains a test, example, bench, fuzz, demo or tool directory;
  - its file name contains `test`, `utf8`, `b64` or `base64`.

  The remaining units are compiled with the project-specific include directories and
  preprocessor definitions that are recorded in the sources manifest. A unit that does not compile
  is recorded and dropped. A project with no compiling unit is dropped.

The 30-group, 120-query minimum and the rule for later amendments are unchanged.
