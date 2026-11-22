# Route B v5, amendment 3 (22 November 2026, after a first sanitizer screen, before any backend run)

No analysis backend, feature extractor or timing has touched any v5 held-out query. This
amendment corrects two measurement instruments. Both errors were found by inspecting the first
sanitizer screen's diagnostics, which are native behavior only. The questions, arms, margins,
statistics, decision rules, caps, minimum and S2 project list are unchanged.

## 1. Header pinning

After the pre-freeze code review, the source preparation collected headers recursively under
every include directory. Every project lists `.`, so this pinned every header in the
repository, including test trees. The frozen v4 extractor adds the parent directory of every
pinned file as an include path. For zstd, `contrib/linux-kernel/test/include/linux/stddef.h`
therefore shadowed the system `<stddef.h>`. This broke every zstd sanitizer build and changed
which zstd kernels linked natively.

**Correction:** headers are collected recursively only under include directories declared for the
project, never from `.`. For `.` and for directories holding translation units, they are
collected non-recursively, as before the review. Headers under a directory whose name contains an
excluded directory word (test, example, bench, fuzz, demo, tool) are never pinned, which applies
the existing translation-unit rule to headers. The sources are prepared again, and the
inventories, plan and native build are redone.

## 2. Sanitizer runtime under address randomization

In the WSL kernel used here, gcc 9's AddressSanitizer runtime sometimes livelocks: it prints
`AddressSanitizer:DEADLYSIGNAL` repeatedly, with no `ERROR:` report, until the screen's timeout.
This is a known incompatibility between older libasan and high mmap randomization entropy. In the
first screen, 48 v5 kernels and 13 v4 kernels were classified as `native_undefined_behavior` /
`timeout` this way. They include trivial Juliet `goodG2B` cases and `sds-is_hex_digit`. These
classifications measure the runtime, not the kernel.

**Correction:**
- Every sanitized executable runs with address randomization disabled (`setarch <arch> -R`).
- The livelock signature without an `ERROR:` report aborts the screen as an instrument failure.
  It is never recorded as a kernel property.
- All other screen rules are unchanged, including the timeout rule for real non-termination.

The first screen outputs are kept unchanged as evidence:
- `route-b-v5-screen-20261122T204019Z` (v5 build `route-b-v5-build-20261122T194330Z`);
- `route-b-v5-screen-v4panel-20261122T204019Z` (v4 panel).

The screen is then run again with the correction on the rebuilt v5 panel and on the v4 panel.

## 3. Builder checks

- Finalization requires the screen's plan and reference hashes to equal those of the current
  build.
- Planning requires each DWARF inventory to match the hash recorded in the sources manifest.
