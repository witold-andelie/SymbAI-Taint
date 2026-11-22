# Route B v5, amendment 2 (22 November 2026, after the native build, before any backend run)

This amendment is made under the design's rule for a panel that falls short of the minimum. No
analysis backend, feature extractor or timing has touched any v5 held-out query. The sanitizer
screen has not been run. Only native build counts were inspected. The questions, arms, margins,
statistics, decision rules, caps and the 30-group, 120-query minimum are unchanged.

## Reason

The native build of the amendment-1 list (`route-b-v5-build-20261122T190701Z`) gave the following
counts:
- 34 of 40 projects had a DWARF inventory.
- 3 projects overlap earlier Route B cohorts (littlefs, zlib, libtommath) and were excluded.
- 20 projects had signature-eligible kernels.
- 13 projects kept at least one kernel after the frozen freestanding-link rule (103 built
  kernels).
- 3 Juliet files gave a complete `bad`/`goodG2B`/`goodB2G` triple.

That is 16 binary groups before the sanitizer screen, which is below 30. Judging by these
yields (about 60% of projects with eligible kernels, and about 65% of those surviving the link),
roughly 50 more projects are needed.

## Changes

- The following 60 projects are appended to the S2 list. They follow the same rules as before:
  family exclusions, overlap check, file-name exclusions, translation-unit rules, pinning,
  DWARF inventory and the per-project cap. Header-only candidates (`dr_libs`, `minimp3`,
  `nanosvg`, `qoi`) use the amendment-1 stub rule. A stub may define several documented
  implementation macros, one for each header it includes.

  | Project | Repository (unit directories) |
  | --- | --- |
  | streamvbyte | lemire/streamvbyte (src) |
  | croaring | RoaringBitmap/CRoaring (src, src/containers, src/art) |
  | fastlz | ariya/FastLZ |
  | shoco | Ed-von-Schleck/shoco |
  | libhydrogen | jedisct1/libhydrogen |
  | poly1305_donna | floodyberry/poly1305-donna |
  | curve25519_donna | agl/curve25519-donna |
  | blake3 | BLAKE3-team/BLAKE3 (c) |
  | argon2 | P-H-C/phc-winner-argon2 (src, src/blake2) |
  | sha3iuf | brainhub/SHA3IUF |
  | secp256k1 | bitcoin-core/secp256k1 (src) |
  | trezor_crypto | trezor/trezor-crypto |
  | cifra | ctz/cifra (src) |
  | hoedown | hoedown/hoedown (src) |
  | flatcc_runtime | dvidelabs/flatcc (src/runtime) |
  | cmp | camgunz/cmp |
  | mpack | ludocode/mpack (src/mpack) |
  | argtable3 | argtable/argtable3 (src) |
  | hashmap_dl | DavidLeeds/hashmap (src) |
  | collections_c | srdja/Collections-C (src) |
  | libyuarel | jacketizer/libyuarel |
  | coremark | eembc/coremark (., posix) |
  | chibicc | rui314/chibicc |
  | clox | munificent/craftinginterpreters (c) |
  | tinyprintf | cjlano/tinyprintf |
  | lwjson | MaJerle/lwjson (lwjson/src/lwjson) |
  | lmdb | LMDB/lmdb (libraries/liblmdb) |
  | unqlite | symisc/unqlite |
  | janet | janet-lang/janet (src/core) |
  | dr_libs | mackron/dr_libs (stub: dr_flac.h, dr_wav.h, dr_mp3.h) |
  | minimp3 | lieff/minimp3 (stub: minimp3.h) |
  | libsais | IlyaGrebnov/libsais (src) |
  | zopfli | google/zopfli (src/zopfli) |
  | snappy_c | andikleen/snappy-c |
  | kcp | skywind3000/kcp |
  | pbc | cloudwu/pbc (src) |
  | libcsv | rgamble/libcsv |
  | semver_c | h2non/semver.c |
  | nanosvg | memononen/nanosvg (stub: src/nanosvg.h) |
  | pdfgen | AndreRenaud/PDFGen |
  | qrcodegen | nayuki/QR-Code-generator (c) |
  | qrcode_ricmoo | ricmoo/QRCode (src) |
  | spiffs | pellepl/spiffs (src) |
  | dhara | dlbeer/dhara (dhara) |
  | zf_log | wonder-mice/zf_log (zf_log) |
  | iniparser | ndevilla/iniparser (src) |
  | jsonsl | mnunberg/jsonsl |
  | ezxml | lxfontes/ezxml |
  | sxml | capmar/sxml |
  | keccak_tiny | coruus/keccak-tiny |
  | libcrc | lammertb/libcrc (src) |
  | huffman | drichardson/huffman |
  | libbloom | jvirkki/libbloom (., murmur2) |
  | hdrhistogram_c | HdrHistogram/HdrHistogram_c (src) |
  | kissfft | mborgerding/kissfft |
  | qoi | phoboslab/qoi (stub: qoi.h) |
  | libebur128 | jiixyj/libebur128 (ebur128) |
  | bstrlib | websnarf/bstrlib |
  | md5_c | Zunawe/md5-c |
  | libpqueue | vy/libpqueue (src) |

- The amendment-2 projects are fetched into their own sources directory. The builder then reads
  one merged manifest that lists the amendment-1 and amendment-2 projects unchanged, together
  with the amendment-1 Juliet section. The build is rerun from a fresh plan over the merged
  manifest. The build is deterministic, so already-built kernels are rebuilt identically.
- The DWARF inventory is a fully linked ELF with unresolved symbols ignored, rather than an
  `ld -r` object. pyelftools cannot apply the TLS relocations that remain in a relocatable
  object's debug sections. This changes how candidates are enumerated, not which functions
  qualify.

The design's rule for later amendments still applies.
