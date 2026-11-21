# Route B v5: headroom of the fixed cascade and learned selection at scale (pre-registration)

Written on 21 November 2026, before any v5 source was fetched or any v5 held-out query was built,
screened, labelled or timed. The SHA-256 of this file, of any dated amendment file, of the
implementation and of the built panel manifest is recorded in `route-b-v5-freeze-*/freeze.json`.
Every later v5 step must refuse to run if any pinned hash changes. Changes need a new, versioned
pre-registration.

## Motivation

- v4 ([result](README.md#route-b-v4-structural-selection-results)) found no benefit of the learned
  order L over the fixed symbolic-first cascade F. On its 62-query, 17-group panel, however, the
  95% bootstrap interval of M2(F) - M2(L) was [-67.3, 1.2] s. "Not shown better" is not "shown
  no better".
- v4 also had one ill-defined query: `sds-sdsAllocSize-L300` reads `s[-1]` outside its two-byte
  setup buffer. Its native reference depends on stack contents, so its "wrong decision" says
  nothing about the checker.
- v5 therefore (1) asks the selector-independent question of how much any choice between the two
  orders could save over F, as an equivalence test with a pre-set margin; (2) re-tests L as
  non-superiority on a larger, new panel; and (3) screens every held-out kernel with sanitizer
  builds of its native reference before the freeze.

## Questions

- **Q1 (primary).** On a new, program-grouped panel of finite-domain write-bound queries, is the
  per-query oracle O over the orders F and C equivalent to F within a margin of
  delta_t = 0.05 s of charged time per trial and delta_v = 0.02 in verified rate?
- **Q2 (primary).** Is the learned order L, refitted on all earlier Route B queries, non-superior to F
  by the same margins?

If Q1 holds, no selector that chooses between these two backend orders can improve on F by more
than the margin on this query family, whatever its features or model.

## Operation catalog, runner and selector (unchanged from v4)

- Backends: `symbolic_certificate` and `concrete_enumeration` in
  `src/selective_analysis/finite_backends.py`; runner: `src/selective_analysis/v4_runner.py`;
  budget B = 3 s per query; inputs x in [0, 255]. These files must be byte-identical to the v4
  freeze (`route-b-v4-freeze-20261121T073634943739Z`). The v4 regression gate is re-run once,
  unchanged, before the v5 freeze, and must pass again.
- Selector L: the v4 specification in `src/selective_analysis/v4_selector.py`, unchanged: the
  `structural_features` v1 vector, development standardization, L2 logistic regression and ridge
  on log seconds (lambda = 1.0), and the expected-time order rule with ties selecting F. Only its
  training data change (below).

## Data

### Development (selector training only)

All 141 earlier Route B queries: the 79 v4 development queries and the 62 v4 held-out panel
queries. Each backend runs alone on each query, twice, the second time in reversed query and
backend order, at B = 3 s. These runs are the only training labels. No v5 held-out query is used.

### Held-out panel

No project, author family or test file may come from any earlier Route B or type corpus. utf8.h and
b64 stay sealed. Files whose names contain `utf8`, `b64` or `base64` are excluded.

- **S2 (projects).** Each project is one binary group. The candidate list below is fixed now. A
  project is dropped and recorded, never replaced, if it cannot be fetched or pinned, or if it
  does not build a DWARF object with plain `gcc -O0 -g` and the preprocessor definitions recorded
  in the sources manifest.
  The excluded author families and project families are those of v1-v4 (benhoyt, rxi, zserge,
  skeeto, antirez, kokke, tidwall, fragglet, attractivechaos, cesanta, troydhanson, json-parser,
  kgabis, mity, sheredom, jwerle; lua, xxhash, stb, miniz, utf8proc, libpng, jansson, cjson, lz4,
  bzip2, xz, brotli). The candidate projects are:

  | Project | Repository |
  | --- | --- |
  | http_parser | nodejs/http-parser |
  | picohttpparser | h2o/picohttpparser |
  | mpaland_printf | mpaland/printf |
  | tinyexpr | codeplea/tinyexpr |
  | crypto_algorithms | B-Con/crypto-algorithms (excluding base64) |
  | sc | tezc/sc |
  | littlefs | littlefs-project/littlefs |
  | mujs | ccxvii/mujs |
  | zlib | madler/zlib |
  | zstd | facebook/zstd (lib/common, lib/compress, lib/decompress) |
  | libart | armon/libart |
  | mbedtls | Mbed-TLS/mbedtls (library) |
  | nanopb | nanopb/nanopb |
  | protobuf_c | protobuf-c/protobuf-c (protobuf-c/protobuf-c.c) |
  | parg | jibsen/parg |
  | argparse | cofyc/argparse |
  | wren | wren-lang/wren (src/vm) |
  | mpc | orangeduck/mpc |
  | berry | berry-lang/berry (src) |
  | libtommath | libtom/libtommath |
  | monocypher | LoupVaillant/Monocypher |
  | blake2 | BLAKE2/BLAKE2 (ref) |
  | tinyobjloader_c | syoyo/tinyobjloader-c |
  | libyaml | yaml/libyaml |
  | mxml | michaelrsweet/mxml |

  Each project is pinned to the default-branch commit at fetch time, and its commit and file
  hashes go into the sources manifest. Kernels are extracted by the v4 rules: source-owned DWARF
  definitions with one integer parameter and an integer return, specialized to probe_index(x),
  linked freestanding. A kernel with maximum native index m yields the queries with capacity m+1
  (safe) and m (violation), or 65536 alone if m >= 65536.
- **S1 (Juliet).** Juliet C/C++ 1.3 test files of CWE121, CWE122 and CWE124 whose sink is an
  integer-indexed array write, flow variant 01 only. Every input source supported by the v4
  Juliet specializer is included, and the six v4 files are excluded. Each file yields its `bad`,
  `goodG2B` and `goodB2G` queries and forms one binary group.

### Sanitizer screen (before the freeze; native only)

For every kernel and Juliet case, the native reference adapter (`-DCHECK_NATIVE`, which prints
indices and never performs the write) is also built in WSL with the v4 flags plus
`-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`. It is then run
over all inputs with `detect_leaks=0`. The whole kernel or case is excluded, with the reason
recorded, if:
- the sanitizer build fails (`sanitizer_build_failed`);
- any sanitizer diagnostic is reported (`native_undefined_behavior`, with its class); or
- any printed index differs from the MinGW native reference (`reference_disagreement`, which also
  catches data-model differences such as `long`).

The screen never runs an analysis backend. The same screen is applied to the v4 panel as a
report-only sensitivity analysis.

### Caps and minimum

- At most 4 kernels per S2 project are kept, chosen by ascending SHA-256 of the case id among
  those that passed the link step and the screen.
- S1 contributes at most floor(S2 queries / 3) queries, by ascending SHA-256 of the file name,
  with all three variants of each selected file.
- **Minimum:** at least 120 queries in at least 30 binary groups. The panel is built and screened
  before the freeze. If it falls short, projects may be appended to the S2 list only by a dated
  amendment file that applies the same rules, before any backend touches a held-out query. If the
  panel still falls short at the freeze, v5 is reported as uninterpretable. Only counts and native
  behavior are inspected before the freeze. Feature extraction and backend runs on held-out
  queries happen only after it.

## Arms

| Arm | Order |
| --- | --- |
| F | symbolic, then concrete (reference). |
| C | concrete, then symbolic. |
| L | v4 selector refitted on the 141 development queries. |
| O | Per (query, repetition), the cheaper correct one of F and C (derived, not run). |

## Protocol

The v4 protocol is unchanged:
- one batch per binary group and arm, with a fresh warm worker per batch;
- two repetitions, the second in reversed query order;
- arm order rotated over groups and repetitions;
- runtime reads only `panel.json` and fixture bytes;
- `offline-references.json` is opened only after every trial is collected.

## Metrics and statistics

- Trial: one (query, repetition, arm). Charged time counts unknown or late requests at B.
  A trial is verified if it is decisive and agrees with the reference.
- For arms X, Y: the per-trial mean difference in charged time, D_t(X, Y), and in verified rate,
  D_v(X, Y). Each is computed as a ratio of group sums.
- Uncertainty: percentile cluster bootstrap over binary groups (10,000 resamples, seed 0). The 90%
  two-sided interval equals two one-sided 5% tests.

## Decision

Wrong decisions are reported first. A wrong decision by F on a screened query is a checker defect:
it is diagnosed, reported, and blocks Q1. A wrong decision by L blocks Q2.

- **Q1 supported** (F near-optimal): no wrong decision by F, the 90% interval of D_t(F, O) lies
  inside (-0.05, 0.05) s, and the 90% interval of D_v(O, F) lies inside (-0.02, 0.02).
- **Q1 not supported:** report the measured headroom and where it comes from. If L also has
  D_t(F, L) with a 90% interval wholly above 0 and no lower verified rate, report that L captures
  part of the headroom (exploratory, as v5 was not designed to show it).
- **Q2 supported** (L non-superior): no wrong decision by L, the upper 95% one-sided bound of
  D_t(F, L) is below 0.05 s, and the upper bound of D_v(L, F) is below 0.02.
- **Q2 not supported:** L may save more than the margin. Follow-up needs a new pre-registration.

The power basis for the margin comes from the v4 records, with the ill-defined sds query removed:
- F's mean charged time is 0.279 s per trial and the headroom D_t(F, O) is 0.013 s.
- Resampling 30 groups from v4 gives a median upper bound of 0.025 s and an 80th percentile of
  0.036 s for that headroom.

delta_t = 0.05 s is therefore about 18% of F's mean and 1/60 of B.

Secondary reports, which decide nothing:
- per-stratum results;
- sanitizer exclusions by class, and the v4 panel re-scored without its excluded kernels;
- v4 and v5 pooled;
- L's chosen orders and coefficients;
- worker replacements and the cold start.

## Execution order

1. This pre-registration (committed before any v5 fetch).
2. Fetch and pin the S2 sources, build their DWARF objects, enumerate candidates, link, and
   compute native references. Run the sanitizer screen and apply the caps (native only). Re-run
   the v4 regression gate. Amend the S2 list only if the minimum is not met.
3. Freeze: this file, any amendment, the implementation, the sources manifest and the panel
   manifest.
4. Label the 141 development queries and refit L. Record the parameters with their hashes.
5. Run F, C and L once on the held-out panel, then audit offline and report every group and
   repetition.
