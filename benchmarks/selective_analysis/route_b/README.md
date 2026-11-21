# Route B information pilot

This experiment measures whether genuine neural type information helps the existing
selector within an analysis budget. It runs before any development of Variant E.
The test panel is new relative to the v1–v23 development records. Six separately
compiled authored programs cover saturation, lane layout, table lookup, mirroring,
grid indexing and periodic control. They share a fixture harness. They are useful
for a first decision and do not represent six real projects.

## Fixed protocol

Each binary contributes two queries on the same byte store into a 64-byte output
array. The entry value ranges from 0 to 31 or from 0 to 255. A separate executable
checks the source index for every input from 0 to 255 before the model is run.
The checker still needs fresh evidence to exclude a violation within each binary
query's scope. The source check serves as a reference for the authored fixtures.
It does not verify arbitrary compiled programs.

| Arm | Information supplied to the existing selector |
|---|---|
| B | None. |
| C | The model's Top-1 label for the predeclared parameter. |
| K | The same genuine Top-3 candidate set as D, with uniform weights and no model scores. |
| D | The genuine Top-3 set and retained raw logits. |

All four arms use the same operation catalog, policy weights, checkers, empty initial
checkpoint and structural features. The K arm uses the same scoring function as
D; only its type weights are uniform. Precomputed information only affects operation
order. The per-function mapping selects the single DWARF-located parameter named
`setting` before reading its candidates. A missing or ambiguous match stays
unavailable. This association has function-parameter scope.

The two analysis budgets are 0.15 and 0.50 seconds. The preregistered decision uses
0.15 seconds. Repeat each comparison twice with rotating arm order. Each arm therefore
has 12 queries per repetition. Report results within program groups because the two
queries in a program share a compiled function and neural record. Timing repetitions
measure variability. They do not increase the number of independent programs.

The clock charges selection, execution and validation. Fresh checker preparation and
native type acquisition are measured separately. All planned outcomes, including
unknowns, unavailable type records and wrong decisions, remain in the denominator.
Native model inputs and raw output pass the v22.1 trace and logit checks before
admission. Reference labels are read by the evaluator after trial collection.

## Decision

Advance to a paired end-to-end cost measurement if one neural arm covers at least
four groups, resolves more queries than B in both repetitions in at least two
groups with a recorded operation-order change, never resolves fewer in any
available group, and the experiment produces
zero wrong decisions. This is a pilot decision criterion. A favorable result
motivates measurement of model acquisition and a strong fixed control before
implementing a gated scheduler.

If genuine coverage is insufficient, inspect acquisition and mapping before making
a scientific judgment. If the effect is absent at sufficient coverage, retain the
result and defer Variant E. Keep any future tuning separate from this panel's
observations.

## Run

From the repository root, run the source reference on Windows with GCC installed.

```powershell
py -3 -B scripts/run_route_b_pilot.py --reference-only
```

For the full CPU pilot, use the existing WSL analysis environment and the separate
original TYGR interpreter on the D: workspace.

```bash
cd /mnt/d/AI_Models/symbolic/SymbAI-Taint
conda activate angr-env
python -B scripts/run_route_b_pilot.py
```

Artifacts go under the workspace parent's `.scratch/selective_analysis/` directory.
Retain `plan.json`, `summary.json`, the run records, and the evidence files needed
to audit them. Temporary reference executables and per-acquisition caches are
removed after use.
The repository contains the small authored inputs and the protocol. The external
model checkpoint and generated outputs follow the
[reproducibility guide](../../../docs/REPRODUCIBILITY.md).

## Local validation

The initial Windows run confirmed all 1,536 source inputs. The repository suite
passed 1,289 tests, and the architecture validator accepted 22 OPM views. A separate
smoke check exercised B on the known v21 scalar fixture. This fixture remains
outside the new panel.

The first WSL pilot completed native inference on all six programs. The
independent DWARF reader missed locations in inline scopes, so the pilot recorded
the neural arms as unavailable. After adding those scopes to the reader, all six
archived outputs passed exact trace and raw-logit validation.

## WSL results

The corrected run `route-b-information-20261118T163008557109Z` completed all 192
trials with six usable model outputs and zero wrong decisions. Each cell gives
resolved trials out of 24. The remaining trials were inconclusive.

| Analysis budget | B | C | K | D |
| --- | ---: | ---: | ---: | ---: |
| 0.15 s (primary) | 16 | 14 | 12 | 13 |
| 0.50 s | 18 | 18 | 18 | 18 |

Each neural arm changed the first operation in all 24 primary-budget pairs
against B. No neural arm had a consistent gain in any program group. K and D
chose the same first operation throughout, and their recorded operation sequences
agreed up to the point where either trial stopped. This limits what the small
difference in their resolved counts can establish about the value of model
scores. At 0.50 s all arms exhausted the catalog on both `palette` queries and
reached the budget limit on the full-scope `grid` query in both repetitions.

The preregistered result is `no_stable_increment_on_this_panel`. This is an
information-only comparison of the existing selector on six authored programs.
The timing budget excludes type acquisition and common preparation. Variant E
remains deferred.

## Read-only byte-load check

A model-free follow-up used the original `palette` and `grid` ELFs on Windows.
The finite-value checker now handles byte loads through `movzx` and the 32-bit
register writes in the query prefixes. It retains the segment, file span, and
relocation checks and rechecks the certificate from the ELF bytes.

In `route-b-byte-readonly-20261118T165438227Z`, the fixed cascade resolved each
`palette` query in all three repetitions, with a median parent wall time of
about 0.24 s per query. The previous fixed cascade left both queries unresolved
in all repetitions. The new certificates each record eight one-byte reads. A
separate literal-state modeled reference checked and freshly rechecked all 256
inputs of `palette_full`. Both `grid` queries still required the expanded check.

The 24 follow-up trials use a 30 s cold parent cap and two known authored
programs. They measure baseline coverage on these cases. The validated byte
loads cover the entire declared domain of each `palette` query, so these cases
provide no measurement of partial-proof reuse.

## Input-domain split diagnostic

The local run `route-b-partial-domain-20261118T170151299Z` used a fixed split at
128 for the full `palette` and `grid` domains and two new authored branch
mechanisms. The cheap checks covered the whole `palette` domain and neither
half of `grid`. For each new branch mechanism, the cheap checks proved one half
and the expanded checker proved the other. A separate literal-state modeled
reference checked all 256 inputs of each new mechanism.

With a 1 s budget in the initialized Windows analysis process, all four modes
completed in all five repetitions for each new mechanism. Combining a rechecked
cheap proof with an expanded check of the remainder reduced the number of paths
checked by the expanded operation from two to one. Relative to a whole-domain
expanded check, its paired median time difference was +2.15 ms on
`mixed_multiply` and -4.86 ms on `mixed_rotate`. It was faster in all repetitions
against the control that ran the expanded checker separately on both halves.

The experiment used a fixed boundary and the cheap side identified by the prior
profile. It does not measure the cost of discovering either in a new program,
or establish a consistent advantage over the whole-domain expanded check on
independent programs.

## Pinned upstream kernel diagnostic

`route-b-external-kernels-20261118T170504629Z` admitted four pinned arithmetic
kernels, one each from Linux, LLVM compiler-rt, musl and GCC libiberty. Each
source was adapted to a common single-byte write query on inputs 0 through
255. A native source-level reference checked all inputs of each adapter.
The AMD64 instructions came from relocation-free objects produced by MinGW GCC
and were packaged as small ELF fixtures for the existing checkers.

Three methods shared each warm wall-clock budget: direct expanded analysis, the
fixed cascade, and automatic splitting after the whole-domain cheap checks.
The splitting clock includes the leading-branch scan, attempted subdomain
checks, fresh evidence validation and any fallback. Every method resolved
9/12 trials at 1 s and 12/12 at 3 s. No trial reported an incorrect decision.

Linux `int_sqrt` was the only case where the automatically detected cut
produced a cheap proof for one side. Its expanded operation checked 15 paths
after reuse, versus 16 on the whole domain, and reported 113 execution steps
in both modes. At 3 s, the median times were 2.393 s with reuse, 2.309 s for
direct expanded analysis, and 2.419 s for the fixed cascade. The paired median
difference between reuse and direct expansion was +0.113 s. The other three
kernels fell back to the whole-domain checker. This small convenience sample
measures behavior on the adapted kernels and supplies no evidence for a general
runtime advantage.

## Solver cost attribution

`route-b-solver-cost-20261118T171608536Z` profiled the same four upstream
adaptations and two authored branch mechanisms. The three methods completed
all 90 recorded trials at a 4 s warm wall-clock budget. The observer timed the
native Z3 check API calls and marked calls made during fresh validation. The
outer clock includes the observer, split discovery, and fresh rechecks.

On Linux `int_sqrt`, the split reduced Z3 checks from 130 to 128 in every
paired repetition. The paired median differences were +10.3 ms inside Z3
checks and +85.2 ms for the full trial. In the direct run, native check calls
accounted for a median 8.7% of wall time, and fresh validation accounted for
49.4% including its own solver calls. Time outside the native check APIs
includes state execution, constraint construction and solver setup.

Both authored mechanisms also removed two Z3 checks. Their paired median wall
differences against direct analysis were -12.9 ms and +9.9 ms, respectively.
The profiles distinguish counts from measured costs on these development
inputs. They neither fit a predictor nor establish performance on held-out
programs.

## Independent-source continuation gate

`route-b-independent-gate-20261118T172437849Z` froze 13 previously unevaluated
functions across littlefs, Lua, SQLite, Redis, and Berkeley SoftFloat before
compilation. The experiment uses their arithmetic routines with a common
single-write harness. Its local source list records blob identities, input
ranges, and all adaptation choices, including the software fallback for
littlefs population count. Native reference executables checked 173,389 input
values across the 13 ranges. The analysis used MinGW-linked AMD64 instructions
and their mapped sections in ELF fixtures.

All 234 planned trials finished. Each method resolved 27/39 trials at 1 s and
30/39 at 3 s, with zero wrong decisions. Automatic partitioning used a partial
proof only on Redis `digits10`. It reduced the recorded symbolic steps including
the recheck from 68 to 64 and retained 32 Z3 calls. Its paired median time
difference against direct expansion was +9.3 ms at 1 s and +21.3 ms at 3 s.
No upstream family met the continuation criterion relative to both baselines.

On queries solved in every repetition by every method, selecting the shortest
observed per-query median retrospectively reduced the sum of times over the
best single method by 0.26% at 1 s and 0.64% at 3 s. The median share of fresh
validation in direct expansion was 43.95% and 43.13%, respectively, on those
matched queries. These are development measurements on adapted functions and
support deferring a partition-benefit predictor with the current methods.

## Independent validation cost pilot

`route-b-independent-check-20261118T173431694Z` used the same initial symbolic
checker in both arms. The path-certificate arm captured complete target-prefix
paths, encoded them, and checked them from the ELF with a separate decoder-based
semantics for a restricted acyclic integer subset. It used one Z3 query covering
the missing-edge and write-bound obligations. The wall clock includes producer
construction, capture, encoding, decoding, and the check.

Fresh replay resolved 35/35 trials. The stand-alone certificate prototype
resolved 30/35 and reported `unknown` on all five `lfs_npw2` repetitions because
`bsr` is outside its subset. On the six supported queries, paired median wall
time was 7.9–25.3 ms lower with certificate validation. A separate untimed
address-equivalence check passed on those six queries. Five altered certificates
were rejected, including omission of a feasible path and a false bound with
rebuilt query identity.

A separate comparison enabled fresh replay after certificate rejection. Both
arms resolved 35/35 trials with zero wrong decisions. The six supported queries
had paired median wall-time reductions of 7.1–25.8 ms, and the unsupported
`lfs_npw2` control had a 3.3 ms median overhead. These pilot cases were selected
after bytecode inspection. The verifier shares Z3 and ELF admission checks
with the existing environment and does not have a mechanically verified x86
semantics or held-out coverage measurement.

## Certificate coverage on the source-selected cohort

`route-b-certificate-coverage-20261118T174339141Z` kept the certificate checker
frozen and ran both fresh replay and the certificate-plus-fallback method on all
13 functions from the earlier independent-source cohort. Eight queries had
not been used to develop the certificate checker and formed the primary
population. All 156 timed trials were retained.

On the primary population, both methods resolved 12/24 trials at 1 s and
15/24 at 3 s. The certificate checker accepted 0/12 and 0/15 attempts at the two
budgets, respectively, and every correct result used fallback. There were no
wrong decisions or material proof disagreements. The 12 certificate
acceptances per budget in the full cohort came from the development queries.
At 3 s, summed per-query medians on paired primary results differed by 0.2%.
The predeclared continuation criterion was unmet.

An untimed path audit separated two non-forward cases. SQLite
`sqlite3LogEstToInt` had three paths that moved to a lower instruction address
without revisiting any address. Lua `luaO_int2fb` had five paths that revisited
an address. The other completed primary queries hit separate register-width,
instruction, or prefix restrictions. These measured coverage limits identify
which proof-checking assumptions account for the missed opportunities.

## Valid lower-address edges in simple paths

`route-b-certificate-acyclic-20261118T174807920Z` changed certificate admission to
allow a path to move to an earlier instruction address. The checker still verifies
each recorded edge against the ELF and rejects repeated addresses within a path.
A new authored layout passed with the updated checker and was separately
rechecked on all 256 inputs. The modified edge, omitted reachable path, and
repeated-address controls were rejected. Six archived certificates reproduced
their earlier validation outcomes.

On the retained binaries, SQLite `sqlite3LogEstToInt` passed the path-shape gate
and stopped at an unsupported instruction prefix in its 16-bit arithmetic.
Lua `luaO_int2fb` remained outside the subset because of repeated instruction
addresses. This is a regression check for the path rule. The prior coverage
experiment remains tied to its original checker.

## Bounded loop path certificates

The experimental checker in `src/selective_analysis/path_certificate.py` checks
finite instruction prefixes even when an instruction address recurs. Each
prefix carries its own register state. The checker verifies recorded transitions
from the ELF, and accepts only when the combined obligations exclude both a
feasible omitted edge and an out-of-bounds target write. It allows at most 64
paths, 128 addresses per path, and 2,048 prefix-tree nodes, and uses the caller's
deadline for checking.

`route-b-certificate-bounded-20261118T175349629Z` verified the retained Lua
`luaO_int2fb` ELF across the declared range of 0–1,023. Its certificate has ten
paths, five with repeated addresses. The checker visited 108 prefix nodes.
Omitting a reachable loop trace, exhausting the node budget, and passing an
expired deadline all prevented acceptance. A separate address-equivalence and
coverage check passed, along with seven earlier certificates.

All five paired trials were faster with certificate validation. The median
total was 0.332 s versus 0.568 s with fresh replay, including producer work and
serialization. The paired median reduction was 0.232 s. This measures one
known Lua query.

## Independent bounded-loop validation cohort

`route-b-bounded-external-20261118T205419917365Z` froze nine arithmetic cases
from Linux v6.12, GCC 14.2.0, zlib 1.3.1, and FFmpeg 7.1 before compilation.
The fixtures inline or link the extracted routines, place the resulting AMD64
segments in ELF, and query a single store indexed by the adapted output. All
474 declared inputs passed native index checks. The cohort includes related
routines within projects and a high-bit output projection for zlib
`x2nmodp`. Results apply to the stated ranges and adapters.
[Linux source](https://github.com/torvalds/linux/tree/v6.12/lib/math),
[GCC source](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.2.0/libgcc/udivmodsi4.c),
[zlib source](https://github.com/madler/zlib/blob/v1.3.1/crc32.c),
[FFmpeg source](https://github.com/FFmpeg/FFmpeg/tree/n7.1/libavutil).

| Budget | Fresh replay correct | Certificate with fallback correct | Certificates accepted |
| --- | ---: | ---: | ---: |
| 1 s | 1/27 | 0/27 | 0/5 attempted |
| 3 s | 6/27 | 6/27 | 0/9 attempted |

All 108 planned trials ran with zero wrong decisions. The 3 s arms agreed on
all paired outcomes, and every correct result in the certificate arm used
fallback. Eighteen of 27 certificate-arm trials at 3 s ended before certificate
verification because the producer was unresolved. The predeclared
cross-project continuation criterion was unmet.

A separate diagnostic reproduced the three verifier rejections. Linux
`int_pow` and `gcd` reached an unsupported `test` instruction. GCC
`__udivmodsi4` reached a `je` using flags set by `shr`. The local cohort,
plan, intake, timed records, and rejection audit retain the exact source and
binary identities.

## Parent-enforced deadlines and producer costs

`route-b-parent-deadline-20261118T212130486294Z` reran the same nine queries
and two validation arms for 108 trials. Each trial used a cold worker. The
parent charged process launch, execution, result read, and cancellation or
reaping to wall time. It admitted complete matching results by the absolute
deadline. Observed wall time including cleanup and result handling extended
up to 32 ms beyond 1 s and 47 ms beyond 3 s. The early completion and forced
cancellation controls both passed.

| Budget | Fresh replay correct | Certificate with fallback correct | Certificates accepted |
| --- | ---: | ---: | ---: |
| 1 s | 0/27 | 0/27 | 0/0 attempted |
| 3 s | 3/27 | 3/27 | 0/6 attempted |

Every 1 s worker reached its setup event and expired before the producer
started. At 3 s both arms resolved all three Linux `int_pow` repetitions
and agreed on all paired outcomes. All correct decisions in the certificate
arm used replay. There were no wrong decisions or late admissions. These
cold-worker counts have a broader timing scope than the earlier warm run.

A separate producer-only profile ran three repetitions per case with a
larger deadline. The reported shares use producer check time after checker
construction. Successor time outside native checks includes state and
constraint handling.

| Case | Producer check median | Share inside native Z3 checks | Share in successor calls outside those checks | Completed paths |
| --- | ---: | ---: | ---: | ---: |
| zlib `multmodp` | 2.056 s | 0.9% | 79.9% | 63 |
| FFmpeg `av_gcd` | 12.012 s | 41.0% | 54.4% | 19 |

Each profile completed the initial symbolic check in all three repetitions.
The measured phases overlap only where a native check ran inside a tracked
phase, and those checks were subtracted from the outside-check shares.
These profiles measure two previously inspected cases.

## Guarded instruction batching pilot

`route-b-instruction-batch-pilot-20261118T213329921957Z` evaluated an experimental
producer that groups up to four consecutive register operations, allowing
one direct conditional branch at the end. The decoder and VEX lift must
agree on the instruction prefix. The producer tracks depth in individual
instructions, stops before the target write, and reconstructs the full
instruction sequence for each path.

The two producers enumerated the same 63 paths for zlib `multmodp` and
19 for FFmpeg `av_gcd`. A separate SMT comparison discharged path-guard,
coverage, address, and write-length disagreements against the single-step
results and native references across all 127 inputs. The one-instruction
depth controls stayed unresolved. The existing verifier accepted the
reconstructed Lua `luaO_int2fb` control certificate and reproduced its
earlier instruction-subset rejection on the two measured queries.

The timing experiment used the same cold-worker parent deadline and fresh
single-step replay in both arms. All 12 trials at 3 s were unresolved.
At the case-specific relaxed budgets, all three pairs for each case
completed with matching instruction traces. Across the 24 trials, no
wrong or late decisions were admitted.

| Case | Relaxed budget | Producer calls, single to batch | Median total wall time, single to batch | Median paired total saving |
| --- | ---: | ---: | ---: | ---: |
| zlib `multmodp` | 8 s | 847 to 582 | 5.999 s to 5.773 s | 0.229 s |
| FFmpeg `av_gcd` | 30 s | 217 to 129 | 24.693 s to 23.210 s | 1.416 s |

Median paired savings in the producer phase were 0.204 s and 0.344 s,
respectively. The full-trial figures include startup and validation time.
The results describe two development queries and a shared replay protocol.

## Certificate validation with cold and prewarmed workers

`route-b-cold-warm-certificate-20261118T214546898406Z` fixed the four-instruction
producer and crossed startup mode with validation strategy on zlib
`multmodp`. The experimental verifier adds the zero flag from register
`test` for equality branches. Its separate stored-path check agreed with
all 63 native indices and rejected a certificate with one feasible path
removed.

Each worker handled one query. Prewarming loaded the runtime before the
worker received its query. The parent enforced an absolute deadline and
retained both query time and launch-to-result time. The cold query clock
includes startup. The prewarmed query clock starts at dispatch to the ready
worker.

| Startup | Validation | Correct at 3 s | Correct at 8 s | Median query time at 8 s |
| --- | --- | ---: | ---: | ---: |
| Cold | Fresh replay | 0/3 | 3/3 | 5.806 s |
| Cold | Certificate with replay fallback | 0/3 | 3/3 | 3.908 s |
| Prewarmed | Fresh replay | 0/3 | 3/3 | 4.199 s |
| Prewarmed | Certificate with replay fallback | 3/3 | 3/3 | 2.285 s |

The three prewarmed certificate trials at 3 s had median query time of
2.287 s and median launch-to-result time of 3.919 s. Median prewarming
took 1.636 s. At 8 s the paired median query time reduction was 1.941 s
for cold workers and 1.914 s for prewarmed workers. The FFmpeg
`av_gcd` functional control completed under a 30 s budget in both arms.
The certificate arm rejected the unsupported `bsf` instruction and obtained
the result through fresh replay.

All 26 planned runs were recorded with zero wrong decisions or late
admissions. These are development results on one certificate-positive
query and one fallback control.

## Frozen certificate comparison on new scalar functions

`route-b-frozen-certificate-panel-20261118T215333450381Z` fixed the producer and verifier
and selected six previously unevaluated scalar functions before compilation.
The sources were FreeType, Opus, OpenJPEG, LLVM compiler-rt, and SDL.
All six adapters built, and native enumeration checked their 384 declared
inputs against the frozen mathematical references. The study uses scoped
marker-write queries built from the pinned arithmetic fragments.
[FreeType source](https://github.com/freetype/freetype/blob/VER-2-13-3/src/base/ftcalc.c),
[Opus source](https://github.com/xiph/opus/blob/v1.5.2/celt/mathops.c),
[OpenJPEG source](https://github.com/uclouvain/openjpeg/blob/v2.5.2/src/lib/openjp2/opj_intmath.h),
[LLVM source](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/compiler-rt/lib/builtins/int_div_impl.inc),
[SDL source](https://github.com/libsdl-org/SDL/blob/release-3.2.0/src/stdlib/SDL_crc16.c).

Both methods used the same prewarmed one-query worker and charged the
same parent deadline. The study retained launch-to-result times separately.
Each method had two trials per query at each budget.

| Query budget | Fresh replay verified | Certificate with fallback verified | Direct certificate | Verified through fallback |
| --- | ---: | ---: | ---: | ---: |
| 3 s | 10/12 | 10/12 | 2 | 8 |
| 8 s | 10/12 | 10/12 | 2 | 8 |

The five resolved cases passed a separate path, guard, and address audit
across their 320 inputs. All 48 trial records were retained with zero
wrong decisions, late admissions, or losses of paired baseline decisions.
FreeType `FT_SqrtFixed` stayed unresolved at both budgets.

OpenJPEG `opj_uint_floorlog2` provided all four direct certificates.
The paired median query time saving was 0.121 s at 3 s and 0.124 s at
8 s. The verifier rejected the modified certificate with one feasible
path removed. Of 18 rejected certificate attempts, 14 first stopped on
`bsr` and four on `neg`. OpenJPEG was the only project that met the
predeclared per-project criterion. The cross-project criterion required
two qualifying projects and remained unmet.

## Guarded bit scan and subtraction flags regression

The path checker accepts register-only 32-bit and 64-bit `bsr` when it
proves the source nonzero at every reachable scan. A reachable zero source
prevents acceptance because the destination is undefined. The checker also
tracks the zero and sign flags of a width-truncated `sub` result for
equality and sign branches. It incorporates the previously tested
register `test` zero-flag rules under the same certificate format.

`route-b-formal-bsr-regression-20261118T220638990261Z` reran the six
existing scalar queries using the same producer, binaries, query bounds,
and prewarmed-worker time limits. All 48 trial records were retained.

| Query budget | Fresh replay correct | Certificate with fallback correct | Prior direct certificate | Revised direct certificate |
| --- | ---: | ---: | ---: | ---: |
| 3 s | 10/12 | 10/12 | 2 | 8 |
| 8 s | 10/12 | 10/12 | 2 | 8 |

FreeType `ft_div64by32`, Opus `isqrt32`, and LLVM `__udivXi3` gained
direct validation in every repetition. Their paired median query savings
at 8 s were 0.527 s, 0.612 s, and 0.256 s, respectively. The OpenJPEG
case continued to validate directly. SDL still used replay after a
`neg` rejection, and FreeType `FT_SqrtFixed` stayed unresolved.

A separate audit verified every completed case against the native
references. Lua and zlib's saved certificates passed, and deleting a
feasible path prevented acceptance. The timed runs produced zero wrong
decisions, lost baseline decisions, or late admissions. This is a
development regression on known cases.

## Independent comparison after the bit-scan revision

`route-b-independent-bsr-panel-20261118T222118158809Z` froze the revised checker and
selected six new scalar routines from fmt, LibTomMath, Boost, and a
mirrored GMP 6.2.1 release before compilation. The method, input ranges,
and source adaptations were pinned. Native enumeration checked 384
inputs. The cases include two C specializations of fmt routines, two
one-digit LibTomMath operations, and two distinct GCD implementations.
[fmt source](https://github.com/fmtlib/fmt/blob/11.0.2/include/fmt/format.h),
[LibTomMath source](https://github.com/libtom/libtommath/blob/v1.3.0/bn_mp_cnt_lsb.c),
[Boost source](https://github.com/boostorg/integer/blob/boost-1.86.0/include/boost/integer/common_factor_rt.hpp),
[GMP snapshot](https://github.com/alisw/GMP/blob/v6.2.1/mini-gmp/mini-gmp.c).

| Prewarmed query budget | Fresh replay verified | Certificate with fallback verified | Direct certificate |
| --- | ---: | ---: | ---: |
| 3 s | 6/12 | 6/12 | 2 |
| 8 s | 6/12 | 6/12 | 2 |

Three queries were resolved and passed a separate trace, guard, and
first-write audit across 192 inputs. All 48 final trials were retained
with zero wrong decisions, late admissions, or losses of paired baseline
decisions. fmt's hexadecimal digit count provided all four direct
certificates. Its 8 s paired median query saving was 42 ms (15.4%),
below the predeclared absolute minimum of 50 ms. No project qualified,
so the cross-project criterion remained unmet.

A GMP source file used form-feed page breaks. Correcting the extractor
to count physical lines recovered the frozen routine and its 64 native
checks. The experiment retained the first 40 measurements and ran only
the eight original GMP slots after this correction. All eight GMP
queries remained unresolved. The initial intake and supplementary
receipts are retained with the combined report.

## Exact finite-input execution baseline

`route-b-concrete-enumeration-20261118T231121220578Z` compared exhaustive
concrete execution with the frozen symbolic pipeline on the existing
Boost `Euclid_gcd`, GMP `mpn_gcd_11`, and LibTomMath `mp_cnt_lsb`
ELF queries. Each declared domain contains 64 inputs. The concrete arm
installed each input as a concrete value in the same VEX-based execution
environment and stopped before the first marker write. It used lifted basic
blocks, required concrete control and write observations, and shared the
symbolic arm's original instruction observation window. All observed
write addresses and lengths were compared independently with native
reference receipts after timing.

| Prewarmed query budget | Frozen symbolic verified | Concrete enumeration verified |
| --- | ---: | ---: |
| 3 s | 0/6 | 4/6 |
| 8 s | 0/6 | 4/6 |

Both repetitions for Boost and LibTomMath covered all 64 inputs at each
budget, including within 3 s when prewarming was charged. Their median
3 s query times were 0.778 s and 0.630 s. The audit checked all 741
observations from complete and partial trials with zero mismatches. All
24 trial records were retained with zero wrong decisions or late
admissions.

GMP observed 62 of 64 inputs in both 8 s repetitions. A separate
larger-depth control confirmed that the remaining two inputs reach
the first write after exactly 128 executed instructions. Both block
and single-step execution agreed on the addresses, lengths, and depth.
The primary observation window covered depths 0 through 127, so the
GMP results remained unresolved there. These results compare practical
pipelines on the three narrow input domains.

## Input-domain size sweep

`route-b-domain-size-sweep-20261118T231807570490Z` reused the fmt hexadecimal digit
count and zlib `multmodp` ELF fixtures with domains of 16, 64, and 512
inputs. Only the input contract changed within each program. Separate
native reference builds and mathematical formulas agreed on all 512
inputs per program. The paired runs used the same prewarmed workers and
128-depth observation window as the preceding comparison.

| Case | Inputs | Correct at 3 s, symbolic and concrete | Correct at 8 s, symbolic and concrete | Median query time at 8 s, symbolic and concrete |
| --- | ---: | ---: | ---: | ---: |
| fmt digit count | 16 | 2/2, 2/2 | 2/2, 2/2 | 0.248 s, 0.258 s |
| fmt digit count | 64 | 2/2, 2/2 | 2/2, 2/2 | 0.287 s, 0.494 s |
| fmt digit count | 512 | 2/2, 0/2 | 2/2, 2/2 | 0.294 s, 3.220 s |
| zlib `multmodp` | 16 | 2/2, 2/2 | 2/2, 2/2 | 0.993 s, 0.966 s |
| zlib `multmodp` | 64 | 2/2, 0/2 | 2/2, 2/2 | 2.695 s, 3.532 s |
| zlib `multmodp` | 512 | 0/2, 0/2 | 0/2, 0/2 | Unresolved in both arms |

Every completed symbolic result used a direct certificate. The 512-input
fmt query had three symbolic paths. At 8 s its median time including
worker startup was 2.134 s with certificates and 4.969 s with enumeration.
For zlib at 512 inputs, a separate diagnostic stopped when the symbolic
frontier reached 76 states, above the configured limit of 64. Enumeration
observed 158 and 162 inputs at 8 s before expiry.

All 48 trial records and prewarming costs were retained. The audit found
zero address or length mismatches across 3,126 concrete observations
and verified the completed symbolic results against native references.
No wrong or late results were admitted. These two development fixtures
show distinct growth in path and state counts as the input domain expands.

## Symbolic prefix for selecting an execution strategy

`route-b-prefix-selector-pilot-20261118T232724510586Z` compared two
rules at a parent-enforced 3 s query deadline. The input-count rule used
exhaustive concrete execution for up to 64 inputs and the frozen symbolic
pipeline for larger domains. The prefix rule kept that default and probed
domains of up to 64 inputs. It switched to symbolic execution only when
the observed frontier peaked at one state, the probe reached its depth
limit or ran out of active states, and no precision loss was observed.

The probe used a 12-instruction depth limit, a 32-call limit, a 16-state
frontier cap, and a cooperative 120 ms clock. The query clock charged
probe setup, selection, execution, validation, and result admission.
The selected backend started with a fresh state. Probe observations
served solely as input to the selection rule.

| Panel | Upstream projects | Per-rule trials | Verified within 3 s after prewarming, size only and prefix | Verified within 3 s after adding observed startup, size only and prefix |
| --- | ---: | ---: | ---: | ---: |
| Development | 5 | 18 | 12, 14 | 12, 12 |
| Selector holdout | 5 | 12 | 12, 12 | 2, 8 |

The development panel contained nine scoped queries and the threshold
was fixed after exploratory measurements on that panel. Both added
prewarmed decisions were repetitions of the zlib 64-input query. The
charged probe time was 63 ms at the median and 159 ms at the maximum.

The holdout retained the complete earlier six-query panel from FreeType,
Opus, OpenJPEG, LLVM, and SDL, all with 64 inputs. These projects were
disjoint from selector development. Some cases had informed earlier
instruction semantics work on the certificate checker. Both controls
completed all holdout trials after prewarming, so the criterion for
additional verified decisions at that deadline was unmet.

The prefix rule chose symbolic execution for both repetitions of the
FreeType division, Opus square root, and SDL CRC queries. The median
paired saving across these six trials was 0.887 s, including the probe.
The median probe cost over all 12 holdout probe trials was 72 ms. All
60 original trial records were retained. The separate audit checked
2,328 concrete address and length observations and reproduced the
completed symbolic results against native references. There were zero
wrong decisions, late admissions, or audit mismatches.

### Cold-start confirmation on the same holdout

A follow-up reused the frozen rules, six query contracts, and paired
schedule. The parent enforced one 3 s deadline from worker launch
through result admission. This run followed inspection of the
startup-adjusted prewarmed results and used the same holdout programs.

| Rule | Verified within 3 s | Unresolved |
| --- | ---: | ---: |
| Input count only | 2/12 | 10/12 |
| Symbolic prefix | 8/12 | 4/12 |

FreeType division, Opus square root, and SDL CRC each gained a verified
decision in both repetitions. The prefix rule preserved both baseline
decisions. The median worker startup was 1.703 s. The separate audit
checked 1,018 concrete address and length observations and reproduced
the admitted symbolic results. All 24 cold trial records had zero wrong
decisions, late admissions, or audit mismatches. The cold comparison
estimates the benefit on this panel under the measured startup costs.

### Cold-start test on five new projects

`route-b-prefix-independent-20261119T063805697Z` froze six scalar queries
before compilation and timing. They cover xxHash avalanche mixing, stb bit
reversal and integer log, miniz two-byte Adler-32, utf8proc byte
classification, and libpng big-endian decoding. The two stb queries
share one project. Each extracted kernel uses an explicit 64-input
domain and a synthetic observation write. Native builds and separate
reference calculations agreed on all 384 inputs.
[xxHash](https://github.com/Cyan4973/xxHash/blob/v0.8.2/xxhash.h),
[stb](https://github.com/nothings/stb/blob/f0569113c93ad095470c54bf34a17b36646bbbb5/stb_vorbis.c),
[miniz](https://github.com/richgel999/miniz/blob/3.0.2/miniz.c),
[utf8proc](https://github.com/JuliaStrings/utf8proc/blob/v2.9.0/utf8proc.c),
[libpng](https://github.com/pnggroup/libpng/blob/v1.6.43/pngrutil.c).

The test reused the frozen prefix rule and both backends. Each method
ran twice per query under a 3 s parent deadline from worker launch.
The input-count rule uses concrete enumeration on every 64-input query.
The continuation criterion required higher coverage than both fixed
backends, no lost concrete decisions, and repeated gains over concrete
enumeration on at least two projects.

| Rule | Verified within 3 s | Unresolved |
| --- | ---: | ---: |
| Fixed concrete enumeration | 12/12 | 0/12 |
| Symbolic prefix | 12/12 | 0/12 |
| Fixed symbolic execution | 8/12 | 4/12 |

The prefix rule used concrete enumeration for both repetitions of the
stb integer log and utf8proc byte classification queries. The fixed
symbolic producer returned unresolved on those four trials. The
prefix rule retained symbolic execution for the other eight trials.
Across 12 pairs completed by the prefix and concrete rules, the median
paired saving was 99 ms with the probe and startup included. The two
utf8proc probes each took about 0.21 s including setup, beyond the
cooperative 120 ms probe clock. Both completed within the parent
deadline after switching to concrete execution.

The coverage criterion was unmet because concrete enumeration completed
every trial. All 36 trial records and 1,024 concrete observations
passed the audit with zero wrong decisions, late admissions, or
address and length mismatches. The paired timing describes this
64-input cohort and its measured startup costs.

### Cold-start domain scaling on the same six kernels

`route-b-independent-domain-sweep-20261119T070742864Z` extended
the six preceding fixtures to 128 and 256 inputs. Each query retained
its ELF bytes, observation site, and output capacity. The ranges
contain all 64 original inputs. Five kernels kept the lower endpoint.
The utf8proc range expanded towards zero within its 256-entry table.
Native builds and separate source-level references agreed on all 1,536
kernel-input combinations through the largest domain.

The parent enforced a 3 s deadline from worker launch in two repetitions
per kernel, size, and fixed backend. Both existing selection rules
choose symbolic execution without a probe above 64 inputs. One
symbolic arm therefore measures their shared choice.

| Inputs per query | Fixed concrete verified | Fixed symbolic verified | Pairs with a verified result from either arm |
| --- | ---: | ---: | ---: |
| 64, preceding run | 12/12 | 8/12 | 12/12 |
| 128 | 9/12 | 8/12 | 10/12 |
| 256 | 7/12 | 8/12 | 10/12 |

The final column uses both outcomes after measurement and provides a
descriptive upper bound for choosing one of the recorded backends.
The 64-input row comes from the preceding cold-start run.

utf8proc byte classification completed only with concrete enumeration
in both repetitions at both expanded sizes. At 256 inputs, stb bit
reversal completed only with the symbolic backend in both repetitions.
The same input count therefore leads to opposite backend preferences
for these two kernels. The expanded stb integer-log queries remained
unresolved in both arms. Across the paired completions at 128 and 256
inputs, the median symbolic savings were 0.398 s (seven pairs) and
0.936 s (five pairs), respectively, including startup.

All 48 new records were retained. The audit checked 4,255 concrete
observations and reproduced the admitted symbolic decisions. It found
zero address or length mismatches, wrong decisions, or late admissions.
These observations characterize the existing adapted kernels under
the measured budget.

### Prefix applicability extended to 256 inputs

`route-b-prefix-256-20261119T071622611Z` retested the same six
256-input contracts from the domain sweep. The only rule change was
the applicability threshold, from 64 to 256 inputs. The prefix
condition and its cooperative limits were frozen. Both fixed backends
were rerun in paired order. Each trial had a 3 s parent deadline from
process launch through result admission.

| Rule | Verified within 3 s | Unresolved |
| --- | ---: | ---: |
| Fixed concrete enumeration | 3/12 | 9/12 |
| Fixed symbolic execution | 7/12 | 5/12 |
| Prefix enabled at 256 inputs | 7/12 | 5/12 |

The prefix arm preserved all seven fixed symbolic results and added
zero. The prespecified coverage criterion was unmet. The fixed
backends together completed eight of the 12 paired slots. One miniz
repetition ran out of time before the prefix arm reported a decision.
Both fixed arms also ran out of time in that repetition. The table
uses the controls rerun with the prefix arm.

For both utf8proc trials, the probe selected concrete enumeration,
which was the only backend that completed a utf8proc trial in this
comparison. Probe and setup cost 0.984 s and 0.937 s, well beyond the
cooperative 120 ms probe clock. The resulting enumeration attempts
observed 61 and 86 of the 256 inputs before the parent stopped them.
In the second repetition, fixed concrete enumeration verified the
query in 2.827 s with essentially the same startup time (1.699 s
for fixed concrete and 1.703 s for the prefix arm).

Across the 11 recorded probes, the charged median was 52 ms and the
maximum was 984 ms. All 36 trials were retained. The audit checked 2,996
concrete observations and reproduced the admitted symbolic results.
There were zero wrong decisions, late admissions, or audit mismatches.
This same-panel test shows how a long probe can consume the time
needed by the backend it selects.

### Routing headroom and synthetic deadline test

`route-b-probe-budget-20261119T081918030Z` paired each 256-input prefix
trial with the fixed trial for the backend it selected. Eight pairs
had a fixed arm with an admitted result. For those pairs, the routing
allowance was estimated as the 3 s deadline minus the prefix trial's
observed startup and the matching fixed trial's time after readiness.

The usable utf8proc pair reserved 1.703 s for startup and 1.128 s
for concrete execution and admission, leaving 168 ms for routing.
The measured probe took 937 ms in that repetition. The 120 ms
nominal cutoff would leave 48 ms for additional overhead under the
matched timing assumption. The first repetition's fixed concrete
result missed the deadline and supplies no completed reference for
this calculation.

The same diagnostic tested parent-enforced response admission and
worker recovery with synthetic Python sleep tasks. Each of three
durations (30 ms, 145 ms, and 950 ms) ran ten times with a clock
starting after readiness and ten times from process launch. The
parent admitted all 20 short tasks, stopped and reaped all 40 longer
tasks, and accepted zero late replies. The longest timed interval
through recovery was 138 ms, or 18 ms past the 120 ms admission
deadline. Applying that measured interval to the usable utf8proc
pair leaves about 30 ms in the retrospective calculation.

This test measures the timer with synthetic work. The retrospective
estimate assumes the recorded backend service time and leaves
the integrated worker and its startup costs for direct measurement.

### Isolated prefix with parent-enforced response admission

`route-b-isolated-prefix-receipt-20261119T084221402Z` tested
the real prefix in a separate process on the same six 256-input
contracts. The backend and probe loaders started concurrently inside
the 3 s deadline. Once the probe reported readiness, the parent allowed
120 ms for a complete reply matching the query and trial identity.
It then recovered the helper before sending one backend choice.
Reply reception, helper recovery, backend execution, validation,
and result admission were charged to the same deadline.

The first transport version waited for the helper interpreter to exit
and discarded some replies already emitted within the probe window.
Its six profiles and 36 trials are retained in
`route-b-isolated-prefix-20261119T083716337Z`.
The corrected transport admits an atomic result file received by the
cutoff. The final schedule was frozen before rerunning all controls.

| Rule | Verified within 3 s | Unresolved |
| --- | ---: | ---: |
| Fixed concrete enumeration | 2/12 | 10/12 |
| Fixed symbolic execution | 8/12 | 4/12 |
| Isolated prefix | 8/12 | 4/12 |

The separate six-case probe profile admitted four replies. In the
paired run, eight of 12 probe replies arrived within their windows.
The other four probes timed out and selected concrete enumeration.
All helpers were recovered. The median probe window including
recovery was 76 ms, with a maximum of 137 ms. No reply arriving
after the 120 ms response cutoff was admitted. Probe loader startup
had a median of 1.921 s and overlapped backend loading.

The isolated prefix preserved all eight fixed symbolic decisions.
Both utf8proc prefix trials remained unresolved after observing
237 and 235 concrete inputs. Both matching fixed concrete trials
also missed the deadline. Across eight pairs completed by both the
isolated prefix and fixed symbolic arms, the isolated method took
188 ms longer at the paired median. The coverage criterion remained
unmet.

All 36 corrected trial records were retained, and the audit checked
3,304 concrete observations and reproduced the admitted symbolic
results. It found zero wrong decisions, late admissions, unreaped
children, or address and length mismatches. The result measures
this cold process arrangement on the existing six-case panel.

### Persistent workers under a charged batch budget

`route-b-persistent-batch-cleanup-20261119T091703991Z` reused the six 256-input
queries in two batch repetitions. Each method received 18 s for the
complete six-query batch, including process loading, communication,
helper replacement, execution, validation, log processing, and recovery.
Each query received at most 3 s after it entered routing. The second
repetition reversed the query order. Imported code remained resident
between requests, and each operation created a fresh query checker.

The fixed methods used a backend process and replaced it after a
request deadline. The prefix method also kept a probe process. A
probe timeout caused that helper to be reaped, with replacement
charged to the next request and the batch. Completed probe replies
kept the helper available for the next query.

| Method | Verified queries over both batches | Batch elapsed time, first and second repetition |
| --- | ---: | ---: |
| Fixed concrete enumeration | 9/12 | 12.220 s, 13.430 s |
| Fixed symbolic execution | 8/12 | 3.183 s, 3.170 s |
| Persistent prefix | 10/12 | 9.963 s, 9.937 s |

All six batches completed within 18 s. The prefix retained every
decision from both fixed methods. Its two added results over fixed
symbolic execution were the utf8proc query in both repetitions.
Its single added result over fixed concrete execution was stb bit
reversal in the reversed batch, where restarting the concrete backend
after the integer-log timeout consumed part of the request budget.
The integer-log query remained unresolved under all three methods.

The prefix received ten of its 12 probe replies on time. Each prefix
batch used four process launches, including helper replacements and
a backend replacement. The fixed concrete batches used two and three
launches, while each symbolic batch used one. The specified
batch-coverage criterion passed on this same-panel engineering test.

The initial attempt encountered a Windows file-sharing error when
the parent removed a staging file still being written by a worker.
Cleanup was moved after worker recovery. Its two completed batches
and interrupted third-batch logs are retained in
`route-b-persistent-batch-20261119T091311778Z`. All six reported batches
were rerun with the corrected transport.

The audit checked all 36 final query records and 3,951 concrete
observations against the saved references. It found zero wrong
decisions, late query or probe admissions, unreaped workers, or
address and length mismatches. The batch protocol charges startup
once for several requests. Further controls and independent samples
are needed to assess a broader selection benefit.

### Fixed symbolic-to-concrete fallback baseline

`route-b-cascade-baseline-20261119T092309078Z` compared the persistent
prefix with a fixed fallback order. The fixed method first ran the
symbolic backend. On an unresolved result, it started fresh concrete
enumeration with the time remaining before the same request deadline.
A decisive symbolic result ended the request. Each attempt's original
events were retained separately, and the final attempt supplied the
reported query result.

The comparison reran both methods on the same six 256-input queries
in forward and reverse order. Each complete batch had an 18 s cold
deadline, each request had at most 3 s, and all loading, communication,
helper replacement, validation, and recovery were charged.

| Method | Verified queries | Batch elapsed time, first and second repetition | Process launches per batch |
| --- | ---: | ---: | ---: |
| Fixed symbolic-to-concrete fallback | 12/12 | 7.170 s, 7.187 s | 1, 1 |
| Persistent prefix | 12/12 | 8.161 s, 8.163 s | 3, 3 |

The prefix added zero decisions over the fixed fallback and took
0.984 s longer at the paired batch median. Its utf8proc requests
were faster by a paired median of 0.828 s. After those probes timed
out, the next queries waited 1.694 s and 1.685 s for replacement
helpers. Those costs contributed to the higher full-batch time.
The fixed cascade's integer-log requests completed in 2.958 s and
2.989 s under the 3 s request limit.

All 24 query records passed the result audit, including 2,048
concrete observations. A separate check also matched all 1,024
raw cascade-stage concrete observations to their saved references.
There were zero wrong decisions, late query or probe admissions,
unreaped workers, or address and length mismatches. All four
batches completed within their budgets.

The prefix's coverage criterion was unmet. The previous advantage
over the two single-backend controls therefore provides insufficient
evidence for an advantage over a fixed fallback order on this panel.
These figures come from the four newly paired batches on the
existing kernels.

### Retrospective zero-acquisition route replay

`route-b-oracle-headroom-20261119T104434914Z` fixed one backend per query
from the preceding cascade logs. Each route was the final backend
in both historical validated repetitions, indexed by the full query
hash. Four routes used symbolic execution and two used concrete
enumeration. A direct replay then measured the cost of using those
routes on fresh query checkers. The routing table was constructed
after observing historical results and serves as a local cost
diagnostic.

The archived first stages that returned unresolved took 1.085 s
and 1.096 s per batch. The new comparison reran the fixed cascade
and the direct replay in forward and reverse order under the same
18 s batch and 3 s request limits. All loading, lookups, execution,
validation, process replacement, and recovery were charged.

| Method | Verified queries | Batch elapsed time, first and second repetition |
| --- | ---: | ---: |
| Fixed symbolic-to-concrete fallback | 10/12 | 10.177 s, 8.848 s |
| Historical route replay | 12/12 | 6.018 s, 6.029 s |

The two added results came from the stb integer-log query. Its
direct concrete requests took 2.883 s and 2.876 s, leaving only
117 ms and 124 ms within their local deadlines. The cascade's
matching requests timed out, causing a backend replacement before
the next query. The cascade used two process launches per batch,
and the replay used one.

Observed batch savings were 4.159 s and 2.819 s. The first pair
included a 1.037 s difference in initial loading time. The remaining
elapsed-time differences after subtracting initial loading were
3.122 s and 2.835 s. These measurements include the downstream
cost of avoiding a request timeout and process replacement.

All 24 query records passed the result audit, including 1,549
canonical concrete observations and a separate check of 974 raw
cascade-stage observations. There were zero wrong decisions, late
admissions, unreaped workers, or address and length mismatches.
The local time-headroom criterion passed. The earlier 12/12
cascade result remains archived with its paired run.

The 117--124 ms request slack is a sizing estimate from two recorded
direct executions for acquisition triggered after a request starts.
Future routing evaluations use the fixed cascade as their primary
control. Shared acquisition completed before requests is charged once
to the batch clock, with its amortized cost reported. Acquisition
triggered inside a request also consumes its local deadline.
The present six programs remain development
cases. A routing rule is frozen before evaluation on disjoint
programs, and genuine type information is evaluated through the
same routing algorithm's input ablation before additional neural
modules are developed.

### Repeated sensitivity to added routing latency

`route-b-latency-sensitivity-20261119T111512335Z` repeated the fixed
cascade and historical route replay on the same six 256-input queries.
The replay injected 0, 50, 100, or 150 ms after each request started
and before route lookup. Each arm ran four times, alternating query
order and rotating method order. The 20 batches retained the 18 s
batch limit and 3 s request limit, including process costs.

| Method | Verified queries | stb integer-log query verified |
| --- | ---: | ---: |
| Fixed cascade | 21/24 | 1/4 |
| Historical route, 0 ms added | 23/24 | 3/4 |
| Historical route, 50 ms added | 24/24 | 4/4 |
| Historical route, 100 ms added | 24/24 | 4/4 |
| Historical route, 150 ms added | 22/24 | 2/4 |

All unresolved results belonged to the integer-log query. In one
repetition, zero-delay replay missed the deadline while all three
delayed replays completed the query. The 100 ms arm's smallest
remaining interval after reply reception was 11.7 ms. Its four
successes make 100 ms the highest all-success latency among the
tested points. The zero-delay failure and nonmonotonic paired
outcomes leave a stable latency guarantee unestablished.

Across the four paired batches, median savings over the cascade
were 1.984 s for zero-delay replay, 2.560 s for 50 ms, 2.212 s
for 100 ms, and 1.025 s for 150 ms. These elapsed-time observations
come from repeated known routes with injected delay. The earlier
117--124 ms slack remains a measurement of its two recorded runs.

All 120 query records passed the independent result and deadline
checks. The audit checked 9,557 canonical concrete observations
and separately matched 2,037 raw cascade-stage observations to
their references. It found zero wrong decisions, late admissions,
unreaped workers, or address and length mismatches. All 20 batches
completed within budget. These measurements characterize timing
sensitivity on six developer queries and support reporting repeated
costs alongside completion counts.

### Cooperative first-stage budget baseline

`route-b-capped-cascade-20261119T112436417Z` tested a fixed 100 ms
budget for the cascade's first symbolic attempt. The attempt clock
included checker construction and validation. An unresolved or
absent result triggered fresh concrete enumeration under the original
request deadline. The first-stage cutoff used the analyzer's existing
cooperative clock, while the parent enforced the 3 s request deadline.

The capped method, original cascade, and historical route replay each
ran four batches on the same six 256-input queries, alternating case
order and rotating method order. Each batch retained the 18 s limit,
including all loading, communication, execution, validation, process
replacement, and recovery.

| Method | Verified queries |
| --- | ---: |
| Original fixed cascade | 21/24 |
| Cooperative 100 ms first stage | 18/24 |
| Historical route replay | 23/24 |

The capped method added zero decisions and lost three paired successes
from the original cascade. Two losses were stb bit reversal and one
was the stb integer-log query. Its paired batch time increased by
a median of 2.903 s across the four repetitions.

The original cascade's bit-reversal symbolic attempts completed in
102--114 ms. All four capped versions ended near 100 ms with an
absent first-stage result, sending the query to concrete execution.
For utf8proc, the capped first attempts still took 925--937 ms.
Across all 24 measured capped stages, nine exceeded 101 ms and the
maximum was 937 ms. These observations distinguish the configured
cooperative budget from the time actually spent before fallback.

All 72 query records passed the result and deadline audit, including
5,256 canonical concrete observations. The audit found zero wrong
decisions, late admissions, unreaped workers, or address and length
mismatches. All 12 batches completed within their budgets. On this
development panel, a uniform short first-stage budget reduced
coverage and increased full-batch cost.

### Model-cache diagnosis and guarded enumeration

`route-b-deadline-diagnosis-20261119T113621347Z` isolated the utf8proc
overrun. With libraries already loaded, three 100 ms symbolic attempts
took 934, 865, and 860 ms. Checker construction took 7--8 ms. In a
representative instrumented run, cached-model constraint evaluation
accounted for 85% of cumulative profile time and the Z3 satisfiability
wrapper for 3%. Symbolic-address enumeration repeatedly rechecked
cached models. Instrumentation increased elapsed time, so the profiles
serve to locate the cost and unprofiled runs measure performance.

A query-local exact cacheless frontend reduced the three attempts to
256, 211, and 213 ms. Adding an absolute-deadline check at each model
enumeration callback reduced them to 100.3, 100.4, and 100.4 ms. The
regression retained the entry constraints, checked state copying,
restored the native solver scope after cancellation, and reused the
same backend successfully. The default, plain, and cacheless-only
negative controls all exceeded the regression's 200 ms allowance;
their failing assertions and original outputs are retained. The
experimental configuration uses angr and claripy 9.2.217 with
z3-solver 4.13.0.0. Installed packages and the project's core checker
were unchanged.

`route-b-guarded-cascade-20261119T114705852Z` then reran the original
cascade, ordinary capped cascade, and guarded version in four paired
repetitions on the same six 256-input developer queries. Query order
alternated and method order rotated. The 18 s batch and 3 s request
budgets included loading, communication, validation, execution, and
process replacement. The guarded version used the new frontend only
for its first symbolic attempt and retained the original concrete
fallback.

| Method | Verified queries | Unresolved queries |
| --- | ---: | ---: |
| Original fixed cascade | 20/24 | 4/24 |
| Cooperative 100 ms first stage | 18/24 | 6/24 |
| Guarded cacheless 100 ms first stage | 22/24 | 2/24 |

utf8proc's ordinary capped stages took 922--938 ms and its guarded
stages took 100--111 ms. Across all 24 guarded stages, the maximum
was 111 ms and twelve exceeded 101 ms. The checks remain cooperative
and provide no hard 100 ms wall-clock bound. The cacheless frontend
also raised libpng's first-stage cost from 68--80 ms to 101--104 ms,
sending those four requests to concrete fallback.

Compared with the original cascade, the guarded version added three
integer-log decisions and lost one bit-reversal decision. Its paired
batch savings were 0.268, -3.156, 0.358, and 0.254 s, with a median
of 0.261 s. The lost decision and slower second batch leave stable
coverage and cost dominance unestablished. These are configuration
diagnostics on the existing development panel; neural information
and held-out programs were not evaluated.

The independent audit checked all 72 query records, 165 source and
fixture hashes, 6,229 canonical concrete observations, and 9,020 raw
stage observations. It found zero wrong decisions, late admissions,
unreaped workers, or address and length mismatches. All 12 batches
finished within budget. Diagnostic profiles, negative controls,
regression scripts, the independent verifier, and both supplementary
assessments remain in the named D-drive experiment directories.

### Cache-preserving deadline checks

The preceding guarded version lost one bit-reversal result after a
100 ms symbolic cutoff, followed by a concrete timeout. That request
also paid approximately 1.8 s for a worker replacement. Separate
operation diagnostics in `route-b-cutoff-sensitivity-20261119T140610Z`
compared the default and cacheless frontends with libraries loaded
and a 1 s operation budget. Three repetitions gave bit-reversal
medians of 91 and 193 ms, respectively, and libpng medians of 70 and
131 ms. All twelve results passed the symbolic reference audit. The
planned full cacheless 150 ms comparison was superseded after these
measurements; its imported runner remains pinned diagnostic evidence.

`route-b-cache-preserving-20261119T141200Z` retained the default exact
composite frontend and its model cache. It added query-local deadline
checks before and after each cached-model constraint evaluation and
at native model-enumeration callbacks. The entry constraints were
unchanged. Regression tests exercised state copying, expired cached
reads, subsequent cached-read reuse, and the actual utf8proc overrun.
Three 100 ms utf8proc attempts returned unresolved in 127, 110, and
106 ms. These remain cooperative deadlines.

A second, separately paired operation diagnostic compared the default
and cache-preserving configurations. Their bit-reversal medians were
107 and 97 ms, and libpng medians were 77 and 87 ms. All twelve
results passed the reference audit. A timed-out symbolic attempt is
discarded and concrete fallback constructs a fresh checker. The
cached-read regression establishes recovery for its tested read
sequence; interrupted state mutations are outside that reuse claim.

Before the full comparison, the protocol fixed 100 and 150 ms first
stages, the original cascade control, four repetitions, alternating
query order, and rotating method order. It reused the same six
256-input queries with 18 s batch and 3 s request budgets. All
loading, communication, validation, execution, and worker replacement
costs were charged.

| Method | Verified queries | Paired median batch saving over original | Worker launches across four batches |
| --- | ---: | ---: | ---: |
| Original fixed cascade | 20/24 | Reference | 8 |
| Cache-preserving 100 ms first stage | 24/24 | 1.468 s | 4 |
| Cache-preserving 150 ms first stage | 23/24 | 2.066 s | 5 |

The 100 ms arm gained all four integer-log results and lost zero
original-cascade successes. Its batch savings were 1.530, 1.720,
1.406, and 1.258 s. All four bit-reversal symbolic stages still
ended at the cutoff; concrete fallback verified those queries.
Avoiding integer-log timeouts also avoided worker replacement in
every 100 ms batch. Its utf8proc stages took 102--110 ms, and its
maximum first-stage duration across all queries was 112 ms.

The 150 ms arm left one integer-log query unresolved. Three of its
four bit-reversal queries completed symbolically, contributing to
its lower batch time. The smallest integer-log reply slack in the
100 ms arm was 8.2 ms. The completion counts and timing tradeoff
leave a reliable latency guarantee and an optimal cutoff unestablished.

All 72 full-comparison records passed independent result and deadline
checks, covering 175 source and fixture hashes, 6,729 canonical concrete
observations, and 7,398 raw stage observations. There were zero wrong
decisions, late admissions, unreaped workers, or address and length
mismatches. The same-panel engineering criterion passed. The 100 ms
configuration is frozen as a non-neural development reference for a
future disjoint-program comparison. Its selection used known
development results. This experiment measured no neural information
value or held-out generalization, and the configuration remains local
to the recorded experimental stack. Installed packages and the core
checker were unchanged.

### Frozen cutoff test on six new projects

`route-b-project-disjoint-20261119T141817Z` tested the frozen
cache-preserving 100 ms configuration on six upstream projects
absent from every earlier Route B cohort. Selection, exact source
Git objects, function ranges, wrappers, 256-input domains, compiler
flags, budgets, and evaluation criteria were fixed before compilation
and timing. Each native executable's full domain was checked against
an independent mathematical projection. All six fixtures built and
all 1,536 native inputs passed.

| Project | Selected upstream function | Fixed cascade verified | Frozen 100 ms verified |
| --- | --- | ---: | ---: |
| Jansson | [`utf8_check_first`](https://github.com/akheron/jansson/blob/v2.14/src/utf.c) | 4/4 | 4/4 |
| cJSON | [`parse_hex4`](https://github.com/DaveGamble/cJSON/blob/v1.7.18/cJSON.c) | 4/4 | 4/4 |
| LZ4 | [`LZ4_NbCommonBytes`](https://github.com/lz4/lz4/blob/v1.9.4/lib/lz4.c) | 4/4 | 4/4 |
| bzip2 | [`BZ2_indexIntoF`](https://github.com/libarchive/bzip2/blob/bzip2-1.0.8/bzlib.c) | 0/4 | 0/4 |
| XZ | [`bsr32`](https://github.com/tukaani-project/xz/blob/v5.6.3/src/common/tuklib_integer.h) | 4/4 | 4/4 |
| Brotli | [`BrotliReverseBits`](https://github.com/google/brotli/blob/v1.1.0/c/enc/entropy_encode.c) | 4/4 | 4/4 |

The functions were carried in the existing freestanding AMD64 ELF
fixture format with a finite-input wrapper and marker write. Source
specializations were recorded before building: LZ4 used the target's
little-endian branch and a nonzero argument, XZ used the GCC intrinsic
branch with nonzero input, bzip2 used a fixed unit-frequency cumulative
table, and Brotli used an eight-bit width. This tests extracted
functions and their wrappers. All queries describe in-scope finite
domains, so the panel measures scheduling cost and completion.

Both methods ran four repetitions, alternating query order and
rotating method order, with the unchanged 18 s batch and 3 s request
budgets. Loading, communication, execution, validation, worker
replacement, and recovery were charged. The 100 ms allowance and
solver implementation were unchanged from the preceding freeze.

| Method | Verified queries | Unresolved queries | Batch elapsed seconds across four repetitions |
| --- | ---: | ---: | --- |
| Original fixed cascade | 20/24 | 4/24 | 9.617, 9.023, 9.058, 9.091 |
| Frozen cache-preserving 100 ms | 20/24 | 4/24 | 12.469, 12.526, 12.437, 12.571 |

There were zero paired gains and zero paired losses. Both methods
left all four bzip2 trials unresolved. The short-cutoff method added
2.852, 3.503, 3.379, and 3.479 s per paired batch, with a median
increase of 3.429 s. Both methods launched eight workers in total.

The original Jansson symbolic stages completed in 197--252 ms and
cJSON stages in 430--440 ms. The 100 ms cutoff interrupted those
attempts and sent the queries to concrete enumeration. Their full
request times became 1.358--1.405 s and 2.835--2.914 s, respectively.
LZ4 and XZ continued to complete symbolically, while both methods
used concrete enumeration for Brotli. The capped first-stage maximum
was 128 ms, consistent with cooperative checkpoint semantics.

The independent audit checked all 48 query records, 210 source and
fixture hashes, 4,096 canonical concrete observations, and 4,438 raw
stage observations. It found zero wrong decisions, late admissions,
unreaped workers, or address and length mismatches. All eight batches
finished within budget. No fixture was replaced and no parameter was
changed after observing the timing results.

The baseline-success preservation criterion passed. The predefined
coverage-transfer criterion required repeated gains in at least two
new projects; it failed with zero gains. The cost-transfer criterion
also failed because all four paired batches became slower. The
original fixed cascade remains the primary general control, with the
100 ms version retained as a sensitivity control. The earlier 24/24
development result remains scoped to its recorded panel. This
experiment evaluated no neural information and supports no claim
about complete applications or balanced detection quality.

### Prospective progress observation

`route-b-progress-observability-20261119T143409Z` collected live
progress from all twelve previously observed functions. Each ran
twice with phase events alone and twice with additional counters,
giving 48 records. Both modes used the same frozen cache-preserving
solver and a full 3 s request deadline. The producer's executable
AST was preserved, adding callbacks at three observation boundaries.
No routing policy or neural information was used.

The parent captured only events both emitted and actually received
before 100 ms from the operation-start event. Features contained
phase, instruction and transition counts, depth-frontier width,
scheduled future states, observed writes, and unsupported-condition
counts. Source identities, addresses, reference labels, and future
events were excluded. The later outcome proxy was a separately
validated symbolic result within 500 ms of operation start. It does
not measure the value of switching to concrete enumeration.

Both modes verified 16/24 runs and retained eight unresolved runs.
Thirteen phase-only runs and fifteen counter-mode runs reached the
checkpoint before finishing. All fifteen had previously received
counter packets; seven subsequently met the 500 ms proxy and eight
did not. The sixteen paired verified runs had a median added query
time of 0.764 ms and a maximum of 82.874 ms. There were zero paired
losses. The predefined median-overhead criterion passed, while the
maximum and two-repetition design limit stronger timing conclusions.

One counter view was shared by an LZ4 repetition that met the proxy
and four utf8proc/Brotli repetitions that did not: producer phase,
one completed transition, one executed instruction, one scheduled
state, and zero observed writes or unsupported conditions. Thus
these finite phase/counter features alone cannot perfectly separate
the recorded outcomes. No predictor or predictive accuracy was
evaluated. Packet ages ranged from 3.5 to 73.8 ms; publication at
5 ms intervals cannot keep counters fresh during a long operation.

All 48 records passed independent source, symbolic-reference, and
parent-receipt checks, covering 227 source and fixture hashes and
103 counter publications. Five workers were reaped. Worker readiness
and replacement took 1.75--2.28 s each and were retained separately
from the information-only query measurements. This experiment
establishes observability and a feature limitation on known cases.
It provides no end-to-end routing gain or held-out generalization
result. The next action-value comparison needs measured continuation
and switching costs under a shared checkpoint protocol.

### Actions from a shared resident checkpoint

`route-b-shared-checkpoint-20261119T144544Z-v2` measured two actions
from one resident producer prefix for each query. All twelve known
functions ran twice, yielding 24 shared prefixes and 48 action records.
The producer suspended once at the first safe execution boundary at
or after 100 ms, or returned candidate evidence before validation.
The continuation resumed that generator and its original validation;
the switching action initialized fresh concrete enumeration.

Both actions paid the same measured prefix and received the same
remaining portion of a 3 s budget. They executed serially. The
continuation clock excluded time spent executing its counterfactual
alternative. Eleven active-producer prefixes had unchanged retained
state digests across concrete execution. The other thirteen prefixes
already held candidate evidence. Actual prefix costs ranged from
31 to 945 ms, so the target checkpoint did not provide a hard 100 ms
response bound.

| Checkpoint phase | Continue preferred | Switch preferred | Both unresolved |
| --- | ---: | ---: | ---: |
| Producer returned, validation pending | 13 | 0 | 0 |
| Active producer | 3 | 6 | 2 |
| Total | 16 | 6 | 2 |

Continuation validated 16/24 actions and switching validated 22/24.
When both validated, the predefined preference required a cost margin
above the greater of 50 ms and 10% of the faster action. All sixteen
such pairs preferred continuation. Switching alone validated both
repetitions of the stb integer-log, utf8proc, and Brotli queries.
Both bzip2 pairs remained unresolved. Existing candidate evidence
therefore accounts for most continuation preferences; the active
producer subset contains both action preferences.

All 48 records passed independent shared-prefix, residual-budget,
receipt-time, and reference checks, covering 248 source and fixture
hashes and 5,806 concrete observations, including partial unresolved
attempts. There were zero wrong decisions or late admissions. An
initial run stopped on a logging helper's constant lookup error.
Its partial records were retained, and all 24 official pairs were
rerun after the lookup correction.

This is a resident-state counterfactual cost study. Worker loading,
audit hashing, between-action waiting, and final state destruction
remain outside the action clock and are retained in raw receipts.
Switching retains the symbolic state for the paired alternative.
Action order alternated across cases; each case used the same order
in both repetitions, leaving case-specific order effects uncontrolled.
Raw producer durations can include the other action's execution;
the separate action and prefix-plus-action measurements define costs.
No learned selector, neural input, held-out test, or deployment speedup
was evaluated. Continuing validation of existing evidence is a strong
structural control for the next selection study.

### Phase-only baseline replay

`route-b-phase-baseline-replay-20261119T145447Z` replayed the simple
rule suggested by the preceding development results: continue when
the producer has returned positive candidate evidence with at least
one path, and otherwise switch. The rule receives only phase,
candidate status, and path count. It chooses validation and never
treats an unvalidated candidate as a final conclusion. No function
identity, future action result, or reference label enters this rule.

The replay uses the existing 24 shared prefixes and 48 measured
actions. It sums actual prefix-plus-action costs, including unresolved
rows. These sums describe charged work rather than measured batch
wall time. A retrospective oracle selects the cheapest validated
action using future outcomes; when neither action validates, it
retains switching to avoid rewarding cheap unresolved work.

| Replay policy | Verified queries | Aggregate charged work |
| --- | ---: | ---: |
| Always continue | 16/24 | 10.767 s |
| Always switch | 22/24 | 39.409 s |
| Continue candidate validation, otherwise switch | 22/24 | 26.337 s |
| Retrospective oracle reference | 22/24 | 20.399 s |

The phase rule and switching control resolve the same query set.
The phase rule saves 13.072 s of aggregate charged work. Its remaining
observed oracle opportunity is 5.938 s, concentrated in two cJSON
prefixes and one Jansson prefix. Both actions validate in these three
cases, but continuation costs less. Their measured margins are
2.396, 2.330, and 1.212 s.

Spread across all 24 queries, that remaining opportunity is about
247 ms per query, or 540 ms across the eleven active-producer
queries. These are retrospective sizing estimates from two
repetitions. They provide no reliable acquisition budget. Model
inference, mapping, feature collection, and scheduling would consume
part of this opportunity, and the inherited startup and cleanup
exclusions remain.

An independent audit matched all 96 replay selections to the 24 raw
prefixes and 48 action receipts, including the feature capsule
available before either action. The rule was chosen after observing
the development pattern. It requires prospective evaluation as a
baseline; no live policy, neural information, or held-out performance
was measured here.

### Live phase rule with charged cleanup

`route-b-live-phase-rule-20261119T150054Z` executed the unchanged
phase rule with three controls: always continue, always switch,
and the original uncapped symbolic-to-concrete cascade. The twelve
known functions formed two six-query groups. Each method ran twice
per group, reversing query order and rotating method order, for
16 batches and 96 planned query records. Selection used only phase,
candidate status, and path count from the resident checkpoint.

Each query retained its original absolute 3 s admission deadline
inside an 18 s cold batch. The selected action ran once. Switching
closed the paused generator and collected discarded state before
fresh concrete execution. All methods performed final garbage
collection before publishing a reply. Construction, checkpoint
waiting, selection, validation, communication, startup, replacement,
and recovery were charged to the parent clocks. The cascade used
the same exact cache-preserving solver without the checkpoint rule.

| Live method | Verified queries | Unresolved queries |
| --- | ---: | ---: |
| Always continue | 16/24 | 8/24 |
| Always switch | 12/24 | 12/24 |
| Frozen phase rule | 19/24 | 5/24 |
| Original fixed cascade | 20/24 | 4/24 |

The phase rule gained seven paired results over always-switch,
lost none, and saved a paired median 4.486 s per batch. All four
paired batches were faster. Its predefined advantage criterion
passed against that control.

Against the original cascade, the phase rule added zero decisions
and lost one cJSON result. It added a paired median 1.148 s per
batch and was faster in only two of four paired batches. The
criterion failed against the stronger control. In the lost cJSON
trial, concrete execution reached final cleanup shortly before the
request deadline; cleanup prevented timely reply admission. The
cascade's matching symbolic request completed in 494 ms.

This live comparison therefore did not establish an advantage over
the original cascade. The replay's aggregate charged-work savings
remain scoped to its resident-state ledger. Actual cleanup and
timeout-induced replacements affected live completion and cost.
The original cascade remains the primary general baseline; the
phase rule remains a structural comparison arm.

The independent audit checked all 96 query records, 72 checkpoint
choices, 266 source and fixture hashes, and 9,355 raw concrete
observations. It verified unchanged absolute deadlines, cleanup
before admitted replies, and the reference evidence. There were
zero wrong decisions, late admissions, unreaped workers, or address
and length mismatches. All 16 batches completed within budget.
These are fresh executions of previously observed functions with
two repetitions per method. No held-out policy generalization or
neural information was evaluated.

### Strong-baseline headroom and neural input eligibility

`route-b-strong-baseline-feasibility-20261119T151028Z` audited the
96 live records before adding another model. The union of admitted
successes across all four methods equals the original cascade's
20/24. None of the observed alternative methods validated an
additional baseline-unresolved query. This describes the recorded
methods and does not rule out other scheduling policies.

Selecting the fastest recorded whole-batch configuration while
preserving each cascade batch's exact success set saves only
0.081 s across the four batch pairs. This retrospective portfolio
uses future outcomes and provides no deployable or reliable timing
advantage. Query times from different batch histories were not
stitched into a synthetic batch time.

In the cascade's four successfully validated concrete fallbacks,
the preceding unsuccessful symbolic intervals total 2.443 s.
They belong to the two utf8proc and two Brotli repetitions. This
trace-local amount excludes cleanup and replacement savings. It
averages 102 ms across all 24 query trials or 611 ms across those
four selected fallbacks. Removing these intervals assumes unchanged
subsequent execution and cache effects; it is a sizing estimate,
not measured net benefit or a hard acquisition allowance. One
unresolved integer-log trial had an internal concrete result before
the deadline, but cleanup prevented parent admission. It remains
unresolved in every reported coverage count.

The input audit also found that all twelve timing ELFs have zero
section-table offsets and zero section counts. They cannot supply
standard DWARF section lookup to the current integration, whose
documented variable locator requires DWARF. This is an integration
eligibility result; the underlying model's capability was not tested.
No inference was attempted. The historical one-probe WSL profile
reported 5.154 s cold acquisition, 1.055 s median graph generation,
and 91 ms median forward time. Its different input and runtime
provide context only. Matched costs for these twelve inputs and a
warm-service cost remain unmeasured.

The next input gate is to compile a native debug ELF once and derive
its metadata-stripped twin, check identical executable code and
instruction addresses, validate location-to-use-site correspondence,
and document the DWARF-assisted identity path. Reference type labels
must remain outside prediction inputs. Baseline and acquisition
timings must then be measured on that matched pair. Earlier timing
numbers cannot be carried over to newly compiled code. Variant E
remains deferred until actual neural information and its net cost
have been evaluated.

An independent audit rechecked the coverage sets, all four symbolic
intervals, and all twelve ELF headers. This step performed no new
solver workload, model inference, or held-out evaluation.

### Native debug/stripped input preparation

`scripts/prepare_native_query_pairs.py` builds native ELF input
pairs from a frozen source/reference manifest. It compiles each
debug ELF once with `-O1 -g -gdwarf-4`, derives a fully stripped twin,
and compares allocated code/data sections and load addresses. It
also checks all 256 native outputs against the existing reference
and extracts the marker-write query from the new binary.

`route-b-native-pairs-20261119T151706Z` contains twelve prepared
source/reference inputs. Only their conditional native self-check
loops use the expanded input domains. Preprocessing the analysis
programs without `CHECK_NATIVE` was identical for all twelve cases.
The manifest pins the builder and every source/reference file.

Host-side checks on an existing Linux debug ELF passed after actual
stripping, rejected a changed executable byte, and verified entry
argument bindings for three existing optimized functions. These
checks validate the inspection path; they do not constitute the
twelve new native builds. The user subsequently completed the native
build in WSL as `native-20261119T153127809228Z`. All twelve pairs,
3,072 native outputs, and twelve entry-argument bindings passed an
independent host-side recheck. GCC 9.4.0, strip 2.34, Python 3.10.20,
pyelftools 0.32, and Capstone 5.0.6 were recorded. No model inference
or new baseline timing was performed by this input gate.

From this workspace's repository root in WSL:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/prepare_native_query_pairs.py --manifest ../.scratch/selective_analysis/route-b-native-pairs-20261119T151706Z/source-manifest.json
```

The builder uses existing GCC, strip, pyelftools, and Capstone,
creates a unique D-drive output directory, retains failures, and
removes intermediate native executables. It performs no installation,
download, model inference, or baseline timing. The reported binding
covers the formal argument and its first register read only. Full
def-use and final-property correspondence still need separate checks.

### Two-function native neural probe

`scripts/probe_native_pair_tygr.py` prepares guarded acquisition on
the cJSON and Brotli debug twins. The two known functions represent
branching parsing and read-only table access. The existing isolated
TYGR runtime and frozen model are reused. The child receives neither
property queries nor reference type labels. Its original input guard,
raw logits, location-adapter trace, source identities, and cold
parent-observed acquisition time are retained.

The parent checks every recorded location trace against an independent
DWARF projection and revalidates the saved model's input domains.
Entry correspondence requires a unique target-function `x` record
whose register-5 location covers the verified first input read.
Missing or ambiguous bindings remain failures. Raw scores are
uncalibrated logits. Full use-site mapping and scheduling benefit
are outside this probe.

Preparation on the native input pair directory passed source and
model identity checks. A retained real acquisition also passed the
new logit/input recheck, while a deliberately nonmatching entry-use
address was rejected. The user then ran the two-function probe as
`neural-probe-20261119T154521513447Z`. cJSON produced genuine logits
and one independently verified entry binding. Its cold parent
acquisition took 10.742 s, including diagnostic capture. Brotli was
refused before any forward: its inverse-left-shift relation is
`18 + 30 = 48`, beyond the saved layers' 44 relation slots. The
checkpoint's preprocessing declares 60 relations, while upstream
model code hardcodes 44. The DWARF adapter recorded no errors.

`neural-domain-audit-20261119T165842213953Z` rechecked cJSON's full
raw logits and entry binding, reproduced the Brotli guard refusal,
and confirmed the prior input/source/model identities. It archives
the original parent script before the diagnostic improvements.
No evidence currently supports a lossless relation remapping.
The guard, checkpoint, upstream source, and original run artifacts
remain unchanged. The original two-case result is 1/2 usable;
the incompatible case remains in the coverage denominator.

The parent now preserves the child's root error and records the
unsupported relation IDs and graph edges. `--remaining` checks the
other ten cases in frozen manifest order without rerunning cJSON
or Brotli. It snapshots the parent and child implementations and
retains every failure. This is a coverage audit of known development
functions, not a new held-out test or a scheduler evaluation.
From the WSL repository root:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/probe_native_pair_tygr.py --pairs ../.scratch/selective_analysis/route-b-native-pairs-20261119T151706Z/native-20261119T153127809228Z --remaining
```

The parent uses `angr-env`; acquisition runs in the existing
`tygr-orig` subprocess. No installation, download, training, or
GPU is required. Capture overhead is included, so these diagnostic
acquisition costs provide no warm-service or deployment estimate.

### Twelve-function neural coverage audit

The user completed the other ten functions in
`neural-probe-20261119T170204866609Z`. Six have genuine target
output and verified entry bindings. Combined with the original
cJSON/Brotli probe, the fixed twelve-case denominator contains
seven usable entry predictions and five pre-forward refusals.
All five refusals concern saved relation-domain limits; no failed
function attempted model execution. Neither run reported changed
sources or inputs.

| Usable entry predictions | Unsupported model inputs and observed relation IDs |
| --- | --- |
| stb ilog threshold, miniz Adler, utf8proc, libpng, cJSON, LZ4, bzip2 | xxHash: 54; stb bit reversal: 51; Jansson: 44, 50; XZ: 50, 55; Brotli: 48 |

`neural-coverage-audit-20261119T170856232495Z` independently
revalidated all successful raw logits and entry mappings, replayed
all input guard refusals, checked debug/stripped identities, and
retained the original twelve-case denominator. It also found
exactly equal complete 75-class entry-logit rows for utf8proc
and LZ4. Their actual model-input tensors differ. This equality
concerns the entry readout, not complete program representations,
all possible variables, or the full scheduler features. Earlier
backend outcomes were measured on different binaries and are not
transferred to these new native inputs.

### Matched native baseline cost gate

`scripts/measure_native_pair_baseline.py` reuses the frozen
cache-preserving symbolic-to-concrete cascade on the complete
twelve-case native panel. The protocol has three repetitions,
six batches of six queries, a 3 s request budget inside an 18 s
batch budget, and the unchanged 50 ms cleanup reserve. Group
and query orders change across repetitions. Worker startup,
transport, checking, validation, state discard, final cleanup,
and recovery are charged to the parent batch clocks. Offline
evidence re-audit time is recorded separately.

The timing intake contains queries only. Neural availability is
used solely for parent-side cost reporting, retaining all seven
available and five unavailable cases. The baseline does not
rank operations using model output. Recorded pre-fallback elapsed
work is descriptive opportunity, not achieved savings or a hard
bound on another policy's benefit. The historical cold model
captures are not a matched warm-service estimate.

The preparation check retained 36 planned records. A single
miniz query passed actual Windows execution and offline evidence
validation as `route-b-native-baseline-20261119T171211117842Z`;
this is a compatibility smoke, not official matched timing.
The new runtime pins its installed solver implementations and
records versions, rather than treating the historical Windows
library hashes as the WSL environment. Official timing must run
in WSL `angr-env` using:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/measure_native_pair_baseline.py --pairs ../.scratch/selective_analysis/route-b-native-pairs-20261119T151706Z/native-20261119T153127809228Z
```

Outputs and process files remain on the D mount. The existing
local coverage audit is required. No new model inference,
training, neural policy evaluation, or Variant E implementation
is part of this collection.

The first WSL launch, `route-b-native-baseline-20261119T171508397563Z`,
failed before any timed batch. The archived bootstrap indexed a
Windows-keyed hash dictionary using a WSL path. The new
`unique_d_dictionary_keys_v1` adapter wraps only that archived JSON
reader while its callers bootstrap. It resolves a unique equivalent
`D:\...` or `/mnt/d/...` dictionary key and rejects ambiguous aliases.
Stored keys, path values, digests, archived source bytes, and analysis
operations are preserved. The same adapter is installed in the
parent and each fresh backend worker, and its revision and source
identity are recorded in the new plan.

`route-b-native-path-fix-20261119T172108208860Z` retains the
verification report and a fresh-worker harness. The actual archived
import chain failed under foreign-style keys before the fix and
passed after it. A newly spawned backend also reached readiness
and exited cleanly under the foreign-key test. Wrong recorded
hashes remain rejected. Twenty-three targeted tests passed, and
`route-b-native-baseline-20261119T172019170248Z` passed the revised
one-case Windows execution smoke. These checks fix portability;
they do not supply the still-pending official WSL timings.

### Official native baseline results

`route-b-native-baseline-20261119T172319633114Z` completed the
official WSL run with Python 3.10.20 and angr 9.2.212. The cascade
resolved 30/36 trials, with six unknowns and no wrong decisions,
late admissions, unreaped workers, or batch-budget failures. All
twelve functions were retained. The two unknown functions, stb ilog
and bzip2, each remained unknown in all three repetitions. Of the
seven functions with genuine entry predictions, five resolved;
all five without usable predictions resolved. These subsets have
different workloads and are not treatment/control comparisons.

`independent-audit.json` in that output rechecks all 36 records,
379 workspace artifact hashes, all reply and cleanup clocks, and
2,152 concrete observations, including partial timed-out runs.
The three WSL runtime-library source hashes were retained by the
collector and not independently reread from Windows.

The event-level cost review changes how request times should be
interpreted:

| Function | Observed stage behavior |
| --- | --- |
| stb ilog | Symbolic analysis returned unknown, then concrete enumeration started. Each timeout retained 204--207 of the 256 input observations. |
| bzip2 | The symbolic producer was still active at the request deadline; no concrete enumeration started. |
| miniz, XZ | About 1.94 s of each 2.1 s request was before the operation opened, largely replacement-worker loading after the preceding timeout. The remaining request tails were about 0.17 s. |
| utf8proc | Concrete fallback resolved all three trials; pre-fallback elapsed work was about 1.09 s per trial. This is not measured routing savings. |
| LZ4 | The symbolic arm resolved each query cheaply, despite its entry logits equaling utf8proc's. Full scheduler features are not asserted equal. |

The original summary's `fallback_trials` counts final policy-choice
receipts. It misses the started but unfinished stb ilog fallbacks.
Likewise, a parent-side default backend on an unknown row is not
evidence that the backend executed. The independent audit derives
actual attempts from nested producer-start events and preserves the
original summary rather than rewriting it.

### Direct concrete control comparison

`scripts/compare_native_backends.py` compares two fixed strategies:
the unchanged symbolic-to-concrete cascade and immediate exact
concrete enumeration. Both arms use the same frozen producers,
checkers, input contracts, process transport and cleanup, with 3 s
request and 18 s batch budgets. Each of the twelve known functions
runs three times per arm. Arm order is counterbalanced within each
group/repetition pair, yielding twelve batches and 72 records.
All cases remain included regardless of neural availability.

The new report distinguishes finalized choices, actual fallback
starts, unfinished fallbacks, and pre-operation waiting. It reports
paired completion gains/losses and batch costs. This tests whether
the cheaper routing alternative can actually finish under budget;
it does not evaluate a neural selector or assume that avoiding a
symbolic prefix necessarily saves time.

Preparation retained all 72 records. Both controls passed a real
one-case Windows smoke as
`route-b-native-backend-controls-20261119T173134245853Z`, with no
correctness or timing-admission errors; this is not official WSL
comparison evidence. Twenty-five targeted tests passed. Run the
formal comparison in WSL `angr-env`:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/compare_native_backends.py --baseline ../.scratch/selective_analysis/route-b-native-baseline-20261119T172319633114Z
```

The prior run is preserved, and fresh cascade/control pairs are
collected under the same runtime rather than comparing control
costs with the historical Windows measurements. No new model
inference, model training, or Variant E work is included.

### Official native control results

`route-b-native-backend-controls-20261119T173351971091Z` completed
the WSL comparison with Python 3.10.20 and angr 9.2.212. Across
the same twelve known functions and three repetitions per arm,
the cascade resolved 30/36 queries and direct concrete execution
resolved 11/36. Direct execution gained no completion and lost
nineteen paired completions. The cascade was faster in all six
paired batches, with a median batch saving of 6.833 s. No wrong
decisions, late admissions, unreaped workers, or batch overruns
were recorded. These are repeats of twelve functions, not 72
independent programs or a neural experiment.

The retained `verify.py` independently checked all 72 records,
384 workspace artifact hashes, 8,536 complete or partial concrete
observations, producer attempts, admission/cleanup clocks, paired
completion sets and batch costs. Three runtime-library hashes were
retained at collection rather than independently reread from Windows.
Two workers were correctly killed and reaped before reaching readiness
when their request windows could no longer accommodate startup.

The direct arm's unknowns show deadline propagation across queries:

| Observed condition | Direct unknowns | Paired losses against the cascade |
| --- | ---: | ---: |
| Producer started after more than 1 s of pre-operation waiting | 17 | 16 |
| Producer did not start | 2 | 2 |
| Producer started without that long wait, but request timed out | 6 | 1 |

The one-second threshold is a post hoc descriptive grouping of
receipts, not a selection feature or causal estimate. Replacement
loading often consumed about two seconds of a three-second request.
This reduced time for the next query, sometimes causing further
timeouts and replacements. The global result is valid for the frozen
charged-batch protocol. It does not establish that direct execution
is intrinsically slower on every query. In particular, utf8proc and
Brotli completed in direct trials with an already ready worker,
while many of their losses followed earlier query timeouts.

The cascade remains the deployment baseline. Neither stb ilog nor
bzip2 gained a completion from the direct control, and no neural
value has been measured. Before implementing another scheduler,
the next useful diagnostic is an equal-budget local action matrix:
confirm worker readiness before each action's 3 s deadline, preserve
the complete twelve-query denominator, and record cold startup,
replacement and total diagnostic cost separately. Such a matrix
would study local action capability and cost; it would not remove
those costs from deployment accounting or overturn the batch result.

### Local action-value matrix

`scripts/measure_native_local_actions.py` prepares the next local
capability/cost diagnostic. It reuses the exact backend worker from
the global control comparison. Each action receives a fresh process;
the parent waits for its readiness marker before opening a new 3 s
absolute action deadline. A previous timeout therefore cannot spend
the next action's allowance on replacement loading. Query-specific
initialization, transport, checking, validation and worker-side
cleanup remain inside the action clock.

The same twelve query contracts and both fixed strategies are retained,
with three repetitions per strategy and balanced first-arm order within
each query/repetition pair. The formal schedule has 72 actions. It
introduces no model calls, new query examples, labels in the worker,
learned routing, or Variant E implementation.

The collection records readiness and reply timestamps, startup time,
action time, parent termination/reaping time, and the full diagnostic
wall time. The per-action ledger must equal startup plus action plus
recovery. Late or mismatched replies cannot resolve a query. Pending
transport payloads are retained in the receipt before their temporary
files are removed, after the producer is reaped. Logs, raw action
records and a paired `matrix.json` are retained on D. Offline evidence
re-audit time is reported separately.

Twenty-eight targeted tests passed, including a delayed-readiness
transport test, rejection of late results, and startup-failure recovery.
Both real one-case host actions passed as
`route-b-native-local-actions-20261119T174703111696Z`. Their distinct
worker PIDs, full post-readiness allowances, cleanup/admission clocks
and cost ledgers passed independent checks. An additional host bzip2
probe timed out at 3 s and was reaped successfully; its diagnostic
receipt is retained in the preparation output and is outside the
formal schedule. These are host compatibility checks, not WSL results.

Run the formal collection from the WSL repository root:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/measure_native_local_actions.py --controls ../.scratch/selective_analysis/route-b-native-backend-controls-20261119T173351971091Z
```

This matrix studies local action value after readiness. It has no 18 s
global batch clock, and cold startup is recorded outside each local
allowance rather than being treated as free deployment work. Neither
the original batch comparison nor end-to-end cost accounting is
replaced. Formal WSL results and any neural benefit remain pending.

### Official local action results

`route-b-native-local-actions-20261119T175040812102Z` completed the
WSL collection with Python 3.10.20 and angr 9.2.212. The cascade
resolved 30/36 actions and direct concrete execution resolved 27/36.
The direct arm gained no completions and lost the three cJSON trials.
Both strategies left stb ilog and bzip2 unresolved. All twelve known
functions and all 72 fresh-worker actions were retained.

| Function | Cascade median action time | Direct median action time | Observed preference |
| --- | ---: | ---: | --- |
| utf8proc | 2.556 s | 1.462 s | Direct was faster in all three pairs |
| LZ4 | 0.197 s | 1.810 s | Cascade was faster in all three pairs |
| Brotli | 2.206 s | 1.888 s | Direct was faster in all three pairs |
| cJSON | 0.619 s, 3/3 resolved | 3.000 s, 0/3 resolved | Cascade preserved completion |

The remaining six mutually resolved functions also favored the
cascade. No wrong decisions, infrastructure failures, late admissions,
unreaped workers or audit disagreements were recorded. Cold startup
totaled 150.262 s and parent recovery 0.844 s; both remain explicit
costs outside the local action allowances. The full diagnostic took
282.265 s including setup, recording and offline re-audit. None of
these local comparisons is an end-to-end speedup claim.

The retained `verify.py` rechecked 72 distinct worker identities,
389 workspace artifact hashes, 10,582 complete or partial concrete
observations, readiness before every 3 s allowance, result admission,
matrix entries and all startup/action/recovery ledgers. Three WSL
runtime-library source hashes were retained by the collector rather
than independently reread from Windows.

### Local information assessment

The retained `assess_information.py` joins the verified local matrix
with the existing guarded neural exports, without new model calls.
The only stable direct-time winners are utf8proc and Brotli. Brotli
has no usable prediction under the frozen model domain. utf8proc
and LZ4 have identical complete entry-logit rows but opposite stable
local preferences.

Their raw input arrays differ in ordering. Exhaustive correspondence
on the three encoded nodes found permutation `[1, 2, 0]` from utf8proc
to LZ4, preserving all 31 node features, all four directed relation
edges with multiplicity, and variable gather/scatter membership.
The resulting rooted model inputs are the same up to ordering, not
merely equal Top-1 labels. Their native graphs contain only the two
register-location/data edge kinds. The current representation does
not retain the task distinction needed for this pair. This identifies
an input-information issue before classifier-head or policy tuning;
the stage at which information is lost has not yet been established.

A post hoc replay choosing the faster successful action separately
for each observed pair exposes 4.248 s of local opportunity across
all three repetitions, of which 3.303 s lies on neural-available
cases. This is not a universal bound, expected utility, a deployable
policy, or a measurement of acquisition-inclusive savings.

An optimistic type-output-only replay grouped equal full mean
75-class logits, preserved completion count first, and then minimized
observed action time. It retained the cascade for every available
feature group. When this equal-output pair is switched together,
the LZ4 penalty exceeds the utf8proc saving. Wholly unresolved groups
retain the baseline without a saving claim. This descriptive result
does not test generalization or exclude interactions with structural
features. It supplies no incremental neural-value evidence here.

The next recommended task is a focused input-graph coverage audit
on this pair: compare execution capture, pre/post-splicing graphs
and feature encoding against the query-relevant instructions. More
timing repetitions, a learned scheduler, or Variant E should wait
until the representation retains a useful distinction. No checkpoint,
guard, upstream source or frozen experiment has been changed by
this assessment.

### Input-graph stage audit

`scripts/audit_native_graph_stages.py` prepares observation of the
existing utf8proc/LZ4 pair in the original TYGR environment. The
standalone Python 3.8 worker is `scripts/capture_tygr_graph_stages.py`.
No new examples, property checks, timing comparisons, type predictions,
training or repairs are included. The frozen checkpoint is loaded only
for its preprocessing configuration, and all module forwards are blocked.

The observer delegates to the original methods once, retains their
return values and exceptions, and restores method bindings afterwards.
It records block instruction lists, returned-state action histories,
step exceptions caught by the original executor, fields left by the
original register/memory read hooks, full graphs before splicing,
retained graphs and normalization mappings, and the original feature
encoding at both graph stages. Observation errors invalidate capture;
they are not allowed to masquerade as subject step exceptions.

The parent independently decodes each native function and records its
write address separately from the acquisition request. It compares
location traces with an offline DWARF projection, checks the saved
model input domain, and requires the final collated batch to agree
with the retained original input under feature/relation/readout
correspondence. Query metadata is not supplied to the original graph
generator. Graph annotation addresses can be block addresses, so
they are not treated as exact use-site mappings.

Static source review found four hypotheses requiring runtime evidence:

- The original block executor catches step exceptions and returns the
  state reached so far, potentially producing a partial graph.
- Read hooks assign `register_read_expr` and `memory_read_expr`; their
  registration and actual values must be inspected in angr 9.0.7491.
  Differences observed in the host's angr 9.2.217 are not confirmation
  about the old runtime or proof of a causal effect.
- Variable-seeded splicing removes disconnected nodes. Missing
  dependencies can therefore originate before the splice itself.
- Coarse node features may merge differences surviving graph creation.

Thirty targeted tests passed, including single-delegation and method
restoration under failure, preservation of original hook fields, and
rooted input correspondence rejecting changed relations or readout.
The preparation checks validated Python 3.8 worker and Python 3.10
parent syntax, strict original request identities, static function
decoding and passive graph-snapshot replay. The old-runtime capture
has not yet run. The source, model and guard remain unchanged.

Run this bounded two-function capture from the WSL repository root:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/audit_native_graph_stages.py --local-actions ../.scratch/selective_analysis/route-b-native-local-actions-20261119T175040812102Z
```

The parent invokes the existing `tygr-orig` Python subprocess and
keeps its requests, source snapshots, raw observations, failures
and logs on D. No package installation or GPU is needed. Encodings
of pre-splicing graphs are diagnostic views, not inputs admitted
to the saved model. A changed final graph is rejected rather than
silently counted as evidence about the historical pipeline.

### Confirmed graph-stage observations

`route-b-graph-stages-20261119T183301641855Z` completed both captures
in the original Python 3.8 / angr 9.0.7491 / torch 1.8.1 environment.
No model forward was attempted, no observer or location error was
recorded, and neither executor recorded a step exception. Both
function histories contain the query's target memory write. Partial
execution caused by a caught step exception therefore does not explain
this pair's collision.

| Stage | utf8proc | LZ4 |
| --- | ---: | ---: |
| Full graph before variable splicing | 25 nodes | 297 nodes |
| Retained variable graph | 3 nodes | 3 nodes |
| Nodes removed | 22 | 294 |
| Target write present in execution history | Yes | Yes |
| Final batch exactly matches original export | Yes | Yes |

The full graphs contain memory and arithmetic relations, including
distinct operation sets. After splicing, both contain only `reg_loc`
and `reg_data`. The recorded normalization mapping reproduces exactly
the union of each seed's ancestors, descendants and the seed itself;
retained labels and encoded features are unchanged. The observed
distinction disappears in the selected-variable view before the final
encoder. This observation alone does not make directed splicing
incorrect. The parameter seed has no directed path to or from the
target-PC memory nodes in the full graph. LZ4's full graph is weakly
connected, which does not establish that directed dependency.

The original runtime's inspection registry contains `reg_read_expr`
and `mem_read_expr`, and does not contain `register_read_expr` or
`memory_read_expr`. Original read-hook observations show a symbolic
read annotation assigned to the long-form field. The actual first
RDI-read action remains an unannotated concrete zero in each function.
This confirms an interface mismatch consistent with missing parameter
propagation. It is not yet a causal intervention proving that renaming
the fields alone, without changing event timing, restores the graph.

The retained `verify.py` and `independent-audit.json` recheck both
captures, 90 unique workspace artifact hashes, location projections,
zero forward attempts, target-write actions, retained graph mappings,
pre/post feature consistency, and exact historical batch equality.
The old runtime inspection module's hash is retained; its file was
not independently reread from Windows.

A full-graph bypass is not an admitted inference fix. LZ4's
pre-splice encoding contains relations 50 and 55, exceeding the
checkpoint's 44 saved relation slots. The guard remains unchanged.
The next recommended experiment is a bounded no-forward hook
comparison: original behavior, corrected expression field names,
and corrected names with read-event timing. Report restored directed
dependencies and saved-model compatibility independently, retaining
the original behavior as control. The earlier scheduling results are
evidence about the historical pipeline, not a refutation of the broader
neural-guidance question. No source or checkpoint repair has been made.

### Controlled read-hook comparison

The controlled experiment is implemented by `scripts/compare_tygr_read_hooks.py`.
It reuses the two reviewed graph-stage inputs, their independent location
projections and their static instructions. Each function/variant runs in a
fresh original TYGR Python subprocess. There are six captures, without new
programs or model forwards.

| Arm | Expression handling | Read-event timing |
| --- | --- | --- |
| `original` | Original callbacks and fields | Original BEFORE |
| `field_names_before` | Call each original read hook once, then route a freshly created long-form expression to the registered short field | Original BEFORE |
| `field_names_after` | The same fresh-expression routing | Move only the matching register/memory read breakpoints to AFTER |

The external adapter leaves the original long-form aliases in place; this
is a routing intervention, not an upstream source rename. An ignored read
must not route a stale expression from a previous callback. The timing
intervention preserves all write hooks. Context managers restore the
original methods even when the experiment fails. The observer retains its
historical `fields_after_original_hook` key: for intervention arms this
field contains observations after the active wrapped hook.

Run from the project directory in WSL:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/compare_tygr_read_hooks.py --graph-stages ../.scratch/selective_analysis/route-b-graph-stages-20261119T183301641855Z
```

The `--prepare-only` option checks preparation without launching TYGR.
Its host validation prepared all six requests and checked the original
strict binary, model, helper and source identities. Twenty-one targeted
tests passed, covering real host inspection reads, exact callback
delegation, ignored/stale values, write-event isolation, restoration on
failure, and input-guard replay. Four host API deprecation warnings do not
validate or invalidate the older runtime; the actual intervention results
below come from a separate WSL collection.

Interpret the results in this order:

1. The original arm must reproduce both historical native batches. Failed
   captures, step exceptions and observer errors remain in the records.
2. Compare pre/post graph sizes, actual target-write actions and directed
   seed-to-target-PC memory reachability across arms. This establishes
   local graph behavior, not complete use-site correspondence or property
   validity.
3. Read `saved_model_guard` separately. The original guard runs unchanged
   and the parent independently replays its receipt. An incompatible graph
   can be captured for diagnosis, but its rejection never admits inference.
   No edges are deleted or remapped, and no weights are modified.
4. Even a restored dependency with a passed tensor guard leaves training
   distribution compatibility, prediction quality, acquisition cost and
   scheduling benefit untested. No model forward is allowed in this gate.

All requests, source snapshots, raw captures, logs, exceptions and guard
rejections remain under D-drive scratch. Existing executed evidence and
upstream TYGR files are preserved. Variant E remains deferred until these
results and checkpoint compatibility are reviewed.

### Confirmed read-hook intervention results

`route-b-read-hook-controls-20261119T191220997252Z` completed all six
original-runtime captures, with no forward attempts, observer errors,
location errors or step exceptions. Every history contains the target
write. A separate retained `verify.py` rechecked all six raw captures and
99 unique workspace artifact hashes. The audit also reconstructs splice
memberships/edges and retained features, checks first argument-read
annotations, and replays the unchanged input guard.

| Function | Arm | Retained nodes | Diagnostic parameter-to-target-PC memory path | Saved tensor guard |
| --- | --- | ---: | --- | --- |
| utf8proc | Original | 3 | Absent | Passed |
| utf8proc | Field routing / BEFORE | 3 | Absent | Passed |
| utf8proc | Field routing / AFTER | 17 | Present | Passed |
| LZ4 | Original | 3 | Absent | Passed |
| LZ4 | Field routing / BEFORE | 3 | Absent | Passed |
| LZ4 | Field routing / AFTER | 221 | Present | Refused: IDs 50, 55 |

The original and field-only batches are exactly equal within each
function. Moving the corrected read hooks to AFTER changes the first RDI
read from an unannotated concrete zero to a symbolic value carrying
`RegisterReadAnnotation`. The diagnostic paths then appear in both full
graphs and their endpoints survive variable splicing. These observations
establish a timing effect conditional on corrected field routing for this
pair. They do not test timing alone, establish general correctness of the
intervention, or show a complete use-site/property proof.

The old equivalent-input finding therefore concerns the historical
acquisition pipeline. It cannot establish that suitably extracted neural
type information lacks value. Equally, larger non-equivalent graphs alone
are not evidence that predictions or scheduling will improve.

The restored LZ4 graph contains inverse `If` and equality relations, which
the unchanged guard refuses. The checkpoint's literal metadata was read
passively with `zipfile` and `pickletools`, without unpickling objects or
importing torch. Its saved `all_ops` list matches the original source's
`REDUCED_OPS`. `If` is index 20 and `Eq` index 25, and the saved inverse
offset is 30: their inverse IDs are 50 and 55. The checkpoint also stores
60 declared edge IDs and `edge_dim=44`. The audit preserves pickle byte
offsets for these scalar observations.

This stored schema/capacity discrepancy does not identify the historical
training relation mapping or prove how unsupported edges were handled
during training. In particular, expanding layers, aliasing IDs or dropping
edges would introduce a different model/input policy rather than validate
the existing checkpoint. A tensor-guard pass for utf8proc likewise does not
validate the changed graph against the training distribution.

In each restored capture, `x` remains the one original DWARF variable but
now has two flattened value-node readouts. Subsequent prediction export
must preserve the variable-to-value membership; the two rows must not be
reported as separate source variables or treated as independent cases.

The next task is to establish relation-schema provenance and a justified
compatible-checkpoint path. A paired neural-output experiment remains
blocked for the restored inputs under the current guard. There is no new
prediction, property decision, held-out evaluation, scheduling measurement
or neural-benefit result in this gate. Original sources, weights and
historical results remain unchanged; Variant E is deferred.

### Relation-schema provenance and runtime check

`scripts/audit_relation_schema.py` separates three questions: what the
checkpoint declares and stores, what the installed operator does, and what
mapping was used during training. They must not be inferred from one
another. The existing input guard remains unchanged in all cases.

Host preparation in `route-b-relation-schema-20261119T192634266587Z`
passed the strict frozen-checkpoint hash and passive metadata parser.
All eight relation coefficient matrices have shape `[44, 10]`, matching
their saved capacity of 44. The saved 29-operation list equals the current
source list; adding the unknown kind gives 30 kinds per direction and 60
declared IDs. All sixteen out-of-capacity IDs, 44 through 59, are inverse
relations under that mapping.

| Restored input | Directed relation entries | Outside saved capacity | Breakdown |
| --- | ---: | ---: | --- |
| utf8proc | 36 | 0 | None |
| LZ4 | 574 | 196 | Inverse `If`: 130; inverse `Eq`: 66 |

These counts describe prepared tensors, not messages observed to be
ignored by a running layer. The historical input views each have four
directed relation entries, all inside the saved capacity.

The shallow upstream checkout has 24 model paths in its Git tree, but
only the frozen x64 O0 base model is materialized locally. The x64
O1/O2/O3 base objects are missing. Local availability checks use
`GIT_NO_LAZY_FETCH=1` and `protocol.allow=never`; no download occurs.
Neither this inventory nor the saved vocabulary proves the historical
training mapping.

Run the combined collection from the project directory in WSL:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/audit_relation_schema.py --hook-controls ../.scratch/selective_analysis/route-b-read-hook-controls-20261119T191220997252Z
```

The `--prepare-only` option performs the passive and local provenance
steps without importing a neural framework or launching the old runtime.
Twelve targeted tests passed, including the actual passive checkpoint
contract and interpretation controls. The standalone worker has Python
3.8-compatible syntax and uses the existing `tygr-orig` environment.

The runtime worker retains the installed `rgcn_conv.py`, constructor
signature, forward/message source and dependency versions. It constructs
one independent CPU RGCN with two feature channels, 44 relation slots and
10 bases. Its known artificial weights are fixed, with zero root and bias
terms. Eleven calls cover an empty graph, valid IDs 0/43, both directions
with valid IDs, negative and out-of-capacity IDs, and valid/unsupported
mixed inputs. Inputs and parameters are checked for mutation. The trained
checkpoint is never loaded or forwarded.

`runtime_interpretation` reports whether unsupported single edges raise
an error or produce zero/nonzero messages, and whether adding an
unsupported reverse edge changes a valid-only result. Failed positive
controls block interpretation. Outcomes describe this installed operator
branch on artificial inputs; they do not reproduce full-model inference,
establish training behavior, justify relation aliasing or authorize an
input-guard bypass. A compatible checkpoint path still needs independent
justification before paired neural experiments. All artifacts remain on D.

### Confirmed installed-operator behavior

`route-b-relation-schema-20261119T192837627552Z` completed the eleven
artificial-parameter CPU checks in Python 3.8, torch 1.8.1+cpu and PyG
1.7.0, with torch-scatter 2.0.6 and torch-sparse 0.6.9. The pretrained
checkpoint was not loaded or forwarded. Positive/empty controls passed.

| Synthetic input | Observed output |
| --- | --- |
| No edges | Zero, with root and bias terms disabled numerically |
| One edge, ID 0 or 43 | Nonzero expected message at its destination |
| Two valid opposite edges, IDs 0 and 43 | Nonzero messages at both destinations |
| One edge, ID -1, 44, 50, 55 or 59 | Exactly the empty-graph output |
| Valid edge plus opposite edge with ID 50 or 55 | Exactly the valid-edge-only output |

The saved `RGCNConv.forward` source iterates over
`range(self.num_relations)`, using
`masked_edge_index(edge_index, edge_type == i)` for each relation. The
examined dense-feature, basis-decomposed path therefore selects only IDs
0 through 43 when configured with 44 relations. Root and bias operations
occur separately. The synthetic observations and source inspection agree:
out-of-capacity edges produce no relation messages in this path instead
of raising an index error.

The separate retained `verify.py` checks 112 unique workspace artifact
hashes, all numerical controls, saved source excerpts against the retained
module, the relation-loop/mask structure, all eight coefficient capacities,
and all six observed relation histograms. It does not import a neural
framework or execute more layer calls. The original Linux module was not
reread from Windows; its retained copy matches its recorded source hash.

This refines the meaning of checkpoint incompatibility. The unchanged
input guard refuses the restored LZ4 input. Without that refusal, the
installed source implies that its 130 inverse-`If` and 66 inverse-`Eq`
entries would not be selected for relation messages in the examined path.
That conditional inference is not a frozen-model output measurement.
Valid relation messages, node features, root transforms and readout
computations would still exist; the whole graph or prediction is not
claimed to become zero.

The result neither proves that historical training silently omitted the
same relations nor validates a relation remapping or guard bypass. It
also does not measure type accuracy or scheduling benefit. The earlier
equivalent-input finding remains a result of the historical extraction
pipeline, while improved extraction introduces a separate input/model
compatibility problem.

The next bounded task is to inspect the alternative upstream x64 base
checkpoint metadata before committing to retraining. A candidate needs
compatible operations, feature/readout semantics and all active layer
capacities, plus immutable identity and provenance. Structural admission
would still need prediction validation on independently separated data.
If no candidate satisfies those requirements, training a complete
60-relation model with the corrected extraction pipeline is a distinct
follow-up design, not an expansion of the current frozen weights.
The twelve diagnostic kernels are not a training set. No further timing
or Variant E work is justified by this operator audit alone.

### Alternative x64 base checkpoint audit

`route-b-candidate-checkpoints-20261119T193458001Z` contains a completed
static audit of the remaining three x64 base checkpoints at upstream
commit `280320129a7f8bbfb9ee61b9a2155d2ddeac44c6`. A separate filtered
bare cache was cloned over SSH. Only the pinned O1/O2/O3 model blobs were
materialized for this audit; the current TYGR checkout and its O0 model
were preserved.

| Model | Declared relation IDs | Active layer capacities | Ordered 75-type vocabulary versus O0 | Complete-domain requirement |
| --- | ---: | --- | --- | --- |
| x64 O0 base, existing reference | 60 | Eight layers, 44 each | Reference | Blocked |
| x64 O1 base | 60 | Eight layers, 44 each | Identical | Blocked |
| x64 O2 base | 60 | Eight layers, 44 each | Identical | Blocked |
| x64 O3 base | 60 | Eight layers, 44 each | Identical | Blocked |

The acquired SHA-256 identities are retained in `summary.json` and the
individual metadata files. Each raw file is 6,053,463 bytes. Git blob
identities are `144ca81c1ea5f1f4890aece85023deaa91ec2df2` (O1),
`e4586768fede82fb20d46d8c5fa669c220d0bf30` (O2) and
`aed246d12379ac1f3493a1eb97ed0f49a6a99260` (O3).

The new `src/selective_analysis/candidate_checkpoint.py` inspects these
explicitly pinned candidate identities using the existing bounded
symbolic-pickle parser. It checks storage descriptors and parameter shapes
without decompressing tensor arrays or resolving any pickle constructor.
Its canonical vocabulary description preserves class names, arguments,
state and type order. Equal output-class counts alone do not pass that
comparison. `scripts/audit_candidate_checkpoints.py` records acquisition,
source snapshots and candidate assessments. Neither the original frozen
reader's hash gate nor the production input guard is relaxed. A hypothetical
`metadata_candidate` result would still leave inference admission false.

Twenty-two targeted tests passed. The actual O0 file produced the same
saved configurations and parameter shapes under the candidate inspector
and original frozen reader, with tensor member reads prohibited by the
test. Other checks cover Git blob identity, symbolic constructor handling,
ordered vocabularies, insufficient single-layer capacity and incomplete
configuration agreement.

The separate retained `verify.py` reconstructs the commit/tree/blob
identity chain and independently rechecks 24 candidate coefficient
matrices and all ordered type entries. It imports no neural framework
and runs no model. Minimal Git object proofs, raw model blobs, fetch logs,
metadata and source snapshots are retained. The duplicate bare download
cache was removed after proof archival, freeing 16,773,588 bytes; verification
passes without that cache. This cleanup preserves the raw audit evidence.

For acquisition reproduction, first create a fresh isolated cache under
D-drive scratch, then run the audit. The cache HEAD must resolve to the
pinned commit and its origin must match the stated SSH repository; the
auditor fails if either identity differs.

```bash
mkdir -p ../.scratch/selective_analysis/candidate-checkpoint-audit
git clone --bare --filter=blob:none --single-branch --no-tags --depth 1 git@github.com:sefcom/TYGR.git ../.scratch/selective_analysis/candidate-checkpoint-audit/upstream.git
python -B scripts/audit_candidate_checkpoints.py --output ../.scratch/selective_analysis/candidate-checkpoint-audit --fetch
```

`--fetch` authorizes the three pinned model-object acquisitions; omitting
it permits only locally available objects and disables network protocols.
The runner uses system OpenSSH directly on Windows. The isolated initial
clone must likewise use the user's functioning SSH configuration. Use a
new output directory rather than replacing an executed source snapshot.

This audit rules out switching among these optimization-level checkpoints
as a complete-domain fix. It does not audit other architectures, structure
models, later commits or all historical releases, and it does not establish
historical training semantics or neural scheduling value.

The next research step is data/type-label readiness before committing to
replacement-model training. The pinned twelve source wrappers all declare
`benchmark_step(uint64_t x)`, as recorded with their source hashes in
`existing-panel-type-observation.json`. That is a statement about entry
declarations, not a full use-site oracle or a proof that type-score
distributions cannot encode context. Keep those kernels as known
integration/cost regressions. Select independent project data with useful
label coverage, group compiler variants by source project, validate
corrected graph/readout correspondence, and separate training, development
and information-value evaluation. Only then assess a small 60-relation
training run and the same-scheduler comparison. No training or Variant E
implementation is part of the current audit.

### Independent type-corpus readiness

`route-b-type-corpus-20261119T195435581328Z` contains six new small C
source projects for a bounded data-readiness exercise. Selection and
project-family splits were written before label extraction or training.
Known diagnostic project families are excluded by the selection policy;
the earlier twelve kernels remain separate regression inputs.

| Project | Fixed commit | Role |
| --- | --- | --- |
| [inih](https://github.com/benhoyt/inih) | `18d8e283993c752731d31176241f9da136454789` | Train |
| [rxi/map](https://github.com/rxi/map) | `d6c355fcfb35e5bf71905c0c28ccee34694b4a95` | Train |
| [jsmn](https://github.com/zserge/jsmn) | `25647e692c7906b96ffd2b05ca54c097948e879c` | Train |
| [optparse](https://github.com/skeeto/optparse) | `a86877ed301d89a4eb64feb08f23af395aede2ed` | Development |
| [utf8.h](https://github.com/sheredom/utf8.h) | `be0931a737ae7f0548fe27e40bf229111cc96b6d` | Evaluation |
| [b64.c](https://github.com/jwerle/b64.c) | `b263049874ae9ca7e2f146500939ed95aed4d4ee` | Evaluation |

`selection.json` freezes the assignments, `manifest.json` pins selected
sources and label-rule implementations, and `source-records.json` retains
SSH origins, commits and license evidence. Sources remain outside Git on
D. No source interface is replaced with a uniform scalar wrapper. A
header-only translation unit contains only the upstream implementation
macro, if required, and include directive. A separate trivial `main`
permits linking and is excluded from function/variable counts.

The new path does not consume `src/type_recovery/dataset.py`'s all-zero
placeholder node labels. It follows real DWARF type references and applies
the original pinned TYGR pure-Python conversion rules and 75-label
normalizer. Selected unchanged class/function definitions execute with
deferred annotations; no torch/angr package or trained checkpoint is
loaded. Missing references, unsupported encodings and upstream conversion
gaps produce explicit `unmapped` records. Raw conversion labels and their
normalized class IDs are retained. A real normalized generic `type` label
is distinguished from a missing/unmapped label.

This step inventories original variables, without implementing the
upstream struct-member location expansion. Location-attribute presence
is reported separately and does not prove a usable location range, IR
use-site or GNN readout. These labels must never become inference input
features or scheduling signals; labels belong to dataset supervision and
offline evaluation only.

Run from the project directory in WSL using the existing environment:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/build_type_corpus.py --corpus ../.scratch/selective_analysis/route-b-type-corpus-v2-20261119T220534466210Z
```

The runner uses native gcc to build O0/O1, x86-64, DWARF4 ELF profiles
with inlining disabled and original source interfaces preserved. It
records compiler identity, exact commands, build failures, binary hashes,
source-owned functions, mapped/unmapped variables, and located-variable
attribute counts. The O0 profile defines the primary label denominator;
O1 measures retention and is not another independent sample. The compiler
variants remain in their original project split.

It also fingerprints source function bodies while accounting for comments,
quoted strings and nested braces. Cross-split exact-body and
identifier-normalized matches with at least twelve body tokens are
reported for review, without silently dropping them. Missing fingerprints
are counted. This is conservative clone screening, not proof that all
copied algorithms or small boilerplate have been identified. Source
project/fork lineage still matters.

Thirteen targeted tests passed, including a genuine retained ELF label
read, exact signed/unsigned character rules, arrays/pointers, missing
upstream conversion support, type cycles, family isolation and renamed
body matches. The independent `verify.py` confirmed all six source commits,
selected code/notice hashes, exact compiler-input bytes, and project
assignments. It compares source text to commit blobs modulo CRLF while
pinning the actual worktree bytes exactly. No identical selected source
file crosses a split. All six MinGW syntax preflights passed; this does not
establish Linux link success or type coverage. Portable preparation is
retained in `labels-20261119T195613724911Z` and collected no new labels.

The initial native inventory and v2 correction are recorded below. Reports retain
`training_allowed=false`: graph/variable/value-row correspondence,
architecture encoding and complete relation processing remain separate
requirements. Label imbalance, unsupported/unseen classes and clone
review results will determine the next data work. Do not reshuffle
projects after seeing evaluation outcomes or treat six projects as a
formal generalization study. No training, model inference, property
verification, scheduling or Variant E implementation occurs in this step.

### Type-corpus v2 link-recipe correction

The first WSL run, `labels-20261119T220108266544Z` under the original
source bundle, completed ten of twelve profiles. inih, rxi/map, jsmn,
optparse and utf8.h completed at O0/O1. Their primary O0 total is 85
functions and 368 mapped variables; those results and original failures
are preserved. The initial zero clone-review groups covers those five
projects only, not a complete six-project result.

Both b64 profiles failed to link. The logs report missing definitions of
`b64_buf_malloc` and `b64_buf_realloc`. The original recipe selected
`encode.c` and `decode.c` but omitted their dependency `buffer.c`; the
same pinned upstream project's Makefile includes `buffer.o`. The host
syntax preflight had no linker stage and therefore missed the omission.

The corrected preparer includes all three source files. A regression
using the actual upstream sources and host gcc first reproduced the
missing-symbol failure, then linked successfully with the corrected
recipe. All fourteen corpus tests pass. The test does not execute the
linked program or establish native Linux inventory completion.

`route-b-type-corpus-v2-20261119T220534466210Z` is a new, versioned
manifest over the original checkouts. Its manifest and `revision.json`
retain the old manifest/run hashes, missing-file cause, added source SHA-256 and Git
blob identity. The added buffer file is
`cc4e366c450611d2f7a035950f807ef0a127bbe540476dd2ad89020703554c51`
and Git blob `2d684ee1bad0a952134b80fc7630f24e60fb79f5`. No project,
commit, partition, label converter, build flag or original source text
is replaced. Header bridges, link-only harness and selection bytes are
copied unchanged. The old source snapshots and failed run remain intact;
current preparer code intentionally differs from the old captured version.

Portable v2 preparation passed in `labels-20261119T220617608602Z`.
The WSL command above now targets v2 and is the next complete native
inventory; its completed result is recorded below. `training_allowed=false`
is still intentional: fixing source
closure does not validate graph/value readouts or establish model
performance. No model, training or scheduling result is produced here.

### Completed v2 type inventory

`route-b-type-corpus-v2-20261119T220534466210Z/labels-20261119T220848049235Z`
completed all twelve O0/O1 profiles, including both repaired b64 builds.
The retained `verify.py` independently replays the full ELF/DWARF
function/variable inventories on the host, checking binary identities,
source ownership, class mappings, location-attribute presence, exact
commands, source hashes, histogram aggregation and clone-screen results.
Its replay imports no neural framework and performs no new compilation,
model execution or symbolic graph extraction.

| Partition | Projects | O0 functions | O0 source-variable records | Observed normalized classes |
| --- | ---: | ---: | ---: | ---: |
| Train | 3 | 28 | 135 | 11 |
| Development | 1 | 15 | 55 | 8 |
| Evaluation | 2 | 47 | 201 | 11 |
| Total | 6 | 90 | 391 | 13 in the union |

All 391 O0 records mapped under the pinned whole-variable conversion
rules. The declared vocabulary remains 75; thirteen observed classes
does not establish 75-class coverage or useful GNN readouts. The
development/evaluation `i32*` class is absent from training, as is the
evaluation-only `u64*`. These coverage gaps are retained as facts rather
than repaired by moving evaluation data into training.

The corresponding O1 profiles retain 391 mapped variable records but
only 387 location attributes, versus 391 at O0. Those attributes are not
proofs of usable location expressions, instruction-level correspondence
or matching variable/value-node rows. Structure-member expansion remains
outside this whole-variable inventory. O1 variants remain attached to
their source projects and are not counted as extra independent examples.

The source-body screen reports zero cross-split review groups and zero
unavailable fingerprints across the ninety primary functions. Its earlier
minimum-token and normalization limitations still apply; this is not
proof that every shared algorithm or lineage relationship is absent.

The following mapping-engineering panel is frozen before graph outcomes:

| Project / partition | Selected O0 function | Pointer variable | Scalar variable |
| --- | --- | --- | --- |
| inih / train | `ini_find_chars_or_comment` | `chars` | `was_space` |
| rxi/map / train | `map_hash` | `str` | `hash` |
| jsmn / train | `jsmn_alloc_token` | `parser` | `num_tokens` |
| optparse / development | `optparse_error` | `data` | `p` |

The common selection rule requires at most eight inventoried variables,
at most 256 source-body tokens, and a located pointer/scalar pair. It uses
lowest source line/name ordering for functions and formal-parameter,
name/offset ordering for variables. This yields four functions and eight
selected variable DIEs from training/development only. Evaluation projects
are not used for mapping-strategy engineering.

`mapping-probe-plan.json` holds binary identities, function addresses and
selected DIE offsets without class labels. Gold review records are in
the separate `mapping-probe-offline-labels.json` and must not enter graph
features, model inference or policy inputs. Both the full ninety-function
denominator and unselected variables remain retained. The small panel is
an engineering scope, not model performance evidence or a training set.

This closes the compilation/label-inventory issue. The remaining technical
requirement is corrected graph and variable/value-readout validation;
limited project/class coverage additionally restricts future research
claims. `training_allowed=false` remains intentional. No GNN information
gain, property-checking improvement or Variant E result has been measured.

### Fixed variable-mapping collector

The frozen four-function/eight-variable panel is now implemented by
`scripts/run_type_mapping.py`, `scripts/capture_type_mapping.py` and
`src/selective_analysis/variable_mapping.py`. Portable preparation is
retained in `route-b-type-mapping-20261119T222853346909Z`. No actual
original-runtime graphs were collected by that preparation.

The independent ELF reader checks each function identity and DWARF4
frame base, then confirms entry CFA = RSP + 8 from the FDE. Each selected
variable currently has a single fixed CFA-relative expression:

| Function | Variable | CFA offset |
| --- | --- | ---: |
| `ini_find_chars_or_comment` | `chars` | -48 |
| `ini_find_chars_or_comment` | `was_space` | -20 |
| `map_hash` | `str` | -40 |
| `map_hash` | `hash` | -20 |
| `jsmn_alloc_token` | `parser` | -40 |
| `jsmn_alloc_token` | `num_tokens` | -56 |
| `optparse_error` | `data` | -56 |
| `optparse_error` | `p` | -28 |

No reference type attribute is used for the independent location facts.
Optimized location lists and non-CFA expressions are outside this first
bounded panel. The worker requests contain no offline class labels or
expected node IDs. The original DWARF-assisted enumerator still uses its
native variable/type metadata, including its normal struct-member logic;
this is not a claim of stripped-only or type-independent enumeration.
No gold output is passed into the feature preprocessor or collator.

Run from the project directory in WSL:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/run_type_mapping.py --inventory ../.scratch/selective_analysis/route-b-type-corpus-v2-20261119T220534466210Z/labels-20261119T220848049235Z
```

Each function runs in a fresh existing `tygr-orig` subprocess with a
120-second limit. The only selected projects are the fixed train and
development inputs. Capture delegates to original graph generation and
records original location-lookup results, step exceptions, action
histories, splice mappings and actual preprocessing/readout tensors.
Missing function results and worker failures keep their logs and remain
in the four-function/eight-variable denominator.

This new data pipeline uses the registered expression fields at AFTER
read events and replaces the generator's literal `arch` token with
explicit `x64`, justified by the checked ELF machine. It constructs the
original preprocessing configuration directly: 31 features, 75 target
classes, 60 declared directed relations and flattened value readouts.
No pretrained model is instantiated. Weight loading and neural module
calls are denied, and original sources are hashed before and after.
The frozen 44-slot checkpoint guard is unchanged and is not used as
admission for these fresh full-domain data.

The parent computes each configured stack address as initial RSP + 8 +
the independently decoded CFA offset. It reconstructs matching `mem_loc`
edges within the location's half-open PC interval and compares that set
with the actual upstream lookup. It then checks retained node identities
and edges, variable-to-normalized-node membership, flattened row groups,
gather/scatter indices, node/feature-row ordering and x64 feature encoding.
Source variables, value nodes and flattened rows remain distinct axes.
Unresolved mappings retain explicit reasons; data are not zero-filled,
relabeled or silently removed to pass these checks.

Twenty-six targeted tests passed, including the eight real retained
locations and corruption cases for slots, lifetimes, readouts, node
replacement, row order, architecture, relation IDs and step exceptions.
The hook and original observer tests also passed. Four host deprecation
warnings reflect the legacy inspection API used by the old runtime.
Worker Python 3.8 syntax and four prepared request identities were checked.
The subsequent original-runtime mapping observations are recorded below.

Even a consistent result establishes location/topology/readout
correspondence only within the observed partial execution and declared
pipeline. It does not prove exact value equivalence on all program paths
or full semantic use-site correctness. It also does not validate the other
383 source-variable records or admit training automatically. No evaluation
project, property checker, neural inference, training or scheduling runs
in this collector.

### Confirmed four-function mapping results

`route-b-type-mapping-20261119T223020304246Z` completed all four fixed
captures, with all eight selected variables passing the recorded
location/topology/readout correspondence checks. Every capture has aligned
node/feature rows and gather/scatter groups, no step exceptions, and no
observer or location errors. Weight-load and neural-forward attempts
remain zero. Original sources were checked unchanged.

| Project | Retained graph nodes | All retained source variables | All value readout rows | Selected variables | Selected value rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| inih | 136 | 3 | 35 | 2 | 18 |
| rxi/map | 110 | 2 | 18 | 2 | 18 |
| jsmn | 133 | 4 | 27 | 2 | 14 |
| optparse | 305 | 5 | 69 | 2 | 30 |
| Total | 684 | 14 | 149 | 8 | 80 |

The separate `verify.py` and `independent-audit.json` recheck 102 unique
workspace artifact hashes, the independent CFA facts, actual upstream
lookups, the exact ancestor/descendant splice membership and induced
edges, retained node labels, architecture encoding, relation endpoints
and all flattened variable/readout groups. Selected variable node sets
are disjoint within each function. The host review imports no neural
framework and performs no further graph execution or model calls.

The original literal `arch` token is replaced with `x64` in this declared
data pipeline; all actual feature rows contain the matching architecture
one-hot prefix. Native preprocessing retains all IDs in its declared
60-relation vocabulary. This remains fresh data preparation, not an
inference admission or successful forward of the old 44-slot checkpoint.

Eighty selected value rows represent eight source variables. The larger
149-row capture contains fourteen source variables, not 149 independent
examples. A later dataset must preserve source-variable and source-project
grouping rather than allowing multi-value variables or compiler variants
to inflate the independent sample denominator.

These observations establish the checked correspondence in the recorded
partial, concretized execution. They do not establish all-path value
equivalence, full semantic use-site correctness, complete-corpus label
admission, model accuracy or neural scheduling benefit. Evaluation projects
remain untouched and training remains disabled.

`next-export-inputs.json` freezes the next data scope: the 43 O0
train/development functions and 190 candidate source-variable records.
It selects no evaluation projects and contains no per-variable class
labels. Subsequent export must report graph/label availability and every
failure or exclusion, and must account explicitly for structured-member
supervision versus the earlier whole-variable inventory. This scope is
not a claim that all 190 variables are admissible. Training or Variant E
should not be inferred from the successful eight-variable check.

### Bulk train/development graph export

`scripts/export_type_graph_dataset.py` consumes the fixed 43-function scope in
the reviewed mapping directory. It selects all 28 training functions and all
15 development functions, with 135 and 55 candidate source variables respectively.
It does not select the two evaluation projects. Run from the repository root:

```bash
conda activate angr-env
python -B scripts/export_type_graph_dataset.py \
  --mapping /mnt/d/AI_Models/symbolic/.scratch/selective_analysis/route-b-type-mapping-20261119T223020304246Z
```

Portable preparation adds `--prepare-only`. Preparation and collection both
write only beneath the D-drive `.scratch/selective_analysis/` directory.
Collection uses the existing Python 3.8 `tygr-orig` interpreter, one function
per child process with a 120-second timeout. Each function prints progress and
retains its request, independent offline source facts, raw capture, log and
review result. Failures do not remove functions from the denominator.

The child is the unchanged model-free worker used for the four-function audit.
It never receives the offline label inventory. The parent joins each eligible
source DIE to a fixed CFA location, actual lookup membership and normalized
value readout rows before attaching its independently inventoried type label.
Whole structs are excluded: the upstream enumerator can expand them into
member variables, which require separate supervision provenance. No whole-struct
class is assigned to member rows. Other unsupported locations, graph contract
errors, execution-step exceptions, duplicate source claims to one row and
conflicting source labels on shared graph values remain explicit exclusions.

Each successful function has separate `features.json` and `supervision.json`
artifacts. Features contain the finite 31-column x64 matrix, full-domain
60-relation edges and value-node readouts. Targets contain admitted source DIE
identities, class IDs and corresponding row groups. Each variable's row weights
sum to one, so a variable with many values does not automatically dominate the
loss. Labels are not feature inputs. `dataset.json` pins the per-function files;
`records.json` preserves all function/variable exclusions and timings;
`summary.json` reports functions, source variables, value rows and observed
classes separately by split. Timings describe data export, not deployment cost.

Host preparation checked all 43 function frames: 188 variables have reviewable
fixed-CFA locations and two whole structs are excluded. This does not predict
graph/readout availability. Thirty-nine targeted tests passed with four legacy
inspection warnings, including recovery of all eight previously reviewed real
source targets and their 80 value rows. Bulk graph collection is still pending.
Training remains disabled until the resulting coverage and artifact identities
are reviewed. The small corpus supports a minimal feasibility training run after
that review, not a generalization claim. It does not admit the frozen 44-slot
checkpoint, establish all-path semantic use-site mapping or demonstrate neural
scheduling benefit.

### Completed bulk graph export

`route-b-type-graphs-20261119T225215150614Z` retained all 43 planned
functions in its accounting and admitted 41 to the dataset. A separate
`verify_export.py` pass rechecked 317 hashes, independent source-label joins,
actual lookup/graph membership, feature and relation tensors, row ownership,
unit source-variable weights and split histograms without importing a neural
framework or executing graphs/models.

| Split | Admitted functions | Admitted source variables | Supervised value rows |
| --- | ---: | ---: | ---: |
| Training | 26 | 129 | 1,998 |
| Development | 15 | 52 | 813 |
| Total | 41 | 181 | 2,811 |

Nine of the 190 candidate source variables remain excluded. The failure
of `ini_parse_string` is a node/feature ordering mismatch; `map_iter_`
returns no selected graph. Other exclusions concern whole-struct supervision
or absent/ambiguous location membership. No exclusion was filled with a
synthetic class or moved across a split. Training covers ten classes and
development seven; development's two `i32*` targets are absent from training.
Value rows and random-seed repetitions are not independent source samples.

### Minimal full-relation training pilot

The next executable is `scripts/train_type_graph_pilot.py`. Its input is the
completed graph-export directory, including the passive review. Preparation
verifies every reviewed artifact again. The new run plan admits exploratory
pilot training explicitly; it leaves historical raw summaries and disabled
training flags unchanged. Evaluation projects remain sealed.

```bash
conda activate angr-env
python -B scripts/train_type_graph_pilot.py \
  --dataset /mnt/d/AI_Models/symbolic/.scratch/selective_analysis/route-b-type-graphs-20261119T225215150614Z
```

Add `--prepare-only` for portable data/configuration verification without Torch.
Add `--smoke-only` for a two-epoch, one-seed integration run instead of the fixed
full pilot. No package installation, original TYGR imports, pretrained weights,
API calls or GPU are required. All generated files remain on the D drive.
The existing WSL `angr-env` has the needed CPU Torch/PyG runtime.

The fixed full pilot uses hidden width 64, two RGCN layers, eight bases,
60 directed relations, 75 class outputs, Adam at 0.003, gradient clipping at
one and 30 epochs. Seeds are 17, 29 and 43. Each seed trains two arms with
identical initial parameters: normal graph messages and messages disabled.
The latter retains the same model structure and root transformations, serving
as a node-feature ablation. A training-only smoothed frequency prior is a
separate baseline. No hyperparameter search or best-development checkpoint
selection occurs; the checkpoint is always the fixed final epoch.

Disjoint function graphs form one full training batch. Readout-row logits are
averaged back to each reviewed source variable before cross-entropy, giving
one loss term per variable. The four neural input arguments contain features,
edges, relation IDs and readout nodes only. The correspondence pooling map
contains row grouping, while gold class IDs remain outside the model inputs.
The evaluation includes all 52 development variables and separately reports
the two whose classes were unseen in training. Source-variable Top-1, Top-3,
NLL and explicitly labeled class-average metrics are recorded for every seed.
The frequency prior's development Top-1 is 11/52 and Top-3 is 47/52.

Before fitting, a controlled runtime check requires relation 59 to propagate
and receive gradients; invalid IDs -1 and 60 must raise. Checkpoints store new
state dictionaries and configuration. Each is reloaded into a fresh instance
and must reproduce all exported raw scores exactly. `predictions.json` exports
all 75 actual source-variable scores and their Top-3 ranks. These scores are
uncalibrated mean logits. They are not a recovered probability distribution.

Host preparation and 38 targeted tests passed on Windows, where one neural
runtime test is skipped because the Windows Torch DLL cannot initialize. The
neural path was then executed in WSL `angr-env` (Python 3.10, Torch 2.11 CPU,
PyG 2.7); see the next section. This small corpus is a training-pipeline
feasibility panel with one development project, not a formal generalization
benchmark or evidence of neural scheduling gain.

### Training pilot results

The WSL smoke run (`route-b-type-training-20261120T191305623359Z`, seed 17,
two epochs) and the fixed full pilot
(`route-b-type-training-20261120T191335375352Z`, three seeds, 30 epochs, both
arms) completed. In both, relation 59 propagated a controlled message and
received a gradient, IDs -1 and 60 were rejected, both arms of each seed began
from the same parameter digest with 81,739 parameters, losses and scores stayed
finite, parameters changed and every reloaded checkpoint reproduced its
exported scores exactly. Pinned sources and the reviewed dataset were unchanged
after the run. No evaluation project was executed. The full pilot took about
75 s on one CPU thread.

Development results use all 52 source variables at the fixed final epoch:

| Arm | Seed 17 | Seed 29 | Seed 43 |
| --- | --- | --- | --- |
| Frequency prior | Top-1 11, Top-3 47, NLL 2.21 | same | same |
| Graph messages | Top-1 28, Top-3 49, NLL 1.57 | Top-1 25, Top-3 48, NLL 1.95 | Top-1 28, Top-3 49, NLL 1.89 |
| Messages disabled | Top-1 25, Top-3 47, NLL 1.91 | Top-1 25, Top-3 48, NLL 1.90 | Top-1 25, Top-3 48, NLL 1.78 |

Both unseen-class `i32*` variables are wrong in every run. The paired graph
minus no-message Top-1 differences are +3, 0 and +3 variables; development NLL
does not consistently favor the graph arm. These are repetitions on one
development project, so the difference is not evidence of a reliable message
effect, and type accuracy is not a scheduling result.

### Coverage and representation diagnosis

`scripts/analyze_type_pilot_coverage.py` is a passive follow-up. It loads no
neural framework and reads the reviewed dataset plus the full pilot's
`predictions.json`. Output: `route-b-type-coverage-20261120T192024747568Z`.

- **The models behave as a bit-width classifier.** Every run predicts all
  14 development `i32` as `i32` and all 64-bit variables as `struct*`. That
  covers 20-22 of 22 `char*`, both `i32*` and, in five of six runs, the
  `void**`. The
  no-message arm reaches exactly 25/52 (all `i32` plus all `struct*`) in
  every seed.
- **Readout node features carry little beyond width.** For every 64-bit class
  (`char*`, `struct*`, `void*`, `u64`, `void**`), 92-99% of readout-row mass
  has the same TYGR feature signature: 64-bit, concretized zero value,
  `is_very_small`, `is_small`, `has_addr`. On that signature, training mass is
  40% `struct*` and 25% `char*`, so the node-only arm selects `struct*`.
  Immediate incident relation profiles are also nearly identical across these
  classes.
- **Discriminating structure exists but lies mostly outside the receptive
  field.** An access node is the target of a forward `mem_loc` edge, and its
  width is the access width. `char*` values are dereferenced only by 8-bit
  accesses (14/25 training and 13/22 development within six forward hops).
  `struct*` values are mostly dereferenced by 32/64-bit accesses (10/11
  development variables), and `i32` values are never dereferenced forward. However, an 8-bit
  access lies within undirected distance 2, the reach of the two-layer RGCN,
  for only 4/25 training and 2/22 development `char*`. By contrast, 21/37
  training `struct*` have a 32/64-bit access within distance 2.
- **Some variables have no in-graph evidence.** Seven training and two
  development `char*` have no 8-bit access within six undirected hops, and
  more have none in the forward direction. Such variables are probably passed
  to calls whose semantics the function graph does not contain.
- **The graph arm's extra hits are not explained by this evidence.** The two
  `char*` correct in seed 17 have forward dereference depths 1 and 3. The two
  in seed 43 have no forward dereference. Elsewhere `char*` is usually ranked
  second behind `struct*`, so these changes are consistent with boundary noise.

These statistics include the development project, which is now inspected.
Any remedy (deeper message passing, derived access-width features, or more
training coverage of byte-pointer use) must be fixed in advance, justified by
training-side statistics and judged on data not used for this diagnosis.
Because the present scores mostly encode value width, a non-type feature the
type-blind scheduler arm can already observe, they are unlikely to carry
incremental information for the Route B scheduling comparison.

### Type pilot v2 pre-registration

The remedy and a new development set are fixed in
[type_pilot_v2_preregistration.md](type_pilot_v2_preregistration.md) before
any new development label, graph or score exists. Training stays the reviewed
129-variable split. The remedy arm is a four-layer RGCN, with the depth set
by a training-only reachability rule, and a deterministic structural baseline
tests whether neural scores add information beyond program structure.
`scripts/prepare_type_dev_extension.py` pinned sds
(`5347739b1581fcba74fd5cab1fc21d2aef317d71`), tiny-regex-c
(`f2632c6d9ed25272987471cdb8b70395c2460bdb`) and json-parser
(`9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`) as primary development projects
and parson (`ec53fb6528b45811df9db0db22cab96a94a96a11`) as the declared backup,
in `route-b-type-dev-extension-20261120T192757085592Z`. Its `selection.json`
records the pre-registration hash. No compilation, label inventory, graph
export or training has been performed for these projects yet.

### Type pilot v2 results

**Development set as executed.** The fixed v1 compile recipe could not link
json-parser (`pow`) or the backup parson (`fabs`), because neither links libm.
`scripts/build_type_dev_extension.py` recorded both failures
(`labels-20261120T194930213966Z`, `labels-20261120T195039466387Z`). It then applied
the backup rule through `--replace-failed` and dropped the failed backup, since the
pre-registration allows no other substitution. The final inventory
`labels-20261120T195143703618Z` built all seven planned profiles (sds and
tiny-regex-c at O0/O1, plus the three training projects at O0 for the clone
screen) and found zero cross-split clone groups. This is a deviation from the
intended three-project set, caused by a selection check that missed the libm
dependency.

`scripts/export_type_dev_graphs.py` reused the reviewed v1 capture worker and
admission rules for all 67 development functions
(`route-b-type-dev-graphs-20261120T195202135627Z`). It exported 49 functions and
admitted 200 of 258 candidate source variables (sds 161, tiny-regex-c 39;
3,403 value rows), above the 100-variable minimum. Sixteen functions failed the
graph feature/readout order check, one returned no function graph and one
recorded a step exception; their variables remain excluded in the denominator.
The independent `verify_type_dev_export.py` rechecked 407 hashes, location/readout
correspondence, row ownership and counts without importing a neural framework.

**Run.** `scripts/train_type_pilot_v2.py` ran once
(`route-b-type-training-v2-20261120T200823775624Z`). All six A1/A2 final
parameter digests matched the v1 run, the 2- and 4-layer runtime contracts
passed, every checkpoint replay reproduced its scores, and pinned sources and
data were unchanged. No evaluation project was executed.

New-development Top-1 out of N = 200 (margin m = 10). Thirteen development
variables belong to classes absent from training and count as errors in every arm.

| Arm | Seed 17 | Seed 29 | Seed 43 | `char*` correct (of 62) |
| --- | ---: | ---: | ---: | --- |
| A0 frequency prior | 18 | 18 | 18 | 0 |
| A1 two-layer RGCN | 49 | 53 | 90 | 5 / 9 / 21 |
| A2 two-layer, no messages | 44 | 44 | 44 | 0 |
| A3 four-layer RGCN | 88 | 59 | 83 | 12 / 14 / 8 |
| A4 four-layer, no messages | 44 | 44 | 44 | 0 |
| A5 structural logistic regression | 121 | 121 | 121 | 39 |

**Pre-registered decision: No R1.** A3 minus A1 was +39, +6 and -7 variables,
and A3's development NLL was lower than A1's only for seed 29. R2 also failed:
A3 trailed A5 by 33, 62 and 38 variables. Per the pre-registration, representation
iteration on this corpus stops, and the next step is a separately pre-registered
training-coverage expansion.

Secondary observations, which do not decide anything: the GNN arms vary strongly
across seeds (A1 49-90), while the deterministic A5 baseline reaches 121/200 with
the lowest NLL (1.63) and recovers 39 of 62 `char*`. Structural access-width
evidence is therefore informative on these projects, but this small GNN, trained
on 129 variables, does not use it reliably. Because a type-blind scheduler can
compute A5-style features directly, no incremental value of neural type scores
has been shown. These results come from one run on two development projects; they
are not a benchmark or a scheduling result.

### Type pilot v3 pre-registration

The training-coverage expansion is fixed in
[type_pilot_v3_preregistration.md](type_pilot_v3_preregistration.md) before any
v3 label, graph or score exists. Training grows from 129 variables to the
original split plus the audited optparse, sds and tiny-regex-c exports, plus
nine new projects. Fresh development is json-parser, parson and md4c. The v3
build recipe adds only `-lm` at link time; every new project and both reused
development projects linked with it in a label-free WSL probe beforehand. GNN
depth is chosen by leave-one-project-out on training only. Three rules decide:
whether coverage helps the GNN (H1), whether the GNN beats the A5 structural
baseline (H2), and whether stacking GNN scores onto A5 features beats A5 (H3).
`scripts/prepare_type_corpus_v3.py` pinned the ten new projects in
`route-b-type-corpus-v3-20261120T203240742242Z`; its `selection.json` records the
pre-registration hash. Nothing has been compiled, labelled or exported for v3 yet.

### Type pilot v3 results

**Data as executed.** `scripts/build_type_corpus_v3.py` built all twelve new O0 profiles
with recipe v3 (`labels-20261120T205258590914Z`). The function cap kept 60 of
c-algorithms' 198, btree's 68, linenoise's 85, md4c's 134 and parson's 144 functions.
The clone screen found two identifier-normalized groups of short wrappers and excluded one
development function (parson `json_object_dotremove`). `scripts/export_type_v3_graphs.py`
(`route-b-type-v3-graphs-20261120T205341199496Z`) admitted 1,079 new training variables
(236 of 326 functions) and 571 development variables (99 of 129 functions); the
independent `verify_type_v3_export.py` passed. Expanded training therefore has 1,460
variables in 15 projects (11.3 times the original 129). Development has 571 variables in
md4c, json-parser and parson.

**Run.** `scripts/train_type_pilot_v3.py` ran once to completion
(`route-b-type-training-v3-20261121T001331640123Z`). Two implementation facts are
recorded as deviations from a literal reading:

- The full expanded batch (88,150 nodes, 294,712 edges) does not fit in WSL memory,
  because PyG `RGCNConv` keeps per-relation activations. Expanded-data fits therefore
  accumulate the full-batch gradient over disjoint function chunks (at most 4,000
  nodes each) before the single clip and Adam step of each epoch. Function graphs are
  disjoint, so this is the same gradient up to floating-point summation order. DGo
  fits use the unchanged v1 `run_model`. An automatic check retrained the original
  data in chunks and matched v1 `run_model` within 3.1e-5 in development logits, with
  identical Top-1.
- An earlier attempt (`route-b-type-training-v3-20261120T225803823863Z`) was stopped
  by host memory reclamation after the reproduction gate and depth selection, before
  any arm was evaluated for a decision. Its per-fold depth-selection results are
  identical to the completed run, as expected for this deterministic pipeline. A
  smoke attempt (`...222850505986Z`) failed earlier from WSL memory exhaustion.

The reproduction gate matched all six DGo digests against v1 A1 (depth 2) and v2 A3
(depth 4). Leave-one-project-out on training selected depth 4 (pooled held-out Top-1:
781 versus 704 of 1,460).

Development Top-1 out of N = 571 (margin m = 29); 43 development variables belong to
classes absent from expanded training.

| Arm | Seed 17 | Seed 29 | Seed 43 | `char*` (of 56) |
| --- | ---: | ---: | ---: | --- |
| D0 frequency prior | 179 | 179 | 179 | 0 |
| D5 structural LR, expanded | 269 | 269 | 269 | 10 |
| D5o structural LR, original | 269 | 269 | 269 | 28 |
| DGo four-layer RGCN, original | 218 | 211 | 228 | 8 / 12 / 4 |
| DG four-layer RGCN, expanded | 247 | 251 | 239 | 8 / 11 / 1 |
| DN no messages, expanded | 278 | 278 | 278 | 0 |
| DS stacked LR | 195 | 243 | 121 | 3 / 50 / 3 |

**Pre-registered decision: Neither.** H1 failed: DG beat DGo by +29, +40 and +11, below
the margin in seed 43. H2 failed: DG trailed D5 by 22, 18 and 30. H3 failed: DS trailed
D5 by 74, 26 and 148. Per the pre-registration, v3 reports a negative result for neural
type information at this scale and stops.

Secondary observations, which decide nothing:
- The development set is dominated by `struct*` (179 of 571) and `u32` (118). DN predicts
  every 64-bit value as `struct*` and so has the highest Top-1 (278) but the lowest macro
  F1 (0.086), against 0.193 for D5 and 0.183 for DG seed 29.
- DS is unstable (121-243) with very high NLL (46-60). With the fixed A5 optimizer
  settings, unscaled log-softmax inputs make this stacking poorly conditioned. That is a
  property of the pre-registered DS specification, not evidence for or against
  complementarity.
- More data reduced the GNN's development NLL (DGo 2.98-4.18; DG 2.33-2.60) and narrowed
  the seed spread, but it did not make the GNN exceed the structural baseline.

These are results for one development set of three projects (dominated by md4c, 395 of 571
variables). They are not a benchmark, and no scheduling comparison was run.
