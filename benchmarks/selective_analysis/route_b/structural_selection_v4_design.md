# Route B v4: structural selection of analysis operations (pre-registration)

Frozen on 21 November 2026, after the operation catalog was fixed in versioned code and passed its
regression gate, and before any held-out query was built, labelled or timed. The SHA-256 of this
file is recorded in `route-b-v4-freeze-*/freeze.json` together with the implementation hashes;
later v4 steps must refuse to run if any of them changes. Changes need a new, versioned
pre-registration.

## Motivation

- v1-v3 found no incremental value of neural type scores over deterministic structural features
  at the tested scale ([v3 result](README.md#type-pilot-v3-results)). Route B continues with
  structural, type-blind features; neural scores are not an arm.
- Data-driven selective analysis (Oh, Yang and Yi, OOPSLA 2015; Heo et al., TOPLAS; Jeong et al.,
  OOPSLA 2017; see [related work](related_work_type_pilots.md)) learns from cheap program features
  where to spend analysis effort. v4 tests that idea for choosing which checker runs first on
  finite-domain memory-write queries.
- Earlier execution-strategy panels had 6-18 queries, and a symbolic-to-concrete cascade already
  verified most of them. Small headroom is expected.

## Question

On a held-out, program-grouped panel of finite-domain write-bound queries, does a backend order
chosen by a learned structural selector verify more queries within the budget, or verify them
with less charged time, than either fixed order, with zero wrong decisions?

## Operation catalog and runner (fixed)

- Backends: `symbolic_certificate` and `concrete_enumeration` in
  `src/selective_analysis/finite_backends.py`. These are AST-identical copies of the archived
  producer, concrete core and worker logic (tests in `tests/test_route_b_v4_backends.py`).
- Runner: `src/selective_analysis/v4_runner.py` uses a warm isolated worker and parent-charged
  requests. The first backend in an order runs under the request deadline; if it is not decisive
  and time remains, the second starts fresh under the same deadline. A late reply is discarded as
  unknown, and the worker is replaced; replacement time is recorded separately.
- Regression gate (passed): `route-b-v4-backend-regression-20261121T073429858926Z` re-ran the
  archived project-disjoint cohort with the symbolic-first order at 3 s. It reproduced the
  archived outcome set in both repetitions (five cases within scope, bzip2 unresolved), with zero
  wrong decisions against the native references.

## Data

- **Development (selector training only):** the 79 distinct single-input queries recorded in
  earlier Route B execution-strategy cohorts (`route-b-*/intake.json`, 62 binaries). They are
  already observed and never support held-out claims. Each backend runs alone on each development
  query, twice in reversed order, at the 3 s budget. These runs are the only training labels.
- **Held-out panel:** built after this freeze by `scripts/build_route_b_v4_panel.py` (`--plan-only`,
  then `--build` with the same output directory). S1 is the six Juliet CWE129 files, with `bad`,
  `goodG2B` and `goodB2G` per file. S2 is source-owned single-parameter kernels from the pinned
  non-sealed corpora that link freestanding; capacities come from native maximum indices only. The
  builder's `--plan-only` run before the freeze found 18 S1 queries and 43 S2 candidate kernels
  (at most 104 queries in at most 19 binary groups) before link filtering.
  `offline-references.json` is never read by runtime code. utf8.h and b64 stay sealed.
- **Minimum:** if the built panel has fewer than 60 queries or fewer than 15 binary groups, v4
  stops and is reported as uninterpretable. No rule is broadened and nothing is substituted.

## Arms

| Arm | Order |
| --- | --- |
| F | symbolic, then concrete (the archived fixed cascade). |
| C | concrete, then symbolic. |
| L | Learned order (below). |
| O | Retrospective oracle over F and C per query (report only). |

The input-count rule is omitted because every held-out domain has 256 inputs, making it identical
to F. The archived prefix/phase rule is omitted because its probe has not been consolidated.

**L, fixed in advance.** Features are the `structural_features` v1 vector (34 values),
standardized with the development mean and standard deviation (zero-variance features are dropped).
For each backend b:
- an L2-regularized logistic regression (lambda = 1.0, Newton iterations to a 1e-10 gradient norm,
  zero initialization) predicts p_b = P(decisive within budget);
- a ridge regression (lambda = 1.0) predicts log charged seconds, giving t_b.

Both are fitted on the development single-backend runs. For a query, L chooses the order whose
expected time E = min(t_first, B) + (1 - p_first) * min(t_second, B) is smaller, with B = 3 s; a tie
selects F. L sees only the query contract and fixture bytes.

## Protocol and metrics

- **Batches and order.** One batch per binary group and arm, with a fresh warm worker per batch.
  There are two repetitions, the second in reversed query order, and arm order rotates. Per-query
  budget B = 3 s.
- **Offline audit.** Decisive results are checked against the offline references after collection.
  Any decisive result that disagrees is a wrong decision.
- **M1 (primary):** verified decisions (safe or violation, agreeing with the reference), summed over
  both repetitions.
- **M2 (primary):** total charged time, with unknown or late requests charged at B.
- **Uncertainty.** Paired by binary group, with a bootstrap over binary groups (10,000 resamples,
  seed 0) for the M2 difference.

## Decision

- **Supported:** L has zero wrong decisions, M1(L) >= max(M1(F), M1(C)), and M2(L) < min(M2(F), M2(C)).
  In addition, the 95% bootstrap interval of M2(best fixed) - M2(L) must exclude zero. The next step
  is an amortization study on multi-query binaries.
- **Not supported:** report that structural selection adds no measurable benefit over a fixed order
  on this panel. Route B then reports the characterization and the negative results.
- **Wrong decisions:** any wrong decision in any arm is reported first and blocks a positive claim.

Secondary reports, which decide nothing: per-stratum results, oracle headroom, per-feature
coefficients, worker replacements and the cold start.

## Execution order

1. Done: catalog consolidation and regression gate.
2. After this freeze: generate development labels, fit L, and record the fitted parameters with
   their hashes.
3. Build and audit the held-out panel (no timing during the build).
4. Run every arm once on the panel and report all binary groups and repetitions.
