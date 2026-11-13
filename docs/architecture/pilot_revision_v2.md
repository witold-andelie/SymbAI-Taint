# Development revision v2: paid prefix reuse and retained candidates

This is a development implementation change within frozen pilot v1, not a new research
claim. RQ1/RQ2, the A-D type views, the common selector/checker boundary and budget rules
remain unchanged. The policy is now `deterministic-pilot-v2`, and the operation catalog
records `exact_prefix_v2`. Run records carry both revisions and their hashes.

## Problem and resulting behavior

In revision v1, dependency recovery only wrote observations. A later check repeated all
execution from the entry. Also, Top-K pointer candidates collapsed to one pointer-role
feature. Revision v2 addresses both engineering limitations without treating predictions
as symbolic facts or removing instructions based on an incomplete dependency graph.

The definitions operation now builds a target backward slice using angr reaching
definitions. Nodes and edges are exported with local IDs. When the target is in the
straight-line entry block, a plan lists every instruction before it. The checker executes
all those instructions, retaining copy-on-write snapshots at each depth. Preparation
is capped at 64 prefix steps and is charged to that operation, including RDA and copies.

A snapshot is admitted only after exact single-successor execution without hooks, syscalls,
symbolic control-flow ambiguity or recorded address concretization. Other cases fall back
to ordinary execution. Slice absence never proves irrelevance. No instruction is omitted
while preparing the prefix, and no RDA value is added as a solver assumption.

A later operation on the same query copies a snapshot at the lesser of its precision cap
and the prepared depth. Reusing a depth-8 state does not allow the 8-step operation to
inspect depth 9. Results record semantic steps, newly executed prefix steps, reused steps
and the query-bound cache ID. Validation always starts fresh from entry and reports zero
reused steps. Caches are neither shared between variants nor imported from another query.

This is ordinary reuse of paid symbolic work, not a new analysis algorithm. Moving work
into preparation need not improve total time. It can avoid repeated work across operations;
the builder and independent validator still pay their actual execution costs.

## Type features and the common policy

Feature views retain exact candidate labels, raw logits, conditional Top-K weights,
raw-score margin and conditional entropy. A Top-1-only view carries no scores and reports
its distributional statistics as missing, not certainty. Missing types in B still leave
the structural score functional.

The shared score keeps the existing coefficient 0.5:

```text
score(action) = (structural_utility + 0.5 * (role_support + information_utility)) / cost_estimate
```

For the definitions operation only, `information_utility = 1 - sum(weight[label]^2)` when
actual candidate weights are available. Other operations and missing distributions receive
no diversity bonus. Thus distinct pointer candidates need not collapse to identical score
components. This is a declared development heuristic, not a calibrated expected benefit.
It may leave C/D's action order identical and is not designed to force a win for D.
Conditional Top-K entropy/diversity are not correctness probabilities or full-vocabulary
uncertainty estimates. Neural features reach selection and its ledger only.

## Planned verification, fixed before the new measured run

Use the existing 12 mechanism programs for correctness regressions; do not create a new
benchmark set. Require prepared/fresh outcomes to match, bounded-depth unknowns to remain
unknown, stale-query reuse to fail, and fresh exclusion validation to survive an invalid
cache. Test raw-score exclusion from C and identity-sensitive D features.

For the compiled integration case, keep the same binary, mapping, raw model output and
0.1/0.3/1-second information budgets. Run all A-D variants again under revision v2, preserving
the old v1 records. Both policy and preparation changed, so historical v1/v2 time differences
cannot isolate either mechanism's causal benefit. Additionally compare cached and fresh
checks from the same query using instruction counters. Total costs must include prefix
construction and fresh validation; saved replay steps alone are not a speedup claim.

This case remains a post-inference developer integration check, not held-out evaluation.
No weights are fitted to its outcomes. Online charged C/D inference and broad mapping
validation are still separate pending work.
