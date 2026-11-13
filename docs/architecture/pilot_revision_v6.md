# Development revision v6: information-value diagnostic

Declared before implementation and measurement on 11 November 2026. RQ1/RQ2, the frozen
A-D policy/parameters and original operation catalog remain unchanged. This diagnostic
tests available information on the **one existing reviewed compiled query**. The twelve
byte-generated mechanisms lack reviewed neural mappings; their predictions are not filled
in or copied from another program. No new mechanism or training data is introduced.

## Comparisons

Use six methods: `info_A`, `info_B`, `info_C`, `info_D`, `info_expanded_only`, and
`info_bounds_then_expanded`. A-D call the frozen selector on its original three operations.
B/C/D differ only in type view: absent, genuine Top-1 label, genuine Top-K/logits. There is
no new scoring rule, fitted cost model or parameter change. The two fixed controls reuse
the full-check and cheap-bound operations as separate strong references; they are not
type ablations with the same operation catalog as A-D.

All methods start from freshly prepared symbolic and byte-bound checkers for the same
query and the same structural features. No initial dependency facts or symbolic-prefix
cache is supplied. Any selected definition analysis/prefix preparation is paid inside
the information budget. Every decisive result is freshly validated. Neural predictions
remain ranking inputs, never solver constraints, path-pruning facts or result labels.

## Information and accounting boundary

Freeze the genuine mapped output of a completed v5 acquisition, together with its raw
output, receipt, binary/model identities and reviewed location anchor. Check that the
mapped record exactly matches remapping the archived raw output under that review. Copy
inputs into the new run directory. B and the controls do not inspect the candidate view.
C drops scores; D retains the true exported values. No constant confidence or synthetic
prediction is accepted by the empirical runner.

The analysis budget starts **after** shared checker preparation and type-view loading.
Exclude model loading/inference, prior mapping, artifact reading/projection and common
checker construction, but record preparation wall time separately. Include selection,
operations, local reanalysis, fresh validation, event recording and parent finalization.
Keep cold subprocess wall time alongside charged information time. This is explicitly
information-only; it cannot establish end-to-end neural benefit. A late result is unknown.

## Fixed first measurement

Run three repetitions at **0.05, 0.15 and 0.50 seconds**, rotating six-method order by
budget and repetition. This retains **54 records for one unique query**. Each run owns a
fresh process; OS caches are not flushed. Common preparation has a separate 30-second
allowance before the information budget's hard process limit. Preserve all failures and
unknowns. Join labels only after workers finish and archive source/plan hashes before launch.

Report per-budget conclusion counts, wrong/unknown counts, charged information time,
complete process wall time, action sequences, model/type identities and projection scores.
Compare B/C/D for information value; compare each with both fixed controls for practical
headroom. Do not infer statistical significance from three repetitions on one positive query.

## Decision

Selection changes without better evidence or lower charged cost do not establish useful
information. Identical C/D decisions establish no observed incremental value from Top-K
on this query. Report negative results unchanged. A positive result would still require
independent mapped queries and paid acquisition before a neural research claim. No new
operation, tuning or warm-service optimization is part of this revision.
