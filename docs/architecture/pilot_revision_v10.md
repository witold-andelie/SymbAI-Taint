# Development revision v10: explicit shared-process cost diagnostic

Declared before implementation and measurement on 11 November 2026. V9 reproduced
functional results, but its WSL aggregate difference depends on one slow first full
run. Do not tune selectors, discard that run or infer a warm service by subtracting
imports. Keep archived v9 sources/results and A-D selection untouched.

## Correctness guard before cost measurement

Independent review reproduced a file/loader inconsistency on a nonstandard ELF: dynamic
relocation metadata referenced a table not covered by the section table used by the old
byte checker. Its file instructions differed from reference-loaded instructions, yet
same-implementation rechecking repeated the exclusion. This does not describe the three
ordinary GCC inputs, whose program facts were already cross-checked, but it requires a fix.

Before v10 measurement, require active dynamic relocation tables to match actual section
and load-segment bytes, reject unsupported relocation formats/types and the complete span
of any executable relocation, and compare each frame-decoded instruction against reference
loader memory. Bump the operation revisions and retain regression tests. The fixed control
order and symbolic checker remain unchanged; cost results use the corrected guard, so v9
and v10 differ in both accounting unit and this conservative implementation correction.

## Unit and fixed schedule

One batch contains the same three existing compiled developer queries, each exactly
once, in one fresh worker process. Use the same expanded_only, frame_bounds_only
and frame_bounds_then_expanded methods. Three repetitions: rotate method order by
repetition and query order by repetition, identically for every method. Nine batch
workers, 27 planned query outcomes; three unique developer inputs, not 27 examples.

Each batch has a 15-second end-to-end budget including interpreter/imports, input checks,
all query preparation/execution/fresh validation, recording, worker exit and parent
cleanup/recovery. No per-query free-startup credit or post-hoc amortization. Each query
uses its remaining batch time. Preserve completed outcomes and mark unstarted/unfinished
queries unknown on a failed or timed-out batch. A result recovered after the global
deadline cannot be counted as an on-time decision; retain it as late evidence.
If full parent finalization exceeds the batch budget, count every decisive recovered
outcome as unknown and preserve it as late evidence. A process failure recovered before
the deadline may retain valid, already flushed completed-query records.

Charge recovery, initial parent finalization and provisional receipt serialization. The
last clock-stamping/receipt write and experiment orchestration/offline evaluation are
outside that timing boundary; report this explicitly. No analysis work is excluded.

Every query gets a fresh project and analysis state. The existing fallback may reuse
its own query's already paid project exactly as in v9. Never reuse projects, prefixes,
certificates, witnesses or explicit analysis summaries across queries. Imports and
ordinary in-process library caches can warm naturally; record that rather than claiming
all caches are cleared. Batch process exit resets explicit application objects.

## Records and interpretation

Record the parent batch clock, query order/outcomes, query start/finish offsets, method
cost ledgers and remaining budget. Query-local durations are diagnostic components;
the primary charged time is the complete batch, not the sum of free-start query costs.
Flush completed query records so failures cannot remove cases. Read gold only after all
batch processes terminate. Hash/archive sources, contracts and input binaries first.

Report all nine batch costs and their three-query outcomes, per-method total/median
batch wall time, correct/wrong/unknown counts and startup/finalization residuals. Make
the changed accounting unit explicit when describing v9 versus v10; this is not a
matched single-query experiment, a learned selector or a GNN warm-service measurement.
No new inputs, compilation, inference, training, downloads, installations, APIs or GPU.
All outputs/caches stay on D. If batching exposes no useful local/full-check cost
tradeoff, report that limitation before adding neural scheduling complexity.
