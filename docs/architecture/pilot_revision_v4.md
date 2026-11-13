# Development revision v4: operation-choice diagnostic

Declared before implementation and measurement on 11 November 2026. The v3 source snapshot
and results stay unchanged. The A-D selector, its three operations and neural-information
boundary also stay unchanged. This revision adds separate diagnostic controls, not a new
claimed neural algorithm or an additional A-D arm.

## Controls and restricted cheap operation

- `expanded_only`: one fresh 128-step check, followed by the existing fresh validation.
- `bounds_only`: one conservative local unsigned-bound analysis, followed by a fresh
  abstract recheck if it proves exclusion. It cannot report a violation.
- `bounds_then_expanded`: try the same bound operation; on unknown, pay for the fresh
  128-step check and its validation. No inferred neural type becomes an analysis fact.

The cheap operation reads ELF executable bytes and a deliberately small x86-64 instruction
subset. It propagates unsigned register intervals through constant/register moves, address
arithmetic, masking, zeroing and direct control flow. A directly adjacent unsigned compare
and branch may narrow an interval. A target write is discharged only when **all** represented
addresses are inside the declared object. A return before the first target write discharges
that path under the same function-entry return convention as the existing checker.

Unsupported instructions, stack modification, other memory accesses, signed guards,
unresolved control flow, wrap-induced imprecision or work limits retain unknown whenever
they prevent the proof. An interval containing an out-of-bounds value is not an existential
witness. The certificate identifies query, bytes, abstract trace and discharged writes;
validation rebuilds it from fresh byte decoding and initial intervals. This is an abstract
recheck using the same implementation, not native replay or an independent proof checker.

## Measurement plan

Use the same twelve existing mechanism queries, without selecting new favorable cases.
Compare the three controls with frozen no-type B. Each trial is a separate cold process,
with a **3-second end-to-end budget** including startup, input checking, information
preparation, operations, validation, recording and parent cleanup/recovery.

Run three repetitions, rotating the four-method order by query and repetition. Record the
actual order. Read developer labels only after all workers terminate. Keep all 144 records,
including unknowns and failures. Report per-method resolved/correct/wrong/timeout counts,
total and median wall time, and per-query operation costs. OS caches are not flushed.
The Windows measurement is a local diagnostic, not a replacement for WSL or held-out data.

Hash and archive runtime sources before launching measured workers. Record Python, angr
and decoder versions. Do not tune the selector or the operation after observing the run.
Subsequent fixes require another recorded run identity; the originals remain available.

## Decision rule

First determine whether bounds checking is both valid and materially cheaper on the queries
it can settle. Compare the combined strategy with expanded-only, counting its failed cheap
attempts too. Complementarity does not imply neural guidance is useful: structural features
may already identify all useful cheap checks. If this happens, retain that result instead
of using model complexity to manufacture a gain. Do not add the operation to A-D or train
a new selector in this revision.
