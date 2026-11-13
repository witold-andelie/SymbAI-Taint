# Development revision v9: restricted compiler-frame bounds checking

Declared before implementation/measurement on 11 November 2026. Keep v4-v8 measured
sources/results and the A-D selector/catalog unchanged. Add a separate frame-aware
checker and diagnostic, not a neural policy or a claimed algorithmic contribution.

## Program model and supported subset

Use the existing BinaryChecker function-entry model to obtain a unique concrete initial
RSP. Charge its project/state construction. Check the bounded stack window against every
mapped ELF load segment and the declared target object; overlap or non-unique/wrapping
entry state gives unknown. No prefix execution, type prediction, mapping proof or source
outcome is a checker input. A fallback may reuse the already paid project, but starts at
a fresh entry state without prepared-prefix reuse.

Support only a straight-line prefix with optional nop/endbr64, one canonical push rbp,
mov rbp,rsp, and optional immediate stack allocation up to 4096 bytes. RBP remains fixed.
Support initialized, aligned, eight-byte negative RBP slots within a 4096-byte window,
respecting the current allocation plus the 128-byte AMD64 red zone. Track exact-width
slot overwrites, loads and supported add/sub/constant-mask operations with unsigned
machine-width intervals. Saved RBP and return-address slots cannot be read/written by
ordinary slot accesses. Frame addresses cannot escape into general registers or stores.

Partial/overlapping accesses, uninitialized reads, other memory, pointer escapes, calls,
branches, epilogues/returns, unsupported arithmetic, code/object overlap and work limits
give unknown. A target write can only yield scoped exclusion when its entire abstract
address/length range is inside the declared object. An unsafe interval is not a witness.
Fresh certificate validation rebuilds entry context and byte analysis independently.
This remains the same implementation's abstract recheck, not native replay or an
independently verified proof checker.

## Diagnostic

Use only the three existing compiled developer queries: original direct-index probe and
both v8 queries. Compare expanded-only, frame-bounds-only, frame-bounds-then-expanded.
Three repetitions, rotated method order, 5 s end-to-end per fresh process: 27 planned
records. Charge interpreter/imports, project/entry context, decoding, checks, validation,
fallback, recording and parent cleanup/recovery. Retain late results as unknown. Record
preparation/execution/validation and action order, including failed cheap attempts.
Read expected outcomes only after workers finish. No inference, download, package
installation, training, API use, selector tuning or additional research cases.

Snapshot sources and query contracts before measurement. The inputs are frozen developer
queries, not held-out projects. Applicability and fixed-fallback value do not establish
neural information value. If the cheap operation is dominated or structural inputs
already identify its useful scope, report that rather than tuning a type-driven policy.
