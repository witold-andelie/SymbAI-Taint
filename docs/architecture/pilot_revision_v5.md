# Development revision v5: acquisition-cost diagnostic

Declared on 11 November 2026 before implementation and measurement. The v3/v4 source
snapshots and results remain unchanged. The A-D selector, operation catalog, cheap-first
controls, query scope and cold-query accounting unit do not change.

## Question and measurement boundary

The v4 WSL expanded checks spent 3.412 seconds on execution plus validation across 36
trials, about 94.8 ms per trial. Failed cheap attempts offer only 1.255 seconds of recorded
skip opportunity across 36 trials. These fixtures have not demonstrated an expensive
analysis choice that can repay the earlier 4.5-5.4 second cold neural acquisition.

Before designing additional refinement operations, separate the acquisition cost into
imports, model loading, upstream graph/location generation, graph preprocessing, batch
preparation, actual model forward, logit/identity export, hashing and serialization.
In particular, do not equate exporter wall time with neural forward time.

## Small fixed diagnostic

Use the **existing reviewed compiled probe**, with its unchanged binary/model hashes and
base-pointer locator plan. Run three independent cold acquisitions, each capped at 30 seconds,
using CPU, one BLAS thread, the existing tygr-orig environment and fresh D-drive caches.
Each run performs new graph extraction, new unlabeled forward inference, raw export and
reviewed location matching. No new benchmark program, model training, query label, model
download or conda modification is required.

Stage timing is opt-in. The ordinary exporter and A-D acquisition keep their current
behavior. Timing contexts must not overlap; iterator timing includes each `next()` call,
including exhaustion, without charging graph-consumer work to graph generation.
Forward timing separates collation/device preparation from the model call. Profiling is
CPU-only, avoiding asynchronous GPU timing claims.

The receipt identifies acquisition, binary, model and raw output. It reports timed stages
and unallocated script time. Outer export-process wall time remains authoritative and
includes process startup and exit; the inner receipt excludes its own final writing.
Mapping and provider overhead remain paid outside the exporter. Preserve failures and
partial logs, and archive the profiled sources and this plan before measurement.

## Interpretation and next decision

This is a **cost diagnostic**, not a new A-D performance comparison or a warm-model test.
Import/loading time can identify an amortization hypothesis, but subtracting it does not
measure a persistent service. Graph/location extraction remains workload-dependent.
No cached inference, graph, mapping or solver result becomes a free end-to-end input.

Report all three trials, stage variability and exported-prediction identity. Compare their
cost scale with the previously recorded operation opportunities, explicitly distinguishing
the compiled probe from the twelve mechanism workloads. Proceed with neural scheduling
only after identifying both useful type information and enough avoidable analysis work
under a declared accounting unit. A cheap-first baseline already solving these fixtures
is not, by itself, a reason to build a more complex scheduler.
