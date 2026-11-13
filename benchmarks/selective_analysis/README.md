# Selective-analysis pilot v1

> **Current checkpoint: development v23, 13 November 2026.** Corrected native acquisition
> covers three authored functions in one ELF; the two table cases have identical actual
> model inputs/full outputs despite different historical operation capabilities. This
> is not a neural scheduling gain. See [status](../../docs/STATUS.md),
> [v23 evidence](../../docs/pilot_evidence.md#v23-retained-type-information-collision-audit)
> and [the documentation map](../../docs/README.md).
>
> **Public reproduction:** the initial developer mechanisms and synthetic tests can
> run from a clean checkout. Genuine exports require external TYGR/model/runtime;
> many versioned commands below additionally require specific historical local `.scratch`
> bundles. These bundles are not distributed in Git. See the
> [three reproduction tiers](../../docs/REPRODUCIBILITY.md) before running a replay.
> Commands and pending steps in chronological sections retain their stage's scope.

This is a small executable feasibility prototype for the [frozen protocol](../../docs/architecture.md).
It runs independently of `src/pipeline.py`. The current evidence validates analysis and
experimental plumbing; it establishes no neural scheduling benefit or publication result.

## Implemented boundary

- A uses a fixed order. B/C/D use **the same** `select_action` implementation and parameters,
  with no types, a Top-1 label, or Top-K raw model scores respectively. Types affect scores only.
- In the frozen A-D catalog, three operations are available to every variant: local reaching definitions, instruction
  exploration capped at 8 steps, and exploration capped at 128 steps. Dependency observation
  records facts and, for an eligible straight-line entry prefix, prepares exact snapshots;
  it cannot itself discharge a bounds query. Later checks can reuse paid snapshots from
  the same query and entry assumptions. All validation starts fresh without reuse.
- The current score is `(structural_utility + 0.5 * (type_support + information_utility)) / estimated_seconds`.
  Structural features include the target's position in the entry block and a conditional
  entry branch. Estimates and weights are declared developer constants, not learned or
  calibrated benefit estimates. They are logged through policy/catalog hashes.
  Definitions receive a conditional candidate-diversity bonus when scores are available;
  missing scores remain explicitly missing. Exact labels, logits, weights and margins
  are retained in selector diagnostics. See the [v2 specification](../../docs/architecture/pilot_revision_v2.md).
- angr solves the target write's address/size bounds condition with machine-width arithmetic.
  Decisive outcomes require a fresh modeled reexecution or complete scoped recheck.
- Each run has an isolated subprocess, a flushed JSONL ledger and a final result. Hard
  timeouts, missing models, unsupported behavior and mapping failures remain `unknown`.
  Gold labels are read only by the separate offline evaluator.

The query explicitly supplies a static object address, capacity, entry and target instruction,
and unsigned ranges for selected input registers. The scope is **the first dynamic visit to
that target**. It is not all writes or whole-program correctness. Only AMD64 ELF and a target
decoding to one ordinary VEX `Store` are supported. Unsupported precision loss blocks
exclusion. SAT witnesses are checked in a fresh program model; **native replay is not implemented**.

## Run the developer mechanisms

For a model-free fresh-checkout run, use `--variants A B`. Requesting C/D without an
accepted genuine type artifact/provider intentionally retains unavailable results;
it does not create a neural baseline. Separate control catalogs described later are
diagnostic experiments, not a changed frozen selector.

The minimal dependencies are [requirements.txt](requirements.txt); the tested local environment
is Python 3.13.10, angr/claripy 9.2.217 and pytest 9.0.3. Genuine TYGR export must use the
upstream model's compatible environment instead. No GPU is needed for A/B.

From the repository root, in PowerShell:

```powershell
py -3 scripts/run_selective_pilot.py --make-mechanisms --variants A B C D --budgets 0.1 0.3 1 --output D:/AI_Models/symbolic/.scratch/selective_analysis/my-information-run
py -3 scripts/evaluate_selective_pilot.py --runs D:/AI_Models/symbolic/.scratch/selective_analysis/my-information-run/runs.json --gold D:/AI_Models/symbolic/.scratch/selective_analysis/mechanisms/gold.json --output D:/AI_Models/symbolic/.scratch/selective_analysis/my-information-run/evaluation.json
py -3 scripts/run_selective_pilot.py --make-mechanisms --variants A B C D --budgets 5 --regime end_to_end --output D:/AI_Models/symbolic/.scratch/selective_analysis/my-end-to-end-run
```

These mechanism-only commands provide no neural mapping artifact or online provider,
so C/D remain unavailable. Use the reviewed compiled fixture's online entry below to
measure actual model acquisition.

Use a fresh output directory per execution. Runtime records identify binary, query, policy,
operation catalog, checkpoints, chosen actions, symbolic evidence and measured stage times.
The mechanisms generate `queries.json` without expected outcomes and a separate `gold.json`.
Changing the executable invalidates its hash-qualified query. Runtime input rejects gold fields.

`mechanisms.py` builds 12 tiny x86-64 ELF files directly from known instruction encodings:
direct and guarded writes, an inclusive-bound error, signed comparison, a branch join,
masking, a register alias, a direct call, an overwritten index, an unreachable write,
a stack spill and an interior pointer. These are **developer fixtures**, not Juliet,
compiler-generated programs, independent evaluation or generalization evidence. Eight have
modeled violations and four have complete exclusions within their stated scope.

All task-created temporary files, library caches, fixtures and run outputs default to
`D:/AI_Models/symbolic/.scratch/selective_analysis/`. Existing executables installed on C:
can be read. The separate research proposal stays in the parent workspace outside Git.
WSL is not required for these generated fixtures. The agent's sandbox cannot launch WSL,
but user-run commands in the existing WSL environments have compiled the integration probe
and measured the diagnostics below.

When running from a user-controlled WSL terminal, inspect the existing environment first:

```bash
cd /mnt/d/AI_Models/symbolic/SymbAI-Taint
bash scripts/check_wsl_environment.sh
```

This reports interpreter/package versions, compiler availability and workspace TYGR model
locations without installing anything or loading a model. Logs and temporary/cache paths
are placed under `/mnt/d/AI_Models/symbolic/.scratch/wsl/`. Windows and WSL have separate
Python environments; passing Windows checks does not establish Linux dependency readiness.

The 10 November WSL inspection found an existing `angr-env` (Python 3.10.20, angr 9.2.212)
and `tygr-orig` (Python 3.8.10, angr 9.0.7491, torch 1.8.1 CPU, PyG 1.7.0). Reuse them:

```bash
/root/miniconda3/bin/python -B scripts/locate_tygr.py
/root/miniconda3/envs/angr-env/bin/python -B scripts/run_wsl_pilot.py
```

The locator also queries registered Conda environments, editable installations and module
paths outside the project. A bounded search checks Linux source/model directories; an
incomplete search is explicitly marked. The earlier workspace-only scan does not establish
that TYGR is absent from WSL. Reports are saved under `.scratch/wsl/tygr-location-*.json`.

The completed 10 November location report found no TYGR package, module entry point,
source root or matching model in the registered environments and declared Linux/workspace
search roots. The `tygr-orig` dependency environment remains present. This does not establish
absence on other unsearched drives or directories. To acquire only the missing source/model
and test loading with the existing environment:

```bash
/root/miniconda3/bin/python -B scripts/run_wsl_pilot.py --fetch-tygr --prepare-only
```

This mode does not run the mechanism experiments or install packages. It writes the source
commit/model hash and a model inspection report to `.scratch/wsl/pilot-*/`. Model inference
and use-site mapping still require separate validation after successful preparation.

The pilot driver executes the same 12 mechanisms in both budget regimes, retaining C/D
as unavailable. No packages, GPU stack or training dataset are installed. Reports remain
under `.scratch/wsl/pilot-*/`. Locate and reuse existing TYGR files before considering
`--fetch-tygr`, which optionally acquires an ignored sparse checkout over SSH and inspects
one official model with `tygr-orig`.
SSH account authentication must already work in the user's WSL environment. The driver
provides a task-local `ssh/known_hosts` under the run directory, using GitHub's published
Ed25519 host key and independently checked SHA-256 fingerprint. `StrictHostKeyChecking=yes`
and the pinned host-key algorithm remain enabled; global SSH files and Conda environments
are not changed. The source and fingerprint are recorded in `ssh/host-trust.json`.
Reference: [GitHub's official host keys](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints).
The driver never overwrites an existing TYGR checkout.

The [upstream commit](https://github.com/sefcom/TYGR/commit/280320129a7f8bbfb9ee61b9a2155d2ddeac44c6)
is pinned. Only `src`, root setup files and
[x64.O0.base.model](https://github.com/sefcom/TYGR/blob/280320129a7f8bbfb9ee61b9a2155d2ddeac44c6/model/MODEL_base/x64.O0.base.model)
(6,053,463 bytes) are checked out. The model's Git blob is verified before loading, and its
SHA-256 is recorded. Loading/inspecting the model does not establish that inference or
use-site mapping works. The WSL driver and real-model integration await execution in the
user-controlled Linux terminal; they cannot be certified by the Windows checks.

## Budget semantics

`information_only` prepares the same program view outside the charged decision interval.
It charges selection, execution, validation, ledger recording and process finalization.
All actual wall time is also recorded. A 30-second extra preparation limit prevents an
unbounded worker. This experiment alone cannot establish deployment value.

`end_to_end` charges wall time from the parent's cold subprocess launch setup through worker
exit and result collection. Online model acquisition must fit there. Each query
pays its own preprocessing; there is no unreported cross-query amortization. A late result
is retained diagnostically but downgraded to `unknown`. OS timeout/termination overhead is
reported as actual elapsed time, so charged time can exceed the nominal limit.

The current CLI order is deterministic (budget, query, A-D) and uses cold workers. Actual
wall time can vary; these single runs are not a statistical comparison. Independent trials,
balanced execution order, memory/GPU accounting and project-separated data remain required
for formal evaluation. Fixed recorded costs are not substituted for actual wall time here.

## Actual end-to-end budget comparison

In the existing WSL `angr-env`, run:

```bash
python -B scripts/run_end_to_end_probe.py
```

This reuses the reviewed compiled fixture; it does not recompile or download anything.
It declares 3/10/20-second cold-query budgets and runs A-D once at each point. Every C/D
run starts a fresh TYGR process with its own acquisition ID and cache directory; A/B
never read the model configuration. Model loading, export, physical-location matching,
feature construction, checking, fresh validation and process finalization are charged.
The C/D exporter and selector use the same configuration; only their type views differ.

The entry first checks POSIX descendant cleanup outside the query budget. It then retains
worker/model logs, fresh raw logits, mapping receipts, partial timeout events and final
results under `.scratch/wsl/end-to-end-*/`. `evaluation.json` reports unknowns and timeouts.
If a killed worker cannot return its model-stage breakdown, that value is missing rather
than zero; the entire elapsed wall time is still charged.

The earlier human-reviewed locator plan and fixed query/bounds are setup inputs. This
is therefore a scoped single-case end-to-end integration, not general automatic mapping
or held-out validation. OS file caches are not flushed. See the
[v3 acquisition specification](../../docs/architecture/pilot_revision_v3.md).

The first real run, `end-to-end-20261111-102804-821`, retained all twelve records.
At 3 s, C/D timed out during acquisition while A/B resolved the query. At 10/20 s,
all resolved it: B took about 1.2 s, C/D 5.8-6.5 s, including 4.5-5.4 s for acquisition.
The four completed exports produced identical logits; C/D selected the same action sequence.
This establishes the online measurement boundary, with no neural net benefit on this query.
See [the evidence log](../../docs/pilot_evidence.md#first-real-end-to-end-run) and
[the operation-menu gate](../../docs/architecture/operation_selection_gate.md).

## Operation-choice diagnostic without model acquisition

The separate operation-choice diagnostic uses no model and can run in the same `angr-env`:

```bash
python -B scripts/run_operation_gate.py
```

It reuses the twelve mechanism definitions, generates fresh identical ELF/query inputs,
and runs B, expanded-only, bounds-only and bounds-then-expanded. Three repetitions use
rotating method order and a 3-second end-to-end budget, retaining 144 records. No training,
download, extra mechanism denominator or manual label-driven selection is performed.
Outputs and source snapshots remain under the parent workspace's
`.scratch/selective_analysis/operation-gate-v4-*/`. Gold is joined only after all workers finish.

The Windows development run matched all expanded-only conclusions with 30.7% lower total
wall time for the fixed bounds-first fallback. WSL replicated the same sources and twelve
queries: expanded-only 36.706 s, combined 28.131 s, with 36/36 repeated queries correctly
resolved by each (23.4% lower total wall time). These are non-neural developer results.
The [v4 plan](../../docs/architecture/pilot_revision_v4.md)
and [evidence](../../docs/pilot_evidence.md#development-v4-operation-choice-controls) describe
the restricted instruction scope and cost interpretation.

For individual controls, the generic runner accepts `--controls expanded_only`,
`--controls bounds_only` or `--controls bounds_then_expanded` with `--regime end_to_end`.
These are separate controls, mutually exclusive with `--variants`, and reject type inputs.
The WSL audit found only 1.255 s spent in failed cheap attempts across all 24 fallbacks.
Simply predicting which cheap checks to skip leaves little saving to repay model costs;
the [routing-headroom discussion](../../docs/pilot_evidence.md#wsl-replication-of-v4-and-routing-headroom)
records this limit without changing the frozen selector.

## Acquisition stage cost diagnostic

Before changing the neural scheduling policy, measure where acquisition time is spent:

```bash
python -B scripts/profile_neural_acquisition.py
```

Run this in the current WSL `angr-env`. The entry finds the existing reviewed compiled probe
and launches three fresh exports through `tygr-orig`, with fresh caches and a 30-second cap
per acquisition. It does not compile new cases or train a model. Each row reports imports,
loading, upstream graph generation, actual forward and location matching. All stage timings,
raw predictions, identity-checked receipts, logs and source snapshots live under
`.scratch/wsl/acquisition-profile-v5-*/` in the parent D-drive workspace.

The ordinary exporter does not write a timing receipt unless requested. The diagnostic
uses CPU and flat timing intervals, includes generator exhaustion, and separates model
collation from forward execution. Outer process wall time is authoritative; script timings
exclude interpreter startup and their own receipt writing. No warm-service cost is measured
or inferred. See [the predeclared v5 plan](../../docs/architecture/pilot_revision_v5.md).

The real run `acquisition-profile-v5-20261111-114641-1245` completed all three trials with
identical predictions and verified identities. Its median acquisition cost is 5.154 s;
separate stage medians are imports 3.265 s, loading 0.042 s, graph generation 1.055 s and
forward 0.091 s. Forward accounts for only 1.4%-1.8% of each complete acquisition.
These results do not measure a warm service or demonstrate a scheduling gain; see
[the audited evidence](../../docs/pilot_evidence.md#real-v5-acquisition-costs).

## Genuine type information: integration probe

### Information-value diagnostic using the existing reviewed artifact

After the v5 acquisition is available, run from either the project on Windows or WSL
`angr-env`:

```bash
python -B scripts/run_information_value.py
```

The script validates and freezes one completed v5 raw/mapped acquisition against its
receipt and reviewed physical locator. It runs frozen A-D plus expanded-only and
bounds-then-expanded, three repetitions at 0.05/0.15/0.50-second information budgets.
All methods get the same common symbolic/byte-checker initialization. Model acquisition,
prior mapping, artifact projection and common preparation are excluded; selection,
selected operations, fresh validation, recording and parent finalization are paid.
All 54 records represent **one** reviewed query. No prediction is synthesized for the
twelve byte-generated mechanisms. No new model or inference is needed.

Outputs, input copies and source snapshots stay under the D-drive parent workspace's
`.scratch/selective_analysis/information-value-v6-*/`. Labels are joined only after all
workers terminate. The first Windows run found no extra resolved query for C/D. Some
low-budget unknowns arise during finalization; do not reinterpret them as worker-only
check failures. See [the predeclared plan](../../docs/architecture/pilot_revision_v6.md)
and [measured evidence](../../docs/pilot_evidence.md#development-v6-information-value-on-windows).

WSL subsequently replicated the same eighteen source/spec hashes, query and type inputs.
At 0.5 s, all methods resolve the query in all three repeats; B's median charged time is
0.268 s, C's 0.413 s and D's 0.414 s. The smaller budget points remain unknown, including
finalization overruns. This is one-query evidence with no extra observed neural benefit.
The recorded v6 view covers the base-pointer prediction only. The separate index prediction
is retained in raw output but is not independently projected. See the
[WSL and input-scope audit](../../docs/pilot_evidence.md#v6-wsl-replication-and-input-scope).

### Separate base-pointer and index mapping

The new mapping diagnostic reuses the existing reviewed query and genuine v5 raw export:

```bash
python -B scripts/review_operand_mapping.py
```

Run in the current WSL `angr-env` or from the Windows project. It proposes the two physical
CFA bindings using the prior one-case review, checks them with fresh symbolic program
states, repeats the checks independently, and only then binds each raw prediction. It
also checks the address sum and constant one-byte length. Both verification passes share
a ten-second cap. No variable name or predicted label selects a binding.

Outputs live under `.scratch/selective_analysis/operand-mapping-v7-*/` on D:. The new
`operand-types.json` schema holds separate role IDs and untouched raw records. `views-C.json`
hides scores per role; `views-D.json` preserves each role's own candidate distribution.
`operand-program-facts.json` separately exports program roles/relations for every future
comparison arm, including B. A/B read no type views. The old single-view loader rejects
the new bundle; v6 results and scoring are not retroactively changed.

Windows and WSL verification succeeded for both operands with two fresh nine-instruction prefixes.
The index retains its original `char*`, `struct*`, `void*` candidates. This validates a
location/use binding, not the correctness of those predicted types or a new scheduling
benefit. WSL verification took 2.183 s, with a 2.207 s diagnostic pipeline; these include
first imports/project construction and are not isolated SMT timings. The canonical bundle
and evidence match Windows. Coverage remains two declared address operands of one query.
See [the v7 plan](../../docs/architecture/pilot_revision_v7.md),
[WSL replication](../../docs/pilot_evidence.md#v7-wsl-mapping-replication) and
[evidence](../../docs/pilot_evidence.md#development-v7-independent-operand-bindings).

### Original compile/export probe

Run one compiled direct-index integration check after successful model inspection:

```bash
/root/miniconda3/envs/angr-env/bin/python -B scripts/run_tygr_inference_probe.py
```

This uses GCC to build `inference_probe.c` with DWARF 4, PIE and no optimization, then
exports genuine Top-3 logits through `tygr-orig` on CPU. The output directory
`.scratch/wsl/inference-*/` contains the ELF, compiler command, symbols, disassembly,
inference log, raw logits and compact summary. Compilation and inference have time limits.
The source reuses the direct-index mechanism as an integration fixture; it is not an
additional independent benchmark or an RQ1/RQ2 comparison. The first-visit property would
be queried at `probe_write` with index in `[0,15]`, not at the fixed-input `main` entry.
Use-site correspondences require location/dependency review before C/D scheduling. The
first probe's base-pointer mapping has now been reviewed and exercised in A-D runs; see
[the measured evidence](../../docs/pilot_evidence.md#first-real-neural-information-only-integration).

On 11 November, an ignored sparse TYGR checkout and the official x64/O0 model were acquired
over SSH using the existing Windows identity. The model is 6,053,463 bytes with SHA-256
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.
All 149 checked-out files match their upstream Git blobs; text files use LF for WSL.
Runtime loading in `tygr-orig` succeeded on 11 November: GlowGNN, 75 unique labels,
independent decoder and `(x)` forward signature. Genuine inference and one base-pointer
use-site mapping were subsequently checked on the compiled probe. C/D information-only
runs work with that reviewed artifact and still report `type_information_unavailable`
when no matching artifact is supplied. Broader mapping validation remains pending.
The online provider is implemented via `--online-tygr provider.json`; its first real
WSL budget comparison is recorded above. Cached logits are accepted only for information-only
trials and never substitute for that online run. Synthetic type inputs require an explicit
test flag and cannot establish neural results.

The export and mapping tools have been exercised on the reviewed integration fixture:

```powershell
python scripts/export_tygr_candidates.py --tygr-root D:/path/to/TYGR --model D:/path/to/model.pt --binary D:/path/to/program.elf --top-k 3 --output D:/AI_Models/symbolic/.scratch/selective_analysis/raw-types.json
py -3 scripts/map_tygr_candidates.py --help
```

The exporter uses the external TYGR code and its independent classifier decoder. It rejects
autoregressive beam scores instead of presenting them as class logits. It preserves raw
value-node logits and vocabulary, and explicitly records mean-logit variable aggregation.
Its existing upstream locator is **DWARF-assisted**; accompanying source type labels are
discarded and the decoder receives `None` for labels. The adapter uses the upstream
non-prediction locator mode because the `predict_phase=True` implementation does not
populate the type list consumed by its serial generator and therefore drops variables.
Source labels are not used in the independent model's forward call.
It makes no claim of stripped-binary operation. Loading a debug binary and attaching its
predictions to a different stripped binary requires a future verified identity transfer.

Raw predictions retain their original function/location identities. The mapper accepts
only exact binary hashes and a manually reviewed correspondence file:

```json
{
  "mappings": [{
    "prediction_id": "ID from raw export",
    "use_site_id": "hash:entry_rva:write_rva:write_address",
    "reviewed_by": "reviewer",
    "evidence": "Concrete location and data-dependency evidence for this correspondence"
  }]
}
```

Use `--help` for the mapper's required raw, manifest and mapping paths. Passing its output
with `--types ...` exposes only the requested type view to the shared selector. No implicit
matching by variable name is performed. D requires at least two ranked labels and finite
raw logits. Its softmax weights are conditional on the retained Top-K set, **not calibrated
type-correctness probabilities**. The legacy fixed confidence `0.9` is not a valid substitute.

## Checks and local evidence

Run the new substantive checks, keeping library caches and temporary files on D:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
py -3 -B -c "from src.selective_analysis.workspace import configure_workspace; configure_workspace(); import pytest; raise SystemExit(pytest.main(['tests/test_selective_analysis.py','-q','-p','no:tmpdir','-p','no:cacheprovider']))"
py -3 scripts/validate_architecture.py --render
```

The Windows sandbox requires ordinary workspace directory permissions, so these tests use
a local temporary-directory factory rather than pytest's restricted temporary directories.

The 10 November 2026 local run passed all **25 new checks**, including actual ELF conditions,
fresh witness validation, real reaching definitions, type-view isolation, strict missing-model
handling, hard subprocess timeouts, evaluator denominators and raw-logit preservation.
The full `tests` directory passed **28 checks**; its three historical structure checks are
smoke checks and should not be read as full legacy functional coverage.

On 11 November, the selective-analysis suite passed **27 checks** after adding two
regressions for strict SSH host-trust initialization and fingerprint rejection. Those
offline checks do not establish that WSL account authentication or model loading succeeded.

After introducing the unlabeled forward helper, **29 selective-analysis checks** passed.
The two additional cases enforce a `None` label argument for both supported model-call
signatures. Actual WSL inference was then confirmed independently by the user-run probe.

Development v2 passed **47 focused checks** and **50 checks across `tests`** (including
the three historical smoke checks). Regressions compare cached/fresh outcomes on the
same 12 mechanisms, enforce precision caps and query identity, require fresh validation,
and reject model scores from C. The measured revision-v2 results are recorded in
[the evidence log](../../docs/pilot_evidence.md#development-v2-measured-reuse-and-retained-candidates).

Development v3 passed **58 focused checks**, with **61 across `tests`**. The new controlled
subprocess fixtures check fresh acquisition, type-view isolation, charged timeouts,
stale/non-matching output rejection, model identity and no model reads in B. These tests
do not substitute for the genuine WSL online run.

The timeout accounting regression now also requires elapsed and charged end-to-end time to
include parent cleanup/result recovery. All 58 focused checks passed after this correction.
Original experimental records and source snapshots are retained unchanged.

Development v5 passed **91 checks across `tests`**, including **88 focused checks** and
three historical smoke checks. New timing tests use an explicitly dummy backend to verify
the actual exporter/provider CLI path, prediction invariance, absent source labels,
non-overlapping timings, generator exhaustion, receipt identities and failure retention.
Those controlled timings are not empirical neural performance measurements.

Development v6 passed **100 checks across `tests`**, including **97 focused checks**.
New checks cover shared initial facts/policy, score masking, genuine-source requirements,
input remapping integrity, deadline retention, fixed controls and isolated information
accounting. Their deliberately fabricated type fixtures are test inputs, not model evidence.

Development v7 passed **120 checks across `tests`**, including **117 focused checks**.
The twenty new checks exercise actual machine-code slot/address relations, wrong/swapped
bindings, stale evidence, deadlines and content identities, separate C/D projections,
legacy-schema rejection, label-independent proposals and candidate-free shared facts.

Measured development results and their exact local artifact paths are in
[pilot evidence](../../docs/pilot_evidence.md). The single-query result is negative for net
benefit; broader RQ1/RQ2 claims require independent evidence.

## Two additional compiled developer queries (v8)

This separate diagnostic adds only two authored programs: `offset_index` adds four to
the entry index; `masked_index` masks it with seven. Each has one eight-byte global
object and one constant byte write. The fixed function-entry input domain is RDI [0,15],
regardless of the call in main. These are developer variants of existing mechanisms,
not held-out projects. The original twelve-case and single-query A-D records are unchanged.

From the repository directory in the existing WSL `angr-env`:

```bash
python -B scripts/run_compiled_queries.py
```

The runner uses GCC and `/root/miniconda3/envs/tygr-orig/bin/python`, with the existing
pinned TYGR model. No installation, download, training or API is performed. It archives
sources and the predeclared [v8 plan](../../docs/architecture/pilot_revision_v8.md), compiles
both binaries and acquires one fresh CPU raw-logit export for each. All caches, logs and
results stay under `/mnt/d/AI_Models/symbolic/.scratch/`. Each run creates a new
`wsl/compiled-queries-v8-...` directory; old artifacts are not overwritten.

Physical location metadata proposes both possible base/index assignments. Candidate
types and names never select a binding. One assignment must pass program-relation checks,
the other must be explicitly rejected, and the accepted assignment must pass a fresh
recheck. The transformed index expression is proved, not assumed. All completed proof
attempts are saved incrementally. Verified mappings yield a raw-preserving role bundle,
candidate-free common facts and separate A/B/C/D projections. These do not enter selection.

Compilation/extraction/export/mapping/property checks have hard process caps of
30/30/120/20/10 seconds per case. Property validation uses the unchanged checker and a
fresh modeled replay or scoped recheck. It runs independently of acquisition/mapping;
native execution remains unimplemented. Failures and unknowns remain in the two-case
denominator. Expected labels are loaded only after both runtime cases finish.

Inspect `case-results.json` and `summary.json`, plus each case's compile/export logs,
stage receipts, query, raw export and assignment attempts. A nonzero script exit means
at least one property or mapping did not pass; it does not discard that case. On Windows,
143 full-suite checks passed (140 focused), including 23 new unit/integration checks.
C syntax checks and extraction from the existing real GCC-produced probe also pass.
The genuine WSL run now passes on both binaries, and its retained artifacts passed an
independent Windows audit. The fixed queries have one modeled violation and one complete
scoped exclusion; both base/index assignments are uniquely verified and freshly rechecked.
The audit also regenerates all Top-K values from the retained 75-class value-node logits.
See [the v8 evidence](../../docs/pilot_evidence.md#v8-genuine-wsl-acquisition-and-mapping-validation).

The existing operation menu still needs work before a scheduling comparison is useful.
A separate post-hoc applicability audit on these unchanged binaries found that the
eight-step checker does not reach either target and local bounds returns
`unsupported_instruction:push`. Both validated conclusions come from the expanded checker.
This is not a controlled timing experiment or a neural-information ablation. Conservatively
supporting compiler stack frames motivates the separate v9 operation; the selector remains frozen.

## Compiler-frame checking (v9)

The separate [v9 checker](../../src/selective_analysis/frame_bounds.py) accepts a restricted
straight-line compiler frame: push rbp, mov rbp/rsp, optional bounded immediate allocation,
and initialized aligned eight-byte negative RBP slots. It derives entry RSP from the
actual reference model and checks that the supported stack window does not overlap the
program image or declared object. Frame pointer escape, other memory, partial overlap,
uninitialized slots, calls, branches and unsupported arithmetic remain unknown.

The operation only proves scoped exclusion, using whole address intervals. It never
reports a violation from an unsafe interval. Decisive certificates require fresh project,
entry context and byte-decoded rechecking. Entry context and validation are charged.
Fallback may reuse the paid reference project, but always begins with a fresh function
state and no prepared prefix. The old local checker and A-D catalog/policy are unchanged.

Run the same three existing compiled inputs in the current WSL `angr-env`:

```bash
python -B scripts/run_frame_bounds_gate.py
```

No new binaries, model inference, package installation, download, training, API calls or
GPU are required. The script discovers the original reviewed probe and latest v8 run;
`--probe-dir` and `--compiled-dir` can select explicit existing directories. It snapshots
sources and binaries, then runs three fixed controls with a 5-second end-to-end budget,
three repetitions and rotated order: 27 cold processes in total. Failed/late checks remain
unknown and all cases stay in the denominator. It reads offline labels only after every
runtime process exits. Outputs remain on D under
`.scratch/selective_analysis/frame-bounds-gate-v9-.../`.

The Windows run completed all 27 records with no wrong decisions or timeouts. Frame-only
resolved 3/9 repeated queries (the masked input); expanded-only and frame-first fallback
each resolved 9/9. Their total wall times were 17.217 s and 17.121 s, with medians 1.903 s
and 1.914 s. That small, mixed timing difference does not establish a stable advantage.
The full suite passed 172 tests (169 focused), including 29 frame/context/control tests.
Eight OPM DOT views validate and render. WSL replicated the same-source, same-input
protocol with all 27 records retained and identical query outcomes. Its full/fallback
totals are 10.610/9.214 s, but the first full run is 2.732 s and is the only matched pair
favoring fallback. Medians are 0.978/1.030 s. See the separate
[timing audit](../../docs/pilot_evidence.md#v9-wsl-replication-and-timing-sensitivity).
These are three authored developer queries, not 27 independent examples or evidence
of neural gains. Shared-process batching remains to be diagnosed explicitly.

## Explicit shared-process costs (v10)

This diagnostic keeps the same three developer inputs and fixed control orders. It
declares a different budget unit: one cold worker executes a three-query batch under a
15-second total parent budget. Three methods and three rotated repetitions yield nine
batch costs and 27 query outcomes. The order of queries also rotates identically across
methods. Every query has fresh program/analysis state; no explicit project, prefix,
witness or certificate passes to a different query. Imports and normal library caches
may warm within a batch, and their actual startup/finalization costs remain charged.

Run in the existing WSL angr-env from the project directory:

```bash
python -B scripts/run_frame_batch.py
```

No new programs, inference, training, downloads, packages, APIs or GPU are needed. Sources,
contracts and binaries are copied before timing. All outputs/caches stay on D under
`.scratch/selective_analysis/frame-batch-v10-.../`. Inspect `batches.json`, `summary.json`
and each batch's request, worker result, flushed events and final receipt. Per-query
intervals are diagnostic components, not the primary charged cost. Labels are read only
after every worker exits. Partial failures retain all identities and recover valid
flushed completions if within budget; any over-budget parent result counts decisive
outcomes as unknown and retains their late evidence. The final timestamp/receipt write
and experiment orchestration/offline join are explicitly outside the timing boundary.

Before measurement, v10 also corrects a reproduced file/loaded-byte inconsistency:
dynamic relocation tables must have verifiable section/load-byte coverage, unsupported
formats/types and any executable write span are rejected, and frame instruction bytes
must match reference memory. Unverifiable layouts, including sectionless dynamic inputs,
can remain unknown. New operation revision markers distinguish this defensive restriction.
Old v9 sources/results stay archived; v9-v10 therefore differ in both accounting unit and
this correctness guard, so their totals are not a matched algorithm speedup experiment.

The full suite passed 253 tests. In the audited primary Windows run, full and fallback
each retain 9/9 correct outcomes at three-batch totals 6.214/6.096 s, with batch medians
2.058/2.030 s. Frame-only retains 3/9 exclusions and six unknowns. An earlier run launched
before test-process exit was confirmed is retained as potentially load-confounded; it
is not pooled or chosen by speed. WSL has now replicated all sources, inputs, orders,
receipts and conclusions: full/fallback totals 4.770/3.835 s, medians 1.239/1.292 s.
Only the first matched batch favors fallback. A separate post-hoc sensitivity removing
that pair from both methods gives fallback 2.27% higher total cost; all primary records
remain retained. See [the WSL audit](../../docs/pilot_evidence.md#v10-wsl-batch-replication-and-decision-checkpoint).
This is a developer cost diagnostic, not evidence of neural guidance or held-out
generalization. The next gate is useful operation tradeoffs and conditional type
information value, using the existing accounting boundary.

## Operation evidence and applicability (v11)

This stage retains **all twelve original generated mechanisms** as its primary denominator.
It probes bounded(8), full(128), RDA-plus-full, direct-prefix-plus-full without RDA and local
bounds. Three rotated repetitions produce 180 records in 36 query workers. No new
mechanisms, neural inference, compilation, training, packages, APIs or hardware are needed.

Run from the project directory in the existing WSL angr-env:

```bash
python -B scripts/run_operation_effects.py
```

Outputs remain on D under `.scratch/selective_analysis/operation-effects-v11-.../`.
Inspect `evaluation.json`, `records.json`, `worker-receipts.json`, per-worker event/receipt
files and `compiled-proof-panel.json`. Every probe starts from the same empty query-bound
checkpoint with its own fresh project/state. Prefix composites may reuse only their own
paid exact prefix, and final result validation starts fresh. Failed preparation remains
paid even when full checking continues without reuse. Unsupported and imprecise results
stay unknown. All 180 identities survive failures; late parent results retain evidence
while counting unknown. Gold is loaded only after every worker exits.

The probe clock includes required setup, preparation, execution and fresh validation.
Shared worker startup and pre-action features are retained separately; neither is a free
deployment cost. Probe times are operation diagnostics, **not deployed-policy throughput**.
Dependency graph size and prepared snapshots remain planning artifacts. Symbolic execution
steps include preparation plus main execution plus fresh validation; abstract local
instruction counts are separate. No training or new selector is evaluated.

The full Windows suite passed 375 tests. The primary run retains all 180 rows with no
wrong validated decisions: bounded 33/36, full 36/36, both prefix composites 36/36, local
12/36. All 33 shared bounded/full successes have identical executed work. Both composites
also retain full total work; RDA composite median costs are higher than full and direct
prefix on every query. Local bounds supplies four correctly excluded inputs. Three-repeat
cost range separation is descriptive, not statistical significance or policy speedup.

The three existing compiled genuine-type inputs are **only a separate post-hoc proof
panel**. No model outputs are invented for the primary mechanisms. Conditional arithmetic
on the retained, already paid operand proofs yields witnesses 8 and 4 for the two modeled
violations and proves the mask exclusion. This is not new program verification or free
feature acquisition. Later B/C/D work must avoid full semantic mapping facts as free inputs,
or charge them and include a facts-to-decision baseline. WSL v11 now replicates all 180
records and counted-work conclusions: bounded 33/36, full/composites 36/36, local 12/36,
with zero wrong decisions and unchanged source/input identities. Probe-local medians are
0.099494/0.104358/0.134515/0.102993/0.021430 s in the listed probe order. These do not
establish policy speed or neural value. See the [WSL audit](../../docs/pilot_evidence.md#v11-wsl-operation-evidence-replication).

## Static location correspondence (v12)

The v11 proof panel motivates a stricter preparation boundary: mapping must not prove the
very property later used to claim neural scheduling value. This entry uses only the three
retained compiled binaries/query manifests and their frozen genuine raw exports. It matches
canonical-frame stack-load occurrences with raw function/CFA/PC metadata, without angr,
symbolic states, a property checker or old operand plans/proofs. It reads no names, type
labels or scores to choose bindings. Unsupported shapes or ambiguity retain unavailable
case records. This is syntactic correspondence, not a target-property proof.

Run from the repository root, using the existing Python with Capstone and pyelftools:

```powershell
py -3 -B scripts/run_location_correspondence.py
```

The same entry can run in WSL `angr-env` as
`python -B scripts/run_location_correspondence.py`. It does not import angr or run new TYGR
inference. Optional `--inference-dir` and `--compiled-dir` select retained input roots;
otherwise the latest complete existing v1/v8 roots are discovered. No new cases, models,
compilation, packages, APIs or GPU are needed.

Outputs go to `.scratch/selective_analysis/location-correspondence-v12-.../`. Inspect
`run-plan.json`, copied raw/binary/query inputs, source snapshots, all three records, each
`location-bundle.json` and `views.json`. The distinct schema is
`symbai.location_type_bundle.v1`; old semantic bundle readers reject it. A/B hide views,
C exposes Top-1 without scores, and D preserves each occurrence's Top-K raw scores with
conditional softmax weights. Those weights are not calibrated correctness probabilities.
C/D projection freshly repeats the static identity check. No common semantic program
facts or base/index roles are exported, and the frozen selector does not consume this view.

Recorded mapping/projection time excludes historical neural acquisition. It is neither
fresh online acquisition nor an end-to-end gain measurement. The three integration inputs
cannot establish completeness, stripped-binary mapping or neural information value.

The Windows diagnostic now retains all three available inputs with two bindings apiece,
and unchanged raw scores. A separate post-hoc identity audit agrees with all six old
prediction-ID/CFA pairs. All 442 tests pass; eleven OPM views validate. See the
[validation and accounting limits](../../docs/pilot_evidence.md#v12-static-location-correspondence).

WSL replication now retains the same three inputs and all six bindings, with identical
normalized A-D views and all eight source/specification hashes matching Windows. Its
0.503939 s runtime is the projection/recording segment after input snapshots, not an
end-to-end model acquisition cost or scheduling result. Raw scores and original artifacts
remain unchanged. See the [cross-environment audit](../../docs/pilot_evidence.md#v12-wsl-correspondence-replication).

## Routing sensitivity before property execution (v13)

This is a small order-only gate on the same three known compiled inputs, using only their
copied binary/query/raw files from v12. It does not read the old semantic proofs, source
labels, gold outcomes, prior operation records or even v12's location-bundle results.
It does not run a property checker, GNN, compiler or training job. The old A-D runner,
catalog and selector remain unchanged; this is a separately versioned diagnostic policy.

From the repository directory in WSL `angr-env`:

```bash
python -B scripts/run_routing_sensitivity.py
```

Windows can use `py -3 -B scripts/run_routing_sensitivity.py`. The latest complete v12
input root is discovered automatically, or pass `--location-input-dir <retained-v12-root>`.
All scratch/cache/output files stay on D under `routing-sensitivity-v13-.../`.

The alternative operations are `frame_bounds` and `expanded_paths`. One policy sees the
same type-blind syntax and scores full checking at 1.0, versus frame at 1.25 with a mask
cue, 0.75 for other supported frame syntax or 0 for unsupported syntax. B is scored before
candidate JSON is parsed. C/D preserve independent occurrence views through v12 mapping.
Their bounded contributor-mixture heuristic adds pointer/integer label support to the
frame score, with an explicit disjoint classifier (a pointer-to-integer is not an integer).
This support is not a semantic fact or joint correctness probability. See the
[complete preimplementation specification](../../docs/architecture/pilot_revision_v13.md).

All of [0,0.25,0.5,1,2] are reported, with primary weight 0.5, common policy/features/catalog
hashes and operation-ID tie-breaking. Masked inputs cannot change order under nonnegative
weights by construction. Unmasked inputs switch only above `weight * support > 0.25`;
the zero and 0.25 weights cannot switch. A first unknown would fall back to the other
operation, so report the complete order. The fixed full-first/frame-first controls are
orders, not newly executed measurements.

Inspect `run-plan.json`, all copied inputs/source hashes, `records.json`, per-case records
and `summary.json`. All three inputs, all 45 group/weight rows and missing-arm reasons
are retained. C/D failure never becomes an artificial B result. Shared static capture,
mapping, projection, per-arm grid selection and record persistence costs are recorded
as diagnostic work. The clock stops after complete-record persistence and summary
preparation; snapshots, historical GNN acquisition, command startup and final summary
serialization are outside it. These are not end-to-end deployment or budget results.

The Windows diagnostic now has 30/30 available C/D-versus-B comparisons and zero changed
orders, including the primary weight. Offset D has a nonzero signal but its threshold
2.369751 exceeds the declared grid; the input was not changed and the grid was not widened.
This is a negative routing result for this heuristic on three known integration inputs.
It neither rules out other schedulers nor demonstrates neural benefit. All 534 tests
pass; twelve OPM views validate. See the [audit](../../docs/pilot_evidence.md#v13-routing-sensitivity-gate).

WSL now reproduces all ten source/specification hashes, original/copied input identities,
type views, signals, scores, thresholds and full orders. All 45 rows and 30 comparisons
are available, with zero changes from B. Its 0.442573 s diagnostic-through-records clock
and 0.100349 s recording/summary-preparation component remain separate from historical
neural acquisition and command startup. They are not an environment performance comparison.
No rerun is required without a new question or change. See the
[WSL audit](../../docs/pilot_evidence.md#v13-wsl-routing-sensitivity-replication).

## Readonly-indirection capability mechanisms (v14)

Run from the project directory in the existing WSL `angr-env`:

```bash
python -B scripts/run_indirection_gate.py
```

Windows uses `py -3 -B scripts/run_indirection_gate.py`. No compiler, model, downloads,
packages, GPU or APIs are required. A fresh output root is created on D at
`.scratch/selective_analysis/indirection-gate-v14-.../`.

This generates exactly three separate authored ELF mechanisms: a 1024-element scalar
span, an immutable two-level pointer chain yielding offsets 2/6, and the same chain with
offsets 2/12 as an unsafe control. They are chosen for declared analysis needs and have
no GNN data. They are not pooled with the original twelve or the three compiled inputs.

All three run interval-only, finite-readonly-only, expanded-only and an actually executed
interval-then-finite fallback, each from a fresh entry in an isolated process. There is one
pass, not a statistical or speed experiment. The global finite cap is 32, instruction cap
128 and parent worker cap 30 s. Top is an overapproximation, not a sampled value subset.
Small constant masks can refine Top to their complete finite image. Readonly loads need
complete initialized file-backed nonwrapping spans, unique segments and no intersecting
relocation write. Mutable loads, unsupported effects and insufficient precision stay unknown.
The operation reports exclusion or unknown, never an abstract violation witness.

Each exclusion receives a fresh byte/data abstract recheck. After all twelve method
workers finish, three separate correctness-reference workers use literal BVV registers
to enumerate a domain of at most 32 assignments, or fresh symbolic scope checking for
larger domains. They recheck witnesses and all literal-input exclusions, and read neither
abstract certificates nor expected labels. This is modeled validation, not native replay.
Offline gold is loaded only after both sets of workers finish. Reference costs are separate;
they do not become free deployment features.

Inspect `run-plan.json`, all `workers/` requests/results/events/parent receipts,
`records.json`, `references.json` and `summary.json`. Unknowns, missing/late results and
failed attempts remain. Parent clocks include process execution and recovery, but exclude
final parent-record and aggregate serialization; stage sums are not complete costs.
No end-to-end policy speed or neural gain is claimed from these clocks.

The Windows run now retains all twelve method records and three complete references,
with no wrong decisions or disagreements. The safe scalar/chain contrast demonstrates
restricted capability complementarity; the unsafe chain receives no abstract exclusion.
All 587 tests pass; thirteen OPM views validate. The frozen selector is unchanged.
See [the audit and limits](../../docs/pilot_evidence.md#v14-readonly-indirection-mechanism-gate).

WSL now replicates all twelve sources/specifications, binary/query identities, method
statuses, abstract certificates and separate reference coverage. No wrong decisions,
reference disagreements or incomplete references remain. Its expanded/fixed-fallback
totals are 3.841506/0.736069 s, but each resolves a different two-query subset: full handles
the unsafe chain; abstract fallback handles the safe chain. These totals cannot be called
a same-quality speedup. See the [WSL audit](../../docs/pilot_evidence.md#v14-wsl-readonly-indirection-replication).

## Complete fixed non-neural cascade (v15)

This separate baseline uses only the three retained v14 binary/query inputs; it reads
no old method/reference result and adds no programs. The two methods are full-only
(`expanded_only`) and `fixed_cascade`, running interval, finite-readonly and expanded
checking in that order. Every attempt is fresh; a validated decisive result stops,
while unknown or a failed attempt advances within the same 30 s query budget. The
existing checkers, cap32, instruction limit128 and frozen A-D selector remain unchanged.

From the repository root in the existing WSL `angr-env`:

```bash
python -B scripts/run_fixed_cascade.py
```

Windows uses `py -3 -B scripts/run_fixed_cascade.py`. An optional `--input-dir` selects a
retained v14 root; otherwise the latest is discovered. No compilation, model, training,
packages, downloads, APIs or GPU are needed. All results/caches stay on D under
`.scratch/selective_analysis/fixed-cascade-v15-.../`.

Three repetitions rotate query order and alternate method order, producing eighteen
method/query records. These remain three unique authored mechanisms. All method workers
finish before three new separate label-free reference workers run; copied offline gold
is parsed only after references finish. Failed/late/missing outputs retain their planned
identities and candidate evidence. Actual worker Python/executable/dependency versions
are recorded, with provenance-lookup overhead included.

The parent-owned clock covers request serialization, process startup/imports, all checks
and fresh validation, event/result persistence, cleanup, recovery and complete detailed
trial-payload persistence. Final small accounting-receipt work, aggregate copying and
offline evaluation are explicitly outside it. The receipt contains the exact payload
SHA-256 and canonical fingerprint plus final status; late evidence counts as unknown.
Stage sums cannot replace the parent charge. This is a declared diagnostic boundary,
not a claim that receipt/evaluation work is free in deployment.

Inspect `run-plan.json`, copied `inputs/`, source snapshots, `records.json`, `references.json`,
per-worker `trial-payload.json`, `receipt.json`, `events.jsonl` and `summary.json`. The
evaluator validates the full 18+3 denominator, empty checkpoints, fresh evidence, payload
identities and reference agreement. It reports status vectors and separates common correct
results, cascade-only/full-only resolution, both unknown, failure and disagreement. Only
the same correctly resolved query/repetition pairs enter latency summaries; every first
trial remains included. Equal counts on different queries are never treated as equal quality.
Three repetitions of known inputs do not establish generalization or stable speed.

Windows validation retains all eighteen trials plus three fresh references. The cascade
correctly resolves all three queries in every repetition; expanded-only resolves two,
with the safe chain remaining unknown. All 665 tests pass and fourteen OPM views validate.
The predeclared rotation alternates methods globally but not fully per query: expanded-only
is first for the unsafe chain in all three repetitions. Filesystem caches were not reset.
This limits timing interpretation; all pairs, including first trials, remain retained.
WSL now reproduces all source/input identities, eighteen outcomes and sequences, abstract
certificates and fresh reference coverage. Runtime versions/costs remain separate. The
unsafe cascade is slightly slower in all three WSL matched pairs. No extra run is needed
to close this replication gate. See [the WSL audit](../../docs/pilot_evidence.md#v15-wsl-fixed-cascade-replication).

## Offline information-readiness gate (v16)

The main agent has already completed this gate on the retained WSL outputs. No new WSL
experiment, model execution, graph generation, property check or package is needed.
For offline reproduction on Windows only:

```powershell
py -3 -B scripts/audit_information_readiness.py
```

Optional `--cascade-dir`, `--location-dir` and `--profile-dir` choose retained v15, v12
and v5 roots. Defaults select the latest complete WSL cascade and existing frozen
location/acquisition panels. All outputs and copied inputs stay under D's
`.scratch/selective_analysis/information-readiness-v16-.../`. The diagnostic checks prior
source snapshots and records new immutable input/source copies plus integrity rechecks.

`availability.json` keeps all three complementary queries and all three genuinely typed
compiled queries separate. Raw scores/ranks are recomputed from the stored value-node
logits; existing bundle identities/bindings are checked without rerunning correspondence.
No exact mapped-query intersection exists. ELF debug-section presence is recorded but
never treated as proof of a working locator. Source excerpts retain the current DWARF/CFA
limits and upstream register/overwrite identity gaps for review.

`trace-headroom.json` recomputes the v15 complete evidence gate and retains all nine
cascade traces. An offline hindsight oracle deletes only preceding unknown attempts at
their recorded elapsed costs, leaving every other parent cost fixed. Its total deletion
is 0.420041 s. Imports/caches can move when work is removed, so this is conditional
accounting rather than an actual runtime upper bound, policy or neural gain. Historical
cold acquisition is separate context for a different query; no new-panel cost or warm
service is estimated. Tests use fabricated metadata, not extra benchmark programs.

The full suite passes 731 tests and fifteen OPM views validate. Inspect `run-plan.json`,
`input_snapshot/`, `source_snapshot/`, `source-findings.json`, `historical-context.json`
and `summary.json`. The separate offline auditor independently rechecks identities and
deletion arithmetic. See [the evidence](../../docs/pilot_evidence.md#v16-information-readiness-and-trace-cost-gate).

## Instruction syntax provenance (v17)

This separate prototype uses only the three original v15 binary/query identities. It
pins both binary and full query hashes, then strips runtime requests to binary/path/hash,
entry RVA and target-store RVA. Object location/capacity, input ranges, gold, raw types
and old evidence never reach the graph recorder. No compiler, model, graph generator
from TYGR, symbolic state, solver, training, API or GPU is used.

In the existing WSL `angr-env`, from the repository root:

```bash
python -B scripts/run_instruction_provenance.py
```

Windows uses `py -3 -B scripts/run_instruction_provenance.py`. No installation is needed.
`--input-dir` selects a retained v15 root; all copies/results stay under D's
`.scratch/selective_analysis/instruction-provenance-v17-.../`. Source/input identities are
snapshotted and rechecked. The strict ordinary straight-line subset is limited to 64
instructions and 4096 nodes; unsupported/partial cases remain unavailable in the report.

PyVEX lifts exactly one instruction at optimization level zero; Capstone checks the
boundary. Every RdTmp resolves a prior same-instruction WrTmp. Get freezes current byte
sources and Put updates only its real span; no final-state register value is read. AL/AH/
AX preservation and lifted EAX zero extension are tested. Loads remain opaque. Restricted
affine address syntax is compared with base/index/scale/displacement modulo 2^64, stopping
at current register-read nodes; this is not a general address/alias/property proof.

The parent separately replays graph structure, byte versions and temporary scopes, checks
fingerprints/dependencies/target completion, runtime metadata and forbidden imports, and
uses the remaining shared 30 s budget after request writing. Late/failed evidence remains
unavailable. The clock includes complete payload persistence; final accounting receipt
and aggregate serialization are explicit exclusions. Diagnostic times are not a policy
speed comparison. Decoder/lifter errors preserve already-recorded partial syntax.

Windows retains all three available graphs: 41/109/109 nodes, 1/3/3 memory bindings and
2/5/5 direct register-address bindings. Safe/outside graphs are identical while full-file
hashes differ. No readonly data values are loaded into the graph. All 871 tests pass;
sixteen OPM views validate. Existing TYGR export/graphs and frozen analysis stay unchanged.

Inspect `workers/*/request.json`, `worker-result.json`, `trial-payload.json`, `receipt.json`,
`records.json` and `summary.json`. The independent audit compares machine bytes and fresh
IR event sequences and replays register byte/temporary sources. This is not yet a TYGR
readout adapter or a neural-value experiment. See [the evidence](../../docs/pilot_evidence.md#v17-instruction-level-syntax-provenance).

WSL replication is now audited. All nine source and four input identities and all three
complete graph objects match Windows exactly, including nodes/edges, byte versions, scoped
temps, instructions and address bindings. WSL reports Python 3.10.20, PyVEX/archinfo
9.2.212, Capstone 5.0.6 and pyelftools 0.32; preserve its receipts separately from Windows.
The equal summary is not a speed or neural-value result. No new run is needed to close
this restricted syntax gate. TYGR's model-stack/readout context remains unvalidated.
See [the WSL audit](../../docs/pilot_evidence.md#v17-wsl-instruction-provenance-replication).

## Passive frozen-model interface audit (v18)

The main agent has completed this gate using existing files. No new WSL run, inference,
graph generation, package, training or GPU is needed. Optional offline reproduction:

```powershell
py -3 -B scripts/audit_tygr_interface.py
```

`--syntax-dir` selects a retained v17 root; `--model` must still match the pinned original
checkpoint SHA-256. Defaults select the existing WSL syntax panel and original model.
Input/source copies and all outputs stay under D's
`.scratch/selective_analysis/model-interface-v18-.../`. Both original and copied source/
input hashes are rechecked. Original bytes/query identities and serialized payload hashes
are verified, rather than relying on a same-directory plan alone.

The checkpoint reader uses a bounded `pickletools` interpreter. Globals, reducers,
constructors and state payloads stay symbolic; no original class, torch or tensor array
is instantiated. It records actual saved configuration, 40 parameter/storage descriptors,
encoder/decoder shapes and every saved RGCN layer capacity. Metadata omitted as nonprimitive
objects (type_set/archs) is listed explicitly instead of populated from source defaults.

`checkpoint-metadata.json` confirms input31/output75, but declared relation IDs0..59
against eight saved layers with capacity44/comp[44,10]. Potential IDs44..59 are outside
that layer domain. `interface-report.json` retains all three graphs: 259 nodes, 38 literal
candidates, 221 nonliteral nodes without upstream value semantics, 238 unmapped dependencies
and twelve unmapped readout candidates. No feature tensor, zero/unknown fallback or readout
group is constructed; `direct_bridge_ready` is false.

`source-findings.json` retains feature/context/row-axis source evidence. Successful old
forward calls do not prove every declared relation ID was consumed, and old raw exports
did not retain prepared edge tensors; the audit does not infer historical edge usage or
failure. A future input must satisfy the structural domain guard and an independently
specified semantic projection. All 948 tests pass; seventeen OPM views validate. The
independent audit checks raw scalar opcode witnesses, saved shapes/storage descriptors,
graph inventories and source/input identities without running a framework or model.
See [the evidence](../../docs/pilot_evidence.md#v18-frozen-model-interface-audit).

## Native preprocessing capture (v19)

From the repository root in WSL's existing `angr-env`:

```bash
python -B scripts/run_native_preprocessing.py
```

The parent automatically starts CPU-only children with the existing
`/root/miniconda3/envs/tygr-orig/bin/python`. No package, model, GPU, compiler or API is
installed or downloaded. All new outputs and caches remain under D's
`.scratch/selective_analysis/native-preprocessing-v19-.../`. Windows can run only
`py -3 -B scripts/run_native_preprocessing.py --prepare-only`; that snapshots and checks
identities without starting the original environment or observing native tensors.

This uses the retained v12 `direct_index`, `offset_index` and `masked_index` binaries,
not v17's three sectionless mechanisms. Binary/query/model identities are pinned, and
all project dependencies and original TYGR Python sources are copied/hashed. Native
requests omit property bounds, expected answers, raw predictions and prior proof records.
The pinned checkpoint loads on CPU for its actual configuration and layer capacities;
every loaded module's forward is replaced with a rejecting guard before any preparation.

The unchanged original DWARF-assisted generator uses symbolic execution for graph features.
Its accompanying gold output is discarded. Each nonempty function is retained before
preprocessing, so a later preparation/collation error preserves original graph/variable
data. Captures include complete NodeLabels, native iteration order, all prepared tensors,
edge IDs, original groups, flattened rows and collated gather/scatter. The original edge
encoder returns the ID of the first sorted label because its return is inside the loop;
see [the correction](../../docs/architecture/pilot_revision_v19_erratum.md). Architecture-token zeros, unknown labels,
node-order issues and capacity violations remain findings; they do not trigger forward
execution or silently discard a capture. The installed RGCN method source is recorded,
not executed to test bad IDs.

Inspect `run-plan.json`, `expected-model-contract.json`, `workers/*/request.json`,
`capture.json`, `trial-payload.json`, `receipt.json`, `worker.log`, `records.json` and
`summary.json`. The parent charges each request through validation and complete payload
persistence against 60 s; snapshot setup, final accounting receipt and aggregate/offline
evaluation are excluded. A killed worker's intermediate snapshot and a parent-generated
recovery receipt cannot establish verified final native no-forward coverage. Failures
stay in the three-case matrix, are logged, and produce a nonzero final command exit.

Windows preflight independently verifies all 79 source files, eight input files and
three pinned identities without launching native workers. All 1061 project tests pass;
eighteen OPM views validate. Selected worker stage timers include failed preparation
and native conversion/persistence; they are diagnostics rather than an additive full
cost decomposition. The parent interval remains authoritative.

The current check is an input-contract diagnostic, not inference, accuracy, scheduling
throughput, historical edge usage or a validated v17 projection. WSL collection is now
audited: three captures, 86 nodes, 103 native edges, 206 directional relation entries,
six original variables and twenty flattened rows. Every observed ID fits the saved
capacity. All 103 edges have one label, so the encoder correction changes no observed ID.
Independent checking reproduces 26/31 feature columns; the remaining five depend on
unretained runtime architecture attributes. No rerun is needed to close this gate.

Optional offline review from Windows or the existing parent environment:

```bash
python -B scripts/audit_native_preprocessing.py
```

This reads retained artifacts, checks source/input/request/payload/budget identities and
writes `validated-audit.json`; it does not launch TYGR or a framework. The historical
79-file source snapshot remains unchanged, while the live validator has the documented
encoder correction. See [the WSL audit](../../docs/pilot_evidence.md#v19-wsl-native-preprocessing-audit).

## Native readout group and frontier correspondence (v20)

This gate can run locally using the retained Linux v19 native artifacts; no new WSL run,
inference, graph generation, compilation or environment change is needed. Optional
reproduction from the project root:

```powershell
py -3 -B scripts/run_native_readout_correspondence.py
```

`--native-dir` selects the retained audited v19 capture root. The entry first verifies
its original identities/receipts. It copies the same three ELF/query/capture sets,
projects each query to exactly binary/hash, entry/write RVAs and capture fingerprint,
and freshly decodes canonical address-load syntax with the restricted v12 static walker.
Object bounds, input ranges, expected answers, historical type scores and role proofs
do not enter correspondence. No type names, exporter IDs, sampled values or variable
names select a group. Unique physical CFA metadata and lifetime covering load/use do.
This is a location-metadata association, not a storage-extent or live-value equality proof.

Every original group and row remains in order. Annotation-PC coincidences are reported
without selecting rows. Native graph inspection retains all byte-sized mem_loc targets
at the declared annotation address; same-root candidates remain distinct. Reverse
data/operator traversal stops at first readout members and records path witnesses,
blocked edges, cycles and revisits. It excludes entire mixed location/unknown edges.
These are exploratory native-graph paths on known developer inputs, without event/role
or semantic dependency-completeness proof. Predictions are not recomputed from a selected
frontier subset. Whole-variable groups can still be tested as coarse ranking features.

Outputs are under D's `.scratch/selective_analysis/native-readout-v20-.../`. Inspect
`run-plan.json`, `source-semantics.json`, `native-audit.json`, `cases/*/request.json`,
`cases/*/record.json`, `records.json` and `summary.json`. Source snapshots include executed
package initializers; the entry also inventories every loaded local Python module and
rejects omissions. Each analysis uses the same retained native inputs and preserves
failed/unavailable cases in the three-query/six-occurrence denominator. Per-case time
excludes historical native acquisition and global preparation; it is not deployment
cost, a budgeted scheduler trial or evidence of speedup.

Six of six load occurrences associate with whole-variable groups. Each graph has two
native target candidates sharing one address root and reaches two readout members.
All twenty original rows survive. Only three groups have any PC-coincident row; none
has an exact-event proof. The independent replay checks source/input hashes, actual ELF
trace bytes and contiguous addresses, physical group joins and BFS frontier membership/
path witnesses. No neural gain or held-out evaluation is measured. See
[the evidence](../../docs/pilot_evidence.md#v20-native-readout-group-and-frontier-correspondence).
The final retained run has nineteen source/evidence files, thirteen inputs and no
untracked loaded local Python modules. All 1183 project tests and nineteen OPM views pass.

## Compiled typed-complementarity readiness (v21)

From the D-drive project root in WSL, using the existing parent environment:

```bash
conda activate angr-env
python -B scripts/run_typed_complementarity.py
```

The script compiles exactly three authored functions into one PIE ELF with DWARF4,
then extracts one fixed byte-write query per function. The scalar span and safe/outside
readonly-offset-table patterns are a new development panel related to v14, not binary
replications or extra primary/held-out samples. Two translation units and no LTO preserve
the readonly loads. The explicit 64-bit mask and register barrier are predeclared authored
choices, not adaptations based on model predictions or experiment results.

One fresh child in `/root/miniconda3/envs/tygr-orig/bin/python` shares the frozen CPU
model across the binary's native function inputs. It records the complete pre-forward
native graph/groups/tensors and rejects unsupported feature/relation/readout domains
before invoking the model. Original architecture token, graph order and aggregation are
preserved. Genuine Top-K means original whole-variable raw-logit means, not calibrated
probabilities. Gold output from the locator is discarded. Partial native records and
domain errors remain on disk; no input remapping, model training or layer changes occur.

Independently of acquisition success, all three extracted queries run interval-only,
finite-readonly-only, expanded-only and fixed interval/finite/expanded cascade controls,
plus separate modeled references. The implementation bodies are unchanged. Runtime
requests accept no gold/type features. Every control/reference has a shared 30 s parent
cap through complete payload persistence; the one cold acquisition has 120 s. Failed,
missing or timed-out controls cannot count as demonstrated capability differences.
Three planned queries remain the denominator even if compilation/extraction fails.

All outputs/cache/binaries stay under D's
`.scratch/selective_analysis/typed-complementarity-v21-.../`. Inspect `compile.log`,
`compiler-version.log`, `extracted-queries.json`, `acquisition.json`, `acquisition/worker.log`,
`acquisition/candidate.json`, `controls/*/*/{candidate,payload,receipt}.json`, `records.json`
and `summary.json`. Original/copy source hashes, model identity and the full original TYGR
inventory are rechecked. A nonzero exit retains failures and logs; it is not an instruction
to install or replace packages automatically.

The summary separately reports eligible genuine function outputs, observed operation
capabilities, their overlap, unknowns/reasons, reference disagreements and paid cold
cost. Function-level availability is not an exact use-site/semantic-role mapping. Cold
acquisition cost is shared over three queries and compared descriptively with the fixed
control total; one pass proves no runtime bound, speedup or stable end-to-end gain.
Compilation, source snapshot setup, final accounting receipt and offline evaluation are
outside those per-worker clocks. The frozen A-D selector remains unchanged.

Windows supports `py -3 -B scripts/run_typed_complementarity.py --prepare-only`. This
checks/snapshots 119 source files and the pinned model and launches no compiler, native
model or operation worker. Windows MinGW syntax-only checking has passed; Linux GCC code
generation, optimized DWARF availability, model coverage and checker support are still
unverified. All 1233 project tests and twenty OPM views pass. See
[the preflight evidence](../../docs/pilot_evidence.md#v21-compiled-typed-complementarity-preparation).

## Same-ELF location-base repair (v22)

**Current correction: v22.1.** The first native adapter run retained its scalar output
but failed complete-trace admission. The corrected code supports the public old/new
pyelftools entry layouts and records the actual version/API plus detailed location
errors. The same command below now creates a distinct v22.1 run. Preserve v22 results.

The corrected WSL acquisition is now audited at 3/3 function coverage, seven variable
records and three guarded forwards, with no location errors. No rerun is needed to
close this repair. See [the successful audit](../../docs/pilot_evidence.md#v221-successful-wsl-repair-audit).

The audited v21 run completed fifteen controls/references with zero wrong decisions,
but genuine native outputs covered 1/3 queries. Eight relative DWARF list entries in
the two table functions use incorrect bases in original TYGR. This diagnostic repairs
only location-list address translation and reacquires predictions on the retained ELF.
It preserves the original TYGR files, model, preprocessing, checkers and old artifacts;
no new compilation or property-control run is needed.

In the existing WSL project directory, with angr-env active:

```bash
python -B scripts/run_location_repair.py
```

The script automatically uses `/root/miniconda3/envs/tygr-orig/bin/python` for one cold
CPU acquisition. The current interpreter prepares/audits files only. No environment
activation inside the script, installation, download, training or API is required.
It expects retained v21 root `typed-complementarity-v21-20261113-124728-819` under the
parent `.scratch/selective_analysis/`, verifies its anchored evidence and exact ELF,
and archives 124 sources and six inputs. All output/cache remains on D at
`.scratch/selective_analysis/location-repair-v22-1-.../`.

The external runtime adapter resolves DWARF4 relative ranges against the CU or latest
selected base. Single-expression bounds and original expression handlers stay intact.
Before model forward the archived worker validates the actual CPU tensor, relation,
endpoint and readout domains. The parent requires a matching offline/runtime adapter
trace and validated raw logits before admitting function-output coverage. A 120 s
parent cap includes the cold wrapper/setup/imports/model/generation/guard/export path
through persisted payload. Preflight, final receipt/reporting are excluded.

Inspect `summary.json`, `acquisition/worker.log`, `acquisition/adapter-api.json`,
`acquisition/adapter-trace.json`, and `acquisition/adapter-errors.json` if created,
`acquisition/native-candidate.json`, request/payload/receipt files, and the captured
native graph/readout data. Partial/missing outputs remain visible. Exit status 1 can
mean coverage is still below 3/3, so retain and share the complete summary and log.
The variant is explicitly marked `external_dwarf4_location_base_adapter_v22_1`.
`runtime_pyelftools`, `entry_api` and `location_errors` expose the compatibility
boundary. Accepted coverage requires the complete matching adapter trace and guarded
raw logits; a rejected acquisition can still retain inspectable genuine prefix outputs.
No exact-event mapping, correct-type, neural-value or performance claim follows from
coverage alone. Prior fixed-control costs are historical, not new timed trials.

Windows supports `py -3 -B scripts/run_location_repair.py --prepare-only`; it runs
offline location projection only and performs no native inference. See
[the frozen scope](../../docs/architecture/pilot_revision_v22.md),
[compatibility correction](../../docs/architecture/pilot_revision_v22_1.md),
[OPM view](../../docs/architecture/location_repair.svg) and
[audited evidence](../../docs/pilot_evidence.md#v221-old-pyelftools-compatibility-correction).

## Retained type-information collision audit (v23)

This completed offline diagnostic reuses the successful v22.1 acquisition and historical
v21 control records. It adds no case, compilation, inference, property execution or
selector. Run from the repository root only to reproduce the already completed audit:

```bash
python -B scripts/audit_type_information.py
```

On Windows use `py -3 -B scripts/audit_type_information.py`. Existing data must include
`location-repair-v22-1-20261113-162629-1577` under the parent `.scratch/selective_analysis/`.
The script verifies acquisition/source/input anchors and raw logits, constructs separate
identity-free whole-function Top-1/Top-K/full-logit views, and only then parses historical
operation outcomes. It also hashes exact prepared and actual collated model inputs.
All three query pairs stay visible; variable names and address IDs are not features.
Full function groups are retained without claiming exact use-site/role correspondence.

Outputs remain on D at `.scratch/selective_analysis/type-information-v23-.../`: inspect
`representations.json`, `pair-comparisons.json`, `summary.json` and the source/input
snapshots. The observed table pair has identical model inputs and complete 75-class
outputs despite different historical capabilities. This does not establish scheduler
benefit or rule out other structural evidence/adaptive fallback. The recorded 8.305 s
cold acquisition and 2.162 s historical fixed-cascade total are descriptive separate
stages/runs, not a matched end-to-end result or speedup bound.

No model/solver framework is imported or new worker launched. The three-query panel is
known development data, not held out. Preserve its role as regression/cost control;
do not tune a type weight to force a positive difference. See
[the scope](../../docs/architecture/pilot_revision_v23.md),
[OPM view](../../docs/architecture/type_information.svg) and
[audited evidence](../../docs/pilot_evidence.md#v23-retained-type-information-collision-audit).
