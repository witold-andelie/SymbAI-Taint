# Public synchronization verification

Recorded 13 November 2026 for the v23 documentation/public-tree synchronization.
These are software/reproduction checks, not new independent research samples or evidence
of neural scheduling benefit.

## Test and architecture results

| Check | Observed result |
|---|---|
| Complete local checkout, optional upstream source/checkpoint present | 1,285 passed, 19 dependency warnings; 79.86 s. |
| Export of staged public files, upstream source/weights/raw receipts absent | 1,273 passed, 12 optional skips, 19 dependency warnings; 53.46 s. |
| OPM contract validation and SVG rendering | 22 views, 440 view-local nodes, 593 links; passed. |
| Markdown relative file targets | No missing file targets. |
| Current-guide local heading links | No missing targets. |
| Staged patch whitespace validation | Passed. |
| Public-export quickstart, twelve authored mechanisms, A and B | Each resolved 12/12 with zero wrong/unknown decisions at a 1 s information-only analysis budget. |

Tests used Windows Python 3.13.10 with angr/claripy 9.2.217 and pytest 9.0.3. The
public export used the same installed Python dependencies; it was not a new minimal
environment installation. No WSL process, native model forward, training or API call was
needed for these checks. Deprecation warnings came from existing torch/PyG imports in
the legacy structure smoke test; those three legacy smoke checks do not establish
the earlier pipeline's correctness.

The quickstart ran from the public export using only freshly generated mechanisms and
its separate offline gold file. Preparation is outside the charged information-only
budget. This is a CLI reproduction check on known fixtures, not an end-to-end timing
comparison or independent evaluation.

The twelve public-export skips comprise seven optional upstream-location-parser checks,
four optional upstream-encoder checks and one optional real-checkpoint check. Synthetic
contract, checker and CLI tests still run. The parser fixture now skips only when the
upstream source is absent; it does not suppress invalid available inputs.

An initial public export under a longer nested path had 1,272 passes, twelve skips and
one `WinError 206` directory-length failure while constructing an archived test fixture.
Repeating the unchanged suite under a short D: parent produced the successful public
result above. The [reproducibility guide](REPRODUCIBILITY.md) records that Windows limit.

## What was checked for publication

The staged tree includes the previously local selective-analysis implementation,
authored fixtures, tests and protocol/diagram sources needed by the updated guides.
This avoids publishing documentation whose required modules are missing from Git.

The file inventory excludes private sibling materials, upstream source, model weights,
generated binaries, caches and historical raw receipt bundles. A targeted credential
and correspondence-pattern scan found no matches. This is an inventory/check result,
not a claim that private raw artifacts have been published. See
[artifact availability](REPRODUCIBILITY.md).

Frozen revision specifications and the chronological scientific observations retain
their original scope. Current entry points distinguish development v23 from the
legacy 13-stage pipeline, explain the representation collision and separate descriptive
cold costs from a paired end-to-end comparison.
