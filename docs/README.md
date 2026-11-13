# Documentation map

The active project studies property-directed scheduling under a fixed budget. The
earlier 13-stage pipeline remains a separate implementation. Its version numbers and
metrics must not be confused with development revisions of the frozen pilot.

## Current guides

| Document | Read it for |
|---|---|
| [Overview](../README.md) | Purpose, research questions and a minimal run. |
| [Status](STATUS.md) | Latest v23 evidence, limitations and next gate. |
| [Architecture](architecture.md) | Frozen protocol, contracts and implementation boundary. |
| [OPM profile](architecture/README.md) | DOT notation, 22 views and rendering instructions. |
| [Pilot guide](../benchmarks/selective_analysis/README.md) | CLI protocols and chronological diagnostic commands. |
| [Reproducibility](REPRODUCIBILITY.md) | Public files, external dependencies and local receipt replay. |
| [Runtime compatibility](VERSION_COMPAT.md) | Measured Windows/WSL and native TYGR environments. |
| [Synchronization verification](VERIFICATION.md) | Local/public-export tests, optional skips and rendering checks. |
| [Research write-up](PAPER_MATERIAL.md) | Supportable observations and missing evidence. |

## Frozen specifications and evidence

The `architecture/pilot_revision_v*.md` files are stage-specific specifications, including
the [v19 erratum](architecture/pilot_revision_v19_erratum.md) and
[v22.1 correction](architecture/pilot_revision_v22_1.md). They retain assumptions and
pending work at their time of writing. [Current status](STATUS.md) identifies the latest
completed gate; frozen protocol details retain their own scope.

[pilot_evidence.md](pilot_evidence.md) is a chronological index of locally retained
receipts, including failed attempts and corrections. Hashes and paths do not mean the
raw bundles are published. The [operation-selection gate](architecture/operation_selection_gate.md)
is a historical decision log, not the current task list.

## Legacy implementation records

These describe `src/pipeline.py` and its different evaluation protocol. Historical
percentages are not results for the frozen A-D pilot.

- [Internal modules and stages](INTERNAL.md)
- [GNN integration](GNN_INTEGRATION.md)
- [Juliet pilot](JULIET_PILOT.md)
- [Implementation log](IMPLEMENTATION_LOG.md)
- [Archived architecture](archive/architecture_v13.md)
- [Original environment recovery notes](../output/tygr/RESUME.md)

Juliet's generated `SUMMARY*.txt` files remain unedited historical output. Use the
scope statements in the Juliet guide when interpreting them.
