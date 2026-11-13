# Reproducibility and artifact availability

Updated 13 November 2026. This guide separates clean-checkout experiments from
diagnostics that replay locally retained development receipts.

## Distributed files

The repository includes the selective-analysis implementation, authored mechanism
generators and C sources, synthetic test fixtures, frozen specifications, OPM DOT
sources and SVG renders. The pilot is independent of `src/pipeline.py`.

Upstream TYGR source, weights, Conda environments, generated ELF files, library caches
and historical raw `.scratch` bundles are not distributed. The [evidence log](pilot_evidence.md)
records observations and artifact identities, not a downloadable raw dataset. Hashes
alone do not make a run replayable.

## Tier 1: clean-checkout mechanisms and tests

Use a Python environment with [pilot dependencies](../benchmarks/selective_analysis/requirements.txt).
The measured Windows environment was Python 3.13.10, angr/claripy 9.2.217 and pytest 9.0.3.
The WSL analysis environment used Python 3.10.20 and angr 9.2.212; these are distinct
runtimes. See [compatibility](VERSION_COMPAT.md). From the repository root in PowerShell:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
$env:TEMP='D:\AI_Models\symbolic\.scratch\selective_analysis'
$env:TMP=$env:TEMP
py -3 -B -m pytest tests -q -p no:cacheprovider --basetemp=D:/AI_Models/symbolic/.scratch/selective_analysis/pytest-public
py -3 -B scripts/validate_architecture.py --render
py -3 -B scripts/run_selective_pilot.py --make-mechanisms --variants A B --budgets 1 --output D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot
py -3 -B scripts/evaluate_selective_pilot.py --runs D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot/runs.json --gold D:/AI_Models/symbolic/.scratch/selective_analysis/mechanisms/gold.json --output D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot/evaluation.json
```

Create the scratch directory before assigning it as TEMP if absent. Use fresh output
and basetemp names. `src/selective_analysis/workspace.py` sets the default scratch root
relative to the checkout's parent; moving the checkout changes that root. Keep generated
files on the intended data drive. Graphviz is needed for `--render`; SVGs are included.
On Windows, use a short checkout-parent path: nested provenance fixtures can exceed
legacy directory-length limits in a deeply nested checkout (`WinError 206`). A shorter
snapshot parent resolves that environment limitation without changing the test cases.

Run `pytest tests`, not the repository root: optional upstream trees contain CLI modules
named `test.py` that are not this suite. Seven parser checks, four native-encoder checks
and one checkpoint check need optional upstream source/weights and skip when those files
are absent. Available but invalid artifacts must still fail. Other synthetic tests run
with the declared dependencies.

The twelve generated mechanisms are developer examples, not a held-out benchmark.
C/D without genuine accepted type artifacts remain unavailable. This A/B run does not
simulate neural predictions or answer RQ1/RQ2.

## Tier 2: optional native acquisition

Genuine exports use separately obtained [TYGR](https://github.com/sefcom/TYGR) source and
the pinned GlowGNN checkpoint in a compatible isolated runtime. The observed runtime is
Python 3.8.10, torch 1.8.1+cpu, torch-geometric 1.7.0, angr/pyvex 9.0.7491 and pyelftools
0.27. CPU acquisition is supported; training and a GPU are unnecessary. Audits do not
implicitly install environments or modify upstream source.

The measured checkpoint SHA-256 is
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.
The saved model has 31 input features and 75 classes. Its declared relation domain has
60 IDs while eight saved RGCN layers have capacity 44; actual prepared inputs must pass
domain checks. Neither runtime version alone guarantees valid inputs. Raw scores are
not calibrated correctness probabilities.

Follow the [pilot guide](../benchmarks/selective_analysis/README.md) for preparation,
compilation and acquisition commands. WSL paths refer to the observed `/mnt/d` workspace.
The interface uses DWARF-assisted locations without supplying ground-truth type labels to
the network. A compiler/runtime change can alter ELF hashes, locations and eligibility;
a new compilation is a new artifact, not the old experiment.

The current repair is external to original TYGR. Legacy self-trained models and constant
confidences cannot replace genuine C/D inputs. Model loading, graph creation, mapping,
selection, checking and validation contribute to end-to-end cost. Report cached/shared
costs with the actual number of queries served.

## Tier 3: historical receipt replay

Many versioned diagnostics select or pin previous `.scratch` bundles. Examples include
`run_native_readout_correspondence.py` (v19 inputs), `run_location_repair.py` (the v21
ELF) and `audit_type_information.py` (successful v22.1 repair). Other drivers locate
earlier bundles by glob. These are replay procedures for specific retained artifacts,
not fresh-checkout one-command experiments.

If the expected bundle is absent, do not fabricate it, replace its hash or reinterpret
a fresh run as the recorded experiment. Use Tier 1, collect an explicitly identified
Tier 2 run, or obtain the original bundle separately. Source copies/input identities
are part of admission checks. Failed receipts remain failures.

## Interpretation rules

- Count fixed queries/programs, not variables, readout rows, repetitions or repeated
  diagnostics. The v21/v22.1 panel has three functions in one ELF, not three projects.
- Gold labels are offline. Split future data by program/project before tuning.
- B/C/D keep the same selector and non-type inputs; changing both algorithm and type
  input cannot isolate the information's contribution.
- Exclusions cover only the declared query. Unsupported behavior and incomplete evidence
  retain `unknown`; native replay is absent.
- The v23 collision and cold costs do not establish neural benefit, paired speedup,
  general impossibility or an independent publication contribution.
