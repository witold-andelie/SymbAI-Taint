# Runtime compatibility and environment boundaries

Updated 13 November 2026. These are measured development environments, not claims about
the latest available packages. Existing working environments need no reinstall for
documentation or offline receipt audits.

## Measured environments

| Component | Windows analysis/tests | WSL analysis (`angr-env`) | WSL native TYGR (`tygr-orig`) |
|---|---|---|---|
| Python | 3.13.10 | 3.10.20 | 3.8.10 |
| angr / claripy / pyvex | 9.2.217 | 9.2.212 | 9.0.7491 |
| PyTorch | Not required for model-free pilot | 2.11.0+cpu observed | 1.8.1+cpu |
| torch-geometric | Not required for model-free pilot | 2.7.0 observed | 1.7.0 |
| pyelftools | 0.33 | Distinct runtime; retain receipt metadata | 0.27 |
| pytest | 9.0.3 | Not installed in the initial environment report | Not needed for native acquisition |

The modern process and original-model process communicate through explicit artifacts
and subprocesses. Do not load the old whole-object checkpoint in a modern PyG process
and assume identical behavior. The existing [pilot requirements](../benchmarks/selective_analysis/requirements.txt)
describe the model-free test stack; [reproducibility](REPRODUCIBILITY.md) provides commands.
The diagram validator only needs Python and Graphviz.

## Frozen checkpoint and input contract

The genuine acquisition uses [TYGR/GlowGNN](https://github.com/sefcom/TYGR), observed at
`model/MODEL_base/x64.O0.base.model`, SHA-256
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.
It has 31 input features, 75 output classes and an independent decoder. A filename
suggesting O0 is not sufficient evidence of the model's complete training domain;
the O1 developer compilation remains an explicit evaluation condition.

Passive inspection found a saved preprocessing domain of 60 relation IDs versus
capacity 44 in all eight saved RGCN layers. IDs 44–59 cannot be admitted to those layers.
This does not prove that old pyvex has exactly 44 operations or that historical forwards
used out-of-domain edges. Actual prepared inputs require endpoint, feature, edge and
readout checks in either runtime. The three v19 captures observed IDs no greater than 37.
The upstream encoder selects the **first sorted edge label**; see the
[v19 correction](architecture/pilot_revision_v19_erratum.md).

## Location compatibility and current repair

The successful v22.1 WSL run observed pyelftools 0.27 entries with four fields:
`entry_offset`, `begin_offset`, `end_offset`, `loc_expr`. Its base entries have two
fields. The external adapter supports that known API and the modern six-field API;
unknown forms fail closed. It applies the compilation-unit or selected base to relative
location ranges, preserving expression handling and explicit trace provenance.

The adapter and acquisition wrappers live in project scripts. **Original TYGR source
and weights are unchanged.** The failed first v22 attempt remains failed; corrected
admission requires the full matching trace and guarded raw scores. See
[repair evidence](pilot_evidence.md#v221-successful-wsl-repair-audit).

DWARF-assisted extraction locates variables without supplying true type labels to the
network. It is not an end-to-end DWARF-free pipeline. Precise use-site/event mapping
and whole-variable association have different scopes.

## Working without the optional native stack

No model, GPU or API is needed for A/B developer mechanisms, synthetic tests or DOT
validation. Tests that explicitly compare optional upstream files skip if those files
are absent. Historical-receipt audits additionally need their exact excluded local
bundles; acquiring a new model output does not recreate an old receipt.

C/D require accepted genuine type outputs. Do not replace missing data with the legacy
constant confidence `0.9`, guessed probabilities or a self-trained fallback. Softmax or
raw scores are not calibrated probabilities without a separate calibration experiment.

## Legacy setup and fallback notes

The earlier pipeline's [recovery notes](../output/tygr/RESUME.md) and
[implementation log](IMPLEMENTATION_LOG.md) preserve old build scripts, dependency
pinning, local source patches and synthetic self-training experiments. They are historical
procedures, not the active pilot's compatibility guarantee or automatic repair recipe.
In particular, patching model layer capacity changes the model contract; it is not an
acceptable silent fix for the frozen checkpoint.

Keep native work in its isolated environment, place temporary files/caches on the data
drive and preserve compiler/runtime metadata with every run. Do not overwrite existing
working environments to replay an old setup command.
