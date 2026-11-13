# Development correction v22.1: old pyelftools location-entry compatibility

Declared on 13 November 2026 after auditing the failed v22 WSL acquisition and before
changing the adapter. RQ1/RQ2, the three retained queries, ELF, original TYGR files,
model and property controls remain unchanged. This corrects an implementation defect;
it does not add a scientific mechanism or a new sample.

The v22 run at `location-repair-v22-20261113-161334-1554` retained one complete,
guard-passed scalar output, identical to v21. Its adapted coverage was correctly
rejected (0/3) because only one of seven expected location records appeared. The
lookup layer swallowed six location exceptions. The actual exception types and
pyelftools runtime version were not recorded, so do not invent them retroactively.

The upstream environment declares pyelftools 0.27. Its official LocationEntry is a
four-field namedtuple without `is_absolute`; the first adapter unconditionally reads
and replaces that field. A local regression must reproduce that failure with the
exact old interface before fixing it. Modern-interface-only replay missed this seam.
Primary API source: [pyelftools v0.27 locationlists.py](https://github.com/eliben/pyelftools/blob/v0.27/elftools/dwarf/locationlists.py).

## Narrow correction and replay

Support only the explicit known four-field DWARF4 entry layout and modern six-field
layout. Old DWARF4 entries are relative to the CU/selected base; modern entries retain
their explicit absolute flag. Preserve the concrete tuple class and replace only its
declared fields. Reject unknown layouts before generation/model forwarding. Keep
expression handlers, semantic trace fields, selected-base rules and guards unchanged.
Record actual pyelftools version and observed entry layouts. Persist detailed location
errors at the adapter boundary before the original lookup can swallow them. Any such
error marks the adapted acquisition invalid, even if original generation continued.

Repeat the v22 single-acquisition protocol on exactly the same retained ELF with the
existing CPU environment. Use a distinct v22.1 artifact prefix/variant; archive the
updated source and both specifications. Preserve all v22 measured copies and outputs.
No compilation, new property trial, installation, training or new selector is required.
Apply the same 120 s parent cost cap and full trace/raw-logit admission checks. Keep
all outputs/cache on D. Complete regression/full checks and actual-ELF offline replay
through both entry layouts before the user-run native acquisition.

Full function coverage after this correction is still a hypothesis. It does not
establish use-site mapping, type correctness, neural gain or equal-budget improvement.
