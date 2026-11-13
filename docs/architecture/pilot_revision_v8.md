# Development revision v8: two additional compiled developer queries

Declared before implementation and acquisition on 11 November 2026. Prior results,
selector parameters and the original twelve mechanism denominator remain unchanged.
This is a separate two-query mapping/validation track, not held-out evaluation or a
neural scheduling comparison. Together with the original probe, it can provide three
compiled query inputs if both acquisitions and mappings succeed.

## Fixed queries

Compile two separate small C programs, each with one eight-byte global object and one
noinline write function. Query that function at its first byte-write visit, with entry
RDI in [0,15], regardless of the fixed call in main.

- `offset_index`: replace the index with entry index plus four modulo 64 bits, then write.
  It is an unguarded affine-offset variant of the existing address-offset mechanisms.
- `masked_index`: replace the index with entry index AND seven, then write. It represents
  the existing masking mechanism in a separately compiled program.

The source programs and query specifications contain no result labels. Keep expected
query outcomes in a separate offline file, read only after all runtime cases finish.
Retain both planned cases, including compile/export/extraction/mapping failures and unknowns.
Do not replace a case after seeing predictions or results. These authored developer
queries are not independent projects or unseen test data.

## Mapping extension

Add operand-plan v2 with a small checked index-expression vocabulary: entry-input plus
an unsigned constant or entry-input bitwise-AND a constant. These expressions are claims
to verify, never extra solver constraints. The v7 identity-input plan and its recorded
evidence remain supported unchanged.

For each compiled function, extract its entry, target byte-write and object from ELF
symbols/instructions. Consider raw function/location metadata only. Require exactly two
eligible eight-byte CFA-relative prediction locations; enumerate their two base/index
assignments. Verify both using fresh program states. Accept only one verified assignment
with every alternative explicitly rejected, then independently recheck the accepted plan.
Missing/ambiguous locations or unknown alternatives retain unknown. No name matching,
candidate labels, model scores or expected outcome selects the binding.

## Acquisition and validation

In existing WSL angr-env, use GCC with DWARF 4, O0, PIE and frame pointers, and tygr-orig
for one fresh CPU export per binary. Pin the existing model hash, use one BLAS thread,
new acquisition IDs and D-drive caches. No download, package installation, training,
external API or additional hardware is required. Archive sources/specification first.
Compilation and isolated query extraction each have 30 s per case; export 120 s;
mapping 20 s total across two proposals and
the accepted-plan recheck. Run the unchanged symbolic property checker with a 10 s cap
including fresh result validation. Preserve all logs, raw scores, proof attempts and failures.

Export role-qualified bundles and candidate-free common facts only for verified mappings.
Then join the two expected labels offline and report property-check correctness separately
from mapping status. Mapping failure does not remove a query from the property denominator.
No role view enters the frozen selector in this revision. Future comparisons must expose
the same program facts to B/C/D and charge real acquisition/mapping costs under their
declared budget regime.
