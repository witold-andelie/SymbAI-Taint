# Development revision v22: DWARF4 location-base repair replication

Declared on 13 November 2026 after auditing v21 and before implementing this repair.
The retained v21 ELF has SHA256
`b3b8eb8a03d09112ef513aea572a840c547161bb41c7041386b2f7616267d9ed`.
All fifteen controls/references completed with zero wrong decisions, but genuine native
outputs covered only one of its three queries. The other functions contain DWARF
variables. Their eight relative location entries are translated with function starts
by the old parser, rather than their compilation-unit base; five resulting intervals
are wholly outside their functions. This is an independently observable location bug,
not proof that repairing it will restore all model outputs.

## Frozen intervention

Reuse exactly this ELF, three query identities and v21 sources/model. Do not recompile,
add samples, rerun property controls or alter old artifacts. Snapshot a new external
adapter and wrapper. At runtime only, wrap the two original location-list entry points
and their lookup aliases. For DWARF4 lists, resolve relative ranges against the latest
base-address selection, or the CU's DW_AT_low_pc when none precedes them. Preserve
absolute entries. Reject missing bases, invalid addresses and unrecognized entries.
Keep original expression parsing, acceptance, variable ordering, grouping, preprocessing,
weights and whole-variable aggregation. Single expressions retain the original function
range. Zero-length list entries have no effect. No generic DWARF5 or type-inference fix.
The wrapper explicitly records that this is an adapted acquisition; it must not be
presented as the unchanged native pipeline. Original TYGR files remain untouched.

Use the archived v21 acquisition implementation and its saved-input guard. The new
standalone wrapper verifies its own, adapter and archived-helper identities, rechecks
all original sources/model/ELF, and preserves old worker validation. Persist the adapter
range trace and raw native output even on failure. The parent charges one cold 120 s
request-through-payload-persistence acquisition including imports, repair setup and
serialization. Preparation/audit/final reporting are outside that diagnostic clock.
Windows supports offline preparation only; actual inference requires the existing WSL
tygr-orig environment. Keep all new outputs/cache on D.

## Interpretation

Report old/new function-output coverage over the same three queries, genuine variable
and row counts separately, adapter changes and failures, guarded forward accounting and
costs. Keep missing outputs, unsupported expressions and incompatible relation domains.
Reuse v21 property-control outcomes only as historical evidence, not new timed trials.
Even full coverage does not establish exact-event mapping, correct predicted types,
neural information value, selector performance, statistical speed or held-out results.
The next research decision remains whether type features add value beyond an equally
informed structural scheduler and the fixed cascade. Do not add a selector in this fix.

DWARF4 section 2.6.2 defines the location-list base rule (printed pages 30–31):
[DWARF4 specification](https://dwarfstd.org/doc/DWARF4.pdf).
