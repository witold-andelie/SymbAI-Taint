#!/usr/bin/env python3
"""Replicate one guarded native acquisition after a documented DWARF4 location repair."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from scripts.run_typed_complementarity import (read, write, snapshot, run_stage, validated_acquisition,
    unchanged, loaded_project_sources, MODEL_HASH, PANEL)
from scripts.tygr_location_adapter import resolve_entries, validate_api, REVISION, VARIANT
from src.selective_analysis.contracts import file_hash, Query
from src.selective_analysis.typed_complementarity import extract_typed_queries
from src.selective_analysis.workspace import configure_workspace

BASELINE = 'typed-complementarity-v21-20261113-124728-819'
BINARY_HASH = 'b3b8eb8a03d09112ef513aea572a840c547161bb41c7041386b2f7616267d9ed'
ANCHORS = {'run-plan.json': '5f8874459680a49105afd17b817f04fca63980f1bdf9154fe7059f860538e32f',
    'summary.json': 'fe29568f7af273cde1b00a64cfec2ebdfc105c1d766f9ae84793f6e7ffdc7bb1',
    'records.json': '79ea7f425584095d1b13d1958818c3c0a19a192d5210bebc179fd9c92c75b1db',
    'acquisition.json': 'ce7ed20934def5c2ec8ec8f12f4bfa1e0e05866174ea07fbf45e209e3af77430',
    'queries.elf': BINARY_HASH}
NEW_SOURCES = ('scripts/run_location_repair.py', 'scripts/export_location_repair.py',
    'scripts/tygr_location_adapter.py', 'docs/architecture/pilot_revision_v22.md',
    'docs/architecture/pilot_revision_v22_1.md')


def offline_trace(binary):
    """Independent ELF reader, without importing original TYGR or model frameworks."""
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.locationlists import LocationParser, LocationExpr, LocationEntry, BaseAddressEntry
    rows = []
    with binary.open('rb') as stream:
        dwarf = ELFFile(stream).get_dwarf_info()
        parser = LocationParser(dwarf.location_lists())
        for cu in dwarf.iter_CUs():
            if cu['version'] != 4:
                raise ValueError('Retained input is outside DWARF4 scope')
            attr = cu.get_top_DIE().attributes.get('DW_AT_low_pc')
            base = attr.value if attr is not None else None
            for function in cu.iter_DIEs():
                if function.tag != 'DW_TAG_subprogram' or 'DW_AT_low_pc' not in function.attributes:
                    continue
                low = function.attributes['DW_AT_low_pc'].value
                high = function.attributes['DW_AT_high_pc']
                high = high.value + (0 if high.form == 'DW_FORM_addr' else low)
                for die in function.iter_children():
                    if die.tag not in ('DW_TAG_variable', 'DW_TAG_formal_parameter') or 'DW_AT_location' not in die.attributes:
                        continue
                    parsed = parser.parse_from_attribute(die.attributes['DW_AT_location'], 4, die=die)
                    if isinstance(parsed, LocationExpr):
                        rows.append({'kind': 'single_expression', 'die_offset': die.offset,
                                     'function_range': [low, high], 'unchanged': True})
                    elif isinstance(parsed, list):
                        _, trace = resolve_entries(parsed, base, cu['address_size'], LocationEntry, BaseAddressEntry)
                        rows.append({'kind': 'location_list', 'die_offset': die.offset, 'cu_offset': cu.cu_offset,
                                     'cu_base': base, 'function_range': [low, high], 'entries': trace})
                    else:
                        raise ValueError('Unexpected retained location description')
    return rows


def repair_summary(acquisition, implementation, expected_trace, queries, old_counts):
    candidate = acquisition['payload']['candidate']
    counts, failure = {}, None
    trace = candidate.get('location_adapter', {}).get('records', [])
    try:
        if candidate.get('location_adapter', {}).get('errors'):
            raise ValueError('Recorded native location errors: ' + str(candidate['location_adapter']['errors']))
        validate_api(candidate.get('location_adapter', {}).get('entry_api'))
        if (candidate.get('acquisition_variant') != VARIANT
                or candidate.get('location_adapter', {}).get('revision') != REVISION
                or candidate['location_adapter'].get('errors') != []
                or not isinstance(candidate['location_adapter'].get('pyelftools'), str)
                or candidate['location_adapter'].get('implementation') != implementation
                or candidate['location_adapter'].get('original_source_files_modified') is not False
                or sorted(trace, key=lambda row: row['die_offset']) != sorted(expected_trace, key=lambda row: row['die_offset'])):
            raise ValueError('Repair provenance or location trace differs from offline ELF projection')
        counts = validated_acquisition(acquisition, BINARY_HASH)
    except Exception as error:
        failure = type(error).__name__ + ': ' + str(error)
    return {'schema': 'symbai.location_repair_summary.v1', 'planned_queries': 3, 'compiled_binaries_reused': 1,
        'binary_sha256': BINARY_HASH, 'acquisition_variant': VARIANT,
        'cases': [{'case_id': query['query_id'], 'old_variable_records': old_counts.get(query['entry_rva'], 0),
                   'new_variable_records': counts.get(query['entry_rva'], 0),
                   'genuine_function_output_available': bool(counts.get(query['entry_rva'], 0))} for query in queries],
        'old_genuine_function_coverage': sum(bool(old_counts.get(query['entry_rva'])) for query in queries),
        'new_genuine_function_coverage': sum(bool(counts.get(query['entry_rva'])) for query in queries),
        'acquisition_validation_failure': failure, 'adapter_location_records': len(trace),
        'runtime_pyelftools': candidate.get('location_adapter', {}).get('pyelftools'),
        'entry_api': candidate.get('location_adapter', {}).get('entry_api'),
        'location_errors': candidate.get('location_adapter', {}).get('errors', []),
        'coverage_admission': 'requires_complete_matching_adapter_trace_and_guarded_raw_logits',
        'forward_calls_attempted': candidate.get('forward_calls_attempted', 0),
        'forward_calls_completed': candidate.get('forward_calls_completed', 0),
        'raw_variable_records': len(candidate.get('records', [])),
        'cold_acquisition_parent_seconds': acquisition['parent_receipt']['charged_seconds'],
        'new_property_controls_executed': 0, 'new_selector_evaluated': False,
        'use_site_mapping_validated': False, 'neural_benefit_measured': False, 'held_out_evaluation': False,
        'cost_interpretation': 'one_adapted_acquisition_same_ELF_not_speedup_or_neural_value'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--tygr-python', type=Path, default=Path('/root/miniconda3/envs/tygr-orig/bin/python'))
    args = parser.parse_args()
    scratch = configure_workspace()
    if not args.prepare_only and (not sys.platform.startswith('linux') or not str(ROOT).startswith('/mnt/d/') or not args.tygr_python.is_file()):
        parser.error('Use existing WSL angr-env on /mnt/d; Windows supports --prepare-only')
    baseline = scratch / BASELINE
    for name, digest in ANCHORS.items():
        if file_hash(baseline / name) != digest:
            raise ValueError('Retained v21 evidence differs: ' + name)
    old_plan = read(baseline / 'run-plan.json')
    sources = {name: baseline / 'source_snapshot' / name for name in old_plan['source_sha256']}
    for name, digest in old_plan['source_sha256'].items():
        if file_hash(sources[name]) != digest:
            raise ValueError('Archived v21 implementation differs: ' + name)
    sources.update({name: ROOT / name for name in NEW_SOURCES})
    output = scratch / ('location-repair-v22-1-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print('Location repair output: ' + str(output), flush=True)
    source_hashes = snapshot(sources, output / 'source_snapshot')
    model = ROOT / 'tygr_original/model/MODEL_base/x64.O0.base.model'
    if file_hash(model) != MODEL_HASH:
        raise ValueError('Pinned model differs')
    inputs = {name: baseline / name for name in ANCHORS}
    inputs['model.model'] = model
    input_hashes = snapshot(inputs, output / 'input_snapshot')
    copies, binary = output / 'source_snapshot', output / 'input_snapshot/queries.elf'
    queries = extract_typed_queries(binary, read(copies / PANEL / 'cases.json'))['queries']
    if [Query.from_dict(query).contract_hash for query in queries] != [row['query_hash'] for row in read(baseline / 'records.json')]:
        raise ValueError('Query identities changed')
    expected_trace = offline_trace(binary)
    write(output / 'offline-location-trace.json', expected_trace)
    upstream = {name[len('tygr_original/'):]: value for name, value in source_hashes.items() if name.startswith('tygr_original/src/')}
    tygr = ROOT / 'tygr_original'
    if (set(upstream) != {path.relative_to(tygr).as_posix() for path in (tygr / 'src').rglob('*.py')}
            or any(not unchanged(tygr / name, digest) for name, digest in upstream.items())):
        raise ValueError('Live original TYGR inventory differs')
    old_counts = validated_acquisition(read(baseline / 'acquisition.json'), BINARY_HASH)
    implementation = {key: {'path': str(copies / name), 'sha256': source_hashes[name]} for key, name in (
        ('base_worker', 'scripts/export_typed_complementarity.py'), ('adapter', 'scripts/tygr_location_adapter.py'),
        ('wrapper', 'scripts/export_location_repair.py'))}
    native = {'schema': 'symbai.typed_acquisition_request.v1', 'binary': str(binary), 'binary_sha256': BINARY_HASH,
        'model': str(output / 'input_snapshot/model.model'), 'model_sha256': MODEL_HASH,
        'tygr_root': str(tygr), 'source_sha256': upstream, 'scratch_dir': str(output / 'acquisition/cache'),
        'worker_sha256': implementation['base_worker']['sha256'],
        'helpers': {key: {'path': str(copies / name), 'sha256': source_hashes[name]} for key, name in (
            ('capture', 'scripts/capture_tygr_preprocessing.py'), ('export', 'scripts/export_tygr_candidates.py'))}}
    request = {'schema': 'symbai.location_repair_request.v1', 'native_request': native, 'implementation': implementation}
    write(output / 'run-plan.json', {'schema': 'symbai.location_repair_plan.v1', 'prepare_only': args.prepare_only,
        'source_sha256': source_hashes, 'source_paths': {name: str(path) for name, path in sources.items()},
        'input_sha256': input_hashes, 'input_paths': {name: str(path) for name, path in inputs.items()},
        'request': request, 'planned_queries': queries, 'parent_cap_seconds': 120, 'baseline': str(baseline)})
    if args.prepare_only:
        summary = {'schema': 'symbai.location_repair_preflight.v1', 'planned_queries': 3,
            'old_genuine_function_coverage': 1, 'offline_location_records': len(expected_trace),
            'compiled_binaries_reused': 1, 'new_compilations': 0, 'native_workers_launched': 0,
            'native_inference_performed': False, 'Linux_collection_pending': True}
    else:
        acquisition = run_stage([str(args.tygr_python), '-B', implementation['wrapper']['path']], request, output / 'acquisition', 120)
        write(output / 'acquisition.json', acquisition)
        summary = repair_summary(acquisition, implementation, expected_trace, queries, old_counts)
    summary.update(changed_sources=[name for name, digest in source_hashes.items() if not unchanged(sources[name], digest)],
        changed_copied_sources=[name for name, digest in source_hashes.items() if not unchanged(copies / name, digest)],
        changed_inputs=[name for name, digest in input_hashes.items() if not unchanged(inputs[name], digest)],
        changed_copied_inputs=[name for name, digest in input_hashes.items() if not unchanged(output / 'input_snapshot' / name, digest)],
        original_tygr_unchanged=all(unchanged(tygr / name, digest) for name, digest in upstream.items()),
        original_tygr_inventory_unchanged=set(upstream) == {path.relative_to(tygr).as_posix() for path in (tygr / 'src').rglob('*.py')})
    loaded = loaded_project_sources()
    summary['loaded_project_sources'] = loaded
    summary['untracked_or_changed_loaded_project_sources'] = [name for name in loaded if name not in source_hashes or not unchanged(ROOT / name, source_hashes[name])]
    write(output / ('preflight-summary.json' if args.prepare_only else 'summary.json'), summary)
    print(json.dumps(summary, indent=2), flush=True)
    if (any(summary[key] for key in ('changed_sources', 'changed_copied_sources', 'changed_inputs', 'changed_copied_inputs',
                                    'untracked_or_changed_loaded_project_sources'))
            or not summary['original_tygr_unchanged'] or not summary['original_tygr_inventory_unchanged']):
        raise RuntimeError('Source/input identity changed')
    if not args.prepare_only and (summary['acquisition_validation_failure'] or summary['new_genuine_function_coverage'] < 3):
        raise SystemExit(1)
    print('Finished. Same-ELF location repair only: ' + str(output), flush=True)


if __name__ == '__main__':
    main()
