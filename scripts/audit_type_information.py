#!/usr/bin/env python3
"""Offline exact representation/capability audit on the retained successful acquisition."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from scripts.run_location_repair import repair_summary, BINARY_HASH
from scripts.run_typed_complementarity import read, write, snapshot, validated_acquisition, loaded_project_sources, unchanged
from src.selective_analysis.contracts import file_hash, fingerprint, Query
from src.selective_analysis.type_information import function_representations, compare_pairs
from src.selective_analysis.workspace import configure_workspace

COLLECTION = 'location-repair-v22-1-20261113-162629-1577'
ANCHORS = {'run-plan.json': '8ddadbc64c09501a6fc876e057eb0af4529bc3386adc9d0c84aa72c9a9087421',
    'summary.json': 'c06b2e1fc598093beccac4cd615918fdff824ab0bc3bed2569ad1153ccdff979',
    'acquisition.json': '81d62369f324ec10a171c0c4df6f37c669998ea23e53073a5ed8b34f9ad7aea2',
    'offline-location-trace.json': '25297dd11d98c2f308dd04ca8a2eb3651ef5293918738354c1aedbed5e6c1d2b'}


def local_path(value):
    if sys.platform == 'win32' and value.startswith('/mnt/d/'):
        return Path('D:/' + value[len('/mnt/d/'):])
    return Path(value)


def validate_collection(collection):
    for name, digest in ANCHORS.items():
        if file_hash(collection / name) != digest:
            raise ValueError('Retained acquisition anchor differs: ' + name)
    plan, acquisition = read(collection / 'run-plan.json'), read(collection / 'acquisition.json')
    for name, digest in plan['source_sha256'].items():
        if file_hash(collection / 'source_snapshot' / name) != digest or file_hash(local_path(plan['source_paths'][name])) != digest:
            raise ValueError('Measured source differs: ' + name)
    for name, digest in plan['input_sha256'].items():
        if file_hash(collection / 'input_snapshot' / name) != digest or file_hash(local_path(plan['input_paths'][name])) != digest:
            raise ValueError('Measured input differs: ' + name)
    folder = collection / 'acquisition'
    request, payload, receipt = [read(folder / name) for name in ('request.json', 'payload.json', 'receipt.json')]
    if (acquisition != {'payload': payload, 'parent_receipt': receipt} or request != plan['request']
            or payload['request_fingerprint'] != fingerprint(request)
            or receipt['payload_sha256'] != file_hash(folder / 'payload.json')
            or receipt['payload_fingerprint'] != fingerprint(payload)
            or read(folder / 'candidate.json') != payload['candidate']
            or receipt['status'] != 'completed' or not 0 < receipt['charged_seconds'] < receipt['budget_seconds'] == 120
            or payload['process']['returncode'] != 0 or payload['process']['timed_out']):
        raise ValueError('Retained acquisition receipt chain differs')
    native = read(folder / 'native-candidate.json')
    candidate = payload['candidate']
    if any(candidate[key] != value for key, value in native.items()):
        raise ValueError('Raw native output differs from adapted result')
    old_counts = validated_acquisition(read(collection / 'input_snapshot/acquisition.json'), BINARY_HASH)
    summary = repair_summary(acquisition, request['implementation'], read(collection / 'offline-location-trace.json'),
        plan['planned_queries'], old_counts)
    if (summary['acquisition_validation_failure'] or summary['new_genuine_function_coverage'] != 3
            or any(read(collection / 'summary.json')[key] != value for key, value in summary.items())):
        raise ValueError('Complete adapted acquisition admission differs')
    return plan, acquisition


def main():
    scratch = configure_workspace()
    collection = scratch / COLLECTION
    plan, acquisition = validate_collection(collection)
    candidate = acquisition['payload']['candidate']
    cases, functions = [], {row['function_address']: row for row in candidate['functions']}
    # All feature construction finishes before reading historical operation results.
    for query in plan['planned_queries']:
        local = dict(query, binary=str(collection / 'input_snapshot/queries.elf'))
        validated_query = Query.from_dict(local)
        features = function_representations(functions[query['entry_rva']], candidate['records'],
            ANCHORS['acquisition.json'], candidate['model_sha256'])
        cases.append({'query_id': query['query_id'], 'query_hash': validated_query.contract_hash, 'features': features})
    if len(cases) != 3 or len({row['query_hash'] for row in cases}) != 3:
        raise ValueError('Retain three distinct fixed queries')
    rows = read(collection / 'input_snapshot/records.json')
    if [(row['case_id'], row['query_hash']) for row in rows] != [(row['query_id'], row['query_hash']) for row in cases]:
        raise ValueError('Historical capability query identities differ')
    outcomes, fixed_costs = {}, []
    for row in rows:
        statuses = {}
        for method, trial in row['operations'].items():
            result = trial['payload']['candidate']
            if (trial['parent_receipt']['status'] != 'completed' or result.get('complete') is not True
                    or result.get('query_hash') != row['query_hash'] or result.get('binary_sha256') != BINARY_HASH
                    or result.get('method') != method):
                raise ValueError('Historical control not complete with matching identity')
            if method in ('interval_only', 'finite_readonly_only', 'expanded_only'):
                statuses[method] = result['result']['status']
        outcomes[row['case_id']] = statuses
        fixed = row['operations']['fixed_cascade']['parent_receipt']['charged_seconds']
        fixed_costs.append({'query_id': row['case_id'], 'parent_seconds': fixed})
    pairs = compare_pairs(cases, outcomes)
    inputs = {name: collection / name for name in ANCHORS}
    inputs['historical-controls.json'] = collection / 'input_snapshot/records.json'
    sources = {name: ROOT / name for name in loaded_project_sources()}
    sources['docs/architecture/pilot_revision_v23.md'] = ROOT / 'docs/architecture/pilot_revision_v23.md'
    output = scratch / ('type-information-v23-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    source_hashes = snapshot(sources, output / 'source_snapshot')
    input_hashes = snapshot(inputs, output / 'input_snapshot')
    write(output / 'run-plan.json', {'schema': 'symbai.type_information_plan.v1', 'source_sha256': source_hashes,
        'source_paths': {name: str(path) for name, path in sources.items()}, 'input_sha256': input_hashes,
        'input_paths': {name: str(path) for name, path in inputs.items()}, 'collection': str(collection),
        'known_development_data': True, 'new_workers_launched': 0})
    write(output / 'representations.json', cases)
    write(output / 'pair-comparisons.json', pairs)
    cold = acquisition['parent_receipt']['charged_seconds']
    report = {'schema': 'symbai.type_information_audit.v1', 'unique_queries': 3,
        'genuine_variable_records': sum(row['features']['variable_records'] for row in cases),
        'native_readout_rows': sum(row['features']['readout_rows'] for row in cases), 'pairs_compared': len(pairs),
        'exact_model_input_collision_pairs': sum(row['actual_model_inputs_equal'] for row in pairs),
        'Top1_collision_pairs': sum(row['representation_equal']['Top1'] for row in pairs),
        'TopK_score_collision_pairs': sum(row['representation_equal']['TopK_scores'] for row in pairs),
        'full_logit_collision_pairs': sum(row['representation_equal']['full_retained_logits'] for row in pairs),
        'full_logit_collision_with_different_historical_capabilities': [row['query_ids'] for row in pairs
            if row['representation_equal']['full_retained_logits'] and row['historical_capability_vectors_differ']],
        'historical_capabilities': outcomes, 'cold_acquisition_parent_seconds': cold,
        'cold_acquisition_per_planned_query_seconds': cold / 3, 'historical_fixed_cascade_costs': fixed_costs,
        'historical_fixed_cascade_total_seconds': sum(row['parent_seconds'] for row in fixed_costs),
        'cost_scope': 'different_runs_and_stages_descriptive_only_not_matched_end_to_end_or_speedup',
        'new_model_inference': False, 'new_property_execution': False, 'new_selector_evaluated': False,
        'use_site_mapping_validated': False, 'neural_benefit_measured': False, 'held_out_evaluation': False,
        'interpretation': 'Identical observed neural views cannot alone distinguish a pair; other structural evidence, adaptive fallback and other inputs remain outside this claim.',
        'changed_sources': [name for name, digest in source_hashes.items() if not unchanged(sources[name], digest)],
        'changed_copied_sources': [name for name, digest in source_hashes.items() if not unchanged(output / 'source_snapshot' / name, digest)],
        'changed_inputs': [name for name, digest in input_hashes.items() if not unchanged(inputs[name], digest)],
        'changed_copied_inputs': [name for name, digest in input_hashes.items() if not unchanged(output / 'input_snapshot' / name, digest)]}
    if {'torch', 'angr', 'claripy', 'pyvex', 'z3'} & set(sys.modules):
        raise RuntimeError('Offline audit imported a model or property framework')
    if any(report[key] for key in ('changed_sources', 'changed_copied_sources', 'changed_inputs', 'changed_copied_inputs')):
        raise RuntimeError('Source/input identity changed')
    write(output / 'summary.json', report)
    print('Type-information audit output: ' + str(output))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
