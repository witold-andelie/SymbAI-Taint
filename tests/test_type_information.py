"""Whole-function feature boundaries and exact-collision scope, without model execution."""
from copy import deepcopy
from pathlib import Path
import uuid

import pytest
from scripts.export_tygr_candidates import pack_logits
from scripts import audit_type_information as cli
from src.selective_analysis.type_information import function_representations, compare_pairs
from src.selective_analysis.workspace import SCRATCH


def example(address=100):
    identity = str(address) + ':0'
    scores = [[float(75 - i) for i in range(75)]]
    record = pack_logits(scores, ['label' + str(i) for i in range(75)], 3)
    record.update(function_address=address, prediction_id=identity, value_nodes=[1],
                  locator_variable_name='name', locations=[])
    entry = {'function_address': address, 'native_input': {'function_address': address,
        'variables': [{'prediction_id': identity, 'original_value_nodes': [1], 'flattened_output_rows': [0]}],
        'prepared': {'opaque_validated_input': [1]}, 'batch': {'opaque_validated_input': [1]}}}
    return entry, [record]


def features(entry, records):
    return function_representations(entry, records, 'a' * 64, 'b' * 64)


def repack(record, rows):
    result = dict(record)
    result.update(pack_logits(rows, record['vocabulary'], 3))
    return result


def test_function_addresses_prediction_ids_names_and_locations_are_not_type_features():
    left, left_records = example(100)
    right, right_records = example(999)
    right_records[0].update(locator_variable_name='completely_different', locations=[{'annotation': 123}])
    a, b = features(left, left_records), features(right, right_records)
    assert a == b and a['variable_records'] == a['readout_rows'] == 1
    assert set(a['representations']['Top1'][0]) == {'labels'}


def test_record_container_order_does_not_change_canonical_native_group_order():
    entry, records = example()
    other = deepcopy(records[0])
    other['prediction_id'] = '100:1'
    other['value_nodes'] = [2]
    entry['native_input']['variables'].append({'prediction_id': '100:1', 'original_value_nodes': [2], 'flattened_output_rows': [1]})
    assert features(entry, records + [other]) == features(entry, [other] + records)


@pytest.mark.parametrize('changed_index,topk_equal', [(0, False), (74, True)])
def test_candidate_scores_and_unretained_classes_are_compared_separately(changed_index, topk_equal):
    entry, records = example()
    rows = deepcopy(records[0]['raw_value_node_logits'])
    rows[0][changed_index] += 0.25
    left, right = features(entry, records), features(entry, [repack(records[0], rows)])
    assert left['signatures']['Top1'] == right['signatures']['Top1']
    assert (left['signatures']['TopK_scores'] == right['signatures']['TopK_scores']) == topk_equal
    assert left['signatures']['full_retained_logits'] != right['signatures']['full_retained_logits']


@pytest.mark.parametrize('damage', ['missing', 'duplicate', 'native_duplicate', 'nodes', 'row_count',
    'vocabulary', 'row_width', 'nan', 'boolean'])
def test_missing_or_malformed_records_cannot_create_valid_representations(damage):
    entry, records = example()
    if damage == 'missing': records = []
    elif damage == 'duplicate': records *= 2
    elif damage == 'native_duplicate': entry['native_input']['variables'] *= 2
    elif damage == 'nodes': records[0]['value_nodes'] = [2]
    elif damage == 'row_count': records[0]['raw_value_node_logits'] *= 2
    elif damage == 'vocabulary': records[0]['vocabulary'][0] = records[0]['vocabulary'][1]
    elif damage == 'row_width': records[0]['raw_value_node_logits'][0].pop()
    elif damage == 'nan': records[0]['raw_value_node_logits'][0][0] = float('nan')
    else: records[0]['raw_value_node_logits'][0][0] = True
    with pytest.raises(ValueError):
        features(entry, records)


def panel():
    entry, records = example()
    result = features(entry, records)
    cases = [{'query_id': str(i), 'features': deepcopy(result)} for i in range(3)]
    outcomes = {str(i): {'interval_only': 'unknown', 'finite_readonly_only': 'unknown',
                        'expanded_only': 'unknown'} for i in range(3)}
    return cases, outcomes


def test_exact_neural_collision_and_capability_difference_do_not_imply_equal_inputs():
    cases, outcomes = panel()
    outcomes['1']['finite_readonly_only'] = 'excluded_within_scope'
    cases[1]['features']['actual_model_input_signature'] = 'different'
    pairs = compare_pairs(cases, outcomes)
    first = pairs[0]
    assert first['historical_capability_vectors_differ'] and not first['actual_model_inputs_equal']
    assert all(first['representation_equal'].values()) and len(pairs) == 3
    assert 'gain' not in first


@pytest.mark.parametrize('damage', ['case_missing', 'duplicate_case', 'outcome_missing', 'bad_status', 'extra_operation'])
def test_pair_denominator_and_status_scope_are_strict(damage):
    cases, outcomes = panel()
    if damage == 'case_missing': cases.pop()
    elif damage == 'duplicate_case': cases[1]['query_id'] = cases[0]['query_id']
    elif damage == 'outcome_missing': outcomes.pop('1')
    elif damage == 'bad_status': outcomes['1']['interval_only'] = 'whole_program_safe'
    else: outcomes['1']['oracle'] = 'violation'
    with pytest.raises(ValueError):
        compare_pairs(cases, outcomes)


def test_cli_refuses_changed_acquisition_before_derived_analysis():
    root = SCRATCH / 'tests' / ('type-information-' + uuid.uuid4().hex)
    root.mkdir(parents=True)
    (root / 'run-plan.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='anchor'):
        cli.validate_collection(root)
