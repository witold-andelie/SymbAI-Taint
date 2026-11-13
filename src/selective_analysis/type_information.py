"""Exact whole-function representation comparisons; never an analysis selector."""
import math

from .contracts import fingerprint
from .types import project_type_candidates


def function_representations(entry, records, artifact_hash, model_hash):
    """Callers separately validate acquisition identity and the saved-input guard."""
    native = entry['native_input']
    address = entry['function_address']
    variables = native['variables']
    if (native['function_address'] != address or not variables
            or len({v['prediction_id'] for v in variables}) != len(variables)):
        raise ValueError('Missing/duplicate native variable identities')
    selected = [record for record in records if record['function_address'] == address]
    by_id = {record['prediction_id']: record for record in selected}
    if len(selected) != len(by_id) or set(by_id) != {v['prediction_id'] for v in variables}:
        raise ValueError('Missing/duplicate whole-function prediction records')
    top1, topk, full = [], [], []
    for variable in variables:
        record = by_id[variable['prediction_id']]
        rows, vocabulary = record['raw_value_node_logits'], record['vocabulary']
        if (record['value_nodes'] != variable['original_value_nodes']
                or len(rows) != len(variable['flattened_output_rows']) or not rows
                or len(vocabulary) != 75 or len(set(vocabulary)) != 75
                or any(not isinstance(label, str) or not label for label in vocabulary)
                or any(len(row) != 75 or any(type(v) not in (int, float) or not math.isfinite(v) for v in row) for row in rows)):
            raise ValueError('Retained full-logit/readout contract differs')
        views = [project_type_candidates(record['candidates'], record['score_kind'], group,
            'tygr_glowgnn', artifact_hash, model_hash) for group in ('C', 'D')]
        top1.append({'labels': list(views[0].labels)})
        topk.append({'labels': list(views[1].labels), 'raw_scores': list(views[1].raw_scores),
                     'conditional_weights': list(views[1].weights)})
        full.append({'vocabulary': vocabulary, 'value_row_logits': rows})
    representations = {'Top1': top1, 'TopK_scores': topk, 'full_retained_logits': full}
    return {'schema': 'symbai.function_type_representations.v1', 'variable_records': len(variables),
        'readout_rows': sum(len(v['flattened_output_rows']) for v in variables),
        'representations': representations,
        'signatures': {name: fingerprint(value) for name, value in representations.items()},
        'prepared_input_signature': fingerprint(native['prepared']),
        'actual_model_input_signature': fingerprint({'batch': native['batch'], 'seventh_gold_input': None}),
        'feature_scope': 'ordered_whole_function_groups_no_exact_event_or_role_claim'}


def compare_pairs(cases, outcomes):
    """Offline join only: outcomes cannot enter feature construction."""
    if len(cases) != 3 or len({case['query_id'] for case in cases}) != 3:
        raise ValueError('Retain all three distinct query identities')
    if set(outcomes) != {case['query_id'] for case in cases}:
        raise ValueError('Incomplete historical capability panel')
    expected = {'interval_only', 'finite_readonly_only', 'expanded_only'}
    if any(set(row) != expected or any(value not in ('unknown', 'violation', 'excluded_within_scope')
                                     for value in row.values()) for row in outcomes.values()):
        raise ValueError('Invalid historical operation statuses')
    pairs = []
    for index, left in enumerate(cases):
        for right in cases[index + 1:]:
            a, b = left['features'], right['features']
            pairs.append({'query_ids': [left['query_id'], right['query_id']],
                'prepared_inputs_equal': a['prepared_input_signature'] == b['prepared_input_signature'],
                'actual_model_inputs_equal': a['actual_model_input_signature'] == b['actual_model_input_signature'],
                'representation_equal': {name: a['signatures'][name] == b['signatures'][name]
                                         for name in ('Top1', 'TopK_scores', 'full_retained_logits')},
                'historical_capability_vectors_differ': outcomes[left['query_id']] != outcomes[right['query_id']]})
    return pairs
