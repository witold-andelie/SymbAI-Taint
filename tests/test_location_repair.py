"""Location semantics and replay boundaries; no native model execution."""
import ast
from collections import namedtuple
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest
from elftools.dwarf.locationlists import LocationEntry, BaseAddressEntry, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.structs import DWARFStructs
from scripts import tygr_location_adapter as adapter
from scripts import export_location_repair as worker
from scripts import run_location_repair as cli
from src.selective_analysis.workspace import SCRATCH

# Exact public pyelftools 0.27 interface (no entry_length/is_absolute fields).
LegacyEntry = namedtuple('LocationEntry', 'entry_offset begin_offset end_offset loc_expr')
LegacyBase = namedtuple('BaseAddressEntry', 'entry_offset base_address')


@pytest.fixture
def root():
    path = SCRATCH / 'tests' / ('location-v22-' + uuid.uuid4().hex)
    path.mkdir(parents=True)
    return path


def entry(start, end, absolute=False, expr=None):
    return LocationEntry(0, 0, start, end, [0x55] if expr is None else expr, absolute)


def base(address):
    return BaseAddressEntry(0, 0, address)


def resolve(items, cu_base=0x1129, address_size=8):
    return adapter.resolve_entries(items, cu_base, address_size, LocationEntry, BaseAddressEntry)


def test_cu_not_function_base_and_preserved_expression_bytes():
    items, trace = resolve([entry(12, 16), entry(16, 42)])
    assert [(item.begin_offset, item.end_offset) for item in items] == [(4405, 4409), (4409, 4435)]
    assert all(item.is_absolute and item.loc_expr == [0x55] for item in items)
    assert trace[0]['active_base'] == 4393


def test_pyelftools027_four_field_entries_use_selected_or_cu_base():
    values = [LegacyEntry(1, 12, 16, [0x55]), LegacyBase(2, 0x2000), LegacyEntry(3, 1, 3, [0x50])]
    resolved, trace = adapter.resolve_entries(values, 4393, 8, LegacyEntry, LegacyBase)
    assert [(item.begin_offset, item.end_offset) for item in resolved] == [(4405, 4409), (8193, 8195)]
    assert all(type(item) is LegacyEntry and item._fields == LegacyEntry._fields for item in resolved)
    assert trace[0]['is_absolute'] is False


def test_real_old_handler_with_027_tuple_classes_preserves_original_expression_handling(original_location):
    old = original_location
    old.LocationEntry, old.BaseAddressEntry = LegacyEntry, LegacyBase
    lookup = SimpleNamespace(die_location_list=old.die_location_list, struct_die_location_list=old.struct_die_location_list)
    adapter.install(old, lookup, lambda _: None)
    args = context([LegacyEntry(0, 12, 16, [0x55])]) + ((4405, 4435),)
    assert [(low, high, loc.reg_num) for low, high, loc in old.die_location_list(*args)] == [(4405, 4409, 5)]


def test_base_selection_replaces_cu_base_and_does_not_leak_between_lists():
    items, _ = resolve([entry(0, 2), base(0x2000), entry(4, 8), base(0x3000), entry(2, 3)])
    assert [item.begin_offset for item in items] == [0x1129, 0x2004, 0x3002]
    assert resolve([entry(0, 1)])[0][0].begin_offset == 0x1129


def test_absolute_ranges_and_zero_cu_base_are_not_guessed_as_relative():
    assert resolve([entry(1, 5, True)], None)[0][0].begin_offset == 1
    assert resolve([entry(1, 5)], 0)[0][0].begin_offset == 1
    assert resolve([base(0), entry(1, 5)], None)[0][0].begin_offset == 1


def test_zero_length_overlap_and_order_are_not_merged_or_clipped():
    items, trace = resolve([entry(10, 20), entry(12, 18), entry(4, 4), entry(2, 7)])
    assert [(item.begin_offset, item.end_offset) for item in items] == [(4403, 4413), (4405, 4411), (4395, 4400)]
    assert trace[2]['zero_length'] is True


@pytest.mark.parametrize('items,cu_base,size', [([entry(1, 2)], None, 8), ([entry(5, 4)], 0, 8),
    ([entry(-1, 2)], 0, 8), ([entry(0, 1)], True, 8), ([base(-1)], 0, 8),
    ([entry(0, 1)], 0, 3), ([entry(0xffffffff, 0xffffffff)], 1, 4),
    ([object()], 0, 8), ([entry(1, 2, 1)], 0, 8)])
def test_uninterpretable_locations_fail_closed(items, cu_base, size):
    with pytest.raises(ValueError):
        resolve(items, cu_base, size)


@pytest.fixture
def original_location():
    # Load just the frozen location parser against current pyelftools, not TYGR/torch.
    path = cli.ROOT / 'tygr_original/src/analysis/dwarf/location.py'
    if not path.is_file():
        pytest.skip('Optional original TYGR source is not included in a clean checkout')
    spec = importlib.util.spec_from_file_location('unmodified_location_for_unit_replay', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CU(dict):
    cu_offset = 0

    def get_top_DIE(self):
        return SimpleNamespace(attributes={'DW_AT_low_pc': SimpleNamespace(value=0x1129)})


def context(parsed):
    cu = CU(version=4, address_size=8)
    die = SimpleNamespace(cu=cu, offset=123, attributes={'DW_AT_location': object()},
        dwarfinfo=SimpleNamespace(config=SimpleNamespace(machine_arch='x64')))
    parser = SimpleNamespace(parse_from_attribute=lambda *args, **kwargs: parsed)
    dumper = SimpleNamespace(expr_parser=DWARFExprParser(DWARFStructs(
        little_endian=True, dwarf_format=32, address_size=8, dwarf_version=4)))
    return die, parser, dumper


def test_replays_actual_old_heuristic_then_corrects_both_bound_entry_points(original_location):
    old = original_location
    lookup = SimpleNamespace(die_location_list=old.die_location_list, struct_die_location_list=old.struct_die_location_list)
    args = context([entry(12, 16), entry(16, 42)]) + ((4405, 4435),)
    assert [(row[0], row[1]) for row in old.die_location_list(*args)] == [(4417, 4421), (4421, 4447)]
    trace = []
    adapter.install(old, lookup, trace.append)
    assert lookup.die_location_list is old.die_location_list
    rows = lookup.die_location_list(*args)
    assert [(row[0], row[1], row[2].reg_num) for row in rows] == [(4405, 4409, 5), (4409, 4435, 5)]
    member = SimpleNamespace(attributes={'DW_AT_data_member_location': SimpleNamespace(value=0)})
    rows = lookup.struct_die_location_list(member, *args)
    assert [(row[0], row[1]) for row in rows] == [(4405, 4409), (4409, 4435)]
    assert trace[0]['cu_base'] == 4393 and trace[0]['function_range'] == [4405, 4435]


def test_single_expression_and_original_multi_operation_rejection_unchanged(original_location):
    old = original_location
    lookup = SimpleNamespace(die_location_list=old.die_location_list, struct_die_location_list=old.struct_die_location_list)
    adapter.install(old, lookup, lambda _: None)
    args = context(LocationExpr([0x55])) + ((4405, 4435),)
    result = old.die_location_list(*args)
    assert [(row[0], row[1], row[2].reg_num) for row in result] == [(4405, 4435, 5)]
    multi = context([entry(12, 16, expr=[0x55, 0x9f])]) + ((4405, 4435),)
    assert old.die_location_list(*multi) == []


def test_adapter_rejects_unknown_version_and_aliased_binding_drift(original_location):
    old = original_location
    lookup = SimpleNamespace(die_location_list=lambda *args: [], struct_die_location_list=old.struct_die_location_list)
    with pytest.raises(ValueError, match='binding'):
        adapter.install(old, lookup, lambda _: None)
    lookup.die_location_list = old.die_location_list
    adapter.install(old, lookup, lambda _: None)
    args = context(LocationExpr([0x55])) + ((4405, 4435),)
    args[0].cu['version'] = 5
    with pytest.raises(ValueError, match='DWARF4'):
        old.die_location_list(*args)


def test_detailed_error_is_retained_before_original_lookup_can_swallow_it(original_location):
    old = original_location
    lookup = SimpleNamespace(die_location_list=old.die_location_list, struct_die_location_list=old.struct_die_location_list)
    trace, errors = [], []
    api = adapter.install(old, lookup, trace.append, errors.append)
    assert api == adapter.location_api(LocationEntry, BaseAddressEntry, LocationExpr)
    args = context([entry(20, 12)]) + ((4405, 4435),)
    # Same suppression pattern as upstream lookup.subprog_die_to_vars.
    try:
        lookup.die_location_list(*args)
    except Exception:
        pass
    assert trace == [] and errors == [{'die_offset': 123, 'function_range': [4405, 4435],
        'structured': False, 'error_type': 'ValueError', 'message': 'Reversed location range'}]


@pytest.mark.parametrize('fields', [('entry_offset', 'begin_offset', 'end_offset', 'loc_expr', 'unknown'), ()])
def test_unrecognized_entry_api_is_refused_at_install_before_generation(original_location, fields):
    old = original_location
    old.LocationEntry = namedtuple('UnsupportedEntry', fields)
    lookup = SimpleNamespace(die_location_list=old.die_location_list, struct_die_location_list=old.struct_die_location_list)
    with pytest.raises(ValueError, match='layout'):
        adapter.install(old, lookup, lambda _: None)


def test_envelope_pins_executing_wrapper_and_archived_helper(root):
    helper, external = root / 'helper.py', root / 'adapter.py'
    helper.write_text('# helper', encoding='utf-8')
    external.write_text('# external', encoding='utf-8')
    impl = {key: {'path': str(path), 'sha256': worker.sha(path)} for key, path in (
        ('wrapper', Path(worker.__file__)), ('base_worker', helper), ('adapter', external))}
    request = {'schema': 'symbai.location_repair_request.v1', 'implementation': impl,
               'native_request': {'worker_sha256': worker.sha(helper)}}
    worker.validate_envelope(request)
    external.write_text('# changed', encoding='utf-8')
    with pytest.raises(ValueError, match='identity'):
        worker.validate_envelope(request)


@pytest.mark.parametrize('damage', ['variant', 'trace', 'implementation', 'revision', 'modified_source'])
def test_adapted_summary_requires_explicit_identity_and_full_offline_trace(monkeypatch, damage):
    trace = [{'die_offset': 1, 'kind': 'single_expression'}]
    candidate = {'acquisition_variant': cli.VARIANT,
        'location_adapter': {'revision': adapter.REVISION, 'implementation': {}, 'records': deepcopy(trace),
            'original_source_files_modified': False, 'entry_api': adapter.location_api(LocationEntry, BaseAddressEntry, LocationExpr),
            'errors': [], 'pyelftools': '0.27-unit'}, 'records': []}
    data = {'payload': {'candidate': candidate}, 'parent_receipt': {'charged_seconds': 1}}
    if damage == 'variant': candidate['acquisition_variant'] = 'unmodified'
    elif damage == 'trace': candidate['location_adapter']['records'] = []
    elif damage == 'implementation': candidate['location_adapter']['implementation'] = {'changed': True}
    elif damage == 'revision': candidate['location_adapter']['revision'] = 'old'
    else: candidate['location_adapter']['original_source_files_modified'] = True
    monkeypatch.setattr(cli, 'validated_acquisition', lambda *_: pytest.fail('Invalid repair must not create coverage'))
    queries = [{'query_id': str(i), 'entry_rva': i} for i in range(3)]
    summary = cli.repair_summary(data, {}, trace, queries, {0: 1})
    assert summary['new_genuine_function_coverage'] == 0 and summary['acquisition_validation_failure']
    assert len(summary['cases']) == 3 and summary['old_genuine_function_coverage'] == 1


def test_missing_function_stays_missing_even_with_valid_repair_trace(monkeypatch):
    data = {'payload': {'candidate': {'acquisition_variant': cli.VARIANT,
        'location_adapter': {'revision': adapter.REVISION, 'implementation': {}, 'records': [],
            'original_source_files_modified': False, 'entry_api': adapter.location_api(LocationEntry, BaseAddressEntry, LocationExpr),
            'errors': [], 'pyelftools': '0.27-unit'}, 'records': []}},
        'parent_receipt': {'charged_seconds': 5}}
    monkeypatch.setattr(cli, 'validated_acquisition', lambda *_: {0: 2, 1: 1})
    queries = [{'query_id': str(i), 'entry_rva': i} for i in range(3)]
    summary = cli.repair_summary(data, {}, [], queries, {0: 1})
    assert summary['new_genuine_function_coverage'] == 2 and summary['cases'][2]['new_variable_records'] == 0
    assert summary['new_property_controls_executed'] == 0 and not summary['neural_benefit_measured']


def test_parent_reports_recorded_location_errors_instead_of_generic_trace_mismatch(monkeypatch):
    errors = [{'die_offset': 99, 'error_type': 'ValueError', 'message': 'Unsupported location'}]
    data = {'payload': {'candidate': {'location_adapter': {'errors': errors}, 'records': []}},
            'parent_receipt': {'charged_seconds': 1}}
    monkeypatch.setattr(cli, 'validated_acquisition', lambda *_: pytest.fail('Location errors must block admission'))
    summary = cli.repair_summary(data, {}, [], [{'query_id': str(i), 'entry_rva': i} for i in range(3)], {})
    assert 'Recorded native location errors' in summary['acquisition_validation_failure']
    assert summary['location_errors'] == errors and summary['new_genuine_function_coverage'] == 0


@pytest.mark.parametrize('module', [adapter, worker])
def test_standalone_old_environment_files_parse_as_python38(module):
    ast.parse(Path(module.__file__).read_text(encoding='utf-8'), feature_version=(3, 8))


def test_prepare_archives_evidence_and_never_starts_native_worker(root, monkeypatch):
    fake_repo, scratch = root / 'repo', root / 'scratch'
    baseline = scratch / cli.BASELINE
    archive = baseline / 'source_snapshot'
    old_files = {'tygr_original/src/__init__.py': '# unchanged original',
                 cli.PANEL + '/cases.json': '{}', 'scripts/export_typed_complementarity.py': '# archived worker',
                 'scripts/capture_tygr_preprocessing.py': '# archived capture',
                 'scripts/export_tygr_candidates.py': '# archived aggregation'}
    for name, text in old_files.items():
        target = archive / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    original = fake_repo / 'tygr_original/src/__init__.py'
    original.parent.mkdir(parents=True)
    original.write_text('# unchanged original', encoding='utf-8')
    for name in cli.NEW_SOURCES:
        target = fake_repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((cli.ROOT / name).read_bytes())
    model = fake_repo / 'tygr_original/model/MODEL_base/x64.O0.base.model'
    model.parent.mkdir(parents=True)
    model.write_bytes(b'unit model identity only')
    binary = baseline / 'queries.elf'
    binary.write_bytes(b'unit retained ELF identity only')
    q = {'query_id': 'unit', 'binary': str(binary), 'binary_sha256': cli.file_hash(binary),
         'entry_rva': 4393, 'write_rva': 4400, 'object_rva': 16448, 'capacity': 8, 'inputs': []}
    old_plan = {'source_sha256': {name: cli.file_hash(archive / name) for name in old_files}}
    cli.write(baseline / 'run-plan.json', old_plan)
    cli.write(baseline / 'records.json', [{'query_hash': cli.Query.from_dict(q).contract_hash}])
    cli.write(baseline / 'summary.json', {'preserved': True})
    cli.write(baseline / 'acquisition.json', {'preserved': True})
    anchors = {name: cli.file_hash(baseline / name) for name in cli.ANCHORS}
    monkeypatch.setattr(cli, 'ROOT', fake_repo)
    monkeypatch.setattr(cli, 'ANCHORS', anchors)
    monkeypatch.setattr(cli, 'BINARY_HASH', cli.file_hash(binary))
    monkeypatch.setattr(cli, 'MODEL_HASH', cli.file_hash(model))
    monkeypatch.setattr(cli, 'configure_workspace', lambda: scratch)
    monkeypatch.setattr(cli, 'extract_typed_queries', lambda path, specs: {'queries': [dict(q, binary=str(path))]})
    monkeypatch.setattr(cli, 'offline_trace', lambda _: [])
    monkeypatch.setattr(cli, 'validated_acquisition', lambda *_: {4393: 1})
    monkeypatch.setattr(cli, 'loaded_project_sources', lambda: [])
    monkeypatch.setattr(cli, 'run_stage', lambda *args: pytest.fail('Preparation started native acquisition'))
    monkeypatch.setattr(cli.sys, 'argv', ['run_location_repair.py', '--prepare-only'])
    cli.main()
    outputs = list(scratch.glob('location-repair-v22-*'))
    assert len(outputs) == 1
    plan = cli.read(outputs[0] / 'run-plan.json')
    summary = cli.read(outputs[0] / 'preflight-summary.json')
    assert plan['input_sha256']['queries.elf'] == cli.file_hash(binary)
    assert all(cli.file_hash(outputs[0] / 'source_snapshot' / name) == digest for name, digest in plan['source_sha256'].items())
    assert summary['native_workers_launched'] == 0 and not summary['native_inference_performed']
    assert summary['changed_sources'] == summary['changed_inputs'] == []
    assert not (outputs[0] / 'acquisition').exists()
