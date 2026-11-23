"""Synthetic, self-cleaning tests; no real evidence is opened by these tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
from unittest.mock import Mock
import uuid

import pytest


def import_script(name):
    spec = importlib.util.spec_from_file_location(name, Path('scripts') / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = import_script('build_evidence_archive')
verifier = import_script('verify_evidence_archive')

MIT = ('Permission is hereby granted, free of charge, to any person obtaining a copy '
       'of this software to deal in the Software without restriction. '
       'THE SOFTWARE IS PROVIDED AS IS.\n')
GPL = 'GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007\n'


def put(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode('ascii'))
    return path


def put_json(path, value):
    return put(path, builder.json_bytes(value))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def tree():
    root = Path('.test-output') / ('ea-' + str(uuid.uuid4().int)[:10])
    root.mkdir(parents=True)
    repository = root / 'repository'
    scratch = root / 'selective_analysis'
    repository.mkdir()
    scratch.mkdir()
    sources = 'route-b-v5-sources-test'
    panel = 'route-b-v5-panel-test'
    v4 = 'route-b-v4-freeze-test'
    v5 = 'route-b-v5-freeze-test'
    catalog = [(sources, 'v5', 'sources', 'Synthetic source pins'),
               (panel, 'v5', 'panel', 'Synthetic panel records'),
               (v4, 'v4', 'freeze', 'Synthetic v4 pins'),
               (v5, 'v5', 'freeze', 'Synthetic v5 pins')]
    project_records = []
    for name, license_text in (('alpha', MIT), ('beta', GPL)):
        source = scratch / sources / 'sources' / name
        notice = put(source / 'LICENSE', license_text)
        put(source / 'upstream.c', 'int upstream(void) { return 0; }\n')
        project_records.append({'project_id': name, 'commit': 'c' * 40,
                                'source_directory': '../.scratch/selective_analysis/' + sources + '/sources/' + name,
                                'license_evidence': {'LICENSE': sha(notice)}})
    sealed_source = scratch / sources / 'sources' / 'utf8_h'
    put(sealed_source / 'utf8.h', 'DO NOT READ\n')
    put(sealed_source / 'LICENSE', MIT)
    project_records.append({'project_id': 'utf8_h',
                            'source_directory': '../.scratch/selective_analysis/' + sources + '/sources/utf8_h',
                            'license_evidence': {'LICENSE': '0' * 64}})
    put_json(scratch / sources / 'sources-manifest.json', {'projects': project_records})
    directory = scratch / panel
    put_json(directory / 'records.json', {'records': [{'decision': 'safe', 'duration': 0.1}]})
    put_json(directory / 'plan.json', {'candidates': [
        {'project': 'alpha', 'spec': {'definition': 'int f(void) { return 7; }',
                                     'body': ['return 7;'], 'capacity': 8}},
        {'project': 'beta', 'spec': {'setup': 'int x = 0;',
                                    'static_dependencies': {'helper': 'int h() { return 0; }'}}}],
        'nested': {'rejections': [{'spec': {'call': 'f()'},
                                   'detail': 'compiler: int vendor(void) { return 1; }'}]}})
    put(directory / 'alpha-kernel.c', 'int f(void) { return 7; }\n')
    put(directory / 'alpha-kernel.elf', b'\x7fELF\x00\x01')
    put(directory / 'beta-kernel.c', 'int f(void) { return 2; }\n')
    put(directory / 'unattributed.c', 'int other(void) { return 3; }\n')
    put(directory / 'alpha-build.log', 'compiler diagnostics\n')
    put_json(directory / 'alpha.labels.json', {'variables': []})
    put(directory / 'metrics.log', 'completed=1\n')
    put(directory / 'weights.pt', b'model')
    put(directory / 'temp' / 'cache', b'cache')
    put(directory / 'graph.json', b'x' * (builder.LIMIT + 1))
    put_json(directory / 'small-graph.json', {'nodes': [0, 1], 'edges': []})
    put(directory / 'b64-hidden.txt', 'DO NOT READ\n')
    design = put(repository / 'benchmarks' / 'synthetic_design.md', '# Synthetic design\n')
    engine = put(repository / 'scripts' / 'engine.py', 'pass\n')
    pins = {'benchmarks/synthetic_design.md': sha(design), 'scripts/engine.py': sha(engine)}
    put_json(scratch / v4 / 'freeze.json', {'pins': pins, 'design_sha256': sha(design),
        'regression': {'directory': '../.scratch/selective_analysis/' + panel,
                       'summary_sha256': sha(directory / 'records.json')}})
    # The actual regression filename must be summary.json, matching the freeze schema.
    put_json(directory / 'summary.json', {'records': [{'decision': 'safe', 'duration': 0.1}]})
    artifact = '../.scratch/selective_analysis/' + panel + '/plan.json'
    put_json(scratch / v5 / 'freeze.json', {'pins': pins, 'design_sha256': sha(design),
        'artifact_files': {artifact: sha(directory / 'plan.json'),
                           '../.scratch/selective_analysis/' + panel + '/alpha-kernel.elf': sha(directory / 'alpha-kernel.elf'),
                           '../.scratch/selective_analysis/' + panel + '/weights.pt': sha(directory / 'weights.pt')},
        'panel': {'directory': '../.scratch/selective_analysis/' + panel,
                  'files': {'records.json': sha(directory / 'records.json')}}})
    state = {'root': root, 'repository': repository, 'scratch': scratch, 'catalog': catalog,
             'output': repository / '.test-output' / 'archive', 'panel': panel,
             'sources': sources, 'v4': v4, 'v5': v5}
    try:
        yield state
    finally:
        # Verify the exact absolute target before the recursive delete on Windows.
        resolved = root.resolve()
        assert resolved.parent == Path('.test-output').resolve()
        assert resolved.name.startswith('ea-')
        shutil.rmtree(root)


def build(tree, **options):
    kwargs = {'output': tree['output'], 'scratch': tree['scratch'],
              'repository': tree['repository'], 'catalog': tree['catalog'], 'commit': 'test-commit'}
    kwargs.update(options)
    return builder.build_archive(**kwargs)


def test_classes_redaction_and_withholding(tree, monkeypatch):
    original_open = Path.open
    def guarded_open(path, *args, **kwargs):
        if builder.sealed(path):
            raise AssertionError('Sealed file was opened: ' + str(path))
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded_open)
    rows, projects, check = build(tree)
    prefix = tree['panel'] + '/'
    assert rows[prefix + 'records.json']['class'] == 'tier1'
    assert rows[prefix + 'metrics.log']['class'] == 'tier1'
    assert rows[prefix + 'small-graph.json']['class'] == 'tier1'
    for name in ('alpha-kernel.c', 'alpha-kernel.elf', 'alpha.labels.json', 'alpha-build.log'):
        assert rows[prefix + name]['class'] == 'tier2'
        assert (tree['output'] / 'tier2' / prefix / name).is_file()
    for name in ('weights.pt', 'temp/cache', 'graph.json'):
        assert rows[prefix + name]['class'] == 'hash_only'
        assert len(rows[prefix + name]['sha256']) == 64
        assert not rows[prefix + name]['archived_path']
    assert rows[prefix + 'b64-hidden.txt']['sha256'] == ''
    assert not rows[prefix + 'beta-kernel.c']['archived_path']
    assert 'GPL' in rows[prefix + 'beta-kernel.c']['reason']
    assert not rows[prefix + 'unattributed.c']['archived_path']
    original = tree['scratch'] / prefix / 'plan.json'
    row = rows[prefix + 'plan.json']
    assert row['class'] == 'tier2'
    assert not row['archived_path']
    assert row['sha256'] == sha(original)
    redacted = tree['output'] / row['redacted_path']
    assert row['redacted_sha256'] == sha(redacted)
    data = json.loads(redacted.read_bytes())
    definition = 'int f(void) { return 7; }'
    canonical = json.dumps(definition, sort_keys=True, separators=(',', ':')).encode('ascii')
    assert data['candidates'][0]['spec']['definition'] == {'redacted_sha256': hashlib.sha256(canonical).hexdigest()}
    assert data['candidates'][0]['spec']['capacity'] == 8
    assert list(data['candidates'][1]['spec']['static_dependencies']) == ['redacted_sha256']
    assert list(data['nested']['rejections'][0]['spec']['call']) == ['redacted_sha256']
    assert list(data['nested']['rejections'][0]['detail']) == ['redacted_sha256']
    assert b'int f' not in redacted.read_bytes()
    assert projects['alpha']['classification'] == 'MIT'
    assert projects['beta']['classification'] == 'GPL'
    assert projects['utf8_h']['sealed']
    assert check['passed']
    license_row = rows[tree['sources'] + '/sources/alpha/LICENSE']
    assert license_row['class'] == 'hash_only'
    copies = json.loads(license_row['license_paths'])
    assert len(copies) == 1
    assert sha(tree['output'] / copies[0]) == license_row['sha256']
    assert not list((tree['output'] / 'tier2' / 'LICENSES').glob('beta/**'))
    counts = verifier.verify_archive(tree['output'])
    assert counts['tier1']['files'] > 0
    assert counts['tier2']['files'] > 0


@pytest.mark.parametrize('text,expected', [
    (MIT, 'MIT'), (GPL, 'GPL'),
    ('GNU LESSER GENERAL PUBLIC LICENSE Version 2.1', 'LGPL'),
    ('Redistribution and use in source and binary forms are permitted. '
     'Redistributions of source code must retain the copyright. '
     'Redistributions in binary form must reproduce the copyright.', 'BSD-2'),
    ('Redistribution and use in source and binary forms are permitted. '
     'Redistributions of source code must retain the copyright. '
     'Redistributions in binary form must reproduce the copyright. '
     'Neither the name may be used to endorse products.', 'BSD-3'),
    ('Apache License Version 2.0, January 2004', 'Apache-2.0'),
    ('Permission to use, copy, modify, and distribute this software for any purpose with or without fee', 'ISC'),
    ('The origin of this software must not be misrepresented. '
     'Altered source versions must be plainly marked.', 'zlib'),
    ('This is free and unencumbered software released into the public domain.', 'Unlicense'),
    ('Creative Commons CC0 1.0 Universal', 'CC0'),
    ('This software is in the public domain.', 'public domain'),
    ('Permission to use, modify and distribute this software for any purpose without fee.', 'other permissive'),
    ('Proprietary. All rights reserved.', 'unknown'),
    ('License: MIT (no grant text retained)', 'unknown'),
    (MIT + GPL, 'GPL'),
    ('Apache License Version 2.0\nLLVM Exceptions: GPL version 2 compatibility', 'Apache-2.0'),
    ('GNU GENERAL PUBLIC LICENSE\nVersion 2\nThe GNU Lesser General Public License is separate.', 'GPL'),
    ('SPDX-License-Identifier: BSD-3-Clause', 'BSD-3'),
    ('Boost Software License - Version 1.0\nPermission is hereby granted, free of charge, '
     'to prepare derivative works.', 'other permissive'),
    ('Redistribution and use in source and binary forms are permitted under the following conditions. '
     'Redistributions of source code must retain this notice and disclaimer.', 'other permissive'),
    ('You can redistribute it under the terms of the GNU General Public License version 2.', 'GPL'),
])
def test_license_texts(text, expected):
    assert builder.classify_license(text) == expected


def test_generated_license_header_is_decoded():
    encoded = 'char __LICENSE[] = {' + ','.join('0x{:02x}'.format(c) for c in MIT.encode('ascii')) + '};'
    assert builder.classify_license(encoded) == 'MIT'
    assert builder.classify_license(encoded.replace('};', ", '\\0'};")) == 'MIT'


def test_relative_path_validation(tree):
    for value in ('../outside', '/absolute', 'C:/absolute', 'safe/../../outside'):
        with pytest.raises(ValueError, match='Unsafe relative path'):
            builder.child(tree['scratch'], value)
    start = Path.cwd()
    with pytest.raises(ValueError, match='sentinel'):
        with builder.working_directory(tree['scratch']):
            raise ValueError('sentinel')
    assert Path.cwd() == start


def test_license_hash_mismatch_fails_before_output(tree):
    put(tree['scratch'] / tree['sources'] / 'sources' / 'alpha' / 'LICENSE', 'tampered\n')
    with pytest.raises(ValueError, match='License evidence hash mismatch'):
        build(tree)
    assert not tree['output'].exists()


def test_freeze_match_and_archiving_status(tree):
    rows, projects, check = build(tree, dry_run=True)
    assert not tree['output'].exists()
    assert len(check['counts']) == 2
    plan = [c for c in check['checks'] if c['field'].endswith('/plan.json')][0]
    assert plan['archived_as'] == ['tier1 redacted']
    model = [c for c in check['checks'] if c['path'].endswith('/weights.pt')][0]
    assert model['archived_as'] == ['hash_only']
    assert all(c['actual_sha256'] == c['expected_sha256'] for c in check['checks'])


@pytest.mark.parametrize('kind', ['pin', 'artifact', 'panel', 'regression', 'design'])
def test_freeze_mismatch_fails_before_output(tree, kind):
    if kind == 'pin':
        put(tree['repository'] / 'scripts' / 'engine.py', 'changed\n')
    else:
        freeze_path = tree['scratch'] / tree['v5' if kind != 'regression' else 'v4'] / 'freeze.json'
        freeze = json.loads(freeze_path.read_bytes())
        if kind == 'artifact':
            freeze['artifact_files'][next(iter(freeze['artifact_files']))] = '0' * 64
        elif kind == 'panel':
            freeze['panel']['files']['records.json'] = '0' * 64
        elif kind == 'regression':
            freeze['regression']['summary_sha256'] = '0' * 64
        else:
            freeze['design_sha256'] = '0' * 64
        put_json(freeze_path, freeze)
    with pytest.raises(ValueError, match='Freeze hash mismatch'):
        build(tree)
    assert not tree['output'].exists()


def test_missing_catalog_directory_fails(tree):
    with pytest.raises(ValueError, match='Catalogued directory missing'):
        build(tree, catalog=tree['catalog'] + [('route-b-v5-missing', 'v5', 'run', 'Missing')])
    assert not tree['output'].exists()


def test_output_boundaries_and_empty_directory(tree):
    with pytest.raises(ValueError, match='outside repository'):
        build(tree, output=tree['repository'] / 'forbidden')
    with pytest.raises(ValueError, match='outside repository'):
        build(tree, output=tree['scratch'] / 'forbidden')
    with pytest.raises(ValueError, match='outside .scratch'):
        build(tree, output=tree['root'] / '.scratch' / 'forbidden')
    tree['output'].mkdir(parents=True)
    put(tree['output'] / 'keep.txt', 'keep\n')
    with pytest.raises(ValueError, match='non-empty'):
        build(tree)
    assert (tree['output'] / 'keep.txt').read_bytes() == b'keep\n'
    (tree['output'] / 'keep.txt').unlink()
    build(tree)
    assert (tree['output'] / 'MANIFEST.tsv').is_file()


def test_deterministic_zips_and_metadata(tree):
    build(tree, make_zip=True)
    other = tree['repository'] / '.test-output' / 'second'
    build(tree, output=other, make_zip=True)
    for filename in ('tier1.zip', 'tier2.zip', 'MANIFEST.tsv', 'SHA256SUMS-tier1.txt',
                     'SHA256SUMS-tier2.txt', 'LICENSES.md', 'FREEZE_CROSSCHECK.json', 'ARCHIVE_README.md'):
        assert (tree['output'] / filename).read_bytes() == (other / filename).read_bytes()
    for filename in ('MANIFEST.tsv', 'LICENSES.md', 'ARCHIVE_README.md'):
        content = (tree['output'] / filename).read_bytes()
        assert b'\r' not in content
        content.decode('ascii')


@pytest.mark.parametrize('change', ['modify', 'extra', 'missing', 'sums', 'manifest'])
def test_verifier_detects_corruption(tree, change):
    build(tree)
    target = tree['output'] / 'tier1' / tree['panel'] / 'records.json'
    if change == 'modify':
        put(target, '{}\n')
    elif change == 'extra':
        put(target.parent / 'extra.txt', 'extra\n')
    elif change == 'missing':
        target.unlink()
    elif change == 'sums':
        sums = tree['output'] / 'SHA256SUMS-tier1.txt'
        put(sums, '0' * 64 + sums.read_text(encoding='ascii')[64:])
    else:
        manifest = tree['output'] / 'MANIFEST.tsv'
        put(manifest, manifest.read_text(encoding='ascii').replace(sha(target), '0' * 64))
    with pytest.raises(ValueError, match='mismatch|disagree'):
        verifier.verify_archive(tree['output'])


def test_juliet_flag_and_permissive_code_json(tree):
    put(tree['scratch'] / tree['panel'] / 'CWE124-case.elf', b'ELF Juliet')
    put_json(tree['scratch'] / tree['panel'] / 'alpha-plan.json',
             {'candidates': [{'project': 'alpha', 'spec': {'definition': 'int x;'}}]})
    rows, projects, check = build(tree, dry_run=True)
    assert not rows[tree['panel'] + '/CWE124-case.elf']['archived_path']
    assert rows[tree['panel'] + '/alpha-plan.json']['archived_path'].startswith('tier2/')
    assert rows[tree['panel'] + '/alpha-plan.json']['redacted_path'].startswith('tier1/')
    rows, projects, check = build(tree, include_juliet=True)
    assert rows[tree['panel'] + '/CWE124-case.elf']['archived_path'].startswith('tier2/')
    assert projects['Juliet']['classification'] == builder.JULIET
    verifier.verify_archive(tree['output'])


def test_external_frozen_dependency_is_hash_only(tree):
    dependency = put(tree['scratch'] / 'route-b-older-diagnostic' / 'records.json', '{}\n')
    path = tree['scratch'] / tree['v5'] / 'freeze.json'
    freeze = json.loads(path.read_bytes())
    freeze['artifact_files']['../.scratch/selective_analysis/route-b-older-diagnostic/records.json'] = sha(dependency)
    put_json(path, freeze)
    rows, projects, check = build(tree)
    row = rows['route-b-older-diagnostic/records.json']
    assert row['class'] == 'hash_only'
    assert row['sha256'] == sha(dependency)
    assert 'outside catalog' in row['reason']
    verifier.verify_archive(tree['output'])


@pytest.mark.parametrize('path,expected', [
    ('sources/b64/b64.c', True), ('sources/utf8_h/LICENSE', True),
    ('sources/utf8.h/LICENSE', True), ('include/utf8.h', True),
    ('labels-x/b64-O0.elf', True), ('labels-x/b64.labels.json', True),
    ('labels/utf8_h-O0.elf', True), ('labels/utf8_h.labels.json', True),
    ('argon2-b64len-L1-adapter.c', False),
    ('argon2-b64_byte_to_char-L1-adapter.c', False),
    ('argon2-b64_char_to_byte-L1-build.log', False),
    ('prefix-b64/ordinary.json', False), ('myutf8_h/file.json', False),
    ('sources/argon2/src/blake2b64.c', False),
    (r'sources\b64\LICENSE', True),
])
def test_seal_is_a_project_boundary(path, expected):
    assert builder.sealed(path) is expected


def test_argon2_b64_kernel_is_hashed_and_frozen(tree):
    relative = tree['panel'] + '/argon2-b64len-L1-adapter.c'
    path = put(tree['scratch'] / relative, 'int b64len(void) { return 7; }\n')
    expected = sha(path)
    freeze_path = tree['scratch'] / tree['v5'] / 'freeze.json'
    freeze = json.loads(freeze_path.read_bytes())
    field = '../.scratch/selective_analysis/' + relative
    freeze['artifact_files'][field] = expected
    put_json(freeze_path, freeze)
    rows, projects, check = build(tree, dry_run=True)
    assert rows[relative]['sha256'] == expected
    assert rows[relative]['class'] == 'tier2'
    assert check['passed']
    entry = next(c for c in check['checks'] if c['field'] == 'artifact_files/' + field)
    assert entry['actual_sha256'] == expected
    assert entry['matched'] is True


def test_b64_source_and_labels_are_sealed_without_open(tree, monkeypatch):
    relatives = [tree['sources'] + '/sources/b64/b64.c', tree['sources'] + '/labels-x/b64-O0.elf']
    protected = {put(tree['scratch'] / relative, 'DO NOT OPEN\n').resolve() for relative in relatives}
    original_open = Path.open
    def guarded_open(path, *args, **kwargs):
        if path.resolve() in protected:
            raise AssertionError('Sealed file opened: ' + str(path))
        return original_open(path, *args, **kwargs)
    opened = Mock(side_effect=guarded_open)
    monkeypatch.setattr(Path, 'open', lambda path, *args, **kwargs: opened(path, *args, **kwargs))
    rows, projects, check = build(tree)
    for relative in relatives:
        row = rows[relative]
        assert row['class'] == 'hash_only'
        assert row['bytes'] == len('DO NOT OPEN\n')
        assert row['sha256'] == row['archived_path'] == row['redacted_path'] == ''
    assert not any(call.args[0].resolve() in protected for call in opened.call_args_list)


@pytest.mark.parametrize('project_id', ['utf8_h', 'b64'])
@pytest.mark.parametrize('frozen', [False, True])
def test_manifest_attributed_aliases_are_never_opened(tree, monkeypatch, project_id, frozen):
    source = tree['sources'] + '/sources/anonymous'
    relative = tree['panel'] + '/anonymous.elf'
    protected = {put(tree['scratch'] / p, 'DO NOT OPEN\n').resolve()
                 for p in (relative, source + '/LICENSE', source + '/upstream.c')}
    manifest_path = tree['scratch'] / tree['sources'] / 'sources-manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    manifest['projects'].append({
        'project_id': project_id,
        'source_directory': '../.scratch/selective_analysis/' + source,
        'dwarf_elf': '../.scratch/selective_analysis/' + relative,
        'license_evidence': {'LICENSE': '0' * 64}})
    put_json(manifest_path, manifest)
    if frozen:
        freeze_path = tree['scratch'] / tree['v5'] / 'freeze.json'
        freeze = json.loads(freeze_path.read_bytes())
        freeze['artifact_files']['../.scratch/selective_analysis/' + relative] = '0' * 64
        put_json(freeze_path, freeze)
    original_open = Path.open
    def guarded_open(path, *args, **kwargs):
        if path.resolve() in protected:
            raise AssertionError('Manifest-sealed file opened: ' + str(path))
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded_open)
    if frozen:
        with pytest.raises(ValueError, match='Freeze cross-check incomplete: 1 sealed hashes'):
            build(tree)
        assert not tree['output'].exists()
    else:
        rows, projects, check = build(tree)
        assert rows[relative]['sha256'] == ''
        assert rows[relative]['class'] == 'hash_only'
        assert projects[project_id]['sealed']
        verifier.verify_archive(tree['output'])


@pytest.mark.parametrize('role', ['graphs', 'mapping'])
def test_graph_mapping_roles_hash_all_bulk_exports(tree, role):
    directory = 'route-b-derived-test'
    catalog = tree['catalog'] + [(directory, 'v3', role, 'Synthetic derived exports')]
    public = ('manifest.json', 'summary.json', 'verify.json', 'verification.json',
              'audit.json', 'selection.json', 'README.md')
    bulk = ('records.json', 'functions.json', 'variables.json', 'request.json',
            'worker.log', 'small-graph.json', 'features.json', 'kernel.c')
    for name in public + bulk:
        put(tree['scratch'] / directory / name, '{}\n')
    # Withholding wins before JSON parsing/redaction; bulk is still hashed.
    put_json(tree['scratch'] / directory / 'raw.json', {'definition': 'int x;'})
    rows, projects, check = build(tree, catalog=catalog)
    for name in public:
        assert rows[directory + '/' + name]['class'] == 'tier1'
    for name in bulk + ('raw.json',):
        row = rows[directory + '/' + name]
        assert row['class'] == 'hash_only'
        assert row['sha256'] == sha(tree['scratch'] / directory / name)
        assert row['archived_path'] == row['redacted_path'] == ''
    verifier.verify_archive(tree['output'])


@pytest.mark.parametrize('name', ['scores.json', 'logits.json', 'seed17/predictions.json', 'worker.log'])
def test_training_dumps_and_logs_have_one_mib_boundary(tree, name):
    directory = 'route-b-training-test'
    catalog = tree['catalog'] + [(directory, 'v3', 'training', 'Synthetic training')]
    small = put(tree['scratch'] / directory / 'small' / name, b'0' + b' ' * (builder.MIB - 2))
    large = put(tree['scratch'] / directory / 'large' / name, b'0' + b' ' * (builder.MIB - 1))
    public = ('summary.json', 'decision.json', 'configuration.json', 'pins.json',
              'metrics.csv', 'history.json')
    for filename in public:
        put(tree['scratch'] / directory / filename, '{}\n')
    rows, projects, check = build(tree, catalog=catalog)
    assert rows[small.relative_to(tree['scratch']).as_posix()]['class'] == 'tier1'
    row = rows[large.relative_to(tree['scratch']).as_posix()]
    assert row['class'] == 'hash_only'
    assert row['sha256'] == sha(large)
    assert row['archived_path'] == row['redacted_path'] == ''
    for filename in public:
        assert rows[directory + '/' + filename]['class'] == 'tier1'
    verifier.verify_archive(tree['output'])


@pytest.mark.parametrize('dry_run', [False, True])
def test_tier1_size_guard_includes_redactions_and_prints_largest(tree, monkeypatch, capsys, dry_run):
    rows, projects, check = build(tree, dry_run=True)
    originals = sum(row['bytes'] for row in rows.values() if row['class'] == 'tier1')
    redacted, changed = builder.redact_json(json.loads((tree['scratch'] / tree['panel'] / 'plan.json').read_bytes()))
    total = originals + len(builder.json_bytes(redacted))
    capsys.readouterr()
    monkeypatch.setattr(builder, 'TIER1_LIMIT', total - 1)
    with pytest.raises(ValueError, match='Tier1 size limit exceeded'):
        build(tree, dry_run=dry_run)
    assert not tree['output'].exists()
    output = capsys.readouterr().out
    assert 'TIER1_TOTAL_BYTES\t{}\tLIMIT_BYTES\t{}'.format(total, total - 1) in output
    lines = [line for line in output.splitlines() if line.startswith('TIER1_FILE\t')]
    assert len(lines) == min(20, sum(row['class'] == 'tier1' or bool(row['redacted_path'])
                                   for row in rows.values()))
    assert [int(line.split('\t')[1]) for line in lines] == sorted(
        [int(line.split('\t')[1]) for line in lines], reverse=True)
    assert any('\tredacted\ttier1/' + tree['panel'] + '/plan.json' in line for line in lines)
    monkeypatch.setattr(builder, 'TIER1_LIMIT', total)
    build(tree, dry_run=dry_run)


def test_sealed_freeze_dependency_fails_closed_without_reading(tree, monkeypatch):
    path = tree['scratch'] / tree['v5'] / 'freeze.json'
    freeze = json.loads(path.read_bytes())
    freeze['artifact_files']['../.scratch/selective_analysis/' + tree['panel'] + '/b64-hidden.txt'] = 'f' * 64
    put_json(path, freeze)
    original_open = Path.open
    def guarded_open(path, *args, **kwargs):
        if builder.sealed(path):
            raise AssertionError('Sealed file was opened: ' + str(path))
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded_open)
    with pytest.raises(ValueError, match='Freeze cross-check incomplete: 1 sealed hashes'):
        build(tree)
    assert not tree['output'].exists()
