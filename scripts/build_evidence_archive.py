#!/usr/bin/env python3
"""Build the two-tier Route B evidence archive without changing its inputs."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from contextlib import contextmanager


REPOSITORY = Path('.')
SCRATCH = Path('../.scratch/selective_analysis')
LIMIT = 5 * 1024 * 1024
MIB = 1024 * 1024
TIER1_LIMIT = 150_000_000  # MB, not MiB; includes redacted copies.
SEALED_PROJECTS = {'utf8_h', 'b64'}
CLASSES = ('tier1', 'tier2', 'hash_only')
JULIET = ('public domain in the US, CC0 1.0 elsewhere (NIST SARD Juliet C/C++ 1.3, '
          '2017-10-01 release; NIST disclaimer applies)')
PERMISSIVE = {'MIT', 'BSD-2', 'BSD-3', 'Apache-2.0', 'ISC', 'zlib',
              'Unlicense', 'CC0', 'public domain', 'other permissive'}

# Exact names are intentional: no glob may silently admit a later experiment.
# Each row is (directory-name pattern, study, role, supported claim/scope).
CATALOG = [
    ('route-b-type-corpus-20261119T195435581328Z', 'v1', 'corpus', 'Original pinned type corpus and initial inventories'),
    ('route-b-type-corpus-v2-20261119T220534466210Z', 'v1', 'corpus', 'Corrected link recipe and retained type inventory'),
    ('route-b-type-mapping-20261119T222853346909Z', 'v1', 'mapping', 'Portable mapping preparation'),
    ('route-b-type-mapping-20261119T223020304246Z', 'v1', 'mapping', 'Four-function mapping observations and audit'),
    ('route-b-type-graphs-20261119T224826100287Z', 'v1', 'graphs', 'Graph export preparation'),
    ('route-b-type-graphs-20261119T225139067843Z', 'v1', 'graphs', 'Superseded graph export attempt'),
    ('route-b-type-graphs-20261119T225215150614Z', 'v1', 'graphs', 'Reviewed train and development graph export'),
    ('route-b-type-training-20261119T232826801169Z', 'v1', 'training', 'Portable training preparation'),
    ('route-b-type-training-20261120T191305623359Z', 'v1', 'training', 'Training smoke run'),
    ('route-b-type-training-20261120T191335375352Z', 'v1', 'training', 'Fixed full training pilot'),
    ('route-b-type-coverage-20261120T192024747568Z', 'v1', 'report', 'Coverage and representation diagnosis'),
    ('route-b-type-dev-extension-20261120T192757085592Z', 'v2', 'corpus', 'Development selection and failed and completed inventories'),
    ('route-b-type-dev-graphs-20261120T195202135627Z', 'v2', 'graphs', 'Development graph admission and audit'),
    ('route-b-type-training-v2-20261120T200706851176Z', 'v2', 'training', 'Superseded training preparation attempt'),
    ('route-b-type-training-v2-20261120T200823775624Z', 'v2', 'training', 'Fixed v2 type pilot'),
    ('route-b-type-corpus-v3-20261120T203240742242Z', 'v3', 'corpus', 'Expanded pinned corpus and inventories'),
    ('route-b-type-v3-graphs-20261120T205341199496Z', 'v3', 'graphs', 'Expanded graph admission and audit'),
    ('route-b-type-training-v3-20261120T222850505986Z', 'v3', 'training', 'Superseded memory-exhausted smoke attempt'),
    ('route-b-type-training-v3-20261120T223803803128Z', 'v3', 'training', 'Superseded intermediate training attempt'),
    ('route-b-type-training-v3-20261120T225803823863Z', 'v3', 'training', 'Superseded interrupted training and depth-selection records'),
    ('route-b-type-training-v3-20261121T001331640123Z', 'v3', 'training', 'Completed fixed v3 type pilot'),
    ('route-b-v4-backend-regression-20261121T073429858926Z', 'v4', 'regression', 'Pre-freeze backend regression gate'),
    ('route-b-v4-freeze-20261121T073634943739Z', 'v4', 'freeze', 'Frozen v4 protocol and implementation'),
    ('route-b-v4-panel-20261121T073950924Z', 'v4', 'panel', 'Held-out structural-selection panel'),
    ('route-b-v4-selector-20261121T074211473909Z', 'v4', 'selector', 'Development-only selector fit'),
    ('route-b-v4-run-20261121T074927114386Z', 'v4', 'run', 'Recorded structural-selection comparison'),
    ('route-b-v4-backend-regression-20261122T114154345536Z', 'v5', 'regression', 'Re-run v4 backend gate before v5 freeze'),
    ('route-b-v5-sources-20261122T113743500630Z', 'v5', 'sources', 'Original amendment-1 source pins'),
    ('route-b-v5-build-20261122T190701Z', 'v5', 'superseded attempt', 'Undersized native build cited by amendment 2'),
    ('route-b-v5-sources-a2-20261122T191324378738Z', 'v5', 'sources', 'Initial amendment-2 source pins'),
    ('route-b-v5-sources-20261122T193721788464Z', 'v5', 'sources', 'Earlier base source inventory'),
    ('route-b-v5-sources-a2-20261122T193823549668Z', 'v5', 'sources', 'Earlier amendment-2 source inventory'),
    ('route-b-v5-sources-merged-20261122T194330Z', 'v5', 'sources', 'Earlier merged sources manifest'),
    ('route-b-v5-build-20261122T194330Z', 'v5', 'superseded attempt', 'Pre-amendment-3 build'),
    ('route-b-v5-screen-20261122T204019Z', 'v5', 'superseded attempt', 'Original v5 screen retained by amendment 3'),
    ('route-b-v5-screen-v4panel-20261122T204019Z', 'v5', 'superseded attempt', 'Original v4 screen retained by amendment 3'),
    ('route-b-v5-sources-20261122T211141478427Z', 'v5', 'sources', 'Corrected amendment-3 base source inventory'),
    ('route-b-v5-sources-a2-20261122T211233498631Z', 'v5', 'sources', 'Corrected amendment-3 additional source inventory'),
    ('route-b-v5-sources-merged-20261122T211650Z', 'v5', 'sources', 'Final merged source pins'),
    ('route-b-v5-build-20261122T211650Z', 'v5', 'build', 'Final native build and candidate accounting'),
    ('route-b-v5-screen-20261122T211650Z', 'v5', 'screen', 'Corrected v5 native sanitizer screen'),
    ('route-b-v5-screen-v4panel-20261122T211650Z', 'v5', 'screen', 'Corrected v4 native sanitizer screen'),
    ('route-b-v5-v4rescore-20261122T211650Z', 'v5', 'report', 'Report-only screened v4 re-score'),
    ('route-b-v5-panel-20261122T221742Z', 'v5', 'panel', 'Finalized screened panel and references'),
    ('route-b-v5-freeze-20261122T221749467036Z', 'v5', 'freeze', 'Frozen v5 protocol, amendments and artifact hashes'),
    ('route-b-v5-selector-20261122T221820142755Z', 'v5', 'selector', 'Refitted development selector'),
    ('route-b-v5-run-20261122T222921001778Z', 'v5', 'run', 'Recorded cascade headroom comparison'),
    ('route-b-v5-report-20261122T211650Z', 'v5', 'report', 'Fixed primary and report-only analyses'),
]


def sealed(path, sealed_paths=()):
    parts = str(path).replace('\\', '/').lower().split('/')
    if (any(part in ('utf8_h', 'utf8.h', 'b64') for part in parts[:-1])
            or parts[-1] == 'utf8.h'
            or parts[-1].startswith(('utf8_h-', 'utf8_h.', 'b64-', 'b64.'))):
        return True
    # Manifest attribution also protects aliases without a project name in them.
    if sealed_paths:
        absolute = Path(os.path.abspath(str(path)))
        return any(str(p).replace('\\', '/').lower() in sealed_paths
                   for p in (absolute,) + tuple(absolute.parents))
    return False


def file_hash(path, sealed_paths=()):
    if sealed(path, sealed_paths):
        raise ValueError('Sealed path must never be opened: ' + str(path))
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def load_json(path, sealed_paths=()):
    if sealed(path, sealed_paths):
        raise ValueError('Sealed path must never be opened: ' + str(path))
    return json.loads(Path(path).read_bytes())


def contained(path, directory):
    try:
        Path(path).resolve().relative_to(Path(directory).resolve())
        return True
    except ValueError:
        return False


@contextmanager
def working_directory(directory):
    """Shorten Windows junction paths without opening files by absolute names."""
    previous = Path.cwd()
    try:
        os.chdir(str(directory))
        yield
    finally:
        os.chdir(str(previous))


def child(directory, value):
    value = str(value).replace('\\', '/')
    parts = value.split('/')
    if not value or value.startswith('/') or ':' in value or '..' in parts:
        raise ValueError('Unsafe relative path: ' + value)
    target = Path(directory) / value
    if not contained(target, directory):
        raise ValueError('Path escapes directory: ' + value)
    return target


def artifact_path(value, repository, scratch):
    """Rebase historical Windows/WSL paths, using the retained scratch root."""
    value = str(value).replace('\\', '/')
    marker = 'selective_analysis/'
    # The marker must be followed by a Route B bundle, not a repository module.
    if marker in value and value.split(marker, 1)[1].startswith('route-b-'):
        return child(scratch, value.split(marker, 1)[1])
    if value.rstrip('/').endswith('selective_analysis'):
        return Path(scratch)
    return child(repository, value)


def validate_output(output, repository=REPOSITORY, scratch=SCRATCH):
    output = Path(output)
    test_area = Path(repository) / '.test-output'
    test_exception = contained(output, test_area) and output.resolve() != test_area.resolve()
    if not test_exception:
        if contained(output, repository) or contained(output, scratch):
            raise ValueError('Output must be outside repository and scratch (except .test-output/)')
        if '.scratch' in [p.lower() for p in output.resolve().parts]:
            raise ValueError('Output must be outside .scratch')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('Output directory exists and is non-empty: ' + str(output))
    # A junction named .test-output must not grant access outside the exception.
    if test_exception and not contained(output, repository):
        raise ValueError('Test output junction escapes repository')
    return output


def classify_license(text):
    """Conservative textual recognition; filenames alone never grant permission."""
    # picoc retains its notice as a generated C byte array, not prose. Decode
    # that narrow representation without compiling or executing anything.
    encoded = re.search(r'char\s+\w*LICENSE\w*\s*\[\s*\]\s*=\s*\{([^}]+)\}', text, re.I)
    body = encoded.group(1).replace("'\\0'", '0x00') if encoded else ''
    if encoded and re.fullmatch(r'(?:\s|,|0x[0-9a-fA-F]{2})+', body):
        text = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', body)).decode('utf-8', errors='replace')
    # Full copyleft headings take precedence. Incidental GPL compatibility
    # references in an Apache LLVM exception do not make that notice GPL.
    headings = list(re.finditer(
        r'^[ \t]*(?:\*[ \t]*)?gnu (lesser |library )?general public license(?:[ \t]+version[^\r\n]*)?[ \t]*$',
        text, re.I | re.M))
    if headings:
        return 'LGPL' if headings[0].group(1) else 'GPL'
    text = re.sub(r'\s+', ' ', text.lower())
    if re.search(r'spdx-license-identifier:\s*lgpl-', text):
        return 'LGPL'
    if re.search(r'spdx-license-identifier:\s*gpl-', text):
        return 'GPL'
    if ('apache license' in text and ('version 2.0' in text or 'license-2.0' in text)
            or 'spdx-license-identifier: apache-2.0' in text):
        return 'Apache-2.0'
    if 'gnu lesser general public license' in text or 'gnu library general public license' in text:
        return 'LGPL'
    if 'gnu general public license' in text or re.search(r'\bgpl[-v]?[23]\b', text):
        return 'GPL'
    if 'creative commons' in text and ('cc0' in text or 'zero v1.0' in text):
        return 'CC0'
    if 'this is free and unencumbered software released into the public domain' in text:
        return 'Unlicense'
    if 'spdx-license-identifier: bsd-3-clause' in text:
        return 'BSD-3'
    if 'spdx-license-identifier: bsd-2-clause' in text:
        return 'BSD-2'
    if ('permission is hereby granted, free of charge' in text and
            ('deal in the software without restriction' in text or 'mit license' in text)):
        return 'MIT'
    if ('redistribution and use in source and binary forms' in text and
            'redistributions of source code must retain' in text and
            'redistributions in binary form must reproduce' in text):
        if 'advertising materials' in text:
            return 'unknown'  # Do not silently call four-clause BSD BSD-3.
        return 'BSD-3' if ('neither the name' in text or 'may not be used to endorse' in text) else 'BSD-2'
    if ('redistribution and use in source and binary forms' in text and
            'redistributions of source code must retain' in text and
            'following conditions' in text and 'disclaimer' in text and
            'advertising' not in text):
        return 'other permissive'  # The retained one-clause BSD notice in tpl.
    if ('boost software license - version 1.0' in text and
            'permission is hereby granted, free of charge' in text and
            'prepare derivative works' in text):
        return 'other permissive'
    if ('permission to use, copy, modify, and' in text and
            ('for any purpose with or without fee' in text or 'isc license' in text)):
        return 'ISC'
    if ('origin of this software must not be misrepresented' in text and
            'altered source versions must be plainly marked' in text):
        return 'zlib'
    if ('dedicated to the public domain' in text or 'released into the public domain' in text
            or 'this software is in the public domain' in text):
        return 'public domain'
    if ('permission' in text and 'distribute' in text and 'modify' in text and
            ('for any purpose' in text or 'without fee' in text) and
            'all rights reserved' not in text):
        return 'other permissive'
    return 'unknown'


def project_rows(data):
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict) and 'project_id' in row]
    return [row for key in ('projects', 'new_projects', 'reused_development_projects',
                            'development_projects', 'training_projects')
            for row in data.get(key, []) if isinstance(row, dict)]


def collect_manifest_seals(scratch, repository, catalog):
    """Read public manifests before opening any project-attributed evidence."""
    manifests = []
    sealed_paths = set()

    def add(value, directory):
        value = str(value).replace('\\', '/')
        if 'selective_analysis/' in value:
            path = artifact_path(value, repository, scratch)
        else:
            path = child(directory, value)
        sealed_paths.add(str(Path(os.path.abspath(str(path)))).replace('\\', '/').lower())

    def visit(value, directory, owner=None, source=None):
        if isinstance(value, list):
            for item in value:
                visit(item, directory, owner, source)
        elif isinstance(value, dict):
            owner = value.get('project_id', value.get('project', owner))
            source = value.get('source_directory', source)
            for key, item in value.items():
                if isinstance(owner, str) and owner in SEALED_PROJECTS:
                    if isinstance(item, str) and (key in ('path', 'file', 'dwarf_elf', 'bridge',
                                                         'binary', 'elf', 'labels')
                                                  or key.endswith(('_path', '_file', '_directory'))):
                        add(item, directory)
                    if key in ('files', 'source_files', 'license_evidence', 'headers', 'translation_units'):
                        base = artifact_path(source, repository, scratch) if source else directory
                        for filename in item if isinstance(item, (dict, list)) else ():
                            add(filename, base)
                visit(item, directory, owner, source)

    for path, role in enumerate_files(scratch, catalog):
        relative = path.relative_to(scratch).as_posix()
        if (path.suffix.lower() != '.json'
                or not ('manifest' in path.name.lower() or path.name == 'source-records.json')
                or 'sources' in Path(relative).parts[1:]
                or sealed(path, sealed_paths)):
            continue
        data = load_json(path, sealed_paths)
        manifests.append((relative, data))
        visit(data, path.parent)
    return manifests, sealed_paths


def collect_licenses(scratch, repository, catalog, include_juliet=False,
                     manifests=None, sealed_paths=()):
    if manifests is None:
        manifests, sealed_paths = collect_manifest_seals(scratch, repository, catalog)
    projects = {}
    for manifest, data in manifests:
        for project in project_rows(data):
            project_id = project.get('project_id')
            if not project_id or not re.fullmatch(r'[A-Za-z0-9_.-]+', project_id):
                raise ValueError('Invalid project ID in ' + manifest)
            record = projects.setdefault(project_id, {'project': project_id, 'evidence': {},
                                                      'manifests': [], 'sealed': False})
            record['manifests'].append(manifest)
            source = project.get('source_directory')
            if project_id in SEALED_PROJECTS or (source and sealed(
                    artifact_path(source, repository, scratch), sealed_paths)):
                record['sealed'] = True
                continue
            if not source:
                continue
            source = artifact_path(source, repository, scratch)
            for filename, expected in project.get('license_evidence', {}).items():
                license_path = child(source, filename)
                if sealed(license_path, sealed_paths):
                    record['sealed'] = True
                    continue
                actual = file_hash(license_path, sealed_paths)
                if actual != expected:
                    raise ValueError('License evidence hash mismatch: ' + str(license_path))
                evidence_name = license_path.relative_to(scratch).as_posix()
                record['evidence'][evidence_name] = {
                    'path': license_path, 'sha256': actual,
                    'classification': classify_license(license_path.read_text(encoding='utf-8', errors='replace'))}
    for record in projects.values():
        kinds = {e['classification'] for e in record['evidence'].values()}
        # A restrictive or unrecognized notice vetoes a permissive-looking notice.
        record['classification'] = next((x for x in ('GPL', 'LGPL', 'unknown') if x in kinds),
                                        sorted(kinds)[0] if kinds else 'unknown')
        if record['sealed']:
            record['classification'] = 'unknown'
        record['permissive'] = record['classification'] in PERMISSIVE
        record['decision'] = ('withheld: sealed; never opened' if record['sealed'] else
                              'include' if record['permissive'] else 'withhold: ' + record['classification'])
    projects['Juliet'] = {'project': 'Juliet', 'classification': JULIET, 'evidence': {},
                          'manifests': [], 'sealed': False, 'permissive': include_juliet,
                          'decision': 'include (--include-juliet)' if include_juliet else
                                      'withhold: requires --include-juliet'}
    return projects


# All these fields occur in extracted kernel specifications. Redact wherever
# they occur, including nested rejections/records, not just candidates[*].spec.
CODE_FIELDS = {'definition', 'body', 'preamble', 'setup', 'call', 'static_dependencies',
               'edits', 'source_code', 'source_text', 'code', 'c_source', 'implementation',
               'detail'}


def redact_json(value):
    changed = False
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.lower() in CODE_FIELDS:
                canonical = json.dumps(item, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=True, allow_nan=False).encode('ascii')
                result[key] = {'redacted_sha256': hashlib.sha256(canonical).hexdigest()}
                changed = True
            else:
                result[key], nested = redact_json(item)
                changed = changed or nested
        return result, changed
    if isinstance(value, list):
        result = []
        for item in value:
            item, nested = redact_json(item)
            result.append(item)
            changed = changed or nested
        return result, changed
    return value, False


def project_for(relative, projects, data=None):
    parts = Path(relative).parts
    lower = relative.lower()
    if 'juliet' in lower or Path(relative).name.startswith('CWE'):
        return ['Juliet']
    if data is not None:
        found = set()
        def visit(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('project', 'project_id') and isinstance(item, str):
                        found.add('Juliet' if item.lower() == 'juliet' else item)
                    else:
                        visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        visit(data)
        if found:
            return sorted(found)
    for name in sorted(projects, key=len, reverse=True):
        if name == 'Juliet':
            continue
        if any(part == name or part.startswith(name + '-') or part.startswith(name + '.')
               for part in parts[1:]):
            return [name]
    return []


def classify_file(relative, size, role='', data=None, sealed_paths=()):
    path = Path(relative)
    parts = [p.lower() for p in path.parts[1:]]
    name = path.name.lower()
    if sealed(relative, sealed_paths):
        return 'hash_only', 'sealed: never opened; SHA-256 unavailable'
    if 'sources' in parts:
        return 'hash_only', 'full source clone (license notices copied separately)'
    if any(p in ('temp', 'tmp', '__pycache__', '.cache') or p.startswith(('tmp-', 'temp-')) for p in parts):
        return 'hash_only', 'temporary directory'
    if path.suffix.lower() in ('.pt', '.pth', '.ckpt'):
        return 'hash_only', 'model checkpoint'
    if role in ('graphs', 'mapping'):
        public = ('manifest', 'summary', 'verify', 'verification', 'audit', 'selection', 'readme')
        if not any(token in name for token in public):
            return 'hash_only', 'derived graph/mapping export; retain protocol evidence only'
    if role == 'training' and size >= MIB:
        if any(token in name for token in ('score', 'logit', 'prediction')):
            return 'hash_only', 'training score/logit/prediction dump at least 1 MiB'
        if path.suffix.lower() == '.log':
            return 'hash_only', 'training log at least 1 MiB'
    graph = ('graph' in role or any(x in name for x in ('graph', 'tensor', 'dataset', 'preprocess', 'capture')))
    if graph and size > LIMIT and role not in ('graphs', 'mapping'):
        return 'hash_only', 'graph tensor/export above 5 MiB'
    if data is not None and redact_json(data)[1]:
        return 'tier2', 'code-bearing JSON; public redacted copy provided'
    if (path.suffix.lower() in ('.c', '.h', '.elf', '.exe', '.o', '.py', '.cpp', '.hpp')
            or 'dwarf' in name or name.endswith('.labels.json')):
        return 'tier2', 'source, executable, or DWARF inventory'
    # Compiler diagnostics can quote upstream source lines. Never put them in tier1.
    if (name.endswith(('-build.log', '.build.log', '-host-syntax.log')) or
            ('dwarf' in parts and path.suffix == '.log')):
        return 'tier2', 'compiler diagnostics may quote third-party code'
    if path.suffix.lower() in ('.json', '.md', '.log', '.txt', '.tsv', '.csv'):
        return 'tier1', 'protocol, records, metadata, or summary'
    return 'tier2', 'unrecognized format; conservative license gate'


FIELDS = ('relative_path', 'bytes', 'sha256', 'class', 'archived_path', 'redacted_sha256',
          'redacted_path', 'license_paths', 'projects', 'reason')


def enumerate_files(scratch, catalog):
    for name, study, role, claim in catalog:
        directory = child(scratch, name)
        if not directory.is_dir():
            raise ValueError('Catalogued directory missing: ' + name)
        def walk_error(error):
            raise error
        for root, directories, files in os.walk(str(directory), followlinks=False, onerror=walk_error):
            if not contained(Path(root), scratch):
                raise ValueError('Evidence directory link escapes scratch: ' + str(root))
            directories.sort()
            for filename in sorted(files):
                path = Path(root) / filename
                if path.is_symlink() and not contained(path, scratch):
                    raise ValueError('Evidence link escapes scratch: ' + str(path))
                yield path, role


def scan(scratch, repository, catalog, projects, sealed_paths=()):
    rows = {}
    redactions = {}
    for path, role in enumerate_files(scratch, catalog):
        relative = path.relative_to(scratch).as_posix()
        size = path.stat().st_size
        kind, reason = classify_file(relative, size, role, sealed_paths=sealed_paths)
        data = None
        if kind != 'hash_only' and path.suffix.lower() == '.json':
            data = load_json(path, sealed_paths)
            kind, reason = classify_file(relative, size, role, data, sealed_paths)
        row = dict.fromkeys(FIELDS, '')
        row.update(relative_path=relative, bytes=size,
                   sha256='' if sealed(path, sealed_paths) else file_hash(path, sealed_paths),
                   **{'class': kind, 'reason': reason})
        owners = project_for(relative, projects, data if kind == 'tier2' else None)
        row['projects'] = ','.join(owners)
        if kind == 'tier1':
            row['archived_path'] = 'tier1/' + relative
        elif kind == 'tier2':
            allowed = owners and all(projects.get(p, {}).get('permissive', False) for p in owners)
            if allowed:
                row['archived_path'] = 'tier2/' + relative
            else:
                row['reason'] += '; withheld: ' + ', '.join(
                    p + '=' + projects.get(p, {}).get('decision', 'unknown') for p in owners)
                if not owners:
                    row['reason'] += 'unattributed project/license unknown'
            if data is not None:
                redacted, changed = redact_json(data)
                if changed:
                    content = json_bytes(redacted)
                    row['redacted_path'] = 'tier1/' + relative
                    row['redacted_sha256'] = hashlib.sha256(content).hexdigest()
                    redactions[relative] = content
        rows[relative] = row
    # Extract only the notices of permissive projects from otherwise hash-only clones.
    for project in projects.values():
        if not project['permissive']:
            continue
        for relative, evidence in project['evidence'].items():
            if relative not in rows:
                raise ValueError('License evidence outside catalog: ' + relative)
            destination = 'tier2/LICENSES/{}/{}/{}'.format(
                project['project'], evidence['sha256'], Path(relative).name)
            row = rows[relative]
            paths = json.loads(row['license_paths'] or '[]')
            if destination not in paths:
                paths.append(destination)
            row['license_paths'] = json.dumps(sorted(paths), separators=(',', ':'))
    return rows, redactions


def freeze_crosscheck(scratch, repository, catalog, rows, sealed_paths=()):
    checks = []
    for name, study, role, claim in catalog:
        if role != 'freeze' or study not in ('v4', 'v5'):
            continue
        freeze = load_json(child(scratch, name) / 'freeze.json', sealed_paths)
        references = []
        for relative, expected in freeze['pins'].items():
            references.append(('pins/' + relative, child(repository, relative), expected))
        for relative, expected in freeze.get('artifact_files', {}).items():
            references.append(('artifact_files/' + relative, artifact_path(relative, repository, scratch), expected))
        if 'design_sha256' in freeze:
            design = [relative for relative in freeze['pins'] if relative.endswith('_design.md')]
            if len(design) != 1:
                raise ValueError('Cannot resolve frozen design: ' + name)
            references.append(('design_sha256', child(repository, design[0]), freeze['design_sha256']))
        # Older v4 freezes store regression hashes outside artifact_files.
        for section, filenames in (('regression', {'summary_sha256': 'summary.json', 'records_sha256': 'records.json'}),
                                    ('sources', {'manifest_sha256': 'sources-manifest.json'}),
                                    ('build', {'plan_sha256': 'plan.json'})):
            item = freeze.get(section, {})
            for key, filename in filenames.items():
                if key in item:
                    directory = artifact_path(item['directory'], repository, scratch)
                    references.append((section + '/' + key, child(directory, filename), item[key]))
        if 'screen' in freeze:
            screen = freeze['screen']
            references.append(('screen/sha256', artifact_path(screen['file'], repository, scratch), screen['sha256']))
        panel = freeze.get('panel', {})
        for filename, expected in panel.get('files', {}).items():
            directory = artifact_path(panel['directory'], repository, scratch)
            references.append(('panel/files/' + filename, child(directory, filename), expected))
        for field, path, expected in references:
            protected = sealed(path, sealed_paths)
            actual = None if protected else file_hash(path, sealed_paths)
            if not protected and actual != expected:
                raise ValueError('Freeze hash mismatch: ' + name + ' ' + field +
                                 ' expected=' + expected + ' actual=' + actual)
            check = {'freeze': name, 'field': field, 'expected_sha256': expected,
                     'actual_sha256': actual, 'matched': None if protected else True}
            if contained(path, scratch):
                relative = path.relative_to(scratch).as_posix()
                if relative not in rows:
                    row = dict.fromkeys(FIELDS, '')
                    row.update(relative_path=relative, bytes=path.stat().st_size, sha256=actual or '',
                               **{'class': 'hash_only', 'reason':
                                  'sealed: never opened; SHA-256 unavailable' if protected else
                                  'freeze dependency outside catalog'})
                    rows[relative] = row
                row = rows[relative]
                if not protected and row['sha256'] != actual:
                    raise ValueError('Evidence changed during scan: ' + relative)
                check.update(path='selective_analysis/' + relative, **{'class': row['class']},
                             archived_as=([row['class']] if row['archived_path'] else []) +
                                         (['tier1 redacted'] if row['redacted_path'] else []) or ['hash_only'],
                             archived_path=row['archived_path'], redacted_path=row['redacted_path'],
                             reason=row['reason'])
            else:
                check.update(path=path.relative_to(repository).as_posix(), archived_as=['repository pin'])
            checks.append(check)
    counts = Counter(check['freeze'] for check in checks)
    verified = Counter(check['freeze'] for check in checks if check['matched'])
    unverified = [check['path'] for check in checks if check['matched'] is None]
    return {'passed': not unverified, 'checks': checks, 'counts': dict(sorted(counts.items())),
            'verified_counts': dict(sorted(verified.items())), 'unverified': unverified,
            'note': 'Original bytes were checked, including withheld and redacted originals. '
                    'Sealed paths were not opened and cannot be declared verified. '
                    'A redacted copy has its own digest; it is not byte-identical to the freeze.'}


def tier1_files(rows, redactions):
    files = []
    for relative, row in rows.items():
        if row['class'] == 'tier1':
            files.append((row['bytes'], row['archived_path'], 'original'))
        if row['redacted_path']:
            files.append((len(redactions[relative]), row['redacted_path'], 'redacted'))
    return sorted(files, key=lambda item: (-item[0], item[1]))


def print_tables(rows, projects, crosscheck, redactions):
    totals = defaultdict(lambda: [0, 0])
    directories = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for row in rows.values():
        kind = row['class']
        totals[kind][0] += 1
        totals[kind][1] += row['bytes']
        directory = row['relative_path'].split('/')[0]
        directories[directory][kind][0] += 1
        directories[directory][kind][1] += row['bytes']
    print('CLASS\tFILES\tBYTES (original files; tier2 includes withheld)')
    for kind in CLASSES:
        print('{}\t{}\t{}'.format(kind, *totals[kind]))
    print('DIRECTORY\ttier1 files\ttier1 bytes\ttier2 files\ttier2 bytes\thash_only files\thash_only bytes')
    for directory, counts in sorted(directories.items()):
        print('\t'.join([directory] + [str(n) for kind in CLASSES for n in counts[kind]]))
    print('REDACTED_COPIES\t{}'.format(sum(bool(r['redacted_path']) for r in rows.values())))
    print('WITHHELD_TIER2_FILES\t{}'.format(sum(r['class'] == 'tier2' and not r['archived_path'] for r in rows.values())))
    print('SEALED_FILES_UNOPENED\t{}'.format(sum(not r['sha256'] for r in rows.values())))
    public_files = tier1_files(rows, redactions)
    public_bytes = sum(size for size, path, kind in public_files)
    redacted_bytes = sum(len(content) for content in redactions.values())
    print('REDACTED_COPY_BYTES\t{}'.format(redacted_bytes))
    print('TIER1_TOTAL_BYTES\t{}\tLIMIT_BYTES\t{}'.format(public_bytes, TIER1_LIMIT))
    print('LARGEST_TIER1_FILES\tBYTES\tKIND\tARCHIVED_PATH (20 largest, including redacted copies)')
    for size, path, kind in public_files[:20]:
        print('TIER1_FILE\t{}\t{}\t{}'.format(size, kind, path))
    print('LICENSE CLASSIFICATION\tPROJECTS (unique project IDs, all manifest versions)')
    for kind, count in sorted(Counter(p['classification'] for p in projects.values()).items()):
        print('{}\t{}'.format(kind, count))
    print('NON_PERMISSIVE_OR_SEALED\tCLASSIFICATION\tDECISION')
    for name, project in sorted(projects.items()):
        if project['classification'] not in PERMISSIVE or project['sealed']:
            print('{}\t{}\t{}'.format(name, project['classification'], project['decision']))
    print('FREEZE_CROSSCHECK\t{}\t{} recorded hashes; {} verified; {} sealed/unverified'.format(
        'PASS' if crosscheck['passed'] else 'INCOMPLETE', len(crosscheck['checks']),
        sum(crosscheck['verified_counts'].values()), len(crosscheck['unverified'])))
    for name, count in sorted(crosscheck['counts'].items()):
        verified = crosscheck['verified_counts'].get(name, 0)
        print('{}\t{}\t{} / {}'.format(name, 'PASS' if verified == count else 'INCOMPLETE', verified, count))
    return public_bytes


RULES = '''Rules, in precedence order:

* Sealed evaluation projects are utf8_h and b64. Exact directory components
  utf8_h, utf8.h, b64; the filename utf8.h; filenames starting utf8_h-, utf8_h.,
  b64-, b64.; and files attributed to either sealed project in manifests are
  never opened, including for hashing or license review. Argon2 kernels with
  b64 inside their names are not sealed. Sealed class is hash_only, size is metadata,
  and their SHA-256 is deliberately blank. No digest is invented. This exception
  to complete hashing preserves the sealed evaluation boundary.
* Full sources/ clones, temporary directories, and .pt/.pth/.ckpt checkpoints
  are hash_only. In graphs/mapping roles, only filenames containing manifest,
  summary, verify, verification, audit, selection, or readme are eligible for tier1;
  other derived exports are hash_only at every size. This includes superseded
  graph attempts. Elsewhere, graph tensors/exports above 5 MiB remain hash_only.
  Training score/logit/prediction dumps and .log files at least 1 MiB are hash_only,
  including superseded training attempts. Summaries, decisions, configurations,
  pins, metrics tables and smaller logs remain public evidence. License notices
  are the explicit clone exception, copied separately into tier2/LICENSES/.
* C/header/object/executable files, DWARF inventories (including *.labels.json),
  Python snapshots, and compiler diagnostics are tier2. Compiler diagnostics may
  quote third-party lines. Unattributed code is withheld as unknown.
* JSON is inspected recursively. Extracted definition, body, preamble, setup,
  call, static_dependencies, edits, source_code, source_text, code, c_source,
  implementation, and compiler-diagnostic detail fields are replaced by objects holding
  redacted_sha256. Canonical field JSON uses sorted keys, compact separators,
  ensure_ascii=True, allow_nan=False, ASCII bytes, and no trailing newline.
  The original remains tier2; a public redacted copy keeps the original path
  in tier1. The manifest records both original and redacted digests.
* Other JSON, Markdown, text, and non-compiler logs are tier1. Unknown formats
  use tier2 and the license gate. SHA sums always describe archived bytes.
* Tier1 originals plus redacted copies must not exceed 150 MB (150,000,000 bytes).
  The builder prints the 20 largest public files and stops before writing on overflow.
* License recognition uses the notice text, never just a filename. GPL, LGPL,
  or unknown evidence vetoes permissive evidence for that project, across all
  retained manifest versions (including alternative-license bundles). This is
  deliberately conservative. The table is evidence classification, not a
  substitute for reviewing notices before publication. Only MIT, BSD-2, BSD-3,
  Apache-2.0, ISC, zlib, Unlicense, CC0, public domain, and other permissive
  notices admit tier2. Juliet requires --include-juliet separately.
* Juliet. The Juliet Test Suite for C/C++ version 1.3 (NIST SARD, released
  2017-10-01) is not subject to copyright protection in the United States. For
  any foreign rights, NIST makes it available under the CC0 1.0 Public Domain
  Dedication. NIST disclaimer: NIST assumes no responsibility whatsoever for its
  use by other parties, and makes no guarantees, expressed or implied, about its
  quality, reliability, or any other characteristic. The SHA-256 of the
  downloaded archive is recorded in the v5 sources manifest.
'''


def write_text(path, text):
    Path(path).write_bytes(text.encode('ascii'))


def deterministic_zip(directory, destination):
    with zipfile.ZipFile(str(destination), 'w', compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(directory.rglob('*'), key=lambda p: p.relative_to(directory).as_posix()):
            if not path.is_file():
                continue
            entry = zipfile.ZipInfo(path.relative_to(directory).as_posix(), (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_STORED
            with path.open('rb') as source, archive.open(entry, 'w', force_zip64=True) as target:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    target.write(block)


def render_licenses(projects):
    lines = ['# License evidence', '', 'Project classifications combine every retained manifest version.',
             'Sealed projects were not opened. Notices copied into tier2 retain their original bytes.', '',
             '| Project | Classification | Evidence file (notice classification) | Tier2 decision |',
             '| --- | --- | --- | --- |']
    for name, project in sorted(projects.items()):
        notices = ['{} ({})'.format(path, e['classification']) for path, e in sorted(project['evidence'].items())]
        lines.append('| {} | {} | {} | {} |'.format(name, project['classification'],
                     '<br>'.join(notices) or ('sealed; unread' if project['sealed'] else 'none recorded'), project['decision']))
    return '\n'.join(lines) + '\n'


def render_readme(catalog, commit):
    lines = ['# Route B evidence archive', '',
             'This two-tier archive records the evidence behind the pre-registered Route B v1-v5 series.',
             'Repository: https://github.com/witold-andelie/SymbAI-Taint', 'Repository commit: ' + commit, '',
             'For headline numbers and their interpretation, read the Training pilot results, Type pilot v2 results,',
             'Type pilot v3 results, Route B v4 structural selection results, and Route B v5 cascade headroom results',
             'sections of benchmarks/selective_analysis/route_b/README.md at that commit. No new result is asserted here.', '',
             'Original paths below are relative to selective_analysis/. Each tier mirrors those paths.',
             'LICENSES/ inside tier2 contains separately extracted notices, with digest directories to avoid collisions.', '',
             '| Directory | Study | Role | Supported claim/scope |', '| --- | --- | --- | --- |']
    lines.extend('| {} | {} | {} | {} |'.format(*row) for row in catalog)
    lines.extend(['', '## Verification', '',
                  'Extract each zip into its corresponding tier directory (zip entries have no tier prefix).',
                  'From tier1 run: sha256sum -c ../SHA256SUMS-tier1.txt',
                  'From tier2 run: sha256sum -c ../SHA256SUMS-tier2.txt',
                  'With the repository checkout run: python -B scripts/verify_evidence_archive.py <archive-directory>', '',
                  'The verifier checks inventories as well as digests, and rejects missing, extra, or changed files.',
                  'MANIFEST.tsv has one row per original file. class describes the original; archived_path describes',
                  'an included original. redacted_path/redacted_sha256 describe its public substitute. license_paths is',
                  'a JSON array of separately extracted notice paths. bytes and sha256 always describe the original.',
                  'A blank archived_path means the original was withheld. reason explains the decision.', '',
                  'FREEZE_CROSSCHECK.json checks every recorded v4/v5 repository pin, artifact_files entry, panel file,',
                  'design and named regression/source/build/screen hash against the live input before output is written.',
                  'Review passed, counts, and the individual expected_sha256/actual_sha256 pairs. Scratch entries state',
                  'whether the archive holds the original, a redacted substitute, or only its hash. Dependencies outside',
                  'the table are individually hash_only in MANIFEST.tsv; their parent directories are not fully included.',
                  'Repository pins are verifiable in the named checkout. Frozen original hashes cannot be checked against',
                  'redacted substitutes; check those against their separate manifest digest. Re-running the builder with',
                  'the retained scratch tree independently repeats the cross-check. No hash authenticates the deposit',
                  'itself without a trusted copy of these metadata files.', '', '## Inclusion and withholding', '', RULES,
                  '## Regeneration', '',
                  'Use git checkout <repository-commit> in a separate checkout. Read docs/REPRODUCIBILITY.md, especially',
                  'Route B v4 and v5 pipelines, for the ordered commands and runtime requirements. Fetch into a NEW',
                  'scratch tree, then check out each manifest project commit explicitly and verify its source hashes.',
                  'Source preparers initially select default-branch heads: merely re-running a fetch is insufficient.',
                  'The archived manifests retain origins, commits, source/license hashes, build commands and recipes.',
                  'Use prepare_type_corpus.py, build_type_corpus.py, run_type_mapping.py, export_type_graph_dataset.py,',
                  'prepare_type_dev_extension.py, build_type_dev_extension.py, export_type_dev_graphs.py,',
                  'prepare_type_corpus_v3.py, build_type_corpus_v3.py, export_type_v3_graphs.py, and the',
                  'train_type_graph_pilot.py / train_type_pilot_v2.py / train_type_pilot_v3.py entry points for type data.',
                  'Use build_route_b_v4_panel.py, label_route_b_v4_development.py and run_route_b_v4_panel.py for v4;',
                  'use prepare_route_b_v5_sources.py,',
                  'build_route_b_v5_dwarf.py, merge_route_b_v5_sources.py, build_route_b_v5_panel.py,',
                  'screen_route_b_v5_sanitizers.py, freeze_route_b_v5.py, label_route_b_v5_development.py,',
                  'run_route_b_v5_panel.py, rescore_route_b_v4_screened.py and report_route_b_v5.py for v5.',
                  'All entry points are under scripts/. Consult their --help and retained plan/command records.',
                  'The native evidence originally used both Windows/MinGW and the documented Linux/WSL runtime.',
                  'Archive construction itself is standard-library Python and runs on Windows without WSL.',
                  'Third-party dependencies and checkpoints are not installed or fetched by this builder.',
                  'Rebuilt binaries, timestamps and training outputs need not match historical bytes; the original',
                  'hashes remain the record of the historical run. Superseded source/build/screen attempts are retained',
                  'as evidence, not proposed as current procedures.', '',
                  '## Sealed evaluation projects', '',
                  'utf8.h (utf8_h) and b64.c (b64) remain sealed for this archiving operation, including licenses.',
                  'The exact path and manifest-attribution rules above enforce this project boundary.',
                  'Argon2 b64_byte_to_char, b64_char_to_byte and b64len kernels are hashed normally.',
                  'Manifests can identify the original projects and earlier inventory activity;',
                  'this archive makes no claim that those historical inventories never existed.',
                  'These projects were not used in the documented training/evaluation runs of the type pilots.',
                  'Their manifest entries have metadata sizes but blank digests. Do not open them to fill that gap.', ''])
    return '\n'.join(lines)


def emit_archive(output, scratch, rows, redactions, projects, crosscheck, catalog, commit, make_zip,
                 sealed_paths=()):
    output.mkdir(parents=True, exist_ok=True)
    for tier in ('tier1', 'tier2'):
        (output / tier).mkdir()
    sums = {'tier1': {}, 'tier2': {}}
    for relative, row in sorted(rows.items()):
        copies = []
        if row['archived_path']:
            copies.append(row['archived_path'])
        copies.extend(json.loads(row['license_paths'] or '[]'))
        for destination in copies:
            target = child(output, destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = child(scratch, relative)
            if sealed(source, sealed_paths):
                raise ValueError('Refusing sealed copy: ' + relative)
            with source.open('rb') as stream, target.open('wb') as result:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    result.write(block)
            actual = file_hash(target)
            if actual != row['sha256']:
                raise ValueError('Evidence changed while copying: ' + relative)
            tier, local = destination.split('/', 1)
            sums[tier][local] = actual
        if row['redacted_path']:
            target = child(output, row['redacted_path'])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(redactions[relative])
            sums['tier1'][relative] = row['redacted_sha256']
    table = io.StringIO(newline='')
    writer = csv.DictWriter(table, fieldnames=FIELDS, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(row for relative, row in sorted(rows.items()))
    write_text(output / 'MANIFEST.tsv', table.getvalue())
    for tier in ('tier1', 'tier2'):
        write_text(output / ('SHA256SUMS-' + tier + '.txt'), ''.join(
            '{}  {}\n'.format(digest, name) for name, digest in sorted(sums[tier].items())))
    write_text(output / 'LICENSES.md', render_licenses(projects))
    (output / 'FREEZE_CROSSCHECK.json').write_bytes(json_bytes(crosscheck))
    write_text(output / 'ARCHIVE_README.md', render_readme(catalog, commit))
    if make_zip:
        for tier in ('tier1', 'tier2'):
            deterministic_zip(output / tier, output / (tier + '.zip'))


def build_archive(output, scratch=SCRATCH, repository=REPOSITORY, catalog=CATALOG,
                  dry_run=False, make_zip=False, include_juliet=False, commit=None):
    output = validate_output(output, repository, scratch)
    # Validate the entire catalog before reading or hashing any inputs.
    names = [row[0] for row in catalog]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate catalog directory')
    for name in names:
        if not child(scratch, name).is_dir():
            raise ValueError('Catalogued directory missing: ' + name)
    # The read-only junction adds enough lexical path length to break Win32 opens
    # even when the physical filename is short. Work relative to its target for
    # all evidence reads; restore cwd before creating any output.
    # Use logical (junction) parents here: Windows resolves '..' from the
    # current-directory spelling, rather than from the junction's target.
    repository_relative = Path(os.path.relpath(str(Path(repository).absolute()), str(Path(scratch).absolute())))
    with working_directory(scratch):
        manifests, sealed_paths = collect_manifest_seals(Path('.'), repository_relative, catalog)
        projects = collect_licenses(Path('.'), repository_relative, catalog, include_juliet,
                                    manifests, sealed_paths)
        rows, redactions = scan(Path('.'), repository_relative, catalog, projects, sealed_paths)
        crosscheck = freeze_crosscheck(Path('.'), repository_relative, catalog, rows, sealed_paths)
    public_bytes = print_tables(rows, projects, crosscheck, redactions)
    if not crosscheck['passed']:
        raise ValueError('Freeze cross-check incomplete: {} sealed hashes cannot be verified under the no-open rule; '
                         'no archive was written'.format(len(crosscheck['unverified'])))
    if public_bytes > TIER1_LIMIT:
        raise ValueError('Tier1 size limit exceeded: {} bytes > {} bytes (150 MB); '
                         '20 largest tier1 files listed above; no archive was written'.format(
                             public_bytes, TIER1_LIMIT))
    if not dry_run:
        if commit is None:
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=str(repository)).decode('ascii').strip()
        emit_archive(output, scratch, rows, redactions, projects, crosscheck, catalog, commit, make_zip,
                     sealed_paths)
    return rows, projects, crosscheck


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--zip', action='store_true', dest='make_zip')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--include-juliet', action='store_true')
    args = parser.parse_args()
    try:
        build_archive(Path(args.output), dry_run=args.dry_run, make_zip=args.make_zip,
                      include_juliet=args.include_juliet)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        sys.stdout.flush()
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
