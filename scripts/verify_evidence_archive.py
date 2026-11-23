#!/usr/bin/env python3
"""Verify both evidence tiers against their SHA256SUMS and original-file manifest."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys


def child(directory, relative):
    if (not relative or '\\' in relative or ':' in relative or relative.startswith('/')
            or '..' in relative.split('/')):
        raise ValueError('Unsafe archive path: ' + relative)
    target = directory / relative
    try:
        target.resolve().relative_to(directory.resolve())
    except ValueError:
        raise ValueError('Archive link escapes directory: ' + relative)
    return target


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def valid_hash(value):
    return re.fullmatch(r'[0-9a-f]{64}', value) is not None


def verify_archive(directory):
    directory = Path(directory)
    expected = {'tier1': {}, 'tier2': {}}
    sizes = {}

    def add(path, sha256, size=None):
        if not valid_hash(sha256):
            raise ValueError('Invalid manifest digest: ' + path)
        child(directory, path)
        tier, relative = path.split('/', 1)
        if tier not in expected:
            raise ValueError('Invalid manifest tier: ' + path)
        if relative in expected[tier] and expected[tier][relative] != sha256:
            raise ValueError('Conflicting manifest entries: ' + path)
        expected[tier][relative] = sha256
        if size is not None:
            sizes[path] = size

    originals = set()
    sealed_count = 0
    redacted_count = 0
    with (directory / 'MANIFEST.tsv').open('r', encoding='ascii', newline='') as stream:
        reader = csv.DictReader(stream, delimiter='\t')
        required = {'relative_path', 'bytes', 'sha256', 'class', 'archived_path',
                    'redacted_sha256', 'redacted_path', 'license_paths', 'reason'}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError('Missing manifest columns')
        for row in reader:
            relative = row['relative_path']
            child(directory, relative)
            if relative in originals:
                raise ValueError('Duplicate original: ' + relative)
            originals.add(relative)
            size = int(row['bytes'])
            if size < 0 or row['class'] not in expected and row['class'] != 'hash_only':
                raise ValueError('Invalid manifest class/size: ' + relative)
            if not row['sha256']:
                if row['class'] != 'hash_only' or not row['reason'].startswith('sealed:'):
                    raise ValueError('Unexplained missing original digest: ' + relative)
                if row['archived_path'] or row['redacted_path'] or row['license_paths']:
                    raise ValueError('Sealed file archived: ' + relative)
                sealed_count += 1
            elif not valid_hash(row['sha256']):
                raise ValueError('Invalid original digest: ' + relative)
            if row['archived_path']:
                if row['archived_path'] != row['class'] + '/' + relative:
                    raise ValueError('Original path/class mismatch: ' + relative)
                add(row['archived_path'], row['sha256'], size)
            if row['redacted_path']:
                if row['redacted_path'] != 'tier1/' + relative or row['class'] != 'tier2':
                    raise ValueError('Redacted path/class mismatch: ' + relative)
                add(row['redacted_path'], row['redacted_sha256'])
                redacted_count += 1
            elif row['redacted_sha256']:
                raise ValueError('Redacted digest without a copy: ' + relative)
            for path in json.loads(row['license_paths'] or '[]'):
                if not path.startswith('tier2/LICENSES/'):
                    raise ValueError('Invalid license copy path: ' + path)
                add(path, row['sha256'], size)
    counts = {}
    for tier in ('tier1', 'tier2'):
        if not (directory / tier).is_dir():
            raise ValueError('Tier directory missing: ' + tier)
        sums = {}
        for line in (directory / ('SHA256SUMS-' + tier + '.txt')).read_text(encoding='ascii').splitlines():
            if len(line) < 67 or line[64:66] != '  ' or not valid_hash(line[:64]):
                raise ValueError('Malformed SHA256SUMS entry: ' + tier)
            sha256, relative = line[:64], line[66:]
            child(directory / tier, relative)
            if relative in sums:
                raise ValueError('Duplicate SHA256SUMS entry: ' + relative)
            sums[relative] = sha256
        if sums != expected[tier]:
            raise ValueError('SHA256SUMS and MANIFEST disagree: ' + tier)
        actual_files = set()
        for path in (directory / tier).rglob('*'):
            if path.is_symlink():
                raise ValueError('Unexpected symlink: ' + str(path))
            if path.is_file():
                actual_files.add(path.relative_to(directory / tier).as_posix())
        if actual_files != set(sums):
            raise ValueError('Tier inventory mismatch: {} missing={} extra={}'.format(
                tier, sorted(set(sums) - actual_files), sorted(actual_files - set(sums))))
        total = 0
        for relative, sha256 in sorted(sums.items()):
            path = child(directory / tier, relative)
            if digest(path) != sha256:
                raise ValueError('SHA-256 mismatch: ' + tier + '/' + relative)
            size = path.stat().st_size
            if sizes.get(tier + '/' + relative, size) != size:
                raise ValueError('Size mismatch: ' + tier + '/' + relative)
            total += size
        counts[tier] = {'files': len(sums), 'bytes': total}
        print('{}: PASS {} files, {} bytes'.format(tier, len(sums), total))
    print('MANIFEST: PASS {} originals, {} redacted copies, {} sealed files unopened'.format(
        len(originals), redacted_count, sealed_count))
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    try:
        verify_archive(Path(args.directory))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
