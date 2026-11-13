#!/usr/bin/env python3
"""Explicitly adapted v21 acquisition, retaining its guard and original source files."""
import argparse
import hashlib
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path
import sys

VARIANT = 'external_dwarf4_location_base_adapter_v22_1'
REVISION = 'dwarf4_cu_or_selected_base_v22_1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_envelope(request):
    if (set(request) != {'schema', 'native_request', 'implementation'}
            or request['schema'] != 'symbai.location_repair_request.v1'
            or set(request['implementation']) != {'base_worker', 'adapter', 'wrapper'}):
        raise ValueError('Invalid repair envelope')
    for entry in request['implementation'].values():
        if set(entry) != {'path', 'sha256'} or sha(entry['path']) != entry['sha256']:
            raise ValueError('Repair implementation identity differs')
    if sha(__file__) != request['implementation']['wrapper']['sha256']:
        raise ValueError('Executing wrapper identity differs')
    if request['native_request']['worker_sha256'] != request['implementation']['base_worker']['sha256']:
        raise ValueError('Archived native helper identity differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding='utf-8'))
    trace, errors, api = [], [], {}
    runtime_pyelftools = None
    payload = {'status': 'failed', 'functions': [], 'records': []}
    base = None
    try:
        validate_envelope(request)
        native = request['native_request']
        scratch = Path(native['scratch_dir']).resolve()
        if not sys.platform.startswith('linux') or not str(scratch).startswith('/mnt/d/'):
            raise ValueError('Repair acquisition requires existing WSL on /mnt/d')
        scratch.mkdir(parents=True, exist_ok=True)
        for key in ('TEMP', 'TMP', 'TMPDIR', 'XDG_CACHE_HOME', 'TORCH_HOME', 'HF_HOME', 'MPLCONFIGDIR', 'NUMBA_CACHE_DIR'):
            os.environ[key] = str(scratch)
        os.environ['CUDA_VISIBLE_DEVICES'] = ''
        sys.dont_write_bytecode = True
        base = load('archived_acquisition_v21', request['implementation']['base_worker']['path'])
        base.validate_request(native)
        adapter = load('external_location_adapter_v22', request['implementation']['adapter']['path'])
        if 'src' in sys.modules:
            raise ValueError('Original TYGR namespace already occupied')
        sys.path.insert(0, str(Path(native['tygr_root']).resolve()))
        from src.analysis.dwarf import location, lookup
        for module, relative in ((location, 'src/analysis/dwarf/location.py'), (lookup, 'src/analysis/dwarf/lookup.py')):
            if Path(module.__file__).resolve() != (Path(native['tygr_root']) / relative).resolve():
                raise ValueError('Loaded original location module has unexpected origin')

        def record(row):
            trace.append(row)
            base.write(args.output.with_name('adapter-trace.json'), {'revision': adapter.REVISION, 'records': trace})

        def record_error(row):
            errors.append(row)
            base.write(args.output.with_name('adapter-errors.json'), {'revision': adapter.REVISION, 'errors': errors})

        api = adapter.install(location, lookup, record, record_error)
        runtime_pyelftools = metadata.version('pyelftools')
        base.write(args.output.with_name('adapter-api.json'), {'revision': adapter.REVISION,
            'pyelftools': runtime_pyelftools, 'entry_api': api})
        projected = args.output.with_name('native-request.json')
        raw_output = args.output.with_name('native-candidate.json')
        base.write(projected, native)
        saved = sys.argv
        try:
            sys.argv = [request['implementation']['base_worker']['path'], '--request', str(projected), '--output', str(raw_output)]
            base.main()
        finally:
            sys.argv = saved
        payload = json.loads(raw_output.read_text(encoding='utf-8'))
        base.validate_request(native)
        validate_envelope(request)
        if errors:
            raise ValueError('Original lookup swallowed {} recorded location errors'.format(len(errors)))
    except Exception as error:
        payload['status'] = 'failed'
        payload['repair_error'] = {'type': type(error).__name__, 'message': str(error)}
    payload['acquisition_variant'] = VARIANT
    payload['location_adapter'] = {'revision': REVISION, 'entry_api': api, 'pyelftools': runtime_pyelftools,
        'errors': errors,
        'implementation': request.get('implementation'), 'records': trace,
        'original_source_files_modified': False, 'exact_event_or_role_mapping_validated': False}
    if base is not None:
        base.write(args.output, payload)
    else:
        args.output.write_text(json.dumps(payload, indent=2, allow_nan=False), encoding='utf-8')
    print('Adapted acquisition: {}; {} functions; {} location records'.format(
        payload['status'], len(payload.get('functions', [])), len(trace)), flush=True)


if __name__ == '__main__':
    main()
