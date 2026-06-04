#!/usr/bin/env python3
"""Select single-file baseline-variant Juliet cases suitable for this pipeline, from a cloned Juliet repo."""
import os, re, shutil

REPO = os.environ.get('JULIET_REPO', os.path.expanduser('~/juliet_repo')) + '/testcases'
OUT  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cases')
CWES = {
    'CWE121_Stack_Based_Buffer_Overflow': 10,
    'CWE122_Heap_Based_Buffer_Overflow':  10,
    'CWE134_Uncontrolled_Format_String':  10,
    'CWE78_OS_Command_Injection':         10,
}
# Prefer these "sources" (our taint engine recognizes stdin/getenv); skip network/win32/complex file sources
PREFER = ('console', 'environment')
SKIP   = ('socket', 'listen', 'w32', 'wchar', 'fscanf', 'file')

def is_single_baseline(name):
    # single-file baseline variant: ends in _01.c (exclude _01a.c/_01b.c multi-file splits)
    return bool(re.search(r'_01\.c$', name)) and not re.search(r'_\d+[a-z]\.c$', name)

os.makedirs(OUT, exist_ok=True)
picked = []
for cwe, n in CWES.items():
    cdir = os.path.join(REPO, cwe)
    cands = []
    for root, _, files in os.walk(cdir):
        for f in files:
            if not f.endswith('.c') or not is_single_baseline(f):
                continue
            low = f.lower()
            if any(s in low for s in SKIP):
                continue
            score = 0 if any(p in low for p in PREFER) else 1
            cands.append((score, f, os.path.join(root, f)))
    cands.sort()                       # preferred sources first
    chosen = cands[:n]
    for _, f, path in chosen:
        shutil.copy(path, os.path.join(OUT, f))
        picked.append((cwe, f))
    print(f"{cwe}: {len(cands)} candidates, {len(chosen)} selected")

print(f"\nSelected {len(picked)} cases -> {OUT}")
