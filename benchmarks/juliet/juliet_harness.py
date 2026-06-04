#!/usr/bin/env python3
"""
Juliet pilot evaluation harness.
For each Juliet case, compile two variants:
  - positive (-DOMITGOOD): only bad()  -> should be detected
  - negative (-DOMITBAD):  only good() -> should not be detected
Use the core analysis (CFG + call graph + taint) to decide "detected" (total_paths > 0).
Phase 1: standard name/structure heuristics (no GNN type-sink).
Phase 2: for positives missed in phase 1, enable GNN type-driven detection (OPM_TYPE_SINKS) and measure
         the GNN's incremental recall.
"""
import os, sys, subprocess, glob, json, signal

JDIR = os.path.dirname(os.path.abspath(__file__))          # benchmarks/juliet
ROOT = os.path.dirname(os.path.dirname(JDIR))              # project root
sys.path.insert(0, ROOT)
CASES, SUPPORT, BUILD = (os.path.join(JDIR, d) for d in ('cases', 'support', 'build'))
os.makedirs(BUILD, exist_ok=True)

from src.binary_analysis.cfg_recovery import recover_cfg
from src.binary_analysis.call_analysis import analyze_calls
from src.taint_analysis.taint_engine_v2 import run_taint_analysis


class Timeout(Exception): pass
def _alarm(signum, frame): raise Timeout()
signal.signal(signal.SIGALRM, _alarm)


def compile_variant(case_path, define, out):
    cmd = ['gcc', '-g', '-O0', '-w', '-DINCLUDEMAIN', define,
           '-I', SUPPORT, case_path, os.path.join(SUPPORT, 'io.c'), '-o', out]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def detect(binary, use_gnn=False, t=120):
    """Return the number of detected taint paths (>0 counts as detected). Timeout guards against angr hangs."""
    signal.alarm(t)
    try:
        cfg = recover_cfg(binary)
        call_graph = analyze_calls(binary, cfg)
        tro = None
        if use_gnn:
            from src.type_recovery.inference import recover_types
            try:
                tro = recover_types(binary, cfg, None, None)
            except Exception:
                tro = None
        res = run_taint_analysis(binary, cfg, call_graph, None, None, tro)
        return int(res['summary']['total_paths'])
    finally:
        signal.alarm(0)


def main():
    cases = sorted(glob.glob(os.path.join(CASES, '*.c')))
    results = []
    print(f"=== Phase 1: standard detection, {len(cases)} cases ===", flush=True)
    for i, c in enumerate(cases, 1):
        name = os.path.basename(c)[:-2]
        rec = {'case': name, 'cwe': name.split('__')[0]}
        badbin = os.path.join(BUILD, name + '_bad')
        goodbin = os.path.join(BUILD, name + '_good')
        try:
            ok_b = compile_variant(c, '-DOMITGOOD', badbin)
            ok_g = compile_variant(c, '-DOMITBAD', goodbin)
            rec['compiled'] = ok_b and ok_g
            if ok_b:
                rec['bad_paths'] = detect(badbin)
            if ok_g:
                rec['good_paths'] = detect(goodbin)
        except Timeout:
            rec['error'] = 'timeout'
        except Exception as e:
            rec['error'] = f"{type(e).__name__}: {e}"
        results.append(rec)
        print(f"[{i}/{len(cases)}] {name}: bad={rec.get('bad_paths','-')} "
              f"good={rec.get('good_paths','-')} {rec.get('error','')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_standard.json'), 'w'), indent=1)

    # Phase 2: for positives missed in phase 1, enable GNN type-driven detection
    os.environ['OPM_TYPE_SINKS'] = '1'
    missed = [r for r in results if r.get('compiled') and r.get('bad_paths', 0) == 0]
    print(f"\n=== Phase 2: GNN type-driven re-check of {len(missed)} positives missed in phase 1 ===", flush=True)
    for i, r in enumerate(missed, 1):
        badbin = os.path.join(BUILD, r['case'] + '_bad')
        try:
            r['bad_paths_gnn'] = detect(badbin, use_gnn=True, t=300)
        except Timeout:
            r['bad_paths_gnn'] = 'timeout'
        except Exception as e:
            r['bad_paths_gnn'] = f"err:{e}"
        print(f"[GNN {i}/{len(missed)}] {r['case']}: bad_gnn={r.get('bad_paths_gnn')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_standard.json'), 'w'), indent=1)

    summarize(results)


def summarize(results):
    comp = [r for r in results if r.get('compiled')]
    TP = sum(1 for r in comp if r.get('bad_paths', 0) > 0)
    FN = sum(1 for r in comp if r.get('bad_paths', 0) == 0)
    FP = sum(1 for r in comp if r.get('good_paths', 0) > 0)
    TN = sum(1 for r in comp if r.get('good_paths', 0) == 0)
    def prf(tp, fp, fn):
        P = tp / (tp + fp) if tp + fp else 0.0
        R = tp / (tp + fn) if tp + fn else 0.0
        F = 2 * P * R / (P + R) if P + R else 0.0
        return P, R, F
    P, R, F = prf(TP, FP, FN)
    # After phase 2: count the positives recovered by the GNN
    TP2 = TP + sum(1 for r in comp if isinstance(r.get('bad_paths_gnn'), int) and r['bad_paths_gnn'] > 0)
    FN2 = len(comp) - TP2
    P2, R2, F2 = prf(TP2, FP, FN2)
    out = [
        "=" * 60,
        f"JULIET PILOT RESULTS  (compiled {len(comp)}/{len(results)} cases)",
        "=" * 60,
        "[Phase 1 standard: name/structure heuristics]",
        f"  TP={TP} FN={FN} FP={FP} TN={TN}",
        f"  Precision={P:.3f}  Recall={R:.3f}  F1={F:.3f}",
        "[Phase 2 +GNN type-driven (on missed positives)]",
        f"  positives recovered by GNN: {TP2 - TP}",
        f"  Recall(total)={R2:.3f}  F1={F2:.3f}  (Precision={P2:.3f})",
        "=" * 60,
    ]
    text = "\n".join(out)
    print("\n" + text, flush=True)
    open(os.path.join(JDIR, 'SUMMARY.txt'), 'w').write(text)


if __name__ == '__main__':
    main()
