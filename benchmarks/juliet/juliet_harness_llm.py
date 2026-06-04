#!/usr/bin/env python3
"""
Juliet pilot -- GNN + LLM fusion.
For each binary: GNN types + type-driven sinks (OPM_TYPE_SINKS=1) + taint -> taint paths;
then feed the **GNN-recovered types** as evidence and adjudicate each path with the LLM (CoT), reusing
OPM's analyze_taint_path_cot. "Detected" = at least one path survives LLM adjudication
(is_real_taint and confidence >= threshold). Compares: standard / +GNN / +GNN+LLM.
"""
import os, sys, glob, json, signal

JDIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(JDIR))
sys.path.insert(0, ROOT)
os.environ['OPM_TYPE_SINKS'] = '1'

CASES, BUILD = os.path.join(JDIR, 'cases'), os.path.join(JDIR, 'build')
THRESH = 0.3  # consistent with pipeline Stage 11

from src.binary_analysis.cfg_recovery import recover_cfg
from src.binary_analysis.call_analysis import analyze_calls
from src.taint_analysis.taint_engine_v2 import run_taint_analysis
from src.type_recovery.inference import recover_types
from src.orchestrator.llm_client import LLMClient, LLMConfig

LLM = LLMClient(LLMConfig(provider='openai',
                          api_base=os.environ['MIMO_API_BASE'],
                          api_key=os.environ['MIMO_API_KEY'],
                          model=os.environ.get('MIMO_MODEL', 'gpt-5.4-mini')))


class Timeout(Exception): pass
signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(Timeout()))


def type_evidence(tro, funcs):
    """Reproduce the GNN type block of OPM's _build_symbolic_evidence: per-variable predicted_type + confidence."""
    parts = ["### Type Information (from GNN type recovery)"]
    for fn in funcs:
        out = (tro or {}).get(fn)
        if not out:
            continue
        for p in getattr(out, 'predictions', [])[:12]:
            parts.append(f"- {fn}:{p.variable_name}: {p.predicted_type} (conf={p.confidence:.2f})")
    return "\n".join(parts) if len(parts) > 1 else ""


def analyze(binary, t=320):
    """Return (taint_paths, tro)."""
    signal.alarm(t)
    try:
        cfg = recover_cfg(binary)
        cg = analyze_calls(binary, cfg)
        try:
            tro = recover_types(binary, cfg, None, None)
        except Exception:
            tro = {}
        res = run_taint_analysis(binary, cfg, cg, None, None, tro)
        return res.get('taint_state', res).get('taint_paths', []) if isinstance(res, dict) else [], tro
    finally:
        signal.alarm(0)


def adjudicate(paths, tro):
    """Per-path LLM adjudication (GNN types as evidence). Returns (detected?, surviving, total)."""
    survived = 0
    for p in paths:
        funcs = [p.get('source_caller'), p.get('sink_caller'),
                 p.get('source'), p.get('sink')]
        ev = type_evidence(tro, [f for f in funcs if f])
        try:
            signal.alarm(90)
            r = LLM.analyze_taint_path_cot(p, symbolic_evidence=ev)
            signal.alarm(0)
        except Exception:
            signal.alarm(0)
            r = {'is_real_taint': True, 'confidence': 0.5}   # conservatively keep on failure
        if r.get('is_real_taint', True) and float(r.get('confidence', 0.5)) >= THRESH:
            survived += 1
            break   # the detection decision only needs one surviving path -> early exit to save calls
    return survived > 0, survived, len(paths)


def main():
    cases = sorted(glob.glob(os.path.join(CASES, '*.c')))
    results = []
    for i, c in enumerate(cases, 1):
        name = os.path.basename(c)[:-2]
        rec = {'case': name}
        for variant, suffix in (('bad', '_bad'), ('good', '_good')):
            binp = os.path.join(BUILD, name + suffix)
            if not os.path.exists(binp):
                continue
            try:
                paths, tro = analyze(binp)
                if paths:
                    det, surv, tot = adjudicate(paths, tro)
                    rec[variant] = {'paths': tot, 'survived': surv, 'detected_llm': det}
                else:
                    rec[variant] = {'paths': 0, 'survived': 0, 'detected_llm': False}
            except Timeout:
                rec[variant] = {'error': 'timeout'}
            except Exception as e:
                rec[variant] = {'error': f"{type(e).__name__}: {e}"}
        results.append(rec)
        b, g = rec.get('bad', {}), rec.get('good', {})
        print(f"[{i}/{len(cases)}] {name}: bad={b.get('survived','-')}/{b.get('paths','-')}"
              f"->{b.get('detected_llm','-')}  good={g.get('survived','-')}/{g.get('paths','-')}"
              f"->{g.get('detected_llm','-')}", flush=True)
        json.dump(results, open(os.path.join(JDIR, 'results_llm.json'), 'w'), indent=1)
    summarize(results)


def summarize(results):
    comp = [r for r in results if 'bad' in r and 'good' in r and 'detected_llm' in r.get('bad', {})]
    TP = sum(1 for r in comp if r['bad'].get('detected_llm'))
    FN = sum(1 for r in comp if not r['bad'].get('detected_llm'))
    FP = sum(1 for r in comp if r['good'].get('detected_llm'))
    TN = sum(1 for r in comp if not r['good'].get('detected_llm'))
    P = TP / (TP + FP) if TP + FP else 0.0
    R = TP / (TP + FN) if TP + FN else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    txt = ("=" * 56 + f"\nJULIET +GNN+LLM fusion  (valid {len(comp)} cases)\n" + "=" * 56 +
           f"\n  TP={TP} FN={FN} FP={FP} TN={TN}"
           f"\n  Precision={P:.3f}  Recall={R:.3f}  F1={F:.3f}\n" + "=" * 56)
    print("\n" + txt, flush=True)
    open(os.path.join(JDIR, 'SUMMARY_LLM.txt'), 'w').write(txt)


if __name__ == '__main__':
    main()
