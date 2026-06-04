import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from src.binary_analysis.cfg_recovery import recover_cfg
from src.type_recovery.inference import recover_types

dbg = os.path.join(ROOT, 'output/gnn_demo/memory_vuln')            # -g binary
strp = os.path.join(ROOT, 'output/gnn_demo/memory_vuln.stripped')  # stripped (for CFG)

cfg = recover_cfg(strp)
cfg_names = set(cfg.functions.keys())
r = recover_types(dbg, cfg=cfg, dfg=None, model_path=None)

resolved = [k for k in r.keys() if not k.startswith('func_0x')]
unresolved = [k for k in r.keys() if k.startswith('func_0x')]
print(f"GNN returned {len(r)} functions; {len(resolved)} resolved to real names; {len(unresolved)} unresolved (func_0x)")
print("Examples of functions matched in the CFG:")
for k in resolved:
    if k in cfg_names:
        types = [p.predicted_type for p in r[k].predictions]
        print(f"   {k:24s} -> {types[:6]}")
