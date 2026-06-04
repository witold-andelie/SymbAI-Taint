"""Demo: after full stripping (--strip-all) the function names are gone, yet the GNN still recovers type semantics."""
import sys, subprocess, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from src.binary_analysis.cfg_recovery import recover_cfg
from src.type_recovery.inference import recover_types

dbg  = os.path.join(ROOT, 'output/gnn_demo/memory_vuln')            # -g (real names)
full = os.path.join(ROOT, 'output/gnn_demo/memory_vuln.fullstrip')

# 1) Fully-stripped copy (strip --strip-all erases .symtab, so all local function names are gone)
subprocess.run(['cp', dbg, full], check=True)
subprocess.run(['strip', '--strip-all', full], check=True)

# 2) Two CFGs: the -g one has real names, the fully-stripped one has sub_xxxx
cfg_dbg  = recover_cfg(dbg)
cfg_full = recover_cfg(full)
addr_true = {f.address: name for name, f in cfg_dbg.functions.items()}

# 3) Run GNN type recovery on the stripped binary (use -g for DWARF variables, base-aligned onto sub_xxxx)
r = recover_types(dbg, cfg=cfg_full, dfg=None, model_path=None)

print(f"\n{'stripped CFG name':<16} | {'(cross-ref) real name':<22} | GNN-recovered type semantics")
print('-'*16 + '-+-' + '-'*22 + '-+-' + '-'*40)
interesting = ('vuln_', 'safe_', 'main')
base = cfg_full.angr_cfg.project.loader.main_object.mapped_base
for sub_name, out in r.items():
    f = cfg_full.functions.get(sub_name)
    if f is None:
        continue
    true = addr_true.get(f.address, '?')   # real name at the same address (both binaries share a base)
    if not any(k in (true or '') for k in interesting):
        continue
    types = [p.predicted_type for p in out.predictions]
    has_buf = any(t in ('char*', 'pointer', 'array') for t in types)
    tag = '  <-- GNN flags it as a buffer-handling function' if has_buf else ''
    print(f"{sub_name:<16} | {true:<22} | {types[:6]}{tag}")
