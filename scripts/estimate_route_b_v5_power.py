#!/usr/bin/env python3
"""Power basis for the Route B v5 margin, from the v4 run records (ill-defined sds query removed)."""
import json, random, statistics as st
R = json.load(open(r"D:/AI_Models/symbolic/.scratch/selective_analysis/route-b-v4-run-20261121T074927114386Z/records.json"))
B = 3.0
# per (case, rep): F, L, oracle(F,C) cost; exclude the ill-defined sds case
cases = {}
for r in R:
    if r["case"].startswith("sds-sdsAllocSize"): continue
    k = (r["case"], r["repetition"]); cases.setdefault(k, {"group": r["group"]})[r["arm"]] = r
units = {}
for (c, rep), d in cases.items():
    f = d["F"]["charged_for_m2"]; l = d["L"]["charged_for_m2"]
    ok = [d[a]["charged_for_m2"] for a in ("F", "C") if d[a]["correct"]]
    o = min(ok) if ok else B
    units.setdefault(d["group"], []).append((f - o, f - l, f))
groups = sorted(units)
n = sum(len(v) for v in units.values())
print("trials", n, "groups", len(groups))
print("mean F per trial", sum(u[2] for v in units.values() for u in v) / n)
print("mean F-O per trial", sum(u[0] for v in units.values() for u in v) / n)
print("mean F-L per trial", sum(u[1] for v in units.values() for u in v) / n)
for g in groups:
    v = units[g]; print(" ", g, len(v), round(sum(u[0] for u in v), 3), round(sum(u[1] for u in v), 3))
# power: resample G groups from v4 groups (null-ish world = v4), CI of per-trial mean via cluster bootstrap
rng = random.Random(1)
def ci_upper(sample, idx, boots=2000):
    vals = []
    for _ in range(boots):
        s = [rng.choice(sample) for _ in sample]
        num = sum(sum(u[idx] for u in units[g]) for g in s); den = sum(len(units[g]) for g in s)
        vals.append(num / den)
    vals.sort(); return vals[int(0.05 * boots)], vals[int(0.95 * boots) - 1]
for G in (17, 30, 40, 60):
    los, his = [], []
    for _ in range(200):
        sample = [rng.choice(groups) for _ in range(G)]
        lo, hi = ci_upper(sample, 0, 500); his.append(hi)
    his.sort()
    print("G", G, "headroom F-O 90%CI upper: median", round(his[100], 4), "80th pct", round(his[160], 4))
