#!/bin/bash
# Validate GNN integration robustness across all test programs
cd "$(dirname "$0")/../.."
PY=/root/miniconda3/envs/angr-env/bin/python
echo "program             | GNN funcs | typed vars | P/R/F1"
echo "--------------------|-----------|------------|--------"
for f in tests/test_programs/*.c; do
  name=$(basename "$f" .c)
  log=$(timeout 500 $PY scripts/run_pipeline.py "$f" -o output/gnn_all/"$name" 2>&1 \
        | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel")
  gnn=$(echo "$log"   | grep -oE "GNN type recovery: [0-9]+ functions" | grep -oE "[0-9]+" | head -1)
  typed=$(echo "$log" | grep -oE "[0-9]+ typed variables" | grep -oE "[0-9]+" | head -1)
  prf=$(echo "$log"   | grep -oE "P=[0-9.]+, R=[0-9.]+, F1=[0-9.]+" | head -1)
  fellback=$(echo "$log" | grep -c "GNN type recovery unavailable")
  flag=""
  [ "$fellback" -gt 0 ] && flag=" [FELL BACK!]"
  printf "%-19s | %-9s | %-10s | %s%s\n" "$name" "${gnn:-?}" "${typed:-?}" "${prf:-?}" "$flag"
done
echo "=== done ==="
