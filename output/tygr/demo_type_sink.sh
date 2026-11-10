#!/bin/bash
# Demo: GNN type-driven sink detection -- a custom hand-rolled buffer-copy function
cd "$(dirname "$0")/../.."
PY=/root/miniconda3/envs/angr-env/bin/python
SRC=output/tygr/demo_custom_sink.c

echo "================ A) type-sinks OFF (pure name/structure heuristics) ================"
unset OPM_TYPE_SINKS
$PY scripts/run_pipeline.py -v $SRC -o output/demo_sink_off 2>&1 \
  | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel" \
  | grep -iE "Found sink:|store_record|Type-driven|Sinks found:|Total traces|Defective traces" | head -12

echo ""
echo "================ B) GNN type-sinks ON (OPM_TYPE_SINKS=1) ================"
export OPM_TYPE_SINKS=1
$PY scripts/run_pipeline.py -v $SRC -o output/demo_sink_on 2>&1 \
  | grep -ivE "unicorn|cle.loader|angr0|datagen0|GlowVar|NodeLabel" \
  | grep -iE "Found sink:|store_record|Type-driven|Type-based sink|Sinks found:|Total traces|Defective traces" | head -12
echo "================ done ================"
