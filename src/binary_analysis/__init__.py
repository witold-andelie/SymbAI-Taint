"""
Binary Analysis Module

Implements:
- CodeLifting: Binary → VEX IR (using angr/pyvex)
- CFGRecovery: Binary → CFG (using angr CFGFast)
- DFGConstruction: VEX IR + CFG → DFG
- CallAnalysis: Function call detection and call graph
- MultiModalFusion: ORACAL-style multi-modal fusion

From infra.txt:
    Binary → CodeLifting → VEX IR
    Binary → CFGRecovery → CFG
    VEX IR + CFG → DFGConstruction → DFG
"""

from .vex_lift import lift_binary, lift_function
from .cfg_recovery import recover_cfg, recover_cfg_function
from .dfg_construction import construct_dfg, construct_function_dfg
from .call_analysis import analyze_calls, CallGraph, CallSite
from .multimodal_fusion import MultiModalFusion, FusionConfig, create_multimodal_fusion
