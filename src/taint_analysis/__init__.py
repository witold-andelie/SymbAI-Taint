"""
Taint Analysis Module

Implements:
- ExecutionPaths + TaintSpec + TypedIR → TaintPropagation → TaintState
- TaintState + ExecutionPaths + TaintSpec → SourceSinkChecking → TaintTrace

From infra.txt:
    "Automated Taint Propagation"
    "Source-Sink Checking"
"""

from .taint_engine import propagate_taint, TaintEngine
from .taint_engine_v2 import run_taint_analysis, TaintEngineV2
from .learned_propagation import LearnedTaintPropagation, create_learned_propagation
from .gnn_sink_detector import GNNSinkDetector, create_gnn_sink_detector
from .counterfactual import CounterfactualValidator, CounterfactualGenerator, create_counterfactual_validator
from .source_sink import check_source_sink, SourceSinkChecker
from .rules import TaintSpec, TaintRule, load_taint_spec
