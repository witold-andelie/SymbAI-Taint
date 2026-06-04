"""
Evaluation Module

Implements:
- TaintTrace + GroundTruth → Evaluation → EvaluationMetrics
- TaintTrace + EvaluationMetrics → ReportGeneration → Report

From infra.txt:
    "Evaluation and Comparison"
    "Report Generation"
"""

from .metrics import compute_metrics, EvaluationMetrics
from .reporter import generate_report, AnalysisReport
