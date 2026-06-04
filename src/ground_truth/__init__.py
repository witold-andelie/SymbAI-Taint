"""
Ground Truth Extraction Module

Implements: SourceCode → GroundTruthExtraction → GroundTruth
From infra.txt: "Ground Truth Extraction"

This module handles:
1. Extracting expected source/sink functions from source code
2. Extracting variable types from source code
3. Identifying expected vulnerable paths
4. Validating ground truth against binary analysis results
"""

from .extractor import extract_ground_truth, extract_from_source
from .validator import validate_ground_truth, compute_accuracy
