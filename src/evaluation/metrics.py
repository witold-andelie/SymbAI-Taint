"""
Evaluation Metrics Module

Implements: TaintTrace + GroundTruth → Evaluation → EvaluationMetrics
From infra.txt: "Evaluation and Comparison"

This module computes precision, recall, F1-score, and other metrics.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.evaluation')


@dataclass
class EvaluationMetrics:
    """Evaluation metrics for taint analysis."""
    # Core metrics
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    # Counts
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    # Additional metrics
    accuracy: float = 0.0
    specificity: float = 0.0

    # Analysis statistics
    total_sources: int = 0
    total_sinks: int = 0
    total_taint_paths: int = 0
    total_vulnerable_paths: int = 0

    # Time statistics
    analysis_time: float = 0.0
    paths_explored: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'accuracy': self.accuracy,
            'specificity': self.specificity,
            'total_sources': self.total_sources,
            'total_sinks': self.total_sinks,
            'total_taint_paths': self.total_taint_paths,
            'total_vulnerable_paths': self.total_vulnerable_paths,
            'analysis_time': self.analysis_time,
            'paths_explored': self.paths_explored,
        }


def compute_metrics(
    taint_trace: List[Dict[str, Any]],
    ground_truth: Dict[str, Any]
) -> Dict[str, float]:
    """
    Compute evaluation metrics.

    Args:
        taint_trace: Taint traces found by analysis
        ground_truth: Ground truth data

    Returns:
        Dictionary of evaluation metrics
    """
    logger.info("Computing evaluation metrics")

    # Extract detected paths
    detected_paths = set()
    for trace in taint_trace:
        source = trace.get('source')
        sink = trace.get('sink')
        if source and sink:
            detected_paths.add((source, sink))

    # Extract expected paths from ground truth
    expected_paths = set()
    for path in ground_truth.get('taint_paths', []):
        source = path.get('source')
        sink = path.get('sink')
        if source and sink:
            expected_paths.add((source, sink))

    # Compute TP, FP, FN
    true_positives = len(detected_paths & expected_paths)
    false_positives = len(detected_paths - expected_paths)
    false_negatives = len(expected_paths - detected_paths)

    # Compute metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Count sources and sinks
    detected_sources = {t.get('source') for t in taint_trace if t.get('source')}
    detected_sinks = {t.get('sink') for t in taint_trace if t.get('sink')}
    expected_sources = set(ground_truth.get('sources', []))
    expected_sinks = set(ground_truth.get('sinks', []))

    # Count vulnerable paths
    vulnerable_detected = sum(1 for t in taint_trace if t.get('is_vulnerable'))
    vulnerable_expected = len(ground_truth.get('vulnerable_paths', []))

    metrics = {
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'detected_paths': len(detected_paths),
        'expected_paths': len(expected_paths),
        'detected_sources': len(detected_sources),
        'detected_sinks': len(detected_sinks),
        'expected_sources': len(expected_sources),
        'expected_sinks': len(expected_sinks),
        'vulnerable_detected': vulnerable_detected,
        'vulnerable_expected': vulnerable_expected,
    }

    logger.info(f"Metrics computed: P={precision:.4f}, R={recall:.4f}, F1={f1_score:.4f}")
    return metrics


def compute_type_recovery_metrics(
    detected_types: Dict[str, str],
    expected_types: Dict[str, str]
) -> Dict[str, float]:
    """
    Compute type recovery metrics.

    Args:
        detected_types: Types detected by GNN
        expected_types: Expected types from ground truth

    Returns:
        Dictionary of type recovery metrics
    """
    correct = 0
    total = 0
    mismatches = []

    for var_name, expected_type in expected_types.items():
        total += 1
        if var_name in detected_types:
            detected_type = detected_types[var_name]
            if _types_match(detected_type, expected_type):
                correct += 1
            else:
                mismatches.append({
                    'variable': var_name,
                    'expected': expected_type,
                    'detected': detected_type,
                })

    accuracy = correct / total if total > 0 else 0.0

    return {
        'accuracy': accuracy,
        'correct': correct,
        'total': total,
        'mismatches': mismatches,
    }


def _types_match(detected: str, expected: str) -> bool:
    """Check if two type strings match."""
    # Normalize types
    def normalize(t: str) -> str:
        t = t.strip().lower()
        t = t.replace(' ', '')
        t = t.replace('*', ' * ')
        return t

    return normalize(detected) == normalize(expected)


def compute_path_coverage(
    explored_paths: int,
    total_paths: int
) -> float:
    """
    Compute path coverage.

    Args:
        explored_paths: Number of paths explored
        total_paths: Total number of paths

    Returns:
        Coverage ratio
    """
    return explored_paths / total_paths if total_paths > 0 else 0.0


def compute_false_positive_rate(
    false_positives: int,
    true_negatives: int
) -> float:
    """
    Compute false positive rate.

    Args:
        false_positives: Number of false positives
        true_negatives: Number of true negatives

    Returns:
        False positive rate
    """
    total = false_positives + true_negatives
    return false_positives / total if total > 0 else 0.0


def compute_false_negative_rate(
    false_negatives: int,
    true_positives: int
) -> float:
    """
    Compute false negative rate.

    Args:
        false_negatives: Number of false negatives
        true_positives: Number of true positives

    Returns:
        False negative rate
    """
    total = false_negatives + true_positives
    return false_negatives / total if total > 0 else 0.0


def get_metrics_summary(metrics: Dict[str, float]) -> str:
    """Get a formatted summary of metrics."""
    lines = [
        "=" * 50,
        "EVALUATION METRICS SUMMARY",
        "=" * 50,
        f"Precision:     {metrics.get('precision', 0):.4f}",
        f"Recall:        {metrics.get('recall', 0):.4f}",
        f"F1-Score:      {metrics.get('f1_score', 0):.4f}",
        "-" * 50,
        f"True Positives:  {metrics.get('true_positives', 0)}",
        f"False Positives: {metrics.get('false_positives', 0)}",
        f"False Negatives: {metrics.get('false_negatives', 0)}",
        "-" * 50,
        f"Detected Paths:  {metrics.get('detected_paths', 0)}",
        f"Expected Paths:  {metrics.get('expected_paths', 0)}",
        f"Detected Sources: {metrics.get('detected_sources', 0)}",
        f"Detected Sinks:   {metrics.get('detected_sinks', 0)}",
        "=" * 50,
    ]
    return '\n'.join(lines)


# Example usage
if __name__ == "__main__":
    print("Evaluation Metrics Module")
    print("This module is used as part of the OPM pipeline.")
