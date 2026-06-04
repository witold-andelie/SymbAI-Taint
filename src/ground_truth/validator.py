"""
Ground Truth Validator

Validates analysis results against ground truth data.
Computes precision, recall, and F1-score metrics.
"""

import logging
from typing import Dict, Any, List, Set, Tuple
from dataclasses import dataclass

logger = logging.getLogger('OPM.ground_truth')


@dataclass
class ValidationResult:
    """Result of validating analysis against ground truth."""
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    details: Dict[str, Any]


def validate_ground_truth(
    analysis_results: Dict[str, Any],
    ground_truth: Dict[str, Any]
) -> Dict[str, ValidationResult]:
    """
    Validate analysis results against ground truth.

    Args:
        analysis_results: Results from the analysis pipeline
        ground_truth: Ground truth data extracted from source

    Returns:
        Dictionary of validation results for each metric
    """
    results = {}

    # Validate sources
    if 'sources' in analysis_results and 'sources' in ground_truth:
        results['sources'] = validate_sources(
            analysis_results['sources'],
            ground_truth['sources']
        )

    # Validate sinks
    if 'sinks' in analysis_results and 'sinks' in ground_truth:
        results['sinks'] = validate_sinks(
            analysis_results['sinks'],
            ground_truth['sinks']
        )

    # Validate taint paths
    if 'taint_paths' in analysis_results and 'taint_paths' in ground_truth:
        results['taint_paths'] = validate_taint_paths(
            analysis_results['taint_paths'],
            ground_truth['taint_paths']
        )

    # Validate types
    if 'types' in analysis_results and 'types' in ground_truth:
        results['types'] = validate_types(
            analysis_results['types'],
            ground_truth['types']
        )

    # Compute overall metrics
    results['overall'] = compute_overall_metrics(results)

    return results


def validate_sources(
    detected_sources: List[str],
    expected_sources: List[str]
) -> ValidationResult:
    """Validate detected sources against expected sources."""
    detected_set = set(detected_sources)
    expected_set = set(expected_sources)

    tp = len(detected_set & expected_set)
    fp = len(detected_set - expected_set)
    fn = len(expected_set - detected_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ValidationResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details={
            'detected': list(detected_set),
            'expected': list(expected_set),
            'true_positives': list(detected_set & expected_set),
            'false_positives': list(detected_set - expected_set),
            'false_negatives': list(expected_set - detected_set),
        }
    )


def validate_sinks(
    detected_sinks: List[str],
    expected_sinks: List[str]
) -> ValidationResult:
    """Validate detected sinks against expected sinks."""
    detected_set = set(detected_sinks)
    expected_set = set(expected_sinks)

    tp = len(detected_set & expected_set)
    fp = len(detected_set - expected_set)
    fn = len(expected_set - detected_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ValidationResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details={
            'detected': list(detected_set),
            'expected': list(expected_set),
            'true_positives': list(detected_set & expected_set),
            'false_positives': list(detected_set - expected_set),
            'false_negatives': list(expected_set - detected_set),
        }
    )


def validate_taint_paths(
    detected_paths: List[Dict[str, Any]],
    expected_paths: List[Dict[str, Any]]
) -> ValidationResult:
    """Validate detected taint paths against expected paths."""
    # Convert paths to comparable format
    detected_set = set()
    for path in detected_paths:
        key = (path.get('source', ''), path.get('sink', ''))
        detected_set.add(key)

    expected_set = set()
    for path in expected_paths:
        key = (path.get('source', ''), path.get('sink', ''))
        expected_set.add(key)

    tp = len(detected_set & expected_set)
    fp = len(detected_set - expected_set)
    fn = len(expected_set - detected_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ValidationResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details={
            'detected': list(detected_set),
            'expected': list(expected_set),
            'true_positives': list(detected_set & expected_set),
            'false_positives': list(detected_set - expected_set),
            'false_negatives': list(expected_set - detected_set),
        }
    )


def validate_types(
    detected_types: Dict[str, str],
    expected_types: Dict[str, str]
) -> ValidationResult:
    """Validate detected types against expected types."""
    tp = 0
    fp = 0
    fn = 0

    # Check each expected type
    for var_name, expected_type in expected_types.items():
        if var_name in detected_types:
            detected_type = detected_types[var_name]
            if _types_match(detected_type, expected_type):
                tp += 1
            else:
                fp += 1
                fn += 1
        else:
            fn += 1

    # Check for extra detected types
    for var_name in detected_types:
        if var_name not in expected_types:
            fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ValidationResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details={
            'total_detected': len(detected_types),
            'total_expected': len(expected_types),
            'correct': tp,
        }
    )


def compute_accuracy(
    detected: List[str],
    expected: List[str]
) -> float:
    """
    Compute simple accuracy (Jaccard similarity).

    Args:
        detected: List of detected items
        expected: List of expected items

    Returns:
        Accuracy score between 0 and 1
    """
    detected_set = set(detected)
    expected_set = set(expected)

    if len(detected_set | expected_set) == 0:
        return 1.0

    return len(detected_set & expected_set) / len(detected_set | expected_set)


def compute_overall_metrics(
    results: Dict[str, ValidationResult]
) -> ValidationResult:
    """Compute overall metrics from individual validation results."""
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for key, result in results.items():
        if key != 'overall':
            total_tp += result.true_positives
            total_fp += result.false_positives
            total_fn += result.false_negatives

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ValidationResult(
        true_positives=total_tp,
        false_positives=total_fp,
        false_negatives=total_fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details={
            'num_metrics': len(results) - 1,  # Exclude 'overall'
        }
    )


def _types_match(detected: str, expected: str) -> bool:
    """Check if two type strings match (with normalization)."""
    # Normalize type strings
    def normalize(t: str) -> str:
        t = t.strip()
        t = t.replace(' ', '')
        # Normalize pointer types
        t = t.replace('*', ' * ')
        # Normalize integer types
        t = t.replace('int32_t', 'int')
        t = t.replace('int64_t', 'long')
        t = t.replace('uint32_t', 'unsigned int')
        t = t.replace('uint64_t', 'unsigned long')
        return t.lower()

    return normalize(detected) == normalize(expected)


def print_validation_report(results: Dict[str, ValidationResult]):
    """Print a formatted validation report."""
    print("\n" + "=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)

    for metric_name, result in results.items():
        print(f"\n{metric_name.upper()}:")
        print(f"  Precision: {result.precision:.4f}")
        print(f"  Recall:    {result.recall:.4f}")
        print(f"  F1-Score:  {result.f1_score:.4f}")
        print(f"  TP: {result.true_positives}, FP: {result.false_positives}, FN: {result.false_negatives}")

    print("\n" + "=" * 60)
