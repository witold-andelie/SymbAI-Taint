#!/usr/bin/env python3
"""
OPM Evaluation Script

Runs the OPM pipeline on test programs and evaluates results.
"""

import os
import sys
import json
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.ground_truth import extract_ground_truth
from src.evaluation import compute_metrics


def compile_test_programs(test_dir: str, output_dir: str) -> Dict[str, str]:
    """Compile test programs."""
    os.makedirs(output_dir, exist_ok=True)

    results = {}
    test_files = list(Path(test_dir).glob("*.c"))

    for source_file in test_files:
        binary_name = source_file.stem
        binary_path = os.path.join(output_dir, binary_name)

        try:
            cmd = ['gcc', '-g', '-O0', '-o', binary_path, str(source_file)]
            subprocess.run(cmd, check=True, capture_output=True)
            results[str(source_file)] = binary_path
            print(f"Compiled: {source_file.name} -> {binary_name}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile {source_file}: {e}")

    return results


def run_analysis(source_file: str, output_dir: str) -> Dict[str, Any]:
    """Run OPM analysis on a source file."""
    from src.pipeline import OPMPipeline, OPMConfig

    config = OPMConfig(
        output_dir=output_dir,
        verbose=False,
    )

    pipeline = OPMPipeline(config)

    try:
        result = pipeline.run(source_file)
        return result
    except Exception as e:
        return {'error': str(e)}


def evaluate_program(source_file: str, output_dir: str) -> Dict[str, Any]:
    """Evaluate a single program."""
    print(f"\nEvaluating: {source_file}")

    # Extract ground truth
    ground_truth = extract_ground_truth(source_file)

    # Run analysis
    analysis_result = run_analysis(source_file, output_dir)

    if 'error' in analysis_result:
        return {
            'source': source_file,
            'error': analysis_result['error'],
        }

    # Compute metrics
    taint_traces = analysis_result.get('taint_traces', [])
    metrics = compute_metrics(taint_traces, ground_truth)

    return {
        'source': source_file,
        'ground_truth': {
            'functions': len(ground_truth.get('functions', [])),
            'variables': len(ground_truth.get('variables', [])),
            'sources': len(ground_truth.get('sources', [])),
            'sinks': len(ground_truth.get('sinks', [])),
            'taint_paths': len(ground_truth.get('taint_paths', [])),
        },
        'analysis': {
            'traces': len(taint_traces),
            'vulnerable': sum(1 for t in taint_traces if t.get('is_vulnerable')),
        },
        'metrics': metrics,
    }


def run_evaluation(test_dir: str, output_dir: str) -> List[Dict[str, Any]]:
    """Run evaluation on all test programs."""
    os.makedirs(output_dir, exist_ok=True)

    results = []
    test_files = list(Path(test_dir).glob("*.c"))

    print(f"Found {len(test_files)} test programs")

    for source_file in test_files:
        program_output_dir = os.path.join(output_dir, source_file.stem)
        result = evaluate_program(str(source_file), program_output_dir)
        results.append(result)

    return results


def print_summary(results: List[Dict[str, Any]]):
    """Print evaluation summary."""
    print("\n" + "=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)

    total_programs = len(results)
    successful = sum(1 for r in results if 'error' not in r)
    failed = total_programs - successful

    print(f"\nPrograms evaluated: {total_programs}")
    print(f"  Successful: {successful}")
    print(f"  Failed: {failed}")

    if successful > 0:
        # Aggregate metrics
        avg_precision = sum(r['metrics']['precision'] for r in results if 'metrics' in r) / successful
        avg_recall = sum(r['metrics']['recall'] for r in results if 'metrics' in r) / successful
        avg_f1 = sum(r['metrics']['f1_score'] for r in results if 'metrics' in r) / successful

        print(f"\nAverage Metrics:")
        print(f"  Precision: {avg_precision:.4f}")
        print(f"  Recall: {avg_recall:.4f}")
        print(f"  F1-Score: {avg_f1:.4f}")

    print("\nDetailed Results:")
    print("-" * 70)

    for result in results:
        source = os.path.basename(result['source'])
        if 'error' in result:
            print(f"{source}: ERROR - {result['error']}")
        else:
            metrics = result['metrics']
            print(f"{source}: P={metrics['precision']:.2f} R={metrics['recall']:.2f} F1={metrics['f1_score']:.2f}")

    print("=" * 70)


def save_results(results: List[Dict[str, Any]], output_path: str):
    """Save evaluation results to file."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResults saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='OPM Evaluation')
    parser.add_argument('--test-dir', default='tests/test_programs',
                        help='Test programs directory')
    parser.add_argument('--output-dir', default='data/results',
                        help='Output directory')
    parser.add_argument('--results-file', default='evaluation_results.json',
                        help='Results output file')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Run evaluation
    results = run_evaluation(args.test_dir, args.output_dir)

    # Print summary
    print_summary(results)

    # Save results
    save_results(results, os.path.join(args.output_dir, args.results_file))


if __name__ == '__main__':
    main()
