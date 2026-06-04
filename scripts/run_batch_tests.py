#!/usr/bin/env python3
"""
Batch Test Script

Runs the OPM pipeline on all test programs and collects results.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('BatchTest')


def run_pipeline_on_test(test_name: str, source_path: str, output_dir: str) -> Dict[str, Any]:
    """Run pipeline on a single test program."""
    from src.pipeline import OPMPipeline, OPMConfig

    logger.info(f"Running pipeline on: {test_name}")

    config = OPMConfig(
        output_dir=output_dir,
        verbose=False,
    )

    pipeline = OPMPipeline(config)

    start_time = time.time()
    try:
        result = pipeline.run(source_path)
        elapsed = time.time() - start_time

        # The result is the report dictionary
        # It contains 'summary' key with metrics
        summary = result.get('summary', {})

        # Extract metrics from summary
        metrics = {
            'precision': summary.get('precision', 0),
            'recall': summary.get('recall', 0),
            'f1_score': summary.get('f1_score', 0),
        }

        return {
            'test_name': test_name,
            'status': 'success',
            'elapsed_time': elapsed,
            'metrics': metrics,
            'summary': summary,
        }
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            'test_name': test_name,
            'status': 'failed',
            'error': str(e),
            'elapsed_time': elapsed,
        }


def run_all_tests(test_dir: str, output_base: str) -> List[Dict[str, Any]]:
    """Run pipeline on all test programs."""
    results = []

    # Find all test programs
    test_files = list(Path(test_dir).glob("*.c"))
    logger.info(f"Found {len(test_files)} test programs")

    for test_file in test_files:
        test_name = test_file.stem
        source_path = str(test_file)
        output_dir = os.path.join(output_base, test_name)

        # Run pipeline
        result = run_pipeline_on_test(test_name, source_path, output_dir)
        results.append(result)

        # Print result
        if result['status'] == 'success':
            metrics = result.get('metrics', {})
            logger.info(f"  {test_name}: P={metrics.get('precision', 0):.2f}, "
                       f"R={metrics.get('recall', 0):.2f}, "
                       f"F1={metrics.get('f1_score', 0):.2f}, "
                       f"Time={result['elapsed_time']:.2f}s")
        else:
            logger.error(f"  {test_name}: FAILED - {result.get('error', 'Unknown')}")

    return results


def print_summary(results: List[Dict[str, Any]]):
    """Print summary of all test results."""
    print("\n" + "=" * 80)
    print("BATCH TEST RESULTS")
    print("=" * 80)

    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] == 'failed']

    print(f"\nTotal tests: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if successful:
        # Calculate average metrics
        avg_precision = sum(r['metrics'].get('precision', 0) for r in successful) / len(successful)
        avg_recall = sum(r['metrics'].get('recall', 0) for r in successful) / len(successful)
        avg_f1 = sum(r['metrics'].get('f1_score', 0) for r in successful) / len(successful)
        avg_time = sum(r['elapsed_time'] for r in successful) / len(successful)

        print(f"\nAverage Metrics:")
        print(f"  Precision: {avg_precision:.4f}")
        print(f"  Recall: {avg_recall:.4f}")
        print(f"  F1-Score: {avg_f1:.4f}")
        print(f"  Time: {avg_time:.2f}s")

    print("\nDetailed Results:")
    print("-" * 80)
    print(f"{'Test Name':<25} {'Status':<10} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Time':<10}")
    print("-" * 80)

    for result in results:
        name = result['test_name']
        status = result['status']

        if status == 'success':
            metrics = result.get('metrics', {})
            p = metrics.get('precision', 0)
            r = metrics.get('recall', 0)
            f1 = metrics.get('f1_score', 0)
            t = result['elapsed_time']
            print(f"{name:<25} {'OK':<10} {p:<12.4f} {r:<12.4f} {f1:<12.4f} {t:<10.2f}")
        else:
            print(f"{name:<25} {'FAILED':<10} {'-':<12} {'-':<12} {'-':<12} {'-':<10}")

    print("=" * 80)


def save_results(results: List[Dict[str, Any]], output_path: str):
    """Save results to JSON file."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    logger.info(f"Results saved to {output_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Run batch tests')
    parser.add_argument('--test-dir', default='tests/test_programs', help='Test programs directory')
    parser.add_argument('--output-dir', default='output/batch_tests', help='Output directory')
    parser.add_argument('--results-file', default='batch_results.json', help='Results file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Run all tests
        results = run_all_tests(args.test_dir, args.output_dir)

        # Print summary
        print_summary(results)

        # Save results
        save_results(results, os.path.join(args.output_dir, args.results_file))

    except Exception as e:
        logger.error(f"Batch test failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
