#!/usr/bin/env python3
"""
OPM Pipeline Runner

Runs the complete OPM taint analysis pipeline.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.pipeline import OPMPipeline, OPMConfig


def main():
    parser = argparse.ArgumentParser(description='OPM Taint Analysis Pipeline')
    parser.add_argument('source', help='C source file to analyze')
    parser.add_argument('--binary', help='Pre-compiled binary (optional)')
    parser.add_argument('--output', '-o', default='./output', help='Output directory')
    parser.add_argument('--taint-spec', help='Taint specification file')
    parser.add_argument('--model', help='GNN model path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-strip', action='store_true', help='Do not strip binary')
    parser.add_argument('--max-steps', type=int, default=1000, help='Max symbolic steps')
    parser.add_argument('--timeout', type=int, default=1000, help='Solver timeout (ms)')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create configuration
    config = OPMConfig(
        output_dir=args.output,
        strip_binary=not args.no_strip,
        gnn_model_path=args.model,
        taint_spec_path=args.taint_spec,
        max_symbolic_steps=args.max_steps,
        solver_timeout=args.timeout,
        verbose=args.verbose,
    )

    # Create pipeline
    pipeline = OPMPipeline(config)

    # Run pipeline
    try:
        result = pipeline.run(args.source)

        print("\n" + "=" * 60)
        print("OPM ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"Source: {args.source}")
        print(f"Output: {args.output}")
        print(f"Report: {result.get('path', 'N/A')}")

        # Print summary
        summary = result.get('summary', {})
        print(f"\nSummary:")
        print(f"  Total traces: {summary.get('total_traces', 0)}")
        print(f"  Vulnerable traces: {summary.get('vulnerable_traces', 0)}")
        print(f"  Precision: {summary.get('precision', 0):.4f}")
        print(f"  Recall: {summary.get('recall', 0):.4f}")
        print(f"  F1-Score: {summary.get('f1_score', 0):.4f}")
        print("=" * 60)

    except Exception as e:
        logging.error(f"Pipeline failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
