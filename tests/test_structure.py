#!/usr/bin/env python3
"""
Test project structure
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")

    try:
        from src.pipeline import OPMPipeline, OPMConfig
        print("  ✓ pipeline module")
    except ImportError as e:
        print(f"  ✗ pipeline module: {e}")

    try:
        from src.compilation import compiler, stripper
        print("  ✓ compilation module")
    except ImportError as e:
        print(f"  ✗ compilation module: {e}")

    try:
        from src.ground_truth import extractor, validator
        print("  ✓ ground_truth module")
    except ImportError as e:
        print(f"  ✗ ground_truth module: {e}")

    try:
        from src.binary_analysis import vex_lift, cfg_recovery, dfg_construction
        print("  ✓ binary_analysis module")
    except ImportError as e:
        print(f"  ✗ binary_analysis module: {e}")

    try:
        from src.type_recovery import inference, dataset
        print("  ✓ type_recovery module")
    except ImportError as e:
        print(f"  ✗ type_recovery module: {e}")

    try:
        from src.typed_ir import type_injector, ir_types
        print("  ✓ typed_ir module")
    except ImportError as e:
        print(f"  ✗ typed_ir module: {e}")

    try:
        from src.symbolic_exec import guided_executor, path_prioritizer
        print("  ✓ symbolic_exec module")
    except ImportError as e:
        print(f"  ✗ symbolic_exec module: {e}")

    try:
        from src.taint_analysis import taint_engine, source_sink, rules
        print("  ✓ taint_analysis module")
    except ImportError as e:
        print(f"  ✗ taint_analysis module: {e}")

    try:
        from src.evaluation import metrics, reporter
        print("  ✓ evaluation module")
    except ImportError as e:
        print(f"  ✗ evaluation module: {e}")


def test_structure():
    """Test project directory structure."""
    print("\nTesting project structure...")

    base_dir = os.path.dirname(os.path.dirname(__file__))

    expected_dirs = [
        'src',
        'src/compilation',
        'src/ground_truth',
        'src/binary_analysis',
        'src/type_recovery',
        'src/typed_ir',
        'src/symbolic_exec',
        'src/taint_analysis',
        'src/evaluation',
        'tests',
        'tests/test_programs',
        'data',
        'scripts',
    ]

    for dir_path in expected_dirs:
        full_path = os.path.join(base_dir, dir_path)
        if os.path.isdir(full_path):
            print(f"  ✓ {dir_path}")
        else:
            print(f"  ✗ {dir_path}")


def test_files():
    """Test that key files exist."""
    print("\nTesting key files...")

    base_dir = os.path.dirname(os.path.dirname(__file__))

    expected_files = [
        'src/__init__.py',
        'src/pipeline.py',
        'src/compilation/__init__.py',
        'src/compilation/compiler.py',
        'src/compilation/stripper.py',
        'src/ground_truth/__init__.py',
        'src/ground_truth/extractor.py',
        'src/ground_truth/validator.py',
        'src/binary_analysis/__init__.py',
        'src/binary_analysis/vex_lift.py',
        'src/binary_analysis/cfg_recovery.py',
        'src/binary_analysis/dfg_construction.py',
        'src/type_recovery/__init__.py',
        'src/type_recovery/inference.py',
        'src/type_recovery/dataset.py',
        'src/typed_ir/__init__.py',
        'src/typed_ir/type_injector.py',
        'src/typed_ir/ir_types.py',
        'src/symbolic_exec/__init__.py',
        'src/symbolic_exec/guided_executor.py',
        'src/symbolic_exec/path_prioritizer.py',
        'src/taint_analysis/__init__.py',
        'src/taint_analysis/taint_engine.py',
        'src/taint_analysis/source_sink.py',
        'src/taint_analysis/rules.py',
        'src/evaluation/__init__.py',
        'src/evaluation/metrics.py',
        'src/evaluation/reporter.py',
        'tests/test_programs/vulnerable.c',
        'tests/test_programs/taint_flow.c',
        'scripts/run_pipeline.py',
        'scripts/evaluate.py',
        'requirements.txt',
        'README.md',
    ]

    for file_path in expected_files:
        full_path = os.path.join(base_dir, file_path)
        if os.path.isfile(full_path):
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path}")


def main():
    print("=" * 50)
    print("OPM Project Structure Test")
    print("=" * 50)

    test_imports()
    test_structure()
    test_files()

    print("\n" + "=" * 50)
    print("Test complete!")
    print("=" * 50)


if __name__ == '__main__':
    main()
