#!/usr/bin/env python3
"""
Generate Training Data

Generates training data from binaries using TYGR datagen.
"""

import os
import sys
import pickle
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tygr', 'TYGR0'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TrainingData')


def generate_training_data(binary_path: str, output_dir: str, verbose: bool = False):
    """Generate training data from a binary."""
    from datagen0.datagen import generate_glow_dataset_no_parallel, Options

    logger.info(f"Generating training data from: {binary_path}")

    options = Options(verbose=verbose)
    os.makedirs(output_dir, exist_ok=True)

    saved = 0
    for glow_input, glow_output in generate_glow_dataset_no_parallel(binary_path, './', options):
        glow_input.ast_graph.ready_for_pickling()
        fname = f"{glow_input.file_name}?{glow_input.function_name}".replace("/", "_")
        out_path = os.path.join(output_dir, fname)

        with open(out_path, "wb") as f:
            pickle.dump((glow_input, glow_output), f)

        saved += 1
        if verbose:
            logger.info(f"Saved: {glow_input.function_name} ({len(glow_input.vars)} vars)")

    logger.info(f"Generated {saved} training samples in {output_dir}")
    return saved


def merge_datasets(input_dirs: list, output_path: str):
    """Merge multiple datasets into one."""
    logger.info(f"Merging {len(input_dirs)} datasets")

    all_samples = []
    for input_dir in input_dirs:
        for filename in os.listdir(input_dir):
            filepath = os.path.join(input_dir, filename)
            try:
                with open(filepath, 'rb') as f:
                    sample = pickle.load(f)
                    all_samples.append(sample)
            except Exception as e:
                logger.warning(f"Failed to load {filepath}: {e}")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(all_samples, f)

    logger.info(f"Merged {len(all_samples)} samples to {output_path}")
    return len(all_samples)


def split_dataset(dataset_path: str, output_dir: str, train_ratio: float = 0.8, val_ratio: float = 0.1):
    """Split dataset into train, validation, and test sets."""
    logger.info(f"Splitting dataset: {dataset_path}")

    with open(dataset_path, 'rb') as f:
        samples = pickle.load(f)

    import random
    random.shuffle(samples)

    n = len(samples)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)

    train_samples = samples[:n_train]
    val_samples = samples[n_train:n_train + n_val]
    test_samples = samples[n_train + n_val:]

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'train.pkl'), 'wb') as f:
        pickle.dump(train_samples, f)

    with open(os.path.join(output_dir, 'val.pkl'), 'wb') as f:
        pickle.dump(val_samples, f)

    with open(os.path.join(output_dir, 'test.pkl'), 'wb') as f:
        pickle.dump(test_samples, f)

    logger.info(f"Split: train={len(train_samples)}, val={len(val_samples)}, test={len(test_samples)}")
    return len(train_samples), len(val_samples), len(test_samples)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate training data')
    parser.add_argument('binary', help='Path to binary file')
    parser.add_argument('-o', '--output', default='data/training', help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Generate training data
        generate_training_data(args.binary, args.output, args.verbose)

        logger.info("Training data generation complete!")

    except Exception as e:
        logger.error(f"Failed to generate training data: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
