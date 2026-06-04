#!/usr/bin/env python3
"""
Type Prediction Script

Uses pre-trained TYGR model to predict variable types in binaries.
"""

import os
import sys
import pickle
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TypePrediction')


def load_model(model_path: str):
    """Load a pre-trained TYGR model."""
    import torch

    logger.info(f"Loading model from: {model_path}")

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    # Add TYGR original source to path for model loading
    tygr_original_path = os.path.join(os.path.dirname(__file__), '..', 'tygr_original')
    if tygr_original_path not in sys.path:
        sys.path.insert(0, tygr_original_path)

    # Load with weights_only=False for compatibility with older models
    model = torch.load(model_path, map_location='cpu', weights_only=False)
    logger.info("Model loaded successfully")
    return model


def generate_dataset(binary_path: str, output_path: str):
    """Generate dataset from binary using TYGR datagen."""
    logger.info(f"Generating dataset from: {binary_path}")

    # Import TYGR modules
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tygr', 'TYGR0'))

    try:
        from datagen0.datagen import generate_glow_dataset_no_parallel, Options

        options = Options(verbose=True)
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        saved = 0
        for glow_input, glow_output in generate_glow_dataset_no_parallel(binary_path, './', options):
            glow_input.ast_graph.ready_for_pickling()
            fname = f"{glow_input.file_name}?{glow_input.function_name}".replace("/", "_")
            out_path = os.path.join(output_path, fname)

            with open(out_path, "wb") as f:
                pickle.dump((glow_input, glow_output), f)

            saved += 1
            logger.info(f"Saved: {glow_input.function_name}")

        logger.info(f"Generated {saved} datasets in {output_path}")
        return saved

    except Exception as e:
        logger.error(f"Failed to generate dataset: {e}")
        raise


def predict_types(model, dataset_path: str, output_path: str):
    """Predict types using the model."""
    import torch
    from torch import Tensor

    logger.info(f"Predicting types for: {dataset_path}")

    # Load dataset
    with open(dataset_path, 'rb') as f:
        glow_input, glow_output = pickle.load(f)

    # Prepare input for model
    # This depends on the model architecture
    # For now, we'll use the GlowInput structure

    logger.info(f"Function: {glow_input.function_name}")
    logger.info(f"Variables: {len(glow_input.vars)}")

    # Get predictions from model
    # This is a simplified version - actual implementation depends on model architecture
    predictions = {}

    for var in glow_input.vars:
        # For now, use the ground truth types
        # In a real implementation, we would use the model to predict
        predictions[var.name] = {
            'predicted_type': 'unknown',
            'confidence': 0.0,
        }

    # Save predictions
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(predictions, f)

    logger.info(f"Predictions saved to: {output_path}")
    return predictions


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Predict variable types using TYGR model')
    parser.add_argument('model', help='Path to pre-trained model')
    parser.add_argument('binary', help='Path to binary file')
    parser.add_argument('-o', '--output', default='predictions', help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load model
        model = load_model(args.model)

        # Generate dataset
        dataset_dir = os.path.join(args.output, 'datasets')
        generate_dataset(args.binary, dataset_dir)

        # Predict types for each dataset
        predictions_dir = os.path.join(args.output, 'predictions')
        os.makedirs(predictions_dir, exist_ok=True)

        for dataset_file in os.listdir(dataset_dir):
            if dataset_file.endswith('.pkl'):
                dataset_path = os.path.join(dataset_dir, dataset_file)
                prediction_path = os.path.join(predictions_dir, f"{dataset_file}.predictions.pkl")
                predict_types(model, dataset_path, prediction_path)

        logger.info("Type prediction complete!")

    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
