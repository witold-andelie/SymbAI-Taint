#!/usr/bin/env python3
"""
Train False Positive Detector

Trains a model to detect false positive taint paths.
"""

import os
import sys
import pickle
import logging
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tygr', 'TYGR0'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TrainFPDetector')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class FPDetector(nn.Module):
    """Neural network for detecting false positive taint paths."""

    def __init__(self, input_dim: int = 10, hidden_dim: int = 32):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, 2)  # Binary: true positive or false positive
        )

    def forward(self, x):
        return self.network(x)


def extract_features_from_path(path_info: Dict[str, Any]) -> torch.Tensor:
    """Extract features from a taint path for FP detection."""
    features = torch.zeros(10)

    # Source-sink distance (in call graph)
    source = path_info.get('source', '')
    sink = path_info.get('sink', '')
    source_caller = path_info.get('source_caller', '')
    sink_caller = path_info.get('sink_caller', '')

    # Same function indicator
    features[0] = 1.0 if source_caller == sink_caller else 0.0

    # Source type
    source_indicators = {
        'gets': 0, 'scanf': 1, 'getchar': 2, 'fgets': 3, 'recv': 4
    }
    features[1] = source_indicators.get(source, 5)

    # Sink type
    sink_indicators = {
        'strcpy': 0, 'strncpy': 1, 'sprintf': 2, 'printf': 3,
        'system': 4, 'malloc': 5, 'free': 6
    }
    features[2] = sink_indicators.get(sink, 7)

    # Path length
    path = path_info.get('path', [])
    features[3] = len(path) / 5.0  # Normalized

    # Is direct call (source caller directly calls sink caller)
    features[4] = 1.0 if len(path) <= 2 else 0.0

    # Source is real input function
    real_sources = {'gets', 'scanf', 'getchar', 'fgets', 'recv', 'read'}
    features[5] = 1.0 if source in real_sources else 0.0

    # Sink is real dangerous function
    real_sinks = {'strcpy', 'strncpy', 'sprintf', 'system', 'gets'}
    features[6] = 1.0 if sink in real_sinks else 0.0

    # Both source and sink are in the same function
    features[7] = 1.0 if source_caller == sink_caller else 0.0

    # Source caller is a vulnerable function name
    vuln_funcs = {'vulnerable_strcpy', 'vulnerable_printf', 'vulnerable_system',
                  'vulnerable_stack', 'vulnerable_heap', 'safe_function'}
    features[8] = 1.0 if source_caller in vuln_funcs else 0.0

    # Sink caller is a vulnerable function name
    features[9] = 1.0 if sink_caller in vuln_funcs else 0.0

    return features


def load_ground_truth_and_predictions() -> List[Tuple[torch.Tensor, int]]:
    """
    Load ground truth and predictions to create training data for FP detector.

    Returns list of (features, label) pairs where label=1 for TP, 0 for FP.
    """
    samples = []

    # Define ground truth paths (from our test program)
    ground_truth_paths = {
        ('argv', 'strcpy'), ('argv', 'printf'), ('argv', 'sprintf'),
        ('argv', 'system'), ('argv', 'strncpy'), ('argv', 'malloc'),
        ('argv', 'free'), ('argv', 'gets'),
        ('gets', 'strcpy'), ('gets', 'strncpy'), ('gets', 'free'), ('gets', 'gets'),
    }

    # Define detected paths (from our analysis)
    detected_paths = [
        {'source': 'gets', 'sink': 'strcpy', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'vulnerable_strcpy', 'path': ['vulnerable_stack', 'main', 'vulnerable_strcpy']},
        {'source': 'gets', 'sink': 'printf', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'vulnerable_strcpy', 'path': ['vulnerable_stack', 'main', 'vulnerable_strcpy']},
        {'source': 'gets', 'sink': 'sprintf', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'vulnerable_system', 'path': ['vulnerable_stack', 'main', 'vulnerable_system']},
        {'source': 'gets', 'sink': 'system', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'vulnerable_system', 'path': ['vulnerable_stack', 'main', 'vulnerable_system']},
        {'source': 'gets', 'sink': 'malloc', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'vulnerable_heap', 'path': ['vulnerable_stack', 'main', 'vulnerable_heap']},
        {'source': 'gets', 'sink': 'printf', 'source_caller': 'vulnerable_stack',
         'sink_caller': 'main', 'path': ['vulnerable_stack', 'main']},
        # True positives (argv paths)
        {'source': 'argv', 'sink': 'strcpy', 'source_caller': 'main',
         'sink_caller': 'vulnerable_strcpy', 'path': ['main', 'vulnerable_strcpy']},
        {'source': 'argv', 'sink': 'printf', 'source_caller': 'main',
         'sink_caller': 'vulnerable_strcpy', 'path': ['main', 'vulnerable_strcpy']},
        {'source': 'argv', 'sink': 'sprintf', 'source_caller': 'main',
         'sink_caller': 'vulnerable_system', 'path': ['main', 'vulnerable_system']},
        {'source': 'argv', 'sink': 'system', 'source_caller': 'main',
         'sink_caller': 'vulnerable_system', 'path': ['main', 'vulnerable_system']},
        {'source': 'argv', 'sink': 'strncpy', 'source_caller': 'main',
         'sink_caller': 'safe_function', 'path': ['main', 'safe_function']},
        {'source': 'argv', 'sink': 'malloc', 'source_caller': 'main',
         'sink_caller': 'vulnerable_heap', 'path': ['main', 'vulnerable_heap']},
        {'source': 'argv', 'sink': 'free', 'source_caller': 'main',
         'sink_caller': 'vulnerable_heap', 'path': ['main', 'vulnerable_heap']},
        {'source': 'argv', 'sink': 'gets', 'source_caller': 'main',
         'sink_caller': 'vulnerable_stack', 'path': ['main', 'vulnerable_stack']},
    ]

    for path_info in detected_paths:
        features = extract_features_from_path(path_info)

        # Check if this is a true positive
        key = (path_info['source'], path_info['sink'])
        is_tp = 1 if key in ground_truth_paths else 0

        samples.append((features, is_tp))

    logger.info(f"Created {len(samples)} training samples")
    return samples


def train_model(model, train_data, val_data, epochs: int = 100, lr: float = 0.001):
    """Train the model."""
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 2.0]))  # Weight TP higher

    history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}

    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0

        for features, label in train_data:
            optimizer.zero_grad()

            x = features.unsqueeze(0)
            y = torch.tensor([label], dtype=torch.long)

            out = model(x)
            loss = criterion(out, y)

            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            pred = out.argmax(dim=1).item()
            train_correct += int(pred == label)

        train_loss /= len(train_data)
        train_acc = train_correct / len(train_data) if train_data else 0

        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)

        # Validation
        if val_data:
            model.eval()
            val_loss = 0.0
            val_correct = 0

            with torch.no_grad():
                for features, label in val_data:
                    x = features.unsqueeze(0)
                    y = torch.tensor([label], dtype=torch.long)

                    out = model(x)
                    loss = criterion(out, y)

                    val_loss += loss.item()
                    pred = out.argmax(dim=1).item()
                    val_correct += int(pred == label)

            val_loss /= len(val_data)
            val_acc = val_correct / len(val_data) if val_data else 0

            history['val_loss'].append(val_loss)
            history['val_acc'].append(val_acc)

            if (epoch + 1) % 20 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}, "
                          f"val_loss={val_loss:.4f}, val_acc={val_acc:.4f}")
        else:
            if (epoch + 1) % 20 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}")

    return history


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Train FP detector')
    parser.add_argument('-o', '--output', default='data/models/fp_detector.pt', help='Output model path')
    parser.add_argument('-e', '--epochs', type=int, default=100, help='Number of epochs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not HAS_TORCH:
        logger.error("PyTorch not available")
        sys.exit(1)

    try:
        # Load data
        all_data = load_ground_truth_and_predictions()

        if len(all_data) == 0:
            logger.error("No training data found")
            sys.exit(1)

        # Split data
        np.random.shuffle(all_data)
        train_size = int(0.8 * len(all_data))

        train_data = all_data[:train_size]
        val_data = all_data[train_size:]

        logger.info(f"Train: {len(train_data)}, Val: {len(val_data)}")

        # Create model
        model = FPDetector(input_dim=10, hidden_dim=32)

        # Train
        history = train_model(model, train_data, val_data, epochs=args.epochs)

        # Save model
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        torch.save({
            'model_state_dict': model.state_dict(),
            'config': {
                'input_dim': 10,
                'hidden_dim': 32,
            }
        }, args.output)

        logger.info(f"Model saved to {args.output}")
        logger.info("Training complete!")

    except Exception as e:
        logger.error(f"Training failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
