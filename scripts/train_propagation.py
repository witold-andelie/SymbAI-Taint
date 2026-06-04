#!/usr/bin/env python3
"""
Train Learned Taint Propagation Model

Trains a neural network to predict taint propagation.
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
logger = logging.getLogger('TrainPropagation')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class PropagationNet(nn.Module):
    """Neural network for predicting taint propagation."""

    def __init__(self, input_dim: int = 16, hidden_dim: int = 64):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 2)  # Binary: propagates or not
        )

    def forward(self, x):
        return self.network(x)


def extract_features_from_graph(glow_input, glow_output) -> List[Tuple[torch.Tensor, int]]:
    """
    Extract features from TYGR graph for taint propagation training.

    Returns list of (features, label) pairs.
    """
    samples = []

    ast_graph = glow_input.ast_graph

    # Get edge features
    if hasattr(ast_graph, 'edge_to_labels'):
        for (src, dst), labels in ast_graph.edge_to_labels.items():
            # Create feature vector
            features = torch.zeros(16)

            # Edge type features
            if 'mem_loc' in labels:
                features[0] = 1.0
            if 'mem_data' in labels:
                features[1] = 1.0
            if 'reg_loc' in labels:
                features[2] = 1.0
            if 'reg_data' in labels:
                features[3] = 1.0

            # Operation features
            for label in labels:
                if '__add__' in str(label):
                    features[4] = 1.0
                elif '__sub__' in str(label):
                    features[5] = 1.0
                elif '__mul__' in str(label):
                    features[6] = 1.0

            # Node features
            if hasattr(ast_graph, 'node_to_label'):
                src_label = ast_graph.node_to_label.get(src)
                dst_label = ast_graph.node_to_label.get(dst)

                if src_label and dst_label:
                    # Size features
                    features[7] = src_label.bitsize / 64.0 if hasattr(src_label, 'bitsize') else 0
                    features[8] = dst_label.bitsize / 64.0 if hasattr(dst_label, 'bitsize') else 0

            # Label: 1 if this is a data flow edge (propagates taint)
            is_data_flow = any(l in labels for l in ['mem_data', 'reg_data', '__add__', '__sub__', 'data'])
            label = 1 if is_data_flow else 0

            samples.append((features, label))

    return samples


def load_training_data(data_dirs: List[str]) -> List[Tuple[torch.Tensor, int]]:
    """Load and extract features from training data."""
    all_samples = []

    for data_dir in data_dirs:
        if not os.path.exists(data_dir):
            continue

        for filename in os.listdir(data_dir):
            filepath = os.path.join(data_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        sample = pickle.load(f)
                        if isinstance(sample, tuple) and len(sample) == 2:
                            glow_input, glow_output = sample
                            features = extract_features_from_graph(glow_input, glow_output)
                            all_samples.extend(features)
                except Exception as e:
                    logger.warning(f"Failed to load {filepath}: {e}")

    logger.info(f"Extracted {len(all_samples)} feature samples")
    return all_samples


def train_model(model, train_data, val_data, epochs: int = 50, lr: float = 0.001):
    """Train the model."""
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

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

            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}, "
                          f"val_loss={val_loss:.4f}, val_acc={val_acc:.4f}")
        else:
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}")

    return history


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Train propagation model')
    parser.add_argument('data_dirs', nargs='+', help='Training data directories')
    parser.add_argument('-o', '--output', default='data/models/propagation.pt', help='Output model path')
    parser.add_argument('-e', '--epochs', type=int, default=50, help='Number of epochs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not HAS_TORCH:
        logger.error("PyTorch not available")
        sys.exit(1)

    try:
        # Load data
        all_data = load_training_data(args.data_dirs)

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
        model = PropagationNet(input_dim=16, hidden_dim=64)

        # Train
        history = train_model(model, train_data, val_data, epochs=args.epochs)

        # Save model
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        torch.save({
            'model_state_dict': model.state_dict(),
            'config': {
                'input_dim': 16,
                'hidden_dim': 64,
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
