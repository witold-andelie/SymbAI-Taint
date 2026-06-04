#!/usr/bin/env python3
"""
Train GNN Model

Trains a GNN model for type recovery using training data.
"""

import os
import sys
import pickle
import logging
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TrainGNN')

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import Dataset, DataLoader
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not available")


class TypeDataset(Dataset):
    """Dataset for type recovery training."""

    def __init__(self, data_dir: str):
        self.samples = []

        # Add TYGR path for loading pickle files
        tygr_path = os.path.join(os.path.dirname(__file__), '..', 'tygr', 'TYGR0')
        if tygr_path not in sys.path:
            sys.path.insert(0, tygr_path)

        # Load all files (they might not have .pkl extension)
        for filename in os.listdir(data_dir):
            filepath = os.path.join(data_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        sample = pickle.load(f)
                        if isinstance(sample, tuple) and len(sample) == 2:
                            self.samples.append(sample)
                except Exception as e:
                    logger.warning(f"Failed to load {filepath}: {e}")

        logger.info(f"Loaded {len(self.samples)} samples")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        glow_input, glow_output = self.samples[idx]

        # Extract features from the graph
        # This is a simplified version - real implementation would
        # convert the AST graph to PyG format

        # For now, return dummy data
        num_nodes = len(glow_input.ast_graph.nodes) if hasattr(glow_input.ast_graph, 'nodes') else 10
        num_vars = len(glow_input.vars)

        # Create dummy node features
        x = torch.randn(num_nodes, 64)

        # Create dummy edge index
        edge_index = torch.randint(0, num_nodes, (2, num_nodes * 2))

        # Create dummy labels (type indices)
        # Map types to indices
        type_map = {
            'i32': 0, 'i64': 1, 'char*': 2, 'void*': 3,
            'array<char>': 4, 'int': 5, 'float': 6,
        }

        # Use the first variable's type as the label
        if len(glow_output.types) > 0:
            type_str = str(glow_output.types[0])
            y = torch.tensor([type_map.get(type_str, 0)], dtype=torch.long)
        else:
            y = torch.tensor([0], dtype=torch.long)

        return x, edge_index, y


class SimpleGNN(nn.Module):
    """Simple GNN for type recovery."""

    def __init__(self, input_dim=64, hidden_dim=128, output_dim=7):
        super().__init__()

        self.conv1 = nn.Linear(input_dim, hidden_dim)
        self.conv2 = nn.Linear(hidden_dim, hidden_dim)
        self.conv3 = nn.Linear(hidden_dim, output_dim)

        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)

    def forward(self, x, edge_index):
        # Simple message passing
        # edge_index shape: [2, num_edges] or [1, 2, num_edges]
        if edge_index.dim() == 3:
            edge_index = edge_index.squeeze(0)

        src, dst = edge_index[0], edge_index[1]

        # Clamp indices to valid range
        num_nodes = x.size(0)
        src = torch.clamp(src, 0, num_nodes - 1)
        dst = torch.clamp(dst, 0, num_nodes - 1)

        # Aggregate messages
        messages = torch.zeros_like(x)
        messages.index_add_(0, dst, x[src])

        # Apply layers
        h = self.relu(self.conv1(messages))
        h = self.dropout(h)
        h = self.relu(self.conv2(h))
        h = self.dropout(h)
        h = self.conv3(h)

        return h


def train_model(model, train_loader, val_loader, epochs=100, lr=0.001):
    """Train the model."""
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    history = {'train_loss': [], 'val_loss': [], 'train_acc': [], 'val_acc': []}

    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for x, edge_index, y in train_loader:
            optimizer.zero_grad()

            # Forward pass
            output = model(x, edge_index)

            # Global average pooling - handle different dimensions
            if output.dim() == 3:
                pooled = output.mean(dim=1).mean(dim=0)  # [num_classes]
            elif output.dim() == 2:
                pooled = output.mean(dim=0)  # [num_classes]
            else:
                pooled = output  # [num_classes]

            # Add batch dimension for loss function
            predictions = pooled.unsqueeze(0)  # [1, num_classes]
            y = y.view(-1)  # [1]

            loss = criterion(predictions, y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            pred = predictions.argmax(dim=1)
            train_correct += (pred == y).sum().item()
            train_total += len(y)

        train_loss /= len(train_loader)
        train_acc = train_correct / train_total if train_total > 0 else 0

        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)

        # Validation
        if val_loader:
            model.eval()
            val_loss = 0.0
            val_correct = 0
            val_total = 0

            with torch.no_grad():
                for x, edge_index, y in val_loader:
                    output = model(x, edge_index)

                    # Global average pooling - handle different dimensions
                    if output.dim() == 3:
                        pooled = output.mean(dim=1).mean(dim=0)  # [num_classes]
                    elif output.dim() == 2:
                        pooled = output.mean(dim=0)  # [num_classes]
                    else:
                        pooled = output  # [num_classes]

                    # Add batch dimension for loss function
                    predictions = pooled.unsqueeze(0)  # [1, num_classes]
                    y = y.view(-1)  # [1]

                    loss = criterion(predictions, y)
                    val_loss += loss.item()

                    pred = predictions.argmax(dim=1)
                    val_correct += (pred == y).sum().item()
                    val_total += len(y)

            val_loss /= len(val_loader)
            val_acc = val_correct / val_total if val_total > 0 else 0

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


def save_model(model, model_path: str):
    """Save the trained model."""
    os.makedirs(os.path.dirname(model_path) or '.', exist_ok=True)

    checkpoint = {
        'model_state_dict': model.state_dict(),
        'model_class': model.__class__.__name__,
    }

    torch.save(checkpoint, model_path)
    logger.info(f"Model saved to: {model_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Train GNN model')
    parser.add_argument('data_dir', help='Training data directory')
    parser.add_argument('-o', '--output', default='data/models/trained_model.pt', help='Output model path')
    parser.add_argument('-e', '--epochs', type=int, default=100, help='Number of epochs')
    parser.add_argument('-lr', '--learning-rate', type=float, default=0.001, help='Learning rate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not HAS_TORCH:
        logger.error("PyTorch not available")
        sys.exit(1)

    try:
        # Load dataset
        dataset = TypeDataset(args.data_dir)

        if len(dataset) == 0:
            logger.error("No training data found")
            sys.exit(1)

        # Split into train and validation
        train_size = int(0.8 * len(dataset))
        val_size = len(dataset) - train_size

        train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])

        train_loader = DataLoader(train_dataset, batch_size=1, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=1, shuffle=False)

        # Create model
        model = SimpleGNN(input_dim=64, hidden_dim=128, output_dim=7)

        # Train model
        history = train_model(model, train_loader, val_loader, epochs=args.epochs, lr=args.learning_rate)

        # Save model
        save_model(model, args.output)

        logger.info("Training complete!")

    except Exception as e:
        logger.error(f"Training failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
