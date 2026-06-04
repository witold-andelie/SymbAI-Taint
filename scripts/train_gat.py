#!/usr/bin/env python3
"""
Train GAT Model for Type Recovery

Trains a Graph Attention Network using TYGR-generated training data.
"""

import os
import sys
import pickle
import logging
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add paths
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tygr', 'TYGR0'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TrainGAT')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.nn import GATv2Conv, global_mean_pool
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch or PyG not available")


def load_training_data(data_dirs: List[str]) -> List[Tuple[Any, Any]]:
    """Load training data from multiple directories."""
    all_samples = []

    for data_dir in data_dirs:
        if not os.path.exists(data_dir):
            logger.warning(f"Directory not found: {data_dir}")
            continue

        for filename in os.listdir(data_dir):
            filepath = os.path.join(data_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        sample = pickle.load(f)
                        if isinstance(sample, tuple) and len(sample) == 2:
                            all_samples.append(sample)
                except Exception as e:
                    logger.warning(f"Failed to load {filepath}: {e}")

    logger.info(f"Loaded {len(all_samples)} samples")
    return all_samples


def convert_to_pyg(glow_input, glow_output, type_map: Dict[str, int]) -> Data:
    """Convert TYGR format to PyG Data."""
    # Get graph structure
    ast_graph = glow_input.ast_graph

    # Node features
    num_nodes = len(ast_graph.nodes) if hasattr(ast_graph, 'nodes') else 0
    if num_nodes == 0:
        num_nodes = 10  # Default

    # Create node features (one-hot encoding of node type)
    x = torch.zeros(num_nodes, 64)

    # Edge index
    edges = []
    if hasattr(ast_graph, 'edges'):
        for edge in ast_graph.edges:
            if len(edge) == 2:
                src, dst = edge
                if src < num_nodes and dst < num_nodes:
                    edges.append([src, dst])

    if not edges:
        # Create dummy edges
        edges = [[0, 1], [1, 2]]

    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

    # Labels (type of first variable)
    if len(glow_output.types) > 0:
        type_str = str(glow_output.types[0])
        y = torch.tensor([type_map.get(type_str, 0)], dtype=torch.long)
    else:
        y = torch.tensor([0], dtype=torch.long)

    return Data(x=x, edge_index=edge_index, y=y)


class GATForTypeRecovery(nn.Module):
    """GAT model for type recovery."""

    def __init__(self, input_dim: int = 64, hidden_dim: int = 128,
                 output_dim: int = 7, num_heads: int = 4, dropout: float = 0.2):
        super().__init__()

        # GAT layers
        self.conv1 = GATv2Conv(input_dim, hidden_dim // num_heads,
                               heads=num_heads, dropout=dropout)
        self.conv2 = GATv2Conv(hidden_dim, hidden_dim // num_heads,
                               heads=num_heads, dropout=dropout)
        self.conv3 = GATv2Conv(hidden_dim, hidden_dim // num_heads,
                               heads=num_heads, dropout=dropout)

        # Layer norms
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.norm2 = nn.LayerNorm(hidden_dim)
        self.norm3 = nn.LayerNorm(hidden_dim)

        # Output layers
        self.output = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_dim)
        )

        self.dropout = dropout

    def forward(self, x, edge_index, batch=None):
        """Forward pass."""
        # GAT layers with residual connections
        h = F.elu(self.conv1(x, edge_index))
        h = self.norm1(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        h2 = F.elu(self.conv2(h, edge_index))
        h2 = self.norm2(h2 + h)  # Residual
        h2 = F.dropout(h2, p=self.dropout, training=self.training)

        h3 = F.elu(self.conv3(h2, edge_index))
        h3 = self.norm3(h3 + h2)  # Residual
        h3 = F.dropout(h3, p=self.dropout, training=self.training)

        # Global pooling
        if batch is not None:
            h3 = global_mean_pool(h3, batch)
        else:
            h3 = h3.mean(dim=0, keepdim=True)

        # Classification
        out = self.output(h3)
        return out


def train_model(model, train_loader, val_loader, epochs: int = 50, lr: float = 0.001):
    """Train the model."""
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()

    history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}

    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for data in train_loader:
            optimizer.zero_grad()

            out = model(data.x, data.edge_index, data.batch)
            loss = criterion(out, data.y.view(-1))

            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            pred = out.argmax(dim=1)
            train_correct += (pred == data.y.view(-1)).sum().item()
            train_total += len(data.y)

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
                for data in val_loader:
                    out = model(data.x, data.edge_index, data.batch)
                    loss = criterion(out, data.y.view(-1))

                    val_loss += loss.item()
                    pred = out.argmax(dim=1)
                    val_correct += (pred == data.y.view(-1)).sum().item()
                    val_total += len(data.y)

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


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Train GAT model')
    parser.add_argument('data_dirs', nargs='+', help='Training data directories')
    parser.add_argument('-o', '--output', default='data/models/gat_model.pt', help='Output model path')
    parser.add_argument('-e', '--epochs', type=int, default=50, help='Number of epochs')
    parser.add_argument('-lr', '--learning-rate', type=float, default=0.001, help='Learning rate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not HAS_TORCH:
        logger.error("PyTorch or PyG not available")
        sys.exit(1)

    try:
        # Load data
        raw_data = load_training_data(args.data_dirs)

        if len(raw_data) == 0:
            logger.error("No training data found")
            sys.exit(1)

        # Type map
        type_map = {
            'i32': 0, 'i64': 1, 'char*': 2, 'void*': 3,
            'array<char>': 4, 'u64': 5, 'int': 6,
        }

        # Convert to PyG format
        pyg_data = []
        for glow_input, glow_output in raw_data:
            try:
                data = convert_to_pyg(glow_input, glow_output, type_map)
                pyg_data.append(data)
            except Exception as e:
                logger.warning(f"Failed to convert sample: {e}")

        logger.info(f"Converted {len(pyg_data)} samples to PyG format")

        if len(pyg_data) == 0:
            logger.error("No valid samples")
            sys.exit(1)

        # Split data
        np.random.shuffle(pyg_data)
        train_size = int(0.8 * len(pyg_data))
        val_size = len(pyg_data) - train_size

        train_data = pyg_data[:train_size]
        val_data = pyg_data[train_size:]

        train_loader = DataLoader(train_data, batch_size=1, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=1, shuffle=False)

        # Create model
        model = GATForTypeRecovery(
            input_dim=64,
            hidden_dim=128,
            output_dim=len(type_map),
            num_heads=4,
            dropout=0.2
        )

        # Train
        history = train_model(model, train_loader, val_loader,
                            epochs=args.epochs, lr=args.learning_rate)

        # Save model
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        torch.save({
            'model_state_dict': model.state_dict(),
            'type_map': type_map,
            'config': {
                'input_dim': 64,
                'hidden_dim': 128,
                'output_dim': len(type_map),
                'num_heads': 4,
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
