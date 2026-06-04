"""
GNN Model for Type Recovery

Implements a Graph Neural Network for predicting variable types from binary code.
Uses the graph structure of CFG/DFG to learn type representations.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger('OPM.type_recovery')

# Try to import torch
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not available, GNN model will not work")


@dataclass
class TypeGNNConfig:
    """Configuration for the Type GNN model."""
    # Model architecture
    input_dim: int = 64       # Input feature dimension
    hidden_dim: int = 128     # Hidden layer dimension
    output_dim: int = 32      # Output embedding dimension
    num_layers: int = 3       # Number of GNN layers
    num_heads: int = 4        # Number of attention heads (for GAT)

    # Training
    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 100
    dropout: float = 0.2

    # Type classes
    num_type_classes: int = 20  # Number of type classes to predict


if HAS_TORCH:
    class GATLayer(nn.Module):
        """Graph Attention Layer."""

        def __init__(self, in_channels, out_channels, heads=1, dropout=0.0):
            super().__init__()
            self.in_channels = in_channels
            self.out_channels = out_channels
            self.heads = heads
            self.dropout = dropout

            # Linear transformation for each head
            self.W = nn.Linear(in_channels, out_channels * heads, bias=False)

            # Attention parameters
            self.a_src = nn.Parameter(torch.empty(1, heads, out_channels))
            self.a_dst = nn.Parameter(torch.empty(1, heads, out_channels))

            # Bias
            self.bias = nn.Parameter(torch.empty(heads * out_channels))

            self.reset_parameters()

        def reset_parameters(self):
            """Reset parameters."""
            nn.init.xavier_uniform_(self.W.weight)
            nn.init.xavier_uniform_(self.a_src)
            nn.init.xavier_uniform_(self.a_dst)
            nn.init.zeros_(self.bias)

        def forward(self, x, edge_index):
            """
            Forward pass.

            Args:
                x: Node features [num_nodes, in_channels]
                edge_index: Edge indices [2, num_edges]

            Returns:
                Updated node features [num_nodes, heads * out_channels]
            """
            num_nodes = x.size(0)
            src, dst = edge_index

            # Linear transformation
            h = self.W(x).view(-1, self.heads, self.out_channels)

            # Compute attention scores
            h_src = (h * self.a_src).sum(dim=-1)  # [num_nodes, heads]
            h_dst = (h * self.a_dst).sum(dim=-1)  # [num_nodes, heads]

            # Edge attention
            e = h_src[src] + h_dst[dst]  # [num_edges, heads]
            e = F.leaky_relu(e, negative_slope=0.2)

            # Softmax
            alpha = torch.zeros(num_nodes, self.heads, device=x.device)
            alpha.index_add_(0, dst, torch.ones(src.size(0), self.heads, device=x.device))
            alpha = torch.gather(alpha, 0, dst.unsqueeze(1).expand(-1, self.heads))
            alpha = e / (alpha + 1e-6)

            # Dropout
            if self.training:
                alpha = F.dropout(alpha, p=self.dropout, training=True)

            # Aggregate
            out = torch.zeros(num_nodes, self.heads, self.out_channels, device=x.device)
            out.index_add_(0, dst, h[src] * alpha.unsqueeze(-1))

            # Reshape and add bias
            out = out.view(num_nodes, -1) + self.bias

            return out

    class TypeGNN(nn.Module):
        """
        Graph Neural Network for Type Recovery.

        Uses Graph Attention Networks (GAT) to learn node embeddings
        and predict variable types.
        """

        def __init__(self, config: TypeGNNConfig):
            super().__init__()
            self.config = config

            # Input projection
            self.input_proj = nn.Linear(config.input_dim, config.hidden_dim)

            # GNN layers
            self.gnn_layers = nn.ModuleList()
            for _ in range(config.num_layers):
                self.gnn_layers.append(
                    GATLayer(
                        in_channels=config.hidden_dim,
                        out_channels=config.hidden_dim // config.num_heads,
                        heads=config.num_heads,
                        dropout=config.dropout
                    )
                )

            # Output layers
            self.output_proj = nn.Sequential(
                nn.Linear(config.hidden_dim, config.hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.dropout),
                nn.Linear(config.hidden_dim, config.output_dim)
            )

            # Classification head
            self.classifier = nn.Sequential(
                nn.Linear(config.output_dim, config.hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.dropout),
                nn.Linear(config.hidden_dim, config.num_type_classes)
            )

        def forward(self, x, edge_index, batch=None):
            """
            Forward pass.

            Args:
                x: Node features [num_nodes, input_dim]
                edge_index: Edge indices [2, num_edges]
                batch: Batch assignment [num_nodes]

            Returns:
                Node embeddings and type predictions
            """
            # Input projection
            h = self.input_proj(x)
            h = torch.relu(h)

            # GNN layers
            for gnn_layer in self.gnn_layers:
                h = gnn_layer(h, edge_index)
                h = torch.relu(h)

            # Output embedding
            embeddings = self.output_proj(h)

            # Type classification
            logits = self.classifier(embeddings)

            return embeddings, logits

        def predict_types(self, x, edge_index, batch=None):
            """
            Predict types for nodes.

            Args:
                x: Node features
                edge_index: Edge indices
                batch: Batch assignment

            Returns:
                Predicted type indices and confidence scores
            """
            self.eval()
            with torch.no_grad():
                _, logits = self.forward(x, edge_index, batch)
                probs = torch.softmax(logits, dim=-1)
                predictions = torch.argmax(probs, dim=-1)
                confidence = torch.max(probs, dim=-1).values

            return predictions, confidence

else:
    # Placeholder classes when torch is not available
    class TypeGNN:
        """Placeholder when torch is not available."""
        def __init__(self, config):
            self.config = config
            logger.warning("TypeGNN created but PyTorch is not available")

        def forward(self, x, edge_index, batch=None):
            raise RuntimeError("PyTorch is not available")

        def predict_types(self, x, edge_index, batch=None):
            raise RuntimeError("PyTorch is not available")


# Type class mapping
TYPE_CLASSES = {
    0: 'void',
    1: 'i8',
    2: 'i16',
    3: 'i32',
    4: 'i64',
    5: 'u8',
    6: 'u16',
    7: 'u32',
    8: 'u64',
    9: 'f32',
    10: 'f64',
    11: 'pointer',
    12: 'array',
    13: 'struct',
    14: 'char',
    15: 'bool',
    16: 'func_ptr',
    17: 'string',
    18: 'buffer',
    19: 'unknown',
}


def create_model(config: Optional[TypeGNNConfig] = None) -> TypeGNN:
    """
    Create a TypeGNN model.

    Args:
        config: Model configuration

    Returns:
        TypeGNN model
    """
    if config is None:
        config = TypeGNNConfig()

    return TypeGNN(config)


def load_model(model_path: str) -> TypeGNN:
    """
    Load a trained model from file.

    Args:
        model_path: Path to model file

    Returns:
        Loaded model
    """
    if not HAS_TORCH:
        raise RuntimeError("PyTorch is not available")

    logger.info(f"Loading model from: {model_path}")

    checkpoint = torch.load(model_path, map_location='cpu')
    config = TypeGNNConfig(**checkpoint['config'])
    model = TypeGNN(config)
    model.load_state_dict(checkpoint['model_state_dict'])

    logger.info("Model loaded successfully")
    return model


def save_model(model: TypeGNN, model_path: str):
    """
    Save a model to file.

    Args:
        model: Model to save
        model_path: Path to save model
    """
    if not HAS_TORCH:
        raise RuntimeError("PyTorch is not available")

    logger.info(f"Saving model to: {model_path}")

    checkpoint = {
        'config': {
            'input_dim': model.config.input_dim,
            'hidden_dim': model.config.hidden_dim,
            'output_dim': model.config.output_dim,
            'num_layers': model.config.num_layers,
            'num_heads': model.config.num_heads,
            'num_type_classes': model.config.num_type_classes,
        },
        'model_state_dict': model.state_dict(),
    }

    torch.save(checkpoint, model_path)
    logger.info("Model saved successfully")


def train_model(
    model: TypeGNN,
    train_data: List[Any],
    val_data: Optional[List[Any]] = None,
    config: Optional[TypeGNNConfig] = None
) -> Dict[str, List[float]]:
    """
    Train the model.

    Args:
        model: Model to train
        train_data: Training data
        val_data: Validation data
        config: Training configuration

    Returns:
        Training history
    """
    if not HAS_TORCH:
        raise RuntimeError("PyTorch is not available")

    if config is None:
        config = model.config

    optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate)
    criterion = nn.CrossEntropyLoss()

    history = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
    }

    for epoch in range(config.epochs):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for batch in train_data:
            x, edge_index, y = batch
            optimizer.zero_grad()

            _, logits = model(x, edge_index)
            loss = criterion(logits, y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            predictions = torch.argmax(logits, dim=-1)
            train_correct += (predictions == y).sum().item()
            train_total += y.size(0)

        train_loss /= len(train_data)
        train_acc = train_correct / train_total if train_total > 0 else 0

        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)

        # Validation
        if val_data:
            model.eval()
            val_loss = 0.0
            val_correct = 0
            val_total = 0

            with torch.no_grad():
                for batch in val_data:
                    x, edge_index, y = batch
                    _, logits = model(x, edge_index)
                    loss = criterion(logits, y)

                    val_loss += loss.item()
                    predictions = torch.argmax(logits, dim=-1)
                    val_correct += (predictions == y).sum().item()
                    val_total += y.size(0)

            val_loss /= len(val_data)
            val_acc = val_correct / val_total if val_total > 0 else 0

            history['val_loss'].append(val_loss)
            history['val_acc'].append(val_acc)

            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{config.epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}, "
                          f"val_loss={val_loss:.4f}, val_acc={val_acc:.4f}")
        else:
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{config.epochs}: "
                          f"train_loss={train_loss:.4f}, train_acc={train_acc:.4f}")

    return history
