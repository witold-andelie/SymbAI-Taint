"""
GAT (Graph Attention Network) Model for Type Recovery

Improved version using Graph Attention Networks for better type inference.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger('OPM.type_recovery')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import GATv2Conv, global_mean_pool
    from torch_geometric.data import Data, Batch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch or PyG not available")


@dataclass
class GATConfig:
    """Configuration for GAT model."""
    # Model architecture
    input_dim: int = 64
    hidden_dim: int = 128
    output_dim: int = 32
    num_layers: int = 3
    num_heads: int = 4
    dropout: float = 0.2

    # Training
    learning_rate: float = 0.001
    weight_decay: float = 1e-4
    epochs: int = 100
    batch_size: int = 32

    # Type classes
    num_type_classes: int = 20


if HAS_TORCH:
    class GATTypeRecovery(nn.Module):
        """
        Graph Attention Network for Type Recovery.

        Uses GATv2Conv for better attention mechanism.
        """

        def __init__(self, config: GATConfig):
            super().__init__()
            self.config = config

            # Input projection
            self.input_proj = nn.Sequential(
                nn.Linear(config.input_dim, config.hidden_dim),
                nn.LayerNorm(config.hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.dropout)
            )

            # GAT layers
            self.gat_layers = nn.ModuleList()
            self.layer_norms = nn.ModuleList()

            for i in range(config.num_layers):
                in_channels = config.hidden_dim
                out_channels = config.hidden_dim // config.num_heads

                self.gat_layers.append(
                    GATv2Conv(
                        in_channels=in_channels,
                        out_channels=out_channels,
                        heads=config.num_heads,
                        dropout=config.dropout,
                        add_self_loops=True,
                        bias=True
                    )
                )
                self.layer_norms.append(nn.LayerNorm(config.hidden_dim))

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

            # Confidence head
            self.confidence_head = nn.Sequential(
                nn.Linear(config.output_dim, config.hidden_dim),
                nn.ReLU(),
                nn.Linear(config.hidden_dim, 1),
                nn.Sigmoid()
            )

        def forward(self, x, edge_index, batch=None):
            """
            Forward pass.

            Args:
                x: Node features [num_nodes, input_dim]
                edge_index: Edge indices [2, num_edges]
                batch: Batch assignment [num_nodes]

            Returns:
                node_embeddings, type_logits, confidence_scores
            """
            # Input projection
            h = self.input_proj(x)

            # GAT layers with residual connections
            for i, (gat_layer, layer_norm) in enumerate(zip(self.gat_layers, self.layer_norms)):
                residual = h
                h = gat_layer(h, edge_index)
                h = layer_norm(h + residual)  # Residual connection
                h = F.elu(h)
                h = F.dropout(h, p=self.config.dropout, training=self.training)

            # Output embedding
            embeddings = self.output_proj(h)

            # Type classification
            type_logits = self.classifier(embeddings)

            # Confidence scores
            confidence = self.confidence_head(embeddings)

            return embeddings, type_logits, confidence

        def predict_types(self, x, edge_index, batch=None):
            """
            Predict types for nodes.

            Args:
                x: Node features
                edge_index: Edge indices
                batch: Batch assignment

            Returns:
                predicted_types, confidence_scores
            """
            self.eval()
            with torch.no_grad():
                _, type_logits, confidence = self.forward(x, edge_index, batch)
                type_probs = F.softmax(type_logits, dim=-1)
                predicted_types = torch.argmax(type_probs, dim=-1)

            return predicted_types, confidence.squeeze(-1)

        def get_attention_weights(self, x, edge_index):
            """
            Get attention weights for interpretability.

            Args:
                x: Node features
                edge_index: Edge indices

            Returns:
                List of attention weights per layer
            """
            self.eval()
            attention_weights = []

            with torch.no_grad():
                h = self.input_proj(x)

                for gat_layer in self.gat_layers:
                    # Get attention weights from GAT layer
                    _, (edge_index_out, attention) = gat_layer(
                        h, edge_index, return_attention_weights=True
                    )
                    attention_weights.append(attention)
                    h = gat_layer(h, edge_index)

            return attention_weights


    class TypeRecoveryTrainer:
        """Trainer for the GAT type recovery model."""

        def __init__(self, model: GATTypeRecovery, config: GATConfig):
            self.model = model
            self.config = config
            self.optimizer = torch.optim.Adam(
                model.parameters(),
                lr=config.learning_rate,
                weight_decay=config.weight_decay
            )
            self.criterion = nn.CrossEntropyLoss()
            self.confidence_criterion = nn.BCELoss()

        def train_epoch(self, train_data: List[Data]) -> Dict[str, float]:
            """Train for one epoch."""
            self.model.train()
            total_loss = 0.0
            total_correct = 0
            total_samples = 0

            for data in train_data:
                self.optimizer.zero_grad()

                # Forward pass
                _, type_logits, confidence = self.model(
                    data.x, data.edge_index, data.batch
                )

                # Type prediction loss
                type_loss = self.criterion(type_logits, data.y)

                # Confidence loss (if available)
                if hasattr(data, 'confidence'):
                    confidence_loss = self.confidence_criterion(
                        confidence.squeeze(), data.confidence
                    )
                    loss = type_loss + 0.1 * confidence_loss
                else:
                    loss = type_loss

                # Backward pass
                loss.backward()
                self.optimizer.step()

                # Statistics
                total_loss += loss.item()
                predictions = torch.argmax(type_logits, dim=-1)
                total_correct += (predictions == data.y).sum().item()
                total_samples += len(data.y)

            return {
                'loss': total_loss / len(train_data),
                'accuracy': total_correct / total_samples if total_samples > 0 else 0
            }

        def evaluate(self, val_data: List[Data]) -> Dict[str, float]:
            """Evaluate the model."""
            self.model.eval()
            total_loss = 0.0
            total_correct = 0
            total_samples = 0

            with torch.no_grad():
                for data in val_data:
                    _, type_logits, confidence = self.model(
                        data.x, data.edge_index, data.batch
                    )

                    loss = self.criterion(type_logits, data.y)
                    total_loss += loss.item()

                    predictions = torch.argmax(type_logits, dim=-1)
                    total_correct += (predictions == data.y).sum().item()
                    total_samples += len(data.y)

            return {
                'loss': total_loss / len(val_data),
                'accuracy': total_correct / total_samples if total_samples > 0 else 0
            }

        def train(self, train_data: List[Data], val_data: Optional[List[Data]] = None,
                  epochs: Optional[int] = None) -> Dict[str, List[float]]:
            """Full training loop."""
            if epochs is None:
                epochs = self.config.epochs

            history = {
                'train_loss': [],
                'train_acc': [],
                'val_loss': [],
                'val_acc': []
            }

            for epoch in range(epochs):
                # Train
                train_metrics = self.train_epoch(train_data)
                history['train_loss'].append(train_metrics['loss'])
                history['train_acc'].append(train_metrics['accuracy'])

                # Validate
                if val_data:
                    val_metrics = self.evaluate(val_data)
                    history['val_loss'].append(val_metrics['loss'])
                    history['val_acc'].append(val_metrics['accuracy'])

                    if (epoch + 1) % 10 == 0:
                        logger.info(
                            f"Epoch {epoch+1}/{epochs}: "
                            f"train_loss={train_metrics['loss']:.4f}, "
                            f"train_acc={train_metrics['accuracy']:.4f}, "
                            f"val_loss={val_metrics['loss']:.4f}, "
                            f"val_acc={val_metrics['accuracy']:.4f}"
                        )
                else:
                    if (epoch + 1) % 10 == 0:
                        logger.info(
                            f"Epoch {epoch+1}/{epochs}: "
                            f"train_loss={train_metrics['loss']:.4f}, "
                            f"train_acc={train_metrics['accuracy']:.4f}"
                        )

            return history


def create_gat_model(config: Optional[GATConfig] = None) -> GATTypeRecovery:
    """Create a GAT model."""
    if not HAS_TORCH:
        raise RuntimeError("PyTorch or PyG not available")

    if config is None:
        config = GATConfig()

    return GATTypeRecovery(config)


def save_gat_model(model: GATTypeRecovery, path: str):
    """Save GAT model."""
    torch.save({
        'config': model.config.__dict__,
        'model_state_dict': model.state_dict(),
    }, path)
    logger.info(f"Model saved to {path}")


def load_gat_model(path: str) -> GATTypeRecovery:
    """Load GAT model."""
    checkpoint = torch.load(path, map_location='cpu')
    config = GATConfig(**checkpoint['config'])
    model = GATTypeRecovery(config)
    model.load_state_dict(checkpoint['model_state_dict'])
    logger.info(f"Model loaded from {path}")
    return model
