"""
Learned Taint Propagation

Uses machine learning to improve taint propagation accuracy.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

import numpy as np

logger = logging.getLogger('OPM.taint_analysis')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


@dataclass
class TaintFeature:
    """Features for taint propagation prediction."""
    # Operation features
    op_type: str = ''  # 'assign', 'add', 'call', etc.
    op_size: int = 0

    # Data flow features
    is_memory_op: bool = False
    is_register_op: bool = False
    is_pointer_op: bool = False

    # Type features
    src_type: str = ''
    dst_type: str = ''
    type_match: bool = False

    # Context features
    in_loop: bool = False
    in_conditional: bool = False
    call_depth: int = 0

    def to_tensor(self) -> 'torch.Tensor':
        """Convert to tensor."""
        if not HAS_TORCH:
            raise RuntimeError("PyTorch not available")

        # Encode features
        op_encoding = {
            'assign': 0, 'add': 1, 'sub': 2, 'mul': 3,
            'call': 4, 'return': 5, 'load': 6, 'store': 7
        }

        features = [
            op_encoding.get(self.op_type, 0),
            self.op_size,
            float(self.is_memory_op),
            float(self.is_register_op),
            float(self.is_pointer_op),
            float(self.type_match),
            float(self.in_loop),
            float(self.in_conditional),
            self.call_depth,
        ]

        return torch.tensor(features, dtype=torch.float32)


if HAS_TORCH:
    class TaintPropagationNet(nn.Module):
        """
        Neural network for predicting taint propagation.

        Predicts whether taint propagates through an operation.
        """

        def __init__(self, input_dim: int = 9, hidden_dim: int = 64):
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
            """Forward pass."""
            return self.network(x)

        def predict(self, features: TaintFeature) -> Tuple[bool, float]:
            """
            Predict taint propagation.

            Args:
                features: Taint features

            Returns:
                (propagates, confidence)
            """
            self.eval()
            with torch.no_grad():
                x = features.to_tensor().unsqueeze(0)
                logits = self.forward(x)
                probs = F.softmax(logits, dim=-1)
                propagates = probs[0, 1] > 0.5
                confidence = probs[0, 1].item()

            return propagates, confidence


class LearnedTaintPropagation:
    """
    Taint propagation with learned model.

    Combines rule-based and learned propagation.
    """

    def __init__(self, model_path: Optional[str] = None):
        # Rule-based propagation (fallback)
        self.rule_based_rules = {
            'assign': True,
            'add': True,
            'sub': True,
            'mul': True,
            'div': False,
            'call': True,
            'return': True,
            'load': True,
            'store': True,
        }

        # Learned model
        self.model = None
        if HAS_TORCH and model_path:
            try:
                self.model = TaintPropagationNet()
                self.model.load_state_dict(torch.load(model_path))
                logger.info(f"Loaded learned model from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

    def extract_features(self, operation: Dict[str, Any]) -> TaintFeature:
        """Extract features from an operation."""
        return TaintFeature(
            op_type=operation.get('type', ''),
            op_size=operation.get('size', 0),
            is_memory_op=operation.get('is_memory', False),
            is_register_op=operation.get('is_register', False),
            is_pointer_op=operation.get('is_pointer', False),
            src_type=operation.get('src_type', ''),
            dst_type=operation.get('dst_type', ''),
            type_match=operation.get('src_type', '') == operation.get('dst_type', ''),
            in_loop=operation.get('in_loop', False),
            in_conditional=operation.get('in_conditional', False),
            call_depth=operation.get('call_depth', 0),
        )

    def should_propagate(self, operation: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determine if taint should propagate through an operation.

        Args:
            operation: Operation information

        Returns:
            (should_propagate, confidence)
        """
        # Try learned model first
        if self.model:
            features = self.extract_features(operation)
            propagates, confidence = self.model.predict(features)
            return propagates, confidence

        # Fallback to rule-based
        op_type = operation.get('type', '')
        propagates = self.rule_based_rules.get(op_type, False)
        return propagates, 1.0

    def propagate_taint(
        self,
        taint_state: Dict[str, Any],
        operations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Propagate taint through operations.

        Args:
            taint_state: Current taint state
            operations: List of operations to process

        Returns:
            Updated taint state
        """
        new_taint_state = dict(taint_state)

        for op in operations:
            should_prop, confidence = self.should_propagate(op)

            if should_prop:
                # Get source taint
                src = op.get('src')
                if src and src in taint_state.get('tainted_vars', {}):
                    # Propagate to destination
                    dst = op.get('dst')
                    if dst:
                        if 'tainted_vars' not in new_taint_state:
                            new_taint_state['tainted_vars'] = {}
                        new_taint_state['tainted_vars'][dst] = {
                            'source': taint_state['tainted_vars'][src].get('source'),
                            'confidence': confidence,
                            'propagation_path': taint_state['tainted_vars'][src].get('propagation_path', []) + [op.get('type', '')],
                        }

        return new_taint_state


class TaintPropagationTrainer:
    """Trainer for the taint propagation model."""

    def __init__(self, model: TaintPropagationNet):
        self.model = model
        self.optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        self.criterion = nn.CrossEntropyLoss()

    def train(self, train_data: List[Tuple[TaintFeature, bool]], epochs: int = 50):
        """Train the model."""
        self.model.train()

        for epoch in range(epochs):
            total_loss = 0.0
            total_correct = 0

            for features, label in train_data:
                self.optimizer.zero_grad()

                x = features.to_tensor().unsqueeze(0)
                y = torch.tensor([int(label)], dtype=torch.long)

                logits = self.model(x)
                loss = self.criterion(logits, y)

                loss.backward()
                self.optimizer.step()

                total_loss += loss.item()
                prediction = logits.argmax(dim=1).item()
                total_correct += int(prediction == int(label))

            if (epoch + 1) % 10 == 0:
                accuracy = total_correct / len(train_data) if train_data else 0
                logger.info(f"Epoch {epoch+1}/{epochs}: loss={total_loss/len(train_data):.4f}, acc={accuracy:.4f}")


def create_learned_propagation(model_path: Optional[str] = None) -> LearnedTaintPropagation:
    """Create a learned taint propagation instance."""
    return LearnedTaintPropagation(model_path)
