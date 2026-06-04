"""
GNN-Based Sink Detector

Uses Graph Neural Networks to detect sink functions instead of rule-based approach.
Reference: VulPathFinder - GNN-powered vulnerability path discovery

This module trains a GNN to identify potential sink functions based on:
1. Call graph context
2. Data flow patterns
3. Function characteristics
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
    from torch_geometric.nn import GCNConv, global_mean_pool
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


@dataclass
class SinkFeatures:
    """Features for sink detection."""
    # Function name features
    func_name: str = ''
    is_library: bool = False
    name_length: int = 0

    # Call context features
    num_callers: int = 0
    num_callees: int = 0
    call_depth: int = 0

    # Data flow features
    num_params: int = 0
    has_pointer_param: bool = False
    has_string_param: bool = False
    returns_pointer: bool = False

    # Usage patterns
    called_with_user_input: bool = False
    called_in_loop: bool = False
    called_with_arithmetic: bool = False

    def to_tensor(self) -> 'torch.Tensor':
        """Convert to tensor."""
        if not HAS_TORCH:
            raise RuntimeError("PyTorch not available")

        features = [
            float(self.is_library),
            self.name_length / 20.0,
            self.num_callers / 10.0,
            self.num_callees / 10.0,
            self.call_depth / 5.0,
            self.num_params / 5.0,
            float(self.has_pointer_param),
            float(self.has_string_param),
            float(self.returns_pointer),
            float(self.called_with_user_input),
            float(self.called_in_loop),
            float(self.called_with_arithmetic),
        ]

        return torch.tensor(features, dtype=torch.float32)


if HAS_TORCH:
    class SinkDetectorGNN(nn.Module):
        """
        GNN for detecting sink functions.

        Uses graph structure and function features to identify potential sinks.
        """

        def __init__(self, input_dim: int = 12, hidden_dim: int = 64, output_dim: int = 2):
            super().__init__()

            # Feature extraction
            self.feature_proj = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            )

            # Graph convolution layers
            self.conv1 = GCNConv(hidden_dim, hidden_dim)
            self.conv2 = GCNConv(hidden_dim, hidden_dim)

            # Classification head
            self.classifier = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(hidden_dim, output_dim)
            )

        def forward(self, x, edge_index, batch=None):
            """
            Forward pass.

            Args:
                x: Node features [num_nodes, input_dim]
                edge_index: Edge indices [2, num_edges]
                batch: Batch assignment

            Returns:
                Classification logits
            """
            # Project features
            h = self.feature_proj(x)

            # Graph convolutions
            h = F.relu(self.conv1(h, edge_index))
            h = F.dropout(h, p=0.2, training=self.training)
            h = F.relu(self.conv2(h, edge_index))

            # Global pooling if batch exists
            if batch is not None:
                h = global_mean_pool(h, batch)

            # Classification
            out = self.classifier(h)

            return out

        def predict_sink(self, features: SinkFeatures, edge_index=None) -> Tuple[bool, float]:
            """
            Predict if a function is a sink.

            Args:
                features: Sink features
                edge_index: Optional edge index for graph context

            Returns:
                (is_sink, confidence)
            """
            self.eval()
            with torch.no_grad():
                x = features.to_tensor().unsqueeze(0)

                # Create dummy edge index if not provided
                if edge_index is None:
                    edge_index = torch.tensor([[0], [0]], dtype=torch.long)

                logits = self.forward(x, edge_index)
                probs = F.softmax(logits, dim=-1)

                is_sink = probs[0, 1] > 0.5
                confidence = probs[0, 1].item()

            return is_sink, confidence


class GNNSinkDetector:
    """
    GNN-based sink detector.

    Combines GNN predictions with rule-based fallback.
    """

    def __init__(self, model_path: Optional[str] = None):
        # Known sinks (rule-based fallback)
        self.known_sinks = {
            'strcpy', 'strncpy', 'strcat', 'strncat',
            'sprintf', 'snprintf', 'printf', 'fprintf',
            'system', 'popen', 'exec', 'execl', 'execlp',
            'malloc', 'calloc', 'realloc', 'free',
            'gets', 'scanf', 'fscanf', 'sscanf',
        }

        # Load GNN model if available
        self.model = None
        if HAS_TORCH and model_path:
            try:
                self.model = self._load_model(model_path)
                logger.info(f"Loaded GNN sink detector from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load GNN model: {e}")

    def _load_model(self, model_path: str) -> SinkDetectorGNN:
        """Load trained GNN model."""
        checkpoint = torch.load(model_path, map_location='cpu')
        model = SinkDetectorGNN(**checkpoint.get('config', {}))
        model.load_state_dict(checkpoint['model_state_dict'])
        return model

    def detect_sinks(self, call_graph: Any, cfg: Any = None) -> List[Dict[str, Any]]:
        """
        Detect sink functions in the binary.

        Args:
            call_graph: Call graph
            cfg: Control flow graph (optional)

        Returns:
            List of detected sinks with confidence scores
        """
        logger.info("Detecting sinks using GNN")

        detected_sinks = []

        # Get all function calls
        if call_graph and hasattr(call_graph, 'call_sites'):
            for addr, call_site in call_graph.call_sites.items():
                callee = call_site.callee if hasattr(call_site, 'callee') else ''
                caller = call_site.caller if hasattr(call_site, 'caller') else ''

                # Extract features
                features = self._extract_features(call_site, call_graph, cfg)

                # Predict using GNN or rule-based
                is_sink, confidence = self._predict_sink(features, callee)

                if is_sink:
                    detected_sinks.append({
                        'function': callee,
                        'caller': caller,
                        'address': addr,
                        'confidence': confidence,
                        'detection_method': 'gnn' if self.model else 'rule',
                    })

        # Deduplicate
        unique_sinks = {}
        for sink in detected_sinks:
            key = (sink['function'], sink['caller'])
            if key not in unique_sinks or sink['confidence'] > unique_sinks[key]['confidence']:
                unique_sinks[key] = sink

        result = list(unique_sinks.values())
        logger.info(f"Detected {len(result)} sinks")

        return result

    def _extract_features(self, call_site: Any, call_graph: Any, cfg: Any = None) -> SinkFeatures:
        """Extract features for a function call."""
        features = SinkFeatures()

        callee = call_site.callee if hasattr(call_site, 'callee') else ''
        caller = call_site.caller if hasattr(call_site, 'caller') else ''

        features.func_name = callee
        features.is_library = callee in self.known_sinks
        features.name_length = len(callee)

        # Call context
        if call_graph and hasattr(call_graph, 'callers'):
            features.num_callers = len(call_graph.callers.get(caller, set()))
            features.num_callees = len(call_graph.callees.get(caller, set()))

        # Check if called with user input (heuristic)
        # This would need more sophisticated analysis in practice
        features.called_with_user_input = self._check_user_input(call_site, call_graph)

        return features

    def _check_user_input(self, call_site: Any, call_graph: Any) -> bool:
        """Check if function is called with user input (heuristic)."""
        # Simple heuristic: check if caller is main or receives argv
        caller = call_site.caller if hasattr(call_site, 'caller') else ''
        return caller == 'main' or 'argv' in str(call_site)

    def _predict_sink(self, features: SinkFeatures, func_name: str) -> Tuple[bool, float]:
        """Predict if a function is a sink."""
        # Rule-based check first
        if func_name in self.known_sinks:
            return True, 1.0

        # GNN prediction if model is available
        if self.model:
            try:
                return self.model.predict_sink(features)
            except Exception as e:
                logger.debug(f"GNN prediction failed: {e}")

        # Default: not a sink
        return False, 0.0

    def is_sink(self, func_name: str) -> bool:
        """Quick check if a function is a known sink."""
        return func_name in self.known_sinks

    def get_sink_type(self, func_name: str) -> str:
        """Get the type of sink vulnerability."""
        sink_types = {
            'strcpy': 'buffer_overflow',
            'strncpy': 'buffer_overflow',
            'strcat': 'buffer_overflow',
            'strncat': 'buffer_overflow',
            'sprintf': 'format_string',
            'snprintf': 'format_string',
            'printf': 'format_string',
            'fprintf': 'format_string',
            'system': 'command_injection',
            'popen': 'command_injection',
            'exec': 'command_injection',
            'execl': 'command_injection',
            'execlp': 'command_injection',
            'malloc': 'memory',
            'calloc': 'memory',
            'realloc': 'memory',
            'free': 'use_after_free',
            'gets': 'buffer_overflow',
            'scanf': 'buffer_overflow',
        }
        return sink_types.get(func_name, 'unknown')


def create_gnn_sink_detector(model_path: Optional[str] = None) -> GNNSinkDetector:
    """Create GNN sink detector."""
    return GNNSinkDetector(model_path)
