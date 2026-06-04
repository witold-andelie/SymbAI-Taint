"""
Multi-Modal Fusion Module

Implements ORACAL-style multi-modal fusion for binary analysis.
Integrates CFG, DFG, and Call Graph for improved vulnerability detection.

Reference: ORACAL - A Robust and Explainable Multimodal Framework
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

import numpy as np

logger = logging.getLogger('OPM.binary_analysis')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


@dataclass
class MultiModalGraph:
    """Multi-modal graph combining CFG, DFG, and Call Graph."""
    # Node features from different modalities
    cfg_nodes: Dict[int, Any] = field(default_factory=dict)
    dfg_nodes: Dict[int, Any] = field(default_factory=dict)
    call_nodes: Dict[int, Any] = field(default_factory=dict)

    # Edge lists
    cfg_edges: List[Tuple[int, int]] = field(default_factory=list)
    dfg_edges: List[Tuple[int, int]] = field(default_factory=list)
    call_edges: List[Tuple[int, int]] = field(default_factory=list)

    # Node mapping (unified node ID -> original node info)
    node_mapping: Dict[int, Dict[str, Any]] = field(default_factory=dict)

    # Features
    node_features: Optional[np.ndarray] = None
    edge_features: Optional[Dict[str, np.ndarray]] = None


@dataclass
class FusionConfig:
    """Configuration for multi-modal fusion."""
    # Feature dimensions
    cfg_feature_dim: int = 32
    dfg_feature_dim: int = 32
    call_feature_dim: int = 32
    fused_feature_dim: int = 64

    # Fusion strategy
    fusion_method: str = 'attention'  # 'concat', 'add', 'attention'

    # Weights for different modalities
    cfg_weight: float = 1.0
    dfg_weight: float = 1.0
    call_weight: float = 1.0


if HAS_TORCH:
    class AttentionFusion(nn.Module):
        """Attention-based multi-modal fusion."""

        def __init__(self, config: FusionConfig):
            super().__init__()
            self.config = config

            total_dim = (config.cfg_feature_dim +
                        config.dfg_feature_dim +
                        config.call_feature_dim)

            # Attention weights
            self.attention = nn.Sequential(
                nn.Linear(total_dim, total_dim // 2),
                nn.ReLU(),
                nn.Linear(total_dim // 2, 3),  # 3 modalities
                nn.Softmax(dim=-1)
            )

            # Projection layers
            self.cfg_proj = nn.Linear(config.cfg_feature_dim, config.fused_feature_dim)
            self.dfg_proj = nn.Linear(config.dfg_feature_dim, config.fused_feature_dim)
            self.call_proj = nn.Linear(config.call_feature_dim, config.fused_feature_dim)

            # Output projection
            self.output_proj = nn.Linear(config.fused_feature_dim, config.fused_feature_dim)

        def forward(self, cfg_feat, dfg_feat, call_feat):
            """
            Fuse features from different modalities.

            Args:
                cfg_feat: CFG features [batch_size, cfg_dim]
                dfg_feat: DFG features [batch_size, dfg_dim]
                call_feat: Call graph features [batch_size, call_dim]

            Returns:
                Fused features [batch_size, fused_dim]
            """
            # Concatenate for attention
            concat = torch.cat([cfg_feat, dfg_feat, call_feat], dim=-1)

            # Compute attention weights
            attn_weights = self.attention(concat)  # [batch_size, 3]

            # Project each modality
            cfg_proj = self.cfg_proj(cfg_feat)
            dfg_proj = self.dfg_proj(dfg_feat)
            call_proj = self.call_proj(call_feat)

            # Weighted sum
            fused = (attn_weights[:, 0:1] * cfg_proj +
                    attn_weights[:, 1:2] * dfg_proj +
                    attn_weights[:, 2:3] * call_proj)

            # Output projection
            output = self.output_proj(fused)

            return output


class MultiModalFusion:
    """
    Multi-modal fusion for binary analysis.

    Combines information from CFG, DFG, and Call Graph
    for improved vulnerability detection.
    """

    def __init__(self, config: Optional[FusionConfig] = None):
        self.config = config or FusionConfig()

        # Initialize fusion model
        if HAS_TORCH:
            self.fusion_model = AttentionFusion(self.config)
        else:
            self.fusion_model = None

    def build_multimodal_graph(self, cfg: Any, dfg: Any, call_graph: Any) -> MultiModalGraph:
        """
        Build multi-modal graph from CFG, DFG, and Call Graph.

        Args:
            cfg: Control flow graph
            dfg: Data flow graph
            call_graph: Call graph

        Returns:
            Multi-modal graph
        """
        logger.info("Building multi-modal graph")

        mm_graph = MultiModalGraph()

        # Add CFG nodes and edges
        if cfg and hasattr(cfg, 'blocks'):
            for addr, block in cfg.blocks.items():
                mm_graph.cfg_nodes[addr] = {
                    'address': addr,
                    'size': block.size if hasattr(block, 'size') else 0,
                    'num_successors': len(block.successors) if hasattr(block, 'successors') else 0,
                }
                for succ in block.successors if hasattr(block, 'successors') else []:
                    mm_graph.cfg_edges.append((addr, succ))

        # Add DFG nodes and edges
        if dfg and hasattr(dfg, 'nodes'):
            for node_id, node in dfg.nodes.items():
                mm_graph.dfg_nodes[node_id] = {
                    'id': node_id,
                    'operation': node.operation if hasattr(node, 'operation') else '',
                    'address': node.address if hasattr(node, 'address') else 0,
                }
            for edge in dfg.edges if hasattr(dfg, 'edges') else []:
                if hasattr(edge, 'source') and hasattr(edge, 'target'):
                    mm_graph.dfg_edges.append((edge.source, edge.target))

        # Add Call Graph nodes and edges
        if call_graph and hasattr(call_graph, 'call_sites'):
            for addr, call_site in call_graph.call_sites.items():
                mm_graph.call_nodes[addr] = {
                    'address': addr,
                    'caller': call_site.caller if hasattr(call_site, 'caller') else '',
                    'callee': call_site.callee if hasattr(call_site, 'callee') else '',
                }
                mm_graph.call_edges.append((addr, addr))  # Self-loop for call site

        # Create unified node mapping
        self._create_node_mapping(mm_graph)

        # Extract features
        self._extract_features(mm_graph)

        logger.info(f"Multi-modal graph: {len(mm_graph.node_mapping)} nodes")
        return mm_graph

    def _create_node_mapping(self, mm_graph: MultiModalGraph):
        """Create unified node mapping."""
        unified_id = 0

        # Map CFG nodes
        for addr in mm_graph.cfg_nodes:
            mm_graph.node_mapping[unified_id] = {
                'type': 'cfg',
                'address': addr,
                'original_id': addr,
            }
            unified_id += 1

        # Map DFG nodes
        for node_id in mm_graph.dfg_nodes:
            mm_graph.node_mapping[unified_id] = {
                'type': 'dfg',
                'original_id': node_id,
            }
            unified_id += 1

        # Map Call Graph nodes
        for addr in mm_graph.call_nodes:
            mm_graph.node_mapping[unified_id] = {
                'type': 'call',
                'address': addr,
                'original_id': addr,
            }
            unified_id += 1

    def _extract_features(self, mm_graph: MultiModalGraph):
        """Extract features for each modality."""
        num_nodes = len(mm_graph.node_mapping)

        # CFG features
        cfg_features = np.zeros((num_nodes, self.config.cfg_feature_dim))
        for i, (node_id, node_info) in enumerate(mm_graph.node_mapping.items()):
            if node_info['type'] == 'cfg':
                addr = node_info.get('address', 0)
                cfg_node = mm_graph.cfg_nodes.get(addr, {})
                # Basic features: address normalized, size, successors
                cfg_features[i, 0] = addr / 0x10000  # Normalized address
                cfg_features[i, 1] = cfg_node.get('size', 0) / 100
                cfg_features[i, 2] = cfg_node.get('num_successors', 0) / 10

        # DFG features
        dfg_features = np.zeros((num_nodes, self.config.dfg_feature_dim))
        for i, (node_id, node_info) in enumerate(mm_graph.node_mapping.items()):
            if node_info['type'] == 'dfg':
                orig_id = node_info.get('original_id', 0)
                dfg_node = mm_graph.dfg_nodes.get(orig_id, {})
                # Operation encoding
                op = dfg_node.get('operation', '')
                op_encoding = {
                    'register_read': 0, 'register_write': 1,
                    'memory_read': 2, 'memory_write': 3,
                    'constant': 4, 'binop': 5,
                }
                dfg_features[i, 0] = op_encoding.get(op, 6)

        # Call graph features
        call_features = np.zeros((num_nodes, self.config.call_feature_dim))
        for i, (node_id, node_info) in enumerate(mm_graph.node_mapping.items()):
            if node_info['type'] == 'call':
                addr = node_info.get('address', 0)
                call_node = mm_graph.call_nodes.get(addr, {})
                # Caller/callee encoding
                caller = call_node.get('caller', '')
                callee = call_node.get('callee', '')
                # Is library call?
                lib_funcs = {'printf', 'scanf', 'strcpy', 'malloc', 'free', 'system'}
                call_features[i, 0] = 1.0 if callee in lib_funcs else 0.0

        mm_graph.node_features = np.concatenate([cfg_features, dfg_features, call_features], axis=1)

    def fuse(self, mm_graph: MultiModalGraph) -> np.ndarray:
        """
        Fuse multi-modal features.

        Args:
            mm_graph: Multi-modal graph

        Returns:
            Fused node features
        """
        if not HAS_TORCH or self.fusion_model is None:
            # Fallback: simple concatenation
            return mm_graph.node_features

        # Convert to tensors
        num_nodes = len(mm_graph.node_mapping)
        cfg_feat = torch.tensor(mm_graph.node_features[:, :self.config.cfg_feature_dim], dtype=torch.float32)
        dfg_feat = torch.tensor(mm_graph.node_features[:, self.config.cfg_feature_dim:
                                                        self.config.cfg_feature_dim + self.config.dfg_feature_dim],
                               dtype=torch.float32)
        call_feat = torch.tensor(mm_graph.node_features[:, -self.config.call_feature_dim:], dtype=torch.float32)

        # Fuse
        with torch.no_grad():
            fused = self.fusion_model(cfg_feat, dfg_feat, call_feat)

        return fused.numpy()

    def get_vulnerability_score(self, mm_graph: MultiModalGraph,
                                 node_id: int, context: Dict[str, Any]) -> float:
        """
        Calculate vulnerability score for a node.

        Args:
            mm_graph: Multi-modal graph
            node_id: Node ID
            context: Analysis context

        Returns:
            Vulnerability score
        """
        score = 0.0

        node_info = mm_graph.node_mapping.get(node_id, {})
        node_type = node_info.get('type', '')

        # CFG-based scoring
        if node_type == 'cfg':
            addr = node_info.get('address', 0)
            cfg_node = mm_graph.cfg_nodes.get(addr, {})
            # More successors = more complex = higher risk
            score += cfg_node.get('num_successors', 0) * 2.0

        # DFG-based scoring
        if node_type == 'dfg':
            orig_id = node_info.get('original_id', 0)
            dfg_node = mm_graph.dfg_nodes.get(orig_id, {})
            op = dfg_node.get('operation', '')
            # Memory operations are riskier
            if 'memory' in op:
                score += 5.0

        # Call graph-based scoring
        if node_type == 'call':
            addr = node_info.get('address', 0)
            call_node = mm_graph.call_nodes.get(addr, {})
            callee = call_node.get('callee', '')
            # Dangerous functions
            dangerous_funcs = {'strcpy', 'sprintf', 'system', 'gets', 'exec'}
            if callee in dangerous_funcs:
                score += 10.0

        return score


def create_multimodal_fusion(config: Optional[FusionConfig] = None) -> MultiModalFusion:
    """Create multi-modal fusion instance."""
    return MultiModalFusion(config)
