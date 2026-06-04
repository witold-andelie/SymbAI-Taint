"""
Type Recovery Dataset Module

Handles dataset preparation for GNN training.
Converts binary analysis data into graph format for PyTorch Geometric.
"""

import os
import logging
import pickle
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

logger = logging.getLogger('OPM.type_recovery')


@dataclass
class GraphData:
    """Graph data for GNN input."""
    node_features: np.ndarray  # Node feature matrix
    edge_index: np.ndarray  # Edge indices (2 x num_edges)
    edge_features: np.ndarray  # Edge feature matrix
    node_labels: np.ndarray  # Node labels (for training)
    num_nodes: int = 0
    num_edges: int = 0


@dataclass
class TypeRecoveryDataset:
    """Dataset for type recovery training."""
    graphs: List[GraphData] = field(default_factory=list)
    labels: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __len__(self):
        return len(self.graphs)

    def __getitem__(self, idx):
        return self.graphs[idx], self.labels[idx]


def prepare_dataset(
    binary_path: str,
    cfg: Any,
    dfg: Any,
    type_recovery_output: Dict[str, Any]
) -> TypeRecoveryDataset:
    """
    Prepare dataset for GNN training.

    Args:
        binary_path: Path to the binary
        cfg: Control Flow Graph
        dfg: Data Flow Graph
        type_recovery_output: Type recovery output with ground truth

    Returns:
        TypeRecoveryDataset ready for training
    """
    logger.info("Preparing dataset for GNN training")

    dataset = TypeRecoveryDataset()

    # Process each function
    for func_name, func_output in type_recovery_output.items():
        # Convert function data to graph format
        graph = _convert_to_graph(func_name, cfg, dfg, func_output)
        if graph is not None:
            dataset.graphs.append(graph)
            dataset.labels.append({
                'function_name': func_name,
                'types': func_output.variable_types,
            })

    dataset.metadata = {
        'binary_path': binary_path,
        'num_graphs': len(dataset.graphs),
        'num_functions': len(type_recovery_output),
    }

    logger.info(f"Dataset prepared: {len(dataset.graphs)} graphs")
    return dataset


def _convert_to_graph(
    func_name: str,
    cfg: Any,
    dfg: Any,
    func_output: Any
) -> Optional[GraphData]:
    """Convert function data to graph format."""
    # Get function from CFG
    func = cfg.functions.get(func_name)
    if func is None:
        return None

    # Collect nodes and edges
    nodes = []
    edges = []
    node_features = []
    edge_features = []

    # Map addresses to node indices
    addr_to_idx = {}

    # Add basic block nodes
    for i, block in enumerate(func.blocks):
        addr_to_idx[block.address] = i

        # Node features: [address, size, num_successors, num_predecessors]
        features = [
            block.address / 0x10000,  # Normalized address
            block.size / 100,  # Normalized size
            len(block.successors) / 10,  # Normalized successor count
            len(block.predecessors) / 10,  # Normalized predecessor count
        ]
        node_features.append(features)
        nodes.append(block.address)

    # Add edges from CFG
    for block in func.blocks:
        src_idx = addr_to_idx.get(block.address)
        if src_idx is None:
            continue

        for succ_addr in block.successors:
            dst_idx = addr_to_idx.get(succ_addr)
            if dst_idx is not None:
                edges.append([src_idx, dst_idx])
                # Edge features: [is_call, is_jump, is_fall_through]
                edge_features.append([0, 1, 0])  # Simplified

    # Add DFG nodes and edges if available
    if dfg is not None:
        # This would add data flow information
        pass

    if len(nodes) == 0:
        return None

    # Convert to numpy arrays
    node_features = np.array(node_features, dtype=np.float32)
    edge_index = np.array(edges, dtype=np.int64).T if edges else np.zeros((2, 0), dtype=np.int64)
    edge_features = np.array(edge_features, dtype=np.float32) if edges else np.zeros((0, 3), dtype=np.float32)

    # Create node labels (for training)
    node_labels = np.zeros(len(nodes), dtype=np.int64)
    # This would be filled with actual type labels during training

    return GraphData(
        node_features=node_features,
        edge_index=edge_index,
        edge_features=edge_features,
        node_labels=node_labels,
        num_nodes=len(nodes),
        num_edges=len(edges),
    )


def save_dataset(dataset: TypeRecoveryDataset, output_path: str):
    """Save dataset to file."""
    logger.info(f"Saving dataset to: {output_path}")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'wb') as f:
        pickle.dump(dataset, f)

    logger.info(f"Dataset saved: {len(dataset.graphs)} graphs")


def load_dataset(input_path: str) -> TypeRecoveryDataset:
    """Load dataset from file."""
    logger.info(f"Loading dataset from: {input_path}")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Dataset not found: {input_path}")

    with open(input_path, 'rb') as f:
        dataset = pickle.load(f)

    logger.info(f"Dataset loaded: {len(dataset.graphs)} graphs")
    return dataset


def convert_to_pytorch_geometric(dataset: TypeRecoveryDataset) -> List[Any]:
    """
    Convert dataset to PyTorch Geometric format.

    Args:
        dataset: TypeRecoveryDataset

    Returns:
        List of PyTorch Geometric Data objects
    """
    try:
        import torch
        from torch_geometric.data import Data
    except ImportError:
        raise ImportError("PyTorch Geometric not installed")

    pyg_data_list = []

    for graph, label in zip(dataset.graphs, dataset.labels):
        # Convert to PyTorch tensors
        x = torch.tensor(graph.node_features, dtype=torch.float)
        edge_index = torch.tensor(graph.edge_index, dtype=torch.long)
        edge_attr = torch.tensor(graph.edge_features, dtype=torch.float)
        y = torch.tensor(graph.node_labels, dtype=torch.long)

        # Create PyG Data object
        data = Data(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            y=y,
            num_nodes=graph.num_nodes,
        )

        # Add metadata
        data.function_name = label.get('function_name', '')

        pyg_data_list.append(data)

    return pyg_data_list


def get_dataset_stats(dataset: TypeRecoveryDataset) -> Dict[str, Any]:
    """Get statistics about the dataset."""
    if len(dataset) == 0:
        return {'num_graphs': 0}

    num_nodes = [g.num_nodes for g in dataset.graphs]
    num_edges = [g.num_edges for g in dataset.graphs]

    return {
        'num_graphs': len(dataset.graphs),
        'avg_nodes': np.mean(num_nodes),
        'max_nodes': np.max(num_nodes),
        'min_nodes': np.min(num_nodes),
        'avg_edges': np.mean(num_edges),
        'max_edges': np.max(num_edges),
        'min_edges': np.min(num_edges),
        'total_nodes': np.sum(num_nodes),
        'total_edges': np.sum(num_edges),
    }


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dataset.py <dataset_path>")
        sys.exit(1)

    dataset_path = sys.argv[1]

    try:
        dataset = load_dataset(dataset_path)
        stats = get_dataset_stats(dataset)

        print(f"Dataset Statistics:")
        print(f"  Graphs: {stats['num_graphs']}")
        print(f"  Avg nodes: {stats.get('avg_nodes', 0):.1f}")
        print(f"  Avg edges: {stats.get('avg_edges', 0):.1f}")
        print(f"  Total nodes: {stats.get('total_nodes', 0)}")
        print(f"  Total edges: {stats.get('total_edges', 0)}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
