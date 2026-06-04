"""
Type Recovery Module (GNN-Based)

Implements: CFG + DFG → GNNSemanticInference → TypeRecoveryOutput
From infra.txt: "GNN-Based Type Recovery (TYGR-style component)"

This module integrates the TYGR component for type recovery.
It uses graph neural networks to predict variable types from binary code.
"""

from .inference import recover_types, recover_function_types
from .dataset import TypeRecoveryDataset, prepare_dataset
from .gnn_model import TypeGNN, TypeGNNConfig, create_model, load_model, save_model
from .gat_model import GATTypeRecovery, GATConfig, create_gat_model, save_gat_model, load_gat_model
