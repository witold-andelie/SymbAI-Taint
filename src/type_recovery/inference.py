"""
Type Recovery Inference Module

Integrates with TYGR for GNN-based type recovery.
This module provides inference capabilities using trained models.
"""

import os
import sys
import logging
import pickle
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger('OPM.type_recovery')

# Add TYGR to path
TYGR_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'tygr', 'TYGR0')
if os.path.exists(TYGR_PATH):
    sys.path.insert(0, TYGR_PATH)


@dataclass
class TypePrediction:
    """Prediction for a single variable."""
    variable_name: str
    predicted_type: str
    confidence: float
    source: str  # 'gnn', 'heuristic', 'dwarf'
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TypeRecoveryOutput:
    """Output from type recovery."""
    function_name: str
    predictions: List[TypePrediction] = field(default_factory=list)
    # Type hints for the GNN
    variable_types: Dict[str, str] = field(default_factory=dict)
    pointer_labels: Dict[str, bool] = field(default_factory=dict)
    buffer_labels: Dict[str, bool] = field(default_factory=dict)
    function_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)


def recover_types(
    binary_path: str,
    cfg: Any,
    dfg: Any,
    model_path: Optional[str] = None,
    confidence_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Recover types from binary using GNN.

    Args:
        binary_path: Path to the binary
        cfg: Control Flow Graph
        dfg: Data Flow Graph
        model_path: Path to trained GNN model
        confidence_threshold: Minimum confidence for predictions

    Returns:
        Dictionary mapping function names to TypeRecoveryOutput
    """
    logger.info("Starting GNN-based type recovery")

    results = {}

    # 1) Real GNN path: version-adapted TYGR GlowGNN (datagen + trained model).
    try:
        results = _recover_with_gnn(binary_path, model_path, cfg)
        if results:
            logger.info(f"GNN type recovery: {len(results)} functions")
            return results
    except Exception as e:
        logger.warning(f"GNN type recovery unavailable ({e}); falling back")

    # 2) Fallbacks
    try:
        results = _recover_with_tygr(binary_path, model_path, confidence_threshold)
    except Exception as e:
        logger.warning(f"TYGR not available, using heuristic fallback: {e}")
        results = _recover_with_heuristics(binary_path, cfg, dfg)

    logger.info(f"Type recovery complete: {len(results)} functions")
    return results


# Vendored (gitignored) TYGR and the GlowGNN model used for type recovery.
_TYGR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tygr_original'))
# Official TYGR model (trained on the real TYDA dataset) — far richer types (char*, f32*, ...)
# than our synthetic fallback. Requires the version-faithful `tygr-orig` env (torch1.8/PyG1.7,
# angr/pyvex 9.0.7491). Override the env's python via the TYGR_PYTHON env var.
_DEFAULT_GNN_MODEL = os.environ.get(
    'TYGR_MODEL',
    os.path.join(_TYGR_DIR, 'model', 'MODEL_base', 'x64.O0.base.model'))
_SYNTHETIC_GNN_MODEL = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'output', 'tygr', 'model_stable.model'))
# Python interpreter of the tygr-orig conda env (must match the official model's versions).
_TYGR_PYTHON = os.environ.get('TYGR_PYTHON', '/root/miniconda3/envs/tygr-orig/bin/python')


def _btype_to_str(btype: Any) -> str:
    """Convert a TYGR btype tuple to a readable OPM type string."""
    try:
        d = dict(btype)
    except Exception:
        return str(btype)
    if 'array' in d:
        return 'array'                 # buffer-like
    if 'pointer' in d or 'ptr' in d:
        inner = d.get('pointer') or d.get('ptr')
        try:
            di = dict(inner)
            if di.get('base') in ('signed_char', 'unsigned_char') or di.get('bitsize') == 8:
                return 'char*'         # string/byte buffer — key taint source/sink
        except Exception:
            pass
        return 'pointer'
    if 'base' in d:
        bits = d.get('bitsize', 0)
        signed = d.get('base') == 'signed'
        return {64: 'int64' if signed else 'uint64',
                32: 'int32' if signed else 'uint32',
                16: 'short', 8: 'char'}.get(bits, f"int{bits}")
    return str(btype)


def _recover_with_gnn(binary_path: str, model_path: Optional[str], cfg: Any) -> Dict[str, Any]:
    """Run the version-adapted TYGR GlowGNN on the binary and map its per-variable type
    predictions into OPM's TypeRecoveryOutput. Requires the binary to carry DWARF
    (TYGR locates variables via DWARF, then the GNN predicts their types)."""
    import subprocess
    import pickle as _pickle

    model = model_path or _DEFAULT_GNN_MODEL
    if not os.path.exists(model):
        raise FileNotFoundError(f"GNN model not found: {model}")
    if not os.path.isdir(_TYGR_DIR):
        raise FileNotFoundError(f"TYGR not found at {_TYGR_DIR}")
    # subprocess runs with cwd=_TYGR_DIR, so the binary path must be absolute.
    binary_path = os.path.abspath(binary_path)
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    out_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'output', 'tygr')
    os.makedirs(out_dir, exist_ok=True)
    out_pkl = os.path.join(out_dir, f"_gnn_pred_{os.getpid()}.pkl")

    # Run in the version-faithful tygr-orig env (its python), not OPM's angr-env.
    py = _TYGR_PYTHON if os.path.exists(_TYGR_PYTHON) else sys.executable
    proc = subprocess.run([py, '-m', 'src.index', 'predict', model, binary_path, out_pkl],
                          cwd=_TYGR_DIR, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not os.path.exists(out_pkl):
        tail = (proc.stderr or proc.stdout or '').strip().splitlines()[-3:]
        raise RuntimeError(f"TYGR predict failed (rc={proc.returncode}): {' | '.join(tail)}")
    with open(out_pkl, 'rb') as f:
        var_dict = _pickle.load(f)
    try:
        os.remove(out_pkl)
    except OSError:
        pass

    # map function low_pc -> function name via the CFG. The GNN's low_pc comes from DWARF
    # (file vaddr, e.g. 0x1149) while angr rebases PIE binaries at mapped_base, so we key by
    # BOTH the absolute address and the (address - base) offset to bridge the PIE rebase.
    base = 0
    try:
        base = cfg.angr_cfg.project.loader.main_object.mapped_base
    except Exception:
        base = 0
    addr_to_name = {}
    if cfg is not None and hasattr(cfg, 'functions'):
        for name, func in cfg.functions.items():
            addr = getattr(func, 'address', None)
            if addr is not None:
                addr_to_name[addr] = name
                addr_to_name[addr - base] = name

    results: Dict[str, Any] = {}
    for low_pc, loc_dict in var_dict.items():
        fname = addr_to_name.get(low_pc, f"func_{hex(low_pc)}")
        preds = []
        for loc, pred_set in loc_dict.items():
            vname = f"{loc[0]}_{loc[1]}"
            for tup in pred_set:
                btype = tup[2] if isinstance(tup, (tuple, list)) and len(tup) >= 3 else tup
                tystr = _btype_to_str(btype)
                preds.append(TypePrediction(variable_name=vname, predicted_type=tystr,
                                            confidence=0.9, source='gnn',
                                            details={'location': loc}))
        if not preds:
            continue
        results[fname] = TypeRecoveryOutput(
            function_name=fname,
            predictions=preds,
            variable_types={p.variable_name: p.predicted_type for p in preds},
            confidence_scores={p.variable_name: p.confidence for p in preds},
            pointer_labels={p.variable_name: (p.predicted_type in ('pointer', 'char*')) for p in preds},
            buffer_labels={p.variable_name: (p.predicted_type in ('array', 'pointer', 'char*')) for p in preds},
        )
    return results


def _recover_with_tygr(
    binary_path: str,
    model_path: Optional[str],
    confidence_threshold: float
) -> Dict[str, Any]:
    """Recover types using TYGR."""
    logger.info("Using TYGR for type recovery")

    # Import TYGR modules
    try:
        from datagen0.datagen import generate_glow_dataset_no_parallel, Options
        from datagen0.common import GlowInput, GlowOutput
    except ImportError as e:
        raise ImportError(f"TYGR modules not available: {e}")

    # Run TYGR data generation
    options = Options(verbose=False)
    results = {}

    for glow_input, glow_output in generate_glow_dataset_no_parallel(binary_path, './', options):
        func_name = glow_input.function_name

        # Convert TYGR output to our format
        predictions = []
        for var, ty in zip(glow_input.vars, glow_output.types):
            pred = TypePrediction(
                variable_name=var.name,
                predicted_type=str(ty),
                confidence=1.0,  # TYGR uses ground truth during generation
                source='dwarf',
                details={
                    'nodes': var.nodes,
                    'locations': var.locs,
                }
            )
            predictions.append(pred)

        output = TypeRecoveryOutput(
            function_name=func_name,
            predictions=predictions,
            variable_types={p.variable_name: p.predicted_type for p in predictions},
            confidence_scores={p.variable_name: p.confidence for p in predictions},
        )

        results[func_name] = output

    return results


def _recover_with_heuristics(
    binary_path: str,
    cfg: Any,
    dfg: Any
) -> Dict[str, Any]:
    """Recover types using heuristics (fallback)."""
    logger.info("Using heuristic type recovery")

    results = {}

    # Analyze each function
    for func_name, func in cfg.functions.items():
        predictions = []

        # Analyze register usage patterns
        for block in func.blocks:
            # Look for patterns that indicate types
            for pred_node_id in dfg.predecessors.get(block.address, []):
                pred_node = dfg.get_node(pred_node_id)
                if pred_node is None:
                    continue

                # Check for pointer patterns
                if pred_node.operation == 'memory_read' or pred_node.operation == 'memory_write':
                    # Likely a pointer
                    if pred_node.operand:
                        pred = TypePrediction(
                            variable_name=pred_node.operand,
                            predicted_type='void*',
                            confidence=0.6,
                            source='heuristic',
                            details={'pattern': 'memory_access'}
                        )
                        predictions.append(pred)

                # Check for arithmetic patterns
                if 'binop_' in pred_node.operation:
                    op = pred_node.operation.replace('binop_', '')
                    if op in ['Iop_Add32', 'Iop_Sub32', 'Iop_Mul32']:
                        pred = TypePrediction(
                            variable_name=pred_node.operand or f"var_{pred_node.id}",
                            predicted_type='i32',
                            confidence=0.5,
                            source='heuristic',
                            details={'pattern': 'arithmetic_32bit'}
                        )
                        predictions.append(pred)
                    elif op in ['Iop_Add64', 'Iop_Sub64', 'Iop_Mul64']:
                        pred = TypePrediction(
                            variable_name=pred_node.operand or f"var_{pred_node.id}",
                            predicted_type='i64',
                            confidence=0.5,
                            source='heuristic',
                            details={'pattern': 'arithmetic_64bit'}
                        )
                        predictions.append(pred)

        # Deduplicate predictions
        seen = set()
        unique_predictions = []
        for pred in predictions:
            key = (pred.variable_name, pred.predicted_type)
            if key not in seen:
                seen.add(key)
                unique_predictions.append(pred)

        output = TypeRecoveryOutput(
            function_name=func_name,
            predictions=unique_predictions,
            variable_types={p.variable_name: p.predicted_type for p in unique_predictions},
            confidence_scores={p.variable_name: p.confidence for p in unique_predictions},
        )

        results[func_name] = output

    return results


def recover_function_types(
    binary_path: str,
    function_name: str,
    model_path: Optional[str] = None
) -> Optional[TypeRecoveryOutput]:
    """
    Recover types for a specific function.

    Args:
        binary_path: Path to the binary
        function_name: Name of the function
        model_path: Path to trained model

    Returns:
        TypeRecoveryOutput or None if function not found
    """
    logger.info(f"Recovering types for function: {function_name}")

    try:
        results = _recover_with_tygr(binary_path, model_path, 0.5)
        return results.get(function_name)
    except Exception as e:
        logger.warning(f"TYGR failed: {e}")
        return None


def load_model(model_path: str) -> Any:
    """
    Load a trained GNN model.

    Args:
        model_path: Path to the model file

    Returns:
        Loaded model
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    logger.info(f"Loading model from: {model_path}")

    # Load model based on extension
    ext = Path(model_path).suffix

    if ext == '.pt' or ext == '.pth':
        import torch
        return torch.load(model_path)
    elif ext == '.pkl':
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    else:
        raise ValueError(f"Unsupported model format: {ext}")


def get_type_summary(results: Dict[str, TypeRecoveryOutput]) -> Dict[str, Any]:
    """
    Get summary of type recovery results.

    Args:
        results: Type recovery results

    Returns:
        Summary dictionary
    """
    total_functions = len(results)
    total_variables = 0
    type_counts = {}
    source_counts = {'gnn': 0, 'heuristic': 0, 'dwarf': 0}

    for func_output in results.values():
        total_variables += len(func_output.predictions)
        for pred in func_output.predictions:
            type_counts[pred.predicted_type] = type_counts.get(pred.predicted_type, 0) + 1
            source_counts[pred.source] = source_counts.get(pred.source, 0) + 1

    return {
        'total_functions': total_functions,
        'total_variables': total_variables,
        'type_distribution': type_counts,
        'source_distribution': source_counts,
        'avg_variables_per_function': total_variables / total_functions if total_functions > 0 else 0,
    }


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python inference.py <binary_path> [--model model_path]")
        sys.exit(1)

    binary = sys.argv[1]
    model = None

    if '--model' in sys.argv:
        idx = sys.argv.index('--model')
        if idx + 1 < len(sys.argv):
            model = sys.argv[idx + 1]

    try:
        results = recover_types(binary, None, None, model)

        # Print results
        for func_name, output in results.items():
            print(f"\n{func_name}:")
            for pred in output.predictions:
                print(f"  {pred.variable_name}: {pred.predicted_type} "
                      f"(confidence: {pred.confidence:.2f}, source: {pred.source})")

        # Print summary
        summary = get_type_summary(results)
        print(f"\nSummary:")
        print(f"  Functions: {summary['total_functions']}")
        print(f"  Variables: {summary['total_variables']}")
        print(f"  Type distribution: {summary['type_distribution']}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
