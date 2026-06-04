"""
GNN Attention Report Module

Converts GNN/GAT attention weights into natural language for LLM consumption.
This enables "neuro-symbolic" fusion: GNN provides structural insights,
LLM provides semantic reasoning.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.type_recovery')


@dataclass
class AttentionInsight:
    """Insight from GNN attention analysis."""
    node_id: int
    address: int
    function_name: str
    attention_score: float
    operation: str
    description: str


class AttentionReportGenerator:
    """
    Generates natural language reports from GNN attention weights.
    """

    def __init__(self):
        # Dangerous function patterns
        self.dangerous_funcs = {
            'gets', 'strcpy', 'strcat', 'sprintf', 'system',
            'exec', 'malloc', 'free', 'printf'
        }

    def generate_report(self, cfg: Any, dfg: Any,
                        type_recovery_output: Dict[str, Any] = None) -> str:
        """
        Generate natural language report from graph analysis.

        Args:
            cfg: Control flow graph
            dfg: Data flow graph
            type_recovery_output: Type recovery results

        Returns:
            Natural language report for LLM
        """
        lines = []
        lines.append("## GNN Graph Analysis Report")
        lines.append("")

        # Analyze CFG structure
        if cfg:
            self._analyze_cfg(cfg, lines)

        # Analyze DFG patterns
        if dfg:
            self._analyze_dfg(dfg, lines)

        # Analyze type recovery insights
        if type_recovery_output:
            self._analyze_type_recovery(type_recovery_output, lines)

        return "\n".join(lines)

    def _analyze_cfg(self, cfg: Any, lines: List[str]):
        """Analyze CFG structure."""
        lines.append("### Control Flow Graph Analysis")

        # Find functions with high connectivity
        high_connectivity = []
        for func_name, func in cfg.functions.items():
            if len(func.blocks) > 3:
                high_connectivity.append((func_name, len(func.blocks)))

        high_connectivity.sort(key=lambda x: x[1], reverse=True)

        if high_connectivity:
            lines.append("**High-complexity functions:**")
            for func_name, block_count in high_connectivity[:5]:
                lines.append(f"- {func_name}: {block_count} blocks")

        # Find calls to dangerous functions
        lines.append("")
        lines.append("**Dangerous function calls:**")
        for addr, cs in cfg.call_sites.items() if hasattr(cfg, 'call_sites') else []:
            if cs.callee in self.dangerous_funcs:
                lines.append(f"- {cs.caller} -> {cs.callee} at {hex(addr)}")

        lines.append("")

    def _analyze_dfg(self, dfg: Any, lines: List[str]):
        """Analyze DFG patterns."""
        lines.append("### Data Flow Graph Analysis")

        # Find high-degree nodes (important data flow hubs)
        if hasattr(dfg, 'nodes') and hasattr(dfg, 'successors'):
            high_degree = []
            for node_id, node in dfg.nodes.items():
                out_degree = len(dfg.successors.get(node_id, []))
                in_degree = len(dfg.predecessors.get(node_id, []))
                if out_degree + in_degree > 3:
                    high_degree.append((node_id, out_degree + in_degree, node))

            high_degree.sort(key=lambda x: x[1], reverse=True)

            if high_degree:
                lines.append("**Critical data flow nodes:**")
                for node_id, degree, node in high_degree[:5]:
                    op = node.operation if hasattr(node, 'operation') else 'unknown'
                    lines.append(f"- Node {node_id}: {op} (degree={degree})")

        lines.append("")

    def _analyze_type_recovery(self, type_output: Dict[str, Any], lines: List[str]):
        """Analyze type recovery insights."""
        lines.append("### Type Recovery Insights")

        # Find high-confidence predictions
        high_confidence = []
        for func_name, output in type_output.items():
            if hasattr(output, 'predictions'):
                for pred in output.predictions:
                    if pred.confidence > 0.8:
                        high_confidence.append((pred.variable_name, pred.predicted_type, pred.confidence))

        if high_confidence:
            lines.append("**High-confidence type predictions:**")
            for var_name, type_name, conf in high_confidence[:10]:
                lines.append(f"- {var_name}: {type_name} (confidence={conf:.2f})")

        # Identify pointer types
        pointers = [(v, t, c) for v, t, c in high_confidence if '*' in t or 'pointer' in t.lower()]
        if pointers:
            lines.append("")
            lines.append("**Pointer variables (potential security impact):**")
            for var_name, type_name, conf in pointers:
                lines.append(f"- {var_name}: {type_name}")

        lines.append("")

    def format_for_llm(self, cfg: Any, dfg: Any,
                       type_recovery_output: Dict[str, Any] = None) -> str:
        """
        Format graph analysis as concise context for LLM.

        Args:
            cfg: Control flow graph
            dfg: Data flow graph
            type_recovery_output: Type recovery results

        Returns:
            Concise natural language summary
        """
        report = self.generate_report(cfg, dfg, type_recovery_output)

        # Extract key points only
        key_points = []
        for line in report.split('\n'):
            if line.startswith('-') or line.startswith('**'):
                key_points.append(line.strip())

        # Limit to 10 key points
        return "\n".join(key_points[:10])


def create_attention_report_generator() -> AttentionReportGenerator:
    """Create an attention report generator."""
    return AttentionReportGenerator()
