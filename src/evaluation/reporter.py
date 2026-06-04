"""
Report Generator Module

Implements: TaintTrace + EvaluationMetrics → ReportGeneration → Report
From infra.txt: "Report Generation"

This module generates analysis reports.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.evaluation')


@dataclass
class AnalysisReport:
    """Analysis report."""
    title: str = "OPM Taint Analysis Report"
    timestamp: str = ''
    binary_path: str = ''
    source_path: str = ''

    # Summary
    summary: Dict[str, Any] = field(default_factory=dict)

    # Metrics
    metrics: Dict[str, float] = field(default_factory=dict)

    # Taint traces
    taint_traces: List[Dict[str, Any]] = field(default_factory=list)

    # Type recovery results
    type_recovery: Dict[str, Any] = field(default_factory=dict)

    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'title': self.title,
            'timestamp': self.timestamp,
            'binary_path': self.binary_path,
            'source_path': self.source_path,
            'summary': self.summary,
            'metrics': self.metrics,
            'taint_traces': self.taint_traces,
            'type_recovery': self.type_recovery,
            'errors': self.errors,
            'warnings': self.warnings,
        }


def generate_report(
    taint_trace: List[Dict[str, Any]],
    metrics: Dict[str, float],
    output_dir: str,
    binary_path: str = '',
    source_path: str = '',
    type_recovery: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate analysis report.

    Args:
        taint_trace: Taint traces found
        metrics: Evaluation metrics
        output_dir: Output directory
        binary_path: Path to analyzed binary
        source_path: Path to source code
        type_recovery: Type recovery results

    Returns:
        Report dictionary
    """
    logger.info("Generating analysis report")

    # Create report
    report = AnalysisReport(
        timestamp=datetime.now().isoformat(),
        binary_path=binary_path,
        source_path=source_path,
        metrics=metrics,
        taint_traces=taint_trace,
        type_recovery=type_recovery or {},
    )

    # Generate summary
    report.summary = _generate_summary(taint_trace, metrics)

    # Save report
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, 'analysis_report.json')

    with open(report_path, 'w') as f:
        json.dump(report.to_dict(), f, indent=2)

    # Generate markdown report
    md_path = os.path.join(output_dir, 'analysis_report.md')
    _generate_markdown_report(report, md_path)

    logger.info(f"Report generated: {report_path}")

    return {
        'path': report_path,
        'markdown_path': md_path,
        'summary': report.summary,
    }


def _generate_summary(
    taint_trace: List[Dict[str, Any]],
    metrics: Dict[str, float]
) -> Dict[str, Any]:
    """Generate report summary."""
    # Count vulnerabilities by type
    vuln_types = {}
    for trace in taint_trace:
        vuln_type = trace.get('vulnerability_type', 'unknown')
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

    return {
        'total_traces': len(taint_trace),
        'vulnerable_traces': sum(1 for t in taint_trace if t.get('is_vulnerable')),
        'vulnerability_types': vuln_types,
        'precision': metrics.get('precision', 0),
        'recall': metrics.get('recall', 0),
        'f1_score': metrics.get('f1_score', 0),
    }


def _generate_markdown_report(report: AnalysisReport, output_path: str):
    """Generate markdown report."""
    lines = [
        f"# {report.title}",
        "",
        f"**Generated:** {report.timestamp}",
        "",
        "## Summary",
        "",
        f"- **Binary:** `{report.binary_path}`",
        f"- **Source:** `{report.source_path}`",
        f"- **Total Traces:** {report.summary.get('total_traces', 0)}",
        f"- **Vulnerable Traces:** {report.summary.get('vulnerable_traces', 0)}",
        "",
        "## Evaluation Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Precision | {report.metrics.get('precision', 0):.4f} |",
        f"| Recall | {report.metrics.get('recall', 0):.4f} |",
        f"| F1-Score | {report.metrics.get('f1_score', 0):.4f} |",
        f"| True Positives | {report.metrics.get('true_positives', 0)} |",
        f"| False Positives | {report.metrics.get('false_positives', 0)} |",
        f"| False Negatives | {report.metrics.get('false_negatives', 0)} |",
        "",
        "## Taint Traces",
        "",
    ]

    if report.taint_traces:
        lines.append("| Source | Sink | Vulnerable | Type |")
        lines.append("|--------|------|------------|------|")
        for trace in report.taint_traces:
            source = trace.get('source', 'N/A')
            sink = trace.get('sink', 'N/A')
            vuln = 'Yes' if trace.get('is_vulnerable') else 'No'
            vuln_type = trace.get('vulnerability_type', 'N/A')
            lines.append(f"| {source} | {sink} | {vuln} | {vuln_type} |")
    else:
        lines.append("No taint traces found.")

    lines.extend([
        "",
        "## Type Recovery",
        "",
    ])

    if report.type_recovery:
        lines.append("Type recovery was performed. See detailed results in JSON report.")
    else:
        lines.append("Type recovery was not performed.")

    if report.errors:
        lines.extend([
            "",
            "## Errors",
            "",
        ])
        for error in report.errors:
            lines.append(f"- {error}")

    if report.warnings:
        lines.extend([
            "",
            "## Warnings",
            "",
        ])
        for warning in report.warnings:
            lines.append(f"- {warning}")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


def load_report(report_path: str) -> AnalysisReport:
    """Load report from file."""
    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Report not found: {report_path}")

    with open(report_path, 'r') as f:
        data = json.load(f)

    report = AnalysisReport()
    report.title = data.get('title', '')
    report.timestamp = data.get('timestamp', '')
    report.binary_path = data.get('binary_path', '')
    report.source_path = data.get('source_path', '')
    report.summary = data.get('summary', {})
    report.metrics = data.get('metrics', {})
    report.taint_traces = data.get('taint_traces', [])
    report.type_recovery = data.get('type_recovery', {})
    report.errors = data.get('errors', [])
    report.warnings = data.get('warnings', [])

    return report


def get_report_summary(report: AnalysisReport) -> str:
    """Get formatted report summary."""
    lines = [
        "=" * 50,
        "ANALYSIS REPORT SUMMARY",
        "=" * 50,
        f"Title: {report.title}",
        f"Timestamp: {report.timestamp}",
        f"Binary: {report.binary_path}",
        "-" * 50,
        f"Total Traces: {report.summary.get('total_traces', 0)}",
        f"Vulnerable Traces: {report.summary.get('vulnerable_traces', 0)}",
        "-" * 50,
        f"Precision: {report.metrics.get('precision', 0):.4f}",
        f"Recall: {report.metrics.get('recall', 0):.4f}",
        f"F1-Score: {report.metrics.get('f1_score', 0):.4f}",
        "=" * 50,
    ]
    return '\n'.join(lines)


# Example usage
if __name__ == "__main__":
    print("Report Generator Module")
    print("This module is used as part of the OPM pipeline.")
