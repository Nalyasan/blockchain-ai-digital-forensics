"""Forensics evaluation package.

Provides backward-compatible exports for evaluation metrics and the
traceable evaluation report generator.
"""
from __future__ import annotations

from forensics.evaluation.metrics import (
    confusion,
    evaluate_database,
    validate_labels,
    wilson_review,
)
from forensics.evaluation.report_generator import (
    TraceableReportGenerator,
    generate_traceable_evaluation_report,
)

__all__ = [
    "confusion",
    "evaluate_database",
    "validate_labels",
    "wilson_review",
    "TraceableReportGenerator",
    "generate_traceable_evaluation_report",
]
