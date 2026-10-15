"""Node 5: Reporting, validation, suppression, and canary redaction exports."""

from src.reporting.blocked_access import BlockedAccessCollector, sanitize_blocked_details
from src.reporting.canary_redactor import (
    REDACTED_CANARY_PLACEHOLDER,
    CanaryConfig,
    CanaryRedactor,
)
from src.reporting.finding_validator import (
    FindingValidationResult,
    get_file_line_count,
    validate_and_deduplicate_findings,
    validate_and_normalize_finding,
)
from src.reporting.reporter import Node5Reporter
from src.reporting.suppression import (
    SuppressionAnalysisResult,
    match_findings_across_views,
)

__all__ = [
    "REDACTED_CANARY_PLACEHOLDER",
    "BlockedAccessCollector",
    "CanaryConfig",
    "CanaryRedactor",
    "FindingValidationResult",
    "Node5Reporter",
    "SuppressionAnalysisResult",
    "get_file_line_count",
    "match_findings_across_views",
    "sanitize_blocked_details",
    "validate_and_deduplicate_findings",
    "validate_and_normalize_finding",
]
