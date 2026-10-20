"""Typed state contract for LangGraph PR review workflow."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict

from src.detection.canary_telemetry import CanaryExposureSession
from src.schemas.findings import Finding, ScannerFinding
from src.schemas.injections import InjectionRecord
from src.schemas.report import BlockedAccess, FinalReport
from src.scanning.models import ScanResult


class ReviewGraphState(TypedDict, total=False):
    # =========================================================================
    # 1. REQUIRED INVOCATION INPUTS (Immutable across all nodes)
    # =========================================================================
    fixture_id: str
    run_idx: int
    patch_content: str
    pr_description: str
    scenario_category: str
    run_dir: Path
    model_id: str
    benchmark_tag: str
    manifest_planted_bugs: Optional[List[Any]]

    # =========================================================================
    # 2. RUNTIME HANDLES & PASS-THROUGH TELEMETRY (Non-serializable)
    # =========================================================================
    canary_session: Optional[CanaryExposureSession]
    blocked_access: BlockedAccess

    # =========================================================================
    # 3. NODE 1 OUTPUT KEYS (Materialization & Sanitization)
    # =========================================================================
    raw_workspace: Path
    stripped_workspace: Path
    readme_content: Optional[str]
    materialization_success: bool

    # =========================================================================
    # 4. NODE 2 OUTPUT KEYS (Static Analysis Scanners)
    # =========================================================================
    scanner_findings: List[ScannerFinding]
    tool_results: Dict[str, ScanResult]
    all_tools_successful: bool
    any_tool_failed: bool

    # =========================================================================
    # 5. NODE 3 OUTPUT KEYS (Paired Reviewer)
    # =========================================================================
    raw_findings: List[Finding]
    stripped_findings: List[Finding]
    paired_review_complete: bool
    unreviewed_files_truncated: bool

    # =========================================================================
    # 6. NODE 4 OUTPUT KEYS (Structured Injection Detection)
    # =========================================================================
    injection_records: List[InjectionRecord]
    injection_detection_error: Optional[str]

    # =========================================================================
    # 7. CROSS-STAGE PIPELINE ERRORS & INFRASTRUCTURE FLAGS
    # =========================================================================
    infrastructure_failure: bool
    pipeline_errors: List[str]

    # =========================================================================
    # 8. TERMINAL REPORT OUTPUT (Node 5)
    # =========================================================================
    final_report: Optional[FinalReport]
