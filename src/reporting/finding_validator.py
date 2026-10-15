"""Deterministic validation, normalization, and deduplication of review findings."""

from pathlib import Path
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from src.materialization.path_safety import PathSafetyError, normalize_relative_path
from src.schemas.findings import Finding
from src.schemas.location import Location
from src.schemas.taxonomies import SourceKind, SourceView


class FindingValidationResult(BaseModel):
    """Result of deterministic finding validation and deduplication."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    valid_findings: List[Finding] = Field(default_factory=list)
    rejected_findings: List[Dict[str, str]] = Field(default_factory=list)
    duplicate_finding_ids: List[str] = Field(default_factory=list)


def get_file_line_count(file_path: Path) -> Optional[int]:
    """Read line count of a file on disk, returning None if file is missing or unreadable."""
    if not file_path.exists() or not file_path.is_file():
        return None
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return len(content.splitlines()) or 1
    except OSError:
        return None


def validate_and_normalize_finding(
    finding: Finding,
    workspace_root: Path,
    expected_view: SourceView,
) -> tuple[Optional[Finding], Optional[str]]:
    """Validate a single finding against the authorized workspace view.

    Returns:
        tuple of (normalized_finding, rejection_reason)
    """
    loc = finding.location

    # 1. Validate PR description source kind
    if loc.source_kind == SourceKind.PR_DESCRIPTION:
        if loc.path is not None:
            return None, "PR description location must have path=None."
        norm_loc = Location(
            source_kind=SourceKind.PR_DESCRIPTION,
            path=None,
            start_line=loc.start_line,
            end_line=loc.end_line,
        )
        norm_finding = finding.model_copy(
            update={"location": norm_loc, "source_view": expected_view}
        )
        return norm_finding, None

    # 2. Validate source_file or readme path safety and existence
    if not loc.path or not loc.path.strip():
        return None, "Path is missing for file-based finding."

    try:
        norm_path_str = normalize_relative_path(loc.path)
    except PathSafetyError as err:
        return None, f"Unsafe or escaping path: {err}"

    target_file = (workspace_root / norm_path_str).resolve()
    try:
        target_file.relative_to(workspace_root.resolve())
    except ValueError:
        return None, f"Path '{norm_path_str}' escapes authorized workspace root."

    total_lines = get_file_line_count(target_file)
    if total_lines is None:
        return None, f"Referenced file '{norm_path_str}' does not exist in authorized workspace."

    # 3. Validate line ranges against source view
    if loc.start_line < 1:
        return None, f"start_line ({loc.start_line}) must be >= 1."
    if loc.end_line < loc.start_line:
        return None, f"end_line ({loc.end_line}) cannot be less than start_line ({loc.start_line})."
    if loc.start_line > total_lines:
        return None, (
            f"start_line ({loc.start_line}) exceeds total lines in file '{norm_path_str}' ({total_lines})."
        )
    if loc.end_line > total_lines:
        return None, (
            f"end_line ({loc.end_line}) exceeds total lines in file '{norm_path_str}' ({total_lines})."
        )

    # 4. Construct normalized finding with preserved source_view
    norm_loc = Location(
        source_kind=loc.source_kind,
        path=norm_path_str,
        start_line=loc.start_line,
        end_line=loc.end_line,
    )
    norm_finding = finding.model_copy(
        update={"location": norm_loc, "source_view": expected_view}
    )
    return norm_finding, None


def validate_and_deduplicate_findings(
    findings: List[Finding],
    workspace_root: Path,
    source_view: SourceView,
) -> FindingValidationResult:
    """Validate, normalize, and deduplicate findings from one review view."""
    valid_list: List[Finding] = []
    rejected_list: List[Dict[str, str]] = []
    duplicate_ids: List[str] = []

    # Deduplication key tracking: (path, category, start_line)
    seen_keys: Set[tuple[str, str, int]] = set()

    for finding in findings:
        norm_finding, reject_reason = validate_and_normalize_finding(
            finding, workspace_root, source_view
        )
        if reject_reason:
            rejected_list.append({
                "finding_id": finding.id,
                "reason": reject_reason,
            })
            continue

        assert norm_finding is not None
        dedup_key = (
            norm_finding.location.path or "",
            norm_finding.category.value,
            norm_finding.location.start_line,
        )

        if dedup_key in seen_keys:
            duplicate_ids.append(norm_finding.id)
            continue

        seen_keys.add(dedup_key)
        valid_list.append(norm_finding)

    return FindingValidationResult(
        valid_findings=valid_list,
        rejected_findings=rejected_list,
        duplicate_finding_ids=duplicate_ids,
    )
