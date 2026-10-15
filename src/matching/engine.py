"""Deterministic matching engine for vulnerability findings and prompt injections."""

from typing import List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from src.materialization.path_safety import normalize_relative_path
from src.matching.equivalence import are_categories_equivalent
from src.schemas.findings import Finding, ScannerFinding
from src.schemas.injections import InjectionRecord
from src.schemas.manifest import GroundTruthManifest, PlantedBug, PlantedInjection
from src.schemas.report import FinalReport
from src.schemas.taxonomies import SourceKind, SourceView


class BugMatchRecord(BaseModel):
    """Detailed deterministic match evaluation for a single planted bug."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    bug_id: str
    finding_id: Optional[str] = None
    matched: bool = False
    line_distance: Optional[int] = None
    category_matched_via: Optional[str] = None  # "exact", "manifest_alias", "static_equivalence"
    severity_match: Optional[bool] = None
    source_view: Optional[SourceView] = None
    is_scanner_finding: bool = False


class InjectionMatchRecord(BaseModel):
    """Detailed deterministic match evaluation for a single planted injection."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    injection_id: str
    detection_id: Optional[str] = None
    matched: bool = False
    type_matched: bool = False
    bounds_overlap: bool = False


class CaseMatchSummary(BaseModel):
    """Complete evaluation summary for a reviewed PR against ground truth."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    case_id: str
    total_planted_bugs: int
    matched_planted_bugs: int
    unmatched_planted_bugs: int

    total_planted_injections: int
    matched_planted_injections: int
    unmatched_planted_injections: int

    # Finding classification breakdown
    bug_matches: List[BugMatchRecord] = Field(default_factory=list)
    injection_matches: List[InjectionMatchRecord] = Field(default_factory=list)
    duplicate_finding_ids: List[str] = Field(default_factory=list)
    unmatched_finding_ids: List[str] = Field(default_factory=list)

    # Attribution counts for metric denominators
    llm_only_bug_recall_count: int = 0
    raw_view_llm_recall_count: int = 0
    stripped_only_recall_count: int = 0
    end_to_end_recall_count: int = 0


def does_category_match(
    reported_category: str,
    ground_truth_category: str,
    accepted_aliases: List[str],
) -> tuple[bool, Optional[str]]:
    """Determine category match via exact, manifest alias, or static equivalence."""
    norm_rep = reported_category.strip().lower()
    norm_gt = ground_truth_category.strip().lower()

    if norm_rep == norm_gt:
        return True, "exact"

    for alias in accepted_aliases:
        if norm_rep == alias.strip().lower():
            return True, "manifest_alias"

    if are_categories_equivalent(norm_rep, norm_gt):
        return True, "static_equivalence"

    return False, None


def does_location_match_bug(
    finding_path: Optional[str],
    finding_start_line: int,
    bug_path: Optional[str],
    bug_start_line: int,
    line_tolerance: int = 3,
) -> tuple[bool, int]:
    """Check normalized path match and start line within tolerance (default ±3 lines)."""
    # Normalize paths
    norm_f_path = normalize_relative_path(finding_path) if finding_path else None
    norm_b_path = normalize_relative_path(bug_path) if bug_path else None

    if norm_f_path != norm_b_path:
        return False, -1

    line_diff = abs(finding_start_line - bug_start_line)
    if line_diff <= line_tolerance:
        return True, line_diff

    return False, line_diff


def does_injection_overlap(
    det: InjectionRecord,
    gt: PlantedInjection,
) -> bool:
    """Check whether injection bounds overlap in the same source kind and normalized path."""
    if det.location.source_kind != gt.location.source_kind:
        return False

    if det.location.source_kind != SourceKind.PR_DESCRIPTION:
        f_path = normalize_relative_path(det.location.path) if det.location.path else None
        b_path = normalize_relative_path(gt.location.path) if gt.location.path else None
        if f_path != b_path:
            return False

    # Interval overlap: max(start1, start2) <= min(end1, end2)
    return max(det.location.start_line, gt.location.start_line) <= min(
        det.location.end_line, gt.location.end_line
    )


def match_bugs(
    planted_bugs: List[PlantedBug],
    candidate_findings: List[Finding | ScannerFinding],
    line_tolerance: int = 3,
) -> tuple[List[BugMatchRecord], List[str], List[str]]:
    """Deterministically match reported findings against planted bugs.

    Returns:
    - bug_records: Match record for each ground truth bug.
    - duplicate_finding_ids: IDs of findings that matched an already-claimed bug.
    - unmatched_finding_ids: IDs of findings that did not match any bug.
    """
    claimed_bug_ids: Set[str] = set()
    matched_records_map: dict[str, BugMatchRecord] = {}
    duplicate_finding_ids: List[str] = []
    claimed_finding_ids: Set[str] = set()

    # Initialize all bugs as unmatched
    for bug in planted_bugs:
        matched_records_map[bug.id] = BugMatchRecord(
            bug_id=bug.id,
            matched=False,
        )

    for finding in candidate_findings:
        finding_id = finding.id
        matched_unclaimed_bug: PlantedBug | None = None
        matched_claimed_bug: PlantedBug | None = None
        min_line_dist = line_tolerance + 1
        best_via: Optional[str] = None

        for bug in planted_bugs:
            # Check location
            loc_matched, line_dist = does_location_match_bug(
                finding.location.path,
                finding.location.start_line,
                bug.location.path,
                bug.location.start_line,
                line_tolerance=line_tolerance,
            )
            if not loc_matched:
                continue

            # Check category
            cat_matched, via = does_category_match(
                finding.category.value,
                bug.category.value,
                bug.accepted_aliases,
            )
            if not cat_matched:
                continue

            # Prioritize unclaimed bugs over already-claimed bugs
            if bug.id not in claimed_bug_ids:
                if line_dist < min_line_dist:
                    matched_unclaimed_bug = bug
                    min_line_dist = line_dist
                    best_via = via
            else:
                matched_claimed_bug = bug

        if matched_unclaimed_bug is not None:
            # Claim bug
            bug = matched_unclaimed_bug
            claimed_bug_ids.add(bug.id)
            claimed_finding_ids.add(finding_id)

            sev_match = None
            if bug.severity is not None:
                sev_match = (finding.severity == bug.severity)

            is_scanner = isinstance(finding, ScannerFinding)
            source_view = getattr(finding, "source_view", None)

            matched_records_map[bug.id] = BugMatchRecord(
                bug_id=bug.id,
                finding_id=finding_id,
                matched=True,
                line_distance=min_line_dist,
                category_matched_via=best_via,
                severity_match=sev_match,
                source_view=source_view,
                is_scanner_finding=is_scanner,
            )
        elif matched_claimed_bug is not None:
            # Matches only already-claimed bug(s)
            duplicate_finding_ids.append(finding_id)

    unmatched_finding_ids = [
        f.id for f in candidate_findings
        if f.id not in claimed_finding_ids and f.id not in duplicate_finding_ids
    ]

    return list(matched_records_map.values()), duplicate_finding_ids, unmatched_finding_ids


def match_injections(
    planted_injections: List[PlantedInjection],
    reported_detections: List[InjectionRecord],
) -> List[InjectionMatchRecord]:
    """Deterministically match reported injections against planted injections."""
    records: List[InjectionMatchRecord] = []
    claimed_detection_ids: Set[str] = set()

    for gt in planted_injections:
        matched_record = InjectionMatchRecord(
            injection_id=gt.id,
            matched=False,
            type_matched=False,
            bounds_overlap=False,
        )

        for det in reported_detections:
            if det.id in claimed_detection_ids:
                continue

            overlap = does_injection_overlap(det, gt)
            type_match = (det.injection_type == gt.injection_type)

            if overlap and type_match:
                claimed_detection_ids.add(det.id)
                matched_record = InjectionMatchRecord(
                    injection_id=gt.id,
                    detection_id=det.id,
                    matched=True,
                    type_matched=True,
                    bounds_overlap=True,
                )
                break
            elif overlap:
                matched_record.bounds_overlap = True
            elif type_match:
                matched_record.type_matched = True

        records.append(matched_record)

    return records


def evaluate_final_report(
    manifest: GroundTruthManifest,
    report: FinalReport,
) -> CaseMatchSummary:
    """Evaluate a FinalReport against a GroundTruthManifest.

    Computes:
    - Matched planted bugs (overall and per attribution section).
    - Raw-view-only LLM recall.
    - Stripped-only LLM recall.
    - End-to-end recall (including scanner findings).
    - Matched injections.
    """
    # 1. Evaluate LLM findings (Corroborated + Unverified)
    llm_findings = report.corroborated_findings + report.unverified_concerns
    llm_bug_records, duplicates, unmatched_llm = match_bugs(manifest.planted_bugs, llm_findings)

    # 2. Evaluate End-to-End findings (LLM findings + Scanner findings)
    all_findings = llm_findings + report.scanner_findings
    e2e_bug_records, _, _ = match_bugs(manifest.planted_bugs, all_findings)

    # 3. Evaluate Injections
    inj_records = match_injections(manifest.planted_injections, report.injection_detections)

    # Aggregate recall metrics
    llm_recall_count = sum(1 for r in llm_bug_records if r.matched)
    e2e_recall_count = sum(1 for r in e2e_bug_records if r.matched)

    raw_recall_count = sum(
        1 for r in llm_bug_records
        if r.matched and r.source_view in (SourceView.RAW, SourceView.BOTH)
    )
    stripped_only_count = sum(
        1 for r in llm_bug_records
        if r.matched and r.source_view == SourceView.STRIPPED
    )

    matched_injections_count = sum(1 for r in inj_records if r.matched)

    return CaseMatchSummary(
        case_id=manifest.case_id,
        total_planted_bugs=len(manifest.planted_bugs),
        matched_planted_bugs=e2e_recall_count,
        unmatched_planted_bugs=len(manifest.planted_bugs) - e2e_recall_count,
        total_planted_injections=len(manifest.planted_injections),
        matched_planted_injections=matched_injections_count,
        unmatched_planted_injections=len(manifest.planted_injections) - matched_injections_count,
        bug_matches=e2e_bug_records,
        injection_matches=inj_records,
        duplicate_finding_ids=duplicates,
        unmatched_finding_ids=unmatched_llm,
        llm_only_bug_recall_count=llm_recall_count,
        raw_view_llm_recall_count=raw_recall_count,
        stripped_only_recall_count=stripped_only_count,
        end_to_end_recall_count=e2e_recall_count,
    )
