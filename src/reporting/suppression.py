"""Deterministic differential suppression and discrepancy analysis across raw and stripped views."""

from typing import List, Set
from pydantic import BaseModel, ConfigDict, Field

from src.matching.equivalence import are_categories_equivalent
from src.schemas.findings import DiscrepancyTag, Finding
from src.schemas.injections import InjectionRecord
from src.schemas.taxonomies import DiscrepancyKind, SourceView


class SuppressionAnalysisResult(BaseModel):
    """Result of differential review comparison and suppression tagging."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    unified_findings: List[Finding] = Field(
        description="Unified findings across views, with preserved source_view and stripped-only recall candidates.",
    )
    discrepancy_tags: List[DiscrepancyTag] = Field(
        description="Auditable discrepancy tags explaining view differences and suppression flags.",
    )


def match_findings_across_views(
    raw_findings: List[Finding],
    stripped_findings: List[Finding],
    injection_records: List[InjectionRecord],
    line_tolerance: int = 3,
) -> SuppressionAnalysisResult:
    """Deterministically compare findings across raw and stripped views.

    Guarantees:
    - Never allows LLM or injection text to authorize suppression directly.
    - Preserves findings existing only in stripped view as recall candidates.
    - Records explicit audit rationale for all discrepancies and suppression tags.
    """
    discrepancy_tags: List[DiscrepancyTag] = []
    unified_findings: List[Finding] = []

    claimed_raw_ids: Set[str] = set()
    claimed_stripped_ids: Set[str] = set()

    has_adversarial_injections = len(injection_records) > 0

    # 1. Match stripped findings against raw findings
    for s_finding in stripped_findings:
        matched_raw: Finding | None = None
        min_distance = line_tolerance + 1

        for r_finding in raw_findings:
            if r_finding.id in claimed_raw_ids:
                continue

            # Path match
            if s_finding.location.path != r_finding.location.path:
                continue

            # Category equivalence
            if not are_categories_equivalent(s_finding.category.value, r_finding.category.value):
                continue

            # Line distance
            dist = abs(s_finding.location.start_line - r_finding.location.start_line)
            if dist <= line_tolerance and dist < min_distance:
                matched_raw = r_finding
                min_distance = dist

        if matched_raw is not None:
            claimed_raw_ids.add(matched_raw.id)
            claimed_stripped_ids.add(s_finding.id)

            line_shift = abs(matched_raw.location.start_line - s_finding.location.start_line)
            cat_mismatch = (matched_raw.category != s_finding.category)

            # Combined finding present in both views
            combined = matched_raw.model_copy(update={"source_view": SourceView.BOTH})
            unified_findings.append(combined)

            if line_shift > 0 or cat_mismatch:
                discrepancy_tags.append(
                    DiscrepancyTag(
                        finding_id=s_finding.id,
                        kind=DiscrepancyKind.MATCHED_SHIFTED,
                        line_shift=line_shift,
                        category_mismatch=cat_mismatch,
                        reason=f"Matched across views with line shift {line_shift} and category mismatch={cat_mismatch}.",
                    )
                )
        else:
            # Finding exists ONLY in stripped view
            claimed_stripped_ids.add(s_finding.id)
            # CRITICAL: Preserve stripped-only finding as an LLM recall candidate!
            unified_findings.append(s_finding)

            # Determine suppression reclassification
            if has_adversarial_injections:
                discrepancy_tags.append(
                    DiscrepancyTag(
                        finding_id=s_finding.id,
                        kind=DiscrepancyKind.SUPPRESSED,
                        reason="Finding was detected in stripped view but absent in raw view where adversarial injection text was identified.",
                    )
                )
            else:
                discrepancy_tags.append(
                    DiscrepancyTag(
                        finding_id=s_finding.id,
                        kind=DiscrepancyKind.STRIPPED_ONLY,
                        reason="Finding appeared in stripped review view only.",
                    )
                )

    # 2. Add remaining raw-only findings
    for r_finding in raw_findings:
        if r_finding.id not in claimed_raw_ids:
            unified_findings.append(r_finding)
            discrepancy_tags.append(
                DiscrepancyTag(
                    finding_id=r_finding.id,
                    kind=DiscrepancyKind.RAW_ONLY,
                    reason="Finding appeared in raw review view only.",
                )
            )

    return SuppressionAnalysisResult(
        unified_findings=unified_findings,
        discrepancy_tags=discrepancy_tags,
    )
