"""Schemas for review findings, scanner findings, and discrepancy tags."""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.schemas.location import Location
from src.schemas.taxonomies import DiscrepancyKind, Severity, SourceView, VulnerabilityCategory


class Finding(BaseModel):
    """Review finding emitted by raw or stripped reviewer subnode."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(description="Run-local stable identifier, e.g. VULN-001.")
    location: Location
    category: VulnerabilityCategory
    severity: Severity
    explanation: str
    evidence: str
    source_view: SourceView = Field(
        description="Review view origin: 'raw', 'stripped', or 'both'."
    )


class ScannerFinding(BaseModel):
    """Deterministic static-analysis scanner finding."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(description="Run-local scanner finding identifier, e.g. SCAN-001.")
    rule_id: str = Field(description="Bandit or Semgrep rule identifier.")
    location: Location
    category: VulnerabilityCategory
    severity: Severity
    evidence: str


class DiscrepancyTag(BaseModel):
    """Differential review discrepancy tag per finding."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(description="Referenced finding identifier.")
    kind: DiscrepancyKind
    line_shift: Optional[int] = Field(
        default=None,
        description="Shift in start line between views, present only when kind is 'matched_shifted'.",
    )
    category_mismatch: Optional[bool] = Field(
        default=None,
        description="Whether category differed, present only when kind is 'matched_shifted'.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Audit explanation for why finding was flagged, shifted, or reclassified.",
    )

    @model_validator(mode="after")
    def validate_shifted_fields(self) -> "DiscrepancyTag":
        """Ensure line_shift and category_mismatch exist if and only if kind is matched_shifted."""
        if self.kind == DiscrepancyKind.MATCHED_SHIFTED:
            if self.line_shift is None:
                raise ValueError("line_shift must be provided when kind is 'matched_shifted'")
            if self.category_mismatch is None:
                raise ValueError("category_mismatch must be provided when kind is 'matched_shifted'")
        else:
            if self.line_shift is not None:
                raise ValueError(
                    f"line_shift must be None when kind is '{self.kind.value}', got {self.line_shift}"
                )
            if self.category_mismatch is not None:
                raise ValueError(
                    f"category_mismatch must be None when kind is '{self.kind.value}', got {self.category_mismatch}"
                )
        return self
