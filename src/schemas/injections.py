"""Schema for structured injection detection records."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.schemas.location import Location
from src.schemas.taxonomies import InjectionType, SourceKind


class DetectionStatus(str, Enum):
    """Classification status for detected injections."""

    SUSPICIOUS = "suspicious"
    CONFIRMED = "confirmed"


class InjectionRecord(BaseModel):
    """Structured record of an identified prompt injection or adversarial instruction.

    Identifies the source channel, location when available, injection class from
    the fixed 4-class taxonomy, concise evidence, confidence, status, and rationale.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(description="Run-local injection record identifier, e.g. INJ-001.")
    source: Optional[SourceKind] = Field(
        default=None,
        description="Source channel where injection was detected (source_file, readme, pr_description).",
    )
    location: Optional[Location] = Field(
        default=None,
        description="Precise location within source file, README, or PR description when available.",
    )
    injection_type: InjectionType = Field(
        description="Exact injection class from the fixed 4-class taxonomy.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Classifier confidence score bounded in [0.0, 1.0].",
    )
    explanation: str = Field(
        description="Technical rationale for flagging the adversarial instruction.",
    )
    evidence: Optional[str] = Field(
        default=None,
        description="Concise excerpt or snippet demonstrating the adversarial injection.",
    )
    status: DetectionStatus = Field(
        default=DetectionStatus.SUSPICIOUS,
        description="Detection status classification (suspicious or confirmed).",
    )

    @model_validator(mode="before")
    @classmethod
    def infer_source_and_validate(cls, data: Any) -> Any:
        if isinstance(data, dict):
            loc = data.get("location")
            src = data.get("source")
            if loc and not src:
                if isinstance(loc, dict) and "source_kind" in loc:
                    data["source"] = loc["source_kind"]
                elif hasattr(loc, "source_kind"):
                    data["source"] = loc.source_kind
            elif src and loc:
                loc_kind = (
                    loc.get("source_kind")
                    if isinstance(loc, dict)
                    else getattr(loc, "source_kind", None)
                )
                if loc_kind:
                    src_val = src.value if hasattr(src, "value") else str(src)
                    loc_val = loc_kind.value if hasattr(loc_kind, "value") else str(loc_kind)
                    # Normalize common model variations to canonical SourceKind
                    if src_val in ("untrusted_raw_diff", "raw_diff", "diff", "code", "file") and loc_val == "source_file":
                        data["source"] = loc_val
                    elif src_val in ("untrusted_pr_description", "pr_description_body", "pr_body") and loc_val == "pr_description":
                        data["source"] = loc_val
                    elif src_val in ("untrusted_readme", "readme_content") and loc_val == "readme":
                        data["source"] = loc_val
                    elif src_val != loc_val:
                        raise ValueError(
                            f"source '{src}' does not match location.source_kind '{loc_kind}'"
                        )
        return data

    @model_validator(mode="after")
    def validate_source_or_location(self) -> "InjectionRecord":
        if self.source is None and self.location is None:
            raise ValueError("At least one of 'source' or 'location' must be provided.")
        if self.source is None and self.location is not None:
            object.__setattr__(self, "source", self.location.source_kind)
        return self
