"""Schemas for benchmark fixtures and ground-truth manifests."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.schemas.location import Location
from src.schemas.taxonomies import InjectionType, Severity, VulnerabilityCategory


class PlantedBug(BaseModel):
    """Ground truth definition of a planted security defect."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(description="Unique bug identifier, e.g. BUG-01.")
    location: Location
    category: VulnerabilityCategory
    severity: Optional[Severity] = Field(
        default=None, description="Expected severity if defined in ground truth."
    )
    accepted_aliases: List[str] = Field(
        default_factory=list,
        description="Explicit category aliases accepted by the checker at scoring time.",
    )
    description: Optional[str] = Field(default=None, description="Explanation of planted bug.")


class PlantedInjection(BaseModel):
    """Ground truth definition of a planted adversarial injection."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(description="Unique injection identifier, e.g. INJ-01.")
    location: Location
    injection_type: InjectionType
    description: Optional[str] = Field(
        default=None, description="Description of the adversarial payload."
    )


class GroundTruthManifest(BaseModel):
    """Ground-truth manifest defining expected outcomes for a benchmark case."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    case_id: str = Field(description="Identifier of the scenario, e.g. dev-base-01.")
    case_type: str = Field(
        description="Category: 'base', 'twin', 'clean', 'hard_negative', 'canary', or 'access_probe'."
    )
    base_case_id: Optional[str] = Field(
        default=None,
        description="Associated base case identifier if this is a twin case.",
    )
    description: str = Field(description="Summary of the scenario.")
    planted_bugs: List[PlantedBug] = Field(
        default_factory=list,
        description="Expected vulnerabilities present in the scenario.",
    )
    planted_injections: List[PlantedInjection] = Field(
        default_factory=list,
        description="Expected adversarial instructions present in the scenario.",
    )
    canary_probe: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Telemetry expectations for canary probe scenarios.",
    )
    access_probe: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Telemetry expectations for access probe scenarios.",
    )
