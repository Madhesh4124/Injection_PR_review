"""Strict Pydantic v2 models for PR review evaluation fixtures."""

import re
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.schemas.manifest import GroundTruthManifest

FIXTURE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")
DISALLOWED_SHELL_CHARS = re.compile(r"[\r\n;&|><$`\\]")


class ScenarioCategory(str, Enum):
    """Scenario category for development and benchmark evaluation cases."""

    BASE = "base"
    TWIN = "twin"
    CLEAN = "clean"
    HARD_NEGATIVE = "hard_negative"
    CANARY = "canary"
    ACCESS_PROBE = "access_probe"


class FixtureMetadata(BaseModel):
    """Metadata describing fixture lineage and domain context."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    title: str = Field(description="Descriptive title of the scenario.")
    author: Optional[str] = Field(default=None, description="Author or generator identity.")
    tags: List[str] = Field(default_factory=list, description="Categorization tags.")
    base_fixture_id: Optional[str] = Field(
        default=None,
        description="Associated base fixture ID if this scenario is an injected twin.",
    )
    extra_context: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional arbitrary string annotations for provenance.",
    )


class ExpectedSecurityBehaviors(BaseModel):
    """Expected security boundary behaviors and telemetry flags for testing."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    expect_differential_suppression: bool = Field(
        default=False,
        description="Whether adversarial instructions are expected to cause differential suppression.",
    )
    expected_blocked_access_types: List[str] = Field(
        default_factory=list,
        description="Expected blocked access probe types (e.g., 'env_read', 'traversal', 'symlink_escape').",
    )
    canary_forms_planted: List[str] = Field(
        default_factory=list,
        description="Planted canary encodings (e.g., 'raw', 'base64', 'hex', 'concatenated').",
    )


class FixtureDefinition(BaseModel):
    """Complete specification of an evaluation or development fixture."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    fixture_id: str = Field(
        description="Unique alphanumeric identifier (e.g. 'dev-base-01', 'frozen-twin-05')."
    )
    base_snapshot_id: str = Field(
        description="Immutable base git tree SHA or snapshot identifier."
    )
    patch_content: str = Field(
        description="Unified diff patch representing the proposed PR changes."
    )
    pr_description: str = Field(
        description="Untrusted user-supplied PR description."
    )
    scenario_category: ScenarioCategory = Field(
        description="Evaluation scenario category."
    )
    manifest: GroundTruthManifest = Field(
        description="Ground-truth manifest defining planted bugs, injections, and probes."
    )
    metadata: FixtureMetadata = Field(
        default_factory=lambda: FixtureMetadata(title="Untitled Fixture"),
        description="Provenance and lineage metadata.",
    )
    expected_behaviors: ExpectedSecurityBehaviors = Field(
        default_factory=ExpectedSecurityBehaviors,
        description="Security defense telemetry expectations.",
    )
    permitted_test_commands: List[str] = Field(
        default_factory=lambda: ["pytest"],
        description="Strict allowlist of permitted fixed test commands in sandbox.",
    )

    @field_validator("fixture_id")
    @classmethod
    def validate_fixture_id_format(cls, value: str) -> str:
        if not FIXTURE_ID_PATTERN.match(value):
            raise ValueError(
                f"fixture_id must match {FIXTURE_ID_PATTERN.pattern}, got '{value}'"
            )
        return value

    @field_validator("permitted_test_commands")
    @classmethod
    def validate_test_commands(cls, commands: List[str]) -> List[str]:
        if not commands:
            raise ValueError("permitted_test_commands cannot be empty.")
        for cmd in commands:
            cmd_clean = cmd.strip()
            if not cmd_clean:
                raise ValueError("Permitted test command cannot be empty.")
            if DISALLOWED_SHELL_CHARS.search(cmd_clean):
                raise ValueError(
                    f"Permitted test command contains forbidden shell metacharacters: '{cmd_clean}'"
                )
            # Allowlist command prefixes (pytest, python -m unittest, python -m pytest)
            valid_prefixes = ("pytest", "python -m pytest", "python -m unittest", "tox")
            if not any(cmd_clean.startswith(prefix) for prefix in valid_prefixes):
                raise ValueError(
                    f"Permitted test command must start with approved test runner {valid_prefixes}, got '{cmd_clean}'"
                )
        return commands

    @model_validator(mode="after")
    def validate_manifest_fixture_alignment(self) -> "FixtureDefinition":
        """Verify consistency between manifest and fixture definition."""
        if self.manifest.case_id != self.fixture_id:
            raise ValueError(
                f"manifest.case_id ('{self.manifest.case_id}') must match fixture_id ('{self.fixture_id}')"
            )
        if self.manifest.case_type != self.scenario_category.value:
            raise ValueError(
                f"manifest.case_type ('{self.manifest.case_type}') must match scenario_category ('{self.scenario_category.value}')"
            )
        return self
