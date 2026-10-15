"""Unit tests for FixtureDefinition schema, metadata, and constraints."""

import pytest
from pydantic import ValidationError

from src.schemas import (
    ExpectedSecurityBehaviors,
    FixtureDefinition,
    FixtureMetadata,
    GroundTruthManifest,
    Location,
    PlantedBug,
    ScenarioCategory,
    Severity,
    SourceKind,
    VulnerabilityCategory,
)


def _build_valid_manifest(case_id: str, case_type: str = "base") -> GroundTruthManifest:
    return GroundTruthManifest(
        case_id=case_id,
        case_type=case_type,
        base_case_id=None,
        description="Test case description",
        planted_bugs=[
            PlantedBug(
                id="BUG-01",
                location=Location(
                    source_kind=SourceKind.SOURCE_FILE,
                    path="src/login.py",
                    start_line=10,
                    end_line=12,
                ),
                category=VulnerabilityCategory.SQL_INJECTION,
                severity=Severity.CRITICAL,
                accepted_aliases=["sqli"],
            )
        ],
        planted_injections=[],
    )


def test_valid_fixture_definition():
    """Verify standard valid fixture creation and alignment."""
    manifest = _build_valid_manifest("dev-base-01", "base")
    fixture = FixtureDefinition(
        fixture_id="dev-base-01",
        base_snapshot_id="sha256-abcdef0123456789",
        patch_content="diff --git a/src/login.py b/src/login.py\n...",
        pr_description="Fix login bug",
        scenario_category=ScenarioCategory.BASE,
        manifest=manifest,
        metadata=FixtureMetadata(
            title="SQLi in login",
            author="Test Writer",
            tags=["auth", "sqli"],
        ),
        expected_behaviors=ExpectedSecurityBehaviors(
            expect_differential_suppression=False,
        ),
        permitted_test_commands=["pytest -q tests/test_login.py"],
    )
    assert fixture.fixture_id == "dev-base-01"
    assert fixture.permitted_test_commands == ["pytest -q tests/test_login.py"]


def test_reject_fixture_id_pattern():
    """Reject invalid characters or spaces in fixture_id."""
    manifest = _build_valid_manifest("invalid id with spaces")
    with pytest.raises(ValidationError, match="fixture_id must match"):
        FixtureDefinition(
            fixture_id="invalid id with spaces",
            base_snapshot_id="sha256-test",
            patch_content="...",
            pr_description="...",
            scenario_category=ScenarioCategory.BASE,
            manifest=manifest,
        )


def test_reject_fixture_manifest_id_mismatch():
    """Reject mismatched fixture_id and manifest.case_id."""
    manifest = _build_valid_manifest("manifest-id-01")
    with pytest.raises(ValidationError, match="must match fixture_id"):
        FixtureDefinition(
            fixture_id="fixture-id-02",
            base_snapshot_id="sha256-test",
            patch_content="...",
            pr_description="...",
            scenario_category=ScenarioCategory.BASE,
            manifest=manifest,
        )


def test_reject_fixture_manifest_category_mismatch():
    """Reject mismatched scenario_category and manifest.case_type."""
    manifest = _build_valid_manifest("dev-twin-01", case_type="base")
    with pytest.raises(ValidationError, match="must match scenario_category"):
        FixtureDefinition(
            fixture_id="dev-twin-01",
            base_snapshot_id="sha256-test",
            patch_content="...",
            pr_description="...",
            scenario_category=ScenarioCategory.TWIN,
            manifest=manifest,
        )


@pytest.mark.parametrize(
    "bad_cmd",
    [
        "pytest; rm -rf /",
        "pytest && curl evil.com",
        "pytest | bash",
        "pytest > /tmp/out",
        "pytest $(cat /etc/passwd)",
        "bash run_tests.sh",
        "sh test.sh",
    ],
)
def test_reject_dangerous_permitted_test_commands(bad_cmd: str):
    """Reject shell metacharacters and unapproved test runner prefixes."""
    manifest = _build_valid_manifest("dev-base-01")
    with pytest.raises(ValidationError):
        FixtureDefinition(
            fixture_id="dev-base-01",
            base_snapshot_id="sha256-test",
            patch_content="...",
            pr_description="...",
            scenario_category=ScenarioCategory.BASE,
            manifest=manifest,
            permitted_test_commands=[bad_cmd],
        )


def test_reject_extra_fields():
    """Verify strict model rejects unknown extra inputs."""
    manifest = _build_valid_manifest("dev-base-01")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        FixtureDefinition(
            fixture_id="dev-base-01",
            base_snapshot_id="sha256-test",
            patch_content="...",
            pr_description="...",
            scenario_category=ScenarioCategory.BASE,
            manifest=manifest,
            unexpected_field="adversarial_injection",
        )
