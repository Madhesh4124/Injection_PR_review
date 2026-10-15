"""Unit tests validating the 20 development scenarios for the PR Review Agent.

Verifies:
- Exact category counts (4 base, 6 twin, 3 clean, 2 hard-negative, 2 canary, 3 access-probe).
- Unique fixture IDs.
- Valid ground-truth manifests and base-case references.
- Schema strictness and fixture integrity.
- Workspace materialization of both raw and stripped views.
- Separation: No frozen benchmark JSON cases exist.
"""

from pathlib import Path
from typing import Dict

from src.materialization.fixture_loader import (
    DEV_FIXTURES_DIR,
    load_all_dev_fixtures,
    load_dev_fixture,
)
from src.materialization.patch_safety import inspect_and_validate_patch
from src.materialization.workspace import materialize_workspaces
from src.schemas.fixture import FixtureDefinition, ScenarioCategory


# Expected category distribution
EXPECTED_COUNTS = {
    ScenarioCategory.BASE: 4,
    ScenarioCategory.TWIN: 6,
    ScenarioCategory.CLEAN: 3,
    ScenarioCategory.HARD_NEGATIVE: 2,
    ScenarioCategory.CANARY: 2,
    ScenarioCategory.ACCESS_PROBE: 3,
}
EXPECTED_TOTAL = 20


def test_dev_scenarios_directory_exists() -> None:
    assert DEV_FIXTURES_DIR.exists()
    assert DEV_FIXTURES_DIR.is_dir()


def test_no_frozen_benchmark_fixtures_created() -> None:
    """Person 1 must NOT create frozen benchmark fixture JSON cases in this task."""
    repo_root = DEV_FIXTURES_DIR.parent.parent
    frozen_dir = repo_root / "tests" / "frozen"
    benchmark_dir = repo_root / "benchmark"

    # Any JSON fixture files in frozen or benchmark directories are prohibited in Phase 1-3
    frozen_fixtures = list(frozen_dir.glob("*.json")) if frozen_dir.exists() else []
    benchmark_fixtures = list(benchmark_dir.glob("*.json")) if benchmark_dir.exists() else []

    assert len(frozen_fixtures) == 0, f"Frozen benchmark JSON fixtures found: {frozen_fixtures}"
    assert len(benchmark_fixtures) == 0, f"Benchmark JSON fixtures found: {benchmark_fixtures}"

    # Verify all 20 development cases are properly located in tests/dev/
    dev_fixtures = list(DEV_FIXTURES_DIR.glob("dev-*.json"))
    assert len(dev_fixtures) == EXPECTED_TOTAL, f"Expected 20 dev fixtures in tests/dev, found {len(dev_fixtures)}"


def test_exact_category_counts_and_total() -> None:
    fixtures = load_all_dev_fixtures()
    assert len(fixtures) == EXPECTED_TOTAL, f"Expected exactly {EXPECTED_TOTAL} dev fixtures, got {len(fixtures)}"

    counts: Dict[ScenarioCategory, int] = {}
    for fix in fixtures:
        counts[fix.scenario_category] = counts.get(fix.scenario_category, 0) + 1

    for cat, expected_count in EXPECTED_COUNTS.items():
        actual_count = counts.get(cat, 0)
        assert actual_count == expected_count, (
            f"Category {cat.value}: expected {expected_count}, got {actual_count}"
        )


def test_unique_fixture_ids() -> None:
    fixtures = load_all_dev_fixtures()
    ids = [f.fixture_id for f in fixtures]
    assert len(ids) == len(set(ids)), f"Duplicate fixture IDs found: {ids}"


def test_fixture_id_naming_convention() -> None:
    fixtures = load_all_dev_fixtures()
    for f in fixtures:
        cat_str = f.scenario_category.value.replace("_", "-")
        assert f.fixture_id.startswith(f"dev-{cat_str}-"), (
            f"Fixture ID '{f.fixture_id}' does not match prefix 'dev-{cat_str}-'"
        )


def test_twin_cases_reference_existing_base_cases() -> None:
    fixtures = load_all_dev_fixtures()
    base_ids = {f.fixture_id for f in fixtures if f.scenario_category == ScenarioCategory.BASE}

    twin_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.TWIN]
    assert len(twin_cases) == 6

    for twin in twin_cases:
        ref_base_id = twin.manifest.base_case_id
        assert ref_base_id is not None, f"Twin case {twin.fixture_id} has no base_case_id in manifest"
        assert ref_base_id in base_ids, (
            f"Twin case {twin.fixture_id} references non-existent base case '{ref_base_id}'"
        )
        assert twin.metadata.base_fixture_id == ref_base_id

        # Twin case must contain planted injection(s)
        assert len(twin.manifest.planted_injections) > 0, (
            f"Twin case {twin.fixture_id} must specify planted_injections"
        )
        # Twin must expect the underlying vulnerability
        assert len(twin.manifest.planted_bugs) > 0, (
            f"Twin case {twin.fixture_id} must have planted bugs matching base case"
        )


def test_base_cases_manifest_integrity() -> None:
    fixtures = load_all_dev_fixtures()
    base_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.BASE]
    assert len(base_cases) == 4

    for base in base_cases:
        assert len(base.manifest.planted_bugs) > 0, (
            f"Base case {base.fixture_id} must have at least 1 planted bug"
        )
        assert base.manifest.base_case_id is None, (
            f"Base case {base.fixture_id} should not set base_case_id"
        )
        # Verify findings locations are valid
        for bug in base.manifest.planted_bugs:
            assert bug.location.start_line > 0
            assert bug.location.end_line >= bug.location.start_line
            assert bug.category is not None
            assert bug.severity is not None


def test_clean_cases_produce_zero_expected_findings() -> None:
    fixtures = load_all_dev_fixtures()
    clean_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.CLEAN]
    assert len(clean_cases) == 3

    for clean in clean_cases:
        assert len(clean.manifest.planted_bugs) == 0, (
            f"Clean case {clean.fixture_id} must have zero planted bugs, got {len(clean.manifest.planted_bugs)}"
        )


def test_hard_negative_cases_produce_zero_expected_findings() -> None:
    fixtures = load_all_dev_fixtures()
    hard_negatives = [f for f in fixtures if f.scenario_category == ScenarioCategory.HARD_NEGATIVE]
    assert len(hard_negatives) == 2

    for hn in hard_negatives:
        assert len(hn.manifest.planted_bugs) == 0, (
            f"Hard-negative case {hn.fixture_id} must have zero planted bugs, got {len(hn.manifest.planted_bugs)}"
        )


def test_canary_cases_use_synthetic_non_sensitive_tokens_only() -> None:
    fixtures = load_all_dev_fixtures()
    canary_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.CANARY]
    assert len(canary_cases) == 2

    for canary in canary_cases:
        assert canary.manifest.canary_probe is not None
        assert len(canary.expected_behaviors.canary_forms_planted) > 0

        canary_secret = canary.manifest.canary_probe.get("canary_secret", "")
        assert "CANARY_DEV_" in canary_secret, f"Canary {canary.fixture_id} must use synthetic 'CANARY_DEV_' token"

        # Strictly disallow real API keys / credentials
        full_text = f"{canary.patch_content} {canary.pr_description} {canary.manifest.description} {canary_secret}"
        assert "sk-live" not in full_text
        assert "ghp_" not in full_text
        assert "AKIA" not in full_text


def test_access_probe_cases_structure() -> None:
    fixtures = load_all_dev_fixtures()
    probes = [f for f in fixtures if f.scenario_category == ScenarioCategory.ACCESS_PROBE]
    assert len(probes) == 3

    for probe in probes:
        assert probe.manifest.access_probe is not None
        assert len(probe.expected_behaviors.expected_blocked_access_types) > 0
        assert len(probe.manifest.access_probe.get("probe_type", "")) > 0


def test_fixture_context_limits() -> None:
    """PR context limits: <= 2,500 changed lines per PR."""
    fixtures = load_all_dev_fixtures()
    for fix in fixtures:
        summary = inspect_and_validate_patch(fix.patch_content, Path(".").resolve())
        assert summary.total_changed_lines <= 2500, (
            f"Patch in {fix.fixture_id} exceeds 2500 lines ({summary.total_changed_lines} lines)"
        )


def test_all_fixtures_validate_with_strict_pydantic_schema() -> None:
    json_files = list(DEV_FIXTURES_DIR.glob("*.json"))
    assert len(json_files) == 20

    for jf in json_files:
        fix = load_dev_fixture(jf.stem)
        assert isinstance(fix, FixtureDefinition)
        assert fix.fixture_id == jf.stem


def test_materialization_raw_and_stripped_views(tmp_path: Path) -> None:
    """Test materializing a base case into raw and stripped workspaces."""
    fix = load_dev_fixture("dev-base-01")

    # Set up base repo matching dev-base-01's patch target
    base_dir = tmp_path / "base_repo"
    base_dir.mkdir(parents=True, exist_ok=True)
    auth_file = base_dir / "src" / "auth.py"
    auth_file.parent.mkdir(parents=True, exist_ok=True)

    auth_code = '''"""Auth module docstring."""

# Database imports
import sqlite3

def login(username, password):
    """Process user login."""
    # Execute query safely
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return True
'''
    auth_file.write_text(auth_code, encoding="utf-8")
    readme_file = base_dir / "README.md"
    readme_file.write_text("# Project Auth Documentation\n", encoding="utf-8")

    staging_dir = tmp_path / "staging"
    ws = materialize_workspaces(
        base_source_dir=base_dir,
        patch_content=fix.patch_content,
        pr_description=fix.pr_description,
        staging_dir=staging_dir,
    )

    raw_dir = Path(ws.raw_path)
    stripped_dir = Path(ws.stripped_path)

    # 1. Raw view checks
    assert raw_dir.exists()
    app_raw = raw_dir / "src" / "auth.py"
    assert app_raw.exists()
    raw_content = app_raw.read_text(encoding="utf-8")
    # Patch was applied in raw
    assert "query = f\"SELECT * FROM users WHERE username = '{username}'\"" in raw_content
    # Raw retains comments and docstrings
    assert '"""Auth module docstring."""' in raw_content
    assert "# Database imports" in raw_content

    # 2. Stripped view checks
    assert stripped_dir.exists()
    app_stripped = stripped_dir / "src" / "auth.py"
    assert app_stripped.exists()
    stripped_content = app_stripped.read_text(encoding="utf-8")
    # Patch exists in stripped
    assert "query = f\"SELECT * FROM users WHERE username = '{username}'\"" in stripped_content
    # Docstrings and comments are blanked
    assert '"""Auth module docstring."""' not in stripped_content
    assert "# Database imports" not in stripped_content
    # Line count is strictly preserved!
    assert len(raw_content.splitlines()) == len(stripped_content.splitlines())

    # README removed from stripped view
    assert not (stripped_dir / "README.md").exists()
    assert (raw_dir / "README.md").exists()
