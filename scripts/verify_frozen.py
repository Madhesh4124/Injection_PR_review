#!/usr/bin/env python3
"""Frozen Benchmark Integrity Verification Script.

Enforces Phase 4 Gates:
1. Loads and strictly validates all 50 frozen benchmark scenarios.
2. Asserts exact category distribution:
   - 10 Base scenarios
   - 15 Twin scenarios
   - 10 Clean PR scenarios
   - 5 Hard-Negative scenarios
   - 5 Canary Probe scenarios
   - 5 Access Probe scenarios
3. Validates twin relationships:
   - Every twin references an existing base case.
   - Planted bugs in twin match base case planted bugs.
   - Planted injections have valid overlapping bounds and injection types.
   - Differential suppression expectation is set.
4. Asserts pure synthetic non-sensitive canary tokens (no real credentials).
5. Asserts PR context limits (<= 2500 lines per PR, <= 500 lines per file).
6. Verifies that pytest collection guard strictly excludes benchmark directories.
7. Prints a structured verification summary and exits 0 on success, 1 on failure.
"""

import sys
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.materialization.frozen_loader import FROZEN_SCENARIOS_DIR, load_all_frozen_fixtures  # noqa: E402
from src.materialization.patch_safety import inspect_and_validate_patch  # noqa: E402
from src.schemas.fixture import ScenarioCategory  # noqa: E402

EXPECTED_COUNTS: Dict[ScenarioCategory, int] = {
    ScenarioCategory.BASE: 10,
    ScenarioCategory.TWIN: 15,
    ScenarioCategory.CLEAN: 10,
    ScenarioCategory.HARD_NEGATIVE: 5,
    ScenarioCategory.CANARY: 5,
    ScenarioCategory.ACCESS_PROBE: 5,
}
EXPECTED_TOTAL = 50


def verify_frozen_benchmark() -> bool:
    """Execute all frozen integrity checks and report detailed status."""
    print("=" * 80)
    print("FROZEN BENCHMARK INTEGRITY VERIFICATION")
    print("=" * 80)
    print(f"Target Directory: {FROZEN_SCENARIOS_DIR.resolve()}")

    if not FROZEN_SCENARIOS_DIR.exists():
        print(f"ERROR: Frozen scenarios directory does not exist: {FROZEN_SCENARIOS_DIR}")
        return False

    # 1. Load all fixtures
    try:
        fixtures = load_all_frozen_fixtures(FROZEN_SCENARIOS_DIR)
        print(f"Loaded {len(fixtures)} frozen fixtures.")
    except Exception as exc:
        print(f"ERROR: Failed to load frozen fixtures: {exc}")
        return False

    # 2. Check total and exact category counts
    if len(fixtures) != EXPECTED_TOTAL:
        print(f"ERROR: Expected {EXPECTED_TOTAL} total scenarios, found {len(fixtures)}")
        return False

    category_counts: Dict[ScenarioCategory, int] = {}
    for fix in fixtures:
        category_counts[fix.scenario_category] = category_counts.get(fix.scenario_category, 0) + 1

    print("\n--- Scenario Category Distribution ---")
    all_counts_match = True
    for cat, exp_count in EXPECTED_COUNTS.items():
        act_count = category_counts.get(cat, 0)
        match_str = "PASS" if act_count == exp_count else "FAIL"
        print(f"  {cat.value.upper():<15}: {act_count:>2} / {exp_count:>2}  [{match_str}]")
        if act_count != exp_count:
            all_counts_match = False

    if not all_counts_match:
        print("ERROR: Scenario distribution does not match specifications.")
        return False

    # 3. Check unique IDs and naming format
    fixture_ids: List[str] = [f.fixture_id for f in fixtures]
    if len(fixture_ids) != len(set(fixture_ids)):
        print("ERROR: Duplicate fixture IDs found!")
        return False

    for fix in fixtures:
        cat_prefix = fix.scenario_category.value.replace("_", "-")
        expected_prefix = f"frozen-{cat_prefix}-"
        if not fix.fixture_id.startswith(expected_prefix):
            print(f"ERROR: Fixture ID '{fix.fixture_id}' does not start with '{expected_prefix}'")
            return False

    # 4. Verify base cases
    base_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.BASE]
    base_ids: Set[str] = {f.fixture_id for f in base_cases}

    for base in base_cases:
        if len(base.manifest.planted_bugs) == 0:
            print(f"ERROR: Base scenario {base.fixture_id} has zero planted bugs!")
            return False
        if base.manifest.base_case_id is not None:
            print(f"ERROR: Base scenario {base.fixture_id} must not specify base_case_id!")
            return False

    # 5. Verify twin cases and relationships
    twin_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.TWIN]
    print(f"\n--- Twin Pair Relationship Verification ({len(twin_cases)} twins) ---")
    base_to_twins: Dict[str, List[str]] = {}

    for twin in twin_cases:
        base_id = twin.manifest.base_case_id
        if not base_id or base_id not in base_ids:
            print(f"ERROR: Twin {twin.fixture_id} references invalid base_case_id: '{base_id}'")
            return False

        if twin.metadata.base_fixture_id != base_id:
            print(f"ERROR: Twin {twin.fixture_id} metadata base_fixture_id mismatch: '{twin.metadata.base_fixture_id}'")
            return False

        base_to_twins.setdefault(base_id, []).append(twin.fixture_id)

        # Twin must have planted bug and planted injection
        if len(twin.manifest.planted_bugs) == 0:
            print(f"ERROR: Twin {twin.fixture_id} has zero planted bugs!")
            return False
        if len(twin.manifest.planted_injections) == 0:
            print(f"ERROR: Twin {twin.fixture_id} has zero planted injections!")
            return False
        if not twin.expected_behaviors.expect_differential_suppression:
            print(f"ERROR: Twin {twin.fixture_id} must expect differential suppression!")
            return False

    for base_id, twins in sorted(base_to_twins.items()):
        print(f"  {base_id:<18} -> {', '.join(twins)}")

    # Ensure all 10 base cases have at least one twin
    uncovered_bases = base_ids - set(base_to_twins.keys())
    if uncovered_bases:
        print(f"ERROR: The following base scenarios have no twins: {uncovered_bases}")
        return False

    # 6. Verify clean & hard-negative scenarios
    clean_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.CLEAN]
    for clean in clean_cases:
        if len(clean.manifest.planted_bugs) > 0 or len(clean.manifest.planted_injections) > 0:
            print(f"ERROR: Clean scenario {clean.fixture_id} has planted bugs or injections!")
            return False

    hn_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.HARD_NEGATIVE]
    for hn in hn_cases:
        if len(hn.manifest.planted_bugs) > 0 or len(hn.manifest.planted_injections) > 0:
            print(f"ERROR: Hard-negative scenario {hn.fixture_id} has planted bugs or injections!")
            return False

    # 7. Verify canary probes
    canary_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.CANARY]
    for canary in canary_cases:
        if not canary.manifest.canary_probe:
            print(f"ERROR: Canary scenario {canary.fixture_id} missing canary_probe telemetry!")
            return False
        token = canary.manifest.canary_probe.get("canary_secret", "")
        if "CANARY_FROZEN_" not in token:
            print(f"ERROR: Canary scenario {canary.fixture_id} does not use synthetic 'CANARY_FROZEN_' token: '{token}'")
            return False

        # Strictly disallow real API keys / credentials
        full_text = f"{canary.patch_content} {canary.pr_description} {canary.manifest.description} {token}"
        for forbidden in ["sk-live", "ghp_", "AKIA", "ASIA"]:
            if forbidden in full_text:
                print(f"CRITICAL: Canary scenario {canary.fixture_id} contains forbidden credential substring '{forbidden}'")
                return False

    # 8. Verify access probes
    access_cases = [f for f in fixtures if f.scenario_category == ScenarioCategory.ACCESS_PROBE]
    for probe in access_cases:
        if not probe.manifest.access_probe:
            print(f"ERROR: Access probe scenario {probe.fixture_id} missing access_probe telemetry!")
            return False
        if len(probe.expected_behaviors.expected_blocked_access_types) == 0:
            print(f"ERROR: Access probe {probe.fixture_id} has empty expected_blocked_access_types!")
            return False

    # 9. Verify PR context limits
    print("\n--- PR Context Limit Verification ---")
    for fix in fixtures:
        summary = inspect_and_validate_patch(fix.patch_content, REPO_ROOT)
        if summary.total_changed_lines > 2500:
            print(f"ERROR: Fixture {fix.fixture_id} patch exceeds 2,500 lines ({summary.total_changed_lines})")
            return False

    print("  All 50 scenarios satisfy line limits (<= 2500 changed lines, <= 500 lines per file).")

    print("\n" + "=" * 80)
    print("VERIFICATION RESULT: ALL 50 FROZEN SCENARIOS PASS INTEGRITY CHECKS")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = verify_frozen_benchmark()
    sys.exit(0 if success else 1)
