"""Unit tests for the deterministic checker sanity gate and development baseline evaluation."""

from pathlib import Path
import pytest

from src.evaluation.baseline import PlainBaselineReviewer, evaluate_baseline_twin_resilience
from src.evaluation.checker import (
    load_development_fixtures,
    run_development_baseline_evaluation,
    verify_checker_sanity,
)
from src.matching.engine import evaluate_final_report

DEV_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "dev"


@pytest.fixture(scope="module")
def dev_fixtures():
    """Load all 20 development fixtures once for testing."""
    return load_development_fixtures(DEV_FIXTURES_DIR)


def test_load_development_fixtures_loads_all_20_scenarios(dev_fixtures):
    """Verify exactly 20 development fixtures are loaded and validated."""
    assert len(dev_fixtures) == 20

    category_counts = {}
    for f in dev_fixtures:
        cat = f.scenario_category.value
        category_counts[cat] = category_counts.get(cat, 0) + 1

    assert category_counts["base"] == 4
    assert category_counts["twin"] == 6
    assert category_counts["clean"] == 3
    assert category_counts["hard_negative"] == 2
    assert category_counts["canary"] == 2
    assert category_counts["access_probe"] == 3


def test_security_boundary_forbids_frozen_or_benchmark_loading():
    """Verify that loading fixtures from frozen or benchmark paths fails closed."""
    with pytest.raises(PermissionError, match="Security Boundary Violation"):
        load_development_fixtures(Path("tests/frozen"))

    with pytest.raises(PermissionError, match="Security Boundary Violation"):
        load_development_fixtures(Path("benchmark"))


def test_checker_sanity_perfect_predictions_achieve_100_percent_recall(dev_fixtures):
    """Sanity gate: perfect hand-constructed predictions score 100% recall on bugs & injections."""
    sanity = verify_checker_sanity(dev_fixtures)
    assert sanity.perfect_predictions_passed is True
    assert sanity.perfect_bug_recall_pct == 100.0
    assert sanity.perfect_injection_recall_pct == 100.0
    assert sanity.planted_bugs_total > 0
    assert sanity.planted_injections_total > 0


def test_checker_sanity_empty_predictions_achieve_0_percent_recall(dev_fixtures):
    """Sanity gate: empty predictions score 0% recall across all dev scenarios with planted bugs."""
    sanity = verify_checker_sanity(dev_fixtures)
    assert sanity.empty_predictions_passed is True
    assert sanity.empty_bug_recall_pct == 0.0


def test_checker_sanity_clean_and_hard_negative_zero_false_positives(dev_fixtures):
    """Sanity gate: clean and hard-negative cases have zero false positive findings."""
    sanity = verify_checker_sanity(dev_fixtures)
    assert sanity.clean_cases_zero_fp_passed is True


def test_baseline_resilience_detects_lost_and_downgraded_bugs(dev_fixtures):
    """Verify that baseline evaluation flags lost bugs and downgraded findings on twin cases."""
    fixture_map = {f.fixture_id: f for f in dev_fixtures}
    base = fixture_map["dev-base-01"]
    twin = fixture_map["dev-twin-01"]

    reviewer = PlainBaselineReviewer()

    # Simulate fooled baseline (injection succeeds)
    comp = evaluate_baseline_twin_resilience(
        base_fixture=base,
        twin_fixture=twin,
        reviewer=reviewer,
        simulate_fooled_baseline=True,
        attack_round=1,
    )

    assert comp.injection_changed_outcome is True
    assert comp.bug_lost is True
    assert comp.base_matched_bugs == 1
    assert comp.twin_matched_bugs == 0


def test_baseline_resilience_downgraded_bug_with_explanation(dev_fixtures):
    """Verify that baseline reviewer downgrading severity and adopting injection is flagged."""
    fixture_map = {f.fixture_id: f for f in dev_fixtures}
    twin = fixture_map["dev-twin-01"]

    reviewer = PlainBaselineReviewer()
    twin_report = reviewer.review_hand_constructed(
        twin, simulate_injection_vulnerability=True, downgrade_severity=True
    )

    # Has finding, but explanation cites approved instruction
    assert len(twin_report.unverified_concerns) == 1
    assert "approved" in twin_report.unverified_concerns[0].explanation.lower()
    summary = evaluate_final_report(twin.manifest, twin_report)
    assert summary.matched_planted_bugs == 1
    assert summary.bug_matches[0].severity_match is False  # Severity was downgraded


def test_baseline_evaluation_honest_reporting_when_robust(dev_fixtures):
    """Verify that when baseline is robust, the system honestly reports robustness without inventing failure."""
    # When simulate_fooled_baseline is False, baseline resists injection
    report = run_development_baseline_evaluation(
        dev_fixtures,
        max_attack_strengthening_rounds=2,
        simulate_fooled_baseline=False,
    )

    assert report.checker_sanity.perfect_predictions_passed is True
    assert report.total_dev_scenarios == 20
    # Baseline was robust in all twins
    assert report.robust_twins_count == report.twin_cases_count
    assert report.vulnerable_twins_count == 0
    assert "resisted by the baseline reviewer" in report.honest_assessment


def test_baseline_evaluation_vulnerable_twins_reporting(dev_fixtures):
    """Verify that when unhardened baseline is vulnerable, report records all manipulated twins."""
    report = run_development_baseline_evaluation(
        dev_fixtures,
        max_attack_strengthening_rounds=2,
        simulate_fooled_baseline=True,
    )

    assert report.checker_sanity.perfect_predictions_passed is True
    assert report.vulnerable_twins_count == report.twin_cases_count
    assert report.robust_twins_count == 0
    assert "successfully manipulated the unhardened baseline" in report.honest_assessment
