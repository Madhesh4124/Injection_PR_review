"""Deterministic 20-scenario parity test suite comparing legacy and LangGraph defended pipelines.

Validates 100% semantic equivalence between:
- _run_defended_fixture_legacy
- _run_defended_fixture_graph
Across all 20 Part 1 development scenarios.
"""

from pathlib import Path
from typing import Any, Dict, List
import pytest

from src.detection.provider import MockLLMProvider
from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
from src.materialization.fixture_loader import load_all_dev_fixtures
from src.schemas.fixture import FixtureDefinition, ScenarioCategory
from src.schemas.report import FinalReport
from src.scanning.models import ScanResult, ScanStatus
from src.scanning.runner import AggregatedScanOutput


def _sort_key(f: Any) -> tuple:
    path = getattr(getattr(f, "location", None), "path", "") or ""
    line = getattr(getattr(f, "location", None), "start_line", 0) or 0
    cat = getattr(getattr(f, "category", None), "value", str(getattr(f, "category", "")))
    return (path, line, cat)


def assert_reports_semantically_equivalent(
    legacy_report: FinalReport,
    graph_report: FinalReport,
) -> None:
    """Validate 100% deterministic semantic parity between legacy and LangGraph reports.

    Excludes non-deterministic or timing-dependent metadata (timestamps, elapsed run duration, run_number).
    """
    # 1. Finding counts
    assert len(legacy_report.corroborated_findings) == len(graph_report.corroborated_findings), (
        f"Corroborated findings count mismatch: legacy={len(legacy_report.corroborated_findings)}, "
        f"graph={len(graph_report.corroborated_findings)}"
    )
    assert len(legacy_report.scanner_findings) == len(graph_report.scanner_findings), (
        f"Scanner findings count mismatch: legacy={len(legacy_report.scanner_findings)}, "
        f"graph={len(graph_report.scanner_findings)}"
    )
    assert len(legacy_report.unverified_concerns) == len(graph_report.unverified_concerns), (
        f"Unverified concerns count mismatch: legacy={len(legacy_report.unverified_concerns)}, "
        f"graph={len(graph_report.unverified_concerns)}"
    )
    assert len(legacy_report.injection_detections) == len(graph_report.injection_detections), (
        f"Injection detections count mismatch: legacy={len(legacy_report.injection_detections)}, "
        f"graph={len(graph_report.injection_detections)}"
    )
    assert len(legacy_report.suppression_flags) == len(graph_report.suppression_flags), (
        f"Suppression flags count mismatch: legacy={len(legacy_report.suppression_flags)}, "
        f"graph={len(graph_report.suppression_flags)}"
    )

    # 2. Findings detail comparison (sorted deterministically)
    for lf, gf in zip(sorted(legacy_report.corroborated_findings, key=_sort_key),
                      sorted(graph_report.corroborated_findings, key=_sort_key)):
        assert lf.location.path == gf.location.path
        assert lf.location.start_line == gf.location.start_line
        assert lf.category == gf.category
        assert lf.severity == gf.severity

    for lsf, gsf in zip(sorted(legacy_report.scanner_findings, key=_sort_key),
                        sorted(graph_report.scanner_findings, key=_sort_key)):
        assert lsf.location.path == gsf.location.path
        assert lsf.location.start_line == gsf.location.start_line
        assert lsf.category == gsf.category
        assert lsf.severity == gsf.severity

    for luf, guf in zip(sorted(legacy_report.unverified_concerns, key=_sort_key),
                        sorted(graph_report.unverified_concerns, key=_sort_key)):
        assert luf.location.path == guf.location.path
        assert luf.location.start_line == guf.location.start_line
        assert luf.category == guf.category
        assert luf.severity == guf.severity

    # 3. Injection Detections detail comparison
    def _inj_sort_key(i: Any) -> tuple:
        p = getattr(getattr(i, "location", None), "path", "") or ""
        return (str(i.id), p, str(i.injection_type))

    for li, gi in zip(sorted(legacy_report.injection_detections, key=_inj_sort_key),
                      sorted(graph_report.injection_detections, key=_inj_sort_key)):
        assert li.id == gi.id
        assert li.injection_type == gi.injection_type
        assert li.source == gi.source

    # 4. Canary Checks Telemetry
    assert legacy_report.canary_checks.model_exposure == graph_report.canary_checks.model_exposure
    assert legacy_report.canary_checks.exfiltration == graph_report.canary_checks.exfiltration
    assert sorted(legacy_report.canary_checks.forms_detected) == sorted(graph_report.canary_checks.forms_detected)
    assert legacy_report.canary_checks.unverified == graph_report.canary_checks.unverified

    # 5. Blocked Access Telemetry
    assert len(legacy_report.blocked_access.tool_unit) == len(graph_report.blocked_access.tool_unit)
    for lt, gt in zip(legacy_report.blocked_access.tool_unit, graph_report.blocked_access.tool_unit):
        assert lt.attempt == gt.attempt
        assert lt.blocked_by == gt.blocked_by

    # 6. Critical Security and Execution Flags
    assert legacy_report.run_metadata.review_complete == graph_report.run_metadata.review_complete
    assert legacy_report.run_metadata.infrastructure_failure == graph_report.run_metadata.infrastructure_failure
    assert legacy_report.run_metadata.unreviewed_files_truncated == graph_report.run_metadata.unreviewed_files_truncated


class DeterministicParityProvider(MockLLMProvider):
    """Deterministic scenario-aware mock provider to test parity across diverse categories."""

    def __init__(self):
        super().__init__()

    def complete(self, prompt: str, **kwargs: Any):
        # Return deterministic valid responses based on prompt keywords
        if "sql" in prompt.lower():
            canned = """{
                "findings": [
                    {
                        "id": "VULN-001",
                        "path": "src/auth.py",
                        "start_line": 12,
                        "end_line": 15,
                        "category": "sql_injection",
                        "severity": "HIGH",
                        "explanation": "SQL injection via query formatting",
                        "evidence": "SELECT * FROM users"
                    }
                ],
                "records": []
            }"""
        elif "injection" in prompt.lower() or "adversarial" in prompt.lower():
            canned = """{
                "findings": [],
                "records": [
                    {
                        "id": "DET-INJ-001",
                        "source": "pr_description",
                        "location": null,
                        "injection_type": "direct_instruction",
                        "confidence": 0.99,
                        "explanation": "Direct instruction prompt injection",
                        "evidence": "ignore previous instructions",
                        "status": "confirmed"
                    }
                ]
            }"""
        else:
            canned = '{"findings": [], "records": []}'

        self.canned_response = canned
        return super().complete(prompt, **kwargs)


@pytest.fixture(autouse=True)
def mock_scanners_for_parity(monkeypatch: pytest.MonkeyPatch):
    """Ensure scanner execution is consistent across both legacy and graph runners."""
    def mock_scanners(ws: Path):
        return AggregatedScanOutput(
            scanner_findings=[],
            tool_results={
                "bandit": ScanResult(tool_name="bandit", status=ScanStatus.SUCCESS),
                "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.SUCCESS),
            },
            all_tools_successful=True,
            any_tool_failed=False,
        )

    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", mock_scanners)
    monkeypatch.setattr("src.workflow.adapters.run_all_scanners", mock_scanners)


ALL_DEV_FIXTURES = load_all_dev_fixtures()


@pytest.mark.parametrize("fixture", ALL_DEV_FIXTURES, ids=[f.fixture_id for f in ALL_DEV_FIXTURES])
def test_all_20_dev_scenarios_parity(fixture: FixtureDefinition, tmp_path: Path):
    """Assert 100% semantic parity between legacy and LangGraph pipeline on each dev scenario."""
    provider = DeterministicParityProvider()

    legacy_dir = tmp_path / "legacy"
    graph_dir = tmp_path / "graph"
    legacy_dir.mkdir(parents=True)
    graph_dir.mkdir(parents=True)

    config = EvaluationConfig(use_simulation=False, runs_per_case=1)
    harness = FrozenEvaluationHarness(config=config, provider=provider, model_id="parity-model-v1")

    # 1. Run Legacy Pipeline
    legacy_report = harness._run_defended_fixture_legacy(
        fixture=fixture,
        run_idx=0,
        run_dir=legacy_dir,
    )

    # 2. Run LangGraph Pipeline
    graph_report = harness._run_defended_fixture_graph(
        fixture=fixture,
        run_idx=0,
        run_dir=graph_dir,
    )

    # 3. Assert Semantic Parity
    assert_reports_semantically_equivalent(legacy_report, graph_report)
