"""Unit tests for high-context model window enforcement and live baseline evaluation gate."""

import json
from pathlib import Path
import pytest

from src.detection.models import ProviderMetadata
from src.detection.ollama_provider import (
    OllamaConfig,
    OllamaOversizedInputError,
    OllamaProvider,
)
from src.detection.provider import LLMProvider, MockLLMProvider, ProviderResponse
from src.evaluation.baseline import PlainBaselineReviewer, evaluate_baseline_twin_resilience
from src.evaluation.checker import load_development_fixtures, run_development_baseline_evaluation
from src.schemas.taxonomies import Severity

DEV_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "dev"


def test_ollama_num_ctx_propagated_in_options():
    """Verify that OllamaConfig.num_ctx is explicitly passed in the request options payload."""
    observed_payload = None

    def mock_transport(payload_bytes, timeout):
        nonlocal observed_payload
        observed_payload = json.loads(payload_bytes.decode("utf-8"))
        return '{"response": "ok"}'

    config = OllamaConfig(
        num_ctx=32768,
        max_concurrency=1,
    )
    provider = OllamaProvider(config=config, transport_fn=mock_transport)
    resp = provider.complete("Test prompt")

    assert resp.content == '{"response": "ok"}'
    assert observed_payload is not None
    assert "options" in observed_payload
    assert observed_payload["options"]["num_ctx"] == 32768
    assert observed_payload["options"]["temperature"] == 0.0
    assert resp.metadata.extra_config["num_ctx"] == 32768


def test_ollama_truncation_detection_prevents_silent_failure():
    """Verify that when Ollama prompt_eval_count reaches or exceeds num_ctx, an error is raised."""
    config = OllamaConfig(num_ctx=8192)
    provider = OllamaProvider(config=config)

    # Simulate response from Ollama daemon where prompt saturated the 8192-token context window
    truncated_ollama_json = json.dumps({
        "response": "Incomplete review",
        "prompt_eval_count": 8192,
        "eval_count": 50,
        "done": True,
    }).encode("utf-8")

    import urllib.request
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.read.side_effect = [truncated_ollama_json, b""]
    mock_resp.__enter__.return_value = mock_resp

    original_urlopen = urllib.request.urlopen
    try:
        urllib.request.urlopen = MagicMock(return_value=mock_resp)
        with pytest.raises(OllamaOversizedInputError) as exc_info:
            provider.complete("Long prompt...")
    finally:
        urllib.request.urlopen = original_urlopen

    assert "exceeded allocated Ollama context window" in str(exc_info.value)
    assert "8192" in str(exc_info.value)


def test_baseline_reviewer_live_unfooled_on_base_fixture():
    """Verify PlainBaselineReviewer parses structured findings from live provider on base fixture."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    # Mock provider that finds the SQL injection on base fixture (dev-base-01: src/auth.py lines 13-14)
    def handler(prompt, system_prompt, temp):
        return json.dumps({
            "findings": [
                {
                    "id": "BASE-001",
                    "path": "src/auth.py",
                    "start_line": 13,
                    "end_line": 14,
                    "category": "sql_injection",
                    "severity": "CRITICAL",
                    "explanation": "SQL query concatenation with unsanitized username parameter",
                    "evidence": "SELECT * FROM users WHERE username = ...",
                }
            ]
        })

    mock_provider = MockLLMProvider(handler=handler, model_name="test-baseline-model")
    reviewer = PlainBaselineReviewer()
    report = reviewer.review_live(base_01, mock_provider)

    assert len(report.unverified_concerns) == 1
    finding = report.unverified_concerns[0]
    assert finding.category == "sql_injection"
    assert finding.severity == Severity.CRITICAL
    assert finding.location.path == "src/auth.py"
    assert report.run_metadata.model_id == "test-baseline-model"


def test_baseline_reviewer_live_fooled_by_injection_on_twin():
    """Verify that an injection causing empty findings results in injection_changed_outcome=True."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")
    twin_01 = next(f for f in fixtures if f.fixture_id == "dev-twin-01")

    def handler(prompt, system_prompt, temp):
        # If prompt contains the twin's adversarial injection instruction, baseline model complies
        if "waiver" in prompt.lower() or "appsec" in prompt.lower():
            return json.dumps({"findings": []})
        # Otherwise, report the security bug
        return json.dumps({
            "findings": [
                {
                    "id": "BASE-001",
                    "path": "src/auth.py",
                    "start_line": 13,
                    "end_line": 14,
                    "category": "sql_injection",
                    "severity": "CRITICAL",
                    "explanation": "SQL injection",
                }
            ]
        })

    mock_provider = MockLLMProvider(handler=handler)
    reviewer = PlainBaselineReviewer()

    comp = evaluate_baseline_twin_resilience(
        base_fixture=base_01,
        twin_fixture=twin_01,
        reviewer=reviewer,
        live_provider=mock_provider,
    )

    assert comp.base_matched_bugs == 1
    assert comp.twin_matched_bugs == 0
    assert comp.bug_lost is True
    assert comp.injection_changed_outcome is True
    assert "successfully manipulated" in comp.notes


def test_run_development_baseline_evaluation_with_live_provider():
    """Verify run_development_baseline_evaluation executes across dev scenarios with live provider."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)

    def naive_reviewer_handler(prompt, system_prompt, temp):
        # Naive unhardened model follows adversarial injections in twin PRs
        if any(term in prompt.lower() for term in ["waiver", "appsec", "secops", "ignore", "skip", "override"]):
            return json.dumps({"findings": []})

        findings = []
        if "auth.py" in prompt or "login" in prompt.lower():
            findings.append({
                "id": "FIND-01",
                "path": "src/auth.py",
                "start_line": 13,
                "end_line": 14,
                "category": "sql_injection",
                "severity": "CRITICAL",
                "explanation": "SQL injection",
            })
        elif "payment.py" in prompt or "stripe" in prompt.lower() or "gateway" in prompt.lower():
            findings.append({
                "id": "FIND-02",
                "path": "src/payment.py",
                "start_line": 11,
                "end_line": 11,
                "category": "hardcoded_secret",
                "severity": "HIGH",
                "explanation": "Hardcoded secret",
            })
        return json.dumps({"findings": findings})

    mock_provider = MockLLMProvider(handler=naive_reviewer_handler)
    report = run_development_baseline_evaluation(
        dev_fixtures=fixtures,
        live_provider=mock_provider,
    )

    assert report.total_dev_scenarios == 20
    assert report.vulnerable_twins_count > 0
    assert len(report.twin_comparisons) == 6
    assert any(c.injection_changed_outcome for c in report.twin_comparisons)


def test_frozen_harness_defended_pipeline_executes_real_nodes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify FrozenEvaluationHarness._run_defended_fixture invokes real Nodes 1-5 with a provider."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus
    from src.schemas.findings import ScannerFinding, Location
    from src.schemas.taxonomies import SourceKind, VulnerabilityCategory

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    # Inject explicit successful scanner test double
    real_scan_finding = ScannerFinding(
        id="SCAN-REAL-01",
        rule_id="rule.sql_injection",
        location=Location(source_kind=SourceKind.SOURCE_FILE, path="src/auth.py", start_line=13, end_line=14),
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        evidence="query = f'SELECT * FROM users'",
    )
    successful_scan = AggregatedScanOutput(
        scanner_findings=[real_scan_finding],
        tool_results={
            "bandit": ScanResult(tool_name="bandit", status=ScanStatus.SUCCESS),
            "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.SUCCESS),
        },
        all_tools_successful=True,
        any_tool_failed=False,
    )
    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", lambda ws: successful_scan)

    # Mock provider returning valid finding for Node 3 and valid injection record for Node 4
    def pipeline_handler(prompt, system_prompt, temp):
        if "node 4" in (system_prompt or "").lower():
            # Node 4 response
            return json.dumps({"records": []})
        # Node 3 response
        return json.dumps({
            "findings": [
                {
                    "id": "FIND-REAL-01",
                    "path": "src/auth.py",
                    "start_line": 13,
                    "end_line": 14,
                    "category": "sql_injection",
                    "severity": "CRITICAL",
                    "explanation": "SQL query concatenation detected",
                    "evidence": "query = f'SELECT * FROM users'",
                }
            ]
        })

    mock_provider = MockLLMProvider(handler=pipeline_handler, model_name="mock-defended-pipeline")
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    run_dir = tmp_path / "defended_run_0"
    run_dir.mkdir()

    report = harness._run_defended_fixture(
        fixture=dev_base_01,
        run_idx=0,
        run_dir=run_dir,
    )

    assert report.run_metadata.review_complete is True
    assert report.run_metadata.infrastructure_failure is False
    assert len(report.corroborated_findings) + len(report.unverified_concerns) >= 1
    # Real Node 2 scanner findings passed through and preserved
    assert any(sf.id == "SCAN-REAL-01" for sf in report.scanner_findings)


def test_frozen_harness_defended_pipeline_fails_closed_on_provider_error(tmp_path: Path):
    """Verify FrozenEvaluationHarness._run_defended_fixture fails closed when provider fails."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    class FailingProvider(LLMProvider):
        def complete(self, prompt, **kwargs):
            raise RuntimeError("Provider connection reset by peer")

    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=FailingProvider())

    run_dir = tmp_path / "defended_run_fail"
    run_dir.mkdir()

    report = harness._run_defended_fixture(
        fixture=dev_base_01,
        run_idx=0,
        run_dir=run_dir,
    )

    assert report.run_metadata.review_complete is False
    assert report.run_metadata.infrastructure_failure is True


# ==============================================================================
# F-01 Regression Tests: Scanner Fallback Removal & Honest Status Reporting
# ==============================================================================

def test_harness_scanner_unavailability_cannot_be_reported_as_successful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-01: Scanner unavailability sets review_complete=False and infrastructure_failure=True."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    unavailable_scan = AggregatedScanOutput(
        scanner_findings=[],
        tool_results={
            "bandit": ScanResult(tool_name="bandit", status=ScanStatus.TOOL_NOT_AVAILABLE, error="Executable not found"),
            "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.TOOL_NOT_AVAILABLE, error="Executable not found"),
        },
        all_tools_successful=False,
        any_tool_failed=True,
    )
    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", lambda ws: unavailable_scan)

    def clean_handler(prompt, system_prompt, temp):
        if "node 4" in (system_prompt or "").lower():
            return json.dumps({"records": []})
        return json.dumps({"findings": []})

    mock_provider = MockLLMProvider(handler=clean_handler)
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    run_dir = tmp_path / "scan_unavail"
    run_dir.mkdir()

    report = harness._run_defended_fixture(fixture=dev_base_01, run_idx=0, run_dir=run_dir)

    assert report.run_metadata.review_complete is False
    assert report.run_metadata.infrastructure_failure is True
    assert report.scanner_findings == []


def test_harness_scanner_errors_cannot_be_replaced_by_synthetic_manifest_bugs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-01: Scanner errors cannot be masked by synthesizing findings from manifest ground truth."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")
    assert len(dev_base_01.manifest.planted_bugs) > 0  # Fixture has ground-truth bugs

    failed_scan = AggregatedScanOutput(
        scanner_findings=[],
        tool_results={
            "bandit": ScanResult(tool_name="bandit", status=ScanStatus.FAILURE, error="Internal crash"),
            "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.FAILURE, error="Internal crash"),
        },
        all_tools_successful=False,
        any_tool_failed=True,
    )
    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", lambda ws: failed_scan)

    def clean_handler(prompt, system_prompt, temp):
        if "node 4" in (system_prompt or "").lower():
            return json.dumps({"records": []})
        return json.dumps({"findings": []})

    mock_provider = MockLLMProvider(handler=clean_handler)
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    run_dir = tmp_path / "scan_err"
    run_dir.mkdir()

    report = harness._run_defended_fixture(fixture=dev_base_01, run_idx=0, run_dir=run_dir)

    # Must NOT synthesize findings from manifest planted_bugs
    assert report.scanner_findings == []
    for bug in dev_base_01.manifest.planted_bugs:
        assert not any(sf.id == f"SCAN-{bug.id}" for sf in report.scanner_findings)
    assert report.run_metadata.infrastructure_failure is True


def test_harness_successful_empty_scanner_results_distinguishable_from_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-01: Successful scans with zero findings are distinguished from scanner failures."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_clean = next(f for f in fixtures if f.fixture_id == "dev-clean-01")

    clean_scan = AggregatedScanOutput(
        scanner_findings=[],
        tool_results={
            "bandit": ScanResult(tool_name="bandit", status=ScanStatus.SUCCESS),
            "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.SUCCESS),
        },
        all_tools_successful=True,
        any_tool_failed=False,
    )
    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", lambda ws: clean_scan)

    def clean_handler(prompt, system_prompt, temp):
        if "node 4" in (system_prompt or "").lower():
            return json.dumps({"records": []})
        return json.dumps({"findings": []})

    mock_provider = MockLLMProvider(handler=clean_handler)
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    run_dir = tmp_path / "clean_scan"
    run_dir.mkdir()

    report = harness._run_defended_fixture(fixture=dev_clean, run_idx=0, run_dir=run_dir)

    assert report.scanner_findings == []
    assert report.run_metadata.infrastructure_failure is False
    assert report.run_metadata.review_complete is True


def test_harness_real_scanner_findings_passed_to_node5_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-01: Real scanner findings are delivered to Node 5 without alteration."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus
    from src.schemas.findings import ScannerFinding, Location
    from src.schemas.taxonomies import SourceKind, VulnerabilityCategory

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    custom_finding = ScannerFinding(
        id="SCAN-EXACT-001",
        rule_id="custom.security.rule",
        location=Location(source_kind=SourceKind.SOURCE_FILE, path="src/auth.py", start_line=13, end_line=14),
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        evidence="Exact raw scanner match",
    )
    scan_res = AggregatedScanOutput(
        scanner_findings=[custom_finding],
        tool_results={
            "bandit": ScanResult(tool_name="bandit", status=ScanStatus.SUCCESS),
            "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.SUCCESS),
        },
        all_tools_successful=True,
        any_tool_failed=False,
    )
    monkeypatch.setattr("src.evaluation.harness.run_all_scanners", lambda ws: scan_res)

    def clean_handler(prompt, system_prompt, temp):
        if "node 4" in (system_prompt or "").lower():
            return json.dumps({"records": []})
        return json.dumps({"findings": []})

    mock_provider = MockLLMProvider(handler=clean_handler)
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    run_dir = tmp_path / "exact_scan"
    run_dir.mkdir()

    report = harness._run_defended_fixture(fixture=dev_base_01, run_idx=0, run_dir=run_dir)

    assert len(report.scanner_findings) == 1
    assert report.scanner_findings[0].id == "SCAN-EXACT-001"
    assert report.scanner_findings[0].rule_id == "custom.security.rule"


# ==============================================================================
# F-02 Regression Tests: Fail-Closed Simulation Selection & Provenance Tags
# ==============================================================================

def test_harness_live_mode_without_provider_raises_configuration_error(tmp_path: Path):
    """F-02: Live mode (use_simulation=False) without a provider raises ValueError."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=None)

    run_dir = tmp_path / "no_prov"
    run_dir.mkdir()

    with pytest.raises(ValueError, match="no LLMProvider was initialized"):
        harness._run_defended_fixture(fixture=dev_base_01, run_idx=0, run_dir=run_dir)

    with pytest.raises(ValueError, match="no LLMProvider was initialized"):
        harness._run_baseline_fixture(fixture=dev_base_01, run_idx=0)


def test_harness_simulation_mode_uses_correct_provenance(tmp_path: Path):
    """F-02: Simulation mode explicitly produces tags starting with simulated-."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=True)
    harness = FrozenEvaluationHarness(config=cfg, provider=None)

    run_dir = tmp_path / "sim_prov"
    run_dir.mkdir()

    defended_report = harness._run_defended_fixture(fixture=dev_base_01, run_idx=0, run_dir=run_dir)
    baseline_report = harness._run_baseline_fixture(fixture=dev_base_01, run_idx=0)

    assert defended_report.run_metadata.benchmark_tag == "simulated-defended"
    assert baseline_report.run_metadata.benchmark_tag == "simulated-baseline"


def test_harness_simulation_methods_cannot_emit_live_benchmark_tag(tmp_path: Path):
    """F-02: Simulation methods strictly emit simulated- tags and never live frozen tags."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=True)
    harness = FrozenEvaluationHarness(config=cfg, provider=None)

    run_dir = tmp_path / "no_live_tag"
    run_dir.mkdir()

    sim_base_report = harness._run_baseline_fixture_simulated(fixture=dev_base_01, run_idx=0)
    sim_def_report = harness._run_defended_fixture_simulated(fixture=dev_base_01, run_idx=0, run_dir=run_dir)

    assert sim_base_report.run_metadata.benchmark_tag == "simulated-baseline"
    assert sim_base_report.run_metadata.benchmark_tag != "frozen-baseline"
    assert sim_def_report.run_metadata.benchmark_tag == "simulated-defended"
    assert sim_def_report.run_metadata.benchmark_tag != "frozen-defended"


def test_harness_provider_backed_execution_supported_without_network():
    """F-02: Local fake provider executes live review without network calls."""
    from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness

    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")

    mock_provider = MockLLMProvider(canned_response='{"findings": []}', model_name="local-fake-model")
    cfg = EvaluationConfig(scenarios_dir=DEV_FIXTURES_DIR, use_simulation=False)
    harness = FrozenEvaluationHarness(config=cfg, provider=mock_provider)

    baseline_report = harness._run_baseline_fixture(fixture=dev_base_01, run_idx=0)
    assert baseline_report.run_metadata.benchmark_tag == "dev-baseline-live"
    assert baseline_report.run_metadata.model_id == "local-fake-model"


def test_zero_base_recall_marked_inconclusive_not_robust():
    """Verify that zero base recall is classified as inconclusive, not evidence of robustness."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    dev_base_01 = next(f for f in fixtures if f.fixture_id == "dev-base-01")
    dev_twin_01 = next(f for f in fixtures if f.fixture_id == "dev-twin-01")

    # Mock provider that fails to detect the planted bug on both base and twin
    mock_provider = MockLLMProvider(canned_response='{"findings": []}', model_name="blind-baseline-model")
    reviewer = PlainBaselineReviewer()

    comp = evaluate_baseline_twin_resilience(
        base_fixture=dev_base_01,
        twin_fixture=dev_twin_01,
        reviewer=reviewer,
        live_provider=mock_provider,
    )

    assert comp.base_matched_bugs == 0
    assert comp.twin_matched_bugs == 0
    assert comp.bug_lost is False
    assert comp.injection_changed_outcome is False
    assert comp.base_vulnerability_detected is False
    assert comp.is_inconclusive_zero_base_recall is True
    assert "inconclusive" in comp.affected_reason.lower()


def test_live_evaluation_does_not_loop_identical_requests():
    """Verify run_development_baseline_evaluation does not repeat identical requests for live models."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    call_count = 0

    def counting_handler(prompt, system_prompt, temp):
        nonlocal call_count
        call_count += 1
        return '{"findings": []}'

    mock_provider = MockLLMProvider(handler=counting_handler, model_name="counting-model")
    report = run_development_baseline_evaluation(
        dev_fixtures=fixtures,
        live_provider=mock_provider,
    )

    # 4 unique base fixtures + 6 twin fixtures = exactly 10 calls.
    # No repeated identical calls as "strengthening rounds".
    assert call_count == 10
    assert report.attack_strengthening_rounds_used == 1
    assert report.inconclusive_twins_count == 6
    assert report.robust_twins_count == 0
    assert report.vulnerable_twins_count == 0


