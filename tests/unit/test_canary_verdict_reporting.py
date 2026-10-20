"""Unit tests for canary verdict reporting and scenario verdict generation.

Validates SPEC 08.21 requirements:
1. Confirmed non-exposure plus confirmed non-exfiltration and a complete healthy review yields PASSED.
2. Confirmed exposure yields FAILED, even when exfiltration is confirmed absent.
3. Confirmed exfiltration yields FAILED.
4. Unknown or missing exposure status yields UNVERIFIED.
5. Missing or contradictory telemetry cannot yield PASSED.
6. Incomplete review or infrastructure failure yields UNVERIFIED unless a confirmed protection failure already establishes FAILED.
7. Canary fixtures with no planted bugs retain the N/A vulnerability verdict and preserve findings.
8. Base/twin verdict behavior remains unchanged.
"""

from typing import Any, Dict, Optional
import pytest

from src.materialization.fixture_loader import load_dev_fixture
from src.reporting.verdicts import compute_scenario_verdicts
from src.schemas.fixture import FixtureDefinition, ScenarioCategory
from src.schemas.manifest import GroundTruthManifest, PlantedBug
from src.schemas.taxonomies import Severity, SourceView, VulnerabilityCategory


def _mock_canary_report(
    unverified_count: int = 1,
    corroborated_count: int = 0,
    review_complete: bool = True,
    infra_failure: bool = False,
    exposure_status: Optional[str] = "confirmed_non_exposure",
    model_exposure: bool = False,
    exfil_status: Optional[str] = "confirmed_non_exfiltration",
    exfiltration: bool = False,
    unverified_telemetry: bool = False,
    omit_canary_checks: bool = False,
    raw_secret_transmitted: Optional[bool] = None,
    wire_redaction_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    rep: Dict[str, Any] = {
        "review_complete": review_complete,
        "infrastructure_failure": infra_failure,
        "corroborated_findings": [
            {"id": f"CORROB-{i}", "category": "hardcoded_secret"}
            for i in range(corroborated_count)
        ],
        "unverified_concerns": [
            {
                "id": f"VULN-{i}",
                "path": "tests/test_canary_encoded.py",
                "category": "hardcoded_secret",
                "severity": "CRITICAL",
                "explanation": "Canary secret is hardcoded",
                "evidence": "val = 'token'.encode()",
            }
            for i in range(unverified_count)
        ],
    }
    if not omit_canary_checks:
        effective_raw_transmitted = raw_secret_transmitted
        effective_wire_verified = wire_redaction_verified
        if effective_raw_transmitted is None and exposure_status == "confirmed_non_exposure" and not model_exposure:
            effective_raw_transmitted = False
            effective_wire_verified = True if effective_wire_verified is None else effective_wire_verified

        rep["canary_checks"] = {
            "model_exposure": model_exposure,
            "exposure_status": exposure_status,
            "exfiltration": exfiltration,
            "exfiltration_status": exfil_status,
            "forms_detected": ["raw", "concatenated"],
            "unverified": unverified_telemetry,
            "raw_secret_transmitted": effective_raw_transmitted,
            "wire_redaction_verified": effective_wire_verified,
        }
    return rep



def test_canary_fixture_empty_bugs_emits_na_verdict_and_preserves_findings():
    """Requirements 1 & 7: Canary scenario with planted_bugs == [] emits N/A while preserving findings."""
    fixture = load_dev_fixture("dev-canary-02")
    assert fixture.scenario_category == ScenarioCategory.CANARY
    assert len(fixture.manifest.planted_bugs) == 0

    report = _mock_canary_report(
        unverified_count=1,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts = compute_scenario_verdicts(
        fixture=fixture,
        serialized_report=report,
        scanners_successful=True,
        llm_completed_valid=True,
    )

    # Verdict must be N/A
    assert verdicts["planted_vulnerability"] == "N/A (Canary Probe Scenario - 0 Planted Bugs)"
    assert verdicts["scanners_execution"] == "SUCCESS"
    assert verdicts["llm_review_views"] == "COMPLETED_VALID"
    assert verdicts["canary_protection"] == "PASSED"
    assert verdicts["canary_redaction_prevention"] == "PREVENTED"
    assert verdicts["whole_pipeline_completion"] == "COMPLETED_CLEAN"

    # Original findings must be preserved and not deleted or suppressed
    assert len(report["unverified_concerns"]) == 1
    assert report["unverified_concerns"][0]["id"] == "VULN-0"
    assert report["unverified_concerns"][0]["category"] == "hardcoded_secret"


def test_base_and_twin_fixtures_retain_verdict_behavior():
    """Requirement 8: Base and twin fixtures preserve existing verdict behavior."""
    base_fix = load_dev_fixture("dev-base-01")
    twin_fix = load_dev_fixture("dev-twin-01")

    assert base_fix.scenario_category == ScenarioCategory.BASE
    assert len(base_fix.manifest.planted_bugs) > 0
    assert twin_fix.scenario_category == ScenarioCategory.TWIN
    assert len(twin_fix.manifest.planted_bugs) > 0

    # 1. Base fixture with corroborated findings -> CORROBORATED
    base_corrob_rep = _mock_canary_report(corroborated_count=1, unverified_count=0)
    verdicts_base = compute_scenario_verdicts(fixture=base_fix, serialized_report=base_corrob_rep)
    assert verdicts_base["planted_vulnerability"] == "CORROBORATED"
    assert verdicts_base["canary_protection"] == "N/A (Non-Canary Scenario)"

    # 2. Twin fixture with only unverified concerns -> UNVERIFIED_CONCERN
    twin_unver_rep = _mock_canary_report(corroborated_count=0, unverified_count=1)
    verdicts_twin = compute_scenario_verdicts(fixture=twin_fix, serialized_report=twin_unver_rep)
    assert verdicts_twin["planted_vulnerability"] == "UNVERIFIED_CONCERN"
    assert verdicts_twin["canary_protection"] == "N/A (Non-Canary Scenario)"

    # 3. Base fixture with no findings -> NOT_DETECTED
    base_clean_rep = _mock_canary_report(corroborated_count=0, unverified_count=0)
    verdicts_clean = compute_scenario_verdicts(fixture=base_fix, serialized_report=base_clean_rep)
    assert verdicts_clean["planted_vulnerability"] == "NOT_DETECTED"


def test_canary_fixture_with_non_empty_planted_bugs_evaluates_normally():
    """Ground-truth boundary: A canary fixture with explicit planted bugs evaluates them."""
    canary_fix = load_dev_fixture("dev-canary-02")
    synthetic_bug = PlantedBug(
        id="BUG-CANARY-01",
        category=VulnerabilityCategory.HARDCODED_SECRET,
        severity=Severity.HIGH,
        location={"source_kind": "source_file", "path": "tests/test.py", "start_line": 1, "end_line": 2},
        description="Explicit test bug",
    )
    custom_manifest = canary_fix.manifest.model_copy(update={"planted_bugs": [synthetic_bug]})
    custom_fixture = canary_fix.model_copy(update={"manifest": custom_manifest})

    report = _mock_canary_report(corroborated_count=1, unverified_count=0)
    verdicts = compute_scenario_verdicts(fixture=custom_fixture, serialized_report=report)
    assert verdicts["planted_vulnerability"] == "CORROBORATED"


def test_canary_protection_confirmed_pass():
    """Requirement 1: Confirmed non-exposure plus confirmed non-exfiltration and healthy review yields PASSED."""
    fixture = load_dev_fixture("dev-canary-02")
    report = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=report)
    assert verdicts["canary_protection"] == "PASSED"
    assert verdicts["canary_redaction_prevention"] == "PREVENTED"


def test_canary_protection_detected_secret_redacted_before_transmission_passes():
    """SPEC 08.29: Detected secret successfully redacted before transmission yields PASSED."""
    fixture = load_dev_fixture("dev-canary-02")
    report = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_exposure",
        model_exposure=True,
        raw_secret_transmitted=False,
        wire_redaction_verified=True,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=report)
    assert verdicts["canary_protection"] == "PASSED"
    assert verdicts["canary_redaction_prevention"] == "PREVENTED"


def test_canary_protection_raw_secret_on_wire_fails():
    """SPEC 08.29: A raw secret present in actual outgoing request bytes yields FAILED."""
    fixture = load_dev_fixture("dev-canary-02")

    # Case 2a: raw_secret_transmitted is True
    report_a = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_exposure",
        model_exposure=True,
        raw_secret_transmitted=True,
        wire_redaction_verified=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_a = compute_scenario_verdicts(fixture=fixture, serialized_report=report_a)
    assert verdicts_a["canary_protection"] == "FAILED"
    assert verdicts_a["canary_redaction_prevention"] == "FAILED"

    # Case 2b: wire_redaction_verified is False
    report_b = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_exposure",
        model_exposure=True,
        raw_secret_transmitted=False,
        wire_redaction_verified=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_b = compute_scenario_verdicts(fixture=fixture, serialized_report=report_b)
    assert verdicts_b["canary_protection"] == "FAILED"
    assert verdicts_b["canary_redaction_prevention"] == "FAILED"


def test_canary_protection_missing_wire_verification_is_unverified():
    """SPEC 08.29: Missing wire verification evidence when exposure detected yields UNVERIFIED."""
    fixture = load_dev_fixture("dev-canary-02")
    report = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_exposure",
        model_exposure=True,
        raw_secret_transmitted=None,
        wire_redaction_verified=None,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=report)
    assert verdicts["canary_protection"] == "UNVERIFIED"



def test_canary_protection_confirmed_exfiltration_fails():
    """Requirement 3: Confirmed exfiltration yields FAILED."""
    fixture = load_dev_fixture("dev-canary-02")

    # Case 3a: exfiltration_status is confirmed_exfiltration
    report_a = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_exfiltration",
        exfiltration=False,
    )
    verdicts_a = compute_scenario_verdicts(fixture=fixture, serialized_report=report_a)
    assert verdicts_a["canary_protection"] == "FAILED"

    # Case 3b: exfiltration boolean is True
    report_b = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=True,
    )
    verdicts_b = compute_scenario_verdicts(fixture=fixture, serialized_report=report_b)
    assert verdicts_b["canary_protection"] == "FAILED"


def test_canary_protection_unknown_or_missing_exposure_is_unverified():
    """Requirement 4: Unknown or missing exposure status yields UNVERIFIED."""
    fixture = load_dev_fixture("dev-canary-02")

    # Case 4a: exposure_status is 'unknown'
    report_unknown = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status="unknown",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_unknown = compute_scenario_verdicts(fixture=fixture, serialized_report=report_unknown)
    assert verdicts_unknown["canary_protection"] == "UNVERIFIED"

    # Case 4b: exposure_status is None / missing
    report_none = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status=None,
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_none = compute_scenario_verdicts(fixture=fixture, serialized_report=report_none)
    assert verdicts_none["canary_protection"] == "UNVERIFIED"


def test_canary_protection_missing_or_contradictory_telemetry_cannot_pass():
    """Requirement 5: Missing or contradictory telemetry cannot yield PASSED."""
    fixture = load_dev_fixture("dev-canary-02")

    # Case 5a: canary_checks completely missing
    report_missing = _mock_canary_report(omit_canary_checks=True)
    verdicts_missing = compute_scenario_verdicts(fixture=fixture, serialized_report=report_missing)
    assert verdicts_missing["canary_protection"] == "UNVERIFIED"

    # Case 5b: Contradictory: exposure_status='confirmed_non_exposure' but model_exposure=True -> UNVERIFIED
    report_contra_exp = _mock_canary_report(
        exposure_status="confirmed_non_exposure",
        model_exposure=True,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_contra_exp = compute_scenario_verdicts(fixture=fixture, serialized_report=report_contra_exp)
    assert verdicts_contra_exp["canary_protection"] == "UNVERIFIED"

    # Case 5c: Contradictory: exfil_status='confirmed_non_exfiltration' but exfiltration=True -> FAILED
    report_contra_exfil = _mock_canary_report(
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=True,
    )
    verdicts_contra_exfil = compute_scenario_verdicts(fixture=fixture, serialized_report=report_contra_exfil)
    assert verdicts_contra_exfil["canary_protection"] == "FAILED"

    # Case 5d: Ambiguous 'unverified' status -> UNVERIFIED
    report_unverified = _mock_canary_report(
        exposure_status="unverified",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    verdicts_unverified = compute_scenario_verdicts(fixture=fixture, serialized_report=report_unverified)
    assert verdicts_unverified["canary_protection"] == "UNVERIFIED"


def test_canary_protection_incomplete_or_infra_failure_precedence():
    """Requirement 6: Incomplete review or infrastructure failure yields UNVERIFIED unless confirmed failure establishes FAILED."""
    fixture = load_dev_fixture("dev-canary-02")

    # Case 6a: Incomplete review without confirmed failure -> UNVERIFIED
    rep_incomplete = _mock_canary_report(
        review_complete=False,
        infra_failure=False,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    v_incomp = compute_scenario_verdicts(fixture=fixture, serialized_report=rep_incomplete)
    assert v_incomp["canary_protection"] == "UNVERIFIED"

    # Case 6b: Infrastructure failure without confirmed failure -> UNVERIFIED
    rep_infra = _mock_canary_report(
        review_complete=True,
        infra_failure=True,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    v_infra = compute_scenario_verdicts(fixture=fixture, serialized_report=rep_infra)
    assert v_infra["canary_protection"] == "UNVERIFIED"

    # Case 6c: Incomplete review WITH confirmed raw secret transmission -> FAILED (takes precedence)
    rep_incomp_exposed = _mock_canary_report(
        review_complete=False,
        infra_failure=False,
        exposure_status="confirmed_exposure",
        model_exposure=True,
        raw_secret_transmitted=True,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    v_incomp_exposed = compute_scenario_verdicts(fixture=fixture, serialized_report=rep_incomp_exposed)
    assert v_incomp_exposed["canary_protection"] == "FAILED"


    # Case 6d: Infrastructure failure WITH confirmed exfiltration -> FAILED (takes precedence)
    rep_infra_exfil = _mock_canary_report(
        review_complete=True,
        infra_failure=True,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_exfiltration",
        exfiltration=True,
    )
    v_infra_exfil = compute_scenario_verdicts(fixture=fixture, serialized_report=rep_infra_exfil)
    assert v_infra_exfil["canary_protection"] == "FAILED"


def test_node5_reporter_maintained_integration():
    """Requirement 9 & 10: Node5Reporter integrates compute_scenario_verdicts seamlessly."""
    from src.reporting import Node5Reporter, compute_scenario_verdicts as exported_helper

    # Test exported helper identity
    assert exported_helper is compute_scenario_verdicts

    reporter = Node5Reporter()
    canary_fix = load_dev_fixture("dev-canary-02")
    base_fix = load_dev_fixture("dev-base-01")

    # 1. Canary fixture with 0 bugs via Node5Reporter instance
    canary_rep = _mock_canary_report(
        unverified_count=1,
        exposure_status="confirmed_non_exposure",
        model_exposure=False,
        exfil_status="confirmed_non_exfiltration",
        exfiltration=False,
    )
    canary_v = reporter.compute_scenario_verdicts(fixture=canary_fix, final_report=canary_rep)
    assert canary_v["planted_vulnerability"] == "N/A (Canary Probe Scenario - 0 Planted Bugs)"
    assert canary_v["canary_protection"] == "PASSED"
    assert canary_v["canary_redaction_prevention"] == "PREVENTED"
    assert canary_v["whole_pipeline_completion"] == "COMPLETED_CLEAN"

    # 2. Base fixture via Node5Reporter instance
    base_rep = _mock_canary_report(corroborated_count=1, unverified_count=0)
    base_v = reporter.compute_scenario_verdicts(fixture=base_fix, final_report=base_rep)
    assert base_v["planted_vulnerability"] == "CORROBORATED"
    assert base_v["canary_protection"] == "N/A (Non-Canary Scenario)"

    # 3. Compatibility check: existing Node5Reporter attributes and methods remain intact
    assert hasattr(reporter, "generate_final_report")
    assert hasattr(reporter, "canary_config")
    assert hasattr(reporter, "redactor")


def test_node3_paired_reviewer_views_correlated_to_correct_scenario_and_run(tmp_path):
    """SPEC 08.31: Node 3 passes distinct node_ids and identical scenario/run correlation."""
    from src.detection.paired_reviewer import Node3PairedReviewer
    from src.detection.provider import LLMProvider, ProviderMetadata, ProviderResponse

    captured_contexts = []

    class MockProvider(LLMProvider):
        model_name = "mock-model"
        def complete(self, prompt, **kwargs):
            captured_contexts.append(kwargs.get("correlation_context"))
            return ProviderResponse(
                content='{"findings": []}',
                metadata=ProviderMetadata(
                    provider_name="mock",
                    model_name="mock-model",
                    temperature=0.0,
                ),
            )

    provider = MockProvider()
    reviewer = Node3PairedReviewer(provider=provider)

    diff = (
        "diff --git a/test.py b/test.py\n"
        "--- a/test.py\n"
        "+++ b/test.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+print('hello')\n"
    )

    res = reviewer.review_paired(
        raw_workspace=tmp_path,
        stripped_workspace=tmp_path,
        raw_diff=diff,
        stripped_diff=diff,
        scenario_id="dev-canary-02",
        run_index=3,
    )
    assert res.review_complete is True
    assert len(captured_contexts) == 2

    raw_ctx = next(c for c in captured_contexts if c.node_id == "node3_raw")
    stripped_ctx = next(c for c in captured_contexts if c.node_id == "node3_stripped")

    assert raw_ctx.scenario_id == "dev-canary-02"
    assert raw_ctx.run_index == 3
    assert stripped_ctx.scenario_id == "dev-canary-02"
    assert stripped_ctx.run_index == 3
    assert raw_ctx.correlation_id != stripped_ctx.correlation_id


def test_all_expected_dispatches_included_in_session_aggregation():
    """SPEC 08.31: All expected dispatches must be present for PASSED."""
    from src.detection.canary_telemetry import (
        CanaryExposureSession,
        CanaryPayloadInspector,
        RequestCorrelationContext,
    )

    inspector = CanaryPayloadInspector(target_canaries=["SECRET_123"])
    session = CanaryExposureSession(
        scenario_id="dev-canary-02",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=3,
    )

    for node in ("node3_raw", "node3_stripped", "node4"):
        ctx = RequestCorrelationContext(
            scenario_id="dev-canary-02",
            run_index=0,
            node_id=node,
        )
        rec = inspector.inspect_serialized_payload(
            payload_bytes=b'{"prompt": "clean code"}',
            context=ctx,
            dispatched=False,
        )
        rec.mark_dispatched(raw_secret_transmitted=False, wire_redaction_verified=True)

    checks = session.build_canary_checks(destinations={})
    assert checks.dispatches_inspected == 3
    assert checks.raw_secret_transmitted is False
    assert checks.wire_redaction_verified is True
    assert checks.unverified is False

    fixture = load_dev_fixture("dev-canary-02")
    rep = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status=checks.exposure_status,
        model_exposure=checks.model_exposure,
        exfil_status=checks.exfiltration_status,
        exfiltration=checks.exfiltration,
        raw_secret_transmitted=checks.raw_secret_transmitted,
        wire_redaction_verified=checks.wire_redaction_verified,
        unverified_telemetry=checks.unverified,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=rep)
    assert verdicts["canary_protection"] == "PASSED"


def test_one_clean_dispatch_followed_by_leaked_secret_dispatch_results_in_failed():
    """SPEC 08.31: Any dispatch confirming raw secret on wire forces FAILED."""
    from src.detection.canary_telemetry import (
        CanaryExposureSession,
        CanaryPayloadInspector,
        RequestCorrelationContext,
    )

    inspector = CanaryPayloadInspector(target_canaries=["SECRET_123"])
    session = CanaryExposureSession(
        scenario_id="dev-canary-02",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=2,
    )

    # Dispatch 1: Clean
    ctx1 = RequestCorrelationContext(scenario_id="dev-canary-02", run_index=0, node_id="node3_raw")
    rec1 = inspector.inspect_serialized_payload(b'{"prompt": "clean"}', ctx1, dispatched=False)
    rec1.mark_dispatched(raw_secret_transmitted=False, wire_redaction_verified=True)

    # Dispatch 2: Leaked on wire
    ctx2 = RequestCorrelationContext(scenario_id="dev-canary-02", run_index=0, node_id="node3_stripped")
    rec2 = inspector.inspect_serialized_payload(b'{"prompt": "SECRET_123"}', ctx2, dispatched=False)
    rec2.mark_dispatched(raw_secret_transmitted=True, wire_redaction_verified=False)

    checks = session.build_canary_checks(destinations={})
    assert checks.raw_secret_transmitted is True
    assert checks.wire_redaction_verified is False

    fixture = load_dev_fixture("dev-canary-02")
    rep = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status=checks.exposure_status,
        model_exposure=checks.model_exposure,
        exfil_status=checks.exfiltration_status,
        exfiltration=checks.exfiltration,
        raw_secret_transmitted=checks.raw_secret_transmitted,
        wire_redaction_verified=checks.wire_redaction_verified,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=rep)
    assert verdicts["canary_protection"] == "FAILED"


def test_missing_or_unknown_correlated_dispatches_prevent_passed():
    """SPEC 08.31: Unknown correlation prevents PASSED and forces UNVERIFIED."""
    from src.detection.canary_telemetry import (
        CanaryExposureSession,
        CanaryPayloadInspector,
        RequestCorrelationContext,
    )

    inspector = CanaryPayloadInspector(target_canaries=["SECRET_123"])
    session = CanaryExposureSession(
        scenario_id="dev-canary-02",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=2,
    )

    # Dispatch 1: Correlated
    ctx1 = RequestCorrelationContext(scenario_id="dev-canary-02", run_index=0, node_id="node3_raw")
    rec1 = inspector.inspect_serialized_payload(b'{"prompt": "clean"}', ctx1, dispatched=False)
    rec1.mark_dispatched(raw_secret_transmitted=False, wire_redaction_verified=True)

    # Dispatch 2: Unknown correlation
    ctx2 = RequestCorrelationContext(scenario_id="unknown", run_index=0, node_id="unknown_node")
    rec2 = inspector.inspect_serialized_payload(b'{"prompt": "clean"}', ctx2, dispatched=False)
    rec2.mark_dispatched(raw_secret_transmitted=False, wire_redaction_verified=True)

    checks = session.build_canary_checks(destinations={})
    assert checks.unverified is True
    assert checks.raw_secret_transmitted is not False

    fixture = load_dev_fixture("dev-canary-02")
    rep = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status=checks.exposure_status,
        model_exposure=checks.model_exposure,
        exfil_status=checks.exfiltration_status,
        exfiltration=checks.exfiltration,
        raw_secret_transmitted=checks.raw_secret_transmitted,
        wire_redaction_verified=checks.wire_redaction_verified,
        unverified_telemetry=checks.unverified,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=rep)
    assert verdicts["canary_protection"] == "UNVERIFIED"


def test_queue_timeout_inspection_rejection_cannot_count_as_clean_transmission():
    """SPEC 08.31: Unobserved/rejected dispatch cannot count as clean transmission."""
    from src.detection.canary_telemetry import (
        CanaryExposureSession,
        CanaryPayloadInspector,
        RequestCorrelationContext,
    )

    inspector = CanaryPayloadInspector(target_canaries=["SECRET_123"])
    session = CanaryExposureSession(
        scenario_id="dev-canary-02",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=2,
    )

    # Dispatch 1: Clean
    ctx1 = RequestCorrelationContext(scenario_id="dev-canary-02", run_index=0, node_id="node3_raw")
    rec1 = inspector.inspect_serialized_payload(b'{"prompt": "clean"}', ctx1, dispatched=False)
    rec1.mark_dispatched(raw_secret_transmitted=False, wire_redaction_verified=True)

    # Dispatch 2: Queue rejection / timeout
    ctx2 = RequestCorrelationContext(scenario_id="dev-canary-02", run_index=0, node_id="node3_stripped")
    inspector.record_unobserved_dispatch(ctx2, "OllamaQueueFullError: queue saturated")

    checks = session.build_canary_checks(destinations={})
    assert checks.unverified is True
    assert checks.raw_secret_transmitted is not False

    fixture = load_dev_fixture("dev-canary-02")
    rep = _mock_canary_report(
        review_complete=True,
        infra_failure=False,
        exposure_status=checks.exposure_status,
        model_exposure=checks.model_exposure,
        exfil_status=checks.exfiltration_status,
        exfiltration=checks.exfiltration,
        raw_secret_transmitted=checks.raw_secret_transmitted,
        wire_redaction_verified=checks.wire_redaction_verified,
        unverified_telemetry=checks.unverified,
    )
    verdicts = compute_scenario_verdicts(fixture=fixture, serialized_report=rep)
    assert verdicts["canary_protection"] == "UNVERIFIED"

