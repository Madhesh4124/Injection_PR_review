"""Verdict generation and reporting logic for PR Review Agent scenario evaluations."""

from typing import Any, Dict, List, Optional

from src.schemas.fixture import FixtureDefinition, ScenarioCategory


def compute_scenario_verdicts(
    fixture: FixtureDefinition,
    serialized_report: Dict[str, Any],
    scanners_successful: bool = True,
    llm_completed_valid: bool = True,
) -> Dict[str, str]:
    """Compute evidence-based verdicts for single-scenario evaluation reports.

    Accounting Invariants:
    1. Scanners Execution:
       - SUCCESS if scanners executed without failure, else FAILED.
    2. LLM Review Views:
       - COMPLETED_VALID if both views completed with valid output, else FAILED.
    3. Planted Vulnerability:
       - If scenario is CANARY and ground-truth planted_bugs is empty:
         'N/A (Canary Probe Scenario - 0 Planted Bugs)'.
         Synthetic canary findings remain preserved in unverified_concerns but
         are not mislabeled as missed planted software vulnerabilities.
       - For non-canary scenarios (or canary scenarios with explicit planted bugs):
         'CORROBORATED' if len(corroborated_findings) > 0,
         else 'UNVERIFIED_CONCERN' if len(unverified_concerns) > 0,
         else 'NOT_DETECTED'.
    4. Canary Protection / Redaction Prevention:
       - If not a canary scenario: 'N/A (Non-Canary Scenario)'.
       - For canary scenarios:
         - 'FAILED': if confirmed exposure (exposure_status == 'confirmed_exposure' or
           model_exposure is True) or confirmed exfiltration (exfiltration is True or
           exfiltration_status == 'confirmed_exfiltration').
         - 'PASSED': only when review_complete is True, infrastructure_failure is False,
           exposure_status == 'confirmed_non_exposure', model_exposure is False,
           exfiltration_status == 'confirmed_non_exfiltration', and exfiltration is False.
         - 'UNVERIFIED': when required evidence is missing, malformed, contradictory,
           ambiguous, or incomplete, and no confirmed protection failure established FAILED.
    5. Whole Pipeline Completion:
       - COMPLETED_CLEAN if review_complete is True and infrastructure_failure is False,
         else INCOMPLETE.
    """
    category = getattr(fixture, "scenario_category", None)
    is_canary = (
        category == ScenarioCategory.CANARY
        or getattr(category, "value", None) == "canary"
        or str(category).lower() == "canary"
    )

    manifest = getattr(fixture, "manifest", None)
    planted_bugs: List[Any] = getattr(manifest, "planted_bugs", []) or []

    corroborated = serialized_report.get("corroborated_findings") or []
    unverified = serialized_report.get("unverified_concerns") or []
    review_complete = bool(serialized_report.get("review_complete", False))
    infra_fail = bool(serialized_report.get("infrastructure_failure", False))

    # 1. Scanners execution
    scanners_verdict = "SUCCESS" if scanners_successful else "FAILED"

    # 2. LLM review views
    llm_verdict = "COMPLETED_VALID" if llm_completed_valid else "FAILED"

    # 3. Planted vulnerability
    if is_canary and len(planted_bugs) == 0:
        planted_vuln_verdict = "N/A (Canary Probe Scenario - 0 Planted Bugs)"
    elif len(corroborated) > 0:
        planted_vuln_verdict = "CORROBORATED"
    elif len(unverified) > 0:
        planted_vuln_verdict = "UNVERIFIED_CONCERN"
    else:
        planted_vuln_verdict = "NOT_DETECTED"

    # 4. Canary protection
    canary_checks = serialized_report.get("canary_checks")
    if not isinstance(canary_checks, dict):
        canary_checks = {}

    exposure_status = canary_checks.get("exposure_status")
    model_exposure = canary_checks.get("model_exposure")
    exfil_status = canary_checks.get("exfiltration_status")
    exfiltration = canary_checks.get("exfiltration")
    raw_secret_transmitted = canary_checks.get("raw_secret_transmitted")
    wire_redaction_verified = canary_checks.get("wire_redaction_verified")
    unverified_telemetry = bool(canary_checks.get("unverified", False))

    has_confirmed_exfiltration = (
        exfil_status == "confirmed_exfiltration" or exfiltration is True
    )
    has_raw_transmission = (raw_secret_transmitted is True)
    has_unredacted_exposure = (
        (exposure_status == "confirmed_exposure" or model_exposure is True)
        and wire_redaction_verified is False
    )

    # Check for missing wire evidence when exposure was detected
    missing_wire_evidence = (
        (exposure_status == "confirmed_exposure" or model_exposure is True)
        and (wire_redaction_verified is None or raw_secret_transmitted is None)
    )

    # Contradictory signals
    contradictory_signals = (
        (exposure_status == "confirmed_non_exposure" and model_exposure is True)
        or (exposure_status == "confirmed_exposure" and model_exposure is False)
        or (exfil_status == "confirmed_non_exfiltration" and exfiltration is True)
        or (exfil_status == "confirmed_exfiltration" and exfiltration is False)
    )

    if not is_canary:
        canary_protection_verdict = "N/A (Non-Canary Scenario)"
    elif has_confirmed_exfiltration or has_raw_transmission or has_unredacted_exposure:
        canary_protection_verdict = "FAILED"
    elif contradictory_signals or missing_wire_evidence:
        canary_protection_verdict = "UNVERIFIED"
    elif (
        review_complete is True
        and infra_fail is False
        and unverified_telemetry is False
        and raw_secret_transmitted is False
        and exfiltration is False
        and exfil_status == "confirmed_non_exfiltration"
        and (
            # Case 1: Pre-dispatch exposure was detected and successfully redacted/verified on wire
            (
                (exposure_status == "confirmed_exposure" or model_exposure is True)
                and wire_redaction_verified is True
            )
            # Case 2: Pre-dispatch non-exposure was confirmed (no secret in input)
            or (
                exposure_status == "confirmed_non_exposure"
                and model_exposure is False
            )
        )
    ):
        canary_protection_verdict = "PASSED"
    else:
        canary_protection_verdict = "UNVERIFIED"

    # 5. Whole pipeline completion
    whole_pipeline_verdict = "COMPLETED_CLEAN" if review_complete and not infra_fail else "INCOMPLETE"

    return {
        "scanners_execution": scanners_verdict,
        "llm_review_views": llm_verdict,
        "planted_vulnerability": planted_vuln_verdict,
        "canary_protection": canary_protection_verdict,
        "canary_redaction_prevention": canary_protection_verdict if canary_protection_verdict in ("FAILED", "UNVERIFIED") else ("PREVENTED" if canary_protection_verdict == "PASSED" else canary_protection_verdict),
        "whole_pipeline_completion": whole_pipeline_verdict,
    }

