"""Comprehensive unit tests for Node 5: Deterministic Validation and Reporting Layer."""

import base64
from pathlib import Path

import pytest

from src.reporting.blocked_access import BlockedAccessCollector, sanitize_blocked_details
from src.reporting.canary_redactor import (
    REDACTED_CANARY_PLACEHOLDER,
    CanaryConfig,
    CanaryRedactor,
)
from src.reporting.finding_validator import (
    validate_and_deduplicate_findings,
    validate_and_normalize_finding,
)
from src.reporting.reporter import Node5Reporter
from src.reporting.suppression import match_findings_across_views
from src.schemas.findings import Finding, ScannerFinding
from src.schemas.injections import DetectionStatus, InjectionRecord
from src.schemas.location import Location
from src.schemas.report import FinalReport
from src.schemas.taxonomies import (
    DiscrepancyKind,
    InjectionType,
    Severity,
    SourceKind,
    SourceView,
    VulnerabilityCategory,
)
from src.scanning.models import ScanResult, ScanStatus


@pytest.fixture
def test_workspaces(tmp_path: Path) -> tuple[Path, Path]:
    """Create temporary raw and stripped workspaces with real files."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    raw_file = raw_ws / "auth.py"
    raw_file.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

    stripped_file = stripped_ws / "auth.py"
    stripped_file.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

    return raw_ws, stripped_ws


# =========================================================================
# 1. Location Validation & Path Normalization Tests
# =========================================================================

def test_validate_finding_positive(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, _ = test_workspaces
    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="./auth.py", start_line=2, end_line=3)
    f = Finding(
        id="VULN-001",
        location=loc,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="SQL injection flaw",
        evidence="cursor.execute()",
        source_view=SourceView.RAW,
    )

    norm_f, err = validate_and_normalize_finding(f, raw_ws, SourceView.RAW)
    assert err is None
    assert norm_f is not None
    assert norm_f.location.path == "auth.py"  # normalized
    assert norm_f.location.start_line == 2
    assert norm_f.location.end_line == 3
    assert norm_f.source_view == SourceView.RAW


def test_reject_impossible_file_not_found(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, _ = test_workspaces
    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="non_existent.py", start_line=1, end_line=1)
    f = Finding(
        id="VULN-002",
        location=loc,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="Missing file finding",
        evidence="evidence",
        source_view=SourceView.RAW,
    )

    norm_f, err = validate_and_normalize_finding(f, raw_ws, SourceView.RAW)
    assert norm_f is None
    assert "does not exist in authorized workspace" in (err or "")


def test_reject_impossible_line_numbers(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, _ = test_workspaces
    # File has 5 lines; start_line 10 is impossible
    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=10, end_line=12)
    f = Finding(
        id="VULN-003",
        location=loc,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="Exceeds file lines",
        evidence="evidence",
        source_view=SourceView.RAW,
    )

    norm_f, err = validate_and_normalize_finding(f, raw_ws, SourceView.RAW)
    assert norm_f is None
    assert "exceeds total lines in file" in (err or "")


def test_deduplicate_candidate_findings(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, _ = test_workspaces
    loc1 = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=2, end_line=3)
    loc2 = Location(source_kind=SourceKind.SOURCE_FILE, path="./auth.py", start_line=2, end_line=4)

    f1 = Finding(
        id="VULN-001",
        location=loc1,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="First finding",
        evidence="evidence",
        source_view=SourceView.RAW,
    )
    f2 = Finding(
        id="VULN-002",  # Duplicate on same file, category, start line
        location=loc2,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="Duplicate finding",
        evidence="evidence",
        source_view=SourceView.RAW,
    )

    res = validate_and_deduplicate_findings([f1, f2], raw_ws, SourceView.RAW)
    assert len(res.valid_findings) == 1
    assert res.valid_findings[0].id == "VULN-001"
    assert res.duplicate_finding_ids == ["VULN-002"]


# =========================================================================
# 2. Differential Suppression & Recall Candidate Preservation
# =========================================================================

def test_match_across_views_matched_shifted() -> None:
    loc_raw = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=2, end_line=2)
    loc_stripped = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=4, end_line=4)

    raw_f = Finding(
        id="RAW-001",
        location=loc_raw,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="Raw finding",
        evidence="evidence",
        source_view=SourceView.RAW,
    )
    stripped_f = Finding(
        id="STRIPPED-001",
        location=loc_stripped,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        explanation="Stripped finding",
        evidence="evidence",
        source_view=SourceView.STRIPPED,
    )

    res = match_findings_across_views([raw_f], [stripped_f], injection_records=[])
    assert len(res.unified_findings) == 1
    assert res.unified_findings[0].source_view == SourceView.BOTH

    assert len(res.discrepancy_tags) == 1
    tag = res.discrepancy_tags[0]
    assert tag.kind == DiscrepancyKind.MATCHED_SHIFTED
    assert tag.line_shift == 2
    assert tag.category_mismatch is False
    assert tag.reason is not None


def test_suppressed_finding_preserved_as_recall_candidate() -> None:
    """Findings in stripped view only must be preserved in final findings list!"""
    loc_stripped = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=3, end_line=3)
    stripped_f = Finding(
        id="STRIPPED-002",
        location=loc_stripped,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        explanation="Found in stripped only",
        evidence="evidence",
        source_view=SourceView.STRIPPED,
    )

    # Injections were detected in raw view
    inj = InjectionRecord(
        id="INJ-001",
        source=SourceKind.PR_DESCRIPTION,
        injection_type=InjectionType.DIRECT_INSTRUCTION,
        confidence=0.99,
        explanation="Commanding to suppress SQL injection",
        status=DetectionStatus.CONFIRMED,
    )

    res = match_findings_across_views(raw_findings=[], stripped_findings=[stripped_f], injection_records=[inj])

    # Preserved as recall candidate!
    assert len(res.unified_findings) == 1
    assert res.unified_findings[0].id == "STRIPPED-002"
    assert res.unified_findings[0].source_view == SourceView.STRIPPED

    # Flagged as suppressed with audit reason
    assert len(res.discrepancy_tags) == 1
    tag = res.discrepancy_tags[0]
    assert tag.kind == DiscrepancyKind.SUPPRESSED
    assert tag.finding_id == "STRIPPED-002"
    assert "absent in raw view" in (tag.reason or "")


# =========================================================================
# 3. Multi-Encoding Canary Redaction Tests
# =========================================================================

def test_canary_redaction_raw_text() -> None:
    secret = "CANARY_DEV_SECRET_DIRECT_987654321"
    config = CanaryConfig(synthetic_canary=secret)
    redactor = CanaryRedactor(config)

    raw_text = f"The secret value is {secret} in line 42."
    redacted, forms = redactor.scan_and_redact_text(raw_text)

    assert secret not in redacted
    assert REDACTED_CANARY_PLACEHOLDER in redacted
    assert "raw" in forms


def test_canary_redaction_base64_encoded() -> None:
    secret = "CANARY_DEV_SECRET_DIRECT_987654321"
    b64_val = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
    config = CanaryConfig(synthetic_canary=secret)
    redactor = CanaryRedactor(config)

    sample = f"Token: {b64_val} (encoded in base64)"
    redacted, forms = redactor.scan_and_redact_text(sample)

    assert b64_val not in redacted
    assert REDACTED_CANARY_PLACEHOLDER in redacted
    assert "base64" in forms


def test_canary_redaction_hex_encoded() -> None:
    secret = "CANARY_DEV_SECRET_DIRECT_987654321"
    hex_val = secret.encode("utf-8").hex()
    config = CanaryConfig(synthetic_canary=secret)
    redactor = CanaryRedactor(config)

    sample = f"HexDump: {hex_val}"
    redacted, forms = redactor.scan_and_redact_text(sample)

    assert hex_val not in redacted
    assert REDACTED_CANARY_PLACEHOLDER in redacted
    assert "hex" in forms


def test_canary_redaction_concatenated_variant() -> None:
    secret = "CANARY_DEV_SECRET_DIRECT_987654321"
    hyphenated = secret.replace("_", "-")
    config = CanaryConfig(synthetic_canary=secret)
    redactor = CanaryRedactor(config)

    sample = f"Concatenated: {hyphenated}"
    redacted, forms = redactor.scan_and_redact_text(sample)

    assert hyphenated not in redacted
    assert REDACTED_CANARY_PLACEHOLDER in redacted
    assert "concatenated" in forms


def test_canary_redaction_nested_pydantic_model() -> None:
    secret = "CANARY_DEV_SECRET_DIRECT_987654321"
    config = CanaryConfig(synthetic_canary=secret)
    redactor = CanaryRedactor(config)

    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=1, end_line=1)
    f = Finding(
        id="VULN-001",
        location=loc,
        category=VulnerabilityCategory.HARDCODED_SECRET,
        severity=Severity.HIGH,
        explanation=f"Exposed token {secret}",
        evidence=f"API_KEY = '{secret}'",
        source_view=SourceView.RAW,
    )

    redacted_f, forms = redactor.redact_data(f)
    assert secret not in redacted_f.explanation
    assert secret not in redacted_f.evidence
    assert REDACTED_CANARY_PLACEHOLDER in redacted_f.explanation
    assert "raw" in forms


def test_canary_config_rejects_live_credentials() -> None:
    with pytest.raises(ValueError, match="Real credentials must NEVER be configured"):
        CanaryConfig(synthetic_canary="sk-live-fake-1234567890")


# =========================================================================
# 4. Blocked Access Classification Tests
# =========================================================================

def test_blocked_access_tool_unit_and_behavioral() -> None:
    collector = BlockedAccessCollector()

    collector.record_tool_unit_blocked(
        attempt="read_file",
        blocked_by="path_validation",
        details="Attempted traversal: ../../etc/shadow",
    )

    collector.record_behavioral_blocked(
        attempt="env_inspection",
        trigger="prompt_injection",
        blocked=True,
        details="Agent attempted to access /proc/self/environ",
    )

    telemetry = collector.build_blocked_access()
    assert len(telemetry.tool_unit) == 1
    assert telemetry.tool_unit[0].attempt == "read_file"
    assert telemetry.tool_unit[0].blocked_by == "path_validation"

    assert len(telemetry.behavioral) == 1
    assert telemetry.behavioral[0].attempt == "env_inspection"
    assert telemetry.behavioral[0].blocked is True


def test_sanitize_blocked_details_removes_host_paths() -> None:
    raw_details = r"Blocked access to C:\Users\john\secret.txt on host"
    sanitized = sanitize_blocked_details(raw_details)
    assert r"C:\Users\john" not in sanitized
    assert "<HOST_PATH>" in sanitized


# =========================================================================
# 5. Node 5 Reporter & Corroboration Engine Tests
# =========================================================================

def test_corroborated_findings_partitioning(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, stripped_ws = test_workspaces
    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=2, end_line=3)

    llm_finding = Finding(
        id="VULN-001",
        location=loc,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        explanation="SQL injection flaw",
        evidence="cursor.execute()",
        source_view=SourceView.RAW,
    )
    scanner_f = ScannerFinding(
        id="SCAN-BANDIT-001",
        rule_id="bandit.B608",
        location=loc,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        evidence="cursor.execute()",
    )

    reporter = Node5Reporter()
    report = reporter.generate_final_report(
        raw_findings=[llm_finding],
        stripped_findings=[],
        scanner_findings=[scanner_f],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
    )

    assert len(report.corroborated_findings) == 1
    assert report.corroborated_findings[0].id == "VULN-001"
    assert len(report.unverified_concerns) == 0
    assert len(report.scanner_findings) == 1


def test_unverified_concern_when_no_scanner_corroboration(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, stripped_ws = test_workspaces
    loc = Location(source_kind=SourceKind.SOURCE_FILE, path="auth.py", start_line=2, end_line=3)

    llm_finding = Finding(
        id="VULN-002",
        location=loc,
        category=VulnerabilityCategory.AUTH_BYPASS,  # No matching scanner finding
        severity=Severity.HIGH,
        explanation="Logic auth bypass",
        evidence="return True",
        source_view=SourceView.RAW,
    )

    reporter = Node5Reporter()
    report = reporter.generate_final_report(
        raw_findings=[llm_finding],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
    )

    assert len(report.corroborated_findings) == 0
    assert len(report.unverified_concerns) == 1
    assert report.unverified_concerns[0].id == "VULN-002"


# =========================================================================
# 6. Tool Failure & Infrastructure Failure Handling
# =========================================================================

def test_infrastructure_failure_when_scanner_fails(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, stripped_ws = test_workspaces
    failed_scan = ScanResult(
        tool_name="bandit",
        status=ScanStatus.FAILURE,
        error="Bandit process crashed with exit code 2",
    )

    reporter = Node5Reporter()
    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        tool_results={"bandit": failed_scan},
    )

    assert report.run_metadata.infrastructure_failure is True
    assert report.run_metadata.review_complete is False


def test_clean_scan_distinguished_from_failure(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, stripped_ws = test_workspaces
    clean_scan = ScanResult(
        tool_name="bandit",
        status=ScanStatus.SUCCESS,
        findings=[],  # 0 findings, clean execution
    )

    reporter = Node5Reporter()
    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        tool_results={"bandit": clean_scan},
    )

    assert report.run_metadata.infrastructure_failure is False
    assert report.run_metadata.review_complete is True


# =========================================================================
# 7. Deterministic JSON Serialization & Schema Validation
# =========================================================================

def test_deterministic_report_serialization(test_workspaces: tuple[Path, Path]) -> None:
    raw_ws, stripped_ws = test_workspaces
    reporter = Node5Reporter()
    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
    )

    json_str = report.model_dump_json(indent=2)
    assert isinstance(json_str, str)
    assert '"corroborated_findings": []' in json_str

    # Roundtrip validation
    reloaded = FinalReport.model_validate_json(json_str)
    assert reloaded.run_metadata.review_complete is True
