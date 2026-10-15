"""Unit tests for Bandit and Semgrep static-analysis adapters and runner."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.schemas.taxonomies import Severity, VulnerabilityCategory
from src.scanning.bandit_adapter import (
    get_bandit_version,
    run_bandit_scan,
)
from src.scanning.models import ScanResult, ScanStatus
from src.scanning.runner import AggregatedScanOutput, run_all_scanners
from src.scanning.semgrep_adapter import (
    get_semgrep_version,
    run_semgrep_scan,
)


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    """Create a temporary mock workspace with sample code."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    sample = ws / "app.py"
    sample.write_text("import os\nos.system('ls')\n", encoding="utf-8")
    return ws


# =========================================================================
# Bandit Adapter Tests
# =========================================================================

def test_bandit_version_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    mock_run = MagicMock()
    mock_run.returncode = 0
    mock_run.stdout = "bandit 1.7.5\n"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_run)

    version = get_bandit_version()
    assert version == "bandit 1.7.5"


def test_bandit_version_tool_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert get_bandit_version() is None


def test_bandit_tool_not_available(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)

    res = run_bandit_scan(mock_workspace)
    assert res.status == ScanStatus.TOOL_NOT_AVAILABLE
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert len(res.findings) == 0
    assert "not installed" in (res.error or "")


def test_bandit_clean_scan(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    monkeypatch.setattr("src.scanning.bandit_adapter.get_bandit_version", lambda: "bandit 1.7.5")

    clean_output = json.dumps({
        "results": [],
        "metrics": {"_totals": {"loc": 42}},
        "errors": [],
    })
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = clean_output
    mock_proc.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_bandit_scan(mock_workspace)
    assert res.status == ScanStatus.SUCCESS
    assert res.is_clean_scan is True
    assert res.is_failure is False
    assert len(res.findings) == 0
    assert res.tool_version == "bandit 1.7.5"
    assert res.files_scanned == 42


def test_bandit_finding_parsed_correctly(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    monkeypatch.setattr("src.scanning.bandit_adapter.get_bandit_version", lambda: "bandit 1.7.5")

    file_path = str(mock_workspace / "app.py")
    bandit_json = json.dumps({
        "results": [
            {
                "code": "os.system(user_input)\n",
                "filename": file_path,
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "issue_severity": "HIGH",
                "issue_text": "Starting a process with a shell, possible injection detected.",
                "line_number": 2,
                "line_range": [2],
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
            }
        ],
        "metrics": {"_totals": {"loc": 10}},
        "errors": [],
    })
    mock_proc = MagicMock()
    mock_proc.returncode = 1  # Bandit returns 1 when issues found
    mock_proc.stdout = bandit_json
    mock_proc.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_bandit_scan(mock_workspace)
    assert res.status == ScanStatus.SUCCESS
    assert res.is_clean_scan is False
    assert res.is_failure is False
    assert len(res.findings) == 1

    finding = res.findings[0]
    assert finding.id == "SCAN-BANDIT-001"
    assert finding.rule_id == "bandit.B602"
    assert finding.category == VulnerabilityCategory.COMMAND_CODE_EXECUTION
    assert finding.severity == Severity.HIGH
    assert finding.location.path == "app.py"
    assert finding.location.start_line == 2


def test_bandit_failure_never_interpreted_as_zero_findings(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-zero error code must be recorded as FAILURE, never as clean scan with 0 findings."""
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    monkeypatch.setattr("src.scanning.bandit_adapter.get_bandit_version", lambda: "bandit 1.7.5")

    mock_proc = MagicMock()
    mock_proc.returncode = 2  # Bandit error code (syntax error, crash)
    mock_proc.stdout = ""
    mock_proc.stderr = "SyntaxError: invalid syntax in file foo.py"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_bandit_scan(mock_workspace)
    assert res.status == ScanStatus.FAILURE
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert len(res.findings) == 0
    assert "error exit code 2" in (res.error or "")


def test_bandit_malformed_json_failure(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    monkeypatch.setattr("src.scanning.bandit_adapter.get_bandit_version", lambda: "bandit 1.7.5")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Corrupted non-JSON output"
    mock_proc.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_bandit_scan(mock_workspace)
    assert res.status == ScanStatus.FAILURE
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert "Failed to parse Bandit JSON output" in (res.error or "")


def test_bandit_timeout_bounded(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/bandit")
    monkeypatch.setattr("src.scanning.bandit_adapter.get_bandit_version", lambda: "bandit 1.7.5")

    def mock_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["bandit"], timeout=5.0)

    monkeypatch.setattr("subprocess.run", mock_timeout)

    res = run_bandit_scan(mock_workspace, timeout_seconds=5.0)
    assert res.status == ScanStatus.TIMEOUT
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert "timed out after 5.0 seconds" in (res.error or "")


def test_bandit_path_traversal_blocked(mock_workspace: Path) -> None:
    res = run_bandit_scan(mock_workspace, relative_target="../../outside")
    assert res.status == ScanStatus.BLOCKED
    assert res.is_failure is True
    assert "Security Boundary Enforced" in (res.error or "")


# =========================================================================
# Semgrep Adapter Tests
# =========================================================================

def test_semgrep_version_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/semgrep")
    mock_run = MagicMock()
    mock_run.returncode = 0
    mock_run.stdout = "1.45.0\n"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_run)

    version = get_semgrep_version()
    assert version == "1.45.0"


def test_semgrep_tool_not_available(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)

    res = run_semgrep_scan(mock_workspace)
    assert res.status == ScanStatus.TOOL_NOT_AVAILABLE
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert len(res.findings) == 0


def test_semgrep_clean_scan(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/semgrep")
    monkeypatch.setattr("src.scanning.semgrep_adapter.get_semgrep_version", lambda: "1.45.0")

    clean_output = json.dumps({
        "results": [],
        "errors": [],
        "paths": {"scanned": ["app.py"]},
    })
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = clean_output
    mock_proc.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_semgrep_scan(mock_workspace)
    assert res.status == ScanStatus.SUCCESS
    assert res.is_clean_scan is True
    assert res.is_failure is False
    assert len(res.findings) == 0
    assert res.files_scanned == 1


def test_semgrep_finding_parsed_correctly(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/semgrep")
    monkeypatch.setattr("src.scanning.semgrep_adapter.get_semgrep_version", lambda: "1.45.0")

    file_path = str(mock_workspace / "app.py")
    semgrep_json = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": file_path,
                "start": {"line": 15, "col": 5},
                "end": {"line": 15, "col": 40},
                "extra": {
                    "message": "User input in raw SQL query",
                    "severity": "ERROR",
                    "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                },
            }
        ],
        "paths": {"scanned": ["app.py"]},
    })
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = semgrep_json
    mock_proc.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_semgrep_scan(mock_workspace)
    assert res.status == ScanStatus.SUCCESS
    assert res.is_clean_scan is False
    assert len(res.findings) == 1

    finding = res.findings[0]
    assert finding.id == "SCAN-SEMGREP-001"
    assert finding.rule_id == "python.lang.security.audit.sqli"
    assert finding.category == VulnerabilityCategory.SQL_INJECTION
    assert finding.severity == Severity.HIGH  # ERROR mapped to HIGH
    assert finding.location.path == "app.py"
    assert finding.location.start_line == 15


def test_semgrep_command_injection_attempt_blocked(mock_workspace: Path) -> None:
    """Disallow shell metacharacters in rule pack parameter."""
    res = run_semgrep_scan(mock_workspace, config_rule="p/python; rm -rf /")
    assert res.status == ScanStatus.BLOCKED
    assert res.is_failure is True
    assert "Disallowed characters" in (res.error or "")


def test_semgrep_failure_never_interpreted_as_zero_findings(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/semgrep")
    monkeypatch.setattr("src.scanning.semgrep_adapter.get_semgrep_version", lambda: "1.45.0")

    mock_proc = MagicMock()
    mock_proc.returncode = 7  # Semgrep fatal error
    mock_proc.stdout = ""
    mock_proc.stderr = "Rule pack not found"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_proc)

    res = run_semgrep_scan(mock_workspace)
    assert res.status == ScanStatus.FAILURE
    assert res.is_failure is True
    assert res.is_clean_scan is False
    assert len(res.findings) == 0


def test_semgrep_timeout_bounded(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/semgrep")
    monkeypatch.setattr("src.scanning.semgrep_adapter.get_semgrep_version", lambda: "1.45.0")

    def mock_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["semgrep"], timeout=10.0)

    monkeypatch.setattr("subprocess.run", mock_timeout)

    res = run_semgrep_scan(mock_workspace, timeout_seconds=10.0)
    assert res.status == ScanStatus.TIMEOUT
    assert res.is_failure is True
    assert res.is_clean_scan is False


# =========================================================================
# Coordinator / Runner Tests
# =========================================================================

def test_run_all_scanners_all_clean(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clean_bandit = ScanResult(
        tool_name="bandit",
        tool_version="1.7.5",
        status=ScanStatus.SUCCESS,
        findings=[],
    )
    clean_semgrep = ScanResult(
        tool_name="semgrep",
        tool_version="1.45.0",
        status=ScanStatus.SUCCESS,
        findings=[],
    )

    monkeypatch.setattr("src.scanning.runner.run_bandit_scan", lambda *a, **kw: clean_bandit)
    monkeypatch.setattr("src.scanning.runner.run_semgrep_scan", lambda *a, **kw: clean_semgrep)

    output: AggregatedScanOutput = run_all_scanners(mock_workspace)
    assert output.all_tools_successful is True
    assert output.any_tool_failed is False
    assert len(output.scanner_findings) == 0


def test_run_all_scanners_partial_failure_distinguished(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If one scanner fails, any_tool_failed must be True and failure must not be masked."""
    failed_bandit = ScanResult(
        tool_name="bandit",
        status=ScanStatus.FAILURE,
        error="Bandit crashed",
    )
    clean_semgrep = ScanResult(
        tool_name="semgrep",
        tool_version="1.45.0",
        status=ScanStatus.SUCCESS,
        findings=[],
    )

    monkeypatch.setattr("src.scanning.runner.run_bandit_scan", lambda *a, **kw: failed_bandit)
    monkeypatch.setattr("src.scanning.runner.run_semgrep_scan", lambda *a, **kw: clean_semgrep)

    output: AggregatedScanOutput = run_all_scanners(mock_workspace)
    assert output.all_tools_successful is False
    assert output.any_tool_failed is True
    assert output.tool_results["bandit"].status == ScanStatus.FAILURE
    assert output.tool_results["semgrep"].status == ScanStatus.SUCCESS
