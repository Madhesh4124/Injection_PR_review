"""Semgrep static analysis adapter with fixed configuration and version tracking."""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from src.matching.rule_map import map_rule_to_category
from src.schemas.findings import ScannerFinding
from src.schemas.location import Location
from src.schemas.taxonomies import Severity, SourceKind, VulnerabilityCategory
from src.scanning.models import ScanResult, ScanStatus

MAX_SEMGREP_OUTPUT_CHARS = 100_000
DEFAULT_SEMGREP_TIMEOUT_SECONDS = 60.0


def get_semgrep_version() -> Optional[str]:
    """Retrieve installed Semgrep version, or None if unavailable."""
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return None
    try:
        proc = subprocess.run([semgrep_bin, "--version"], capture_output=True, text=True, timeout=5, check=False)
        if proc.returncode == 0:
            return proc.stdout.strip().splitlines()[0]
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def run_semgrep_scan(
    workspace_root: Path,
    config_rule: str = "p/python",
    timeout_seconds: float = DEFAULT_SEMGREP_TIMEOUT_SECONDS,
) -> ScanResult:
    """Execute Semgrep against raw repository files using pinned rules."""
    start_time = time.monotonic()

    # Security check: Disallow flag injection, whitespace, and shell metacharacters
    if config_rule.startswith("-") or any(c in config_rule for c in " \t\r\n;&|><$`\\"):
        return ScanResult(
            tool_name="semgrep",
            status=ScanStatus.BLOCKED,
            error="Disallowed characters or flag prefix in Semgrep rule pack configuration.",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return ScanResult(
            tool_name="semgrep",
            status=ScanStatus.TOOL_NOT_AVAILABLE,
            error="Semgrep binary is not installed or available in PATH.",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

    version = get_semgrep_version()
    cmd = [
        semgrep_bin,
        "scan",
        "--config", config_rule,
        "--json",
        "--quiet",
        str(workspace_root.resolve()),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration = round(time.monotonic() - start_time, 3)

        if proc.returncode != 0:
            return ScanResult(
                tool_name="semgrep",
                tool_version=version,
                status=ScanStatus.FAILURE,
                error=f"Semgrep returned error exit code {proc.returncode}: {proc.stderr[:1000]}",
                raw_output=proc.stderr[:MAX_SEMGREP_OUTPUT_CHARS],
                duration_seconds=duration,
            )

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as json_err:
            return ScanResult(
                tool_name="semgrep",
                tool_version=version,
                status=ScanStatus.FAILURE,
                error=f"Failed to parse Semgrep JSON output: {json_err}",
                raw_output=proc.stdout[:MAX_SEMGREP_OUTPUT_CHARS],
                duration_seconds=duration,
            )

        findings: List[ScannerFinding] = []
        results_list = data.get("results", [])

        for idx, item in enumerate(results_list, start=1):
            check_id = item.get("check_id", "unknown")
            category = map_rule_to_category(check_id) or VulnerabilityCategory.OTHER_LOGIC_SECURITY_BUG
            raw_sev = str(item.get("extra", {}).get("severity", "MEDIUM")).upper()
            if raw_sev in ("ERROR", "CRITICAL"):
                severity = Severity.HIGH
            elif raw_sev in ("WARNING", "MEDIUM"):
                severity = Severity.MEDIUM
            elif raw_sev in ("INFO", "LOW"):
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM

            raw_path = Path(item.get("path", "")).resolve()
            try:
                rel_file = raw_path.relative_to(workspace_root.resolve()).as_posix()
            except ValueError:
                rel_file = raw_path.name

            loc = Location(
                source_kind=SourceKind.SOURCE_FILE,
                path=rel_file,
                start_line=item.get("start", {}).get("line", 1),
                end_line=item.get("end", {}).get("line", 1),
            )
            findings.append(
                ScannerFinding(
                    id=f"SCAN-SEMGREP-{idx:03d}",
                    rule_id=check_id,
                    location=loc,
                    category=category,
                    severity=severity,
                    evidence=item.get("extra", {}).get("lines", "").strip()[:500],
                )
            )

        return ScanResult(
            tool_name="semgrep",
            tool_version=version,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=proc.stdout[:MAX_SEMGREP_OUTPUT_CHARS],
            duration_seconds=duration,
            files_scanned=len(data.get("paths", {}).get("scanned", [])),
        )

    except subprocess.TimeoutExpired:
        return ScanResult(
            tool_name="semgrep",
            tool_version=version,
            status=ScanStatus.TIMEOUT,
            error=f"Semgrep scan timed out after {timeout_seconds} seconds.",
            duration_seconds=timeout_seconds,
        )
    except Exception as exc:
        return ScanResult(
            tool_name="semgrep",
            tool_version=version,
            status=ScanStatus.FAILURE,
            error=f"Unexpected error running Semgrep: {exc}",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )
