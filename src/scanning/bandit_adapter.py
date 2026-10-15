"""Bandit static analysis adapter with fixed configuration and version tracking."""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from src.matching.rule_map import map_rule_to_category
from src.materialization.path_safety import (
    PathSafetyError,
    SecurityContainmentError,
    verify_path_containment,
)
from src.schemas.findings import ScannerFinding
from src.schemas.location import Location
from src.schemas.taxonomies import Severity, SourceKind, VulnerabilityCategory
from src.scanning.models import ScanResult, ScanStatus

MAX_SCAN_OUTPUT_CHARS = 100_000
DEFAULT_BANDIT_TIMEOUT_SECONDS = 30.0


def get_bandit_version() -> Optional[str]:
    """Retrieve installed Bandit version, or None if unavailable."""
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return None
    try:
        proc = subprocess.run([bandit_bin, "--version"], capture_output=True, text=True, timeout=5, check=False)
        if proc.returncode == 0:
            return proc.stdout.strip().splitlines()[0]
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def run_bandit_scan(
    workspace_root: Path,
    relative_target: str = ".",
    timeout_seconds: float = DEFAULT_BANDIT_TIMEOUT_SECONDS,
) -> ScanResult:
    """Execute Bandit against raw repository files using pinned configurations."""
    start_time = time.monotonic()
    clean_target = relative_target.strip()

    try:
        if clean_target in (".", ""):
            target_path = workspace_root.resolve()
        else:
            target_path = verify_path_containment(workspace_root, clean_target, must_exist=True)
    except (PathSafetyError, SecurityContainmentError) as err:
        return ScanResult(
            tool_name="bandit",
            status=ScanStatus.BLOCKED,
            error=f"Security Boundary Enforced: {err}",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return ScanResult(
            tool_name="bandit",
            status=ScanStatus.TOOL_NOT_AVAILABLE,
            error="Bandit binary is not installed or available in PATH.",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

    version = get_bandit_version()
    cmd = [
        bandit_bin,
        "-r", str(target_path),
        "-f", "json",
        "-q",
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

        # Bandit returns exit code 0 (no issues) or 1 (issues found). Both are successful scans!
        # Exit code > 1 or syntax errors indicate scanner failure.
        if proc.returncode not in (0, 1):
            return ScanResult(
                tool_name="bandit",
                tool_version=version,
                status=ScanStatus.FAILURE,
                error=f"Bandit returned error exit code {proc.returncode}: {proc.stderr[:1000]}",
                raw_output=proc.stderr[:MAX_SCAN_OUTPUT_CHARS],
                duration_seconds=duration,
            )

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as json_err:
            return ScanResult(
                tool_name="bandit",
                tool_version=version,
                status=ScanStatus.FAILURE,
                error=f"Failed to parse Bandit JSON output: {json_err}",
                raw_output=proc.stdout[:MAX_SCAN_OUTPUT_CHARS],
                duration_seconds=duration,
            )

        findings: List[ScannerFinding] = []
        metrics = data.get("metrics", {}).get("_totals", {})
        files_scanned = metrics.get("loc", 0)

        for idx, item in enumerate(data.get("results", []), start=1):
            rule_id = f"bandit.{item.get('test_id')}"
            category = map_rule_to_category(rule_id) or VulnerabilityCategory.OTHER_LOGIC_SECURITY_BUG
            sev_str = item.get("issue_severity", "MEDIUM").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM

            # Normalize file path relative to workspace
            raw_path = Path(item.get("filename", "")).resolve()
            try:
                rel_file = raw_path.relative_to(workspace_root.resolve()).as_posix()
            except ValueError:
                rel_file = raw_path.name

            loc = Location(
                source_kind=SourceKind.SOURCE_FILE,
                path=rel_file,
                start_line=item.get("line_number", 1),
                end_line=item.get("line_range", [item.get("line_number", 1)])[-1],
            )
            findings.append(
                ScannerFinding(
                    id=f"SCAN-BANDIT-{idx:03d}",
                    rule_id=rule_id,
                    location=loc,
                    category=category,
                    severity=severity,
                    evidence=item.get("code", "").strip()[:500],
                )
            )

        return ScanResult(
            tool_name="bandit",
            tool_version=version,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=proc.stdout[:MAX_SCAN_OUTPUT_CHARS],
            duration_seconds=duration,
            files_scanned=files_scanned,
        )

    except subprocess.TimeoutExpired:
        return ScanResult(
            tool_name="bandit",
            tool_version=version,
            status=ScanStatus.TIMEOUT,
            error=f"Bandit scan timed out after {timeout_seconds} seconds.",
            duration_seconds=timeout_seconds,
        )
    except Exception as exc:
        return ScanResult(
            tool_name="bandit",
            tool_version=version,
            status=ScanStatus.FAILURE,
            error=f"Unexpected error running Bandit: {exc}",
            duration_seconds=round(time.monotonic() - start_time, 3),
        )
