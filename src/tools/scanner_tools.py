"""Restricted static analysis adapters for Semgrep and Bandit."""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List

from src.matching.rule_map import map_rule_to_category
from src.materialization.path_safety import (
    PathSafetyError,
    SecurityContainmentError,
    verify_path_containment,
)
from src.schemas.findings import ScannerFinding
from src.schemas.location import Location
from src.schemas.taxonomies import Severity, SourceKind, VulnerabilityCategory
from src.tools.base import ToolResult


def run_bandit(
    workspace_root: Path,
    relative_target: str = ".",
) -> ToolResult:
    """Execute pinned Bandit static analysis against raw files in the authorized workspace."""
    start_time = time.monotonic()
    clean_target = relative_target.strip()
    try:
        if clean_target in (".", ""):
            target_path = workspace_root.resolve()
        else:
            target_path = verify_path_containment(workspace_root, clean_target, must_exist=True)
    except (PathSafetyError, SecurityContainmentError) as err:
        return ToolResult.blocked(str(err))

    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return ToolResult.failure(
            "Bandit binary is not installed or available in the execution environment."
        )

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
            timeout=30,
            check=False,
        )
        duration = time.monotonic() - start_time
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ToolResult.failure(f"Failed to parse Bandit JSON output: {proc.stderr}")

        findings: List[ScannerFinding] = []
        for idx, item in enumerate(data.get("results", []), start=1):
            rule_id = f"bandit.{item.get('test_id')}"
            category = map_rule_to_category(rule_id) or VulnerabilityCategory.OTHER_LOGIC_SECURITY_BUG
            sev_str = item.get("issue_severity", "MEDIUM").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM

            # Normalize file path relative to workspace
            raw_path = Path(item.get("filename", "")).resolve()
            rel_file = raw_path.relative_to(workspace_root.resolve()).as_posix()

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
                    evidence=item.get("code", "").strip(),
                )
            )

        return ToolResult.ok(findings, duration_seconds=duration)

    except subprocess.TimeoutExpired:
        return ToolResult.failure("Bandit scan timed out after 30 seconds.")
    except Exception as exc:
        return ToolResult.failure(f"Bandit execution error: {exc}")


def run_semgrep(
    workspace_root: Path,
    config_rule: str = "auto",
) -> ToolResult:
    """Execute pinned Semgrep rules against raw files in the authorized workspace."""
    start_time = time.monotonic()

    # Disallow arbitrary remote rules, flags, or injection in config argument
    if config_rule.startswith("-") or any(c in config_rule for c in " \t\r\n;&|><$`\\"):
        return ToolResult.blocked("Disallowed characters or flag prefix in Semgrep config rule.")

    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return ToolResult.failure(
            "Semgrep binary is not installed or available in the execution environment."
        )

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
            timeout=60,
            check=False,
        )
        duration = time.monotonic() - start_time
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ToolResult.failure(f"Failed to parse Semgrep JSON output: {proc.stderr}")

        findings: List[ScannerFinding] = []
        for idx, item in enumerate(data.get("results", []), start=1):
            check_id = item.get("check_id", "unknown")
            category = map_rule_to_category(check_id) or VulnerabilityCategory.OTHER_LOGIC_SECURITY_BUG
            sev_str = item.get("extra", {}).get("severity", "MEDIUM").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM

            raw_path = Path(item.get("path", "")).resolve()
            rel_file = raw_path.relative_to(workspace_root.resolve()).as_posix()

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
                    evidence=item.get("extra", {}).get("lines", "").strip(),
                )
            )

        return ToolResult.ok(findings, duration_seconds=duration)

    except subprocess.TimeoutExpired:
        return ToolResult.failure("Semgrep scan timed out after 60 seconds.")
    except Exception as exc:
        return ToolResult.failure(f"Semgrep execution error: {exc}")
