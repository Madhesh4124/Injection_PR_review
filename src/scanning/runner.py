"""Static analysis coordinator executing pinned scanners on raw workspace files."""

from pathlib import Path
from typing import Dict, List
from pydantic import BaseModel, ConfigDict, Field

from src.schemas.findings import ScannerFinding
from src.scanning.bandit_adapter import run_bandit_scan
from src.scanning.models import ScanResult, ScanStatus
from src.scanning.semgrep_adapter import run_semgrep_scan


class AggregatedScanOutput(BaseModel):
    """Immutable aggregate output from all configured static analysis scanners."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scanner_findings: List[ScannerFinding] = Field(default_factory=list)
    tool_results: Dict[str, ScanResult] = Field(default_factory=dict)
    all_tools_successful: bool = Field(default=False)
    any_tool_failed: bool = Field(default=False)


def run_all_scanners(
    workspace_root: Path,
    semgrep_rule: str = "p/python",
) -> AggregatedScanOutput:
    """Execute all configured static analysis tools and produce merged findings.

    Preserves failure distinctions; never equates tool failures with zero findings.
    """
    bandit_res = run_bandit_scan(workspace_root)
    semgrep_res = run_semgrep_scan(workspace_root, config_rule=semgrep_rule)

    tool_results = {
        "bandit": bandit_res,
        "semgrep": semgrep_res,
    }

    # Collect findings
    combined_findings: List[ScannerFinding] = []
    combined_findings.extend(bandit_res.findings)
    combined_findings.extend(semgrep_res.findings)

    all_successful = (
        bandit_res.status == ScanStatus.SUCCESS and semgrep_res.status == ScanStatus.SUCCESS
    )
    any_failed = (
        bandit_res.is_failure or semgrep_res.is_failure
    )

    return AggregatedScanOutput(
        scanner_findings=combined_findings,
        tool_results=tool_results,
        all_tools_successful=all_successful,
        any_tool_failed=any_failed,
    )
