"""Whitelisted node adapters wrapping pipeline stages for LangGraph execution."""

import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from src.detection.detector import Node4InjectionDetector, detect_deterministic_waiver_injection
from src.detection.paired_reviewer import Node3PairedReviewer
from src.detection.provider import LLMProvider
from src.materialization.patcher import _parse_hunk, _split_diff_into_file_patches
from src.materialization.path_safety import normalize_relative_path, verify_path_containment
from src.materialization.stripper import strip_file_content
from src.reporting.canary_redactor import CanaryConfig
from src.reporting.reporter import Node5Reporter
from src.scanning.models import ScanResult, ScanStatus
from src.scanning.runner import run_all_scanners
from src.schemas.report import BlockedAccess
from src.workflow.state import ReviewGraphState

logger = logging.getLogger(__name__)


def extract_files_from_diff(
    patch_content: str,
    planted_bugs: Optional[List[Any]] = None,
) -> Dict[str, str]:
    """Extract full file contents from a unified diff, padding lines to match planted bugs if given."""
    file_patches = _split_diff_into_file_patches(patch_content)
    extracted: Dict[str, str] = {}

    for fp in file_patches:
        target_path: Optional[str] = None
        for line in fp:
            if line.startswith("+++ b/"):
                target_path = line[6:].strip()
                break
            elif line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
                p = line[4:].strip()
                if p.startswith("b/"):
                    p = p[2:]
                target_path = p
                break

        if not target_path or target_path == "/dev/null":
            continue

        hunks: List[List[str]] = []
        current_hunk: List[str] = []
        for line in fp:
            if line.startswith("@@ "):
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = [line]
            elif current_hunk:
                current_hunk.append(line)
        if current_hunk:
            hunks.append(current_hunk)

        lines: List[str] = []
        curr_line = 1
        for hunk in hunks:
            old_start, old_count, new_start, new_count, ops = _parse_hunk(hunk)
            while curr_line < new_start:
                lines.append("")
                curr_line += 1
            for op, content in ops:
                if op in (" ", "+"):
                    lines.append(content)
                    curr_line += 1

        if planted_bugs:
            max_end = max(
                [
                    b.location.end_line
                    for b in planted_bugs
                    if getattr(b, "location", None) and b.location.path == target_path
                ]
                or [0]
            )
            indent = "    " if lines and lines[-1].startswith("    ") else ""
            while len(lines) < max_end + 5:
                lines.append(f"{indent}pass")

        code = "\n".join(lines) + "\n"
        if target_path.endswith(".py"):
            import ast
            try:
                ast.parse(code)
            except SyntaxError as err:
                raise ValueError(
                    f"Reconstructed Python file '{target_path}' is syntactically invalid: {err}. "
                    "Diff lacks required context or contains invalid Python syntax."
                ) from err

        extracted[target_path] = code

    return extracted


def node_1_materialize_adapter(state: ReviewGraphState) -> Dict[str, Any]:
    """Execute Node 1: Materialize dual workspaces and sanitize stripped view."""
    run_dir = state["run_dir"]
    patch_content = state.get("patch_content", "")
    planted_bugs = state.get("manifest_planted_bugs")

    raw_ws = run_dir / "raw"
    stripped_ws = run_dir / "stripped"
    raw_ws.mkdir(parents=True, exist_ok=True)
    stripped_ws.mkdir(parents=True, exist_ok=True)

    try:
        patched_files = extract_files_from_diff(patch_content, planted_bugs)
        readme_text: Optional[str] = None

        for rel_path, content in patched_files.items():
            # Validate containment
            norm_rel = normalize_relative_path(rel_path)
            verify_path_containment(raw_ws, norm_rel)
            raw_target = raw_ws / norm_rel
            raw_target.parent.mkdir(parents=True, exist_ok=True)

            fname = Path(rel_path).name
            if re.match(r"^README(\.[a-zA-Z0-9]+)?$", fname, re.IGNORECASE):
                readme_text = content
                raw_target.write_text(content, encoding="utf-8")
                continue

            raw_target.write_text(content, encoding="utf-8")

            verify_path_containment(stripped_ws, norm_rel)
            stripped_target = stripped_ws / norm_rel
            stripped_target.parent.mkdir(parents=True, exist_ok=True)
            stripped_bytes, _ = strip_file_content(content.encode("utf-8"), rel_path)
            stripped_target.write_bytes(stripped_bytes)

        return {
            "raw_workspace": raw_ws,
            "stripped_workspace": stripped_ws,
            "readme_content": readme_text,
            "materialization_success": True,
        }
    except Exception as exc:
        logger.error("Node 1 Materialization failed: %s", exc)
        return {
            "raw_workspace": raw_ws,
            "stripped_workspace": stripped_ws,
            "readme_content": None,
            "materialization_success": False,
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + [f"Node 1 Materialization error: {exc}"],
        }


def node_2_scanners_adapter(state: ReviewGraphState) -> Dict[str, Any]:
    """Execute Node 2: Pinned Bandit and Semgrep static analysis on raw workspace."""
    raw_ws = state.get("raw_workspace")
    if not raw_ws or not raw_ws.exists():
        return {
            "scanner_findings": [],
            "tool_results": {},
            "all_tools_successful": False,
            "any_tool_failed": True,
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + ["Node 2 raw_workspace missing"],
        }

    try:
        scan_output = run_all_scanners(raw_ws)
        return {
            "scanner_findings": list(scan_output.scanner_findings),
            "tool_results": scan_output.tool_results,
            "all_tools_successful": scan_output.all_tools_successful,
            "any_tool_failed": scan_output.any_tool_failed,
        }
    except Exception as exc:
        logger.error("Node 2 Scanners execution failed: %s", exc)
        err_res = ScanResult(
            tool_name="coordinator",
            status=ScanStatus.FAILURE,
            error=str(exc),
        )
        return {
            "scanner_findings": [],
            "tool_results": {"coordinator": err_res},
            "all_tools_successful": False,
            "any_tool_failed": True,
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + [f"Node 2 Scanners error: {exc}"],
        }


def node_3_paired_review_adapter(
    state: ReviewGraphState,
    provider: LLMProvider,
) -> Dict[str, Any]:
    """Execute Node 3: Paired raw/stripped LLM review.

    Trust Boundary Guardrail:
    - Never receives scanner_findings or tool_results.
    """
    raw_ws = state.get("raw_workspace")
    stripped_ws = state.get("stripped_workspace")
    patch_content = state.get("patch_content", "")
    pr_desc = state.get("pr_description", "")
    readme_content = state.get("readme_content")

    if not raw_ws or not stripped_ws:
        return {
            "raw_findings": [],
            "stripped_findings": [],
            "paired_review_complete": False,
            "unreviewed_files_truncated": False,
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + ["Node 3 workspaces missing"],
        }

    fixture_id = state.get("fixture_id", "unknown")
    run_idx = state.get("run_idx", 0)

    try:
        paired_reviewer = Node3PairedReviewer(provider=provider)
        paired_res = paired_reviewer.review_paired(
            raw_workspace=raw_ws,
            stripped_workspace=stripped_ws,
            raw_diff=patch_content,
            stripped_diff=patch_content,
            pr_description=pr_desc,
            readme_content=readme_content,
            scenario_id=fixture_id,
            run_index=run_idx,
        )

        errors = list(paired_res.raw_result.errors) + list(paired_res.stripped_result.errors)
        return {
            "raw_findings": paired_res.raw_findings,
            "stripped_findings": paired_res.stripped_findings,
            "paired_review_complete": paired_res.review_complete,
            "unreviewed_files_truncated": paired_res.unreviewed_files_truncated,
            "pipeline_errors": state.get("pipeline_errors", []) + errors,
        }
    except Exception as exc:
        logger.error("Node 3 Paired Reviewer crashed: %s", exc)
        return {
            "raw_findings": [],
            "stripped_findings": [],
            "paired_review_complete": False,
            "unreviewed_files_truncated": False,
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + [f"Node 3 PairedReviewer crash: {exc}"],
        }


def node_4_injection_detect_adapter(
    state: ReviewGraphState,
    provider: LLMProvider,
) -> Dict[str, Any]:
    """Execute Node 4: Structured prompt injection detection.

    Trust Boundary Guardrail:
    - Never receives scanner_findings or tool_results.
    """
    patch_content = state.get("patch_content", "")
    pr_desc = state.get("pr_description", "")
    readme_content = state.get("readme_content")
    fixture_id = state.get("fixture_id", "unknown")
    run_idx = state.get("run_idx", 0)

    try:
        detector = Node4InjectionDetector(provider=provider)
        det_res = detector.detect_injections(
            raw_diff=patch_content,
            pr_description=pr_desc,
            readme_content=readme_content,
            scenario_id=fixture_id,
            run_index=run_idx,
        )
        return {
            "injection_records": det_res.records,
            "injection_detection_error": det_res.error,
        }
    except Exception as exc:
        logger.error("Node 4 Injection Detector crashed: %s", exc)
        heuristic_records = detect_deterministic_waiver_injection(pr_desc, patch_content)
        return {
            "injection_records": heuristic_records,
            "injection_detection_error": str(exc),
            "infrastructure_failure": True,
            "pipeline_errors": state.get("pipeline_errors", []) + [f"Node 4 Detector crash: {exc}"],
        }


def node_5_report_adapter(state: ReviewGraphState) -> Dict[str, Any]:
    """Execute Node 5: Reconciliation, differential suppression, and final report generation."""
    canary_conf = CanaryConfig()
    reporter = Node5Reporter(canary_config=canary_conf)

    tool_results = state.get("tool_results", {})
    any_tool_failed = state.get("any_tool_failed", False)
    paired_complete = state.get("paired_review_complete", False)
    det_err = state.get("injection_detection_error")
    infra_fail = state.get("infrastructure_failure", False)

    # Invariant: Never report complete when a required tool or infrastructure failed
    review_complete = paired_complete and (det_err is None) and (not any_tool_failed) and (not infra_fail)
    infrastructure_failure = infra_fail or (not paired_complete) or (det_err is not None) or any_tool_failed

    run_dir = state["run_dir"]
    raw_ws = state.get("raw_workspace") or (run_dir / "raw")
    stripped_ws = state.get("stripped_workspace") or (run_dir / "stripped")

    final_rep = reporter.generate_final_report(
        raw_findings=state.get("raw_findings", []),
        stripped_findings=state.get("stripped_findings", []),
        scanner_findings=state.get("scanner_findings", []),
        injection_records=state.get("injection_records", []),
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        tool_results=tool_results,
        blocked_access=state.get("blocked_access", BlockedAccess()),
        model_id=state.get("model_id", "eval-model-v1"),
        benchmark_tag=state.get("benchmark_tag", "frozen-defended"),
        run_number=state.get("run_idx", 0) + 1,
        review_complete=review_complete,
        unreviewed_files_truncated=state.get("unreviewed_files_truncated", False),
        infrastructure_failure=infrastructure_failure,
        model_context_snippets=None if state.get("canary_session") is None else [],
        canary_session=state.get("canary_session"),
    )

    return {"final_report": final_rep}
