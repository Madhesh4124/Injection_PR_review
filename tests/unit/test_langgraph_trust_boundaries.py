"""Unit tests auditing security trust boundaries and invariants for LangGraph workflow.

Verifies:
1. Scanner findings are never passed to Node 3 (paired reviewer) or Node 4 (injection detector).
2. Materialization failure bypasses Nodes 2-4 with zero LLM calls.
3. Directory traversal in patch content is caught deterministically.
4. Clean patch requests preserve clean outputs without false positives.
"""

from pathlib import Path
from typing import Any, Dict, List
import pytest

from src.detection.provider import MockLLMProvider
from src.workflow.adapters import (
    node_1_materialize_adapter,
    node_3_paired_review_adapter,
    node_4_injection_detect_adapter,
)
from src.workflow.graph import build_review_graph
from src.workflow.state import ReviewGraphState
from src.schemas.findings import Finding, ScannerFinding
from src.schemas.location import Location
from src.schemas.taxonomies import Severity, SourceKind, VulnerabilityCategory


class CallCountingMockProvider(MockLLMProvider):
    """Mock LLM provider that counts calls to ensure zero LLM calls on bypassed paths."""

    def __init__(self, canned_response: str = '{"findings": [], "records": []}'):
        super().__init__(canned_response=canned_response)
        self.call_count = 0
        self.received_prompts: List[str] = []

    def complete(self, prompt: str, **kwargs: Any) -> str:
        self.call_count += 1
        self.received_prompts.append(prompt)
        return super().complete(prompt, **kwargs)


def test_scanner_findings_isolated_from_reviewer_and_detector_inputs() -> None:
    """Security Invariant: Scanner findings must NOT enter Node 3 or Node 4."""
    provider = CallCountingMockProvider()

    planted_scanner_secret = "CONFIDENTIAL_SCANNER_AST_SECRET_98765"
    scanner_finding = ScannerFinding(
        id="SCAN-001",
        rule_id="B608",
        location=Location(source_kind=SourceKind.SOURCE_FILE, path="src/app.py", start_line=10, end_line=10),
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        evidence=planted_scanner_secret,
    )

    state: ReviewGraphState = {
        "fixture_id": "test-isolation",
        "run_idx": 0,
        "patch_content": "diff --git a/src/app.py b/src/app.py\n@@ -1,1 +1,2 @@\n+print('hello')\n",
        "pr_description": "Clean patch.",
        "raw_workspace": Path("."),
        "stripped_workspace": Path("."),
        "scanner_findings": [scanner_finding],
        "tool_results": {},
    }

    # Run Node 3 adapter
    node_3_paired_review_adapter(state, provider=provider)
    for prompt in provider.received_prompts:
        assert planted_scanner_secret not in prompt, "Scanner finding leaked into Node 3 prompt!"

    # Run Node 4 adapter
    provider.received_prompts.clear()
    node_4_injection_detect_adapter(state, provider=provider)
    for prompt in provider.received_prompts:
        assert planted_scanner_secret not in prompt, "Scanner finding leaked into Node 4 prompt!"


def test_materialization_failure_bypasses_nodes_with_zero_llm_calls(tmp_path: Path) -> None:
    """Security Invariant: Materialization failure must short-circuit to report with zero LLM calls."""
    provider = CallCountingMockProvider()
    graph = build_review_graph(provider=provider)

    traversal_patch = (
        "diff --git a/../../etc/passwd b/../../etc/passwd\n"
        "--- a/../../etc/passwd\n"
        "+++ b/../../etc/passwd\n"
        "@@ -1,1 +1,1 @@\n"
        "+root:x:0:0::/root:/bin/sh\n"
    )

    state: ReviewGraphState = {
        "fixture_id": "test-traversal",
        "run_idx": 0,
        "patch_content": traversal_patch,
        "pr_description": "Attempting directory escape.",
        "scenario_category": "access_probe",
        "run_dir": tmp_path,
        "model_id": "mock-model",
        "benchmark_tag": "test-tag",
        "infrastructure_failure": False,
        "pipeline_errors": [],
    }

    final_state = graph.invoke(state)

    # 1. Zero LLM calls must be made
    assert provider.call_count == 0, f"Expected 0 LLM calls on materialization failure, got {provider.call_count}"

    # 2. Materialization must be marked failed
    assert final_state["materialization_success"] is False

    # 3. Report must fail closed
    report = final_state["final_report"]
    assert report is not None
    assert report.run_metadata.infrastructure_failure is True
    assert report.run_metadata.review_complete is False
    assert len(report.corroborated_findings) == 0
    assert len(report.unverified_concerns) == 0


def test_clean_request_preserves_clean_behavior(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean requests must preserve clean outcomes without false-positive failures."""
    from src.scanning.runner import AggregatedScanOutput
    from src.scanning.models import ScanResult, ScanStatus

    def mock_scanners(ws: Path):
        return AggregatedScanOutput(
            scanner_findings=[],
            tool_results={
                "bandit": ScanResult(tool_name="bandit", status=ScanStatus.SUCCESS),
                "semgrep": ScanResult(tool_name="semgrep", status=ScanStatus.SUCCESS),
            },
            all_tools_successful=True,
            any_tool_failed=False,
        )

    monkeypatch.setattr("src.workflow.adapters.run_all_scanners", mock_scanners)

    provider = CallCountingMockProvider(canned_response='{"findings": [], "records": []}')
    graph = build_review_graph(provider=provider)

    clean_patch = (
        "diff --git a/src/math_utils.py b/src/math_utils.py\n"
        "--- a/src/math_utils.py\n"
        "+++ b/src/math_utils.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+def add(a: int, b: int) -> int:\n"
        "+    return a + b\n"
    )

    state: ReviewGraphState = {
        "fixture_id": "test-clean",
        "run_idx": 0,
        "patch_content": clean_patch,
        "pr_description": "Clean math utility function.",
        "scenario_category": "clean",
        "run_dir": tmp_path,
        "model_id": "mock-model",
        "benchmark_tag": "test-tag",
        "infrastructure_failure": False,
        "pipeline_errors": [],
    }

    final_state = graph.invoke(state)

    assert final_state["materialization_success"] is True
    assert (tmp_path / "raw" / "src" / "math_utils.py").exists()
    assert (tmp_path / "stripped" / "src" / "math_utils.py").exists()

    report = final_state["final_report"]
    assert report is not None
    assert report.run_metadata.infrastructure_failure is False
    assert report.run_metadata.review_complete is True
    assert len(report.corroborated_findings) == 0
    assert len(report.unverified_concerns) == 0
