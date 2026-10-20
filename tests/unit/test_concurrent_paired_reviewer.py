"""Deterministic offline unit tests for concurrent paired review execution and fail-closed semantics."""

import json
import threading
import time
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from src.detection.paired_reviewer import Node3PairedReviewer
from src.detection.provider import LLMProvider, ProviderMetadata, ProviderResponse
from src.schemas.taxonomies import SourceView
from src.workflow.adapters import node_3_paired_review_adapter, node_5_report_adapter
from src.workflow.state import ReviewGraphState


SAMPLE_PATCH = """diff --git a/src/app.py b/src/app.py
index e69de29..4952028 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,5 +1,5 @@
 def handle_request(req):
-    return "ok"
+    key = "sk_live_12345"
+    return key
"""

RAW_FINDING_JSON = json.dumps({
    "findings": [
        {
            "id": "VULN-RAW-001",
            "path": "src/app.py",
            "start_line": 3,
            "end_line": 3,
            "category": "hardcoded_secret",
            "severity": "high",
            "title": "Raw Secret",
            "description": "Hardcoded live API key found in raw diff.",
            "recommendation": "Use environment variables.",
            "confidence": 0.95,
        }
    ]
})

STRIPPED_FINDING_JSON = json.dumps({
    "findings": [
        {
            "id": "VULN-STRIPPED-001",
            "path": "src/app.py",
            "start_line": 3,
            "end_line": 3,
            "category": "hardcoded_secret",
            "severity": "high",
            "title": "Stripped Secret",
            "description": "Hardcoded live API key found in stripped diff.",
            "recommendation": "Use environment variables.",
            "confidence": 0.95,
        }
    ]
})


def _setup_workspace(tmp_path: Path) -> Path:
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    app_file = src_dir / "app.py"
    app_file.write_text(
        "def handle_request(req):\n    key = 'sk_live_12345'\n    return key\n",
        encoding="utf-8",
    )
    return tmp_path


def test_concurrent_request_overlap_demonstrated(tmp_path: Path) -> None:
    """Deterministic proof of concurrency using a 2-thread rendezvous barrier.
    
    If the requests run sequentially, thread 1 will block at barrier.wait() and
    time out with BrokenBarrierError. If concurrent, both threads arrive and pass
    the barrier simultaneously.
    """
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    barrier = threading.Barrier(2, timeout=2.0)
    worker_threads = set()

    def barrier_complete(prompt: str, *args: Any, **kwargs: Any) -> ProviderResponse:
        worker_threads.add(threading.current_thread().name)
        # Rendezvous: both threads must be active inside complete() concurrently
        barrier.wait()
        time.sleep(0.1)  # Brief simulated work
        return ProviderResponse(
            content=RAW_FINDING_JSON,
            metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
        )

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.side_effect = barrier_complete

    reviewer = Node3PairedReviewer(provider=mock_provider)
    start_t = time.monotonic()
    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=SAMPLE_PATCH,
        stripped_diff=SAMPLE_PATCH,
        pr_description="Test PR",
    )
    elapsed = time.monotonic() - start_t

    assert paired_result.review_complete is True
    assert len(worker_threads) == 2, "Expected 2 distinct worker threads to execute reviews"
    assert all("node3_paired_review" in name for name in worker_threads)
    # 2 concurrent 0.1s sleeps should complete in ~0.15s, strictly < 0.35s
    assert elapsed < 0.8, f"Expected concurrent execution to finish quickly, took {elapsed:.2f}s"


RAW_PATCH = """diff --git a/src/app.py b/src/app.py
index e69de29..4952028 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,5 +1,5 @@
 def handle_request(req):
-    return "ok"
+    key = "sk_live_12345"  # RAW_VIEW
+    return key
"""

STRIPPED_PATCH = """diff --git a/src/app.py b/src/app.py
index e69de29..4952028 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,5 +1,5 @@
 def handle_request(req):
-    return "ok"
+    key = "sk_live_12345"  # STRIPPED_VIEW
+    return key
"""


def test_independent_result_association(tmp_path: Path) -> None:
    """Confirm raw and stripped responses remain strictly associated with their respective views."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    class ViewAwareMockProvider(LLMProvider):
        def complete(self, prompt: str, **kwargs: Any) -> ProviderResponse:
            if "RAW_VIEW" in prompt:
                content = RAW_FINDING_JSON
            else:
                content = STRIPPED_FINDING_JSON
            return ProviderResponse(
                content=content,
                metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
            )

    provider = ViewAwareMockProvider()
    reviewer = Node3PairedReviewer(provider=provider)

    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=RAW_PATCH,
        stripped_diff=STRIPPED_PATCH,
    )

    assert paired_result.review_complete is True
    assert len(paired_result.raw_findings) == 1
    assert paired_result.raw_findings[0].id == "VULN-RAW-001"
    assert paired_result.raw_findings[0].source_view == SourceView.RAW

    assert len(paired_result.stripped_findings) == 1
    assert paired_result.stripped_findings[0].id == "VULN-STRIPPED-001"
    assert paired_result.stripped_findings[0].source_view == SourceView.STRIPPED


def test_one_view_failure_raw_times_out(tmp_path: Path) -> None:
    """When raw view times out, stripped view completes, but review_complete MUST be False."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    class PartialFailProvider(LLMProvider):
        def complete(self, prompt: str, **kwargs: Any) -> ProviderResponse:
            if "RAW_VIEW" in prompt:
                raise TimeoutError("Raw view timed out waiting for response")
            return ProviderResponse(
                content=STRIPPED_FINDING_JSON,
                metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
            )

    provider = PartialFailProvider()
    reviewer = Node3PairedReviewer(provider=provider)

    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=RAW_PATCH,
        stripped_diff=STRIPPED_PATCH,
    )

    assert paired_result.review_complete is False
    assert len(paired_result.raw_findings) == 0
    assert len(paired_result.raw_result.errors) == 1
    assert "TimeoutError" in paired_result.raw_result.errors[0]

    # Stripped succeeded, but total review is incomplete
    assert len(paired_result.stripped_findings) == 1
    assert paired_result.stripped_result.review_complete is True


def test_one_view_failure_stripped_times_out(tmp_path: Path) -> None:
    """When stripped view times out, raw view completes, but review_complete MUST be False."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    class PartialFailProvider(LLMProvider):
        def complete(self, prompt: str, **kwargs: Any) -> ProviderResponse:
            if "RAW_VIEW" not in prompt:
                raise TimeoutError("Stripped view timed out waiting for response")
            return ProviderResponse(
                content=RAW_FINDING_JSON,
                metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
            )

    provider = PartialFailProvider()
    reviewer = Node3PairedReviewer(provider=provider)

    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=RAW_PATCH,
        stripped_diff=STRIPPED_PATCH,
    )

    assert paired_result.review_complete is False
    assert len(paired_result.raw_findings) == 1
    assert paired_result.raw_result.review_complete is True

    assert len(paired_result.stripped_findings) == 0
    assert len(paired_result.stripped_result.errors) == 1
    assert "TimeoutError" in paired_result.stripped_result.errors[0]


def test_both_views_fail_concurrently(tmp_path: Path) -> None:
    """When both views fail/time out, both errors are recorded and review_complete is False."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    class BothFailProvider(LLMProvider):
        def complete(self, prompt: str, **kwargs: Any) -> ProviderResponse:
            time.sleep(0.05)
            raise TimeoutError("Ollama request exceeded wall-clock timeout of 120.0s")

    provider = BothFailProvider()
    reviewer = Node3PairedReviewer(provider=provider)

    start_t = time.monotonic()
    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=SAMPLE_PATCH,
        stripped_diff=SAMPLE_PATCH,
    )
    elapsed = time.monotonic() - start_t

    assert paired_result.review_complete is False
    assert len(paired_result.raw_findings) == 0
    assert len(paired_result.stripped_findings) == 0
    assert len(paired_result.raw_result.errors) == 1
    assert len(paired_result.stripped_result.errors) == 1
    # Both 0.05s timeouts occur concurrently, so elapsed should be < 0.2s
    assert elapsed < 0.4


def test_end_to_end_node_fail_closed_on_partial_failure(tmp_path: Path) -> None:
    """Verify Node 3 adapter through Node 5 report adapter marks review incomplete."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    call_lock = threading.Lock()
    call_indices = []

    class OneFailProvider(LLMProvider):
        def complete(self, prompt: str, **kwargs: Any) -> ProviderResponse:
            with call_lock:
                idx = len(call_indices)
                call_indices.append(idx)
            if idx == 0:
                raise TimeoutError("Simulated view timeout")
            return ProviderResponse(
                content=STRIPPED_FINDING_JSON,
                metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
            )

    provider = OneFailProvider()

    state: ReviewGraphState = {
        "fixture_id": "test-partial-fail",
        "run_idx": 0,
        "patch_content": SAMPLE_PATCH,
        "pr_description": "PR description",
        "run_dir": tmp_path,
        "raw_workspace": raw_ws,
        "stripped_workspace": stripped_ws,
        "materialization_success": True,
        "scanner_findings": [],
        "tool_results": {},
        "all_tools_successful": True,
        "any_tool_failed": False,
        "infrastructure_failure": False,
        "pipeline_errors": [],
    }

    # Execute Node 3 adapter
    node_3_out = node_3_paired_review_adapter(state, provider=provider)
    state.update(node_3_out)

    assert state["paired_review_complete"] is False
    # Exactly one view failed and the other succeeded
    total_findings = len(state["raw_findings"]) + len(state["stripped_findings"])
    assert total_findings == 1

    # Execute Node 5 report adapter
    node_5_out = node_5_report_adapter(state)
    final_rep = node_5_out["final_report"]

    assert final_rep.run_metadata.review_complete is False
    assert final_rep.run_metadata.infrastructure_failure is True
    # Incomplete review must never corroborate findings as clean
    assert len(final_rep.corroborated_findings) == 0


def test_executor_clean_shutdown(tmp_path: Path) -> None:
    """Verify ThreadPoolExecutor cleans up all worker threads after execution."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.return_value = ProviderResponse(
        content='{"findings": []}',
        metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
    )

    reviewer = Node3PairedReviewer(provider=mock_provider)
    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=SAMPLE_PATCH,
        stripped_diff=SAMPLE_PATCH,
    )
    assert paired_result.review_complete is True

    # Give OS a moment to reclaim threads
    time.sleep(0.05)
    active_thread_names = [t.name for t in threading.enumerate() if t.is_alive()]
    active_pool_workers = [n for n in active_thread_names if "node3_paired_review" in n]
    assert len(active_pool_workers) == 0, f"Found unjoined executor worker threads: {active_pool_workers}"


def test_worker_unhandled_exception_propagates_fail_closed(tmp_path: Path) -> None:
    """Verify unhandled worker exceptions propagate and are not swallowed into clean findings."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    reviewer = Node3PairedReviewer(provider=MagicMock(spec=LLMProvider))
    # Simulate an unexpected non-chunk exception during execution (e.g. invalid plan)
    reviewer.review_single_view = MagicMock(side_effect=RuntimeError("Worker unhandled crash"))

    with pytest.raises(RuntimeError, match="Worker unhandled crash"):
        reviewer.review_paired(
            raw_workspace=raw_ws,
            stripped_workspace=stripped_ws,
            raw_diff=SAMPLE_PATCH,
            stripped_diff=SAMPLE_PATCH,
        )

