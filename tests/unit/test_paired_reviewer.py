"""Unit tests for Node 3 Paired Reviewer and fail-closed coverage tracking."""

import json
from pathlib import Path
from unittest.mock import MagicMock

from src.detection.context_budget import ContextBudgetConfig
from src.detection.ollama_provider import OllamaOversizedInputError
from src.detection.paired_reviewer import Node3PairedReviewer
from src.detection.provider import LLMProvider, ProviderMetadata, ProviderResponse
from src.schemas.taxonomies import SourceView


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

VALID_FINDINGS_JSON = json.dumps({
    "findings": [
        {
            "id": "VULN-001",
            "path": "src/app.py",
            "start_line": 3,
            "end_line": 3,
            "category": "hardcoded_secret",
            "severity": "high",
            "title": "Hardcoded Secret",
            "description": "Hardcoded live API key found.",
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


def test_successful_single_chunk_review_complete(tmp_path: Path) -> None:
    """Mock provider returns valid JSON, verify review_complete=True with validated findings."""
    ws = _setup_workspace(tmp_path)
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.return_value = ProviderResponse(
        content=VALID_FINDINGS_JSON,
        metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
    )

    reviewer = Node3PairedReviewer(provider=mock_provider)
    result = reviewer.review_single_view(
        workspace_root=ws,
        diff_text=SAMPLE_PATCH,
        view=SourceView.RAW,
    )

    assert result.review_complete is True
    assert result.unreviewed_files_truncated is False
    assert len(result.findings) == 1
    assert result.findings[0].id == "VULN-001"
    assert result.findings[0].location.path == "src/app.py"
    assert result.findings[0].source_view == SourceView.RAW
    assert len(result.errors) == 0
    assert result.total_required_chunks == 1
    assert result.processed_chunk_ids == ["chunk-001"]


def test_chunk_failure_marks_review_incomplete(tmp_path: Path) -> None:
    """Mock provider raises TimeoutError, verify review_complete=False and fail-closed errors recorded."""
    ws = _setup_workspace(tmp_path)
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.side_effect = TimeoutError("The read operation timed out")

    reviewer = Node3PairedReviewer(provider=mock_provider)
    result = reviewer.review_single_view(
        workspace_root=ws,
        diff_text=SAMPLE_PATCH,
        view=SourceView.RAW,
    )

    assert result.review_complete is False
    assert result.unreviewed_files_truncated is False
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert "TimeoutError" in result.errors[0]
    assert len(result.processed_chunk_ids) == 0


def test_length_truncation_marks_review_incomplete(tmp_path: Path) -> None:
    """Mock provider raises OllamaOversizedInputError (done_reason='length'), verify review_complete=False."""
    ws = _setup_workspace(tmp_path)
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.side_effect = OllamaOversizedInputError(
        "Ollama generation truncated: context overflow for model test-model."
    )

    reviewer = Node3PairedReviewer(provider=mock_provider)
    result = reviewer.review_single_view(
        workspace_root=ws,
        diff_text=SAMPLE_PATCH,
        view=SourceView.RAW,
    )

    assert result.review_complete is False
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert "OllamaOversizedInputError" in result.errors[0]


def test_paired_review_requires_both_views(tmp_path: Path) -> None:
    """Raw view fails while stripped view succeeds; verify PairedReviewResult.review_complete=False."""
    raw_ws = _setup_workspace(tmp_path / "raw")
    stripped_ws = _setup_workspace(tmp_path / "stripped")

    call_count = 0

    def mock_complete(*args, **kwargs) -> ProviderResponse:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call is raw view -> fails
            raise TimeoutError("Raw view timed out")
        # Second call is stripped view -> succeeds
        return ProviderResponse(
            content=VALID_FINDINGS_JSON,
            metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
        )

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.side_effect = mock_complete

    reviewer = Node3PairedReviewer(provider=mock_provider)
    paired_result = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=SAMPLE_PATCH,
        stripped_diff=SAMPLE_PATCH,
    )

    assert paired_result.review_complete is False
    assert len(paired_result.raw_findings) == 0
    assert len(paired_result.stripped_findings) == 1


def test_partial_chunk_coverage_incomplete(tmp_path: Path) -> None:
    """Multi-chunk review where one chunk fails must produce review_complete=False."""
    ws = _setup_workspace(tmp_path)
    (ws / "src" / "b.py").write_text("def b(): pass\n", encoding="utf-8")

    # Each file has enough lines to exceed single-chunk budget under tiny config
    file1_lines = "\n".join(f"+ line_a_{i} = {i}" for i in range(120))
    file2_lines = "\n".join(f"+ line_b_{i} = {i}" for i in range(120))
    two_file_patch = (
        f"diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,121 @@\n{file1_lines}\n"
        f"diff --git a/src/b.py b/src/b.py\n--- a/src/b.py\n+++ b/src/b.py\n@@ -1,1 +1,121 @@\n{file2_lines}\n"
    )

    # Force multi-chunk by setting small context window
    tiny_cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=800,
        metadata_reserve=200,
        tool_result_reserve=200,
        safety_margin_tokens=100,
    )

    call_count = 0

    def mock_complete(*args, **kwargs) -> ProviderResponse:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return ProviderResponse(
                content='{"findings": []}',
                metadata=ProviderMetadata(provider_name="mock", model_name="mock-model"),
            )
        raise TimeoutError("Second chunk timed out")

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.complete.side_effect = mock_complete

    reviewer = Node3PairedReviewer(provider=mock_provider, config=tiny_cfg)
    result = reviewer.review_single_view(
        workspace_root=ws,
        diff_text=two_file_patch,
        view=SourceView.RAW,
    )

    assert result.review_complete is False
    assert len(result.errors) == 1
    assert "TimeoutError" in result.errors[0]


def test_limit_breach_marks_truncated_and_incomplete(tmp_path: Path) -> None:
    """Diff exceeding per-file line limit (500 lines) triggers limit_breach and review_complete=False."""
    ws = _setup_workspace(tmp_path)
    giant_diff = "diff --git a/src/app.py b/src/app.py\n" + ("+ line\n" * 505)

    mock_provider = MagicMock(spec=LLMProvider)
    reviewer = Node3PairedReviewer(provider=mock_provider)

    result = reviewer.review_single_view(
        workspace_root=ws,
        diff_text=giant_diff,
        view=SourceView.RAW,
    )

    assert result.review_complete is False
    assert result.unreviewed_files_truncated is True
    assert len(result.errors) == 1
    assert "Context limit breach" in result.errors[0]
    # Provider should never be called when limit breach is detected pre-flight
    assert mock_provider.complete.call_count == 0
