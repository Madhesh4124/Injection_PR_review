"""Unit tests for context budgeting, conservative token estimation, and Node 3 Paired Reviewer."""

import json
from pathlib import Path
import pytest

from src.detection.context_budget import (
    ContextBudgetConfig,
    estimate_tokens_conservative,
    plan_review_chunks,
)
from src.detection.paired_reviewer import (
    Node3PairedReviewer,
    parse_findings_from_llm_output,
)
from src.detection.provider import LLMProvider, MockLLMProvider, ProviderResponse
from src.schemas.findings import Finding
from src.schemas.taxonomies import Severity, SourceView, VulnerabilityCategory


def test_conservative_token_estimator():
    """Verify conservative token estimator adds documented safety buffer and handles empty text."""
    assert estimate_tokens_conservative("") == 0
    # 30 chars -> 10 base tokens * 1.15 buffer = 12 tokens
    est = estimate_tokens_conservative("a" * 30)
    assert est == 12
    # Guaranteed >= 1 for non-empty text (1 char -> 1 base * 1.15 -> 2 buffered)
    assert estimate_tokens_conservative("x") == 2


def test_chunk_planning_small_diff_single_pass():
    """Verify small PR diff within budget emits a single-pass plan."""
    patch = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        "-def old(): pass\n"
        "+def new(): pass\n"
    )
    plan = plan_review_chunks(patch_content=patch, pr_description="Small refactor")

    assert not plan.limit_breach
    assert plan.single_pass
    assert len(plan.chunks) == 1
    assert plan.required_chunk_ids == ["chunk-001"]
    assert plan.chunks[0].chunk_id == "chunk-001"


def test_chunk_planning_oversized_pr_lines_limit():
    """Verify PR exceeding 2,500 lines sets limit_breach=True and records breach reason."""
    patch = "diff --git a/huge.py b/huge.py\n" + ("+line\n" * 2600)
    plan = plan_review_chunks(patch_content=patch)

    assert plan.limit_breach
    assert "exceeds PR limit (2500 lines)" in (plan.breach_reason or "")


def test_chunk_planning_oversized_pr_bytes_limit():
    """Verify PR exceeding 125 KB sets limit_breach=True."""
    # 130 KB of diff
    patch = "diff --git a/big.py b/big.py\n" + ("+" + "x" * 99 + "\n") * 1350
    plan = plan_review_chunks(patch_content=patch)

    assert plan.limit_breach
    assert "exceeds PR limit (128000 bytes)" in (plan.breach_reason or "")


def test_chunk_planning_oversized_file_lines_limit():
    """Verify individual file exceeding 500 lines sets limit_breach=True."""
    patch = "diff --git a/long_file.py b/long_file.py\n" + ("+code_line\n" * 550)
    plan = plan_review_chunks(patch_content=patch)

    assert plan.limit_breach
    assert "exceeds limit (500 lines)" in (plan.breach_reason or "")


def test_chunk_planning_multi_file_chunking():
    """Verify multi-file PR exceeding budget is deterministically chunked."""
    file1 = "diff --git a/f1.py b/f1.py\n" + ("+line1\n" * 200)
    file2 = "diff --git a/f2.py b/f2.py\n" + ("+line2\n" * 200)
    patch = file1 + file2

    # Restrict budget so both files cannot fit in one chunk
    cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=200,
        metadata_reserve=100,
        tool_result_reserve=100,
        safety_margin_tokens=100,
    )
    plan = plan_review_chunks(patch_content=patch, config=cfg)

    assert not plan.limit_breach
    assert not plan.single_pass
    assert len(plan.chunks) >= 2
    assert plan.required_chunk_ids == ["chunk-001", "chunk-002"]


def test_paired_reviewer_successful_complete_coverage(tmp_path: Path):
    """Verify paired review succeeds and validates findings when all chunks pass."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    # Create dummy source files
    (raw_ws / "auth.py").write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
    (stripped_ws / "auth.py").write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

    diff = (
        "diff --git a/auth.py b/auth.py\n"
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -1,3 +1,3 @@\n"
        "-line1\n"
        "+line1_vuln\n"
    )

    mock_json = json.dumps({
        "findings": [
            {
                "id": "V-1",
                "path": "auth.py",
                "start_line": 2,
                "end_line": 3,
                "category": "sql_injection",
                "severity": "CRITICAL",
                "explanation": "SQL query concatenation.",
                "evidence": "SELECT *",
            }
        ]
    })
    provider = MockLLMProvider(canned_response=mock_json)
    reviewer = Node3PairedReviewer(provider=provider)

    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=diff,
        stripped_diff=diff,
    )

    assert res.review_complete
    assert not res.unreviewed_files_truncated
    assert len(res.raw_findings) == 1
    assert len(res.stripped_findings) == 1
    assert res.raw_findings[0].category == VulnerabilityCategory.SQL_INJECTION
    assert res.raw_findings[0].severity == Severity.CRITICAL


def test_paired_reviewer_missing_chunk_fails_closed(tmp_path: Path):
    """Verify that a provider error during any chunk sets review_complete=False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "f.py").write_text("code\n" * 10, encoding="utf-8")
    (stripped_ws / "f.py").write_text("code\n" * 10, encoding="utf-8")

    diff = "diff --git a/f.py b/f.py\n+new_code\n"

    # Provider that raises an error
    class ErrorProvider(LLMProvider):
        def complete(self, prompt, **kwargs):
            raise RuntimeError("Provider connection timeout")

    reviewer = Node3PairedReviewer(provider=ErrorProvider())
    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=diff,
        stripped_diff=diff,
    )

    assert not res.review_complete
    assert not res.unreviewed_files_truncated
    assert len(res.raw_result.errors) > 0


def test_paired_reviewer_oversized_pr_fails_closed(tmp_path: Path):
    """Verify that an oversized PR (>2,500 lines) immediately sets review_complete=False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    huge_diff = "diff --git a/huge.py b/huge.py\n" + ("+line\n" * 2600)
    provider = MockLLMProvider(canned_response='{"findings": []}')
    reviewer = Node3PairedReviewer(provider=provider)

    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=huge_diff,
        stripped_diff=huge_diff,
    )

    assert not res.review_complete
    assert res.unreviewed_files_truncated
    assert any("Context limit breach" in err for err in res.raw_result.errors)


def test_paired_reviewer_invalid_findings_rejected(tmp_path: Path):
    """Verify findings with non-existent files or line numbers out of bounds are rejected."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    (raw_ws / "valid.py").write_text("line1\nline2\n", encoding="utf-8")

    diff = "diff --git a/valid.py b/valid.py\n+change\n"

    mock_json = json.dumps({
        "findings": [
            # Invalid: references non-existent file
            {
                "id": "F-BAD-PATH",
                "path": "ghost.py",
                "start_line": 1,
                "end_line": 1,
                "category": "sql_injection",
                "severity": "HIGH",
            },
            # Invalid: line number exceeds file length (valid.py has 2 lines)
            {
                "id": "F-BAD-LINE",
                "path": "valid.py",
                "start_line": 50,
                "end_line": 55,
                "category": "command_injection",
                "severity": "CRITICAL",
            },
            # Valid finding
            {
                "id": "F-GOOD",
                "path": "valid.py",
                "start_line": 1,
                "end_line": 2,
                "category": "auth_bypass",
                "severity": "HIGH",
            },
        ]
    })
    provider = MockLLMProvider(canned_response=mock_json)
    reviewer = Node3PairedReviewer(provider=provider)

    view_res = reviewer.review_single_view(
        workspace_root=raw_ws,
        diff_text=diff,
        view=SourceView.RAW,
    )

    assert len(view_res.findings) == 1
    assert view_res.findings[0].category == VulnerabilityCategory.AUTH_BYPASS
    assert view_res.findings[0].location.path == "valid.py"


def test_parse_findings_malformed_llm_json():
    """Verify parsing handles markdown fences, valid empty findings, and rejects malformed/plain text safely."""
    # Valid explicit empty findings
    assert parse_findings_from_llm_output('{"findings": []}', SourceView.RAW) == []

    # Plain text without JSON fails closed with ValueError
    with pytest.raises(ValueError, match="LLM findings validation failed"):
        parse_findings_from_llm_output("No vulnerabilities found here.", SourceView.RAW)

    # Markdown fenced JSON
    fenced = "```json\n{\"findings\": [{\"path\": \"app.py\", \"start_line\": 1, \"category\": \"sql_injection\"}]}\n```"
    res1 = parse_findings_from_llm_output(fenced, SourceView.RAW)
    assert len(res1) == 1
    assert res1[0].category == VulnerabilityCategory.SQL_INJECTION
    assert res1[0].source_view == SourceView.RAW

    # Unfenced raw JSON with explicit view
    raw = '{"findings": [{"path": "db.py", "start_line": 5, "category": "hardcoded_secret"}]}'
    res2 = parse_findings_from_llm_output(raw, SourceView.STRIPPED)
    assert len(res2) == 1
    assert res2[0].source_view == SourceView.STRIPPED


def test_paired_reviewer_malformed_chunk_fails_closed(tmp_path: Path):
    """Verify that a malformed JSON response from a chunk sets review_complete=False fail-closed."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "app.py").write_text("code\n" * 5, encoding="utf-8")
    (stripped_ws / "app.py").write_text("code\n" * 5, encoding="utf-8")

    diff = "diff --git a/app.py b/app.py\n+new_code\n"

    # Provider returning invalid truncated JSON
    provider = MockLLMProvider(canned_response='{"findings": [{"path": "app.py", "start_line":')
    reviewer = Node3PairedReviewer(provider=provider)

    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=diff,
        stripped_diff=diff,
    )

    assert not res.review_complete
    assert not res.unreviewed_files_truncated
    assert len(res.raw_findings) == 0
    assert any("validation failed" in err for err in res.raw_result.errors)


def test_paired_reviewer_multi_chunk_partial_failure_fails_closed(tmp_path: Path):
    """Verify that if chunk 1 succeeds but chunk 2 fails with malformed JSON, review_complete is False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "f1.py").write_text("code\n" * 250, encoding="utf-8")
    (raw_ws / "f2.py").write_text("code\n" * 250, encoding="utf-8")
    (stripped_ws / "f1.py").write_text("code\n" * 250, encoding="utf-8")
    (stripped_ws / "f2.py").write_text("code\n" * 250, encoding="utf-8")

    diff = (
        "diff --git a/f1.py b/f1.py\n" + ("+line1\n" * 200) +
        "diff --git a/f2.py b/f2.py\n" + ("+line2\n" * 200)
    )

    def chunk_handler(prompt, system_prompt, temperature):
        if "f1.py" in prompt:
            return '{"findings": [{"path": "f1.py", "start_line": 5, "category": "sql_injection"}]}'
        else:
            return 'I found some issues but here is no JSON.'

    cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=200,
        metadata_reserve=100,
        tool_result_reserve=100,
        safety_margin_tokens=100,
    )
    reviewer = Node3PairedReviewer(provider=MockLLMProvider(handler=chunk_handler), config=cfg)

    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=diff,
        stripped_diff=diff,
    )

    assert not res.review_complete
    assert not res.unreviewed_files_truncated
    assert any("validation failed" in err for err in res.raw_result.errors)


def test_paired_reviewer_redacts_canary_and_keys_in_chunk_errors(tmp_path: Path):
    """Verify that chunk error logs and messages scrub API keys and canary secrets."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "f.py").write_text("code\n", encoding="utf-8")
    (stripped_ws / "f.py").write_text("code\n", encoding="utf-8")

    class LeakingErrorProvider(LLMProvider):
        def complete(self, prompt, **kwargs):
            raise RuntimeError(
                "Failed with sk-or-v1-9876543210abcdef and CANARY_SECRET_LEAK_123456"
            )

    reviewer = Node3PairedReviewer(provider=LeakingErrorProvider())
    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff="diff --git a/f.py b/f.py\n+c\n",
        stripped_diff="diff --git a/f.py b/f.py\n+c\n",
    )

    assert not res.review_complete
    assert not res.unreviewed_files_truncated
    for err in res.raw_result.errors:
        assert "sk-or-v1-9876543210abcdef" not in err
        assert "CANARY_SECRET_LEAK_123456" not in err
        assert "[REDACTED_KEY]" in err or "[REDACTED_CANARY]" in err


def test_paired_reviewer_provider_failure_without_limit_breach(tmp_path: Path):
    """F-03: Provider failure without limit breach sets review_complete=False and unreviewed_files_truncated=False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (stripped_ws / "main.py").write_text("print('hello')\n", encoding="utf-8")

    class ProviderHttpError(LLMProvider):
        def complete(self, prompt, **kwargs):
            raise ConnectionError("HTTP 502 Bad Gateway")

    reviewer = Node3PairedReviewer(provider=ProviderHttpError())
    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff="diff --git a/main.py b/main.py\n+print('hello')\n",
        stripped_diff="diff --git a/main.py b/main.py\n+print('hello')\n",
    )

    assert res.review_complete is False
    assert res.unreviewed_files_truncated is False
    assert any("HTTP 502 Bad Gateway" in err for err in res.raw_result.errors)


def test_paired_reviewer_malformed_model_output_without_limit_breach(tmp_path: Path):
    """F-03: Malformed output without limit breach sets review_complete=False and unreviewed_files_truncated=False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (stripped_ws / "main.py").write_text("print('hello')\n", encoding="utf-8")

    provider = MockLLMProvider(canned_response="This is raw prose without any JSON formatting.")
    reviewer = Node3PairedReviewer(provider=provider)
    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff="diff --git a/main.py b/main.py\n+print('hello')\n",
        stripped_diff="diff --git a/main.py b/main.py\n+print('hello')\n",
    )

    assert res.review_complete is False
    assert res.unreviewed_files_truncated is False
    assert len(res.raw_findings) == 0


def test_paired_reviewer_actual_file_limit_breach(tmp_path: Path):
    """F-03: Exceeding 500 lines per file sets review_complete=False and unreviewed_files_truncated=True."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    # Create oversized file exceeding MAX_FILE_LINES_LIMIT (500 lines)
    oversized_diff = "diff --git a/huge.py b/huge.py\n" + ("+x = 1\n" * 505)

    provider = MockLLMProvider(canned_response='{"findings": []}')
    reviewer = Node3PairedReviewer(provider=provider)
    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=oversized_diff,
        stripped_diff=oversized_diff,
    )

    assert res.review_complete is False
    assert res.unreviewed_files_truncated is True
    assert any("Context limit breach" in err for err in res.raw_result.errors)


def test_paired_reviewer_partial_chunk_failure_metadata(tmp_path: Path):
    """F-03: Partial chunk failure preserves successful chunk findings, sets review_complete=False, unreviewed_files_truncated=False."""
    raw_ws = tmp_path / "raw"
    raw_ws.mkdir()
    stripped_ws = tmp_path / "stripped"
    stripped_ws.mkdir()

    (raw_ws / "a.py").write_text("code\n" * 250, encoding="utf-8")
    (raw_ws / "b.py").write_text("code\n" * 250, encoding="utf-8")
    (stripped_ws / "a.py").write_text("code\n" * 250, encoding="utf-8")
    (stripped_ws / "b.py").write_text("code\n" * 250, encoding="utf-8")

    diff = (
        "diff --git a/a.py b/a.py\n" + ("+line_a_content_padding\n" * 200) +
        "diff --git a/b.py b/b.py\n" + ("+line_b_content_padding\n" * 200)
    )

    call_count = {"count": 0}

    def chunk_handler(prompt, system_prompt, temperature):
        call_count["count"] += 1
        if "a.py" in prompt:
            return '{"findings": [{"path": "a.py", "start_line": 10, "category": "hardcoded_secret"}]}'
        raise TimeoutError("Request timed out on second chunk")

    cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=200,
        metadata_reserve=100,
        tool_result_reserve=100,
        safety_margin_tokens=100,
    )
    reviewer = Node3PairedReviewer(provider=MockLLMProvider(handler=chunk_handler), config=cfg)

    res = reviewer.review_paired(
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        raw_diff=diff,
        stripped_diff=diff,
    )

    assert res.review_complete is False
    assert res.unreviewed_files_truncated is False
    # Finding from chunk 1 (a.py) is retained
    assert any(f.location.path == "a.py" for f in res.raw_findings)
    # Failure on chunk 2 (b.py) is recorded
    assert any("TimeoutError" in err for err in res.raw_result.errors)

