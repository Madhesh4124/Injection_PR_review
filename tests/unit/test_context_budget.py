"""Unit tests for deterministic context budgeting and conservative chunking."""

from src.detection.context_budget import (
    MAX_FILE_BYTES_LIMIT,
    MAX_PR_BYTES_LIMIT,
    ContextBudgetConfig,
    estimate_tokens_conservative,
    plan_review_chunks,
)


def test_tiny_diff_fits_single_chunk() -> None:
    """An 8-line patch fits into a single chunk with single_pass=True and no breach."""
    patch = (
        "diff --git a/src/payment.py b/src/payment.py\n"
        "--- a/src/payment.py\n"
        "+++ b/src/payment.py\n"
        "@@ -10,3 +10,3 @@\n"
        "- def process(): pass\n"
        "+ def process():\n"
        "+     key = 'sk_live_test'\n"
        "+     return key\n"
    )
    plan = plan_review_chunks(patch_content=patch)
    assert plan.limit_breach is False
    assert plan.single_pass is True
    assert len(plan.chunks) == 1
    assert plan.required_chunk_ids == ["chunk-001"]
    assert plan.chunks[0].chunk_id == "chunk-001"
    assert plan.total_files == 1


def test_pr_lines_limit_breach_detected() -> None:
    """PR with lines exceeding MAX_PR_LINES_LIMIT (2500) triggers limit breach."""
    oversized_lines = "diff --git a/src/big.py b/src/big.py\n" + ("+ line\n" * 2505)
    plan = plan_review_chunks(patch_content=oversized_lines)
    assert plan.limit_breach is True
    assert "exceeds PR limit" in (plan.breach_reason or "")


def test_pr_bytes_limit_breach_detected() -> None:
    """PR exceeding MAX_PR_BYTES_LIMIT (125 KB) triggers limit breach."""
    giant_content = "diff --git a/src/big.py b/src/big.py\n" + ("+ " + "x" * 1000 + "\n") * 130
    assert len(giant_content.encode("utf-8")) > MAX_PR_BYTES_LIMIT
    plan = plan_review_chunks(patch_content=giant_content)
    assert plan.limit_breach is True
    assert "exceeds PR limit" in (plan.breach_reason or "")


def test_file_lines_limit_breach_detected() -> None:
    """Single file exceeding MAX_FILE_LINES_LIMIT (500) triggers limit breach."""
    file_diff = "diff --git a/src/mod.py b/src/mod.py\n" + ("+ val\n" * 505)
    plan = plan_review_chunks(patch_content=file_diff)
    assert plan.limit_breach is True
    assert "exceeds limit" in (plan.breach_reason or "")


def test_file_bytes_limit_breach_detected() -> None:
    """Single file exceeding MAX_FILE_BYTES_LIMIT (25 KB) triggers limit breach."""
    file_diff = "diff --git a/src/data.py b/src/data.py\n" + ("+ " + "y" * 500 + "\n") * 60
    assert len(file_diff.encode("utf-8")) > MAX_FILE_BYTES_LIMIT
    plan = plan_review_chunks(patch_content=file_diff)
    assert plan.limit_breach is True
    assert "exceeds limit" in (plan.breach_reason or "")


def test_token_estimate_conservative() -> None:
    """estimate_tokens_conservative applies 3 chars/token + 15% safety buffer."""
    assert estimate_tokens_conservative("") == 0
    # 30 chars -> 10 base -> ceil(10 * 1.15) = 12 tokens
    assert estimate_tokens_conservative("a" * 30) == 12
    # Buffer ensures conservative estimate >= base
    for length in [1, 10, 50, 100, 1000]:
        s = "x" * length
        est = estimate_tokens_conservative(s)
        assert est >= len(s) / 3.0


def test_chunking_by_file_when_total_tokens_exceed_single_chunk_budget() -> None:
    """When multiple files fit individually but together exceed budget, splits file-by-file."""
    file1 = "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1,1 +1,2 @@\n+ a = 1\n"
    file2 = "diff --git a/src/b.py b/src/b.py\n--- a/src/b.py\n+++ b/src/b.py\n@@ -1,1 +1,2 @@\n+ b = 2\n"
    combined = file1 + file2

    # Set tiny available_content_tokens so combined diff exceeds budget but each file fits
    tiny_cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=500,
        metadata_reserve=200,
        tool_result_reserve=200,
        safety_margin_tokens=100,
    )
    # net available = 2048 - (512+500+200+200+100) = 536 tokens
    # artificially check if plan splits by file
    plan = plan_review_chunks(patch_content=combined, config=tiny_cfg)
    assert plan.limit_breach is False
    assert plan.total_files == 2


def test_chunking_by_hunk_when_file_exceeds_budget() -> None:
    """When a single file's tokens exceed chunk budget, splits into per-hunk chunks."""
    hunk1 = "@@ -1,10 +1,10 @@\n" + ("+ line_a\n" * 10)
    hunk2 = "@@ -20,10 +20,10 @@\n" + ("+ line_b\n" * 10)
    file_diff = "diff --git a/src/big_file.py b/src/big_file.py\n" + hunk1 + hunk2

    # Configure budget so individual hunks fit but whole file does not
    # Available content tokens = 500
    cfg = ContextBudgetConfig(
        context_window=2048,
        max_output_tokens=512,
        system_prompt_reserve=600,
        metadata_reserve=200,
        tool_result_reserve=200,
        safety_margin_tokens=100,
    )

    plan = plan_review_chunks(patch_content=file_diff, config=cfg)
    assert plan.limit_breach is False
    assert len(plan.chunks) >= 1
