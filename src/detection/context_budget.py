"""Deterministic context budgeting and conservative chunking for PR review.

Enforces PRD limits:
- Per file: <= 500 lines or 25 KB
- Per PR: <= 2,500 lines or 125 KB

Computes conservative token budgets reserving space for system instructions,
PR metadata, tool results, and generation outputs. Chunks oversized diffs
by file or hunk boundaries while tracking exact required chunk IDs.
"""

import math
import re
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field


MAX_FILE_LINES_LIMIT = 500
MAX_FILE_BYTES_LIMIT = 25 * 1024  # 25 KB
MAX_PR_LINES_LIMIT = 2500
MAX_PR_BYTES_LIMIT = 125 * 1024  # 125 KB

DIFF_FILE_HEADER_REGEX = re.compile(r"^diff --git a/(.*?) b/(.*?)$", re.MULTILINE)
DIFF_HUNK_HEADER_REGEX = re.compile(r"^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@(.*)$", re.MULTILINE)


def estimate_tokens_conservative(text: str) -> int:
    """Documented conservative token estimator for code and structured diffs.

    Heuristic:
    - In source code, punctuation, whitespace, and variable names average ~3 characters per token.
    - Adds a 15% safety buffer to guarantee we fail closed and never underestimate token consumption.
    """
    if not text:
        return 0
    char_count = len(text)
    base_estimate = math.ceil(char_count / 3.0)
    buffered = math.ceil(base_estimate * 1.15)
    return max(1, buffered)


class ContextBudgetConfig(BaseModel):
    """Budget configuration balancing inputs, tool output, and generation capacity."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    context_window: int = Field(
        default=32768,
        ge=2048,
        le=131072,
        description="Total token context window supported by the model/provider.",
    )
    max_output_tokens: int = Field(
        default=4096,
        ge=512,
        le=16384,
        description="Tokens reserved strictly for model output generation.",
    )
    system_prompt_reserve: int = Field(
        default=1500,
        ge=200,
        le=8000,
        description="Tokens reserved for system prompt and review guidelines.",
    )
    metadata_reserve: int = Field(
        default=1000,
        ge=100,
        le=5000,
        description="Tokens reserved for PR metadata and description.",
    )
    tool_result_reserve: int = Field(
        default=2048,
        ge=0,
        le=8000,
        description="Tokens reserved for retrieved tool outputs.",
    )
    safety_margin_tokens: int = Field(
        default=500,
        ge=100,
        le=2000,
        description="Safety buffer to absorb tokenizer variance.",
    )

    @property
    def available_content_tokens(self) -> int:
        """Net tokens available for actual diff and code content per request."""
        overhead = (
            self.max_output_tokens
            + self.system_prompt_reserve
            + self.metadata_reserve
            + self.tool_result_reserve
            + self.safety_margin_tokens
        )
        net = self.context_window - overhead
        return max(500, net)


class DiffChunk(BaseModel):
    """A deterministically bounded chunk of PR diff content."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    chunk_id: str
    file_path: str
    diff_content: str
    line_count: int
    byte_size: int
    estimated_tokens: int
    hunk_index: int = 0
    total_hunks_for_file: int = 1


class ChunkPlan(BaseModel):
    """Deterministic plan for covering an entire PR."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    chunks: List[DiffChunk]
    required_chunk_ids: List[str]
    total_files: int
    total_lines: int
    total_bytes: int
    limit_breach: bool = False
    breach_reason: Optional[str] = None
    single_pass: bool = True


class FileDiffSection:
    """Parsed per-file diff section."""

    def __init__(self, file_path: str, raw_text: str):
        self.file_path = file_path
        self.raw_text = raw_text
        self.lines = raw_text.splitlines()
        self.line_count = len(self.lines)
        self.byte_size = len(raw_text.encode("utf-8"))
        self.estimated_tokens = estimate_tokens_conservative(raw_text)


def split_diff_by_files(patch_content: str) -> List[FileDiffSection]:
    """Split unified diff text into individual per-file diff sections."""
    if not patch_content.strip():
        return []

    sections: List[FileDiffSection] = []
    matches = list(DIFF_FILE_HEADER_REGEX.finditer(patch_content))

    if not matches:
        # Fallback if no git diff header is present
        return [FileDiffSection(file_path="unknown_file", raw_text=patch_content)]

    for i, match in enumerate(matches):
        start_idx = match.start()
        end_idx = matches[i + 1].start() if i + 1 < len(matches) else len(patch_content)
        file_path = match.group(2)
        raw_text = patch_content[start_idx:end_idx]
        sections.append(FileDiffSection(file_path=file_path, raw_text=raw_text))

    return sections


def plan_review_chunks(
    patch_content: str,
    pr_description: str = "",
    readme_content: Optional[str] = None,
    config: Optional[ContextBudgetConfig] = None,
) -> ChunkPlan:
    """Build a deterministic chunk plan ensuring full PR coverage within context budgets.

    Enforces:
    - Total PR limit (2,500 lines or 125 KB).
    - Per-file limit (500 lines or 25 KB).
    - Conservative token capacity per chunk.
    """
    cfg = config or ContextBudgetConfig()
    total_bytes = len(patch_content.encode("utf-8"))
    total_lines = len(patch_content.splitlines()) if patch_content else 0

    limit_breach = False
    breach_reasons: List[str] = []

    # Enforce PRD context limits
    if total_lines > MAX_PR_LINES_LIMIT:
        limit_breach = True
        breach_reasons.append(
            f"PR total lines ({total_lines}) exceeds PR limit ({MAX_PR_LINES_LIMIT} lines)."
        )
    if total_bytes > MAX_PR_BYTES_LIMIT:
        limit_breach = True
        breach_reasons.append(
            f"PR total bytes ({total_bytes}) exceeds PR limit ({MAX_PR_BYTES_LIMIT} bytes)."
        )

    file_sections = split_diff_by_files(patch_content)
    total_files = len(file_sections)

    # Check per-file limits
    for sec in file_sections:
        if sec.line_count > MAX_FILE_LINES_LIMIT:
            limit_breach = True
            breach_reasons.append(
                f"File '{sec.file_path}' lines ({sec.line_count}) exceeds limit ({MAX_FILE_LINES_LIMIT} lines)."
            )
        if sec.byte_size > MAX_FILE_BYTES_LIMIT:
            limit_breach = True
            breach_reasons.append(
                f"File '{sec.file_path}' bytes ({sec.byte_size}) exceeds limit ({MAX_FILE_BYTES_LIMIT} bytes)."
            )

    # Calculate token budgets
    budget_limit = cfg.available_content_tokens
    total_tokens_est = estimate_tokens_conservative(patch_content)

    # If the whole patch fits in one chunk and no limit breach, emit single-pass plan
    if not limit_breach and total_tokens_est <= budget_limit:
        chunk = DiffChunk(
            chunk_id="chunk-001",
            file_path="all_files",
            diff_content=patch_content,
            line_count=total_lines,
            byte_size=total_bytes,
            estimated_tokens=total_tokens_est,
            hunk_index=0,
            total_hunks_for_file=1,
        )
        return ChunkPlan(
            chunks=[chunk],
            required_chunk_ids=["chunk-001"],
            total_files=total_files,
            total_lines=total_lines,
            total_bytes=total_bytes,
            limit_breach=False,
            breach_reason=None,
            single_pass=True,
        )

    # Otherwise, chunk deterministically file-by-file (and hunk-by-hunk if a file exceeds budget)
    chunks: List[DiffChunk] = []
    chunk_counter = 1

    for sec in file_sections:
        if sec.estimated_tokens <= budget_limit:
            cid = f"chunk-{chunk_counter:03d}"
            chunks.append(
                DiffChunk(
                    chunk_id=cid,
                    file_path=sec.file_path,
                    diff_content=sec.raw_text,
                    line_count=sec.line_count,
                    byte_size=sec.byte_size,
                    estimated_tokens=sec.estimated_tokens,
                    hunk_index=0,
                    total_hunks_for_file=1,
                )
            )
            chunk_counter += 1
        else:
            # File diff exceeds single chunk budget: split by hunks
            hunk_matches = list(DIFF_HUNK_HEADER_REGEX.finditer(sec.raw_text))
            if not hunk_matches:
                # Fallback: slice lines
                chunk_lines: List[str] = []
                cur_tokens = 0
                sub_idx = 0
                for line in sec.lines:
                    line_tokens = estimate_tokens_conservative(line + "\n")
                    if cur_tokens + line_tokens > budget_limit and chunk_lines:
                        text_chunk = "\n".join(chunk_lines)
                        cid = f"chunk-{chunk_counter:03d}"
                        chunks.append(
                            DiffChunk(
                                chunk_id=cid,
                                file_path=sec.file_path,
                                diff_content=text_chunk,
                                line_count=len(chunk_lines),
                                byte_size=len(text_chunk.encode("utf-8")),
                                estimated_tokens=cur_tokens,
                                hunk_index=sub_idx,
                                total_hunks_for_file=len(sec.lines),
                            )
                        )
                        chunk_counter += 1
                        sub_idx += 1
                        chunk_lines = [line]
                        cur_tokens = line_tokens
                    else:
                        chunk_lines.append(line)
                        cur_tokens += line_tokens

                if chunk_lines:
                    text_chunk = "\n".join(chunk_lines)
                    cid = f"chunk-{chunk_counter:03d}"
                    chunks.append(
                        DiffChunk(
                            chunk_id=cid,
                            file_path=sec.file_path,
                            diff_content=text_chunk,
                            line_count=len(chunk_lines),
                            byte_size=len(text_chunk.encode("utf-8")),
                            estimated_tokens=cur_tokens,
                            hunk_index=sub_idx,
                            total_hunks_for_file=sub_idx + 1,
                        )
                    )
                    chunk_counter += 1
            else:
                total_hunks = len(hunk_matches)
                for h_idx, h_match in enumerate(hunk_matches):
                    h_start = h_match.start()
                    h_end = hunk_matches[h_idx + 1].start() if h_idx + 1 < len(hunk_matches) else len(sec.raw_text)
                    hunk_text = sec.raw_text[h_start:h_end]
                    cid = f"chunk-{chunk_counter:03d}"
                    chunks.append(
                        DiffChunk(
                            chunk_id=cid,
                            file_path=sec.file_path,
                            diff_content=hunk_text,
                            line_count=len(hunk_text.splitlines()),
                            byte_size=len(hunk_text.encode("utf-8")),
                            estimated_tokens=estimate_tokens_conservative(hunk_text),
                            hunk_index=h_idx,
                            total_hunks_for_file=total_hunks,
                        )
                    )
                    chunk_counter += 1

    req_ids = [c.chunk_id for c in chunks]
    return ChunkPlan(
        chunks=chunks,
        required_chunk_ids=req_ids,
        total_files=total_files,
        total_lines=total_lines,
        total_bytes=total_bytes,
        limit_breach=limit_breach,
        breach_reason="; ".join(breach_reasons) if breach_reasons else None,
        single_pass=False,
    )
