"""Safe parsing, path validation, and context limit enforcement for unified diff patches."""

import re
from pathlib import Path
from typing import Dict, Set

from src.materialization.path_safety import (
    MAX_CHANGED_BYTES_PER_PR,
    MAX_CHANGED_LINES_PER_PR,
    ContextLimitExceededError,
    PathSafetyError,
    normalize_relative_path,
    verify_path_containment,
)

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
OLD_FILE_RE = re.compile(r"^--- (?:a/(.+?)|/dev/null)(?:\t.*)?$")
NEW_FILE_RE = re.compile(r"^\+\+\+ (?:b/(.+?)|/dev/null)(?:\t.*)?$")


class MalformedPatchError(ValueError):
    """Raised when patch syntax is corrupt or invalid."""


class PatchSafetySummary:
    """Summary of patch inspection and safety validation."""

    def __init__(self) -> None:
        self.modified_files: Set[str] = set()
        self.additions: int = 0
        self.deletions: int = 0
        self.per_file_changes: Dict[str, int] = {}

    @property
    def total_changed_lines(self) -> int:
        return self.additions + self.deletions


def inspect_and_validate_patch(
    patch_content: str,
    workspace_root: Path,
) -> PatchSafetySummary:
    """Parse unified diff patch and strictly validate all paths and size limits.

    Fails closed on:
    - Paths escaping workspace root (traversal, absolute, NUL byte).
    - Exceeding MAX_CHANGED_LINES_PER_PR (2,500 lines).
    - Exceeding MAX_CHANGED_BYTES_PER_PR (125 KB).
    - Corrupt or malformed unified diff structure.
    """
    byte_size = len(patch_content.encode("utf-8"))
    if byte_size > MAX_CHANGED_BYTES_PER_PR:
        raise ContextLimitExceededError(
            f"Patch byte size ({byte_size} bytes) exceeds limit ({MAX_CHANGED_BYTES_PER_PR} bytes)."
        )

    summary = PatchSafetySummary()
    lines = patch_content.splitlines()

    current_file: str | None = None
    in_hunk = False

    for line_idx, line in enumerate(lines, start=1):
        if line.startswith("diff --git "):
            in_hunk = False
            m = DIFF_GIT_RE.match(line)
            if not m:
                raise MalformedPatchError(f"Malformed diff --git line {line_idx}: '{line}'")
            orig_path, new_path = m.group(1), m.group(2)
            # Both paths must pass path safety unless /dev/null
            if orig_path != "/dev/null":
                try:
                    norm_orig = normalize_relative_path(orig_path)
                    verify_path_containment(workspace_root, norm_orig)
                except PathSafetyError as err:
                    raise PathSafetyError(
                        f"Patch diff line {line_idx} references unsafe path: {orig_path}"
                    ) from err
            if new_path != "/dev/null":
                try:
                    norm_new = normalize_relative_path(new_path)
                    verify_path_containment(workspace_root, norm_new)
                except PathSafetyError as err:
                    raise PathSafetyError(
                        f"Patch diff line {line_idx} references unsafe path: {new_path}"
                    ) from err
            current_file = norm_new if new_path != "/dev/null" else norm_orig
            summary.modified_files.add(current_file)
            if current_file not in summary.per_file_changes:
                summary.per_file_changes[current_file] = 0

        elif line.startswith("--- "):
            in_hunk = False
            m = OLD_FILE_RE.match(line)
            if not m:
                raise MalformedPatchError(f"Malformed '---' line {line_idx}: '{line}'")
            path = m.group(1)
            if path:
                norm = normalize_relative_path(path)
                verify_path_containment(workspace_root, norm)

        elif line.startswith("+++ "):
            in_hunk = False
            m = NEW_FILE_RE.match(line)
            if not m:
                raise MalformedPatchError(f"Malformed '+++' line {line_idx}: '{line}'")
            path = m.group(1)
            if path:
                norm = normalize_relative_path(path)
                verify_path_containment(workspace_root, norm)
                current_file = norm
                summary.modified_files.add(current_file)
                if current_file not in summary.per_file_changes:
                    summary.per_file_changes[current_file] = 0

        elif line.startswith("@@"):
            if not HUNK_HEADER_RE.match(line):
                raise MalformedPatchError(f"Malformed hunk header line {line_idx}: '{line}'")
            in_hunk = True

        elif in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                summary.additions += 1
                if current_file:
                    summary.per_file_changes[current_file] += 1
            elif line.startswith("-") and not line.startswith("---"):
                summary.deletions += 1
                if current_file:
                    summary.per_file_changes[current_file] += 1
            elif line.startswith(" ") or line == "":
                pass
            elif line.startswith("\\ No newline at end of file"):
                pass
            else:
                # Unexpected character inside hunk
                raise MalformedPatchError(
                    f"Invalid diff line inside hunk at line {line_idx}: '{line[:30]}'"
                )

    if summary.total_changed_lines > MAX_CHANGED_LINES_PER_PR:
        raise ContextLimitExceededError(
            f"Total changed lines in patch ({summary.total_changed_lines}) exceeds PR limit ({MAX_CHANGED_LINES_PER_PR})."
        )

    return summary
