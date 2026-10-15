"""Safe pure-Python patch application for unified diffs.

Applies hunks to a staging workspace without executing shell commands or git on the host.
"""

from pathlib import Path
from typing import List, Tuple

from src.materialization.patch_safety import (
    HUNK_HEADER_RE,
    NEW_FILE_RE,
    OLD_FILE_RE,
    MalformedPatchError,
    inspect_and_validate_patch,
)
from src.materialization.path_safety import (
    normalize_relative_path,
    verify_path_containment,
)


class PatchApplicationError(ValueError):
    """Raised when a patch cannot be cleanly applied to workspace files."""


def _split_diff_into_file_patches(patch_content: str) -> List[List[str]]:
    """Split full patch into per-file diff line groups."""
    file_patches: List[List[str]] = []
    current_patch: List[str] = []

    for line in patch_content.splitlines():
        if line.startswith("diff --git "):
            if current_patch:
                file_patches.append(current_patch)
            current_patch = [line]
        elif current_patch:
            current_patch.append(line)

    if current_patch:
        file_patches.append(current_patch)

    return file_patches


def _parse_hunk(hunk_lines: List[str]) -> Tuple[int, int, int, int, List[Tuple[str, str]]]:
    """Parse a hunk header and hunk contents.

    Returns: (old_start, old_count, new_start, new_count, operations)
    operations: list of (op_type, content) where op_type in (' ', '-', '+', '\\')
    """
    header_line = hunk_lines[0]
    m = HUNK_HEADER_RE.match(header_line)
    if not m:
        raise MalformedPatchError(f"Invalid hunk header: '{header_line}'")

    old_start = int(m.group(1))
    old_count = int(m.group(2)) if m.group(2) is not None else 1
    new_start = int(m.group(3))
    new_count = int(m.group(4)) if m.group(4) is not None else 1

    ops: List[Tuple[str, str]] = []
    for line in hunk_lines[1:]:
        if not line:
            ops.append((" ", ""))
            continue
        op = line[0]
        content = line[1:]
        if op in (" ", "-", "+", "\\"):
            ops.append((op, content))
        else:
            raise MalformedPatchError(f"Invalid diff line in hunk: '{line[:30]}'")

    return old_start, old_count, new_start, new_count, ops


def _apply_file_hunks(
    original_lines: List[str],
    hunks: List[List[str]],
) -> List[str]:
    """Apply parsed hunks to original lines in order."""
    result_lines = list(original_lines)
    offset = 0

    for hunk_lines in hunks:
        old_start, old_count, new_start, new_count, ops = _parse_hunk(hunk_lines)
        # 1-indexed to 0-indexed with accumulated offset
        target_idx = (old_start - 1) + offset

        # Verify context and deletions against current lines
        check_idx = target_idx
        replacement_lines: List[str] = []
        lines_consumed = 0

        for op, content in ops:
            if op == " ":
                if check_idx < len(result_lines) and result_lines[check_idx] != content:
                    raise PatchApplicationError(
                        f"Context mismatch at line {check_idx + 1}: expected '{content}', got '{result_lines[check_idx]}'"
                    )
                check_idx += 1
                lines_consumed += 1
                replacement_lines.append(content)
            elif op == "-":
                if check_idx < len(result_lines) and result_lines[check_idx] != content:
                    raise PatchApplicationError(
                        f"Deletion mismatch at line {check_idx + 1}: expected '{content}', got '{result_lines[check_idx]}'"
                    )
                check_idx += 1
                lines_consumed += 1
            elif op == "+":
                replacement_lines.append(content)
            elif op == "\\":
                # '\ No newline at end of file'
                pass

        # Splice into result
        result_lines[target_idx: target_idx + lines_consumed] = replacement_lines
        offset += len(replacement_lines) - lines_consumed

    return result_lines


def apply_patch_to_workspace(
    workspace_root: Path,
    patch_content: str,
) -> List[str]:
    """Safely apply a unified diff patch to files in workspace_root.

    Returns the list of modified/created/deleted file paths.
    Fails closed on any containment escape or hunk mismatch.
    """
    inspect_and_validate_patch(patch_content, workspace_root)
    file_diffs = _split_diff_into_file_patches(patch_content)
    affected_files: List[str] = []

    for file_diff in file_diffs:
        old_file: str | None = None
        new_file: str | None = None
        hunk_blocks: List[List[str]] = []
        current_hunk: List[str] = []

        for line in file_diff:
            if line.startswith("--- "):
                m = OLD_FILE_RE.match(line)
                if m:
                    old_file = m.group(1)
            elif line.startswith("+++ "):
                m = NEW_FILE_RE.match(line)
                if m:
                    new_file = m.group(1)
            elif line.startswith("@@"):
                if current_hunk:
                    hunk_blocks.append(current_hunk)
                current_hunk = [line]
            elif current_hunk:
                current_hunk.append(line)

        if current_hunk:
            hunk_blocks.append(current_hunk)

        if new_file is None and old_file is None:
            continue

        # Case 1: File deletion
        if new_file == "/dev/null" or new_file is None:
            assert old_file is not None
            norm_old = normalize_relative_path(old_file)
            target = verify_path_containment(workspace_root, norm_old)
            if target.exists():
                target.unlink()
            affected_files.append(norm_old)
            continue

        # Case 2: File creation or modification
        norm_new = normalize_relative_path(new_file)
        target = verify_path_containment(workspace_root, norm_new)

        if old_file == "/dev/null" or not target.exists():
            original_lines = []
        else:
            original_content = target.read_text(encoding="utf-8")
            original_lines = original_content.splitlines()

        if hunk_blocks:
            patched_lines = _apply_file_hunks(original_lines, hunk_blocks)
        else:
            patched_lines = original_lines

        # Write out patched file
        target.parent.mkdir(parents=True, exist_ok=True)
        new_text = "\n".join(patched_lines)
        if patched_lines and not new_text.endswith("\n"):
            new_text += "\n"
        target.write_text(new_text, encoding="utf-8")
        affected_files.append(norm_new)

    return affected_files
