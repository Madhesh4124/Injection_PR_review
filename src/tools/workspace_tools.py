"""Restricted filesystem tools operating strictly within an authorized workspace."""

import difflib
import os
import time
from pathlib import Path
from typing import List

from src.materialization.path_safety import (
    PathSafetyError,
    SecurityContainmentError,
    verify_path_containment,
)
from src.tools.base import MAX_TOOL_OUTPUT_CHARS, ToolResult

MAX_FILE_READ_BYTES = 64 * 1024  # 64 KB tool read limit


def list_files(
    workspace_root: Path,
    relative_dir: str = "",
) -> ToolResult:
    """List files within an authorized workspace view.

    Rejects directory traversal and symlink escapes.
    """
    start_time = time.monotonic()
    try:
        if relative_dir:
            target_dir = verify_path_containment(workspace_root, relative_dir, must_exist=True)
        else:
            target_dir = workspace_root.resolve()

        if not target_dir.is_dir():
            return ToolResult.failure(f"Path is not a directory: {relative_dir}")

        rel_files: List[str] = []
        root_resolved = workspace_root.resolve()

        for dirpath, _, filenames in os.walk(target_dir):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.is_symlink():
                    resolved = fpath.resolve()
                    try:
                        resolved.relative_to(root_resolved)
                    except ValueError:
                        return ToolResult.blocked(
                            f"Symlink escapes workspace root: {fpath} -> {resolved}"
                        )
                rel_posix = fpath.relative_to(root_resolved).as_posix()
                rel_files.append(rel_posix)

        rel_files.sort()
        duration = time.monotonic() - start_time
        return ToolResult.ok(rel_files, duration_seconds=duration)

    except (PathSafetyError, SecurityContainmentError) as err:
        return ToolResult.blocked(str(err))
    except Exception as exc:
        return ToolResult.failure(f"Error listing files: {exc}")


def read_file(
    workspace_root: Path,
    relative_path: str,
    max_bytes: int = MAX_FILE_READ_BYTES,
) -> ToolResult:
    """Read file content bounded strictly within the authorized workspace.

    Rejects absolute paths, '..' traversal, symlink escapes, and files > 64 KB.
    """
    start_time = time.monotonic()
    try:
        target = verify_path_containment(workspace_root, relative_path, must_exist=True)
        if not target.is_file():
            return ToolResult.failure(f"Target path is not a file: {relative_path}")

        file_size = target.stat().st_size
        if file_size > max_bytes:
            return ToolResult.blocked(
                f"File '{relative_path}' size ({file_size} bytes) exceeds limit ({max_bytes} bytes)."
            )

        content = target.read_text(encoding="utf-8", errors="replace")
        if len(content) > MAX_TOOL_OUTPUT_CHARS:
            content = content[:MAX_TOOL_OUTPUT_CHARS]

        duration = time.monotonic() - start_time
        return ToolResult.ok(
            {
                "path": relative_path,
                "content": content,
                "size_bytes": file_size,
                "line_count": len(content.splitlines()),
            },
            duration_seconds=duration,
        )

    except (PathSafetyError, SecurityContainmentError) as err:
        return ToolResult.blocked(str(err))
    except FileNotFoundError:
        return ToolResult.failure(f"File not found: {relative_path}")
    except Exception as exc:
        return ToolResult.failure(f"Error reading file: {exc}")


def inspect_diff(
    raw_workspace: Path,
    stripped_workspace: Path,
    relative_path: str,
) -> ToolResult:
    """Inspect the differential between raw and stripped source for a file."""
    start_time = time.monotonic()
    try:
        raw_file = verify_path_containment(raw_workspace, relative_path, must_exist=False)
        stripped_file = verify_path_containment(stripped_workspace, relative_path, must_exist=False)

        raw_lines = raw_file.read_text(encoding="utf-8").splitlines() if raw_file.exists() else []
        stripped_lines = stripped_file.read_text(encoding="utf-8").splitlines() if stripped_file.exists() else []

        diff = list(
            difflib.unified_diff(
                raw_lines,
                stripped_lines,
                fromfile=f"raw/{relative_path}",
                tofile=f"stripped/{relative_path}",
                lineterm="",
            )
        )
        diff_text = "\n".join(diff)[:MAX_TOOL_OUTPUT_CHARS]
        duration = time.monotonic() - start_time
        return ToolResult.ok(diff_text, duration_seconds=duration)

    except (PathSafetyError, SecurityContainmentError) as err:
        return ToolResult.blocked(str(err))
    except Exception as exc:
        return ToolResult.failure(f"Error inspecting diff: {exc}")
