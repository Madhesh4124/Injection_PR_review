"""Deterministic path safety, normalization, and workspace containment checks."""

from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable, Union

# Bounded context and resource limits
MAX_LINES_PER_FILE = 500
MAX_BYTES_PER_FILE = 25 * 1024  # 25 KB
MAX_CHANGED_LINES_PER_PR = 2500
MAX_CHANGED_BYTES_PER_PR = 125 * 1024  # 125 KB
MAX_TOOL_READ_BYTES = 64 * 1024  # 64 KB
MAX_FILES_PER_FIXTURE = 100
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024  # 10 MB


class PathSafetyError(ValueError):
    """Raised when a path violates safety invariants (traversal, absolute, NUL byte)."""


class SecurityContainmentError(PathSafetyError):
    """Raised when a resolved path or symlink escapes the workspace root."""


class ContextLimitExceededError(ValueError):
    """Raised when file or PR context limits are breached."""


def normalize_relative_path(path: Union[str, Path]) -> str:
    """Validate and normalize a repository-relative path.

    Enforces:
    - No NUL bytes (\\x00).
    - No absolute paths (POSIX, Windows drive, or UNC).
    - No directory traversal ('..').
    - Normalized POSIX representation ('/' separators, stripped redundant dots/slashes).
    """
    raw_str = str(path).strip()
    if not raw_str:
        raise PathSafetyError("Path cannot be empty or whitespace only.")

    if "\x00" in raw_str:
        raise PathSafetyError(f"Path contains forbidden NUL byte: {repr(raw_str)}")

    # Check Windows and POSIX absolute markers
    p_posix = PurePosixPath(raw_str)
    p_win = PureWindowsPath(raw_str)
    if (
        p_posix.is_absolute()
        or p_win.is_absolute()
        or raw_str.startswith("/")
        or raw_str.startswith("\\")
        or (len(raw_str) >= 2 and raw_str[1] == ":")
    ):
        raise PathSafetyError(f"Absolute paths are forbidden: {raw_str}")

    # Standardize to forward slashes for cross-platform inspection
    normalized_str = raw_str.replace("\\", "/")
    parts = [p for p in normalized_str.split("/") if p and p != "."]

    for part in parts:
        clean_part = part.rstrip(". ")
        if not clean_part or clean_part == "..":
            raise PathSafetyError(f"Parent directory traversal or invalid component ('{part}') is forbidden: {raw_str}")
        if part.endswith(" ") or part.endswith("."):
            raise PathSafetyError(f"Path component with trailing dot or whitespace is forbidden on Windows: '{part}'")
        if any(c in part for c in '<>:"|?*'):
            raise PathSafetyError(f"Path component contains illegal characters: {part}")

    if not parts:
        raise PathSafetyError(f"Invalid path resolves to empty root: {raw_str}")

    return "/".join(parts)


def verify_path_containment(
    workspace_root: Path,
    relative_path: Union[str, Path],
    must_exist: bool = False,
) -> Path:
    """Verify that a path remains strictly within the workspace root after symlink resolution.

    Fails closed on symlink escapes or out-of-root resolution.
    """
    normalized = normalize_relative_path(relative_path)
    root_resolved = workspace_root.resolve()

    candidate = (root_resolved / normalized)

    # If the target exists (or its existing ancestor if creating new file), check symlinks
    if candidate.is_symlink() or candidate.exists():
        candidate_resolved = candidate.resolve()
        try:
            candidate_resolved.relative_to(root_resolved)
        except ValueError as err:
            raise SecurityContainmentError(
                f"Resolved path escapes workspace root: {candidate_resolved} (root: {root_resolved})"
            ) from err
    else:
        # Check closest existing parent or symlink for escapes
        curr = candidate
        while not (curr.exists() or curr.is_symlink()) and curr != root_resolved:
            curr = curr.parent

        if curr.is_symlink() or curr.exists():
            curr_resolved = curr.resolve()
            try:
                curr_resolved.relative_to(root_resolved)
            except ValueError as err:
                raise SecurityContainmentError(
                    f"Parent symlink escapes workspace root: {curr_resolved} (root: {root_resolved})"
                ) from err

        if must_exist:
            raise FileNotFoundError(f"Path does not exist: {candidate}")

    return candidate


def verify_archive_members_containment(
    member_names: Iterable[str],
    workspace_root: Path,
) -> None:
    """Verify an archive's members to prevent Zip-Slip / Tar-Slip escapes."""
    root_resolved = workspace_root.resolve()
    for member in member_names:
        # Normalize and verify
        normalized = normalize_relative_path(member)
        target = (root_resolved / normalized).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError as err:
            raise SecurityContainmentError(
                f"Archive member escapes workspace root: {member}"
            ) from err


def validate_file_content_limits(content: Union[str, bytes], path: str = "file") -> None:
    """Enforce per-file line and size limits."""
    if isinstance(content, str):
        byte_len = len(content.encode("utf-8"))
        line_count = len(content.splitlines())
    else:
        byte_len = len(content)
        line_count = len(content.split(b"\n"))

    if byte_len > MAX_BYTES_PER_FILE:
        raise ContextLimitExceededError(
            f"File '{path}' exceeds max size limit ({byte_len} bytes > {MAX_BYTES_PER_FILE} bytes)."
        )

    if line_count > MAX_LINES_PER_FILE:
        raise ContextLimitExceededError(
            f"File '{path}' exceeds max line limit ({line_count} lines > {MAX_LINES_PER_FILE} lines)."
        )
