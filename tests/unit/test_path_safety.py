"""Unit tests for path safety, normalization, and workspace containment."""

import os
from pathlib import Path
import pytest

from src.materialization.path_safety import (
    ContextLimitExceededError,
    PathSafetyError,
    SecurityContainmentError,
    normalize_relative_path,
    validate_file_content_limits,
    verify_archive_members_containment,
    verify_path_containment,
)


def test_normalize_relative_path_positive():
    """Verify standard relative paths are correctly normalized."""
    assert normalize_relative_path("src/auth.py") == "src/auth.py"
    assert normalize_relative_path("src//models///user.py") == "src/models/user.py"
    assert normalize_relative_path("./tests/unit/test.py") == "tests/unit/test.py"
    assert normalize_relative_path("README.md") == "README.md"
    # Windows-style backslashes normalized to forward slashes
    assert normalize_relative_path("src\\utils\\helpers.py") == "src/utils/helpers.py"


@pytest.mark.parametrize(
    "bad_path",
    [
        "/etc/passwd",
        "/root/secret",
        "C:\\Windows\\System32",
        "D:/Data/project",
        "\\\\network\\share\\file.txt",
        "//server/resource",
    ],
)
def test_reject_absolute_paths(bad_path: str):
    """Reject POSIX, Windows, and UNC absolute paths."""
    with pytest.raises(PathSafetyError, match="Absolute paths are forbidden"):
        normalize_relative_path(bad_path)


@pytest.mark.parametrize(
    "traversal_path",
    [
        "../secret.txt",
        "src/../../etc/shadow",
        "foo/bar/../../../baz",
        "..",
    ],
)
def test_reject_parent_directory_traversal(traversal_path: str):
    """Reject any path with '..' traversal components."""
    with pytest.raises(PathSafetyError, match="Parent directory traversal"):
        normalize_relative_path(traversal_path)


def test_reject_nul_bytes():
    """Reject paths containing NUL bytes."""
    with pytest.raises(PathSafetyError, match="forbidden NUL byte"):
        normalize_relative_path("src/auth.py\x00.exe")


def test_reject_empty_or_whitespace_paths():
    """Reject empty or whitespace paths."""
    with pytest.raises(PathSafetyError, match="cannot be empty"):
        normalize_relative_path("   ")


def test_symlink_containment_positive(tmp_path: Path):
    """Verify symlinks pointing within workspace pass containment verification."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target_file = workspace / "target.py"
    target_file.write_text("print('hello')", encoding="utf-8")

    link_path = workspace / "link.py"
    try:
        os.symlink(target_file, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this test environment")

    resolved = verify_path_containment(workspace, "link.py")
    assert resolved.resolve() == target_file.resolve()


def test_symlink_escape_rejected(tmp_path: Path):
    """Reject symlinks pointing outside workspace root."""
    outside_file = tmp_path / "secret_host.txt"
    outside_file.write_text("host secret", encoding="utf-8")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    escape_link = workspace / "leak_link.txt"

    try:
        os.symlink(outside_file, escape_link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this test environment")

    with pytest.raises(SecurityContainmentError, match="escapes workspace root"):
        verify_path_containment(workspace, "leak_link.txt")


def test_archive_members_escape_rejected(tmp_path: Path):
    """Reject zip-slip archive member paths attempting to escape workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Member with parent directory traversal
    with pytest.raises(PathSafetyError, match="Parent directory traversal"):
        verify_archive_members_containment(["safe.py", "../../outside.py"], workspace)


def test_file_line_and_byte_limits():
    """Enforce 500 lines per file and 25 KB limits."""
    # Under limit
    safe_content = "x = 1\n" * 400
    validate_file_content_limits(safe_content)

    # Exceeds 500 lines
    too_many_lines = "x = 1\n" * 501
    with pytest.raises(ContextLimitExceededError, match="exceeds max line limit"):
        validate_file_content_limits(too_many_lines)

    # Exceeds 25 KB
    large_content = "a" * (26 * 1024)
    with pytest.raises(ContextLimitExceededError, match="exceeds max size limit"):
        validate_file_content_limits(large_content)
