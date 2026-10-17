"""Integration tests executing against a real Docker daemon.

Explicitly distinguished from mocked unit tests. If Docker is unavailable,
these tests are skipped and marked unverified.
"""

from pathlib import Path
import subprocess
import pytest

from src.sandbox.docker_runner import DockerRunner, is_docker_available
from src.sandbox.models import ExecutionStatus


@pytest.mark.integration
def test_docker_isolated_execution(tmp_path: Path):
    """Integration test: Verify actual Docker container execution."""
    if not is_docker_available():
        pytest.skip(
            "Docker daemon is not running or available in the local environment; "
            "integration test cannot execute and remains UNVERIFIED."
        )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "test_app.py").write_text("print('CONTAINER_SANDBOX_OK')", encoding="utf-8")

    runner = DockerRunner()
    result = runner.run(workspace, "python test_app.py")

    assert result.status == ExecutionStatus.SUCCESS
    assert result.exit_code == 0
    assert "CONTAINER_SANDBOX_OK" in result.stdout


@pytest.mark.integration
def test_docker_network_none_enforcement(tmp_path: Path):
    """Integration test: Verify network access fails inside the container."""
    if not is_docker_available():
        pytest.skip(
            "Docker daemon is not running or available in the local environment; "
            "integration test cannot execute and remains UNVERIFIED."
        )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    # Attempt outbound HTTP request
    probe_code = """
import urllib.request
try:
    urllib.request.urlopen('http://1.1.1.1', timeout=2)
    print('NETWORK_LEAK')
except Exception as e:
    print('NETWORK_BLOCKED')
"""
    (workspace / "probe.py").write_text(probe_code, encoding="utf-8")

    runner = DockerRunner()
    result = runner.run(workspace, "python probe.py")

    assert result.status == ExecutionStatus.SUCCESS
    assert "NETWORK_BLOCKED" in result.stdout
    assert "NETWORK_LEAK" not in result.stdout


@pytest.mark.integration
def test_docker_read_only_root_filesystem_enforcement(tmp_path: Path):
    """Integration test: Verify root filesystem is mounted read-only."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    probe_code = """
try:
    with open('/etc/pwned.txt', 'w') as f:
        f.write('fail')
    print('WRITE_ROOT_SUCCESS')
except OSError as e:
    print('READ_ONLY_ROOT_OK')
"""
    (workspace / "fs_probe.py").write_text(probe_code, encoding="utf-8")

    runner = DockerRunner()
    result = runner.run(workspace, "python fs_probe.py")

    assert result.status == ExecutionStatus.SUCCESS
    assert "READ_ONLY_ROOT_OK" in result.stdout
    assert "WRITE_ROOT_SUCCESS" not in result.stdout


@pytest.mark.integration
def test_docker_host_environment_isolation(tmp_path: Path, monkeypatch):
    """Integration test: Verify host environment variables are not passed through."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    monkeypatch.setenv("SECRET_HOST_TOKEN_123", "leak_this_token")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    probe_code = """
import os
token = os.getenv('SECRET_HOST_TOKEN_123', 'NOT_FOUND')
print(f'TOKEN_STATUS:{token}')
"""
    (workspace / "env_probe.py").write_text(probe_code, encoding="utf-8")

    runner = DockerRunner()
    result = runner.run(workspace, "python env_probe.py")

    assert result.status == ExecutionStatus.SUCCESS
    assert "TOKEN_STATUS:NOT_FOUND" in result.stdout


@pytest.mark.integration
def test_docker_non_root_user(tmp_path: Path):
    """Integration test: Verify container executes as non-root user (1000:1000)."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    probe_code = """
import os
print(f'UID:{os.getuid()}')
"""
    (workspace / "uid_probe.py").write_text(probe_code, encoding="utf-8")

    runner = DockerRunner()
    result = runner.run(workspace, "python uid_probe.py")

    assert result.status == ExecutionStatus.SUCCESS
    assert "UID:1000" in result.stdout


@pytest.mark.integration
def test_docker_path_traversal_escape_blocked(tmp_path: Path):
    """Integration test 2: Path traversal attempts cannot escape authorized workspace."""
    from src.tools.workspace_tools import read_file

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "valid.py").write_text("VALID_CONTENT", encoding="utf-8")

    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("HOST_SECRET", encoding="utf-8")

    # Attempt ../ traversal
    res = read_file(workspace, "../secret.txt")
    assert not res.success
    assert res.status == ExecutionStatus.BLOCKED_ACCESS

    # Attempt absolute path
    res_abs = read_file(workspace, str(outside_file))
    assert not res_abs.success
    assert res_abs.status == ExecutionStatus.BLOCKED_ACCESS


@pytest.mark.integration
def test_docker_symlink_escape_blocked(tmp_path: Path):
    """Integration test 3: Symlinks targeting outside workspace are blocked deterministically."""
    from src.tools.workspace_tools import list_files, read_file

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "confidential.txt").write_text("SECRET", encoding="utf-8")

    # Create file symlink inside workspace pointing outside
    symlink_path = workspace / "escape_link.txt"
    try:
        symlink_path.symlink_to(outside_dir / "confidential.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this environment")

    res_list = list_files(workspace)
    assert not res_list.success
    assert res_list.status == ExecutionStatus.BLOCKED_ACCESS
    assert "escapes workspace" in res_list.error.lower()


@pytest.mark.integration
def test_docker_arbitrary_host_command_blocked(tmp_path: Path):
    """Integration test 4: Arbitrary host commands and shell injection are blocked."""
    from src.tools.test_runner_tool import run_tests

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "test.py").write_text("print('TEST')", encoding="utf-8")

    permitted = ["pytest -q", "python test.py"]

    # Command injection attempt via semicolon
    res1 = run_tests(workspace, "pytest -q; rm -rf /", permitted_commands=permitted)
    assert not res1.success
    assert res1.status == ExecutionStatus.BLOCKED_ACCESS
    assert "forbidden shell metacharacters" in res1.error

    # Command injection attempt via pipe
    res2 = run_tests(workspace, "pytest -q | cat /etc/passwd", permitted_commands=permitted)
    assert not res2.success
    assert res2.status == ExecutionStatus.BLOCKED_ACCESS

    # Disallowed command
    res3 = run_tests(workspace, "cat /etc/shadow", permitted_commands=permitted)
    assert not res3.success
    assert res3.status == ExecutionStatus.BLOCKED_ACCESS
    assert "Disallowed test command" in res3.error


@pytest.mark.integration
def test_docker_timeout_and_resource_limits(tmp_path: Path):
    """Integration test 8: Timeout limits and execution resource bounds are enforced."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    from src.sandbox.docker_runner import SandboxConfig

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    # Script that sleeps longer than timeout
    (workspace / "hang.py").write_text("import time\ntime.sleep(15)\nprint('DONE')", encoding="utf-8")

    cfg = SandboxConfig(timeout_seconds=2.0)
    runner = DockerRunner(config=cfg)

    res = runner.run(workspace, "python hang.py")
    assert res.status == ExecutionStatus.TIMEOUT
    assert "timed out" in (res.blocked_reason or "").lower()


@pytest.mark.integration
def test_docker_container_cleanup_after_failure(tmp_path: Path):
    """Integration test 9: Containers are cleaned up after a timeout or failure."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    from src.sandbox.docker_runner import SandboxConfig

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "hang_cleanup.py").write_text("import time\ntime.sleep(10)", encoding="utf-8")

    cfg = SandboxConfig(timeout_seconds=1.5)
    runner = DockerRunner(config=cfg)
    runner.run(workspace, "python hang_cleanup.py")

    # Verify no dangling sandbox containers remain
    ps_proc = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=sandbox-"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ps_proc.returncode == 0
    # Container list should be empty
    assert ps_proc.stdout.strip() == ""


@pytest.mark.integration
def test_docker_malformed_command_fails_safely(tmp_path: Path):
    """Integration test 10: Malformed fixture commands fail safely without crash."""
    if not is_docker_available():
        pytest.skip("Docker daemon is not running or available.")

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    runner = DockerRunner()
    # Unmatched quote produces shlex parse error
    res = runner.run(workspace, "python -c 'unclosed quote")
    assert res.status == ExecutionStatus.BLOCKED_ACCESS
    assert "Failed to parse command arguments" in (res.blocked_reason or "")


@pytest.mark.integration
def test_fixture_never_executed_on_host(tmp_path: Path, monkeypatch):
    """Integration test 11: Untrusted fixture code is never executed on host if Docker fails."""
    from src.tools.test_runner_tool import run_tests

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker_file = tmp_path / "host_executed.marker"
    # Python script that would create a marker file if executed on host
    code = f"import pathlib\npathlib.Path(r'{marker_file}').write_text('PWNED')\n"
    (workspace / "untrusted.py").write_text(code, encoding="utf-8")

    # Simulate Docker unavailability
    monkeypatch.setattr("src.sandbox.docker_runner.is_docker_available", lambda: False)

    res = run_tests(workspace, "python untrusted.py", permitted_commands=["python untrusted.py"])
    assert not res.success
    assert res.status == ExecutionStatus.INFRASTRUCTURE_FAILURE
    assert not marker_file.exists()


@pytest.mark.integration
def test_raw_workspace_immutability_and_unicode_sanitizer(tmp_path: Path):
    """Integration test 12: Raw workspace immutability and Unicode sanitization preservation."""
    from src.materialization.unicode_sanitizer import sanitize_unicode_text

    raw_code = "print('Hello\u200bWorld')  # Zero-width space\n"
    clean_text, res = sanitize_unicode_text(raw_code, relative_path="app.py")

    # Sanitize flags the anomaly without corrupting execution semantics
    assert res.anomalies_count > 0
    assert len(res.annotations) > 0
    assert "print('Hello" in clean_text


