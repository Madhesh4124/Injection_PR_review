"""Integration tests executing against a real Docker daemon.

Explicitly distinguished from mocked unit tests. If Docker is unavailable,
these tests are skipped and marked unverified.
"""

from pathlib import Path
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

