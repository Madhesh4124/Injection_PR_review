"""Unit tests verifying restricted Docker command construction, security flags, and isolation."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.sandbox.docker_runner import (
    PINNED_SANDBOX_IMAGE,
    DockerRunner,
    SandboxConfig,
)
from src.sandbox.models import ExecutionStatus


def test_docker_command_security_flags(tmp_path: Path):
    """Verify all non-negotiable security flags are strictly applied."""
    runner = DockerRunner(SandboxConfig())
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    cmd = runner.build_docker_command(
        workspace,
        ["pytest", "-q"],
        container_name="test-sandbox-01",
    )

    # 1. Base command and container name
    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--name" in cmd
    assert cmd[cmd.index("--name") + 1] == "test-sandbox-01"
    assert "--rm" in cmd

    # 2. Network isolation
    assert "--network" in cmd
    assert cmd[cmd.index("--network") + 1] == "none"

    # 3. Privilege and capability restrictions
    assert "--cap-drop" in cmd
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in cmd
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"

    # 4. Non-root user execution
    assert "--user" in cmd
    assert cmd[cmd.index("--user") + 1] == "1000:1000"

    # 5. Resource and process limits
    assert "--pids-limit" in cmd
    assert cmd[cmd.index("--pids-limit") + 1] == "100"
    assert "--memory" in cmd
    assert cmd[cmd.index("--memory") + 1] == "512m"
    assert "--cpus" in cmd
    assert cmd[cmd.index("--cpus") + 1] == "1.0"

    # 6. Read-only root filesystem
    assert "--read-only" in cmd
    assert "--tmpfs" in cmd

    # 7. Strictly scoped workspace mount
    assert "-v" in cmd
    mount_arg = cmd[cmd.index("-v") + 1]
    assert mount_arg.endswith(":/workspace:rw")
    assert "-w" in cmd
    assert cmd[cmd.index("-w") + 1] == "/workspace"

    # 8. Pinned image digest
    assert PINNED_SANDBOX_IMAGE in cmd

    # 9. No host environment or credentials leaked
    for arg in cmd:
        assert "AWS_" not in arg
        assert "GITHUB_TOKEN" not in arg
        assert "API_KEY" not in arg


def test_docker_unavailable_returns_infrastructure_failure(tmp_path: Path):
    """Verify runner fails closed with INFRASTRUCTURE_FAILURE when Docker daemon is down."""
    runner = DockerRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with patch("src.sandbox.docker_runner.is_docker_available", return_value=False):
        res = runner.run(workspace, "pytest")
        assert res.status == ExecutionStatus.INFRASTRUCTURE_FAILURE
        assert "Docker engine is not available" in (res.infrastructure_error or "")


def test_timeout_kills_container_and_returns_timeout_status(tmp_path: Path):
    """Verify timeout triggers docker kill and returns TIMEOUT status."""
    runner = DockerRunner(SandboxConfig(timeout_seconds=5.0))
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with patch("src.sandbox.docker_runner.is_docker_available", return_value=True):
        with patch("subprocess.run") as mock_subproc:
            # First call (docker run) times out
            mock_subproc.side_effect = [
                subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=5.0),
                MagicMock(returncode=0),  # docker kill
                MagicMock(returncode=0),  # docker rm
            ]

            res = runner.run(workspace, "pytest")
            assert res.status == ExecutionStatus.TIMEOUT
            assert "timed out" in (res.blocked_reason or "")
            # Verify docker kill was invoked
            kill_calls = [call for call in mock_subproc.call_args_list if "kill" in str(call)]
            assert len(kill_calls) >= 1


def test_container_cleanup_after_unexpected_exception(tmp_path: Path):
    """Verify docker rm is invoked even after unexpected host execution exceptions."""
    runner = DockerRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with patch("src.sandbox.docker_runner.is_docker_available", return_value=True):
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.side_effect = [
                OSError("Unexpected kernel error"),
                MagicMock(returncode=0),  # docker rm
            ]

            res = runner.run(workspace, "pytest")
            assert res.status == ExecutionStatus.INFRASTRUCTURE_FAILURE
            # Cleanup rm called
            rm_calls = [call for call in mock_subproc.call_args_list if "rm" in str(call)]
            assert len(rm_calls) >= 1
