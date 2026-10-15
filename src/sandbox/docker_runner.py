"""Restricted Docker runner for isolated execution of untrusted repository test code."""

import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.sandbox.models import ExecutionResult, ExecutionStatus

# Pinned immutable Docker image digest for sandbox execution
PINNED_SANDBOX_IMAGE = "python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
DEFAULT_HOST_TIMEOUT_SECONDS = 30.0
MAX_OUTPUT_BYTES = 100 * 1024  # 100 KB output limit to prevent context flooding


class SandboxConfig(BaseModel):
    """Configuration for Docker sandbox execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    image_digest: str = Field(default=PINNED_SANDBOX_IMAGE)
    timeout_seconds: float = Field(ge=1.0, le=300.0, default=DEFAULT_HOST_TIMEOUT_SECONDS)
    memory_limit: str = Field(default="512m")
    cpus_limit: str = Field(default="1.0")
    pids_limit: int = Field(ge=10, le=500, default=100)
    network_disabled: bool = Field(default=True)
    non_root_user: str = Field(default="1000:1000")
    read_only_root: bool = Field(default=True)


def is_docker_available() -> bool:
    """Check if the Docker CLI and daemon are operational."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return res.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


class DockerRunner:
    """Restricted Docker runner enforcing non-root, capability-drop, and network isolation."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()

    def build_docker_command(
        self,
        workspace_host_path: Path,
        command_args: List[str],
        container_name: str,
    ) -> List[str]:
        """Construct the isolated docker run invocation arguments."""
        cmd = [
            "docker",
            "run",
            "--name",
            container_name,
            "--rm",
        ]

        if self.config.network_disabled:
            cmd.extend(["--network", "none"])

        cmd.extend([
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", self.config.non_root_user,
            "--pids-limit", str(self.config.pids_limit),
            "--memory", self.config.memory_limit,
            "--cpus", self.config.cpus_limit,
        ])

        if self.config.read_only_root:
            cmd.append("--read-only")
            cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        # Mount strictly the workspace at /workspace (read-write for test artifacts)
        # Using POSIX path for Windows Docker host compatibility
        resolved_workspace = workspace_host_path.resolve().as_posix()
        cmd.extend(["-v", f"{resolved_workspace}:/workspace:rw"])
        cmd.extend(["-w", "/workspace"])

        # Zero host environment pass-through: provide only minimal execution variables
        cmd.extend([
            "-e", "PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
            "-e", "PYTHONPATH=/workspace",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "HOME=/tmp",
        ])

        # Image and command
        cmd.append(self.config.image_digest)
        cmd.extend(command_args)

        return cmd

    def run(
        self,
        workspace_host_path: Path,
        command: str,
    ) -> ExecutionResult:
        """Execute an allowlisted command inside the isolated container."""
        # Sanity check: verify Docker availability
        if not is_docker_available():
            return ExecutionResult(
                status=ExecutionStatus.INFRASTRUCTURE_FAILURE,
                infrastructure_error="Docker engine is not available or not running on the host.",
                command_executed=command,
            )

        container_name = f"sandbox-{uuid.uuid4().hex[:12]}"
        try:
            command_args = shlex.split(command, posix=True)
        except ValueError as err:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED_ACCESS,
                blocked_reason=f"Failed to parse command arguments safely: {err}",
                command_executed=command,
            )

        docker_cmd = self.build_docker_command(workspace_host_path, command_args, container_name)
        start_time = time.monotonic()

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
            duration = time.monotonic() - start_time
            stdout = proc.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
            stderr = proc.stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]

            status = ExecutionStatus.SUCCESS if proc.returncode == 0 else ExecutionStatus.FAILURE
            return ExecutionResult(
                status=status,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=round(duration, 3),
                command_executed=command,
            )

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start_time
            # Ensure container is killed and cleaned up
            subprocess.run(["docker", "kill", container_name], capture_output=True, check=False)
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                duration_seconds=round(duration, 3),
                blocked_reason=f"Execution timed out after {self.config.timeout_seconds} seconds.",
                command_executed=command,
            )

        except Exception as exc:
            duration = time.monotonic() - start_time
            # Ensure container is cleaned up even on unexpected host exception
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)
            return ExecutionResult(
                status=ExecutionStatus.INFRASTRUCTURE_FAILURE,
                duration_seconds=round(duration, 3),
                infrastructure_error=f"Unexpected exception during container execution: {exc}",
                command_executed=command,
            )
