from pathlib import Path
from typing import List, Optional

from src.sandbox.docker_runner import DockerRunner
from src.sandbox.models import ExecutionStatus
from src.schemas.fixture import DISALLOWED_SHELL_CHARS
from src.tools.base import ToolResult


def run_tests(
    workspace_root: Path,
    test_command: str,
    permitted_commands: List[str],
    runner: Optional[DockerRunner] = None,
) -> ToolResult:
    r"""Execute tests inside the isolated Docker sandbox using an allowlisted command profile.

    Rejects:
    - Commands not in the fixture's permitted_commands list.
    - Commands containing shell injection metacharacters (;&|><$\).
    - Host execution under all circumstances.
    """
    cmd_clean = test_command.strip()

    # Security check 1: Reject shell metacharacters
    if DISALLOWED_SHELL_CHARS.search(cmd_clean):
        return ToolResult.blocked(
            f"Test command contains forbidden shell metacharacters: '{cmd_clean}'"
        )

    # Security check 2: Strict allowlist match against trusted configuration
    clean_permitted = [p.strip() for p in permitted_commands]
    if cmd_clean not in clean_permitted:
        return ToolResult.blocked(
            f"Disallowed test command: '{cmd_clean}' is not in permitted list: {clean_permitted}"
        )

    # Execute inside Docker runner
    active_runner = runner or DockerRunner()
    result = active_runner.run(workspace_root, cmd_clean)

    if result.status == ExecutionStatus.BLOCKED_ACCESS:
        return ToolResult.blocked(result.blocked_reason or "Blocked by sandbox policy")
    elif result.status == ExecutionStatus.TIMEOUT:
        return ToolResult.failure(
            f"Test execution timed out: {result.blocked_reason}",
            status=ExecutionStatus.TIMEOUT,
        )
    elif result.status == ExecutionStatus.INFRASTRUCTURE_FAILURE:
        return ToolResult.failure(
            f"Infrastructure failure: {result.infrastructure_error}",
            status=ExecutionStatus.INFRASTRUCTURE_FAILURE,
        )

    return ToolResult(
        success=(result.status == ExecutionStatus.SUCCESS),
        status=result.status,
        data={
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": cmd_clean,
        },
        duration_seconds=result.duration_seconds,
    )
