"""Execution models and status telemetry for sandboxed runs."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ExecutionStatus(str, Enum):
    """Execution status distinction for sandboxed processes."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    BLOCKED_ACCESS = "blocked_access"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class ExecutionResult(BaseModel):
    """Structured result of sandboxed test or tool execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    status: ExecutionStatus
    exit_code: Optional[int] = Field(default=None)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    duration_seconds: float = Field(ge=0.0, default=0.0)
    blocked_reason: Optional[str] = Field(default=None)
    infrastructure_error: Optional[str] = Field(default=None)
    command_executed: Optional[str] = Field(default=None)
