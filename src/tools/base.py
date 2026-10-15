"""Base classes and structured result schemas for restricted review tools."""

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.sandbox.models import ExecutionStatus

MAX_TOOL_OUTPUT_CHARS = 100_000  # 100 KB max output limit


class ToolResult(BaseModel):
    """Structured response from a restricted agent tool."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    success: bool
    status: ExecutionStatus
    data: Optional[Any] = Field(default=None)
    error: Optional[str] = Field(default=None)
    blocked_reason: Optional[str] = Field(default=None)
    duration_seconds: float = Field(ge=0.0, default=0.0)

    @classmethod
    def blocked(cls, reason: str) -> "ToolResult":
        """Convenience constructor for security-blocked tool invocations."""
        return cls(
            success=False,
            status=ExecutionStatus.BLOCKED_ACCESS,
            blocked_reason=reason,
            error=f"Security Boundary Enforced: {reason}",
        )

    @classmethod
    def failure(cls, error_msg: str, status: ExecutionStatus = ExecutionStatus.FAILURE) -> "ToolResult":
        """Convenience constructor for failed executions."""
        return cls(
            success=False,
            status=status,
            error=error_msg,
        )

    @classmethod
    def ok(cls, data: Any, duration_seconds: float = 0.0) -> "ToolResult":
        """Convenience constructor for successful tool invocations."""
        return cls(
            success=True,
            status=ExecutionStatus.SUCCESS,
            data=data,
            duration_seconds=round(duration_seconds, 3),
        )
