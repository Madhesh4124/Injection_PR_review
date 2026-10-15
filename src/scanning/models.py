"""Models and immutable data containers for static analysis scanner findings."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.schemas.findings import ScannerFinding


class ScanStatus(str, Enum):
    """Execution status for static analysis scans."""

    SUCCESS = "success"
    FAILURE = "failure"
    TOOL_NOT_AVAILABLE = "tool_not_available"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


class ScanResult(BaseModel):
    """Immutable result of a static analysis tool invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    tool_version: Optional[str] = Field(default=None)
    status: ScanStatus
    findings: List[ScannerFinding] = Field(default_factory=list)
    raw_output: str = Field(default="")
    error: Optional[str] = Field(default=None)
    duration_seconds: float = Field(ge=0.0, default=0.0)
    files_scanned: int = Field(ge=0, default=0)

    @property
    def is_clean_scan(self) -> bool:
        """True only if scan executed successfully and found 0 defects."""
        return self.status == ScanStatus.SUCCESS and len(self.findings) == 0

    @property
    def is_failure(self) -> bool:
        """True if scan failed, timed out, or tool was not available."""
        return self.status != ScanStatus.SUCCESS
