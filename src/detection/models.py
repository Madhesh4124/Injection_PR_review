"""Data models, requests, results, and provider metadata for Node 4 injection detection."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.schemas.injections import InjectionRecord

# Fixed, documented size limits for Node 4
MAX_DIFF_BYTES: int = 125_000  # 125 KB, aligned with MAX_CHANGED_BYTES_PER_PR
MAX_PR_DESCRIPTION_BYTES: int = 25_000  # 25 KB
MAX_README_BYTES: int = 25_000  # 25 KB
MAX_TOTAL_INPUT_BYTES: int = 175_000  # 175 KB total across all untrusted channels
MAX_OUTPUT_CHARS: int = 100_000  # 100 KB max raw LLM output text
MAX_OUTPUT_RECORDS: int = 50  # Upper bound on records returned to prevent memory exhaustion

SENSITIVE_KEY_NAMES = {
    "api_key",
    "apikey",
    "token",
    "secret",
    "authorization",
    "password",
    "passwd",
    "credential",
    "credentials",
    "access_key",
    "private_key",
}


class OversizedInputError(ValueError):
    """Raised when an untrusted input exceeds fixed Node 4 context and size limits."""


class MalformedDetectorOutputError(ValueError):
    """Raised when model output fails strict Pydantic validation or cannot be parsed."""


class ProviderError(RuntimeError):
    """Raised when the underlying LLM provider encounters an error or timeout."""


class ProviderMetadata(BaseModel):
    """Provenance and runtime metadata for the LLM provider invocation.

    Guarantees secrets, API keys, and authorization headers are never logged.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    provider_name: str = Field(description="Name of provider (e.g. mock, openai, anthropic, google).")
    model_name: str = Field(description="Configured model identifier.")
    model_version: Optional[str] = Field(
        default=None, description="Optional pinned model version or digest."
    )
    temperature: float = Field(
        default=0.0,
        ge=0.0,
        le=2.0,
        description="Sampling temperature (must be 0.0 when supported).",
    )
    extra_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized non-sensitive runtime configuration parameters.",
    )

    @model_validator(mode="after")
    def scrub_sensitive_metadata(self) -> "ProviderMetadata":
        """Verify that no sensitive credential keys exist in extra_config."""
        for key, val in list(self.extra_config.items()):
            key_lower = key.lower()
            if any(s in key_lower for s in SENSITIVE_KEY_NAMES):
                raise ValueError(f"Sensitive configuration key '{key}' must not be recorded in metadata.")
            if isinstance(val, str) and (val.startswith("sk-") or val.startswith("ghp_") or "bearer " in val.lower()):
                raise ValueError(f"Sensitive credential value detected in key '{key}'.")
        return self


class InjectionDetectionRequest(BaseModel):
    """Validated inputs for Node 4 injection detection."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    raw_diff: str = Field(description="Raw unified PR diff text.")
    pr_description: str = Field(description="Untrusted PR description text.")
    readme_content: Optional[str] = Field(
        default=None,
        description="README markdown text from the authorized raw view, if present.",
    )

    @model_validator(mode="after")
    def validate_input_size_limits(self) -> "InjectionDetectionRequest":
        """Enforce strict context and size limits on untrusted input channels."""
        diff_bytes = len(self.raw_diff.encode("utf-8"))
        if diff_bytes > MAX_DIFF_BYTES:
            raise OversizedInputError(
                f"PR diff size ({diff_bytes} bytes) exceeds limit ({MAX_DIFF_BYTES} bytes)."
            )

        desc_bytes = len(self.pr_description.encode("utf-8"))
        if desc_bytes > MAX_PR_DESCRIPTION_BYTES:
            raise OversizedInputError(
                f"PR description size ({desc_bytes} bytes) exceeds limit ({MAX_PR_DESCRIPTION_BYTES} bytes)."
            )

        readme_bytes = len(self.readme_content.encode("utf-8")) if self.readme_content else 0
        if readme_bytes > MAX_README_BYTES:
            raise OversizedInputError(
                f"README content size ({readme_bytes} bytes) exceeds limit ({MAX_README_BYTES} bytes)."
            )

        total_bytes = diff_bytes + desc_bytes + readme_bytes
        if total_bytes > MAX_TOTAL_INPUT_BYTES:
            raise OversizedInputError(
                f"Total untrusted input size ({total_bytes} bytes) exceeds limit ({MAX_TOTAL_INPUT_BYTES} bytes)."
            )

        return self


class InjectionDetectorOutput(BaseModel):
    """Strict wrapper schema required for model JSON output."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    records: List[InjectionRecord] = Field(
        default_factory=list,
        description="List of detected injection records strictly matching the schema.",
    )

    @field_validator("records")
    @classmethod
    def validate_record_count(cls, records: List[InjectionRecord]) -> List[InjectionRecord]:
        if len(records) > MAX_OUTPUT_RECORDS:
            raise ValueError(
                f"Output record count ({len(records)}) exceeds upper limit ({MAX_OUTPUT_RECORDS})."
            )
        return records


class InjectionDetectionResult(BaseModel):
    """Result emitted by Node 4 injection detector."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    records: List[InjectionRecord] = Field(default_factory=list)
    provider_metadata: ProviderMetadata
    raw_response: Optional[str] = Field(
        default=None,
        description="Raw response string received from the provider, bounded.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error details if provider failed or output was rejected.",
    )
    duration_seconds: float = Field(ge=0.0, default=0.0)

    @property
    def is_success(self) -> bool:
        """True if analysis completed without provider or validation errors."""
        return self.error is None
