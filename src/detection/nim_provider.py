"""NVIDIA NIM (Inference Microservice) Provider adapter.

Supports both:
1. NVIDIA Hosted API Catalog (https://integrate.api.nvidia.com/v1) for development and testing.
2. Self-hosted on-prem NIM Docker containers (http://localhost:8000/v1) for isolated deployment.

Default Model: 'meta/llama-3.1-8b-instruct' (128k context window).
Alternative Model: 'meta/llama-3.1-70b-instruct' or 'qwen/qwen2.5-coder-32b-instruct'.
"""

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.detection.models import ProviderError, ProviderMetadata
from src.detection.provider import LLMProvider, ProviderResponse


class NIMError(ProviderError):
    """Base exception for NVIDIA NIM provider failures."""


class NIMRateLimitError(NIMError):
    """Raised when rate limits (HTTP 429) are encountered."""


class NIMModelUnavailableError(NIMError):
    """Raised when NIM microservice or model is unreachable or loading (HTTP 503)."""


class NIMOversizedInputError(NIMError):
    """Raised when request exceeds NIM context capacity."""


class NIMInvalidOutputError(NIMError):
    """Raised when NIM returns malformed or non-JSON responses."""


class NIMCanaryInspectionError(NIMError):
    """Raised when canary inspection blocks dispatch fail-closed."""


class NIMConfig(BaseModel):
    """Configuration for NVIDIA NIM microservice."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    api_key: Optional[str] = Field(
        default=None,
        description="NVIDIA API key (nvapi-...) for hosted endpoints; not required for local self-hosted NIM containers.",
    )
    base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        description="Base URL: 'https://integrate.api.nvidia.com/v1' for hosted or 'http://localhost:8000/v1' for local container.",
    )
    model_name: str = Field(
        default="meta/llama-3.1-8b-instruct",
        description="NIM model identifier (e.g., meta/llama-3.1-8b-instruct, qwen/qwen2.5-coder-32b-instruct).",
    )
    max_context_tokens: int = Field(
        default=131072,
        ge=2048,
        le=131072,
        description="Maximum model context window in tokens (128k for Llama-3.1).",
    )
    max_tokens: int = Field(
        default=4096,
        ge=256,
        le=16384,
        description="Maximum generation tokens.",
    )
    timeout_seconds: float = Field(default=120.0, ge=5.0, le=600.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    base_backoff_seconds: float = Field(default=1.0, ge=0.01, le=10.0)
    max_backoff_seconds: float = Field(default=10.0, ge=0.01, le=30.0)
    jitter_seconds: float = Field(default=0.5, ge=0.0, le=2.0)
    max_input_bytes: int = Field(default=250_000, ge=1)
    max_output_bytes: int = Field(default=100_000, ge=1)

    @classmethod
    def from_env(cls) -> "NIMConfig":
        """Instantiate configuration from environment variables."""
        api_key = (
            os.getenv("NVIDIA_API_KEY")
            or os.getenv("NIM_API_KEY")
            or os.getenv("NGC_API_KEY")
        )
        base_url = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        model = os.getenv("NIM_MODEL", "meta/llama-3.1-8b-instruct")

        return cls(
            api_key=api_key,
            base_url=base_url,
            model_name=model,
            max_context_tokens=int(os.getenv("NIM_MAX_CONTEXT_TOKENS", "131072")),
            max_tokens=int(os.getenv("NIM_MAX_TOKENS", "4096")),
            timeout_seconds=float(os.getenv("NIM_TIMEOUT_SECONDS", "120.0")),
            max_retries=int(os.getenv("NIM_MAX_RETRIES", "2")),
            max_input_bytes=int(os.getenv("NIM_MAX_INPUT_BYTES", "250000")),
            max_output_bytes=int(os.getenv("NIM_MAX_OUTPUT_BYTES", "100000")),
        )


class NIMProvider(LLMProvider):
    """NVIDIA NIM provider supporting high-context (128k) models for local and cloud deployment."""

    def __init__(
        self,
        config: Optional[NIMConfig] = None,
        transport_fn: Optional[Callable[..., str]] = None,
        dispatch_inspector: Optional[Any] = None,
        enforce_canary_inspection: bool = False,
    ) -> None:
        self.config = config or NIMConfig.from_env()
        self._transport_fn = transport_fn
        self.dispatch_inspector = dispatch_inspector
        self.enforce_canary_inspection = enforce_canary_inspection
        self.provider_name = "nvidia_nim"
        self.model_name = self.config.model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Execute chat completion with NVIDIA NIM."""
        start_time = time.monotonic()
        deadline = start_time + self.config.timeout_seconds

        # 1. Enforce input byte limits
        total_input_bytes = len(prompt.encode("utf-8")) + len((system_prompt or "").encode("utf-8"))
        if total_input_bytes > self.config.max_input_bytes:
            raise NIMOversizedInputError(
                f"Input size ({total_input_bytes} bytes) exceeds limit ({self.config.max_input_bytes} bytes)."
            )

        # 2. Pre-flight conservative token budget check
        from src.detection.context_budget import estimate_tokens_conservative
        est_tokens = estimate_tokens_conservative(prompt + (system_prompt or ""))
        if est_tokens > self.config.max_context_tokens:
            raise NIMOversizedInputError(
                f"Estimated input tokens ({est_tokens}) exceeds model context limit ({self.config.max_context_tokens})."
            )

        # 3. Prepare OpenAI-compatible payload
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": temperature if temperature > 0 else 0.0,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # 4. Wire-level canary boundary inspection
        inspection_record = None
        if self.dispatch_inspector is not None:
            ctx = self._get_correlation_context(correlation_context)
            try:
                inspection_record = self.dispatch_inspector.inspect_serialized_payload(
                    payload_bytes=payload_bytes,
                    context=ctx,
                    dispatched=False,
                )
            except Exception as exc:
                raise NIMCanaryInspectionError(f"Canary inspection failed before dispatch: {exc}") from exc

            from src.detection.canary_telemetry import InspectionStatus
            if (
                inspection_record is None
                or not hasattr(inspection_record, "inspection_status")
                or inspection_record.inspection_status != InspectionStatus.COMPLETED
            ):
                raise NIMCanaryInspectionError("Canary payload inspection failed fail-closed.")
        elif self.enforce_canary_inspection:
            raise NIMCanaryInspectionError("Canary inspection is required but no inspector was configured.")

        # 5. Execute request with retry protection
        attempt = 0
        last_error: Optional[Exception] = None

        while attempt <= self.config.max_retries:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise NIMError(f"NIM request exceeded timeout of {self.config.timeout_seconds:.1f}s.")

            try:
                if self._transport_fn is not None:
                    try:
                        content = self._transport_fn(payload_bytes, remaining_time)
                    except TypeError:
                        content = self._transport_fn(payload, remaining_time)
                else:
                    content = self._default_transport(payload_bytes, remaining_time)

                if inspection_record is not None and hasattr(inspection_record, "mark_dispatched"):
                    inspection_record.mark_dispatched()

                # Validate output size
                out_bytes = len(content.encode("utf-8"))
                if out_bytes > self.config.max_output_bytes:
                    raise NIMInvalidOutputError(
                        f"NIM output size ({out_bytes} bytes) exceeds limit ({self.config.max_output_bytes} bytes)."
                    )

                metadata = ProviderMetadata(
                    provider_name=self.provider_name,
                    model_name=self.config.model_name,
                    temperature=temperature,
                    extra_config={
                        "num_ctx": self.config.max_context_tokens,
                        "attempts_used": attempt + 1,
                    },
                )
                return ProviderResponse(content=content, metadata=metadata)

            except Exception as exc:
                last_error = exc
                if not self._is_transient_error(exc) or attempt >= self.config.max_retries:
                    break

                attempt += 1
                backoff = min(
                    self.config.max_backoff_seconds,
                    self.config.base_backoff_seconds * (2 ** (attempt - 1)),
                )
                time.sleep(backoff)

        raise last_error or NIMError("NIM execution failed.")

    def _default_transport(self, payload_bytes: bytes, timeout: float) -> str:
        """Call NVIDIA NIM API using standard urllib."""
        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Injection-Robust-PR-Agent/1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        req = urllib.request.Request(endpoint, data=payload_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                choices = resp_data.get("choices", [])
                if not choices:
                    raise NIMInvalidOutputError("No choices returned in NIM response.")

                choice = choices[0]
                finish_reason = choice.get("finish_reason")
                if finish_reason in ("length", "context_length_exceeded"):
                    raise NIMOversizedInputError(
                        f"NIM response hit context length limit (finish_reason='{finish_reason}')."
                    )

                return choice.get("message", {}).get("content", "") or ""

        except urllib.error.HTTPError as h_err:
            if h_err.code == 429:
                raise NIMRateLimitError(f"NIM rate limit exceeded (HTTP 429): {h_err}") from h_err
            if h_err.code == 503:
                raise NIMModelUnavailableError(f"NIM microservice unavailable or loading (HTTP 503): {h_err}") from h_err
            if h_err.code in (401, 403):
                raise NIMModelUnavailableError(f"NIM authentication failed (HTTP {h_err.code}): {h_err}") from h_err
            raise

    def _is_transient_error(self, exc: Exception) -> bool:
        """Check if error is transient and retriable."""
        if isinstance(exc, (NIMRateLimitError, urllib.error.URLError, ConnectionError, TimeoutError)):
            return True
        msg = str(exc).lower()
        return any(term in msg for term in ["429", "503", "rate limit", "timed out", "timeout"])

    def _get_correlation_context(self, ctx: Optional[Any]) -> Any:
        if ctx is not None:
            return ctx
        from src.detection.canary_telemetry import RequestCorrelationContext
        return RequestCorrelationContext(
            scenario_id="unknown",
            run_index=0,
            node_id="nim_node",
            model_name=self.config.model_name,
        )
