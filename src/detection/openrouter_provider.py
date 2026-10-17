"""OpenRouter Provider adapter.

Supports OpenRouter unified API gateway (https://openrouter.ai/api/v1) for cloud inference,
providing access to models with large context windows (128k+) including:
- Free tier models: 'meta-llama/llama-3.1-8b-instruct:free', 'google/gemma-2-9b-it:free', 'qwen/qwen-2.5-coder-32b-instruct:free'
- Production models: 'meta-llama/llama-3.1-70b-instruct', 'anthropic/claude-3.5-sonnet', 'google/gemini-pro-1.5'

Integrates:
- Pre-flight conservative token budgeting against declared context window.
- Post-flight truncation detection (finish_reason == 'length').
- Wire-level canary boundary checks.
- Transient error retry with exponential backoff and jitter (HTTP 429, 502, 503).
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


import re

class OpenRouterError(ProviderError):
    """Base exception for OpenRouter provider failures."""


class OpenRouterRateLimitError(OpenRouterError):
    """Raised when OpenRouter rate limits (HTTP 429) are encountered."""

    def __init__(self, message: str, retry_after: Optional[float] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class OpenRouterCreditsExhaustedError(OpenRouterError):
    """Raised when account balance or free credits are exhausted (HTTP 402)."""


class OpenRouterModelUnavailableError(OpenRouterError):
    """Raised when upstream provider or model is temporarily unavailable (HTTP 502/503)."""


class OpenRouterOversizedInputError(OpenRouterError):
    """Raised when request exceeds declared context window."""


class OpenRouterInvalidOutputError(OpenRouterError):
    """Raised when OpenRouter returns malformed or non-JSON responses."""


class OpenRouterCanaryInspectionError(OpenRouterError):
    """Raised when canary inspection blocks dispatch fail-closed."""


class OpenRouterConfig(BaseModel):
    """Configuration for OpenRouter inference gateway."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    api_key: Optional[str] = Field(
        default=None,
        description="OpenRouter API key (sk-or-v1-...).",
    )
    base_url: str = Field(
        default="https://openrouter.ai/api/v1",
        description="Base URL for OpenRouter API.",
    )
    model_name: str = Field(
        default="meta-llama/llama-3.1-8b-instruct:free",
        description="OpenRouter model identifier (e.g., 'meta-llama/llama-3.1-8b-instruct:free', 'google/gemma-2-9b-it:free').",
    )
    max_context_tokens: int = Field(
        default=131072,
        ge=2048,
        le=2097152,
        description="Maximum model context window in tokens (e.g. 128k for Llama-3.1, 1M+ for Gemini).",
    )
    max_tokens: int = Field(
        default=4096,
        ge=256,
        le=32768,
        description="Maximum generation tokens.",
    )
    request_budget: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum requests permitted for this provider instance session.",
    )
    site_url: str = Field(
        default="https://github.com/injection-pr-agent",
        description="App URL sent in HTTP-Referer header for OpenRouter analytics.",
    )
    site_name: str = Field(
        default="Injection-Robust PR Review Agent",
        description="App title sent in X-Title header.",
    )
    timeout_seconds: float = Field(default=120.0, ge=5.0, le=600.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    base_backoff_seconds: float = Field(default=1.0, ge=0.01, le=10.0)
    max_backoff_seconds: float = Field(default=10.0, ge=0.01, le=30.0)
    jitter_seconds: float = Field(default=0.5, ge=0.0, le=2.0)
    max_input_bytes: int = Field(default=350_000, ge=1)
    max_output_bytes: int = Field(default=150_000, ge=1)

    @classmethod
    def from_env(cls) -> "OpenRouterConfig":
        """Instantiate configuration from environment variables."""
        api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPEN_ROUTER_API_KEY")
        if not api_key:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as k:
                    api_key, _ = winreg.QueryValueEx(k, "OPENROUTER_API_KEY")
            except Exception:
                pass
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        model = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
        budget_str = os.getenv("OPENROUTER_REQUEST_BUDGET")

        return cls(
            api_key=api_key,
            base_url=base_url,
            model_name=model,
            max_context_tokens=int(os.getenv("OPENROUTER_MAX_CONTEXT_TOKENS", "131072")),
            max_tokens=int(os.getenv("OPENROUTER_MAX_TOKENS", "4096")),
            request_budget=int(budget_str) if budget_str else None,
            timeout_seconds=float(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "120.0")),
            max_retries=int(os.getenv("OPENROUTER_MAX_RETRIES", "2")),
            max_input_bytes=int(os.getenv("OPENROUTER_MAX_INPUT_BYTES", "350000")),
            max_output_bytes=int(os.getenv("OPENROUTER_MAX_OUTPUT_BYTES", "150000")),
        )


class OpenRouterProvider(LLMProvider):
    """LLMProvider implementation connecting to OpenRouter.ai."""

    def __init__(
        self,
        config: Optional[OpenRouterConfig] = None,
        transport_fn: Optional[Callable[..., str]] = None,
        dispatch_inspector: Optional[Any] = None,
        enforce_canary_inspection: bool = False,
    ) -> None:
        self.config = config or OpenRouterConfig.from_env()
        self._transport_fn = transport_fn
        self.dispatch_inspector = dispatch_inspector
        self.enforce_canary_inspection = enforce_canary_inspection
        self.provider_name = "openrouter"
        self.model_name = self.config.model_name
        self.requests_completed = 0

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Execute chat completion via OpenRouter with safety checks."""
        # 0. Check session request budget
        if self.config.request_budget is not None and self.requests_completed >= self.config.request_budget:
            raise OpenRouterRateLimitError(
                f"Configured request budget ({self.config.request_budget}) reached for OpenRouter session."
            )

        start_time = time.monotonic()
        deadline = start_time + self.config.timeout_seconds

        # 1. Enforce input byte limits
        total_input_bytes = len(prompt.encode("utf-8")) + len((system_prompt or "").encode("utf-8"))
        if total_input_bytes > self.config.max_input_bytes:
            raise OpenRouterOversizedInputError(
                f"Input size ({total_input_bytes} bytes) exceeds limit ({self.config.max_input_bytes} bytes)."
            )

        # 2. Pre-flight conservative token check
        from src.detection.context_budget import estimate_tokens_conservative
        est_tokens = estimate_tokens_conservative(prompt + (system_prompt or ""))
        if est_tokens > self.config.max_context_tokens:
            raise OpenRouterOversizedInputError(
                f"Estimated input tokens ({est_tokens}) exceeds model context limit ({self.config.max_context_tokens})."
            )

        # 3. Build payload
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": temperature if temperature > 0 else 0.0,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # 4. Canary inspection
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
                raise OpenRouterCanaryInspectionError(f"Canary inspection failed before dispatch: {exc}") from exc

            from src.detection.canary_telemetry import InspectionStatus
            if (
                inspection_record is None
                or not hasattr(inspection_record, "inspection_status")
                or inspection_record.inspection_status != InspectionStatus.COMPLETED
            ):
                raise OpenRouterCanaryInspectionError("Canary payload inspection failed fail-closed.")
        elif self.enforce_canary_inspection:
            raise OpenRouterCanaryInspectionError("Canary inspection is required but no inspector was configured.")

        # 5. Execute with retries
        attempt = 0
        last_error: Optional[Exception] = None

        while attempt <= self.config.max_retries:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise OpenRouterError(f"OpenRouter request exceeded timeout of {self.config.timeout_seconds:.1f}s.")

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
                    raise OpenRouterInvalidOutputError(
                        f"OpenRouter output size ({out_bytes} bytes) exceeds limit ({self.config.max_output_bytes} bytes)."
                    )

                self.requests_completed += 1

                metadata = ProviderMetadata(
                    provider_name=self.provider_name,
                    model_name=self.config.model_name,
                    temperature=temperature,
                    extra_config={
                        "num_ctx": self.config.max_context_tokens,
                        "attempts_used": attempt + 1,
                        "requests_completed": self.requests_completed,
                    },
                )
                return ProviderResponse(content=content, metadata=metadata)

            except Exception as exc:
                last_error = exc
                if not self._is_transient_error(exc) or attempt >= self.config.max_retries:
                    break

                attempt += 1
                if isinstance(exc, OpenRouterRateLimitError) and exc.retry_after is not None and exc.retry_after > 0:
                    backoff = min(self.config.max_backoff_seconds, exc.retry_after)
                else:
                    backoff = min(
                        self.config.max_backoff_seconds,
                        self.config.base_backoff_seconds * (2 ** (attempt - 1)),
                    )
                time.sleep(backoff)

        raise last_error or OpenRouterError("OpenRouter execution failed.")

    def _default_transport(self, payload_bytes: bytes, timeout: float) -> str:
        """Call OpenRouter API using standard urllib."""
        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "HTTP-Referer": self.config.site_url,
            "X-Title": self.config.site_name,
            "User-Agent": "Injection-Robust-PR-Agent/1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        req = urllib.request.Request(
            url=endpoint,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                resp_bytes = response.read()
        except urllib.error.HTTPError as http_err:
            status = http_err.code
            err_body = http_err.read().decode("utf-8", errors="replace")
            # Redact API keys from exception messages
            err_body = re.sub(r"sk-[a-zA-Z0-9_\-]+", "[REDACTED_API_KEY]", err_body)

            retry_after_hdr = http_err.headers.get("Retry-After")
            retry_after_val = None
            if retry_after_hdr:
                try:
                    retry_after_val = float(retry_after_hdr)
                except ValueError:
                    pass

            if status == 402:
                raise OpenRouterCreditsExhaustedError(
                    f"OpenRouter credits exhausted or payment required (HTTP 402): {err_body}"
                )
            if status == 401:
                raise OpenRouterError(
                    f"OpenRouter authentication failed (HTTP 401). Check OPENROUTER_API_KEY: {err_body}"
                )
            if status == 429:
                raise OpenRouterRateLimitError(
                    f"OpenRouter rate limit exceeded (HTTP 429): {err_body}",
                    retry_after=retry_after_val,
                )
            if status in (500, 502, 503, 504):
                raise OpenRouterModelUnavailableError(
                    f"OpenRouter upstream service error (HTTP {status}): {err_body}"
                )
            if status == 400 and ("context" in err_body.lower() or "too long" in err_body.lower()):
                raise OpenRouterOversizedInputError(
                    f"OpenRouter rejected input as oversized: {err_body}"
                )
            raise OpenRouterError(f"OpenRouter HTTP error {status}: {err_body}")

        except urllib.error.URLError as url_err:
            raise OpenRouterModelUnavailableError(
                f"Failed to connect to OpenRouter at {endpoint}: {url_err}"
            )

        try:
            resp_json = json.loads(resp_bytes.decode("utf-8"))
        except Exception as exc:
            raise OpenRouterInvalidOutputError(
                f"Failed to parse OpenRouter JSON response: {exc}"
            ) from exc

        choices = resp_json.get("choices")
        if not choices or not isinstance(choices, list):
            raise OpenRouterInvalidOutputError(
                f"Malformed OpenRouter response: missing 'choices' list: {resp_json}"
            )

        choice = choices[0]
        finish_reason = choice.get("finish_reason")
        if finish_reason == "length":
            raise OpenRouterOversizedInputError(
                f"OpenRouter generation truncated: finish_reason='length' for model {self.config.model_name}."
            )

        message = choice.get("message", {})
        content = message.get("content")
        if content is None:
            raise OpenRouterInvalidOutputError("Missing 'content' in OpenRouter response message.")

        return content

    def _is_transient_error(self, exc: Exception) -> bool:
        """Determine if error is transient and safe to retry."""
        if isinstance(exc, (OpenRouterRateLimitError, OpenRouterModelUnavailableError)):
            return True
        if isinstance(exc, (ConnectionError, TimeoutError, urllib.error.URLError)):
            return True
        return False

    def _get_correlation_context(self, correlation_context: Optional[Any]) -> Any:
        if correlation_context is not None:
            return correlation_context
        from src.detection.canary_telemetry import RequestCorrelationContext
        return RequestCorrelationContext()
