"""Hugging Face LLM provider adapter supporting high-context models.

Supports models with large context windows (e.g. Qwen2.5-Coder-7B-Instruct,
Llama-3.1-8B-Instruct with 32k-128k context) via the Hugging Face Inference API,
dedicated endpoints, or local inference pipelines.
"""

import json
import math
import os
import random
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.detection.models import ProviderError, ProviderMetadata
from src.detection.provider import LLMProvider, ProviderResponse


class HuggingFaceError(ProviderError):
    """Base exception for all Hugging Face provider errors."""


class HuggingFaceTimeoutError(HuggingFaceError):
    """Raised when request execution times out."""


class HuggingFaceRateLimitError(HuggingFaceError):
    """Raised when Hugging Face API returns HTTP 429 Too Many Requests."""


class HuggingFaceModelUnavailableError(HuggingFaceError):
    """Raised when the requested model is unavailable, still loading, or unauthorized."""


class HuggingFaceInvalidOutputError(HuggingFaceError):
    """Raised when the model output is malformed or exceeds size limits."""


class HuggingFaceOversizedInputError(HuggingFaceError):
    """Raised when prompt exceeds allocated context limits."""


class HuggingFaceCanaryInspectionError(HuggingFaceError):
    """Raised when canary dispatch boundary inspection fails before network transmission."""


class HuggingFaceConfig(BaseModel):
    """Thread-safe configuration for Hugging Face inference execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    api_key: Optional[str] = Field(
        default=None,
        description="Hugging Face API token (HF_TOKEN or HUGGINGFACE_API_KEY).",
    )
    model_name: str = Field(
        default="Qwen/Qwen2.5-Coder-7B-Instruct",
        description="Hugging Face model repository ID (e.g. Qwen/Qwen2.5-Coder-7B-Instruct with 32k context).",
    )
    endpoint_url: Optional[str] = Field(
        default=None,
        description="Optional custom Hugging Face Inference Endpoint URL.",
    )
    max_context_tokens: int = Field(
        default=32768,
        ge=2048,
        le=131072,
        description="Allocated context window in tokens (e.g. 32768, preventing silent 2048-token truncation).",
    )
    max_new_tokens: int = Field(
        default=4096,
        ge=128,
        le=16384,
        description="Maximum tokens generated in response.",
    )
    timeout_seconds: float = Field(
        default=120.0,
        gt=0.0,
        le=600.0,
        description="Maximum execution timeout in seconds.",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retry attempts for transient errors (rate limits, model loading).",
    )
    base_backoff_seconds: float = Field(default=1.0, ge=0.01, le=10.0)
    max_backoff_seconds: float = Field(default=10.0, ge=0.01, le=30.0)
    jitter_seconds: float = Field(default=0.5, ge=0.0, le=2.0)
    max_input_bytes: int = Field(
        default=175_000,
        ge=1,
        description="Maximum allowed input bytes (prompt + system prompt).",
    )
    max_output_bytes: int = Field(
        default=100_000,
        ge=1,
        description="Maximum allowed output bytes before aborting.",
    )

    @classmethod
    def from_env(cls) -> "HuggingFaceConfig":
        """Instantiate configuration from environment variables."""
        token = os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_API_KEY") or os.getenv("HUGGING_FACE_HUB_TOKEN")
        return cls(
            api_key=token,
            model_name=os.getenv("HF_MODEL", os.getenv("HUGGINGFACE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")),
            endpoint_url=os.getenv("HF_ENDPOINT_URL"),
            max_context_tokens=int(os.getenv("HF_NUM_CTX", os.getenv("HF_MAX_CONTEXT_TOKENS", "32768"))),
            max_new_tokens=int(os.getenv("HF_MAX_NEW_TOKENS", "4096")),
            timeout_seconds=float(os.getenv("HF_TIMEOUT_SECONDS", "120.0")),
            max_retries=int(os.getenv("HF_MAX_RETRIES", "2")),
            base_backoff_seconds=float(os.getenv("HF_BASE_BACKOFF_SECONDS", "1.0")),
            max_backoff_seconds=float(os.getenv("HF_MAX_BACKOFF_SECONDS", "10.0")),
            jitter_seconds=float(os.getenv("HF_JITTER_SECONDS", "0.5")),
            max_input_bytes=int(os.getenv("HF_MAX_INPUT_BYTES", "175000")),
            max_output_bytes=int(os.getenv("HF_MAX_OUTPUT_BYTES", "100000")),
        )


class HuggingFaceProvider(LLMProvider):
    """LLM Provider adapter executing completions against Hugging Face models."""

    def __init__(
        self,
        config: Optional[HuggingFaceConfig] = None,
        transport_fn: Optional[Callable[..., str]] = None,
        dispatch_inspector: Optional[Any] = None,
        enforce_canary_inspection: bool = False,
    ) -> None:
        self.config = config or HuggingFaceConfig.from_env()
        self._transport_fn = transport_fn
        self.dispatch_inspector = dispatch_inspector
        self.enforce_canary_inspection = enforce_canary_inspection
        self.provider_name = "huggingface"
        self.model_name = self.config.model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Execute chat completion with Hugging Face model."""
        start_time = time.monotonic()
        deadline = start_time + self.config.timeout_seconds

        # 1. Enforce input size limits
        total_input_bytes = len(prompt.encode("utf-8")) + len((system_prompt or "").encode("utf-8"))
        if total_input_bytes > self.config.max_input_bytes:
            raise HuggingFaceOversizedInputError(
                f"Input size ({total_input_bytes} bytes) exceeds limit ({self.config.max_input_bytes} bytes)."
            )

        # 1b. Enforce pre-flight conservative token budget check
        from src.detection.context_budget import estimate_tokens_conservative
        est_tokens = estimate_tokens_conservative(prompt + (system_prompt or ""))
        if est_tokens > self.config.max_context_tokens:
            raise HuggingFaceOversizedInputError(
                f"Estimated input tokens ({est_tokens}) exceeds model context limit ({self.config.max_context_tokens}). "
                "Pre-flight check failed closed to prevent silent context truncation."
            )

        # 2. Prepare payload
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.config.max_new_tokens,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # 3. Canary dispatch boundary inspection before transmission
        inspection_record = None
        if self.dispatch_inspector is not None:
            from src.detection.canary_telemetry import RequestCorrelationContext, InspectionStatus
            ctx = correlation_context
            if not isinstance(ctx, RequestCorrelationContext):
                ctx = RequestCorrelationContext(
                    scenario_id=getattr(ctx, "scenario_id", "hf_call"),
                    node_id=getattr(ctx, "node_id", "hf_provider"),
                    model_name=self.config.model_name,
                )
            try:
                inspection_record = self.dispatch_inspector.inspect_serialized_payload(
                    payload_bytes=payload_bytes,
                    context=ctx,
                    dispatched=False,
                )
            except Exception as exc:
                clean_msg = f"Canary payload inspection failed before dispatch ({type(exc).__name__}); request blocked fail-closed."
                raise HuggingFaceCanaryInspectionError(clean_msg) from exc

            if (
                inspection_record is None
                or not hasattr(inspection_record, "inspection_status")
                or inspection_record.inspection_status != InspectionStatus.COMPLETED
            ):
                raise HuggingFaceCanaryInspectionError("Canary payload inspection did not complete successfully; request blocked fail-closed.")

        # 4. Execute inference with retry backoff
        attempt = 0
        last_error: Optional[Exception] = None

        while attempt <= self.config.max_retries:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise HuggingFaceTimeoutError(
                    f"Hugging Face request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s."
                )

            try:
                if self._transport_fn is not None:
                    try:
                        content = self._transport_fn(payload_bytes, remaining_time)
                    except TypeError:
                        content = self._transport_fn(payload, remaining_time)
                else:
                    content = self._default_transport(messages, temperature, remaining_time)

                if inspection_record is not None and hasattr(inspection_record, "mark_dispatched"):
                    inspection_record.mark_dispatched()

                # Validate output size
                out_bytes = len(content.encode("utf-8"))
                if out_bytes > self.config.max_output_bytes:
                    raise HuggingFaceInvalidOutputError(
                        f"Model output size ({out_bytes} bytes) exceeded limit ({self.config.max_output_bytes} bytes)."
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
                if time.monotonic() >= deadline:
                    raise HuggingFaceTimeoutError(
                        f"Hugging Face request exceeded timeout of {self.config.timeout_seconds:.1f}s."
                    ) from exc

                last_error = exc
                is_transient = self._is_transient_error(exc)
                if not is_transient or attempt >= self.config.max_retries:
                    break

                attempt += 1
                backoff = min(
                    self.config.max_backoff_seconds,
                    self.config.base_backoff_seconds * math.pow(2, attempt - 1),
                ) + random.uniform(0.0, self.config.jitter_seconds)

                if (deadline - time.monotonic()) <= backoff:
                    raise HuggingFaceTimeoutError("Request timed out during retry backoff.") from exc
                time.sleep(backoff)

        if isinstance(last_error, HuggingFaceError):
            raise last_error
        raise HuggingFaceError(f"Hugging Face execution failed after {attempt + 1} attempts: {last_error}") from last_error

    def _default_transport(self, messages: list, temperature: float, timeout: float) -> str:
        """Call Hugging Face via huggingface_hub InferenceClient or HTTP."""
        try:
            from huggingface_hub import InferenceClient

            client = InferenceClient(
                model=self.config.endpoint_url or self.config.model_name,
                token=self.config.api_key,
                timeout=timeout,
            )
            chat_resp = client.chat_completion(
                messages=messages,
                temperature=temperature if temperature > 0 else 0.01,
                max_tokens=self.config.max_new_tokens,
            )
            choice = chat_resp.choices[0]
            finish_reason = getattr(choice, "finish_reason", None) or (choice.get("finish_reason") if isinstance(choice, dict) else None)
            if finish_reason in ("length", "context_length_exceeded"):
                raise HuggingFaceOversizedInputError(
                    f"Hugging Face response reached token limit or context length exceeded (finish_reason='{finish_reason}')."
                )
            msg = choice.message if hasattr(choice, "message") else choice.get("message", {})
            content = getattr(msg, "content", None) or (msg.get("content") if isinstance(msg, dict) else "")
            return content or ""
        except ImportError:
            # Fallback to direct HTTP API if huggingface_hub is unavailable
            return self._http_fallback(messages, temperature, timeout)
        except Exception as exc:
            err_str = str(exc).lower()
            if "429" in err_str or "rate limit" in err_str:
                raise HuggingFaceRateLimitError(f"Hugging Face rate limit exceeded: {exc}") from exc
            if "503" in err_str or "loading" in err_str:
                raise HuggingFaceModelUnavailableError(f"Hugging Face model is currently loading: {exc}") from exc
            if "401" in err_str or "403" in err_str or "token" in err_str:
                raise HuggingFaceModelUnavailableError(f"Hugging Face authentication error: {exc}") from exc
            raise

    def _http_fallback(self, messages: list, temperature: float, timeout: float) -> str:
        """Direct HTTP request to Hugging Face Inference API."""
        url = self.config.endpoint_url or f"https://api-inference.huggingface.co/models/{self.config.model_name}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        req_data = json.dumps({
            "model": self.config.model_name,
            "messages": messages,
            "temperature": temperature if temperature > 0 else 0.01,
            "max_tokens": self.config.max_new_tokens,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                choices = resp_data.get("choices", [])
                if choices and "message" in choices[0]:
                    finish_reason = choices[0].get("finish_reason")
                    if finish_reason in ("length", "context_length_exceeded"):
                        raise HuggingFaceOversizedInputError(
                            f"Hugging Face HTTP response reached token limit (finish_reason='{finish_reason}')."
                        )
                    return choices[0]["message"].get("content", "")
                raise HuggingFaceInvalidOutputError("Missing choices in Hugging Face response.")
        except urllib.error.HTTPError as h_err:
            if h_err.code == 429:
                raise HuggingFaceRateLimitError(f"Rate limited by Hugging Face API (HTTP 429): {h_err}") from h_err
            if h_err.code in (401, 403):
                raise HuggingFaceModelUnavailableError(f"Unauthorized or model access restricted (HTTP {h_err.code}): {h_err}") from h_err
            if h_err.code == 503:
                raise HuggingFaceModelUnavailableError(f"Model is currently loading (HTTP 503): {h_err}") from h_err
            raise

    def _is_transient_error(self, exc: Exception) -> bool:
        """Determine if an exception is transient and eligible for retry."""
        if isinstance(exc, (HuggingFaceRateLimitError, urllib.error.URLError, ConnectionError, TimeoutError)):
            return True
        err_msg = str(exc).lower()
        return any(term in err_msg for term in ["429", "503", "rate limit", "timed out", "timeout", "temporarily unavailable"])
