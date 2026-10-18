"""Resource-protected Ollama LLM provider adapter.

Guarantees:
- Concurrency bounded by configurable Semaphore (default: 1 concurrent request).
- Bounded waiting queue rejecting requests when saturated (default: max 5 waiting).
- Configurable request timeouts covering queue wait and HTTP execution (default: 120s).
- Transient failure retry with exponential backoff and randomized jitter (max 2 retries).
- Non-transient errors (schema validation, client errors, oversized inputs) fail immediately without retry.
- Bounded input and output byte limits preventing host memory exhaustion.
- Explicit typed errors: Timeout, QueueFull, ModelUnavailable, InvalidOutput, OversizedInput.
- Zero cloud-provider dependencies and zero API key requirements (pure stdlib HTTP).
- Thread-safe and deadlock-free execution with guaranteed cleanup.
"""

import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.detection.models import ProviderError, ProviderMetadata
from src.detection.provider import LLMProvider, ProviderResponse


# Explicit exception classes
class OllamaError(ProviderError):
    """Base exception for all Ollama provider failures."""


class OllamaTimeoutError(OllamaError):
    """Raised when an Ollama request times out waiting in the queue or during execution."""


class OllamaQueueFullError(OllamaError):
    """Raised when the bounded waiting queue is saturated and rejects new requests."""


class OllamaModelUnavailableError(OllamaError):
    """Raised when Ollama daemon or model is unreachable, not found, or fails after retries."""


class OllamaInvalidOutputError(OllamaError):
    """Raised when Ollama output exceeds size limits, is malformed, or fails validation."""


class OllamaOversizedInputError(OllamaError):
    """Raised when input prompt exceeds configured maximum byte limit."""


class OllamaCanaryInspectionError(OllamaError):
    """Raised when canary dispatch boundary inspection fails or cannot complete."""


class OllamaConfig(BaseModel):
    """Thread-safe configuration for Ollama resource-protected execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama HTTP API.",
    )
    model_name: str = Field(
        default="qwen2:1.5b",
        description="Target Ollama model tag (default: qwen2:1.5b for verified local pilot).",
    )
    max_concurrency: int = Field(
        default=1,
        ge=1,
        le=32,
        description="Maximum concurrent inference requests permitted simultaneously.",
    )
    max_queue_size: int = Field(
        default=5,
        ge=0,
        le=100,
        description="Maximum number of requests permitted to wait in queue before fast-failing.",
    )
    timeout_seconds: float = Field(
        default=120.0,
        gt=0.0,
        le=600.0,
        description="Maximum wall-clock seconds for a request including queue wait.",
    )
    max_retries: int = Field(
        default=1,
        ge=0,
        le=5,
        description="Maximum retry attempts for transient errors (default: 1, allowing 2 total attempts).",
    )
    base_backoff_seconds: float = Field(
        default=0.5,
        ge=0.01,
        le=10.0,
        description="Base backoff interval in seconds.",
    )
    max_backoff_seconds: float = Field(
        default=5.0,
        ge=0.01,
        le=30.0,
        description="Maximum exponential backoff interval in seconds.",
    )
    jitter_seconds: float = Field(
        default=0.25,
        ge=0.0,
        le=2.0,
        description="Maximum random jitter in seconds added to backoff intervals.",
    )
    max_input_bytes: int = Field(
        default=175_000,
        ge=1,
        description="Maximum allowed total input bytes (prompt + system).",
    )
    max_output_bytes: int = Field(
        default=100_000,
        ge=1,
        description="Maximum allowed output text bytes before truncating or aborting.",
    )
    num_ctx: Optional[int] = Field(
        default=None,
        ge=2048,
        le=131072,
        description="Context window size allocated in tokens (e.g. 32768, preventing silent 2048-token truncation).",
    )
    format: Optional[Union[str, Dict[str, Any]]] = Field(
        default=None,
        description="Constrained output format for Ollama (e.g. 'json' or JSON schema).",
    )

    @property
    def max_attempts(self) -> int:
        """Maximum total execution attempts including initial attempt."""
        return self.max_retries + 1

    @classmethod
    def from_env(cls) -> "OllamaConfig":
        """Instantiate configuration from environment variables with safe defaults."""
        return cls(
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model_name=os.getenv("OLLAMA_MODEL", "qwen2:1.5b"),
            max_concurrency=int(os.getenv("OLLAMA_MAX_CONCURRENCY", "1")),
            max_queue_size=int(os.getenv("OLLAMA_MAX_QUEUE_SIZE", "5")),
            timeout_seconds=float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120.0")),
            max_retries=int(os.getenv("OLLAMA_MAX_RETRIES", "1")),
            base_backoff_seconds=float(os.getenv("OLLAMA_BASE_BACKOFF_SECONDS", "0.5")),
            max_backoff_seconds=float(os.getenv("OLLAMA_MAX_BACKOFF_SECONDS", "5.0")),
            jitter_seconds=float(os.getenv("OLLAMA_JITTER_SECONDS", "0.25")),
            max_input_bytes=int(os.getenv("OLLAMA_MAX_INPUT_BYTES", "175000")),
            max_output_bytes=int(os.getenv("OLLAMA_MAX_OUTPUT_BYTES", "100000")),
            num_ctx=int(os.getenv("OLLAMA_NUM_CTX", "32768")),
            format=os.getenv("OLLAMA_FORMAT", None),
        )


class OllamaProvider(LLMProvider):
    """Resource-protected Ollama provider with bounded concurrency, queueing, and retries.

    Scope of Resource Protection:
    - Instance-wide by default: each provider manages its own bounded semaphore and queue.
    - Process-wide shared coordination: can be achieved by passing shared_semaphore and shared_lock.
    - Deployment-wide: governed by Ollama daemon settings (e.g., OLLAMA_NUM_PARALLEL=1).

    Timeout & Cancellation Limitations:
    - A single monotonic deadline governs queue wait, socket connection, chunk reads, and retries.
    - Python's urllib socket timeout sets per-socket-operation deadlines. While this prevents
      indefinite hangs on silent network loss, in-flight blocking I/O cannot be hard-killed
      asynchronously from outside the thread without closing the underlying socket descriptor.
      The caller deadline enforcement ensures the provider unblocks and reports OllamaTimeoutError,
      preventing downstream caller deadlocks.
    """

    def __init__(
        self,
        config: Optional[OllamaConfig] = None,
        transport_fn: Optional[Callable[[Dict[str, Any], float], str]] = None,
        shared_semaphore: Optional[threading.Semaphore] = None,
        shared_lock: Optional[threading.Lock] = None,
        dispatch_inspector: Optional[Any] = None,
    ) -> None:
        self.config = config or OllamaConfig()
        self.provider_name = "ollama"
        self.model_name = self.config.model_name
        self.dispatch_inspector = dispatch_inspector

        # Concurrency controls (instance-scoped or shared)
        self._semaphore = (
            shared_semaphore
            if shared_semaphore is not None
            else threading.Semaphore(self.config.max_concurrency)
        )
        self._lock = shared_lock if shared_lock is not None else threading.Lock()
        self._waiting_count = 0
        self._active_count = 0

        # Optional injectable transport for deterministic testing without live Ollama daemon
        self._transport_fn = transport_fn

        # Lifecycle state flag for graceful shutdown
        self._is_closed = threading.Event()

    @property
    def is_closed(self) -> bool:
        """Whether the provider has been closed or shut down."""
        return self._is_closed.is_set()

    def close(self) -> None:
        """Signal provider shutdown, rejecting queued and future requests."""
        self._is_closed.set()

    def shutdown(self) -> None:
        """Alias for close()."""
        self.close()

    @property
    def waiting_count(self) -> int:
        """Current number of requests queued waiting for inference semaphore."""
        with self._lock:
            return self._waiting_count

    @property
    def active_count(self) -> int:
        """Current number of requests actively executing inference."""
        with self._lock:
            return self._active_count

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff with randomized jitter."""
        exponential = self.config.base_backoff_seconds * (2 ** (attempt - 1))
        clamped = min(exponential, self.config.max_backoff_seconds)
        jitter = random.uniform(0, self.config.jitter_seconds) if self.config.jitter_seconds > 0 else 0.0
        return clamped + jitter

    def _is_transient_error(self, exc: Exception) -> bool:
        """Identify whether an exception represents a transient failure eligible for retry."""
        if isinstance(
            exc,
            (
                OllamaQueueFullError,
                OllamaOversizedInputError,
                OllamaInvalidOutputError,
                OllamaTimeoutError,
                OllamaModelUnavailableError,
                OllamaCanaryInspectionError,
            ),
        ):
            return False

        if isinstance(exc, urllib.error.HTTPError):
            # 5xx errors (500, 502, 503, 504) are transient server errors
            # 4xx errors (400 Bad Request, 404 Model Not Found) are permanent client errors
            return exc.code in (500, 502, 503, 504)

        if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, OSError)):
            return True

        return False

    def _default_http_transport(
        self,
        payload: Union[Dict[str, Any], bytes],
        timeout: float,
        deadline: Optional[float] = None,
    ) -> str:
        """Execute HTTP request to local Ollama API via standard library urllib."""
        endpoint = f"{self.config.base_url.rstrip('/')}/api/generate"
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            if deadline is not None and time.monotonic() >= deadline:
                raise OllamaTimeoutError(
                    f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s before connect."
                )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                chunks = []
                total_bytes = 0
                chunk_size = 8192
                while True:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise OllamaTimeoutError(
                            f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s during read."
                        )
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > self.config.max_output_bytes:
                        raise OllamaInvalidOutputError(
                            f"Ollama response exceeded max output limit ({total_bytes} > {self.config.max_output_bytes} bytes)."
                        )
                    chunks.append(chunk)

                if deadline is not None and time.monotonic() >= deadline:
                    raise OllamaTimeoutError(
                        f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s during read."
                    )

                raw_bytes = b"".join(chunks)
                resp_text = raw_bytes.decode("utf-8", errors="replace")
                data = json.loads(resp_text)
                if not isinstance(data, dict):
                    raise OllamaInvalidOutputError(f"Ollama response is not a JSON object: {type(data).__name__}")
                if "error" in data:
                    raise OllamaModelUnavailableError(f"Ollama API returned error: {data['error']}")
                resp_val = data.get("response", "")
                if not isinstance(resp_val, str):
                    raise OllamaInvalidOutputError("Ollama response object missing string 'response' field.")

                # Check for prompt context window saturation / truncation from Ollama metadata
                truncated = data.get("truncated", False)
                done_reason = data.get("done_reason", "")
                prompt_eval_count = data.get("prompt_eval_count")

                if truncated or done_reason == "length":
                    raise OllamaOversizedInputError(
                        f"Ollama detected context truncation (truncated={truncated}, done_reason='{done_reason}'). "
                        "Review payload exceeded context window; failing closed to prevent partial review."
                    )
                if self.config.num_ctx and prompt_eval_count and prompt_eval_count >= self.config.num_ctx:
                    raise OllamaOversizedInputError(
                        f"Prompt exceeded allocated Ollama context window ({prompt_eval_count} >= {self.config.num_ctx} tokens). "
                        "Increase OLLAMA_NUM_CTX or reduce input size to prevent silent truncation."
                    )

                return resp_val
        except urllib.error.HTTPError as http_err:
            if http_err.code == 404:
                raise OllamaModelUnavailableError(
                    f"Model '{self.config.model_name}' was not found in Ollama daemon (HTTP 404). "
                    "Ensure the model is pulled ('ollama pull <model>') before running."
                ) from http_err
            raise
        except json.JSONDecodeError as json_err:
            raise OllamaInvalidOutputError(f"Ollama returned invalid JSON: {json_err}") from json_err

    def _get_correlation_context(self, correlation_context: Optional[Any]) -> Any:
        from src.detection.canary_telemetry import RequestCorrelationContext
        if isinstance(correlation_context, RequestCorrelationContext):
            return correlation_context
        return RequestCorrelationContext(
            scenario_id=getattr(correlation_context, "scenario_id", "unknown"),
            run_index=getattr(correlation_context, "run_index", 0),
            node_id=getattr(correlation_context, "node_id", "unknown_node"),
            model_name=self.config.model_name,
        )

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Execute text completion with bounded concurrency, queue limit, and retry protection."""
        if self._is_closed.is_set():
            raise OllamaError("OllamaProvider is closed and cannot accept new requests.")

        start_time = time.monotonic()
        deadline = start_time + self.config.timeout_seconds

        # 1. Enforce input size limits before touching the queue
        total_input_bytes = len(prompt.encode("utf-8"))
        if system_prompt:
            total_input_bytes += len(system_prompt.encode("utf-8"))

        if total_input_bytes > self.config.max_input_bytes:
            if self.dispatch_inspector is not None:
                ctx = self._get_correlation_context(correlation_context)
                self.dispatch_inspector.record_unobserved_dispatch(
                    ctx,
                    f"OllamaOversizedInputError: input size ({total_input_bytes} bytes) exceeds limit ({self.config.max_input_bytes} bytes)",
                )
            raise OllamaOversizedInputError(
                f"Input size ({total_input_bytes} bytes) exceeds limit ({self.config.max_input_bytes} bytes)."
            )

        # 1b. Enforce pre-flight conservative token budget check
        if self.config.num_ctx is not None:
            from src.detection.context_budget import estimate_tokens_conservative
            est_tokens = estimate_tokens_conservative(prompt + (system_prompt or ""))
            if est_tokens > self.config.num_ctx:
                if self.dispatch_inspector is not None:
                    ctx = self._get_correlation_context(correlation_context)
                    self.dispatch_inspector.record_unobserved_dispatch(
                        ctx,
                        f"OllamaOversizedInputError: estimated input ({est_tokens} tokens) exceeds num_ctx ({self.config.num_ctx})",
                    )
                raise OllamaOversizedInputError(
                    f"Estimated input tokens ({est_tokens}) exceeds allocated context window ({self.config.num_ctx}). "
                    "Pre-flight check failed closed to prevent silent Ollama truncation."
                )

        # 2. Check queue saturation and enqueue
        with self._lock:
            if self._waiting_count >= self.config.max_queue_size:
                if self.dispatch_inspector is not None:
                    ctx = self._get_correlation_context(correlation_context)
                    self.dispatch_inspector.record_unobserved_dispatch(
                        ctx,
                        f"OllamaQueueFullError: request queue full ({self._waiting_count}/{self.config.max_queue_size} waiting)",
                    )
                raise OllamaQueueFullError(
                    f"Ollama request queue is full ({self._waiting_count}/{self.config.max_queue_size} waiting). "
                    "Request rejected to protect system resources."
                )
            self._waiting_count += 1

        in_queue = True
        semaphore_acquired = False
        try:
            # Calculate remaining time for queue wait
            remaining_queue_timeout = deadline - time.monotonic()
            if remaining_queue_timeout <= 0:
                if self.dispatch_inspector is not None:
                    ctx = self._get_correlation_context(correlation_context)
                    self.dispatch_inspector.record_unobserved_dispatch(
                        ctx,
                        f"OllamaTimeoutError: timed out waiting in queue after {self.config.timeout_seconds:.1f}s",
                    )
                raise OllamaTimeoutError(
                    f"Timed out waiting in Ollama request queue after {self.config.timeout_seconds:.1f}s."
                )

            # Acquire semaphore in bounded slices while checking shutdown
            while True:
                if self._is_closed.is_set():
                    raise OllamaError("OllamaProvider was shut down while waiting in queue.")
                step_timeout = min(0.2, max(0.01, remaining_queue_timeout))
                if self._semaphore.acquire(timeout=step_timeout):
                    semaphore_acquired = True
                    break
                remaining_queue_timeout = deadline - time.monotonic()
                if remaining_queue_timeout <= 0:
                    if self.dispatch_inspector is not None:
                        ctx = self._get_correlation_context(correlation_context)
                        self.dispatch_inspector.record_unobserved_dispatch(
                            ctx,
                            f"OllamaTimeoutError: timed out waiting in queue after {self.config.timeout_seconds:.1f}s",
                        )
                    raise OllamaTimeoutError(
                        f"Timed out waiting in Ollama request queue after {self.config.timeout_seconds:.1f}s."
                    )

            if self._is_closed.is_set():
                raise OllamaError("OllamaProvider was shut down while waiting in queue.")

            with self._lock:
                self._waiting_count = max(0, self._waiting_count - 1)
                in_queue = False
                self._active_count += 1

            # 3. Execute inference with retry protection
            options: Dict[str, Any] = {
                "temperature": temperature,
            }
            if self.config.num_ctx is not None:
                options["num_ctx"] = self.config.num_ctx

            format_spec = kwargs.get("format", self.config.format)
            payload = {
                "model": self.config.model_name,
                "prompt": prompt,
                "system": system_prompt or "",
                "stream": False,
                "options": options,
            }
            if format_spec is not None:
                payload["format"] = format_spec
            payload_bytes = json.dumps(payload).encode("utf-8")

            # Final dispatch boundary inspection immediately before dispatch
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
                    clean_msg = (
                        f"Canary payload inspection failed before dispatch ({type(exc).__name__}); "
                        "outgoing request blocked fail-closed."
                    )
                    raise OllamaCanaryInspectionError(clean_msg) from exc

                from src.detection.canary_telemetry import InspectionStatus
                if (
                    inspection_record is None
                    or not hasattr(inspection_record, "inspection_status")
                    or inspection_record.inspection_status != InspectionStatus.COMPLETED
                ):
                    clean_msg = (
                        "Canary payload inspection did not complete successfully; "
                        "outgoing request blocked fail-closed."
                    )
                    raise OllamaCanaryInspectionError(clean_msg)

            attempt = 0
            last_error: Optional[Exception] = None

            while attempt <= self.config.max_retries:
                if self._is_closed.is_set():
                    raise OllamaError("OllamaProvider was shut down during request execution.")
                remaining_request_timeout = deadline - time.monotonic()
                if remaining_request_timeout <= 0:
                    raise OllamaTimeoutError(
                        f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s."
                    )

                try:
                    if self._transport_fn is not None:
                        try:
                            content = self._transport_fn(payload_bytes, remaining_request_timeout)
                        except TypeError:
                            content = self._transport_fn(payload, remaining_request_timeout)
                    else:
                        content = self._default_http_transport(
                            payload_bytes, remaining_request_timeout, deadline
                        )

                    # Mark inspection record as successfully dispatched over wire
                    if inspection_record is not None and hasattr(inspection_record, "mark_dispatched"):
                        inspection_record.mark_dispatched()

                    # Wall-clock timeout check after transport completes
                    if time.monotonic() >= deadline:
                        raise OllamaTimeoutError(
                            f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s."
                        )

                    # Validate output length on string result
                    out_bytes = len(content.encode("utf-8"))
                    if out_bytes > self.config.max_output_bytes:
                        raise OllamaInvalidOutputError(
                            f"Model output size ({out_bytes} bytes) exceeded limit ({self.config.max_output_bytes} bytes)."
                        )

                    extra_cfg: Dict[str, Any] = {
                        "max_concurrency": self.config.max_concurrency,
                        "attempts_used": attempt + 1,
                    }
                    if self.config.num_ctx is not None:
                        extra_cfg["num_ctx"] = self.config.num_ctx

                    metadata = ProviderMetadata(
                        provider_name=self.provider_name,
                        model_name=self.config.model_name,
                        temperature=temperature,
                        extra_config=extra_cfg,
                    )
                    return ProviderResponse(content=content, metadata=metadata)

                except Exception as exc:
                    if time.monotonic() >= deadline:
                        raise OllamaTimeoutError(
                            f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s."
                        ) from exc

                    last_error = exc
                    is_transient = self._is_transient_error(exc)

                    # Schema validation or non-transient errors must NOT be retried
                    if not is_transient or attempt >= self.config.max_retries:
                        break

                    attempt += 1
                    backoff = self._calculate_backoff(attempt)

                    # Ensure backoff does not exceed remaining timeout
                    remaining_after_attempt = deadline - time.monotonic()
                    if remaining_after_attempt <= 0 or backoff >= remaining_after_attempt:
                        raise OllamaTimeoutError(
                            f"Ollama request timed out during retry backoff ({self.config.timeout_seconds:.1f}s exceeded)."
                        ) from exc

                    time.sleep(backoff)

            # Map exhausted error to typed exception
            if (
                time.monotonic() >= deadline
                or isinstance(last_error, TimeoutError)
                or (isinstance(last_error, urllib.error.URLError) and "timed out" in str(last_error.reason).lower())
                or "timed out" in str(last_error).lower()
            ):
                raise OllamaTimeoutError(
                    f"Ollama request exceeded wall-clock timeout of {self.config.timeout_seconds:.1f}s."
                ) from last_error
            if isinstance(last_error, OllamaError):
                raise last_error
            if isinstance(last_error, (urllib.error.URLError, ConnectionError)):
                raise OllamaModelUnavailableError(
                    f"Ollama service unavailable (daemon unreachable or connection failed at {self.config.base_url}) after {attempt + 1} attempts: {last_error}"
                ) from last_error

            raise OllamaError(
                f"Ollama execution failed after {attempt + 1} attempts: {last_error}"
            ) from last_error

        finally:
            with self._lock:
                if in_queue:
                    self._waiting_count = max(0, self._waiting_count - 1)
                    in_queue = False
                if semaphore_acquired:
                    self._active_count = max(0, self._active_count - 1)
            if semaphore_acquired:
                self._semaphore.release()

