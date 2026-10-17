"""Unit tests for OpenRouter Provider adapter."""

import json
from unittest.mock import MagicMock
import pytest

from src.detection.canary_telemetry import CanaryPayloadInspector, InspectionStatus
from src.detection.openrouter_provider import (
    OpenRouterCanaryInspectionError,
    OpenRouterConfig,
    OpenRouterCreditsExhaustedError,
    OpenRouterInvalidOutputError,
    OpenRouterModelUnavailableError,
    OpenRouterOversizedInputError,
    OpenRouterProvider,
    OpenRouterRateLimitError,
)


def test_openrouter_config_defaults_and_from_env(monkeypatch):
    """Verify OpenRouterConfig defaults and environment variable overrides."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "mock-openrouter-test-api-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "google/gemma-2-9b-it:free")
    monkeypatch.setenv("OPENROUTER_MAX_CONTEXT_TOKENS", "131072")

    cfg = OpenRouterConfig.from_env()
    assert cfg.api_key == "mock-openrouter-test-api-key"
    assert cfg.model_name == "google/gemma-2-9b-it:free"
    assert cfg.max_context_tokens == 131072
    assert cfg.base_url == "https://openrouter.ai/api/v1"


def test_openrouter_provider_successful_completion():
    """Verify OpenRouterProvider formats request and parses response correctly."""
    captured_payload = None

    def mock_transport(payload_bytes: bytes, timeout: float) -> str:
        nonlocal captured_payload
        captured_payload = json.loads(payload_bytes.decode("utf-8"))
        return "PR review: No security vulnerabilities found in diff."

    cfg = OpenRouterConfig(api_key="test-key", model_name="meta-llama/llama-3.1-8b-instruct:free")
    provider = OpenRouterProvider(config=cfg, transport_fn=mock_transport)

    resp = provider.complete(
        prompt="Review this git diff",
        system_prompt="You are a secure code reviewer.",
        temperature=0.0,
    )

    assert resp.content == "PR review: No security vulnerabilities found in diff."
    assert resp.metadata.provider_name == "openrouter"
    assert resp.metadata.model_name == "meta-llama/llama-3.1-8b-instruct:free"
    assert captured_payload["model"] == "meta-llama/llama-3.1-8b-instruct:free"
    assert len(captured_payload["messages"]) == 2
    assert captured_payload["messages"][0]["role"] == "system"
    assert captured_payload["messages"][1]["role"] == "user"


def test_openrouter_oversized_input_byte_limit():
    """Verify OpenRouterProvider rejects input exceeding byte limit."""
    cfg = OpenRouterConfig(max_input_bytes=100)
    provider = OpenRouterProvider(config=cfg, transport_fn=lambda p, t: "ok")

    with pytest.raises(OpenRouterOversizedInputError) as exc_info:
        provider.complete("x" * 200)

    assert "exceeds limit" in str(exc_info.value)


def test_openrouter_oversized_input_token_limit():
    """Verify OpenRouterProvider rejects input exceeding context token window."""
    cfg = OpenRouterConfig(max_context_tokens=2048)
    provider = OpenRouterProvider(config=cfg, transport_fn=lambda p, t: "ok")

    with pytest.raises(OpenRouterOversizedInputError) as exc_info:
        provider.complete("code chunk line\n" * 1000)

    assert "exceeds model context limit" in str(exc_info.value)


def test_openrouter_canary_inspection_blocks_dispatch():
    """Verify wire-level canary inspection blocks dispatch fail-closed if canary found."""
    mock_inspector = MagicMock(spec=CanaryPayloadInspector)
    record = MagicMock()
    record.inspection_status = InspectionStatus.FAILED
    mock_inspector.inspect_serialized_payload.return_value = record

    provider = OpenRouterProvider(
        config=OpenRouterConfig(api_key="test"),
        transport_fn=lambda p, t: "ok",
        dispatch_inspector=mock_inspector,
    )

    with pytest.raises(OpenRouterCanaryInspectionError):
        provider.complete("Prompt containing canary")


def test_openrouter_transient_retry_handling():
    """Verify provider retries on transient errors and succeeds on subsequent attempt."""
    call_count = 0

    def retry_transport(payload_bytes: bytes, timeout: float) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("Connection reset by peer (simulated 503)")
        return "Recovered response from OpenRouter"

    cfg = OpenRouterConfig(api_key="test", max_retries=2, base_backoff_seconds=0.01)
    provider = OpenRouterProvider(config=cfg, transport_fn=retry_transport)

    resp = provider.complete("Retry test prompt")
    assert resp.content == "Recovered response from OpenRouter"
    assert call_count == 2
    assert resp.metadata.extra_config["attempts_used"] == 2


def test_openrouter_request_budget_enforcement():
    """Verify provider halts and raises OpenRouterRateLimitError when request budget is exhausted."""
    cfg = OpenRouterConfig(api_key="test", request_budget=2)
    provider = OpenRouterProvider(config=cfg, transport_fn=lambda p, t: "response")

    # 1st and 2nd requests succeed within budget
    r1 = provider.complete("p1")
    r2 = provider.complete("p2")
    assert r1.content == "response"
    assert r2.content == "response"

    # 3rd request violates budget
    with pytest.raises(OpenRouterRateLimitError) as exc_info:
        provider.complete("p3")

    assert "Configured request budget (2) reached" in str(exc_info.value)


def test_openrouter_error_message_redacts_api_keys():
    """Verify provider redacts any API key from HTTP error bodies."""
    import urllib.error
    import io

    headers = {"Content-Type": "application/json"}
    err_body = '{"error": "Unauthorized sk-or-v1-supersecretkey123456789"}'
    fp = io.BytesIO(err_body.encode("utf-8"))
    http_error = urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs=headers,
        fp=fp,
    )

    def failing_transport(payload_bytes: bytes, timeout: float) -> str:
        raise http_error

    provider = OpenRouterProvider(config=OpenRouterConfig(api_key="secret"), transport_fn=failing_transport)

    with pytest.raises(Exception) as exc_info:
        provider.complete("test")

    err_str = str(exc_info.value)
    assert "sk-or-v1-supersecretkey123456789" not in err_str

