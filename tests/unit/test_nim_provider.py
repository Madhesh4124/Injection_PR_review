"""Unit tests for NVIDIA NIM Provider adapter."""

import json
from unittest.mock import MagicMock
import pytest

from src.detection.canary_telemetry import CanaryPayloadInspector, InspectionStatus
from src.detection.nim_provider import (
    NIMCanaryInspectionError,
    NIMConfig,
    NIMInvalidOutputError,
    NIMModelUnavailableError,
    NIMOversizedInputError,
    NIMProvider,
    NIMRateLimitError,
)


def test_nim_config_defaults_and_from_env(monkeypatch):
    """Verify NIMConfig defaults and environment variable overrides."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-key-123")
    monkeypatch.setenv("NIM_MODEL", "meta/llama-3.1-70b-instruct")
    monkeypatch.setenv("NIM_MAX_CONTEXT_TOKENS", "131072")

    cfg = NIMConfig.from_env()
    assert cfg.api_key == "nvapi-test-key-123"
    assert cfg.model_name == "meta/llama-3.1-70b-instruct"
    assert cfg.max_context_tokens == 131072
    assert cfg.base_url == "https://integrate.api.nvidia.com/v1"


def test_nim_provider_successful_completion():
    """Verify NIMProvider successfully formats request and parses response."""
    captured_payload = None

    def mock_transport(payload_bytes: bytes, timeout: float) -> str:
        nonlocal captured_payload
        captured_payload = json.loads(payload_bytes.decode("utf-8"))
        return "Review complete: no vulnerabilities found."

    cfg = NIMConfig(api_key="test-key", model_name="meta/llama-3.1-8b-instruct")
    provider = NIMProvider(config=cfg, transport_fn=mock_transport)

    resp = provider.complete(
        prompt="Review this code",
        system_prompt="You are a code reviewer.",
        temperature=0.0,
    )

    assert resp.content == "Review complete: no vulnerabilities found."
    assert resp.metadata.provider_name == "nvidia_nim"
    assert resp.metadata.model_name == "meta/llama-3.1-8b-instruct"
    assert captured_payload["model"] == "meta/llama-3.1-8b-instruct"
    assert len(captured_payload["messages"]) == 2
    assert captured_payload["messages"][0]["role"] == "system"


def test_nim_oversized_input_byte_limit():
    """Verify NIMProvider rejects input exceeding byte limit."""
    cfg = NIMConfig(max_input_bytes=100)
    provider = NIMProvider(config=cfg, transport_fn=lambda p, t: "ok")

    with pytest.raises(NIMOversizedInputError) as exc_info:
        provider.complete("a" * 200)

    assert "exceeds limit" in str(exc_info.value)


def test_nim_oversized_input_token_limit():
    """Verify NIMProvider rejects input exceeding context token window."""
    cfg = NIMConfig(max_context_tokens=2048)
    provider = NIMProvider(config=cfg, transport_fn=lambda p, t: "ok")

    # 10,000 characters is ~3,800 tokens, exceeding 2048
    with pytest.raises(NIMOversizedInputError) as exc_info:
        provider.complete("code line\n" * 1000)

    assert "exceeds model context limit" in str(exc_info.value)


def test_nim_canary_inspection_blocks_dispatch():
    """Verify wire-level canary inspection blocks dispatch fail-closed if canary found."""
    mock_inspector = MagicMock(spec=CanaryPayloadInspector)
    record = MagicMock()
    record.inspection_status = InspectionStatus.FAILED
    mock_inspector.inspect_serialized_payload.return_value = record

    provider = NIMProvider(
        config=NIMConfig(api_key="test"),
        transport_fn=lambda p, t: "ok",
        dispatch_inspector=mock_inspector,
    )

    with pytest.raises(NIMCanaryInspectionError):
        provider.complete("Prompt containing canary")


def test_nim_transient_retry_handling():
    """Verify provider retries on transient errors and succeeds on subsequent attempt."""
    call_count = 0

    def retry_transport(payload_bytes: bytes, timeout: float) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("Connection reset by peer (simulated 503)")
        return "Recovered response"

    cfg = NIMConfig(api_key="test", max_retries=2, base_backoff_seconds=0.01)
    provider = NIMProvider(config=cfg, transport_fn=retry_transport)

    resp = provider.complete("Retry test prompt")
    assert resp.content == "Recovered response"
    assert call_count == 2
    assert resp.metadata.extra_config["attempts_used"] == 2
