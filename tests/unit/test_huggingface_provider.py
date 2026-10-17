"""Unit tests for Hugging Face provider adapter supporting high-context models."""

import json
from unittest.mock import MagicMock
import pytest

from src.detection.huggingface_provider import (
    HuggingFaceCanaryInspectionError,
    HuggingFaceConfig,
    HuggingFaceError,
    HuggingFaceInvalidOutputError,
    HuggingFaceOversizedInputError,
    HuggingFaceProvider,
    HuggingFaceRateLimitError,
    HuggingFaceTimeoutError,
)
from src.detection.canary_telemetry import (
    CanaryPayloadInspector,
    InspectionStatus,
    RequestCorrelationContext,
)


def test_huggingface_config_defaults_and_env(monkeypatch):
    """Verify HuggingFaceConfig has large context defaults and reads environment correctly."""
    monkeypatch.setenv("HF_TOKEN", "hf_test_token_123")
    monkeypatch.setenv("HF_MODEL", "Qwen/Qwen2.5-Coder-32B-Instruct")
    monkeypatch.setenv("HF_NUM_CTX", "65536")

    cfg = HuggingFaceConfig.from_env()
    assert cfg.api_key == "hf_test_token_123"
    assert cfg.model_name == "Qwen/Qwen2.5-Coder-32B-Instruct"
    assert cfg.max_context_tokens == 65536
    assert cfg.max_new_tokens == 4096


def test_huggingface_complete_with_transport():
    """Verify complete() executes cleanly through transport and returns ProviderResponse."""
    def mock_transport(payload_bytes, timeout):
        data = json.loads(payload_bytes.decode("utf-8"))
        assert data["model"] == "Qwen/Qwen2.5-Coder-7B-Instruct"
        assert len(data["messages"]) == 2
        assert data["messages"][0]["role"] == "system"
        assert data["messages"][1]["role"] == "user"
        return '{"findings": []}'

    cfg = HuggingFaceConfig(model_name="Qwen/Qwen2.5-Coder-7B-Instruct", max_context_tokens=32768)
    provider = HuggingFaceProvider(config=cfg, transport_fn=mock_transport)

    resp = provider.complete(
        prompt="Review this code.",
        system_prompt="You are a reviewer.",
        temperature=0.0,
    )
    assert resp.content == '{"findings": []}'
    assert resp.metadata.provider_name == "huggingface"
    assert resp.metadata.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert resp.metadata.extra_config["num_ctx"] == 32768


def test_huggingface_oversized_input_rejected():
    """Verify prompts exceeding max_input_bytes are rejected before dispatch."""
    cfg = HuggingFaceConfig(max_input_bytes=100)
    provider = HuggingFaceProvider(config=cfg, transport_fn=lambda p, t: "ok")

    huge_prompt = "A" * 200
    with pytest.raises(HuggingFaceOversizedInputError) as exc_info:
        provider.complete(prompt=huge_prompt)
    assert "exceeds limit" in str(exc_info.value)


def test_huggingface_output_size_limit():
    """Verify output exceeding max_output_bytes raises HuggingFaceInvalidOutputError."""
    cfg = HuggingFaceConfig(max_output_bytes=50)
    provider = HuggingFaceProvider(config=cfg, transport_fn=lambda p, t: "X" * 100)

    with pytest.raises(HuggingFaceInvalidOutputError) as exc_info:
        provider.complete(prompt="hello")
    assert "exceeded limit" in str(exc_info.value)


def test_huggingface_canary_inspection_enforced():
    """Verify dispatch_inspector inspects serialized payload and marks dispatched."""
    inspector = MagicMock()
    mock_record = MagicMock()
    mock_record.inspection_status = InspectionStatus.COMPLETED
    inspector.inspect_serialized_payload.return_value = mock_record

    provider = HuggingFaceProvider(
        config=HuggingFaceConfig(),
        transport_fn=lambda p, t: "result",
        dispatch_inspector=inspector,
    )

    ctx = RequestCorrelationContext(
        scenario_id="dev-twin-01",
        run_index=1,
        node_id="baseline",
        model_name="hf-qwen",
    )
    resp = provider.complete("Check code", correlation_context=ctx)

    assert resp.content == "result"
    assert inspector.inspect_serialized_payload.called
    assert mock_record.mark_dispatched.called


def test_huggingface_retry_on_rate_limit():
    """Verify transient rate-limit errors trigger backoff and retry."""
    attempts = 0

    def flaky_transport(payload_bytes, timeout):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HuggingFaceRateLimitError("Rate limit 429 exceeded")
        return "success after retry"

    cfg = HuggingFaceConfig(
        max_retries=2,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.05,
        jitter_seconds=0.01,
    )
    provider = HuggingFaceProvider(config=cfg, transport_fn=flaky_transport)
    resp = provider.complete("Test retry")

    assert attempts == 2
    assert resp.content == "success after retry"
    assert resp.metadata.extra_config["attempts_used"] == 2
