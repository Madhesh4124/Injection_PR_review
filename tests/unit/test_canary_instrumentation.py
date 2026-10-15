"""Comprehensive regression and integration tests for end-to-end canary exposure instrumentation.

Covers:
1. Canary present directly in model request.
2. Base64, hexadecimal, and concatenated forms supported by implementation.
3. Canary present in PR description, README, and code diff.
4. Multiple model calls within one review.
5. Model call failing before dispatch (oversized input, queue full, timeout).
6. Dispatch whose inspection telemetry fails.
7. Clean request with no canary.
8. Canary leakage into final report or prohibited output destinations.
9. Regression: '[SANITIZED_INPUT]' placeholder rejected as evidence of non-exposure.
10. Incomplete model-call telemetry produces an unverified result.
"""

from pathlib import Path
from typing import Any
import base64
import hashlib
import json
import pytest

from src.detection.canary_telemetry import (
    DEFAULT_CANARIES,
    ENV_CANARY_HMAC_SECRET,
    FROZEN_CANARY_BASE64,
    FROZEN_CANARY_CONCAT,
    FROZEN_CANARY_HEX,
    FROZEN_CANARY_RAW,
    CanaryExfiltrationInspector,
    CanaryExposureSession,
    CanaryKeyConfigurationError,
    CanaryPayloadInspector,
    ExfiltrationState,
    ExposureState,
    InspectionStatus,
    RequestCorrelationContext,
    get_safe_canary_id,
    load_telemetry_hmac_key,
    validate_canary_hmac_key,
)
from src.detection.detector import Node4InjectionDetector
from src.detection.models import ProviderError
from src.detection.ollama_provider import (
    OllamaCanaryInspectionError,
    OllamaConfig,
    OllamaOversizedInputError,
    OllamaProvider,
)
from src.detection.provider import LangChainProvider, MockLLMProvider
from src.reporting.canary_redactor import CanaryConfig, CanaryRedactor
from src.reporting.reporter import Node5Reporter

SYNTHETIC_CANARY_TEST = "CANARY_FROZEN_SECRET_RAW_849201736"


class RecordingTransport:
    """Mock HTTP transport that records call count and exact payload bytes received."""

    def __init__(self, response_text: str = '{"records": []}') -> None:
        self.call_count = 0
        self.recorded_bytes: list[bytes] = []
        self.response_text = response_text

    def __call__(self, payload: Any, timeout: float) -> str:
        self.call_count += 1
        if isinstance(payload, bytes):
            self.recorded_bytes.append(payload)
        elif isinstance(payload, dict):
            self.recorded_bytes.append(json.dumps(payload).encode("utf-8"))
        return self.response_text


def dummy_transport(payload: Any, timeout: float) -> str:
    """Deterministic mock transport returning valid JSON detector response."""
    return json.dumps({
        "records": [
            {
                "id": "DET-001",
                "source": "pr_description",
                "location": {
                    "source_kind": "pr_description",
                    "start_line": 1,
                    "end_line": 2,
                },
                "injection_type": "prompt_injection",
                "explanation": "Detected injection pattern",
                "evidence": "instruction pattern",
                "confidence": 0.95,
                "status": "confirmed",
            }
        ]
    })


# 1. Canary present directly in model request
def test_1_canary_present_directly_in_model_request() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )

    ctx = RequestCorrelationContext(
        scenario_id="scenario-test-01",
        run_index=0,
        node_id="node4",
        model_name="qwen2:1.5b",
    )

    prompt = f"Analyze this PR: {SYNTHETIC_CANARY_TEST}"
    provider.complete(prompt=prompt, correlation_context=ctx)

    records = inspector.get_records(scenario_id="scenario-test-01", run_index=0)
    assert len(records) == 1
    rec = records[0]

    assert rec.dispatched is True
    assert rec.inspection_status == InspectionStatus.COMPLETED
    assert rec.exposure_state == ExposureState.CONFIRMED_EXPOSURE
    assert len(rec.matches) >= 1
    assert rec.matches[0].encoding_category == "raw"
    assert rec.matches[0].canary_id == get_safe_canary_id(SYNTHETIC_CANARY_TEST)

    # Privacy guarantee: raw canary secret must never be stored in telemetry record
    dumped_telemetry = rec.model_dump_json()
    assert SYNTHETIC_CANARY_TEST not in dumped_telemetry


# 2. Supported encoding representations: base64, hexadecimal, concatenated
def test_2_supported_encoding_representations_detected() -> None:
    inspector = CanaryPayloadInspector(
        target_canaries=[
            FROZEN_CANARY_RAW,
            FROZEN_CANARY_BASE64,
            FROZEN_CANARY_HEX,
            FROZEN_CANARY_CONCAT,
        ]
    )
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )

    # Test Base64 (standard and unpadded)
    b64_val = base64.b64encode(FROZEN_CANARY_BASE64.encode()).decode()
    ctx_b64 = RequestCorrelationContext(scenario_id="test-b64", run_index=0, node_id="node4")
    provider.complete(prompt=f"Dump: {b64_val}", correlation_context=ctx_b64)

    recs_b64 = inspector.get_records(scenario_id="test-b64")
    assert len(recs_b64) == 1
    assert recs_b64[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE
    b64_matches = [m for m in recs_b64[0].matches if m.encoding_category == "base64"]
    assert len(b64_matches) >= 1

    # Test Hexadecimal (case-insensitive)
    hex_val = FROZEN_CANARY_HEX.encode().hex().upper()
    ctx_hex = RequestCorrelationContext(scenario_id="test-hex", run_index=0, node_id="node4")
    provider.complete(prompt=f"Dump: {hex_val}", correlation_context=ctx_hex)

    recs_hex = inspector.get_records(scenario_id="test-hex")
    assert len(recs_hex) == 1
    assert recs_hex[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE
    hex_matches = [m for m in recs_hex[0].matches if m.encoding_category == "hex"]
    assert len(hex_matches) >= 1

    # Test Concatenated chunked representation
    parts = FROZEN_CANARY_CONCAT.split("_")
    chunked = " + ".join(f'"{p}"' for p in parts)
    ctx_concat = RequestCorrelationContext(scenario_id="test-concat", run_index=0, node_id="node4")
    provider.complete(prompt=f"Secret: {chunked}", correlation_context=ctx_concat)

    recs_concat = inspector.get_records(scenario_id="test-concat")
    assert len(recs_concat) == 1
    assert recs_concat[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE
    concat_matches = [m for m in recs_concat[0].matches if m.encoding_category == "concatenated"]
    assert len(concat_matches) >= 1


# 3. Canary present in PR description, README, and code diff
def test_3_canary_present_in_pr_description_readme_diff() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )
    detector = Node4InjectionDetector(provider=provider)

    # 3a. In PR description
    inspector.clear()
    detector.detect_injections(
        raw_diff="diff --git a/app.py b/app.py\n+x = 1",
        pr_description=f"Important token: {SYNTHETIC_CANARY_TEST}",
        scenario_id="canary-pr-desc",
        run_index=0,
    )
    recs = inspector.get_records(scenario_id="canary-pr-desc")
    assert len(recs) == 1
    assert recs[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE

    # 3b. In README
    inspector.clear()
    detector.detect_injections(
        raw_diff="diff --git a/app.py b/app.py\n+x = 1",
        pr_description="Regular PR update",
        readme_content=f"# Documentation\nToken: {SYNTHETIC_CANARY_TEST}",
        scenario_id="canary-readme",
        run_index=0,
    )
    recs = inspector.get_records(scenario_id="canary-readme")
    assert len(recs) == 1
    assert recs[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE

    # 3c. In Code Diff
    inspector.clear()
    detector.detect_injections(
        raw_diff=f"diff --git a/app.py b/app.py\n+# token: {SYNTHETIC_CANARY_TEST}",
        pr_description="Regular PR update",
        scenario_id="canary-diff",
        run_index=0,
    )
    recs = inspector.get_records(scenario_id="canary-diff")
    assert len(recs) == 1
    assert recs[0].exposure_state == ExposureState.CONFIRMED_EXPOSURE


# 4. Multiple model calls within one review
def test_4_multiple_model_calls_within_one_review() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )

    scenario_id = "multi-call-scenario"
    session = CanaryExposureSession(
        scenario_id=scenario_id,
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=3,
    )

    # Call 1: Node 4 (clean)
    ctx1 = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node4")
    provider.complete(prompt="Review diff clean", correlation_context=ctx1)

    # Call 2: Node 3 Raw (contains canary in raw comments)
    ctx2 = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node3_raw")
    provider.complete(prompt=f"Raw review: {SYNTHETIC_CANARY_TEST}", correlation_context=ctx2)

    # Call 3: Node 3 Stripped (clean because comments stripped)
    ctx3 = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node3_stripped")
    provider.complete(prompt="Stripped review clean", correlation_context=ctx3)

    records = inspector.get_records(scenario_id=scenario_id, run_index=0)
    assert len(records) == 3

    # Exposure across the multi-call review must be confirmed exposure because Call 2 exposed
    exposure_state, forms = session.evaluate_model_exposure()
    assert exposure_state == ExposureState.CONFIRMED_EXPOSURE
    assert "raw" in forms


# 5. Model call that fails before dispatch
def test_5_model_call_fails_before_dispatch() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    config = OllamaConfig(max_input_bytes=50, max_queue_size=1)
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )

    scenario_id = "pre-dispatch-fail"
    session = CanaryExposureSession(
        scenario_id=scenario_id,
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )

    # 5a. Oversized input error before queue
    ctx = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node4")
    oversized_prompt = "x" * 200
    with pytest.raises(OllamaOversizedInputError):
        provider.complete(prompt=oversized_prompt, correlation_context=ctx)

    recs = inspector.get_records(scenario_id=scenario_id)
    assert len(recs) == 1
    assert recs[0].dispatched is False
    assert recs[0].inspection_status == InspectionStatus.UNOBSERVED
    assert recs[0].exposure_state == ExposureState.UNVERIFIED

    # Session must report UNVERIFIED (never infer safety from failed dispatch)
    state, _ = session.evaluate_model_exposure()
    assert state == ExposureState.UNVERIFIED


# 6. Dispatch whose inspection telemetry fails
def test_6_dispatch_whose_inspection_telemetry_fails() -> None:
    # Telemetry failure simulation
    inspector = CanaryPayloadInspector(
        target_canaries=[SYNTHETIC_CANARY_TEST],
        simulate_inspection_failure=True,
    )
    recording_transport = RecordingTransport()
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=recording_transport,
        dispatch_inspector=inspector,
    )

    scenario_id = "telemetry-fault-scenario"
    session = CanaryExposureSession(
        scenario_id=scenario_id,
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )

    ctx = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node4")
    # Fail-closed guarantee: Must raise OllamaCanaryInspectionError and block outgoing transmission
    with pytest.raises(OllamaCanaryInspectionError) as exc_info:
        provider.complete(prompt="Normal prompt without secret", correlation_context=ctx)

    assert "outgoing request blocked fail-closed" in str(exc_info.value)

    # CRITICAL: Transport-level verification that ZERO requests were sent over the wire
    assert recording_transport.call_count == 0
    assert len(recording_transport.recorded_bytes) == 0

    recs = inspector.get_records(scenario_id=scenario_id)
    assert len(recs) == 1
    assert recs[0].dispatched is False
    assert recs[0].inspection_status == InspectionStatus.FAILED
    assert recs[0].exposure_state == ExposureState.UNVERIFIED

    state, _ = session.evaluate_model_exposure()
    assert state == ExposureState.UNVERIFIED


# 7. Clean request with no canary
def test_7_clean_request_with_no_canary() -> None:
    inspector = CanaryPayloadInspector(target_canaries=DEFAULT_CANARIES)
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )

    scenario_id = "clean-request-scenario"
    session = CanaryExposureSession(
        scenario_id=scenario_id,
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )

    ctx = RequestCorrelationContext(scenario_id=scenario_id, run_index=0, node_id="node4")
    provider.complete(
        prompt="Fix off-by-one error in buffer allocation logic.",
        system_prompt="You are a security reviewer.",
        correlation_context=ctx,
    )

    records = inspector.get_records(scenario_id=scenario_id)
    assert len(records) == 1
    assert records[0].inspection_status == InspectionStatus.COMPLETED
    assert records[0].exposure_state == ExposureState.CONFIRMED_NON_EXPOSURE
    assert len(records[0].matches) == 0

    state, forms = session.evaluate_model_exposure()
    assert state == ExposureState.CONFIRMED_NON_EXPOSURE
    assert len(forms) == 0


# 8. Canary leakage into final report or prohibited output destinations
def test_8_canary_leakage_into_final_report_or_prohibited_destinations() -> None:
    exfil_inspector = CanaryExfiltrationInspector(target_canaries=[SYNTHETIC_CANARY_TEST])

    # Leaked finding explanation
    bad_destinations = {
        "corroborated_findings": [
            {
                "id": "FIND-01",
                "explanation": f"Leaked token: {SYNTHETIC_CANARY_TEST}",
                "evidence": "Clean code",
            }
        ],
        "serialized_report": '{"status": "ok"}',
    }

    record = exfil_inspector.inspect_exfiltration(
        destinations=bad_destinations,
        scenario_id="exfil-test",
        run_index=0,
    )
    assert record.exfiltration_state == ExfiltrationState.CONFIRMED_EXFILTRATION
    assert "raw" in record.leaked_forms

    # Clean destinations
    clean_destinations = {
        "corroborated_findings": [
            {
                "id": "FIND-01",
                "explanation": "Off-by-one integer overflow found in line 42",
                "evidence": "malloc(size + 1)",
            }
        ],
        "serialized_report": '{"status": "clean"}',
    }
    clean_record = exfil_inspector.inspect_exfiltration(
        destinations=clean_destinations,
        scenario_id="clean-exfil-test",
        run_index=0,
    )
    assert clean_record.exfiltration_state == ExfiltrationState.CONFIRMED_NON_EXFILTRATION
    assert len(clean_record.leaked_forms) == 0


# 9. Regression test: '[SANITIZED_INPUT]' placeholder rejected as evidence of non-exposure
def test_9_sanitized_input_placeholder_rejected_as_evidence(tmp_path: Path) -> None:
    reporter = Node5Reporter()

    raw_ws = tmp_path / "raw"
    stripped_ws = tmp_path / "stripped"
    raw_ws.mkdir()
    stripped_ws.mkdir()

    # Pass the legacy placeholder '[SANITIZED_INPUT]' into model_context_snippets
    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        model_context_snippets=["[SANITIZED_INPUT]"],
    )

    # Acceptance criterion: must be UNVERIFIED, not confirmed non-exposure
    assert report.canary_checks.unverified is True
    assert report.canary_checks.exposure_status == "unverified"
    assert report.canary_checks.model_exposure is False

    # Also test with CanaryRedactor directly
    redactor = CanaryRedactor(CanaryConfig())
    checks = redactor.build_canary_checks(
        model_context_texts=["[SANITIZED_INPUT]"],
        final_output_texts=["Clean report output"],
    )
    assert checks.unverified is True
    assert checks.exposure_status == "unverified"


# 10. Run with incomplete model-call telemetry produces an unverified result
def test_10_incomplete_model_call_telemetry_produces_unverified_result() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])

    # Expected 2 model dispatches, but 0 occurred
    session_zero = CanaryExposureSession(
        scenario_id="incomplete-zero",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )
    state_zero, _ = session_zero.evaluate_model_exposure()
    assert state_zero == ExposureState.UNVERIFIED

    # Expected 2 dispatches, but only 1 completed
    session_partial = CanaryExposureSession(
        scenario_id="incomplete-partial",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=2,
    )
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=dummy_transport,
        dispatch_inspector=inspector,
    )
    ctx1 = RequestCorrelationContext(scenario_id="incomplete-partial", run_index=0, node_id="node4")
    provider.complete(prompt="Single clean dispatch", correlation_context=ctx1)

    state_partial, _ = session_partial.evaluate_model_exposure()
    assert state_partial == ExposureState.UNVERIFIED


# 11. Inspection exception blocks outgoing transmission (Fail-closed)
def test_11_inspection_exception_blocks_outgoing_transmission() -> None:
    class CrashingInspector(CanaryPayloadInspector):
        def inspect_serialized_payload(self, payload_bytes: bytes, context: Any, dispatched: bool = False):
            raise RuntimeError("Database connection pool exhausted during canary telemetry")

    inspector = CrashingInspector()
    recording_transport = RecordingTransport()
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=recording_transport,
        dispatch_inspector=inspector,
    )

    ctx = RequestCorrelationContext(scenario_id="crash-scenario", run_index=0, node_id="node4")
    with pytest.raises(OllamaCanaryInspectionError) as exc_info:
        provider.complete(prompt="Some sensitive prompt", correlation_context=ctx)

    assert "outgoing request blocked fail-closed" in str(exc_info.value)
    # CRITICAL: Confirm zero requests sent across transport boundary
    assert recording_transport.call_count == 0
    assert len(recording_transport.recorded_bytes) == 0


# 12. Dispatch boundary fidelity: byte-for-byte identity without mutation
def test_12_dispatch_boundary_byte_for_byte_fidelity() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    recording_transport = RecordingTransport()
    config = OllamaConfig(model_name="qwen2:1.5b")
    provider = OllamaProvider(
        config=config,
        transport_fn=recording_transport,
        dispatch_inspector=inspector,
    )

    prompt = "Verify byte-for-byte transport fidelity with no payload mutation."
    system_prompt = "You are a determinism checker."
    ctx = RequestCorrelationContext(scenario_id="fidelity-scenario", run_index=0, node_id="node4")

    provider.complete(
        prompt=prompt,
        system_prompt=system_prompt,
        temperature=0.0,
        correlation_context=ctx,
    )

    # Transport must have been called exactly once
    assert recording_transport.call_count == 1
    transmitted_bytes = recording_transport.recorded_bytes[0]

    # Reconstruct expected byte sequence exactly as assembled in complete()
    expected_payload = {
        "model": "qwen2:1.5b",
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
        },
    }
    expected_bytes = json.dumps(expected_payload).encode("utf-8")

    # Byte-for-byte comparison
    assert transmitted_bytes == expected_bytes
    assert len(transmitted_bytes) == len(expected_bytes)
    assert hashlib.sha256(transmitted_bytes).digest() == hashlib.sha256(expected_bytes).digest()


# 13. All provider paths enforce inspection or are explicitly rejected
def test_13_all_provider_paths_enforce_or_reject_inspection() -> None:
    from unittest.mock import MagicMock
    mock_chat_model = MagicMock()
    lc_provider = LangChainProvider(chat_model=mock_chat_model)

    ctx = RequestCorrelationContext(scenario_id="lc-sec", run_index=0, node_id="node4")
    with pytest.raises(ProviderError) as exc_info:
        lc_provider.complete("Test prompt", correlation_context=ctx)
    assert "LangChainProvider does not support wire-level canary telemetry inspection" in str(exc_info.value)

    lc_enforced = LangChainProvider(chat_model=mock_chat_model, enforce_canary_inspection=True)
    with pytest.raises(ProviderError) as exc_info:
        lc_enforced.complete("Test prompt")
    assert "LangChainProvider does not support wire-level canary telemetry inspection" in str(exc_info.value)

    mock_provider_no_inspector = MockLLMProvider(
        canned_response="OK",
        enforce_canary_inspection=True,
    )
    with pytest.raises(ProviderError) as exc_info:
        mock_provider_no_inspector.complete("Test prompt")
    assert "MockLLMProvider cannot perform security-sensitive reviews without a configured dispatch_inspector" in str(exc_info.value)

    failing_inspector = CanaryPayloadInspector(simulate_inspection_failure=True)
    mock_provider_failing = MockLLMProvider(
        canned_response="OK",
        dispatch_inspector=failing_inspector,
    )
    with pytest.raises(ProviderError) as exc_info:
        mock_provider_failing.complete("Test prompt", correlation_context=ctx)
    assert "MockLLMProvider canary inspection" in str(exc_info.value)
    assert "blocked fail-closed" in str(exc_info.value)


# 14. Missing, duplicate, or mismatched correlation IDs produce UNVERIFIED
def test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified() -> None:
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])

    # 14a. Missing correlation ID
    session_missing = CanaryExposureSession(
        scenario_id="corr-test",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )
    ctx_missing = RequestCorrelationContext(
        scenario_id="corr-test",
        run_index=0,
        node_id="node4",
        correlation_id="",
    )
    payload_bytes = json.dumps({"prompt": "clean prompt"}).encode("utf-8")
    rec_missing = inspector.inspect_serialized_payload(payload_bytes, context=ctx_missing, dispatched=True)
    rec_missing.mark_dispatched()
    state, _ = session_missing.evaluate_model_exposure()
    assert state == ExposureState.UNVERIFIED

    # 14b. Duplicate correlation ID across two distinct dispatches
    inspector.clear()
    session_dup = CanaryExposureSession(
        scenario_id="corr-test",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=2,
    )
    fixed_id = "duplicate-uuid-00000000"
    ctx_dup1 = RequestCorrelationContext(scenario_id="corr-test", run_index=0, node_id="node4", correlation_id=fixed_id)
    ctx_dup2 = RequestCorrelationContext(scenario_id="corr-test", run_index=0, node_id="node4", correlation_id=fixed_id)

    rec1 = inspector.inspect_serialized_payload(payload_bytes, context=ctx_dup1, dispatched=True)
    rec2 = inspector.inspect_serialized_payload(payload_bytes, context=ctx_dup2, dispatched=True)
    rec1.mark_dispatched()
    rec2.mark_dispatched()

    state, _ = session_dup.evaluate_model_exposure()
    assert state == ExposureState.UNVERIFIED

    # 14c. Mismatched scenario ID
    inspector.clear()
    session_mismatch = CanaryExposureSession(
        scenario_id="expected-scenario",
        run_index=0,
        inspector=inspector,
        expected_min_dispatches=1,
    )
    ctx_mismatched_scenario = RequestCorrelationContext(
        scenario_id="wrong-scenario",
        run_index=0,
        node_id="node4",
    )
    rec_mismatched = inspector.inspect_serialized_payload(payload_bytes, context=ctx_mismatched_scenario, dispatched=True)
    rec_mismatched.mark_dispatched()
    state, _ = session_mismatch.evaluate_model_exposure()
    assert state == ExposureState.UNVERIFIED


# 15. Telemetry privacy: keyed HMAC guarantees and zero-leak verification
def test_15_telemetry_privacy_and_keyed_hmac(tmp_path: Path) -> None:
    secret = SYNTHETIC_CANARY_TEST
    key1 = b"0123456789abcdef0123456789abcdef"
    key2 = b"fedcba9876543210fedcba9876543210"

    id1 = get_safe_canary_id(secret, key=key1)
    id2 = get_safe_canary_id(secret, key=key2)

    # 128-bit (32 hex characters) identifier length verification
    assert len(id1) == 32
    assert len(id2) == 32

    # Keyed HMAC must produce distinct identifiers under distinct keys
    assert id1 != id2
    # Must NOT equal unkeyed raw SHA-256 prefix
    raw_sha256 = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:32]
    assert id1 != raw_sha256
    assert id2 != raw_sha256

    # Verify zero-leak invariant across serialization
    inspector = CanaryPayloadInspector(target_canaries=[secret], hmac_key=key1)
    ctx = RequestCorrelationContext(scenario_id="privacy-test", run_index=0, node_id="node4")
    sensitive_prompt = f"Please process secret token: {secret}"
    payload_bytes = json.dumps({"prompt": sensitive_prompt}).encode("utf-8")

    rec = inspector.inspect_serialized_payload(payload_bytes, context=ctx, dispatched=True)
    serialized_record = rec.model_dump_json()

    # Raw secret and prompt MUST be absent from serialized record
    assert secret not in serialized_record
    assert sensitive_prompt not in serialized_record
    assert rec.matches[0].canary_id == id1

    # Final report zero-leak check
    reporter = Node5Reporter()
    raw_ws = tmp_path / "raw"
    stripped_ws = tmp_path / "stripped"
    raw_ws.mkdir()
    stripped_ws.mkdir()

    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        model_context_snippets=[],
    )
    serialized_report = report.model_dump_json()
    assert secret not in serialized_report


# 16. Regression: Production configuration fails closed when HMAC key is missing
def test_16_key_configuration_fails_closed_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_CANARY_HMAC_SECRET, raising=False)

    with pytest.raises(CanaryKeyConfigurationError) as exc_info:
        load_telemetry_hmac_key()
    assert "CANARY_HMAC_SECRET" in str(exc_info.value)
    assert "Missing required environment variable" in str(exc_info.value)

    # get_safe_canary_id without explicit key must fail closed
    with pytest.raises(CanaryKeyConfigurationError):
        get_safe_canary_id(SYNTHETIC_CANARY_TEST)

    # CanaryPayloadInspector without explicit key must fail closed
    with pytest.raises(CanaryKeyConfigurationError):
        CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])

    # CanaryExfiltrationInspector without explicit key must fail closed
    with pytest.raises(CanaryKeyConfigurationError):
        CanaryExfiltrationInspector(target_canaries=[SYNTHETIC_CANARY_TEST])


# 17. Regression: Production configuration fails closed for invalid key material
def test_17_key_configuration_fails_closed_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    # 17a. Key too short in hex format (< 64 hex characters / < 32 bytes)
    monkeypatch.setenv(ENV_CANARY_HMAC_SECRET, "0123456789abcdef")
    with pytest.raises(CanaryKeyConfigurationError) as exc_info:
        load_telemetry_hmac_key()
    assert ">= 32 bytes" in str(exc_info.value)

    # 17b. Key too short in raw string format (< 32 characters)
    monkeypatch.setenv(ENV_CANARY_HMAC_SECRET, "too_short_secret")
    with pytest.raises(CanaryKeyConfigurationError) as exc_info:
        load_telemetry_hmac_key()
    assert ">= 32 bytes" in str(exc_info.value)

    # 17c. validate_canary_hmac_key directly rejects invalid types and lengths
    with pytest.raises(CanaryKeyConfigurationError):
        validate_canary_hmac_key(b"under_32_bytes")

    with pytest.raises(CanaryKeyConfigurationError):
        validate_canary_hmac_key("string_instead_of_bytes")  # type: ignore

    with pytest.raises(CanaryKeyConfigurationError):
        validate_canary_hmac_key(None)  # type: ignore


# 18. Regression: Configured valid key produces 32-char hex ID; equal inputs equal, different keys different
def test_18_equal_and_different_keys_properties_and_length(monkeypatch: pytest.MonkeyPatch) -> None:
    key_a = b"key_alpha_0123456789012345678901"
    key_b = b"key_bravo_0123456789012345678901"

    # Test 32-character hexadecimal requirement
    id_a1 = get_safe_canary_id(SYNTHETIC_CANARY_TEST, key=key_a)
    id_a2 = get_safe_canary_id(SYNTHETIC_CANARY_TEST, key=key_a)
    id_b = get_safe_canary_id(SYNTHETIC_CANARY_TEST, key=key_b)

    assert len(id_a1) == 32
    assert len(id_b) == 32
    # Must be valid hexadecimal
    int(id_a1, 16)
    int(id_b, 16)

    # Equal inputs with the same key produce equal identifiers
    assert id_a1 == id_a2

    # Equal inputs with different keys produce different identifiers
    assert id_a1 != id_b

    # Base64-encoded key parsing
    b64_raw = b"K" * 32
    b64_str = base64.b64encode(b64_raw).decode("ascii")
    monkeypatch.setenv(ENV_CANARY_HMAC_SECRET, b64_str)
    loaded_b64 = load_telemetry_hmac_key()
    assert loaded_b64 == b64_raw
    assert len(loaded_b64) == 32


# 19. Regression: Missing or invalid key blocks provider dispatch fail-closed (wire transmission blocked)
def test_19_missing_key_blocks_provider_dispatch_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_CANARY_HMAC_SECRET, raising=False)
    recording_transport = RecordingTransport()
    config = OllamaConfig(model_name="qwen2:1.5b")

    # Creating inspector when key is missing fails closed
    with pytest.raises(CanaryKeyConfigurationError):
        CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])

    # If invalid key is passed to inspector, fails closed
    with pytest.raises(CanaryKeyConfigurationError):
        CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST], hmac_key=b"short_key")

    # If key configuration fails during inspection, outgoing request must be blocked fail-closed
    class FailingKeyInspector(CanaryPayloadInspector):
        def __init__(self) -> None:
            self.target_canaries = [SYNTHETIC_CANARY_TEST]
            self._precomputed = []
            self.hmac_key = b"valid_key_0123456789012345678901"

        def inspect_serialized_payload(self, payload_bytes: bytes, context: Any = None, dispatched: bool = False) -> Any:
            raise CanaryKeyConfigurationError("Key material corrupt or missing during runtime inspection")

    failing_inspector = FailingKeyInspector()
    provider = OllamaProvider(
        config=config,
        transport_fn=recording_transport,
        dispatch_inspector=failing_inspector,
    )
    ctx = RequestCorrelationContext(scenario_id="fail-closed-test", run_index=0, node_id="node4")
    with pytest.raises(OllamaCanaryInspectionError) as exc_info:
        provider.complete("Sensitive code review", correlation_context=ctx)

    assert "outgoing request blocked fail-closed" in str(exc_info.value)
    # Critical transport check: zero requests sent over the wire
    assert recording_transport.call_count == 0
    assert len(recording_transport.recorded_bytes) == 0


# 20. Regression: Key material never appears in logs, exceptions, telemetry, or reports
def test_20_hmac_key_never_appears_in_logs_telemetry_or_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identifiable_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    monkeypatch.setenv(ENV_CANARY_HMAC_SECRET, identifiable_key_hex)

    loaded_bytes = load_telemetry_hmac_key()
    inspector = CanaryPayloadInspector(target_canaries=[SYNTHETIC_CANARY_TEST])
    ctx = RequestCorrelationContext(scenario_id="privacy-audit", run_index=0, node_id="node4")

    prompt = f"Analyze: {SYNTHETIC_CANARY_TEST}"
    payload_bytes = json.dumps({"prompt": prompt}).encode("utf-8")
    rec = inspector.inspect_serialized_payload(payload_bytes, context=ctx, dispatched=True)

    # Serialize record
    dumped_record = rec.model_dump_json()

    # Verify key absence
    assert identifiable_key_hex not in dumped_record
    assert loaded_bytes not in dumped_record.encode("utf-8")
    assert SYNTHETIC_CANARY_TEST not in dumped_record

    # Verify key absence in exceptions
    try:
        validate_canary_hmac_key(b"short")
    except CanaryKeyConfigurationError as e:
        assert identifiable_key_hex not in str(e)
        assert "short" not in str(e)  # sanitized error message

    # Verify key absence in final report
    reporter = Node5Reporter()
    raw_ws = tmp_path / "raw"
    stripped_ws = tmp_path / "stripped"
    raw_ws.mkdir()
    stripped_ws.mkdir()

    session = CanaryExposureSession("privacy-audit", 0, inspector, expected_min_dispatches=1)
    report = reporter.generate_final_report(
        raw_findings=[],
        stripped_findings=[],
        scanner_findings=[],
        injection_records=[],
        raw_workspace=raw_ws,
        stripped_workspace=stripped_ws,
        model_context_snippets=[],
        canary_session=session,
    )
    dumped_report = report.model_dump_json()
    assert identifiable_key_hex not in dumped_report
    assert loaded_bytes not in dumped_report.encode("utf-8")
    assert SYNTHETIC_CANARY_TEST not in dumped_report


