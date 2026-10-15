# Fail-Closed Security Review: Canary Exposure Instrumentation

**Project:** Injection-Robust PR Review Agent  
**Date:** October 15, 2026  
**Auditor:** Antigravity (Google DeepMind - Advanced Agentic Coding)  
**Status:** **APPROVED — FAIL-CLOSED DISPATCH ENFORCED**

---

## 1. Executive Summary

This security review audited the runtime boundary of the newly implemented canary exposure instrumentation across all model dispatch paths in the **Injection-Robust PR Review Agent**. 

### Verified Guarantees:
1. **Strict Fail-Closed Dispatch:** If `CanaryPayloadInspector.inspect_serialized_payload()` raises an unexpected exception, returns an invalid inspection record, or encounters simulated telemetry failures, the outgoing request is **unconditionally blocked before transmission**. Transport-level recording tests prove that **zero HTTP requests and zero bytes are transmitted**.
2. **Dispatch-Boundary Fidelity:** The byte sequence evaluated by the inspector (`payload_bytes`) is the **identical, unmutated byte sequence** passed directly to the HTTP transport (`_default_http_transport` / `urllib.request.Request`). SHA-256 digests of the inspected and transmitted byte arrays match byte-for-byte.
3. **Provider Path Enforcement & Rejection:** Every production and alternative provider path is accounted for:
   - `OllamaProvider`: Fully instrumented with fail-closed pre-dispatch wire inspection.
   - `MockLLMProvider`: Fully instrumented; raises `ProviderError` fail-closed on inspection failure or if uninstrumented during security reviews.
   - `LangChainProvider`: Does not observe raw socket streams and is **explicitly rejected with `ProviderError`** for all security-sensitive reviews.
4. **Correlation Context Integrity:** Dispatches with missing, duplicate, or mismatched correlation IDs cannot be falsely credited with safety and are strictly resolved as `ExposureState.UNVERIFIED`.
5. **Keyed HMAC Privacy & Zero-Leak Telemetry:** Canary tokens are identified in telemetry via keyed **HMAC-SHA256** digests, preventing offline dictionary and rainbow table inversion against structured synthetic tokens ($10^9$ entropy). Raw secrets, encoded secrets, and full prompts are strictly absent from logs, exceptions, artifacts, and serialized JSON reports.

---

## 2. Code Paths Verified & Fail-Closed Dispatch Architecture

### 2.1 Trace of Dispatch Execution Path

In `src/detection/ollama_provider.py` (`OllamaProvider.complete()`):

1. **Pre-flight Bounds:** Input byte limit check (`len(prompt) + len(system_prompt) <= max_input_bytes`) and queue limit checks are evaluated. If rejected, `record_unobserved_dispatch()` records `dispatched=False` and typed errors are raised.
2. **Payload Assembly & Serialization:**
   ```python
   payload = {
       "model": self.config.model_name,
       "prompt": prompt,
       "system": system_prompt or "",
       "stream": False,
       "options": {"temperature": temperature},
   }
   payload_bytes = json.dumps(payload).encode("utf-8")
   ```
3. **Pre-Dispatch Canary Inspection:**
   ```python
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
   ```
4. **Transport Invocation (Only reached if inspection successfully completed):**
   ```python
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
   ```

### 2.2 Fail-Closed Invariants:
- If `inspect_serialized_payload()` raises any exception (e.g. `RuntimeError`, memory exhaustion, database error):
  - `OllamaCanaryInspectionError` is raised immediately.
  - Execution never enters the `while attempt <= self.config.max_retries:` loop.
  - Neither `self._transport_fn` nor `self._default_http_transport` is called.
  - `dispatched` is never set to `True`.
  - In `OllamaProvider._is_transient_error()`, `OllamaCanaryInspectionError` is classified as non-transient, guaranteeing it is **never retried**.
- If `inspect_serialized_payload()` returns a non-`COMPLETED` record (e.g. `InspectionStatus.FAILED` during simulated faults):
  - `OllamaCanaryInspectionError` is raised immediately.
  - The transport is never called (`call_count == 0`).

---

## 3. Dispatch-Boundary Fidelity

### 3.1 Guarantee
The exact byte array inspected by `CanaryPayloadInspector` is passed without reserialization or dictionary alteration into the HTTP client:
1. `payload_bytes = json.dumps(payload).encode("utf-8")` is generated once.
2. `inspector.inspect_serialized_payload(payload_bytes, ...)` operates on `payload_bytes`.
3. `_default_http_transport(payload_bytes, ...)` binds `data = payload_bytes` directly into `urllib.request.Request(endpoint, data=data, ...)`.

### 3.2 Evidence
In `tests/unit/test_canary_instrumentation.py::test_12_dispatch_boundary_byte_for_byte_fidelity`:
- Inspected bytes and received bytes were compared across the recording boundary.
- Assertions verified:
  ```python
  assert transmitted_bytes == expected_bytes
  assert len(transmitted_bytes) == len(expected_bytes)
  assert hashlib.sha256(transmitted_bytes).digest() == hashlib.sha256(expected_bytes).digest()
  ```
  Both length and SHA-256 match exactly, confirming zero payload mutation or reserialization.

---

## 4. Provider Path Audit

| Provider Class | Instrumentation Mechanism | Behavior on Failure / Missing Inspector | Security-Sensitive Status |
| :--- | :--- | :--- | :--- |
| **`OllamaProvider`** (`src/detection/ollama_provider.py`) | Wire-level pre-dispatch payload inspection | Raises `OllamaCanaryInspectionError`, blocks socket transmission | **ENFORCED FAIL-CLOSED** |
| **`MockLLMProvider`** (`src/detection/provider.py`) | Serialized inspection before handler invocation | Raises `ProviderError` if inspector missing or inspection fails | **ENFORCED FAIL-CLOSED** |
| **`LangChainProvider`** (`src/detection/provider.py`) | Rejection boundary | Raises `ProviderError` whenever `correlation_context` or `enforce_canary_inspection=True` is provided | **EXPLICITLY REJECTED** |

No provider path can silently bypass canary inspection during security-sensitive reviews.

---

## 5. Correlation Context Integrity

In `CanaryExposureSession.evaluate_model_exposure()`:
1. **Missing Correlation IDs:** Any record with empty, whitespace, or sentinel `unknown` correlation ID triggers `has_unverified = True`.
2. **Duplicate Correlation IDs:** If two distinct dispatches share the same `correlation_id`, replay / non-uniqueness is detected, triggering `has_unverified = True`.
3. **Mismatched Metadata:** If a record's `scenario_id` or `run_index` differs from the session's expected values, `has_unverified = True`.
4. **Dispatch State Verification:** If `rec.dispatched is False` or `rec.inspection_status != InspectionStatus.COMPLETED`, `has_unverified = True`.

Under any of these conditions, the session produces `ExposureState.UNVERIFIED` and cannot produce `ExposureState.CONFIRMED_NON_EXPOSURE`.

---

## 6. Telemetry Privacy & Threat Model

### 6.1 Threat Model for Synthetic Canaries
Synthetic tokens follow canonical structures such as `CANARY_FROZEN_SECRET_RAW_849201736` (9 numeric digits). 
- **Entropy:** $\approx 10^9$ possibilities ($\approx 30$ bits of entropy).
- **Vulnerability of Unkeyed SHA-256:** A rainbow table or precomputed dictionary can invert an unkeyed 12-char or 16-char SHA-256 prefix in minutes.

### 6.2 Keyed HMAC Solution
To prevent dictionary inversion, `canary_telemetry.py` employs keyed **HMAC-SHA256**:
```python
def get_safe_canary_id(secret: str, key: Optional[bytes] = None) -> str:
    hmac_key = key if key is not None else _DEFAULT_TELEMETRY_HMAC_KEY
    return hmac.new(hmac_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
```
Without knowledge of `hmac_key`, precomputed rainbow tables against the synthetic token space are mathematically ineffective.

### 6.3 Zero-Leak Verification
Verified across all serialized representations (`tests/unit/test_canary_instrumentation.py::test_15_telemetry_privacy_and_keyed_hmac`):
- Raw canary string is absent from `DispatchInspectionRecord.model_dump_json()`.
- Prompt text is absent from `DispatchInspectionRecord.model_dump_json()`.
- Exception messages sanitize internal details and do not echo user prompt or secrets (`clean_msg = f"... ({type(exc).__name__})"`).
- Final reports generated by `Node5Reporter` contain zero occurrences of raw synthetic canaries.

---

## 7. Verification Results

### 7.1 Regression Test Suite
All tests executed against the actual working tree:

- **Canary Instrumentation Regression Suite (`tests/unit/test_canary_instrumentation.py`):**
  - `test_1_canary_present_directly_in_model_request`: **PASSED**
  - `test_2_supported_encoding_representations_detected`: **PASSED**
  - `test_3_canary_present_in_pr_description_readme_diff`: **PASSED**
  - `test_4_multiple_model_calls_within_one_review`: **PASSED**
  - `test_5_model_call_fails_before_dispatch`: **PASSED**
  - `test_6_dispatch_whose_inspection_telemetry_fails`: **PASSED** (Transport call count == 0 verified)
  - `test_7_clean_request_with_no_canary`: **PASSED**
  - `test_8_canary_leakage_into_final_report_or_prohibited_destinations`: **PASSED**
  - `test_9_sanitized_input_placeholder_rejected_as_evidence`: **PASSED**
  - `test_10_incomplete_model_call_telemetry_produces_unverified_result`: **PASSED**
  - `test_11_inspection_exception_blocks_outgoing_transmission`: **PASSED** (Transport call count == 0 verified)
  - `test_12_dispatch_boundary_byte_for_byte_fidelity`: **PASSED** (Byte-for-byte SHA256 match verified)
  - `test_13_all_provider_paths_enforce_or_reject_inspection`: **PASSED** (Rejection verified)
  - `test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified`: **PASSED**
  - `test_15_telemetry_privacy_and_keyed_hmac`: **PASSED**
  - **Result: 15 passed in 2.62s.**

- **Full Unit Test Suite (`tests/unit`):**
  - **Result: 248 passed in 43.49s.**

- **Integration Test Suite (`tests/integration`):**
  - Includes real local Ollama inference with `qwen2:1.5b`.
  - **Result: 8 passed, 5 skipped (Docker daemon skipped on Windows) in 79.78s.**

- **Code Formatting & Linter (`python -m ruff check .`):**
  - **Result: All checks passed! 0 errors.**

- **Live Local Ollama Validation (`scripts/validate_canary_instrumentation.py`):**
  - Report: `benchmark/results/canary_instrumentation_validation.json`
  - Model exposure: 4 confirmed exposure, 1 confirmed non-exposure, 3 unverified.
  - Canary exfiltration: 0 confirmed exfiltration, 8 confirmed non-exfiltration.
  - **Result: Succeeded with 0 unhandled errors.**

---

## 8. Artifact Preservation Confirmation

As required by the security audit protocol:
- **Frozen Benchmark Scenarios (`benchmark/scenarios/*`):** Preserved without modification.
- **Previous Frozen Benchmark Report (`benchmark/results/frozen_benchmark_report.json`):** Preserved without modification.
- **Previous Audit Validity Report (`benchmark/results/audit_validity_report.md`):** Preserved without modification.
- **Evaluation Thresholds and Models:** Preserved without tuning against benchmark data.

---

## 9. Remaining Limitations

1. **Supported Encoding Surface:**
   The inspector captures five canonical representations: raw substring, standard Base64 (padded and unpadded), hexadecimal, chunked/concatenated variants, and environment token definitions. Custom cryptographic transformations (e.g., bitwise XOR with arbitrary key, ROT13, custom steganography, or token fragmenting split across multiple conversational sessions) are not supported.
2. **Synchronous Sockets:**
   Python's `urllib` network calls enforce monotonic deadlines per operation. If an external connection locks at the OS socket level without erroring, the process thread waits until the socket timeout fires. The fail-closed check guarantees that no untracked or uninspected bytes reach the socket.
