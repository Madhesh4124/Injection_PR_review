# Independent Read-Only Security Verification Report: Canary Instrumentation

**Project:** Injection-Robust PR Review Agent  
**Date:** October 15, 2026  
**Auditor:** Antigravity (Google DeepMind - Advanced Agentic Coding)  
**Report File:** `benchmark/results/canary_read_only_verification_report.md`  
**Executive Verdict:** **VERIFIED WITH LIMITATIONS**

---

## 1. Executive Summary

An independent, read-only security verification of the canary exposure and exfiltration telemetry instrumentation was conducted across all model execution boundaries in the **Injection-Robust PR Review Agent**.

### Summary of Verification Outcomes:
- **Fail-Closed Dispatch Enforcement:** **VERIFIED**. Outgoing requests are unconditionally blocked before transmission if payload inspection raises an exception, returns an incomplete/malformed record, or encounters telemetry faults. Transport recording tests verify that **zero requests and zero bytes are transmitted** upon inspection failure.
- **Dispatch-Boundary Fidelity:** **VERIFIED**. The serialized JSON byte sequence (`payload_bytes`) evaluated by `CanaryPayloadInspector` is the identical, byte-for-byte sequence passed directly to the HTTP transport (`_default_http_transport` / `urllib.request.Request`). No payload mutation, re-keying, or reserialization occurs.
- **Provider Coverage & Rejection:** **VERIFIED**. `OllamaProvider` enforces wire-level inspection; `MockLLMProvider` enforces inspection fail-closed; and `LangChainProvider` is explicitly rejected with `ProviderError` for all security-sensitive reviews. No silent fallback paths exist.
- **Correlation Integrity:** **VERIFIED**. Missing, empty, duplicate, or mismatched correlation IDs prevent `CONFIRMED_NON_EXPOSURE` and force `UNVERIFIED`.
- **Telemetry Privacy:** **VERIFIED WITH LIMITATIONS**. Raw secrets, Base64 forms, hex forms, concatenated forms, and sensitive prompt text are strictly absent from logs, exceptions, telemetry records, and serialized reports. However, the default HMAC key is derived from a static in-source salt, which is susceptible to offline dictionary attacks if an attacker with source-code access knows the structured synthetic token space ($10^9$ entropy).

---

## 2. Repository State and Audited Scope

### 2.1 Git Working Tree
- **Branch:** `main` (clean tracking, untracked development and benchmark artifacts present).
- **Working Tree Integrity:** Zero modified files in `benchmark/scenarios/`. Frozen ground-truth manifests, scenarios, benchmark configurations, and previously generated audit reports (`frozen_benchmark_report.json`, `audit_validity_report.md`, `canary_fail_closed_security_review.md`) remain **completely unmodified**.

### 2.2 Exact Files and Functions Inspected
1. **`src/detection/ollama_provider.py`**:
   - `OllamaProvider.complete()`: Lines 328–510 (pre-dispatch bounds, payload assembly, wire inspection, HTTP dispatch).
   - `OllamaProvider._default_http_transport()`: Lines 250–315 (urllib request creation and streaming read).
   - `OllamaProvider._is_transient_error()`: Lines 225–248 (exception categorization; `OllamaCanaryInspectionError` classified as non-transient).
   - `OllamaCanaryInspectionError`: Lines 54–56 (explicit typed exception).
2. **`src/detection/canary_telemetry.py`**:
   - `CanaryPayloadInspector.inspect_serialized_payload()`: Lines 250–360 (thread-safe byte scanning, exception sanitization).
   - `CanaryPayloadInspector._precompute_patterns()`: Lines 180–245 (regex compilation for raw, base64, hex, concat, env).
   - `CanaryExposureSession.evaluate_model_exposure()`: Lines 490–545 (correlation ID uniqueness, presence, metadata match, tri-state resolution).
   - `CanaryExposureSession.build_canary_checks()`: Lines 546–585 (reconciliation, placeholder rejection).
   - `get_safe_canary_id()`: Lines 60–72 (keyed HMAC-SHA256 generation).
3. **`src/detection/provider.py`**:
   - `MockLLMProvider.complete()`: Lines 61–125 (fail-closed inspection gate, missing-inspector rejection).
   - `LangChainProvider.complete()`: Lines 140–165 (unsupported provider rejection on security-sensitive correlation).
4. **`src/detection/detector.py`**:
   - `Node4InjectionDetector.detect_injections()`: Lines 41–165 (correlation context forwarding, prompt formatting).
5. **`src/reporting/reporter.py`**:
   - `Node5Reporter.generate_final_report()`: Lines 41–223 (deterministic corroboration, discrepancy matching, canary redaction).
6. **`tests/unit/test_canary_instrumentation.py`**:
   - 15 comprehensive unit regression tests covering fail-closed dispatch, byte-for-byte fidelity, provider rejection, correlation validation, and zero-leak privacy.

---

## 3. HMAC Key Management and Identifier Privacy

### 3.1 Key Lifecycle Analysis
- **Generation:** `_DEFAULT_TELEMETRY_HMAC_KEY: bytes = hashlib.sha256(b"antigravity-canary-telemetry-key-v1").digest()` generates a 256-bit (32-byte) key.
- **Supply Mechanism:** `CanaryPayloadInspector` and `CanaryExfiltrationInspector` accept an optional `hmac_key: Optional[bytes] = None`. When omitted, they fall back to `_DEFAULT_TELEMETRY_HMAC_KEY`.
- **Storage:** In-memory module variable. It is never logged, never printed, and never serialized into JSON reports.
- **Exposure in Diagnostics:** Verified that exceptions, error logs, and telemetry schemas do not echo the HMAC key or raw secrets. Exception messages are sanitized:
  `clean_msg = f"Canary payload inspection failed before dispatch ({type(exc).__name__}); outgoing request blocked fail-closed."`

### 3.2 Threat Model & Collision Assessment
- **Secret Space Entropy:** Synthetic canaries follow patterns like `CANARY_FROZEN_SECRET_RAW_<9 digits>` ($\approx 10^9$ possibilities, $\approx 30$ bits of entropy).
- **Default Salt Predictability:** Because `b"antigravity-canary-telemetry-key-v1"` is static in source code, an adversary with access to the codebase knows the default key and could compute an offline dictionary of all $10^9$ HMACs.
- **Truncation Length (16 Hex Characters = 64 bits):**
  - Collision probability for $N$ records: $P \approx \frac{N^2}{2 \times 2^{64}}$.
  - For $N = 100$ target canaries, $P \approx 2.7 \times 10^{-16}$.
  - For $N = 10^5$ records, $P \approx 2.7 \times 10^{-10}$ (negligible).
  - *Recommendation:* Increase default truncation to 32 hex characters (128 bits) to satisfy NIST SP 800-107 high-assurance recommendations, and load `CANARY_HMAC_SECRET` from environment variables when available.

### 3.3 Zero-Leak Verification
Verified via `tests/unit/test_canary_instrumentation.py::test_15_telemetry_privacy_and_keyed_hmac`:
- Raw canary tokens: **ABSENT** from telemetry records and reports.
- Base64, hex, and concat forms: **ABSENT** from telemetry records and reports.
- Full prompts and request envelopes: **ABSENT** from telemetry records and reports.
- Telemetry records store only the 16-character HMAC digest prefix (`canary_id`), the encoding category, and match booleans.

---

## 4. Dispatch Boundary Verification

### 4.1 Step-by-Step Execution Trace

```
Caller -> Node4InjectionDetector.detect_injections()
  |
  +-> Format user prompt & system prompt
  +-> Pass RequestCorrelationContext
  +-> OllamaProvider.complete()
        |
        +-> Input size & queue capacity checks (pre-flight)
        +-> payload = {"model": ..., "prompt": prompt, "system": system_prompt, ...}
        +-> payload_bytes = json.dumps(payload).encode("utf-8")  [SINGLE SERIALIZATION]
        |
        +-- [PRE-DISPATCH INSPECTION BOUNDARY]
        |     |
        |     +-> CanaryPayloadInspector.inspect_serialized_payload(payload_bytes, dispatched=False)
        |     |
        |     +-> EXCEPTION OR INVALID STATUS?
        |           YES: Raise OllamaCanaryInspectionError(fail_closed)
        |                [TRANSPORT NEVER CALLED; 0 BYTES TRANSMITTED]
        |           NO:  Proceed to transport loop
        |
        +-- [TRANSPORT DISPATCH BOUNDARY]
              |
              +-> self._default_http_transport(payload_bytes, timeout, deadline)
              |     |
              |     +-> data = payload_bytes  [EXACT BYTES, NO RE-SERIALIZATION]
              |     +-> req = urllib.request.Request(endpoint, data=data)
              |     +-> urllib.request.urlopen(req, timeout=timeout)
              |
              +-> On HTTP Success: inspection_record.mark_dispatched() (dispatched = True)
              +-> On HTTP Error / Timeout: dispatched remains False
```

### 4.2 Independent Verification Checklist

| Property | Verified? | Evidence |
| :--- | :---: | :--- |
| Single serialization | **YES** | `payload_bytes` serialized on line 428 of `ollama_provider.py`; reused directly for inspection and transport. |
| Inspector receives exact bytes | **YES** | `inspect_serialized_payload(payload_bytes=payload_bytes)` called on line 434. |
| Transport receives exact bytes | **YES** | `_default_http_transport(payload_bytes, ...)` called on line 458; `req.data == payload_bytes`. |
| Zero mutation between inspect & dispatch | **YES** | `test_12_dispatch_boundary_byte_for_byte_fidelity`: `assert transmitted_bytes == expected_bytes`. |
| Exceptions block transport | **YES** | `test_11_inspection_exception_blocks_outgoing_transmission`: `recording_transport.call_count == 0`. |
| Malformed results block transport | **YES** | `test_6_dispatch_whose_inspection_telemetry_fails`: `recording_transport.call_count == 0`. |
| Retry mechanism bypass prevented | **YES** | `OllamaCanaryInspectionError` classified as non-transient in `_is_transient_error()` (line 235). |
| Pre-dispatch errors marked UNVERIFIED | **YES** | `test_5_model_call_fails_before_dispatch`: `recs[0].dispatched is False`, state is `UNVERIFIED`. |

---

## 5. Provider and Fallback Path Coverage

### 5.1 Provider Implementations in Codebase
Only three classes implement `LLMProvider`:
1. `OllamaProvider` (`src/detection/ollama_provider.py`):
   - Active production engine.
   - Enforces pre-dispatch inspection before `_default_http_transport`.
2. `MockLLMProvider` (`src/detection/provider.py`):
   - Offline testing provider.
   - Raises `ProviderError` fail-closed if `dispatch_inspector` raises or fails.
   - Raises `ProviderError` if `enforce_canary_inspection=True` and `dispatch_inspector` is missing.
3. `LangChainProvider` (`src/detection/provider.py`):
   - Adapter for LangChain chat models.
   - Raises `ProviderError("LangChainProvider does not support wire-level canary telemetry inspection and is explicitly rejected for security-sensitive reviews.")` whenever `correlation_context` is provided or `enforce_canary_inspection=True`.

### 5.2 Factory / Registry / Fallback Audit
- Search for provider factories, registries, and dynamic fallback switches confirmed that **no automatic cloud fallbacks or alternative HTTP clients exist**.
- Inference is exclusively routed to Ollama.
- Configuration errors (e.g. invalid model tag, unreachable daemon) produce explicit typed exceptions (`OllamaModelUnavailableError`, `OllamaTimeoutError`), never fallback to mock or cloud providers.

---

## 6. Correlation Integrity and Exposure-State Semantics

The tri-state logic in `CanaryExposureSession.evaluate_model_exposure()` was verified against all fault conditions:

| Scenario Condition | Expected State | Actual State | Verified In |
| :--- | :---: | :---: | :--- |
| Missing / empty `correlation_id` | `UNVERIFIED` | `UNVERIFIED` | `test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified` |
| Duplicate `correlation_id` across dispatches | `UNVERIFIED` | `UNVERIFIED` | `test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified` |
| Mismatched `scenario_id` | `UNVERIFIED` | `UNVERIFIED` | `test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified` |
| Mismatched `run_index` | `UNVERIFIED` | `UNVERIFIED` | `test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified` |
| Missing dispatch record (fewer than expected) | `UNVERIFIED` | `UNVERIFIED` | `test_10_incomplete_model_call_telemetry_produces_unverified_result` |
| Inspector telemetry failure | `UNVERIFIED` | `UNVERIFIED` | `test_6_dispatch_whose_inspection_telemetry_fails` |
| Pre-dispatch failure (oversized / queue full) | `UNVERIFIED` | `UNVERIFIED` | `test_5_model_call_fails_before_dispatch` |
| Transport failure / timeout | `UNVERIFIED` | `UNVERIFIED` | `rec.dispatched` remains `False` -> triggers `UNVERIFIED` |
| Clean request with complete evidence | `CONFIRMED_NON_EXPOSURE` | `CONFIRMED_NON_EXPOSURE` | `test_7_clean_request_with_no_canary` |
| Canary present in request | `CONFIRMED_EXPOSURE` | `CONFIRMED_EXPOSURE` | `test_1_canary_present_directly_in_model_request` |
| Placeholder used (`[SANITIZED_INPUT]`) | `UNVERIFIED` | `UNVERIFIED` | `test_9_sanitized_input_placeholder_rejected_as_evidence` |

**Invariant Established:** `CONFIRMED_NON_EXPOSURE` strictly requires affirmative evidence that all expected dispatches were executed, inspected, completed with `dispatched=True`, contained zero canary matches, and possessed valid, unique correlation metadata.

---

## 7. Reporting, Redaction, and Deterministic Finding Preservation

In `src/reporting/reporter.py` (`Node5Reporter`):
1. **Deterministic Finding Primacy:**
   - Scanner findings (`Bandit`, `Semgrep`) originate from deterministic local AST/pattern analyzers.
   - LLM model findings are cross-checked via `match_findings_across_views()` and `are_categories_equivalent()`.
   - Stripped-only findings are preserved even if adversarial comments suppressed raw LLM review.
   - An LLM cannot delete, suppress, downgrade, or alter deterministic findings.
2. **Canary Redaction:**
   - `CanaryRedactor.redact_data()` sanitizes finding explanations, evidence strings, file paths, and discrepancy notes prior to assembling `FinalReport`.
3. **Conservative Failure Handling:**
   - If any static analysis tool, scanner, or infrastructure component fails, `RunMetadata.review_complete` is forced to `False` and `infrastructure_failure` is set to `True`.

---

## 8. Verification Commands and Test Results

### 8.1 Automated Test Execution

| Command | Test Target | Results | Execution Time |
| :--- | :--- | :--- | :--- |
| `python -m pytest tests/unit/test_canary_instrumentation.py -v` | Dedicated fail-closed & canary tests | **15 passed** | 2.62s |
| `python -m pytest tests/unit -v` | Full unit regression test suite | **248 passed** | 43.49s |
| `python -m pytest tests/integration -v` | Live Ollama & provider integration | **8 passed, 5 skipped** | 79.78s |
| `python -m ruff check .` | Code formatting & lint check | **All checks passed! (0 errors)** | 1.85s |
| `python scripts/validate_canary_instrumentation.py` | Local Ollama live validation script | **8 runs completed; 0 unhandled errors** | 98.41s |

### 8.2 Skipped Tests Analysis
- **Docker Integration Tests (`tests/integration/test_docker_integration.py`):** 5 tests were skipped because the Docker daemon is not running on this Windows host.
- *Audit Note:* These tests are marked as **SKIPPED (environmental limitation)**. No claim is made that Docker isolation was verified on this host.

### 8.3 Live Ollama Inference Results
`scripts/validate_canary_instrumentation.py` executed live inference against local Ollama (`qwen2:1.5b` on `http://localhost:11434`):
- Model exposure: 4 confirmed exposures, 1 confirmed non-exposure, 3 unverified.
- Canary exfiltration: 0 confirmed exfiltrations, 8 confirmed non-exfiltrations.
- Result artifact: `benchmark/results/canary_instrumentation_validation.json` (created without modifying frozen scenarios or previous benchmark reports).

---

## 9. Security Findings and Remediation

### Finding 1: Static Default Salt in Source Code (Medium Severity)
- **Observation:** `_DEFAULT_TELEMETRY_HMAC_KEY` in `canary_telemetry.py` is derived from a hard-coded salt string: `b"antigravity-canary-telemetry-key-v1"`.
- **Impact:** An attacker with access to the source code can know the default HMAC key. Given the low entropy of synthetic canary tokens ($10^9$ possibilities), an attacker could precompute dictionary mappings offline from candidate tokens to their 16-hex-char IDs.
- **Remediation Recommendation:**
  1. Support loading an external secret via environment variable (e.g., `os.environ.get("CANARY_HMAC_SECRET")`).
  2. If unset in production, generate a process-ephemeral cryptographic key via `secrets.token_bytes(32)`.
  3. Retain the static salt only for deterministic offline unit tests when explicitly requested.

### Finding 2: HMAC Identifier Truncation Length (Low Severity / Informational)
- **Observation:** Truncation is currently set to 16 hex characters (64 bits).
- **Impact:** While 64 bits provides robust protection against accidental collisions ($P < 10^{-9}$ for up to $10^5$ records), NIST SP 800-107 recommends a minimum of 128 bits (32 hex characters) for cryptographic MAC truncation to guard against prefix-guessing attacks.
- **Remediation Recommendation:** Increase truncated ID length to 32 hex characters in `get_safe_canary_id()`:
  ```python
  return hmac.new(hmac_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
  ```

### Finding 3: Environmental Limitation on Docker Isolation (Informational)
- **Observation:** Docker isolation tests (`tests/integration/test_docker_integration.py`) skipped due to missing daemon on host.
- **Impact:** Docker filesystem and network isolation guarantees could not be verified dynamically in this environment.
- **Remediation Recommendation:** Execute integration suite in a container-enabled Linux staging environment prior to final release.

---

## 10. Conclusion and Verdict

### Verdict: **VERIFIED WITH LIMITATIONS**

The implementation enforces strict, verified **fail-closed dispatch** across all model execution boundaries. If canary telemetry inspection fails, outgoing requests are blocked before transmission, and zero bytes reach the HTTP transport. Dispatched payloads maintain strict byte-for-byte fidelity with inspected sequences. All alternative providers are either instrumented fail-closed or explicitly rejected.

The limitations identified are non-blocking for local development but require the recommended HMAC key configuration before deployment in adversarial threat environments where source code is accessible to untrusted parties.
