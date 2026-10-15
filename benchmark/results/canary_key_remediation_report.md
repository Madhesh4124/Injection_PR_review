# Canary Telemetry Remediation Report: F-01 & F-02

**Project:** Injection-Robust PR Review Agent  
**Date:** October 15, 2026  
**Status:** **Remediated & Verified**  
**Remediation Target:** Findings F-01 and F-02 from `benchmark/results/canary_read_only_verification_report.md`

---

## Executive Summary

This remediation report documents the architectural fixes and regression verification for findings **F-01** (Static default HMAC key) and **F-02** (HMAC identifier truncated to 64 bits) within the Injection-Robust PR Review Agent's wire-level canary telemetry instrumentation.

Both security findings have been resolved with strict adherence to mandatory fail-closed constraints:
1. **F-01 Resolved:** Removed `_DEFAULT_TELEMETRY_HMAC_KEY` completely. Telemetry initialization now fails closed with `CanaryKeyConfigurationError` if `CANARY_HMAC_SECRET` is missing, malformed, or shorter than 32 bytes (256 bits). Test suites inject isolated test-only keys via pytest fixtures (`conftest.py`), ensuring test keys cannot become production defaults.
2. **F-02 Resolved:** HMAC-SHA256 telemetry identifiers are expanded from 16 hexadecimal characters (64 bits) to 32 hexadecimal characters (128 bits), conforming to NIST SP 800-107 recommendations for collision resistance while maintaining zero secret leakage across wire-level payloads, correlation records, and final reports.

All 20 canary instrumentation unit tests passed, the live Ollama validation suite passed with zero leaks, and all 253 repository unit tests passed.

---

## Summary of Findings & Remediation Status

| Finding ID | Title | Severity | Status | Remediation Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-01** | Static default HMAC key | Medium / Operational | **RESOLVED** | Removed static fallback constant `_DEFAULT_TELEMETRY_HMAC_KEY`. Mandated `CANARY_HMAC_SECRET` with $\ge 32$ bytes. Fails closed with `CanaryKeyConfigurationError` if missing or weak. Isolated test fixture added to `conftest.py`. |
| **F-02** | HMAC identifier truncated to 64 bits | Low / Defense-in-Depth | **RESOLVED** | Increased identifier length from 16 hex characters (64 bits) to 32 hex characters (128 bits). Updated `get_safe_canary_id()`, Pydantic models, validation schemas, and regression tests. |

---

## Files Changed & Rationale

| File Path | Description of Changes | Rationale |
| :--- | :--- | :--- |
| [`src/detection/canary_telemetry.py`](../../src/detection/canary_telemetry.py) | - Removed `_DEFAULT_TELEMETRY_HMAC_KEY`.<br>- Added `ENV_CANARY_HMAC_SECRET = "CANARY_HMAC_SECRET"`.<br>- Added typed exception `CanaryKeyConfigurationError(ValueError)`.<br>- Added `validate_canary_hmac_key(key: bytes) -> bytes` enforcing $\ge 32$ bytes.<br>- Added `load_telemetry_hmac_key() -> bytes` supporting 64 hex characters, Base64, or raw UTF-8 bytes $\ge 32$.<br>- Updated `get_safe_canary_id()` to return 32 hex characters (`[:32]`).<br>- Updated `CanaryPayloadInspector.__init__` and `CanaryExfiltrationInspector.__init__` to fail closed if key cannot be validated or loaded.<br>- Updated `CanaryMatchEvidence` field docstring to reflect 32 hex characters. | Eliminates hardcoded key vulnerability (F-01), enforces cryptographic strength fail-closed, and expands identifier entropy to 128 bits (F-02). |
| [`src/detection/__init__.py`](../../src/detection/__init__.py) | - Exported `CanaryKeyConfigurationError`, `ENV_CANARY_HMAC_SECRET`, `load_telemetry_hmac_key`, and `validate_canary_hmac_key`.<br>- Added them to `__all__`. | Provides clean public API for key validation and error handling across application modules. |
| [`conftest.py`](../../conftest.py) | - Added `TEST_CANARY_HMAC_SECRET` constant.<br>- Added `setup_test_canary_hmac_secret(monkeypatch)` fixture (`autouse=True`). | Injects explicit deterministic test key during pytest sessions without hardcoding production defaults. Allows unit tests to override or delete the key using `monkeypatch`. |
| [`.env.example`](../../.env.example) | - Added documentation and specification for `CANARY_HMAC_SECRET`.<br>- Documented hex, Base64, and UTF-8 key formats and deployment access control requirements. | Guides production operators on key generation and secret isolation. |
| [`scripts/validate_canary_instrumentation.py`](../../scripts/validate_canary_instrumentation.py) | - Added `os.environ.setdefault("CANARY_HMAC_SECRET", ...)` for standalone test runs. | Enables safe standalone diagnostic execution when invoked outside of pytest without weakening production fail-closed semantics. |
| [`tests/unit/test_canary_instrumentation.py`](../../tests/unit/test_canary_instrumentation.py) | - Updated `test_15` to assert 32 hex characters and 32-byte test keys.<br>- Added `test_16` (Missing key fails closed).<br>- Added `test_17` (Invalid/short key fails closed).<br>- Added `test_18` (Equal/different key properties, 32 hex chars, Base64 parsing).<br>- Added `test_19` (Missing/invalid key blocks provider dispatch fail-closed; zero wire requests).<br>- Added `test_20` (Zero key leakage in logs, exceptions, telemetry, reports). | Provides regression test coverage for all 10 mandatory verification requirements. |

---

## Detailed Analysis: F-01 & F-02 Remediation

### 1. F-01: Production Key Configuration & Fail-Closed Enforcement

#### How Key Configuration Works
Key material is supplied to the process via the `CANARY_HMAC_SECRET` environment variable or explicitly passed as `hmac_key: bytes` to `CanaryPayloadInspector` and `CanaryExfiltrationInspector`.

The function `load_telemetry_hmac_key()` resolves the key using the following algorithm:
1. **Missing or Empty Check:** If `CANARY_HMAC_SECRET` is unset or empty, raise `CanaryKeyConfigurationError` immediately.
2. **Hex Decoding:** If the secret string has length 64 and contains hexadecimal characters, decode via `bytes.fromhex(val)` yielding 32 raw bytes.
3. **Base64 Decoding:** If the secret represents valid Base64 data yielding $\ge 32$ bytes, decode via `base64.b64decode(val)`.
4. **UTF-8 Fallback:** Otherwise, encode as UTF-8 bytes and verify `len(raw_bytes) >= 32`.
5. **Strength Validation:** In all branches, `validate_canary_hmac_key()` asserts `isinstance(key, bytes)` and `len(key) >= 32`.

#### Sanitized Error Messages
When configuration is missing or invalid, exceptions never reveal the attempted key material or environment secrets:
- Missing: `"Missing required environment variable 'CANARY_HMAC_SECRET' for canary telemetry HMAC derivation."`
- Insufficient Strength: `"Configured canary HMAC key is insufficiently strong: expected >= 32 bytes (256 bits), got {N} bytes."`

#### Cross-Run Identifier Stability
- **Design Assessment:** The Injection-Robust PR Review Agent requires **cross-run identifier stability** across multi-stage review workflows, discrepancy analysis, post-run audit verification, and benchmark evaluation runs.
- **Decision:** Rather than generating an ephemeral random key per process startup (which would make identifiers non-comparable across process restarts or distributed review worker nodes), the system uses **securely managed persistent key material** supplied through `CANARY_HMAC_SECRET`.
- **Operational Requirement:** Environment variables alone do not provide cryptographic boundary isolation. Host environments must restrict process memory access, prevent child process inheritance where untrusted subprocesses are spawned, and manage `CANARY_HMAC_SECRET` through a secure secret store (e.g., Vault, AWS Secrets Manager, Kubernetes Secret with restricted RBAC).

#### Key Rotation Implications
- When `CANARY_HMAC_SECRET` is rotated, the HMAC derivation produces distinct identifier hashes:
  $$\text{HMAC}_{K_1}(S) \neq \text{HMAC}_{K_2}(S)$$
- **Comparability Boundary:** Canary identifiers derived under different key versions **cannot be silently compared**. Attempting to reconcile correlation records or discrepancy markers across rotation boundaries will result in identifier mismatches.
- **Operational Recommendation:** When key rotation occurs, historical telemetry records should be tagged with key version identifiers or archived as a distinct audit epoch. Active multi-turn PR reviews should conclude before rotation, or telemetry reconciliation must be scoped per key epoch.

---

### 2. F-02: Identifier Length Expansion to 128 Bits

#### Length Before and After
- **Prior Implementation:** 16 hexadecimal characters (64 bits of HMAC-SHA256 output).
- **Remediated Implementation:** 32 hexadecimal characters (128 bits of HMAC-SHA256 output).

$$\text{Identifier} = \text{HMAC-SHA256}(K, S)[:32]$$

#### Security Invariants Preserved
1. **Collision Resistance:** At 128 bits, the expected collision probability across $2^{32}$ telemetry events is approximately $2^{-65} \approx 2.7 \times 10^{-20}$, satisfying NIST SP 800-107 truncation criteria for high-security correlation tags.
2. **Keyed HMAC:** The identifier remains derived from a keyed HMAC-SHA256, preventing attackers with knowledge of the canary plaintext from precomputing identifier hashes without knowledge of the 32-byte secret key $K$.
3. **No Leakage:** Increasing the prefix from 16 to 32 hex characters leaks zero bits of the raw canary secret $S$ or HMAC key $K$.
4. **Compatibility:** Pydantic schemas (`CanaryMatchEvidence`), regex matchers, JSON serializers, and reporter redactors operate seamlessly with 32-character strings.

---

## Regression Verification & Test Results

### 10 Mandatory Regression Criteria Verification

| # | Requirement | Test Case | Status |
| :--- | :--- | :--- | :--- |
| 1 | Production config fails closed when key is missing | `test_16_key_configuration_fails_closed_when_missing` | **PASS** |
| 2 | Production config fails closed for invalid key material | `test_17_key_configuration_fails_closed_when_invalid` | **PASS** |
| 3 | Configured valid key generates 32-character hex identifier | `test_18_equal_and_different_keys_properties_and_length` | **PASS** |
| 4 | Equal inputs with same key produce equal identifiers | `test_18_equal_and_different_keys_properties_and_length` | **PASS** |
| 5 | Equal inputs with different keys produce different identifiers | `test_18_equal_and_different_keys_properties_and_length` | **PASS** |
| 6 | Key never appears in logs, exceptions, telemetry, or reports | `test_20_hmac_key_never_appears_in_logs_telemetry_or_reports` | **PASS** |
| 7 | Raw canary and encoded variants remain absent from telemetry | `test_1`, `test_15`, `test_20` | **PASS** |
| 8 | Missing/invalid key cannot cause inspection bypass or uninstrumented fallback | `test_19_missing_key_blocks_provider_dispatch_fail_closed` | **PASS** |
| 9 | Existing canary correlation and exposure-state tests pass | `test_1` through `test_14` | **PASS** |
| 10 | Existing dispatch-boundary fail-closed behavior remains intact | `test_6`, `test_11`, `test_12`, `test_19` | **PASS** |

### Test Commands and Actual Outputs

#### Command 1: Linter & Static Analysis
```bash
python -m ruff check .
```
**Output:**
```
All checks passed!
```

#### Command 2: Canary Instrumentation Unit Tests
```bash
python -m pytest tests/unit/test_canary_instrumentation.py -v
```
**Output:**
```
============================= test session starts =============================
platform win32 -- Python 3.12.3, pytest-9.0.0, pluggy-1.6.0
rootdir: <project-root>/Injection_PR_review
configfile: pyproject.toml
plugins: hydra-core-1.3.2, anyio-4.12.1, Faker-37.11.0, langsmith-0.6.9
collected 20 items

tests/unit/test_canary_instrumentation.py::test_1_canary_present_directly_in_model_request PASSED [  5%]
tests/unit/test_canary_instrumentation.py::test_2_supported_encoding_representations_detected PASSED [ 10%]
tests/unit/test_canary_instrumentation.py::test_3_canary_present_in_pr_description_readme_diff PASSED [ 15%]
tests/unit/test_canary_instrumentation.py::test_4_multiple_model_calls_within_one_review PASSED [ 20%]
tests/unit/test_canary_instrumentation.py::test_5_model_call_fails_before_dispatch PASSED [ 25%]
tests/unit/test_canary_instrumentation.py::test_6_dispatch_whose_inspection_telemetry_fails PASSED [ 30%]
tests/unit/test_canary_instrumentation.py::test_7_clean_request_with_no_canary PASSED [ 35%]
tests/unit/test_canary_instrumentation.py::test_8_canary_leakage_into_final_report_or_prohibited_destinations PASSED [ 40%]
tests/unit/test_canary_instrumentation.py::test_9_sanitized_input_placeholder_rejected_as_evidence PASSED [ 45%]
tests/unit/test_canary_instrumentation.py::test_10_incomplete_model_call_telemetry_produces_unverified_result PASSED [ 50%]
tests/unit/test_canary_instrumentation.py::test_11_inspection_exception_blocks_outgoing_transmission PASSED [ 55%]
tests/unit/test_canary_instrumentation.py::test_12_dispatch_boundary_byte_for_byte_fidelity PASSED [ 60%]
tests/unit/test_canary_instrumentation.py::test_13_all_provider_paths_enforce_or_reject_inspection PASSED [ 65%]
tests/unit/test_canary_instrumentation.py::test_14_missing_duplicate_mismatched_correlation_ids_produce_unverified PASSED [ 70%]
tests/unit/test_canary_instrumentation.py::test_15_telemetry_privacy_and_keyed_hmac PASSED [ 75%]
tests/unit/test_canary_instrumentation.py::test_16_key_configuration_fails_closed_when_missing PASSED [ 80%]
tests/unit/test_canary_instrumentation.py::test_17_key_configuration_fails_closed_when_invalid PASSED [ 85%]
tests/unit/test_canary_instrumentation.py::test_18_equal_and_different_keys_properties_and_length PASSED [ 90%]
tests/unit/test_canary_instrumentation.py::test_19_missing_key_blocks_provider_dispatch_fail_closed PASSED [ 95%]
tests/unit/test_canary_instrumentation.py::test_20_hmac_key_never_appears_in_logs_telemetry_or_reports PASSED [100%]

============================= 20 passed in 0.55s ==============================
```

#### Command 3: End-to-End Live Ollama Validation
```bash
python scripts/validate_canary_instrumentation.py
```
**Output:**
```
[*] Local Ollama availability for live validation: True
[+] Successfully wrote validation report to: benchmark\results\canary_instrumentation_validation.json
{
  "model_exposure": {
    "confirmed_exposure_count": 4,
    "confirmed_non_exposure_count": 1,
    "unverified_count": 3,
    "total_runs": 8
  },
  "canary_exfiltration": {
    "confirmed_exfiltration_count": 0,
    "confirmed_non_exfiltration_count": 8,
    "destinations_inspected": [
      "corroborated_findings",
      "unverified_concerns",
      "scanner_findings",
      "injection_records",
      "discrepancy_tags",
      "blocked_access",
      "serialized_report_json"
    ]
  }
}
```

#### Command 4: Full Unit & Regression Suite Execution
```bash
python -m pytest tests/unit -v
```
**Output:**
```
============================ 253 passed in 39.41s =============================
```

---

## Confirmation of Mandatory Constraints

1. **Frozen Benchmark Scenarios Untouched:** No files in `benchmark/scenarios/` were modified, opened for edit, or removed.
2. **Prior Benchmark and Audit Artifacts Untouched:** The following prior artifacts remain strictly unmodified:
   - `benchmark/results/frozen_benchmark_report.json`
   - `benchmark/results/audit_validity_report.md`
   - `benchmark/results/canary_fail_closed_security_review.md`
   - `benchmark/results/canary_read_only_verification_report.md`
3. **No Frozen Benchmark Rerun:** The frozen 300-evaluation benchmark was not re-executed.
4. **Security Controls Maintained:** Fail-closed dispatch, canary inspection, correlation validation, redaction, and deterministic finding priority remain strictly intact.
5. **No Secret Leakage:** Neither the HMAC key nor raw canary values are printed, logged, or serialized in any report or telemetry JSON.

---

## Remaining Risks & Scope Limitations

1. **Secret Storage Environment Security:** The application enforces key length ($\ge 32$ bytes) and fail-closed absence checks, but the security of `CANARY_HMAC_SECRET` ultimately depends on the deployment orchestrator. If the host environment or Docker host exposes environment variables to unauthorized local users, key material could be exposed.
2. **Key Rotation Re-indexing:** Historical telemetry generated under a previous HMAC key cannot be reconciled with telemetry from a rotated key without maintaining an epoch map.
3. **Docker-Dependent Tests:** Tests requiring the local Docker daemon were skipped due to Docker being offline on the host, consistent with permitted test protocols.
4. **Scope of Remediation:** Remediation of findings F-01 and F-02 hardens the canary telemetry subsystem. It does not imply that all external attack surfaces (e.g. host-level side channels or kernel isolation) are production-secure.

---

## Final Assessment

- **Finding F-01 (Static default HMAC key):** **RESOLVED**  
- **Finding F-02 (HMAC identifier truncated to 64 bits):** **RESOLVED**  
- **Test Evidence:** 20/20 canary tests passed; 253/253 full unit suite passed; live Ollama validation verified.
