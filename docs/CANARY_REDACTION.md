# Canary Telemetry, Pre-Dispatch Inspection, and Redaction Specification

## 1. Overview and Security Objectives

Canary detection is a critical defensive telemetry and validation mechanism in the Injection-Robust PR Review Agent. It prevents sensitive synthetic secrets from leaking into:
1. **Model input context:** Inspecting outgoing serialized request payloads at the wire boundary before socket transmission.
2. **Review reports and public artifacts:** Inspecting and redacting final findings, discrepancy tags, scanner summaries, and serialized JSON.
3. **Persistent logs and telemetry:** Recording non-reversible 128-bit identifiers rather than raw secrets or secret-bearing prompts.

> [!CAUTION]
> **Synthetic Tokens Only:** Canary values are strictly synthetic tokens (e.g. `CANARY_FROZEN_SECRET_RAW_849201736`) supplied by trusted configuration. Live production API keys or credentials must **never** be used as canary values.

---

## 2. Wire-Level Pre-Dispatch Inspection (`CanaryPayloadInspector`)

Pre-dispatch canary inspection operates at the exact boundary between model payload serialization and HTTP transport dispatch.

### 2.1 Dispatch-Boundary Invariants
- **Inspection Timing:** Payload inspection occurs in [`OllamaProvider.complete()`](../src/detection/ollama_provider.py#L431-L459) immediately before invoking the transport layer.
- **Byte-for-Byte Fidelity:** The inspected byte array (`payload_bytes`) is the identical buffer passed directly to the HTTP transport (`urllib.request.Request`). No re-serialization, payload mutation, or dictionary alteration occurs between inspection and transmission.
- **Fail-Closed Dispatch:** If [`CanaryPayloadInspector.inspect_serialized_payload()`](../src/detection/canary_telemetry.py#L260) raises an exception, encounters an internal fault, or fails to return `InspectionStatus.COMPLETED`, the provider raises [`OllamaCanaryInspectionError`](../src/detection/ollama_provider.py#L54-L56) and immediately aborts. Zero HTTP requests and zero bytes are transmitted across the socket.
- **Non-Transient Classification:** `OllamaCanaryInspectionError` is classified as non-transient in `OllamaProvider._is_transient_error()`, guaranteeing that inspection failures are **never retried**.

### 2.2 Provider Enforcement
- Security-sensitive reviews require an instrumented provider.
- If an uninstrumented provider (such as [`LangChainProvider`](../src/detection/provider.py#L155) or an unconfigured [`MockLLMProvider`](../src/detection/provider.py#L90)) receives a request with correlation context or mandatory inspection enabled, it raises `ProviderError` fail-closed.

---

## 3. Cryptographic Canary Identification (F-01 & F-02 Remediation)

To prevent telemetry records from becoming an exfiltration channel, raw canary tokens are never written to inspection logs. Instead, each match records a non-reversible identifier derived via keyed HMAC-SHA256:

$$\text{CanaryID} = \text{HMAC-SHA256}(K, S)[:32]$$

### 3.1 128-Bit Truncation (F-02)
- Telemetry identifiers are truncated to **32 hexadecimal characters (128 bits)**, adhering to NIST SP 800-107 recommendations for high-assurance collision resistance.
- Expected collision probability across $2^{32}$ telemetry events is approximately $2^{-65} \approx 2.7 \times 10^{-20}$.

### 3.2 Keyed HMAC Security (F-01)
- Identifiers are strictly keyed ($K$), preventing dictionary precomputation attacks by adversaries who know synthetic canary candidate tokens.
- `_DEFAULT_TELEMETRY_HMAC_KEY` has been deleted from the codebase.
- The key $K$ is never exposed in logs, exceptions, telemetry JSON, or reports.

---

## 4. Production Configuration & Key Management

### 4.1 Mandatory Environment Configuration
Production execution requires a valid key supplied via the `CANARY_HMAC_SECRET` environment variable.
- If `CANARY_HMAC_SECRET` is unset, empty, or whitespace-only, [`load_telemetry_hmac_key()`](../src/detection/canary_telemetry.py#L77) raises [`CanaryKeyConfigurationError`](../src/detection/canary_telemetry.py#L60) fail-closed.
- Error messages are sanitized and never echo key fragments or attempted secrets.

### 4.2 Accepted Formats
1. **64-Character Hexadecimal (Recommended):** Parsed via `bytes.fromhex()` yielding 32 raw bytes (256 bits).
2. **Base64 String ($\ge 32$ decoded bytes):** Parsed via `base64.b64decode(secret_str, validate=True)`. Standard 32-byte keys produce 44-character Base64 strings.
3. **Raw UTF-8 Bytes ($\ge 32$ characters):** Parsed via `secret_str.encode("utf-8")`.

### 4.3 Safe Key Generation
Keys must be generated using a cryptographically secure pseudorandom number generator (CSPRNG):

```bash
# Recommended: 64-character hexadecimal string (32 bytes)
openssl rand -hex 32

# Alternative: Python CSPRNG
python -c "import secrets; print(secrets.token_hex(32))"
```

> [!IMPORTANT]
> **Length vs. Entropy:** Code validation enforces that the key contains at least 32 bytes (`len(key) >= 32`). However, byte length alone **does not guarantee high entropy**. Deployments must ensure keys are generated via CSPRNG rather than low-entropy passphrases.

### 4.4 Cross-Run Stability and Key Rotation
- **Cross-Run Stability:** The multi-stage PR review agent requires persistent key material across restarts to enable discrepancy analysis, audit reconciliation, and multi-turn tracking. Process-ephemeral keys are unacceptable as they break post-run correlation.
- **Key Rotation Boundary:** Rotating `CANARY_HMAC_SECRET` from $K_1$ to $K_2$ changes all derived identifiers:
  $$\text{HMAC}_{K_1}(S) \neq \text{HMAC}_{K_2}(S)$$
  Telemetry generated under different keys **cannot be silently compared**. Operators rotating keys must archive prior telemetry under an explicit epoch label or conclude active reviews before rotating.

### 4.5 Test-Fixture Isolation
- An autouse fixture in [`conftest.py`](../conftest.py#L18-L23) injects a deterministic test key strictly during pytest sessions.
- Production and CLI execution paths never import `conftest.py` and fail closed if `CANARY_HMAC_SECRET` is unconfigured.

---

## 5. Exposure State Evaluation (`CanaryExposureSession`)

Exposure evaluation computes a verified tri-state status across all dispatches for a given scenario run:

```text
                               +-----------------------------+
                               | Dispatches Inspected >= Min |
                               +-----------------------------+
                                              |
                       +----------------------+----------------------+
                       | NO                                         | YES
                       v                                             v
              +-----------------+                       +-------------------------+
              |   UNVERIFIED    |                       | Any Canaries Detected?  |
              +-----------------+                       +-------------------------+
                                                                     |
                                             +-----------------------+-----------------------+
                                             | YES                                           | NO
                                             v                                               v
                                  +---------------------+                        +-----------------------+
                                  | CONFIRMED_EXPOSURE  |                        | Inspection Faults,    |
                                  +---------------------+                        | Unobserved, or Bad    |
                                                                                 | Correlation Context?  |
                                                                                 +-----------------------+
                                                                                             |
                                                                     +-----------------------+-----------------------+
                                                                     | YES                                           | NO
                                                                     v                                               v
                                                          +-----------------+                           +-------------------------+
                                                          |   UNVERIFIED    |                           | CONFIRMED_NON_EXPOSURE  |
                                                          +-----------------+                           +-------------------------+
```

### Tri-State Definitions
- **`CONFIRMED_EXPOSURE`:** Evaluated first. If ANY dispatch contained a target canary in any supported encoding, the run is flagged as confirmed exposure.
- **`CONFIRMED_NON_EXPOSURE`:** Returned **only if**:
  1. Observed dispatches $\ge \text{expected\_min\_dispatches}$.
  2. Every dispatch record has `inspection_status == InspectionStatus.COMPLETED` and `dispatched == True`.
  3. Every dispatch record contains a valid, non-empty, unique `correlation_id` matching the scenario session.
  4. Zero canaries were detected across all wire payloads.
  5. Legacy placeholders (e.g. `[SANITIZED_INPUT]`) were not used as proof of non-exposure.
- **`UNVERIFIED`:** Conservative fallback applied when:
  - Fewer dispatches than expected occurred.
  - A dispatch failed before transmission (oversized input, queue full, timeout).
  - Inspection telemetry encountered a fault.
  - Correlation IDs are missing, duplicate, or mismatched.

---

## 6. Output Redaction and Exfiltration Detection

In addition to pre-dispatch wire inspection, [`CanaryRedactor`](../src/reporting/canary_redactor.py) and [`CanaryExfiltrationInspector`](../src/detection/canary_telemetry.py#L465) inspect and redact final outputs across four representations:

| Form | Detection Mechanism | Example Match | Redaction Output |
| :--- | :--- | :--- | :--- |
| **Raw Text** | Substring regex matching | `CANARY_FROZEN_SECRET_RAW_849201736` | `[REDACTED_CANARY_SECRET]` |
| **Base64** | Standard padded (`=`) and unpadded variants | `Q0FOQVJZX0ZST1pFTl9TRUNSRVRfUkFXXzg0OTIwMTczNg==` | `[REDACTED_CANARY_SECRET]` |
| **Hexadecimal** | Case-insensitive byte-to-hex representation | `43414e4152595f46524f5a454e5f534543524554...` | `[REDACTED_CANARY_SECRET]` |
| **Concatenated** | Expressions joining chunks with `+`, quotes, or spaces | `"CANARY_" + "FROZEN_SECRET..."` | `[REDACTED_CANARY_SECRET]` |

Destinations inspected for exfiltration:
- `corroborated_findings` explanations and evidence
- `unverified_concerns` explanations and evidence
- `scanner_findings` text
- `injection_records` explanations
- `discrepancy_tags`
- `blocked_access` logs
- `serialized_report_json`

---

## 7. Documented Scope Limitations

1. **Heuristic Coverage Boundary:** Pattern inspection detects canonical encodings (raw, standard Base64, hex, concatenated chunking). It does not detect:
   - Nested or layered encodings (e.g., Base64 inside Gzip inside URL encoding).
   - Arbitrary bitwise or cryptographic obfuscations (XOR with unknown keys, ROT13).
   - Multi-turn disclosure techniques that fragment secrets across independent review prompts.
2. **Operational Secret Protection:** The application relies on `CANARY_HMAC_SECRET` being protected by the host OS or container runtime. If host processes or container inspection tools expose environment variables, key confidentiality is compromised.
3. **Sandbox Independence:** Canary redaction and wire inspection provide defense-in-depth telemetry. Untrusted code execution must remain isolated via Docker (`--network none`, non-root, read-only root) rather than relying exclusively on string inspection.
4. **Unit Verification Scope:** Passing unit tests verifies code-level invariants but does not substitute for end-to-end operational deployment security.

