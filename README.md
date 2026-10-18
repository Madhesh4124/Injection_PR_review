# Injection-Robust PR Review Agent

The **Injection-Robust PR Review Agent** is a multi-stage security analysis pipeline engineered to review code pull requests without succumbing to prompt injection, instructions embedded in diffs/comments/readmes, or adversarial jailbreaks. It guarantees that deterministic security findings are never suppressed or overridden by LLM output.

The system combines dual-view source materialization, isolated Docker container execution, offline deterministic static analysis (Semgrep, Bandit), an injection-detection model node (Node 4), wire-level pre-dispatch canary exposure telemetry, and deterministic discrepancy validation & reporting (Node 5).

---

## Architecture

The agent executes as a multi-node pipeline:

```text
Untrusted PR Input (Diff, PR Description, Code Files)
                        |
                        v
               [Node 1: Context Loader]
               + Enforces size and context limits
               + Creates comment/docstring-stripped workspace
               + Preserves raw workspace immutability
                        |
        +---------------+---------------+---------------+
        |                               |               |
        v                               v               v
[Node 2: Static Scanner]      [Node 3: Paired Review]  [Node 4: Injection Detector]
+ Pinned Semgrep & Bandit     + Raw View Review        + Structured classification
+ Raw code files only         + Stripped View Review   + Raw diff, PR desc, README
+ 100% offline & immutable    + Local Ollama model     + 4 fixed injection classes
+ Never seen by LLM reviewer  + Wire canary telemetry  + Zero tool permissions
        |                               |               |
        +---------------+---------------+---------------+
                        |
                        v
         [Node 5: Verifier & Discrepancy Reporter]
         + Reconciles LLM findings with scanner findings
         + Flags differential suppression (stripped-only findings)
         + Enforces deterministic finding precedence (never overridden by LLM)
         + Scans & redacts canary secrets across all outputs
         + Emits auditable review report with tri-state canary verification
```

### Component Responsibilities

1. **Input Processing & PR Context (Node 1):**
   - Enforces context limits (500 lines or 25 KB per file; 2,500 lines or 125 KB per PR).
   - Materializes two distinct workspaces: an immutable **raw workspace** and a disposable **stripped workspace** (where comments and docstrings are whitespace-blanked, README files are removed, and PR descriptions are absent).
   - Sanitizes Unicode anomalies (bidi controls, zero-width characters) with exact line references.
2. **Deterministic Offline Security Checks (Node 2):**
   - Runs pinned Semgrep and Bandit scanners strictly against the raw code workspace.
   - Produces immutable scanner findings. The LLM reviewer (Node 3) is never supplied scanner output, preventing adversarial PR content from manipulating or suppressing static analysis.
3. **LLM-Based Paired Review (Node 3):**
   - Dispatches review requests to high-context models via Ollama (configured with `num_ctx=32768`) or Hugging Face (`Qwen/Qwen2.5-Coder-7B-Instruct`) at temperature `0.0`.
   - Reviews the raw workspace and stripped workspace independently using deterministic context budgeting and chunking (`src/detection/context_budget.py`).
   - Tracks 100% chunk coverage, validating candidate findings and setting `review_complete=False` fail-closed if any chunk fails, truncates, or encounters provider errors.
   - Guarded by resource limits (bounded concurrency, queue limits, monotonic timeouts, transient-only retries).
4. **Structured Injection Detection (Node 4):**
   - Classifies adversarial prompt injections across diffs, PR descriptions, and README files.
   - Restricted to structured schema output across four fixed classes (`instruction_override`, `authority_claim`, `canary_probe`, `access_probe`). Operates without tool access.
5. **Canary Payload Inspection & Exposure Telemetry:**
   - Wire-level inspection evaluates exact serialized HTTP payloads immediately before transmission to the local Ollama daemon or Hugging Face endpoint.
   - Records non-reversible 128-bit keyed HMAC identifiers rather than raw secrets.
6. **Discrepancy Validation & Reporting (Node 5):**
   - Computes differential suppression tags: if a vulnerability is detected in the stripped view but omitted in the raw view, suspected suppression is flagged.
   - Evaluates multi-destination exfiltration checks and redacts synthetic secrets across reports, findings, and logs.
   - Emits the final structured JSON report with verified tri-state canary exposure metrics.
7. **Docker Execution Sandboxing:**
   - Untrusted fixture test execution runs inside an isolated container with `--network none`, `--cap-drop ALL`, `no-new-privileges`, non-root execution (`--user 1000:1000`), read-only root filesystem (`--read-only`), memory and CPU limits, and automatic container cleanup on failure or timeout.
8. **Fail-Closed Failure Handling:**
   - If payload inspection fails, outgoing model dispatch is immediately aborted before socket transmission.
   - Discrepancies, missing telemetry, or infrastructure timeouts produce conservative `UNVERIFIED` metrics.

---

## Security Properties

### Canary Exposure Instrumentation & Redaction
- **Pre-Dispatch Wire Inspection:** Outgoing payloads are inspected immediately before dispatch. If inspection encounters an error, dispatch fails closed and transmission is blocked.
- **Byte-for-Byte Fidelity:** The inspected byte buffer is the identical byte array passed to the HTTP transport. No payload re-serialization or mutation occurs.
- **128-Bit Truncated Keyed HMAC:** Telemetry identifiers use keyed HMAC-SHA256 truncated to 32 hexadecimal characters (128 bits), adhering to NIST SP 800-107 to prevent precomputation and collision attacks.
- **Fail-Closed Verification:** `CONFIRMED_NON_EXPOSURE` is reported **only** when all expected dispatches completed inspection, were confirmed transmitted over the wire, carried valid unique correlation IDs, and contained zero canary matches. Any missing dispatch or telemetry fault yields `UNVERIFIED`.
- **Zero Secret Leakage:** Keys, raw canaries, and encoded variants are never written to logs, exceptions, telemetry JSON, or reports. Legacy placeholders like `[SANITIZED_INPUT]` are rejected as evidence of non-exposure.

### Deterministic Finding Protection
- **No LLM Overrides:** Deterministic security findings produced by offline scanners cannot be overridden, dismissed, or downgraded by LLM output.
- **Independent Checker:** Verification and scoring logic runs 100% offline and functions even when Ollama is offline or unavailable.

For the comprehensive technical specification of canary telemetry, see:  
[**`docs/CANARY_REDACTION.md`**](docs/CANARY_REDACTION.md)

---

## Installation & Configuration

### Prerequisites
- Python 3.12+
- Local [Ollama](https://ollama.ai) daemon running on `http://localhost:11434` with model `qwen2:1.5b`
- Optional: Docker daemon (required for containerized test runner integration tests)

### Environment Configuration

Configure the agent using environment variables or a `.env` file based on [`.env.example`](.env.example):

```bash
# Copy template configuration
cp .env.example .env
```

#### 1. Canary Telemetry HMAC Key (`CANARY_HMAC_SECRET`)
Production paths utilizing canary telemetry require a cryptographically secure 32-byte HMAC secret.

- **Mandatory Configuration:** If `CANARY_HMAC_SECRET` is unset, empty, or shorter than 32 bytes, the system fails closed with `CanaryKeyConfigurationError`.
- **No Hardcoded Defaults:** The codebase contains zero fallback or default keys. Test-only keys in `conftest.py` are strictly isolated to pytest sessions and cannot become production defaults.
- **Entropy vs. Length:** Code validation verifies `len(key) >= 32` bytes (256 bits). However, minimum length does **not prove high entropy**. Keys must be generated using a CSPRNG:
  ```bash
  # Recommended: Generate a 32-byte (64 hex characters) random key
  openssl rand -hex 32

  # Alternative using Python secrets module
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- **Accepted Formats:**
  1. 64-character hexadecimal string (recommended).
  2. Base64 string representing $\ge 32$ decoded bytes (e.g. from `openssl rand -base64 32`).
  3. Raw UTF-8 string with length $\ge 32$ characters.
- **Secret Storage:** Protect `CANARY_HMAC_SECRET` via restricted file permissions or secret managers (e.g. Kubernetes Secrets, Vault). Never commit secrets to version control.
- **Cross-Run Stability & Key Rotation:** Multi-turn PR reviews require persistent key material across restarts so identifiers remain stable. Rotating `CANARY_HMAC_SECRET` changes derived identifiers ($\text{HMAC}_{K_1}(S) \neq \text{HMAC}_{K_2}(S)$); telemetry from different key epochs cannot be silently compared.

#### 2. Ollama Inference Configuration

| Variable | Type | Default | Description |
|---|---|---|---|
| `CANARY_HMAC_SECRET` | String | *(None)* | Mandatory 32-byte secret for canary HMAC derivation |
| `OLLAMA_BASE_URL` | String | `http://localhost:11434` | Base URL of the local Ollama daemon |
| `OLLAMA_MODEL` | String | `qwen2:1.5b` | Local model tag |
| `OLLAMA_MAX_CONCURRENCY` | Integer | `1` | Maximum simultaneous inference calls (semaphore-bounded) |
| `OLLAMA_MAX_QUEUE_SIZE` | Integer | `5` | Maximum queued requests before fast-failing with `OllamaQueueFullError` |
| `OLLAMA_TIMEOUT_SECONDS` | Float | `120.0` | Maximum wall-clock seconds per request |
| `OLLAMA_MAX_RETRIES` | Integer | `1` | Retries for transient errors only (total attempts = 2) |
| `OLLAMA_BASE_BACKOFF_SECONDS` | Float | `0.5` | Exponential backoff initial delay |
| `OLLAMA_MAX_BACKOFF_SECONDS` | Float | `5.0` | Exponential backoff ceiling |
| `OLLAMA_JITTER_SECONDS` | Float | `0.25` | Random backoff jitter |
| `OLLAMA_MAX_INPUT_BYTES` | Integer | `175000` | Input size limit before queue entry |
| `OLLAMA_MAX_OUTPUT_BYTES` | Integer | `100000` | Maximum stream read limit for model responses |

---

## Verification Status

### Latest Verification Results (Remediation & Integration Audit)
According to the latest test suite execution:

| Suite / Verification Check | Scope | Result | Notes |
| :--- | :--- | :--- | :--- |
| **Full Unit Test Suite** | `tests/unit/` | **347 PASSED** | 100% pass rate across all schemas, unified parsers, security gates, providers, and runners |
| **Unified JSON Parser Suite** | `tests/unit/test_baseline_json_parser.py` | **11 PASSED** | Balanced brace parsing, fenced blocks, escape recovery, fail-closed handling |
| **Node 3 & Context Budget Suite** | `tests/unit/test_context_budget_and_paired_reviewer.py` | **18 PASSED** | Context budget, chunking, malformed/schema chunk fail-closed, canary scrubbing, truncation decoupling |
| **Harness Pipeline Integration** | `tests/unit/test_model_context_and_baseline_gate.py` | **15 PASSED** | Real Nodes 1–5 pipeline execution, scanner unavailability fail-closed, simulation isolation |
| **Ollama Provider Suites** | `tests/unit/test_ollama_*.py` | **19 PASSED** | Concurrency controls, semaphore bounds, fast queue rejection, timeout bounds |
| **Docker Integration Tests** | `tests/integration/test_docker_integration.py` | **13 PASSED** | 12 security controls verified in active Docker engine (51.89s) |
| **Dev Baseline Resilience Gate** | `scripts/run_dev_baseline.py` | **SIMULATED ONLY** | 6 pairs pass in simulation mode; live provider gate run remains pending |

### Audit Verdict
**`PASS WITH LIMITATIONS`**

> [!NOTE]
> This verdict applies specifically to **Part 1: Canary Exposure Instrumentation and Deployment Configuration**, not to the entire application.

---

## Security Limitations & Operational Boundaries

1. **Entropy Operational Dependency:** Byte length checks (`len(key) >= 32`) verify mathematical minimum keyspace, but cannot evaluate random entropy. Deployments must generate keys via CSPRNG (`openssl rand -hex 32`).
2. **Environment Variable Secret Protection:** `CANARY_HMAC_SECRET` is supplied via environment variables. Operating systems must restrict process access (`/proc/<pid>/environ`) and container metadata visibility to authorized runtime service accounts.
3. **Key Rotation Re-Indexing:** Derivation is tied to the secret key. Rotating keys invalidates cross-comparison with historical telemetry unless an external key-epoch migration strategy is maintained.
4. **Heuristic Encoding Scope:** Canary inspection detects canonical encodings (raw, standard Base64, hexadecimal, and string-concatenated chunks). It does not detect nested encodings (e.g. Base64 inside Gzip), custom ciphers (ROT13, XOR with arbitrary keys), or multi-turn fragmented disclosures.
5. **Integration Test Verification Scope:** In this session, all 13 integration tests were executed and passed across two separate pytest invocations: 5 Docker container isolation tests (32.55s) and 8 live-provider integration tests (44.95s), totaling 77.50s combined elapsed time. Note that the two suites were invoked separately rather than via a single combined pytest run.
6. **Unit Tests vs. Production Validation:** Successful unit tests verify implemented code invariants, but do not replace operational security controls, host kernel hardening, or container isolation policies.

---

## Audit Artifacts & Verification Reports

The following audit and evaluation artifacts are preserved in `benchmark/results/`:
- [`benchmark/results/part1_deployment_verification.md`](benchmark/results/part1_deployment_verification.md): Part 1 deployment and implementation verification report (`PASS WITH LIMITATIONS`).
- [`benchmark/results/canary_key_remediation_report.md`](benchmark/results/canary_key_remediation_report.md): Remediation evidence for findings F-01 and F-02.
- [`benchmark/results/canary_read_only_verification_report.md`](benchmark/results/canary_read_only_verification_report.md): Initial read-only security audit of canary telemetry.
- [`benchmark/results/canary_fail_closed_security_review.md`](benchmark/results/canary_fail_closed_security_review.md): Security review of fail-closed dispatch boundaries.
- [`benchmark/results/audit_validity_report.md`](benchmark/results/audit_validity_report.md): Post-benchmark evaluation validity audit.
- [`benchmark/results/frozen_benchmark_report.json`](benchmark/results/frozen_benchmark_report.json): Frozen 300-evaluation baseline and defended-system benchmark records.
