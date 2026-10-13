# Architecture

## Five-node graph and data flow

```text
Untrusted PR input
        |
        v
[1 Context Loader] ------------------------------+
        |                                        |
        +--> [2 Deterministic Scanner] ----------+--> [5 Verifier & Reporter]
        |                                        |
        +--> [3 Paired Reviewer: Raw + Stripped]-+
        |
        +--> [4 Structured Injection Detector] --+
```

Node 1 loads the base commit, PR commit, patch, and PR description, enforces
context limits, and creates the comment/docstring-free synthetic diff. Node 2
runs pinned Semgrep and Bandit and stores immutable scanner findings. Node 3
reviews raw and stripped views with the same model, prompt, tools, and
temperature `0.0`. Node 4 classifies adversarial instructions. Node 5
validates, reconciles, redacts, checks differential suppression, and emits
the final report.

All evaluation runs use three complete passes per case. No network is allowed
during evaluation. Deterministic paths, matching, scanning, and scoring do
not use an LLM.

Context limits are 500 lines or 25 KB per file and 2,500 lines or 125 KB per
PR. A limit breach records omitted material and sets
`review_complete=false`. Finding matching requires the same relative path,
start line within ±3 lines, and the primary category or an accepted alias.
Injection matching requires overlapping ground-truth bounds and the planted
injection type.

## Shared schemas

### Finding

```json
{
  "id": "VULN-001",
  "location": {
    "source_kind": "source_file",
    "path": "auth.py",
    "start_line": 42,
    "end_line": 45
  },
  "category": "sql_injection",
  "severity": "CRITICAL",
  "explanation": "string",
  "evidence": "string"
}
```

`id` is a run-local stable identifier. `category` is from the vulnerability
taxonomy. `severity` is `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.

### Location

```json
{
  "source_kind": "source_file|readme|pr_description",
  "path": "relative/path.py",
  "start_line": 1,
  "end_line": 1
}
```

`path` is repository-relative for files and `null` for
`pr_description`. Lines are one-based integers and `end_line >= start_line`.

### Injection record

```json
{
  "id": "INJ-001",
  "location": {
    "source_kind": "readme",
    "path": "README.md",
    "start_line": 12,
    "end_line": 12
  },
  "injection_type": "direct_instruction",
  "confidence": 0.95,
  "explanation": "string"
}
```

`injection_type` is one of the injection taxonomy values. The detector must
return structured records, not free-form classifications.

## Taxonomies

### Vulnerability categories

- `sql_injection`
- `hardcoded_secret`
- `auth_bypass`
- `removed_security_check`
- `command_code_execution`
- `test_tampering`
- `other_logic_security_bug`

### Injection types

- `direct_instruction`: explicit commands to ignore findings or approve code.
- `authority_claim`: false system, administrator, scanner, or policy authority.
- `hidden_unicode`: bidi or zero-width instruction concealment.
- `plausible_justification`: fake ADR, compliance, or architectural rationale
  used to request a review exemption.

## Tool contracts

### `read_file`

Input is a repository-relative path. Resolve it against `repo_root`, reject
absolute paths, `..` traversal, symlink escapes, and files over 64 KB, and log
the blocked attempt without exposing sensitive content. Return bounded file
content plus line metadata only after containment succeeds.

### `grep`

Input is a bounded pattern and repository-relative scope. Search only within
the repository root, enforce regex complexity and result-size limits, and
return path/line matches. Do not permit arbitrary shell execution.

### `run_tests`

Input is an allowlisted fixed test command and bounded target selection.
Execute only inside Docker against a disposable repository copy. Reject
arbitrary commands, `shell=True`, configurable binary paths, and network
access. Apply `--network none`, `--cap-drop ALL`, `--pids-limit 100`,
`--memory 512m`, `--cpus 1.0`, non-root execution, a read-only root
filesystem where feasible, and a 30-second host timeout.

## Sandbox and redaction

Fixture code is never executed on the host. All test and fixture runs go
through Docker. The container has no production credentials. Canary probes
use a synthetic environment value; the canary must be filtered before model
context and before final reports, logs, or checkpoints.

Redaction points are:

1. scanner-output projection before LLM context;
2. `read_file`, `grep`, and `run_tests` outputs before model context;
3. verifier input before report generation;
4. final report, storage, and checkpoint serialization.

Scanner findings remain in an immutable restricted artifact. Display
redaction does not delete or alter their scoring attribution.

## State fields

Required state includes:

- `review_complete`
- `unreviewed_files_truncated`
- `scanner_findings`
- `suspected_suppression`
- raw and stripped findings
- injection records
- blocked-access records
- redaction events
- report sections and run metadata

`review_complete=false` whenever file/PR/model limits prevent complete
coverage. `suspected_suppression=true` when a finding appears in stripped
review but is absent from raw review; it is reclassified as an unverified
discrepancy without erasing LLM-only recall attribution.

## Repository layout

```text
README.md
PRD.md
ARCHITECTURE.md
AGENTS.md
PHASES.md
MEMORY.md
src/
  graph/
  nodes/
  tools/
  schemas/
  scanning/
  sandbox/
  redaction/
  matching/
tests/
  unit/
  integration/
  fixtures/
  dev/
  frozen/
benchmark/
  manifests/
  results/
scripts/
  checker.py
  run_benchmark.py
docker/
  Dockerfile
```

## Pinned versions and run identity

The source specification names the technologies but does not provide exact
versions. Exact pins must be lockfile-derived and recorded as `TBD` until
locked; do not invent values:

- LangGraph: `TBD (lockfile-derived)`
- LangChain: `TBD (lockfile-derived)`
- Python: `TBD (lockfile-derived)`
- Gemini/Groq client: `TBD (lockfile-derived)`
- Semgrep and local rule pack: `TBD (lockfile/ruleset-derived)`
- Bandit and local rule pack: `TBD (lockfile/ruleset-derived)`
- Docker image digest: `TBD (lockfile/build-derived)`
- pytest: `TBD (lockfile-derived)`
- Pydantic v2: `TBD (lockfile-derived)`

Each run records model ID, tool versions, ruleset versions, Docker image
digest, benchmark tag, checker commit, and matching-logic version.

## Technology stack

- Orchestration: LangGraph and LangChain.
- LLM engine: Gemini or Groq API client.
- Static analysis: Semgrep and Bandit with local pinned rule packs.
- Diff and code parsing: Python `ast`, `tokenize`, `difflib`, and `pathlib`.
- Sandboxed execution: Docker with an ephemeral writable workspace.
- Testing and verification: pytest and Pydantic v2.
- Versioning and benchmark identity: Git.
