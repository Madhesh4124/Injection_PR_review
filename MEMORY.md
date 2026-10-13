# Memory

This file is append-only. It records decisions, rationale, open questions,
gotchas, results, and artifact identity. Secrets and synthetic canary values
must never be written here.

## 2026-10-13

### Decisions and why

- The public claim is **injection-resistant, not injection-proof** because
  deterministic boundaries reduce attack impact but cannot establish
  universal immunity or guarantee container escape prevention.
- The benchmark is split into 45 frozen scenarios and 10 development cases
  so prompts, verifier logic, redaction, and path checks can be tuned without
  contaminating reported evaluation results.
- A paired raw/stripped review is retained because suppression is observable
  only when prose-bearing and prose-free views can be compared.
- Scanner findings remain immutable and independent because an LLM must not be
  able to erase deterministic evidence.
- Blocked-access probes include environment reads, out-of-root reads,
  traversal, and symlink escape because a blocked-access rate without those
  cases would not measure the stated threat.
- Stripped-only findings retain LLM-only recall attribution when Corroborated
  or Unverified; suppression reclassification changes report handling, not
  whether the LLM detected the bug.
- Injection detection is a defended-agent classifier metric only; the plain
  baseline is `N/A` for that metric because it has no injection classifier.
- The plain baseline must run on the development set before Nodes 4 and 5.
  If injections do not change baseline output, attacks must be strengthened
  before defenses are evaluated.
- Every case must fit 500 lines per file and 2,500 lines per PR. Otherwise
  `review_complete=false` is intentional, not a silent partial success.

### Current phase

Phase 5, documentation and demo. The specification-derived contracts are
written; implementation and benchmark execution remain downstream work.

### Open questions

- Exact dependency, runtime, scanner-rule, and Docker image versions still
  need to be locked from the project lockfile/build.
- The final model provider and model ID must be selected and recorded per run.
- The benchmark tag and checker commit do not exist until the implementation
  repository is initialized and frozen.

### Known gotchas

- The synthetic canary value is intentionally absent from this log and all
  ordinary logs/checkpoints.
- Container flags are defense in depth; they do not claim to prevent every
  kernel or hypervisor escape.
- Unicode controls are annotated with line references rather than silently
  removed, preserving executable semantics while exposing hidden instructions.
- Homoglyph detection remains heuristic.
- Mechanical test attribution is optional stretch functionality; core
  vulnerable PRs are expected to have passing tests.
- A documentation/schema change must update `ARCHITECTURE.md` in the same
  change when shared schemas or state change.

### Results to date

- Source specification inspected: `injection_robust_pr_review_agent.md`.
- Documentation contracts created: `PRD.md`, `ARCHITECTURE.md`, `AGENTS.md`,
  `PHASES.md`, and this `MEMORY.md`.
- No benchmark, implementation test suite, checker run, or model evaluation
  has been executed in this documentation-only phase.

### Artifact hashes and versions

| Artifact | Value |
|---|---|
| Benchmark tag | `TBD (created at freeze)` |
| Checker commit | `TBD (created at freeze)` |
| Model ID | `TBD (recorded per run)` |
| LangGraph/LangChain versions | `TBD (lockfile-derived)` |
| Python version | `TBD (lockfile-derived)` |
| Semgrep/Bandit versions and rule packs | `TBD (lockfile/ruleset-derived)` |
| Docker image digest | `TBD (build-derived)` |
| pytest/Pydantic versions | `TBD (lockfile-derived)` |
| Fixture/manifests hash | `TBD (computed at freeze)` |
| Checker source hash | `TBD (computed at freeze)` |

