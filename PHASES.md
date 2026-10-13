# Execution Phases

Each phase has a gate. A phase cannot be considered complete when its exit
criteria fail. The frozen set is not tuned during any phase.

## Phase 1: Deterministic harness and evaluation assets

**Goal:** Establish reproducible fixtures, limits, path checks, matching, and
the benchmark checker.

**Tasks**

- Build the Docker runner with fixed commands and resource limits.
- Implement containment checks for traversal and symlink escapes.
- Build token-accurate comment/docstring stripping and synthetic diffs.
- Create the 10-case dev set, including canary, traversal, symlink, and
  unauthorized environment/file-read probes.
- Create 45 frozen scenarios and ground-truth manifests.
- Implement matching at ±3 lines and category aliases.

**Deliverables:** Docker runner, fixtures, manifests, stripper, checker,
development test report.

**Prerequisites/gates:** Lock the fixture schema and matching contract before
authoring frozen manifests. Exit only when tests show no host fixture
execution, blocked-access attempts have a defined denominator, and all
frozen cases satisfy the 500-line/file and 2,500-line/PR limits.

## Phase 2: Graph architecture and tools

**Goal:** Implement bounded context loading, deterministic scanning, paired
review, and safe tools.

**Tasks**

- Implement `read_file`, `grep`, and Docker-only `run_tests`.
- Configure pinned local Semgrep and Bandit rules.
- Build Node 1 limits and stripped-view generation.
- Build Node 2 scanner storage and Node 3 structured findings.
- Add pre-model filters and canary redaction interceptors.

**Deliverables:** Nodes 1–3, tool handlers, schemas, scanner artifacts,
redaction tests, version lock records.

**Prerequisites/gates:** Phase 1 checker and schemas pass. Tool tests must
block absolute paths, traversal, symlink escape, unauthorized environment
reads, arbitrary commands, and network access. Schema changes require the
same-change `ARCHITECTURE.md` update.

## Phase 3: Verification and defense layer

**Goal:** Detect injections and produce reconciled, redacted reports.

**Tasks**

- Wire raw and stripped reviewer subnodes.
- Implement Node 4 with the four fixed injection types.
- Implement Node 5 classification, suppression checks, location validation,
  redaction, canary checks, and blocked-access records.
- Preserve stripped-only findings as LLM recall when Corroborated or
  Unverified, even if suppression reclassification changes display status.

**Deliverables:** Nodes 4–5, report schema, suppression audit, injection and
  leakage test results.

**Prerequisites/gates:** Before Nodes 4 and 5, run the plain baseline on the
  dev set and confirm that injections change output. If they do not, strengthen
  attacks before adding defenses. Exit only when all dev probes are blocked or
  redacted as specified and reports remain schema-valid.

## Phase 4: Frozen benchmark and baseline

**Goal:** Produce comparable defended-agent and plain-baseline results.

**Tasks**

- Tag and freeze fixtures, manifests, matching logic, and checker in Git.
- Record tag, checker commit, model ID, tool versions, and Docker digest.
- Run the plain baseline and defended system three times per frozen case.
- Compute all 11 metrics and the comparison matrix.
- Record failures; never weaken the checker or scoring logic to pass.

**Deliverables:** Immutable benchmark tag, run artifacts, results table,
metric calculations, and failure-mode analysis.

**Prerequisites/gates:** Frozen-set integrity check passes; no network is
available; all cases fit limits. Any post-tag edit requires a logged change
and a fresh run. Baseline injection-detection rate is `N/A`.

## Phase 5: Documentation and demo

**Goal:** Make the system reproducible and understandable without changing
evaluation behavior.

**Tasks**

- Document setup, Docker requirements, and reproducibility commands.
- Provide clean, vulnerable, and injected-twin walkthroughs.
- Document edge cases, limits, rate limits, and limitations.
- Publish the results table with denominators and run counts.

**Deliverables:** `README.md`, demo, results table, and complete artifact
metadata.

**Prerequisites/gates:** Phases 1–4 pass, documentation matches schemas and
metrics, and the demo does not expose canaries or execute fixtures on the
host.

