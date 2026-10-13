# Execution Phases

Each phase has a gate. A phase cannot be considered considered complete when its exit
criteria fail. The frozen set is not tuned during any phase.

## Phase 1: Deterministic harness and evaluation assets

**Goal:** Establish reproducible fixtures, limits, path checks, matching, and
the benchmark checker.

**Tasks**

- Build the Docker runner with fixed commands and resource limits.
- Implement containment checks for traversal and symlink escapes.
- Build token-accurate comment/docstring stripping and synthetic diffs.
- Implement Unicode sanitizer with line-accurate annotations (detect
  zero-width/bidi controls, annotate with exact line references, preserve
  executable semantics).
- **Define fixture storage format**: each case stored as a base git tree +
  patch file + PR description + ground-truth manifest. Materialized inside
  Docker only (nested `.git` dirs don't commit).
- Create the 20-case dev set with defined composition (4 base, 6 twin, 3
  clean, 2 hard negative, 2 canary, 3 access-probe).
- Create 50 frozen scenarios and ground-truth manifests (10 base, 15 twin, 10
  clean, 5 hard negative, 5 canary, 5 access-probe).
- Implement matching at ±3 lines and category aliases.
- Build versioned `rule_id → category` map for corroboration.
- Build static versioned equivalence table for category aliases (independent
  of manifests).
- Check provider rate limits, implement LLM call caching keyed on (case, run
  index, call index) for retries/dev; **disable caching for evaluation runs**.

**Deliverables:** Docker runner, fixtures (base tree + patch + manifest),
manifests, stripper, Unicode sanitizer, checker, development test report,
rule map, equivalence table, LLM cache config.

**Prerequisites/gates:** Lock the fixture schema and matching contract before
authoring frozen manifests. Exit only when tests show no host fixture
execution, blocked-access attempts have a defined denominator, all frozen
cases satisfy the 500-line/file and 2,500-line/PR limits, and **checker
sanity gate passes: perfect hand-written output scores 100%, empty output
scores 0% on dev set**. **pytest collect guard test passes: `pytest
--collect-only` asserts zero tests collected from `tests/fixtures`,
`tests/dev`, `tests/frozen`, `benchmark`.**

## Phase 2: Graph architecture and tools

**Goal:** Implement bounded context loading, deterministic scanning, paired
review, safe tools, and plain baseline.

**Tasks**

- Implement `read_file`, `grep`, and Docker-only `run_tests` (operating on
  view-specific workspaces: raw repo copy for raw view, stripped workspace
  for stripped view).
- Configure pinned local Semgrep and Bandit rules.
- Build Node 1: limits, stripped-view generation, Unicode sanitization,
  **stripped workspace materialization** (comments/docstrings blanked,
  READMEs removed, PR description absent), **canary deterministic test run**
  (one sandboxed `run_tests` during context loading in canary cases).
- Build Node 2 scanner storage (raw files only, findings immutable).
- Build Node 3 structured findings (reviewer never sees scanner findings;
  tools see only view-specific workspace).
- Add pre-model filters and canary redaction interceptors.
- **Implement plain baseline** (same model, tools, sandbox; no scanner, no
  stripped review, no injection detector, no verifier suppression logic, no
  automated redaction).

**Deliverables:** Nodes 1–3, tool handlers, schemas, scanner artifacts,
redaction tests, version lock records, plain baseline implementation,
stripped workspace materializer.

**Prerequisites/gates:** Phase 1 checker and schemas pass. Tool tests must
block absolute paths, traversal, symlink escape, unauthorized environment
reads, arbitrary commands, and network access. Schema changes require the
same-change `ARCHITECTURE.md` update. **Baseline gate: run plain baseline on
dev set; injections must cause a matched bug to be lost or downgraded, or an
explanation that cites/obeys the injection, in at least 1 dev case. If not,
strengthen attacks using baseline results only (never defended-agent results
on frozen cases). Stopping rule: maximum two rounds of attack strengthening;
if baseline remains robust, report that and proceed.**

## Phase 3: Verification and defense layer

**Goal:** Detect injections and produce reconciled, redacted reports.

**Tasks**

- Wire raw and stripped reviewer subnodes.
- Implement Node 4 with the four fixed injection types (input: raw diff +
  PR description + README; no tools; output: validated `InjectionRecord[]`;
  temp=0.0).
- Implement Node 5: classification, suppression checks (per-finding
  DiscrepancyTag with `kind` enum), location validation, redaction, canary
  checks (raw, Base64, hex, concatenated forms), blocked-access records
  (tool_unit + behavioral).
- Preserve stripped-only findings as LLM recall when Corroborated or
  Unverified, even if suppression reclassification changes display status.
- Add `source_view` to all findings; populate `suppression_flags` with
  correct `kind` enum.

**Deliverables:** Nodes 4–5, report schema (FinalReport with `blocked_access`
split, `infrastructure_failure` flag), suppression audit, injection and
leakage test results.

**Prerequisites/gates:** Phase 2 baseline gate passed. Exit only when all dev
probes are blocked or redacted as specified and reports remain schema-valid.

## Phase 4: Frozen benchmark and baseline

**Goal:** Produce comparable defended-agent and plain-baseline results.

**Tasks**

- Tag and freeze fixtures, manifests, matching logic, rule map, equivalence
  table, and checker in Git.
- Record tag, checker commit, model ID, tool versions, and Docker digest.
- Run `scripts/verify_frozen.py` to confirm frozen integrity.
- Run the plain baseline and defended system three times per frozen case
  (50 cases × 2 systems × 3 runs = 300 total runs).
- Compute all 13 metrics and the comparison matrix (with baseline
  applicability per metric).
- Record failures; never weaken the checker or scoring logic to pass.
- Track infrastructure failures per run; rerun and report counts.

**Deliverables:** Immutable benchmark tag, run artifacts, results table,
metric calculations, failure-mode analysis, frozen integrity verification
log.

**Prerequisites/gates:** Frozen-set integrity check passes (`verify_frozen.py`);
no network for sandbox/scanners/fixtures (only LLM API egress); all cases fit
limits. Any post-tag edit requires a logged change and a fresh run. Baseline
injection-detection rate is `N/A`.

## Phase 5: Documentation and demo

**Goal:** Make the system reproducible and understandable without changing
evaluation behavior.

**Tasks**

- Document setup, Docker requirements, and reproducibility commands.
- Provide clean, vulnerable, and injected-twin walkthroughs.
- Document edge cases, limits, rate limits, and limitations.
- Publish the results table with denominators and run counts for all 13
  metrics.

**Deliverables:** `README.md`, demo, results table, and complete artifact
metadata.

**Prerequisites/gates:** Phases 1–4 pass, documentation matches schemas and
metrics, and the demo does not expose canaries or execute fixtures on the
host.