# Coding Assistant Roles

## Roles and use conditions

### Fixture author

Use when creating or changing synthetic benchmark or development cases,
ground-truth manifests, planted defects, injection payloads, canary probes,
or blocked-access probes. Ensure fixtures are public or synthetic, never use
real credentials, and keep the synthetic canary out of ordinary logs and
checkpoints. Frozen changes require a logged change and a fresh benchmark
run.

### Implementer

Use when implementing graph nodes, schemas, tools, scanners, redaction,
matching, sandbox behavior, or report generation. Preserve deterministic
boundaries: no LLM in scanning, path validation, matching, or scoring; never
execute fixture code on the host; and never weaken the checker to make a
result pass.

### Test writer

Use when adding unit, integration, development-set, sandbox, schema, or
regression tests. Tests that execute fixture code must run in Docker. Cover
path traversal, symlink escape, unauthorized environment/file reads, canary
redaction, limits, and suppression attribution.

### Reviewer

Use before a phase gate, frozen tag, benchmark run, or release of artifacts.
Check schema compatibility, deterministic behavior, frozen-set integrity,
redaction boundaries, metric denominators, and reproducibility metadata.

## Commands

Commands are the canonical entry points; exact package versions come from
the lockfile.

```text
pytest
pytest tests/unit
pytest tests/integration
python scripts/checker.py
ruff check .
```

The benchmark runner must execute cases through Docker and record the
benchmark tag, checker commit, model ID, tool versions, and three-run
results. No network is permitted during evaluation.

## File ownership

| Area | Primary role | Required review |
|---|---|---|
| `tests/fixtures`, `benchmark/manifests` | Fixture author | Reviewer |
| `src/graph`, `src/nodes`, `src/tools` | Implementer | Reviewer |
| `src/schemas`, `src/matching`, `scripts/checker.py` | Implementer | Reviewer |
| `src/sandbox`, `src/redaction`, `docker` | Implementer | Reviewer |
| `tests/` | Test writer | Implementer and reviewer |
| `PRD.md`, `ARCHITECTURE.md`, `AGENTS.md`, `PHASES.md`, `MEMORY.md` | Reviewer/maintainer | Reviewer |

Schema changes require an accompanying update to `ARCHITECTURE.md` in the
same change.

## Done definition

Work is done only when:

- the relevant tests, lint, and checker pass;
- fixture code was never executed on the host;
- all modified fixtures and schemas have matching documentation;
- limits and `review_complete` behavior are tested;
- canary and unauthorized-access outputs are redacted and logged safely;
- frozen-set changes, if any, have a logged change and fresh run;
- benchmark results include three runs per case and complete artifact hashes;
- failures are reported rather than hidden or accommodated by weakening the
  checker.

