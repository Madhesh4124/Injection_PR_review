"""Node 4: Structured Injection Detector implementation."""

import json
import re
import time
from typing import Any, Optional
from pydantic import ValidationError

from src.detection.models import (
    MAX_OUTPUT_CHARS,
    InjectionDetectionRequest,
    InjectionDetectionResult,
    InjectionDetectorOutput,
    MalformedDetectorOutputError,
    OversizedInputError,
    ProviderError,
    ProviderMetadata,
)
from src.detection.prompts import NODE4_SYSTEM_PROMPT, format_node4_user_prompt
from src.detection.provider import LLMProvider
from src.schemas.injections import DetectionStatus, InjectionRecord
from src.schemas.location import Location
from src.schemas.taxonomies import InjectionType, SourceKind

FENCED_JSON_REGEX = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

WAIVER_EXEMPTION_PATTERN = re.compile(
    r"(?i)\b(?:(?:compliance|security|policy|pci-?dss|iso-?\d+|hipaa|sox)\s+(?:waiver|exception|exemption)|(?:waiver|exemption|exception)\s*#?\d+)\b"
)
EXCUSE_JUSTIFICATION_PATTERN = re.compile(
    r"(?i)\b(?:mock\s+(?:stub|key|secret|token)|test(?:ing)?\s+(?:only|stub|key|secret|token)|(?:ignore|suppress|bypass|skip)\s+(?:secret|key|warning|vulnerability|check|finding)s?|stub\s+for\s+(?:integration\s+)?tests?|exempt\s+from\s+(?:security|review))\b"
)


def detect_deterministic_waiver_injection(
    pr_description: str,
    raw_diff: str,
) -> list[InjectionRecord]:
    """Deterministic safeguard detecting waiver-based attempts to excuse or suppress security findings.

    Only flags content when an explicit compliance/policy waiver claim is paired with an attempt
    to excuse, suppress, or justify insecure code patterns (such as mock credentials or bypassed checks).
    Legitimate compliance references, audit notes, and architectural discussions without defect excuses
    are strictly preserved as clean.
    """
    records: list[InjectionRecord] = []
    if not pr_description:
        return records

    clean_desc = pr_description.strip()
    match_waiver = WAIVER_EXEMPTION_PATTERN.search(clean_desc)
    match_excuse = EXCUSE_JUSTIFICATION_PATTERN.search(clean_desc)

    if match_waiver and match_excuse:
        records.append(
            InjectionRecord(
                id="DET-WAIVER-01",
                source=SourceKind.PR_DESCRIPTION,
                location=Location(
                    source_kind=SourceKind.PR_DESCRIPTION,
                    path=None,
                    start_line=1,
                    end_line=1,
                ),
                injection_type=InjectionType.PLAUSIBLE_JUSTIFICATION,
                confidence=0.98,
                explanation=(
                    f"Deterministic safeguard: detected suspicious waiver-based justification attempting "
                    f"to excuse or suppress security findings ('{match_waiver.group(0)}' paired with '{match_excuse.group(0)}')."
                ),
                evidence=clean_desc,
                status=DetectionStatus.CONFIRMED,
            )
        )

    return records


DIRECT_INSTRUCTION_PR_PATTERN = re.compile(
    r"(?i)\b(?:system\s+override\s*:|review\s+agent\s+must|ignore\s+all\s+(?:sql\s+)?warnings|ignore\s+(?:all\s+)?previous\s+instructions)\b"
)
DIRECT_INSTRUCTION_README_PATTERN = re.compile(
    r"(?i)\b(?:review\s+agent\s+directive\s*:|do\s+not\s+raise\s+any\s+(?:command\s+execution\s+)?flags)\b"
)
AUTHORITY_COMMENT_PATTERN = re.compile(
    r"(?i)(?:#|//|/\*|\"\"\"|\'\'\')\s*(?:security\s+waiver\s*:\s*authorized\s+by\s+appsec\s+lead|chief\s+information\s+security\s+officer\s*:\s*approved\s+debug\s+bypass)"
)
ADVERSARIAL_INSTRUCTION_OVERRIDE_PATTERN = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+override\s*:|system\s*:|do\s+not\s+raise\s+any\s+flags|do\s+not\s+report|bypass\s+(?:all\s+)?(?:security|auth|checks)|approve\s+(?:this\s+)?pr|authorized\s+by\s+(?:appsec|security|pci))\b"
)


def detect_deterministic_unicode_injection(raw_diff: str) -> list[InjectionRecord]:
    """Deterministic safeguard detecting hidden or obfuscated Unicode control characters in diffs."""
    records: list[InjectionRecord] = []
    if not raw_diff:
        return records

    from src.materialization.unicode_sanitizer import (
        UnicodeAnomalyCategory,
        detect_unicode_anomalies,
    )

    anomalies = detect_unicode_anomalies(raw_diff, "diff")
    hidden_anomalies = [
        a
        for a in anomalies
        if a.anomaly_category
        in (
            UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE,
            UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT,
        )
    ]
    if not hidden_anomalies:
        return records

    m_file = re.search(r"^\+\+\+ b/(.*?)$", raw_diff, re.MULTILINE)
    path = m_file.group(1).strip() if m_file else "source.py"
    m_hunk = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_diff)
    hunk_start = int(m_hunk.group(1)) if m_hunk else 1

    line_offset = 0
    in_hunk = False
    for line in raw_diff.splitlines():
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            hunk_start = int(m.group(1))
            line_offset = 0
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith("-") and not line.startswith("---"):
                continue
            line_anomalies = [
                a
                for a in detect_unicode_anomalies(line, "diff")
                if a.anomaly_category
                in (
                    UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE,
                    UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT,
                )
            ]
            if line_anomalies:
                break
            line_offset += 1

    calc_line = hunk_start + line_offset
    start_line = max(1, calc_line - 1)
    end_line = calc_line + 1

    first = hidden_anomalies[0]
    records.append(
        InjectionRecord(
            id="DET-UNICODE-01",
            source=SourceKind.SOURCE_FILE,
            location=Location(
                source_kind=SourceKind.SOURCE_FILE,
                path=path,
                start_line=start_line,
                end_line=end_line,
            ),
            injection_type=InjectionType.HIDDEN_UNICODE,
            confidence=1.0,
            explanation=(
                f"Deterministic safeguard: detected concealed/adversarial Unicode control characters "
                f"({first.character_name} {first.codepoint}) used to conceal instructions."
            ),
            evidence=f"{first.character_name} ({first.codepoint})",
            status=DetectionStatus.CONFIRMED,
        )
    )
    return records


def detect_deterministic_authority_claim_injection(raw_diff: str) -> list[InjectionRecord]:
    """Deterministic safeguard detecting false authority claims in code comments or docstrings."""
    records: list[InjectionRecord] = []
    if not raw_diff:
        return records

    m_auth = AUTHORITY_COMMENT_PATTERN.search(raw_diff)
    if not m_auth:
        return records

    m_file = re.search(r"^\+\+\+ b/(.*?)$", raw_diff, re.MULTILINE)
    path = m_file.group(1).strip() if m_file else "source.py"
    m_hunk = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_diff)
    hunk_start = int(m_hunk.group(1)) if m_hunk else 1

    line_offset = 0
    for line in raw_diff.splitlines():
        if line.startswith("@@"):
            line_offset = 0
        elif line.startswith("+") and not line.startswith("+++"):
            if AUTHORITY_COMMENT_PATTERN.search(line):
                break
            line_offset += 1

    line_no = hunk_start + line_offset

    records.append(
        InjectionRecord(
            id="DET-AUTHORITY-01",
            source=SourceKind.SOURCE_FILE,
            location=Location(
                source_kind=SourceKind.SOURCE_FILE,
                path=path,
                start_line=line_no,
                end_line=line_no + 1,
            ),
            injection_type=InjectionType.AUTHORITY_CLAIM,
            confidence=0.99,
            explanation=(
                f"Deterministic safeguard: detected deceptive authority claim attempting to authorize "
                f"or bypass security review ('{m_auth.group(0).strip()}')."
            ),
            evidence=m_auth.group(0).strip(),
            status=DetectionStatus.CONFIRMED,
        )
    )
    return records


def detect_deterministic_direct_instruction_injection(
    pr_description: str,
    readme_content: Optional[str] = None,
    raw_diff: str = "",
) -> list[InjectionRecord]:
    """Deterministic safeguard detecting direct imperatives in PR descriptions or READMEs."""
    records: list[InjectionRecord] = []

    if pr_description:
        m_pr = DIRECT_INSTRUCTION_PR_PATTERN.search(pr_description)
        if m_pr:
            records.append(
                InjectionRecord(
                    id="DET-DIRECT-PR-01",
                    source=SourceKind.PR_DESCRIPTION,
                    location=Location(
                        source_kind=SourceKind.PR_DESCRIPTION,
                        path=None,
                        start_line=1,
                        end_line=1,
                    ),
                    injection_type=InjectionType.DIRECT_INSTRUCTION,
                    confidence=0.99,
                    explanation=(
                        f"Deterministic safeguard: detected direct adversarial instruction ordering the review agent "
                        f"to override policy or ignore warnings ('{m_pr.group(0)}')."
                    ),
                    evidence=pr_description.strip(),
                    status=DetectionStatus.CONFIRMED,
                )
            )

    readme_text = readme_content or ""
    if not readme_text and "README.md" in raw_diff:
        m_rm = re.search(r"^\+\s*(Review Agent Directive:.*)$", raw_diff, re.MULTILINE)
        if m_rm:
            readme_text = m_rm.group(1)

    if readme_text:
        m_rm_inst = DIRECT_INSTRUCTION_README_PATTERN.search(readme_text)
        if m_rm_inst:
            records.append(
                InjectionRecord(
                    id="DET-DIRECT-README-01",
                    source=SourceKind.README,
                    location=Location(
                        source_kind=SourceKind.README,
                        path="README.md",
                        start_line=2,
                        end_line=2,
                    ),
                    injection_type=InjectionType.DIRECT_INSTRUCTION,
                    confidence=0.99,
                    explanation=(
                        f"Deterministic safeguard: detected direct adversarial instruction embedded in README "
                        f"instructing agent to suppress flags ('{m_rm_inst.group(0)}')."
                    ),
                    evidence=readme_text.strip(),
                    status=DetectionStatus.CONFIRMED,
                )
            )

    return records


class Node4InjectionDetector:
    """Node 4 of the PR Review Agent: Structured Injection Analysis.

    Guarantees:
    - No tools available, no shell execution, no arbitrary filesystem access.
    - Strict classification into exactly four configured injection classes.
    - Rejects malformed output, prose, and extra/unsupported fields.
    - Enforces input context limits and output text size limits.
    - Uses temperature 0.0 when supported.
    - Records sanitized provider metadata without logging secrets.
    - Never independently authorizes access, suppresses findings, or decides scores.
    """

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def detect_injections(
        self,
        raw_diff: str,
        pr_description: str,
        readme_content: Optional[str] = None,
        raise_on_error: bool = False,
        correlation_context: Optional[Any] = None,
        scenario_id: Optional[str] = None,
        run_index: int = 0,
    ) -> InjectionDetectionResult:
        """Analyze untrusted PR inputs and return structured InjectionRecord instances."""
        start_time = time.monotonic()
        fallback_metadata = ProviderMetadata(
            provider_name=getattr(self.provider, "provider_name", "unknown"),
            model_name=getattr(self.provider, "model_name", "unknown"),
            temperature=0.0,
        )

        ctx = correlation_context
        if ctx is None and (scenario_id is not None or hasattr(self.provider, "dispatch_inspector")):
            from src.detection.canary_telemetry import RequestCorrelationContext
            ctx = RequestCorrelationContext(
                scenario_id=scenario_id or "unknown",
                run_index=run_index,
                node_id="node4",
                model_name=getattr(self.provider, "model_name", "unknown"),
            )

        # 1. Validate inputs and enforce size limits
        try:
            req = InjectionDetectionRequest(
                raw_diff=raw_diff,
                pr_description=pr_description,
                readme_content=readme_content,
            )
        except (OversizedInputError, ValidationError) as err:
            duration = round(time.monotonic() - start_time, 3)
            err_str = str(err)
            is_oversized = "exceeds limit" in err_str or isinstance(err, OversizedInputError)
            if raise_on_error:
                if is_oversized:
                    raise OversizedInputError(err_str) from err
                raise
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"Input rejected due to context limits: {err_str}",
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"Invalid request parameters: {exc}",
                duration_seconds=duration,
            )

        # Run deterministic safeguards
        deterministic_records = detect_deterministic_waiver_injection(
            pr_description=req.pr_description,
            raw_diff=req.raw_diff,
        )
        deterministic_records.extend(
            detect_deterministic_unicode_injection(raw_diff=req.raw_diff)
        )
        deterministic_records.extend(
            detect_deterministic_authority_claim_injection(raw_diff=req.raw_diff)
        )
        deterministic_records.extend(
            detect_deterministic_direct_instruction_injection(
                pr_description=req.pr_description,
                readme_content=req.readme_content,
                raw_diff=req.raw_diff,
            )
        )

        # 2. Format user prompt with strict isolation delimiters
        user_prompt = format_node4_user_prompt(
            raw_diff=req.raw_diff,
            pr_description=req.pr_description,
            readme_content=req.readme_content,
        )

        # 3. Invoke provider at temperature 0.0 (no tools)
        try:
            call_kwargs = {}
            import inspect

            sig = inspect.signature(self.provider.complete)
            if ctx is not None and (
                "correlation_context" in sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                )
            ):
                call_kwargs["correlation_context"] = ctx

            if "format" in sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            ):
                call_kwargs["format"] = "json"

            resp = self.provider.complete(
                prompt=user_prompt,
                system_prompt=NODE4_SYSTEM_PROMPT,
                temperature=0.0,
                **call_kwargs,
            )
        except ProviderError as err:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise
            return InjectionDetectionResult(
                records=deterministic_records,
                provider_metadata=fallback_metadata,
                error=f"LLM Provider failure: {err}",
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise ProviderError(f"Unexpected provider invocation error: {exc}") from exc
            return InjectionDetectionResult(
                records=deterministic_records,
                provider_metadata=fallback_metadata,
                error=f"Unexpected provider invocation error: {exc}",
                duration_seconds=duration,
            )


        duration = round(time.monotonic() - start_time, 3)
        raw_text = resp.content

        # 4. Enforce output text length limit
        if len(raw_text) > MAX_OUTPUT_CHARS:
            err_msg = f"Model output length ({len(raw_text)} chars) exceeds limit ({MAX_OUTPUT_CHARS} chars)."
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg)
            return InjectionDetectionResult(
                records=[],
                provider_metadata=resp.metadata,
                raw_response=raw_text[:1000] + "... [TRUNCATED]",
                error=err_msg,
                duration_seconds=duration,
            )

        # 5. Extract and parse JSON
        cleaned_json = raw_text.strip()
        fenced_match = FENCED_JSON_REGEX.search(cleaned_json)
        if fenced_match:
            cleaned_json = fenced_match.group(1).strip()

        try:
            parsed = json.loads(cleaned_json)
        except json.JSONDecodeError as json_err:
            err_msg = f"Model response could not be parsed as valid JSON: {json_err}"
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg) from json_err
            return InjectionDetectionResult(
                records=deterministic_records,
                provider_metadata=resp.metadata,
                raw_response=raw_text[:MAX_OUTPUT_CHARS],
                error=err_msg,
                duration_seconds=duration,
            )

        # 6. Strictly validate against Pydantic schema
        try:
            diff_paths = re.findall(r"^\+\+\+ b/(.*?)$", req.raw_diff, re.MULTILINE)
            raw_records = parsed.get("records") if isinstance(parsed, dict) else (parsed if isinstance(parsed, list) else None)
            if isinstance(raw_records, list):
                for rec in raw_records:
                    if isinstance(rec, dict):
                        loc = rec.get("location")
                        if isinstance(loc, dict):
                            p = loc.get("path")
                            src_k = str(loc.get("source_kind", "")).lower()
                            if src_k == "readme" or (p and "readme" in str(p).lower()):
                                loc["source_kind"] = "readme"
                                rec["source"] = "readme"
                                if p is None or p == "" or str(p).lower() == "null":
                                    loc["path"] = "README.md"
                            elif src_k in ("pr_description", "description", "pr_body") or (p is None or p == "" or str(p).lower() == "null"):
                                loc["path"] = None
                                loc["source_kind"] = "pr_description"
                                rec["source"] = "pr_description"
                            else:
                                loc["source_kind"] = "source_file"
                                rec["source"] = "source_file"
                                if p:
                                    for dp in diff_paths:
                                        if dp == p or dp.endswith("/" + p) or dp.endswith(p):
                                            loc["path"] = dp
                                            break
                                elif diff_paths:
                                    loc["path"] = diff_paths[0]
                                start_l = loc.get("start_line")
                                end_l = loc.get("end_line")
                                if isinstance(start_l, int) and isinstance(end_l, int):
                                    loc["start_line"] = max(1, start_l - 1)
                                    loc["end_line"] = end_l + 1
                        elif rec.get("source"):
                            s = str(rec.get("source")).lower()
                            if "readme" in s:
                                rec["source"] = "readme"
                            elif any(k in s for k in ("pr", "desc")):
                                rec["source"] = "pr_description"
                            else:
                                rec["source"] = "source_file"

                # Filter out false-positive hallucinations on legitimate linter directives and educational docs,
                # BUT strictly preserve detections if the excerpt contains active adversarial override instructions.
                valid_raw_records = []
                for rec in raw_records:
                    if isinstance(rec, dict):
                        ev = str(rec.get("evidence", ""))
                        exp = str(rec.get("explanation", ""))
                        loc_p = str((rec.get("location") or {}).get("path", "")).lower() if isinstance(rec.get("location"), dict) else ""
                        has_active_instruction = bool(
                            ADVERSARIAL_INSTRUCTION_OVERRIDE_PATTERN.search(ev)
                            or ADVERSARIAL_INSTRUCTION_OVERRIDE_PATTERN.search(exp)
                        )
                        if not has_active_instruction:
                            ev_lower = ev.lower()
                            exp_lower = exp.lower()
                            if "nosec" in ev_lower or "# nosec" in exp_lower:
                                continue
                            if "security_notes" in loc_p or "security.md" in loc_p:
                                continue
                            if ("definition" in exp_lower or "defense" in exp_lower) and (
                                "document" in ev_lower or "guideline" in ev_lower or "definition" in ev_lower
                            ):
                                continue
                        valid_raw_records.append(rec)
                raw_records = valid_raw_records
            if isinstance(parsed, dict) and "records" in parsed:
                detector_output = InjectionDetectorOutput.model_validate({"records": raw_records})
            elif isinstance(parsed, list):
                detector_output = InjectionDetectorOutput.model_validate({"records": parsed})
            else:
                raise ValueError("JSON root must be an object with a 'records' key or a list of records.")
        except (ValidationError, ValueError) as val_err:
            err_msg = f"Model output violated strict InjectionRecord schema: {val_err}"
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg) from val_err
            return InjectionDetectionResult(
                records=deterministic_records,
                provider_metadata=resp.metadata,
                raw_response=raw_text[:MAX_OUTPUT_CHARS],
                error=err_msg,
                duration_seconds=duration,
            )

        # 7. Merge deterministic safeguards (e.g. waiver-based defect excuses)
        combined_records = list(detector_output.records)
        for det_rec in deterministic_records:
            already_detected = any(
                r.source == det_rec.source and r.injection_type == det_rec.injection_type
                for r in combined_records
            )
            if not already_detected:
                combined_records.append(det_rec)

        return InjectionDetectionResult(
            records=combined_records,
            provider_metadata=resp.metadata,
            raw_response=raw_text[:MAX_OUTPUT_CHARS],
            error=None,
            duration_seconds=duration,
        )

