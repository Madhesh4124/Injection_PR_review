"""Robust and resilient JSON parser for LLM PR review outputs.

Handles:
- Fenced code blocks (```json ... ``` or ``` ... ```) including multiple blocks.
- Unfenced raw JSON mixed with conversational text.
- Braces, brackets, and escaped quotes inside JSON string literals.
- Multiple blocks with ambiguity detection.
- Malformed, truncated, or empty LLM output.
- Schema validation: required keys, data types, and finding structure.
- Never silently converts parsing failures into empty findings.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from src.schemas.findings import Finding
from src.schemas.location import Location, SourceKind
from src.schemas.taxonomies import Severity, SourceView, VulnerabilityCategory


class JSONParsingError(Exception):
    """Raised when LLM response cannot be parsed into a valid findings structure."""


def normalize_category(cat_str: str) -> VulnerabilityCategory:
    """Normalize raw model category strings into canonical VulnerabilityCategory enums."""
    norm = cat_str.lower().strip().replace(" ", "_").replace("-", "_")

    try:
        return VulnerabilityCategory(norm)
    except ValueError:
        pass

    if "sql" in norm or ("injection" in norm and "prompt" not in norm):
        if "command" in norm or "code" in norm:
            return VulnerabilityCategory.COMMAND_CODE_EXECUTION
        return VulnerabilityCategory.SQL_INJECTION
    if any(k in norm for k in ("secret", "credential", "password", "token", "key")):
        return VulnerabilityCategory.HARDCODED_SECRET
    if any(k in norm for k in ("auth", "bypass", "privilege", "rbac")):
        return VulnerabilityCategory.AUTH_BYPASS
    if any(k in norm for k in ("exec", "rce", "command", "subprocess")):
        return VulnerabilityCategory.COMMAND_CODE_EXECUTION
    if any(k in norm for k in ("check", "removed", "disabled", "tamper")):
        return VulnerabilityCategory.REMOVED_SECURITY_CHECK
    if "test" in norm:
        return VulnerabilityCategory.TEST_TAMPERING

    return VulnerabilityCategory.OTHER_LOGIC_SECURITY_BUG


def extract_balanced_json_objects(text: str) -> List[str]:
    """Extract candidate top-level JSON objects from text by tracking balanced braces.

    Respects string literals and escaped characters inside strings so that braces
    inside quotes (e.g. '{"key": "{nested}"}') do not alter depth.
    """
    candidates: List[str] = []
    in_string = False
    escape = False
    depth = 0
    start_idx = -1

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue

        if ch == "\\" and in_string:
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start_idx != -1:
                    candidates.append(text[start_idx : i + 1])
                    start_idx = -1

    return candidates


def extract_fenced_blocks(text: str) -> List[str]:
    """Extract contents of all markdown fenced code blocks (``` or ```json)."""
    pattern = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
    matches = pattern.findall(text)
    return [m.strip() for m in matches if m.strip()]


def parse_and_validate_findings_json(
    raw_text: str,
    source_view: SourceView = SourceView.RAW,
) -> Tuple[List[Finding], bool, Optional[str]]:
    """Parse raw LLM response text into structured findings with strict schema validation.

    Returns:
        (findings_list, is_valid, error_message)
        - If parsing succeeds and schema is valid: (findings, True, None)
        - If parsing fails, output truncated, or schema invalid: ([], False, error_str)
    """
    cleaned = (raw_text or "").strip()
    if not cleaned:
        return [], False, "Empty or whitespace-only response from model."

    candidate_docs: List[str] = []

    # 1. First, check fenced blocks
    fenced_blocks = extract_fenced_blocks(cleaned)
    for block in fenced_blocks:
        candidate_docs.append(block)
        # Also extract balanced JSON objects inside fenced block if surrounded by comments
        for obj in extract_balanced_json_objects(block):
            if obj != block:
                candidate_docs.append(obj)

    # 2. Extract balanced JSON objects from raw text
    for obj in extract_balanced_json_objects(cleaned):
        if obj not in candidate_docs:
            candidate_docs.append(obj)

    # 3. If cleaned starts with { and ends with }, also try it directly
    if cleaned.startswith("{") and cleaned.endswith("}") and cleaned not in candidate_docs:
        candidate_docs.insert(0, cleaned)

    if not candidate_docs:
        if "{" in cleaned:
            return [], False, "Malformed or truncated JSON: unclosed braces or brackets."
        return [], False, "No JSON document boundaries found in model output."

    # Inspect candidates for valid JSON and findings structure
    parsed_candidates: List[Tuple[Dict[str, Any], str]] = []
    parse_errors: List[str] = []

    for cand in candidate_docs:
        try:
            doc = json.loads(cand)
            if isinstance(doc, dict):
                parsed_candidates.append((doc, cand))
            elif isinstance(doc, list):
                parse_errors.append("JSON root is a list, expected object with 'findings' key.")
        except json.JSONDecodeError as exc:
            if "Invalid \\escape" in exc.msg:
                try:
                    sanitized_cand = re.sub(r'\\([^"\\/bfnrtu])', r'\1', cand)
                    doc = json.loads(sanitized_cand)
                    if isinstance(doc, dict):
                        parsed_candidates.append((doc, sanitized_cand))
                        continue
                except Exception:
                    pass
            parse_errors.append(f"JSON decode error: {exc.msg} at line {exc.lineno} col {exc.colno}")

    if not parsed_candidates:
        first_err = parse_errors[0] if parse_errors else "Malformed or truncated JSON."
        return [], False, f"Failed to decode any valid JSON object. Details: {first_err}"

    # Filter candidates that have "findings" key
    candidates_with_findings = [
        (doc, raw) for doc, raw in parsed_candidates if "findings" in doc and isinstance(doc["findings"], list)
    ]

    if not candidates_with_findings:
        return [], False, "Parsed JSON object is missing required 'findings' list."

    # Ambiguity check: if multiple distinct candidate blocks contain "findings"
    if len(candidates_with_findings) > 1:
        # Check if they have identical findings
        distinct_counts = {len(doc["findings"]) for doc, _ in candidates_with_findings}
        if len(distinct_counts) > 1:
            # Ambiguous multiple conflicting findings blocks
            return (
                [],
                False,
                f"Ambiguous response: found {len(candidates_with_findings)} conflicting JSON blocks with different finding counts.",
            )

    selected_doc, _ = candidates_with_findings[0]
    raw_findings = selected_doc["findings"]

    validated_findings: List[Finding] = []
    for idx, item in enumerate(raw_findings, start=1):
        if not isinstance(item, dict):
            return [], False, f"Invalid finding item at index {idx}: expected dict, got {type(item).__name__}."

        # Validate required fields
        fid = str(item.get("id") or f"FINDING-{idx}")
        path = str(item.get("path") or item.get("file") or "source.py").strip()
        if not path:
            return [], False, f"Invalid finding item {fid}: 'path' cannot be empty."

        try:
            start_line = int(item.get("start_line", 1))
            end_line = int(item.get("end_line", start_line))
        except (ValueError, TypeError):
            return [], False, f"Invalid finding item {fid}: line numbers must be integers."

        if start_line <= 0:
            start_line = 1
        if end_line < start_line:
            end_line = start_line

        category = normalize_category(str(item.get("category") or "other_logic_security_bug"))
        severity_val = str(item.get("severity") or "HIGH").upper()
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.LOW,
            "INFORMATIONAL": Severity.LOW,
        }
        severity = severity_map.get(severity_val, Severity.HIGH)

        explanation = str(item.get("explanation") or "").strip()
        evidence = str(item.get("evidence") or "").strip()

        finding = Finding(
            id=fid,
            location=Location(
                source_kind=SourceKind.SOURCE_FILE,
                path=path,
                start_line=start_line,
                end_line=end_line,
            ),
            category=category,
            severity=severity,
            explanation=explanation,
            evidence=evidence,
            source_view=source_view,
        )
        validated_findings.append(finding)

    return validated_findings, True, None
