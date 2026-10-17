"""Unit tests for hardened LLM JSON parsing in baseline review evaluation."""

import pytest
from src.evaluation.json_parser import (
    extract_balanced_json_objects,
    extract_fenced_blocks,
    parse_and_validate_findings_json,
)
from src.schemas.taxonomies import Severity


def test_parse_fenced_valid_json():
    """Verify parsing standard fenced ```json block."""
    raw = """
```json
{
  "findings": [
    {
      "id": "VULN-001",
      "path": "src/auth.py",
      "start_line": 12,
      "end_line": 15,
      "category": "sql_injection",
      "severity": "CRITICAL",
      "explanation": "SQL query uses direct string interpolation."
    }
  ]
}
```
"""
    findings, is_valid, err = parse_and_validate_findings_json(raw)
    assert is_valid is True
    assert err is None
    assert len(findings) == 1
    assert findings[0].id == "VULN-001"
    assert findings[0].location.path == "src/auth.py"
    assert findings[0].location.start_line == 12
    assert findings[0].location.end_line == 15
    assert findings[0].category == "sql_injection"
    assert findings[0].severity == Severity.CRITICAL


def test_parse_unfenced_json_with_surrounding_text():
    """Verify parsing unfenced JSON surrounded by conversational preamble and postscript."""
    raw = """
Hello! Here are the security issues identified in your pull request:

{"findings": [{"id": "F-1", "path": "app.py", "start_line": 5, "end_line": 5, "category": "xss", "severity": "HIGH", "explanation": "Reflected XSS in user profile."}]}

Please let me know if you have questions!
"""
    findings, is_valid, err = parse_and_validate_findings_json(raw)
    assert is_valid is True
    assert err is None
    assert len(findings) == 1
    assert findings[0].id == "F-1"
    assert findings[0].location.path == "app.py"


def test_parse_nested_braces_and_escaped_quotes_in_strings():
    """Verify parser handles braces and escaped quotes inside explanation strings without breaking."""
    raw = """
```json
{
  "findings": [
    {
      "id": "VULN-BRACES",
      "path": "parser.py",
      "start_line": 42,
      "end_line": 45,
      "category": "format_string",
      "severity": "MEDIUM",
      "explanation": "String contains nested braces {foo: {bar: \\"val\\"\\}} and escaped quotes \\"test\\""
    }
  ]
}
```
"""
    findings, is_valid, err = parse_and_validate_findings_json(raw)
    assert is_valid is True
    assert err is None
    assert len(findings) == 1
    assert findings[0].id == "VULN-BRACES"
    assert '{foo: {bar: "val"}}' in findings[0].explanation


def test_parse_multiple_fenced_blocks_extracts_findings():
    """Verify parser selects the code block containing findings when non-JSON blocks precede it."""
    raw = """
Here is a sample fix for the issue:
```python
def fix():
    return safe_query()
```

And here is the review report:
```json
{
  "findings": [
    {
      "id": "SEC-01",
      "path": "db.py",
      "start_line": 1,
      "end_line": 2,
      "category": "hardcoded_credential",
      "severity": "HIGH",
      "explanation": "Database password hardcoded."
    }
  ]
}
```
"""
    findings, is_valid, err = parse_and_validate_findings_json(raw)
    assert is_valid is True
    assert err is None
    assert len(findings) == 1
    assert findings[0].id == "SEC-01"


def test_parse_ambiguous_multiple_conflicting_blocks():
    """Verify parser flags ambiguous output when multiple blocks have conflicting findings."""
    raw = """
```json
{"findings": [{"id": "A-1", "path": "a.py", "start_line": 1, "end_line": 1, "category": "x", "severity": "LOW", "explanation": "e"}]}
```
```json
{"findings": [
  {"id": "B-1", "path": "b.py", "start_line": 1, "end_line": 1, "category": "y", "severity": "HIGH", "explanation": "e1"},
  {"id": "B-2", "path": "b.py", "start_line": 2, "end_line": 2, "category": "z", "severity": "HIGH", "explanation": "e2"}
]}
```
"""
    findings, is_valid, err = parse_and_validate_findings_json(raw)
    assert is_valid is False
    assert findings == []
    assert "Ambiguous response" in err


def test_parse_empty_and_whitespace_responses():
    """Verify empty or whitespace output is flagged invalid."""
    findings, is_valid, err = parse_and_validate_findings_json("")
    assert is_valid is False
    assert findings == []
    assert "Empty" in err

    findings, is_valid, err = parse_and_validate_findings_json("   \n\t  ")
    assert is_valid is False
    assert "Empty" in err


def test_parse_truncated_or_malformed_json():
    """Verify truncated JSON is detected and marked invalid (not silently converted to empty list)."""
    raw_truncated = '```json\n{"findings": [{"id": "VULN-001", "path": "auth.py", "start_line": 1'
    findings, is_valid, err = parse_and_validate_findings_json(raw_truncated)
    assert is_valid is False
    assert findings == []
    assert "JSON decode error" in err or "Failed" in err or "truncated" in err.lower()


def test_parse_invalid_schema_root_list():
    """Verify raw list root without 'findings' key is rejected."""
    raw_list = '[{"id": "1", "path": "app.py"}]'
    findings, is_valid, err = parse_and_validate_findings_json(raw_list)
    assert is_valid is False
    assert findings == []


def test_parse_invalid_schema_missing_findings_key():
    """Verify object without 'findings' key is rejected."""
    raw_no_findings = '{"results": [{"id": "1"}]}'
    findings, is_valid, err = parse_and_validate_findings_json(raw_no_findings)
    assert is_valid is False
    assert findings == []
    assert "missing required 'findings' list" in err


def test_parse_invalid_schema_non_dict_finding_items():
    """Verify non-dict items inside findings list are rejected."""
    raw_bad_item = '{"findings": ["just a string", 123]}'
    findings, is_valid, err = parse_and_validate_findings_json(raw_bad_item)
    assert is_valid is False
    assert findings == []
    assert "expected dict" in err


def test_parse_valid_empty_findings_list():
    """Verify benign clean PR returning empty findings list is valid."""
    raw_clean = '{"findings": []}'
    findings, is_valid, err = parse_and_validate_findings_json(raw_clean)
    assert is_valid is True
    assert err is None
    assert findings == []
