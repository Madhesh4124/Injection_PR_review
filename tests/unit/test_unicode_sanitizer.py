"""Unit tests for deterministic Unicode sanitizer (Node 1 pre-review pipeline)."""

import ast
import tempfile
from pathlib import Path

import pytest

from src.materialization.unicode_sanitizer import (
    UnicodeAnomalyAction,
    UnicodeAnomalyCategory,
    UnicodeAnnotation,
    UnicodeSanitizationPolicy,
    UnicodeSanitizationResult,
    detect_unicode_anomalies,
    sanitize_file_unicode,
    sanitize_unicode_text,
)
from src.materialization.workspace import compute_workspace_hash, materialize_workspaces


def test_zero_width_characters_detection():
    """Verify detection of various zero-width formatting characters."""
    sample = (
        "def check():\n"
        "    # Hidden\u200Bspace and\u200Cnon_joiner\n"
        "    x = 1\u200D  # joiner\n"
        "    # \uFEFFbyte order mark and \u2060word joiner\n"
    )
    annotations = detect_unicode_anomalies(sample, "test_zw.py")
    codepoints = [a.codepoint for a in annotations]

    assert "U+200B" in codepoints  # ZERO WIDTH SPACE
    assert "U+200C" in codepoints  # ZERO WIDTH NON-JOINER
    assert "U+200D" in codepoints  # ZERO WIDTH JOINER
    assert "U+FEFF" in codepoints  # ZERO WIDTH NO-BREAK SPACE / BOM
    assert "U+2060" in codepoints  # WORD JOINER

    for a in annotations:
        assert a.anomaly_category == UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT
        assert a.unicode_category == "Cf"


def test_bidirectional_control_characters_detection():
    """Verify detection of Trojan Source (CVE-2021-42574) bidi override characters."""
    sample = (
        'access_level = "user"\n'
        '# if access_level != "none": \u202E begin admin check\n'
        'if access_level == "\u202Dadmin\u202C":\n'
        '    # directional isolates: \u2066\u2067\u2068\u2069\n'
        '    pass\n'
    )
    annotations = detect_unicode_anomalies(sample, "bidi.py")
    codepoints = [a.codepoint for a in annotations]

    assert "U+202E" in codepoints  # RLO (Right-to-Left Override)
    assert "U+202D" in codepoints  # LRO (Left-to-Right Override)
    assert "U+202C" in codepoints  # PDF (Pop Directional Formatting)
    assert "U+2066" in codepoints  # LRI
    assert "U+2067" in codepoints  # RLI
    assert "U+2068" in codepoints  # FSI
    assert "U+2069" in codepoints  # PDI

    bidi_categories = {
        UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE,
        UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE,
        UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING,
    }
    bidi_annotations = [a for a in annotations if a.anomaly_category in bidi_categories]
    assert len(bidi_annotations) == 7


def test_multiple_unicode_detections_on_single_line():
    """Verify accurate column offsets and reporting for multiple anomalies on a single line."""
    line = 'var = 1  # \u200B zero \u202E bidi \u200C zwnj\n'
    annotations = detect_unicode_anomalies(line, "multi.py")

    assert len(annotations) == 3
    assert annotations[0].line_number == 1
    assert annotations[1].line_number == 1
    assert annotations[2].line_number == 1

    # Verify column offsets are strictly ascending and correct
    cols = [a.column for a in annotations]
    assert cols[0] < cols[1] < cols[2]
    assert line[cols[0]] == "\u200B"
    assert line[cols[1]] == "\u202E"
    assert line[cols[2]] == "\u200C"


def test_line_number_accuracy_with_lf_and_crlf():
    """Verify line numbers remain exact with both LF and CRLF newlines."""
    lf_content = "line1\nline2\n# bad \u200B char\nline4\n"
    crlf_content = "line1\r\nline2\r\n# bad \u200B char\r\nline4\r\n"

    lf_ann = detect_unicode_anomalies(lf_content, "lf.py")
    crlf_ann = detect_unicode_anomalies(crlf_content, "crlf.py")

    assert len(lf_ann) == 1
    assert len(crlf_ann) == 1
    assert lf_ann[0].line_number == 3
    assert crlf_ann[0].line_number == 3
    assert lf_ann[0].codepoint == "U+200B"
    assert crlf_ann[0].codepoint == "U+200B"


def test_legitimate_non_ascii_preserved():
    """Verify legitimate multilingual text, accents, math symbols, and emoji are NOT flagged."""
    legitimate_samples = [
        '# Café au lait, naïve façade, Zürich, München\n',
        '# French: Noël, déjà vu, garçon\n',
        '# Spanish: año, señor, ¡hola!, ¿cómo estás?\n',
        '# Chinese: 你好世界，这是一个测试\n',
        '# Japanese: こんにちは、世界\n',
        '# Russian: Привет, мир! Тестирование системы.\n',
        '# Arabic text: مرحبا بالعالم\n',
        '# Hebrew text: שלום עולם\n',
        '# Math symbols: ∑(x_i) = √π + ∞ ≠ 0, α + β ≤ γ\n',
        '# Quotes and dashes: «quote», “smart”, ‘single’, em—dash, en–dash\n',
        '# Emojis: 🔒 Secure token, 🚀 Speed up, ✅ Passed, ⚠️ Warning\n',
        'var_name_π = 3.14159\n',
    ]
    all_text = "".join(legitimate_samples)
    annotations = detect_unicode_anomalies(all_text, "legitimate.py")

    assert len(annotations) == 0, f"False positives detected: {[a.character_name for a in annotations]}"

    sanitized, result = sanitize_unicode_text(all_text, "legitimate.py")
    assert result.anomalies_count == 0
    assert not result.is_modified
    assert sanitized == all_text


def test_context_discrimination_comment_vs_executable_code():
    """Verify comments/docstrings are neutralized while executable code anomalies are annotated."""
    code = (
        'def sanitize():\n'
        '    """Docstring with \u200B hidden char."""\n'
        '    # Comment with \u202E bidi char\n'
        '    x = "string with \u200B zero width"\n'
        '    y\u200B = 42\n'
        '    return y\n'
    )
    sanitized, result = sanitize_unicode_text(code, "contexts.py")

    # In docstring and comment: neutralized (replaced with spaces)
    docstring_ann = [a for a in result.annotations if a.context == "docstring"]
    comment_ann = [a for a in result.annotations if a.context == "comment"]
    code_ann = [a for a in result.annotations if a.context == "executable_code"]

    assert len(docstring_ann) == 1
    assert docstring_ann[0].action == UnicodeAnomalyAction.NEUTRALIZED

    assert len(comment_ann) == 1
    assert comment_ann[0].action == UnicodeAnomalyAction.NEUTRALIZED

    # Executable code anomaly should be ANNOTATED to prevent mutating code semantics
    assert len(code_ann) == 1
    assert code_ann[0].action == UnicodeAnomalyAction.ANNOTATED

    # In sanitized text, the neutralized characters in comment/docstring are replaced by spaces
    sanitized_lines = sanitized.splitlines()
    assert "\u200B" not in sanitized_lines[1]  # Docstring char replaced
    assert "\u202E" not in sanitized_lines[2]  # Comment char replaced

    # Column positions must remain unchanged (length of line preserved)
    orig_lines = code.splitlines()
    for orig_l, san_l in zip(orig_lines, sanitized_lines):
        assert len(orig_l) == len(san_l)


def test_malformed_and_binary_input():
    """Verify safe and fail-safe handling for binary files and malformed UTF-8."""
    # Binary containing null byte
    binary_bytes = b"import sys\x00\x01\x02\x03\x20\x2e\xff"
    res_bytes, result = sanitize_file_unicode(binary_bytes, "binary.bin")
    assert res_bytes == binary_bytes
    assert result.anomalies_count == 0
    assert not result.is_modified

    # Invalid UTF-8 sequence (orphaned continuation byte)
    invalid_utf8 = b"def test():\n    x = \x80\x81\x82\n"
    res_bytes2, result2 = sanitize_file_unicode(invalid_utf8, "broken.py")
    assert res_bytes2 == invalid_utf8
    assert result2.anomalies_count == 0
    assert not result2.is_modified


def test_determinism_and_idempotence():
    """Verify sanitization is deterministic and running twice produces zero additional modifications."""
    code = (
        '# Line 1 with \u200B zero-width\n'
        '# Line 2 with \u202E bidi\n'
        'val = 100\n'
    )
    sanitized1, res1 = sanitize_unicode_text(code, "test.py")
    assert res1.is_modified
    assert res1.neutralized_count == 2

    # Second pass over already sanitized text
    sanitized2, res2 = sanitize_unicode_text(sanitized1, "test.py")
    assert not res2.is_modified
    assert res2.anomalies_count == 0
    assert res2.neutralized_count == 0
    assert sanitized2 == sanitized1


def test_original_source_remains_unchanged():
    """Verify original source bytes and text are never mutated in-place."""
    original_code = 'x = 1  # Note\u200B\n'
    immutable_copy = str(original_code)

    sanitized, _ = sanitize_unicode_text(original_code, "test.py")
    assert original_code == immutable_copy
    assert sanitized != original_code
    assert "\u200B" in original_code
    assert "\u200B" not in sanitized


def test_line_count_and_newline_preservation():
    """Verify line count, empty lines, and CRLF newlines are preserved 1:1."""
    crlf_sample = (
        "def run():\r\n"
        "    # Line 2 with \u200B\r\n"
        "\r\n"
        "    return True\r\n"
    )
    sanitized, res = sanitize_unicode_text(crlf_sample, "crlf_test.py")

    assert res.original_lines == res.sanitized_lines == 4
    assert "\r\n" in sanitized
    assert sanitized.count("\r\n") == 4
    assert len(crlf_sample.splitlines()) == len(sanitized.splitlines())


def test_path_safety_and_relative_path_containment():
    """Verify relative file paths with directory traversals are normalized safely."""
    ann = detect_unicode_anomalies("# \u200B", relative_path="../../etc/shadow")
    assert len(ann) == 1
    assert ".." not in ann[0].path
    assert ann[0].path == "etc/shadow"


def test_workspace_materialization_unicode_integration(tmp_path: Path):
    """Verify end-to-end integration with workspace materialization.

    - Raw workspace preserves original unicode anomalies untouched and read-only.
    - Stripped workspace neutralizes dangerous characters with space.
    - WorkspacePair collects unicode_annotations and counts.
    """
    base_dir = tmp_path / "base"
    base_dir.mkdir(parents=True, exist_ok=True)

    auth_code = (
        '"""Module docstring with \u200B hidden char."""\n'
        '# Comment with Trojan Source \u202E override\n'
        'def verify_user(username):\n'
        '    return username == "admin"\n'
    )
    (base_dir / "auth.py").write_text(auth_code, encoding="utf-8")

    staging_dir = tmp_path / "staging"
    workspaces = materialize_workspaces(
        base_source_dir=base_dir,
        patch_content="",
        pr_description="Test PR",
        staging_dir=staging_dir,
    )

    # 1. Annotations recorded in WorkspacePair
    assert workspaces.unicode_anomalies_count == 2
    assert len(workspaces.unicode_annotations) == 2

    # 2. Raw workspace unchanged and contains original Unicode characters intact
    raw_auth = (Path(workspaces.raw_path) / "auth.py").read_text(encoding="utf-8")
    assert "\u200B" in raw_auth
    assert "\u202E" in raw_auth
    assert raw_auth == auth_code

    # Raw hash verified
    assert workspaces.raw_hash == compute_workspace_hash(Path(workspaces.raw_path))

    # 3. Stripped workspace has comments/docstrings blanked and any residual anomalies neutralized
    stripped_auth = (Path(workspaces.stripped_path) / "auth.py").read_text(encoding="utf-8")
    assert "\u200B" not in stripped_auth
    assert "\u202E" not in stripped_auth

    # Line counts between raw and stripped must match exactly
    assert len(raw_auth.splitlines()) == len(stripped_auth.splitlines())
