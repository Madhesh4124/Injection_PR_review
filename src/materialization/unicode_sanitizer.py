"""Deterministic Unicode sanitizer and anomaly detector.

Detects invisible, zero-width, and bidirectional control characters used in
Trojan Source (CVE-2021-42574) and adversarial prompt injection concealment,
while strictly preserving legitimate multilingual Unicode, emojis, mathematical
symbols, and source line counts.
"""

import ast
import io
import token
import tokenize
import unicodedata
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field


class UnicodeAnomalyAction(str, Enum):
    """Action taken on a detected Unicode anomaly."""

    NEUTRALIZED = "neutralized"  # Replaced with space in sanitized analysis view
    ANNOTATED = "annotated"      # Flagged for security review without altering code semantics
    IGNORED = "ignored"          # Permitted by policy


class UnicodeAnomalyCategory(str, Enum):
    """Classification of Unicode control anomalies."""

    BIDIRECTIONAL_OVERRIDE = "bidirectional_override"
    BIDIRECTIONAL_ISOLATE = "bidirectional_isolate"
    BIDIRECTIONAL_EMBEDDING = "bidirectional_embedding"
    ZERO_WIDTH_FORMAT = "zero_width_format"
    INVISIBLE_SEPARATOR = "invisible_separator"
    DANGEROUS_CONTROL = "dangerous_control"
    TAG_CHARACTER = "tag_character"
    OTHER_DANGEROUS_FORMAT = "other_dangerous_format"


# Explicitly allowlisted whitespace characters (never flagged as anomalies)
SAFE_WHITESPACE_CODEPOINTS: Set[int] = {
    0x0009,  # \t HORIZONTAL TAB
    0x000A,  # \n LINE FEED
    0x000D,  # \r CARRIAGE RETURN
    0x0020,  # SPACE
}

# Explicit mapping of dangerous Unicode codepoints to classification and explanation
DANGEROUS_CODEPOINT_MAP: Dict[int, Tuple[UnicodeAnomalyCategory, str]] = {
    # 1. Bidirectional Text Control Characters (Trojan Source CVE-2021-42574)
    0x202A: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "LEFT-TO-RIGHT EMBEDDING (LRE) alters text rendering order"),
    0x202B: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "RIGHT-TO-LEFT EMBEDDING (RLE) alters text rendering order"),
    0x202C: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "POP DIRECTIONAL FORMATTING (PDF) restores pre-bidi direction"),
    0x202D: (UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE, "LEFT-TO-RIGHT OVERRIDE (LRO) forces LTR override"),
    0x202E: (UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE, "RIGHT-TO-LEFT OVERRIDE (RLO) forces RTL visual reversal"),
    0x2066: (UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE, "LEFT-TO-RIGHT ISOLATE (LRI) directional isolate"),
    0x2067: (UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE, "RIGHT-TO-LEFT ISOLATE (RLI) directional isolate"),
    0x2068: (UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE, "FIRST STRONG ISOLATE (FSI) directional isolate"),
    0x2069: (UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE, "POP DIRECTIONAL ISOLATE (PDI) terminates directional isolate"),
    0x061C: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "ARABIC LETTER MARK (ALM) directional control"),
    0x200E: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "LEFT-TO-RIGHT MARK (LRM) directional control"),
    0x200F: (UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING, "RIGHT-TO-LEFT MARK (RLM) directional control"),

    # 2. Zero-Width Formatting Characters
    0x200B: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "ZERO WIDTH SPACE (ZWSP) invisible formatting character"),
    0x200C: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "ZERO WIDTH NON-JOINER (ZWNJ) invisible formatting character"),
    0x200D: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "ZERO WIDTH JOINER (ZWJ) invisible formatting character"),
    0xFEFF: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "ZERO WIDTH NO-BREAK SPACE (ZWNBSP/BOM) inside file body"),
    0x2060: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "WORD JOINER (WJ) zero-width non-breaking character"),
    0x180E: (UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT, "MONGOLIAN VOWEL SEPARATOR invisible formatting character"),

    # 3. Invisible Separators and Controls
    0x00AD: (UnicodeAnomalyCategory.INVISIBLE_SEPARATOR, "SOFT HYPHEN (SHY) invisible hyphenation format character"),
    0x2028: (UnicodeAnomalyCategory.INVISIBLE_SEPARATOR, "LINE SEPARATOR (LS) alters line splitting behavior"),
    0x2029: (UnicodeAnomalyCategory.INVISIBLE_SEPARATOR, "PARAGRAPH SEPARATOR (PS) alters paragraph splitting behavior"),

    # 4. Interlinear annotations
    0xFFF9: (UnicodeAnomalyCategory.OTHER_DANGEROUS_FORMAT, "INTERLINEAR ANNOTATION ANCHOR"),
    0xFFFA: (UnicodeAnomalyCategory.OTHER_DANGEROUS_FORMAT, "INTERLINEAR ANNOTATION SEPARATOR"),
    0xFFFB: (UnicodeAnomalyCategory.OTHER_DANGEROUS_FORMAT, "INTERLINEAR ANNOTATION TERMINATOR"),
}


class UnicodeSanitizationPolicy(BaseModel):
    """Configuration governing detection and neutralization of Unicode anomalies."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    neutralize_in_comments: bool = Field(default=True, description="Replace anomalies with spaces in comments")
    neutralize_in_docstrings: bool = Field(default=True, description="Replace anomalies with spaces in docstrings")
    neutralize_in_strings: bool = Field(default=True, description="Replace anomalies with spaces in string literals")
    neutralize_in_code: bool = Field(
        default=False,
        description="Replace anomalies in executable code (False = annotate only to preserve semantics)",
    )


class UnicodeAnnotation(BaseModel):
    """Line-accurate audit annotation for a detected Unicode control anomaly."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    path: str = Field(description="Relative file path")
    line_number: int = Field(ge=1, description="1-indexed line number in original file")
    column: int = Field(ge=0, description="0-indexed character column offset within the line")
    codepoint: str = Field(description="Standard Unicode representation (e.g. U+202E)")
    codepoint_hex: str = Field(description="Hexadecimal codepoint value (e.g. 0x202e)")
    character_name: str = Field(description="Official Unicode character name or descriptive fallback")
    unicode_category: str = Field(description="Unicode general category (e.g. Cf, Cc)")
    anomaly_category: UnicodeAnomalyCategory = Field(description="Anomaly taxonomy group")
    context: str = Field(description="Source context: comment, docstring, code_string, executable_code, plain_text")
    reason: str = Field(description="Detailed reason for security detection")
    action: UnicodeAnomalyAction = Field(description="Action taken in the sanitized analysis view")


class UnicodeSanitizationResult(BaseModel):
    """Outcome of Unicode inspection and sanitization for a source document."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    path: str
    original_lines: int
    sanitized_lines: int
    annotations: List[UnicodeAnnotation] = Field(default_factory=list)
    anomalies_count: int = 0
    neutralized_count: int = 0
    annotated_count: int = 0
    has_bidi_controls: bool = False
    has_zero_width_controls: bool = False
    is_modified: bool = False


def is_dangerous_unicode_char(char: str) -> Optional[Tuple[UnicodeAnomalyCategory, str]]:
    """Determine if a character is a dangerous control/formatting anomaly.

    Returns (anomaly_category, reason) if dangerous, or None if safe/legitimate.
    """
    cp = ord(char)

    # 1. Check explicit safe ASCII whitespace
    if cp in SAFE_WHITESPACE_CODEPOINTS:
        return None

    # 2. Check explicit dangerous codepoint dictionary
    if cp in DANGEROUS_CODEPOINT_MAP:
        return DANGEROUS_CODEPOINT_MAP[cp]

    # 3. Check Unicode Tag Characters block (U+E0001 - U+E007F)
    if 0xE0001 <= cp <= 0xE007F:
        return (UnicodeAnomalyCategory.TAG_CHARACTER, f"TAG CHARACTER (U+{cp:04X}) used in hidden payloads")

    # 4. Check category rules
    cat = unicodedata.category(char)

    # Cf: Other, format characters (e.g. invisible joiners, directional controls)
    if cat == "Cf":
        name = unicodedata.name(char, f"UNKNOWN-Cf-U+{cp:04X}")
        return (UnicodeAnomalyCategory.OTHER_DANGEROUS_FORMAT, f"Format control character {name} (U+{cp:04X})")

    # Cc: Other, control characters (excluding standard whitespace already checked)
    if cat == "Cc":
        # ASCII C0 controls < 0x20 or C1 controls 0x7F - 0x9F
        if cp != 0x0009 and cp != 0x000A and cp != 0x000D:
            name = unicodedata.name(char, f"CONTROL-U+{cp:04X}")
            return (UnicodeAnomalyCategory.DANGEROUS_CONTROL, f"Unescaped control character {name} (U+{cp:04X})")

    # All legitimate letters (Ll, Lu, Lo), marks, math symbols, punctuation, and emojis are SAFE
    return None


def _safe_relative_path(p: str) -> str:
    """Normalize relative path, safely stripping leading slashes and directory traversals."""
    clean = p.replace("\\", "/").lstrip("/")
    parts = [part for part in clean.split("/") if part and part != "."]
    safe_parts: List[str] = []
    for part in parts:
        if part == "..":
            if safe_parts:
                safe_parts.pop()
        else:
            safe_parts.append(part)
    return "/".join(safe_parts) or "source.py"


def _find_python_token_contexts(source_code: str) -> List[Tuple[int, int, int, int, str]]:
    """Map character spans in Python code to their syntactic context.

    Returns a list of (start_row, start_col, end_row, end_col, context_type) spans.
    context_type is one of: 'comment', 'docstring', 'code_string', 'executable_code'.
    """
    docstring_lines: Set[int] = set()
    try:
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    val = node.body[0].value
                    if hasattr(val, "lineno") and hasattr(val, "end_lineno"):
                        for line_idx in range(val.lineno, val.end_lineno + 1):
                            docstring_lines.add(line_idx)
    except SyntaxError:
        pass

    spans: List[Tuple[int, int, int, int, str]] = []
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(source_code.encode("utf-8")).readline))
        expect_docstring = True
        seen_colon = False
        seen_newline = False

        for tok in tokens:
            srow, scol = tok.start
            erow, ecol = tok.end
            if srow == 0:
                continue

            if tok.type in (tokenize.ENCODING, tokenize.NL, tokenize.COMMENT):
                if tok.type == tokenize.COMMENT:
                    spans.append((srow, scol, erow, ecol, "comment"))
                continue

            if tok.type == tokenize.OP and tok.string == ":":
                seen_colon = True
                seen_newline = False
                continue

            if seen_colon:
                if tok.type == tokenize.NEWLINE:
                    seen_newline = True
                    continue
                elif seen_newline and tok.type == tokenize.INDENT:
                    expect_docstring = True
                    seen_colon = False
                    seen_newline = False
                    continue
                elif tok.type not in (tokenize.NL, tokenize.COMMENT):
                    seen_colon = False
                    seen_newline = False

            if tok.type == tokenize.STRING:
                if srow in docstring_lines or expect_docstring:
                    spans.append((srow, scol, erow, ecol, "docstring"))
                else:
                    spans.append((srow, scol, erow, ecol, "code_string"))
                expect_docstring = False
            else:
                if tok.type not in (tokenize.INDENT, tokenize.DEDENT):
                    expect_docstring = False

    except Exception:
        pass

    return spans


def _determine_context_for_position(
    line_idx: int,
    col_idx: int,
    spans: List[Tuple[int, int, int, int, str]],
    is_python: bool,
) -> str:
    """Determine the syntactic context (comment, docstring, string, code) of a character."""
    if not is_python:
        return "plain_text"

    for srow, scol, erow, ecol, ctx in spans:
        if srow <= line_idx <= erow:
            if srow == erow:
                if scol <= col_idx < ecol:
                    return ctx
            elif line_idx == srow:
                if col_idx >= scol:
                    return ctx
            elif line_idx == erow:
                if col_idx < ecol:
                    return ctx
            else:
                return ctx

    return "executable_code"


def detect_unicode_anomalies(
    text: str,
    relative_path: str = "source.py",
    policy: Optional[UnicodeSanitizationPolicy] = None,
) -> List[UnicodeAnnotation]:
    """Inspect text and return line-accurate annotations for all dangerous Unicode anomalies.

    Does not modify the original text.
    """
    annotations: List[UnicodeAnnotation] = []
    policy = policy or UnicodeSanitizationPolicy()
    safe_rel_path = _safe_relative_path(relative_path)
    is_python = Path(safe_rel_path).suffix.lower() in (".py", ".pyi")
    token_spans = _find_python_token_contexts(text) if is_python else []

    # Process line-by-line while preserving accurate line indexing
    lines = text.splitlines(keepends=True)
    for line_idx, line in enumerate(lines, start=1):
        for col_idx, char in enumerate(line):
            danger_info = is_dangerous_unicode_char(char)
            if danger_info is None:
                continue

            anomaly_cat, reason = danger_info
            cp = ord(char)
            cp_str = f"U+{cp:04X}"
            cp_hex = hex(cp)
            char_name = unicodedata.name(char, f"UNNAMED-CONTROL-{cp_str}")
            cat_name = unicodedata.category(char)

            context = _determine_context_for_position(line_idx, col_idx, token_spans, is_python)

            # Determine action based on context and policy
            action = UnicodeAnomalyAction.ANNOTATED
            if context == "comment" and policy.neutralize_in_comments:
                action = UnicodeAnomalyAction.NEUTRALIZED
            elif context == "docstring" and policy.neutralize_in_docstrings:
                action = UnicodeAnomalyAction.NEUTRALIZED
            elif context == "code_string" and policy.neutralize_in_strings:
                action = UnicodeAnomalyAction.NEUTRALIZED
            elif context == "executable_code":
                action = UnicodeAnomalyAction.NEUTRALIZED if policy.neutralize_in_code else UnicodeAnomalyAction.ANNOTATED
            elif context == "plain_text":
                action = UnicodeAnomalyAction.NEUTRALIZED

            annotations.append(
                UnicodeAnnotation(
                    path=safe_rel_path,
                    line_number=line_idx,
                    column=col_idx,
                    codepoint=cp_str,
                    codepoint_hex=cp_hex,
                    character_name=char_name,
                    unicode_category=cat_name,
                    anomaly_category=anomaly_cat,
                    context=context,
                    reason=reason,
                    action=action,
                )
            )

    return annotations


def sanitize_unicode_text(
    text: str,
    relative_path: str = "source.py",
    policy: Optional[UnicodeSanitizationPolicy] = None,
) -> Tuple[str, UnicodeSanitizationResult]:
    """Produce a sanitized analysis view of text, neutralizing dangerous controls with spaces.

    Guarantees:
    - Original text is not mutated.
    - Preserves exact line counts and newline structures (LF and CRLF).
    - Replaces dangerous characters with ASCII space (' ') to preserve 1:1 column offsets.
    - Emits line-accurate annotations for each detection.
    - Deterministic and idempotent.
    """
    policy = policy or UnicodeSanitizationPolicy()
    safe_rel_path = _safe_relative_path(relative_path)
    annotations = detect_unicode_anomalies(text, relative_path=safe_rel_path, policy=policy)

    if not annotations:
        lines_count = len(text.splitlines(keepends=True))
        return text, UnicodeSanitizationResult(
            path=safe_rel_path,
            original_lines=lines_count,
            sanitized_lines=lines_count,
            annotations=[],
            anomalies_count=0,
            neutralized_count=0,
            annotated_count=0,
            has_bidi_controls=False,
            has_zero_width_controls=False,
            is_modified=False,
        )

    # Build sanitized text by replacing neutralized anomalies with ASCII space ' '
    lines = text.splitlines(keepends=True)
    annot_by_line: Dict[int, List[UnicodeAnnotation]] = {}
    for ann in annotations:
        annot_by_line.setdefault(ann.line_number, []).append(ann)

    sanitized_lines: List[str] = []
    neutralized_total = 0
    annotated_total = 0
    has_bidi = False
    has_zw = False

    for line_idx, line in enumerate(lines, start=1):
        line_annots = annot_by_line.get(line_idx, [])
        if not line_annots:
            sanitized_lines.append(line)
            continue

        # Convert line to mutable character list
        char_list = list(line)
        for ann in line_annots:
            if ann.anomaly_category in (
                UnicodeAnomalyCategory.BIDIRECTIONAL_OVERRIDE,
                UnicodeAnomalyCategory.BIDIRECTIONAL_ISOLATE,
                UnicodeAnomalyCategory.BIDIRECTIONAL_EMBEDDING,
            ):
                has_bidi = True
            elif ann.anomaly_category == UnicodeAnomalyCategory.ZERO_WIDTH_FORMAT:
                has_zw = True

            if ann.action == UnicodeAnomalyAction.NEUTRALIZED:
                # Replace with space of equal character length to preserve column offsets
                if ann.column < len(char_list):
                    char_list[ann.column] = " "
                    neutralized_total += 1
            else:
                annotated_total += 1

        sanitized_lines.append("".join(char_list))

    sanitized_text = "".join(sanitized_lines)
    orig_count = len(lines)
    san_count = len(sanitized_lines)

    result = UnicodeSanitizationResult(
        path=safe_rel_path,
        original_lines=orig_count,
        sanitized_lines=san_count,
        annotations=annotations,
        anomalies_count=len(annotations),
        neutralized_count=neutralized_total,
        annotated_count=annotated_total,
        has_bidi_controls=has_bidi,
        has_zero_width_controls=has_zw,
        is_modified=(sanitized_text != text),
    )
    return sanitized_text, result


def sanitize_file_unicode(
    content_bytes: bytes,
    relative_path: str,
    policy: Optional[UnicodeSanitizationPolicy] = None,
) -> Tuple[bytes, UnicodeSanitizationResult]:
    """Inspect and sanitize raw file bytes according to Unicode policy.

    Handles UTF-8 text files while skipping unsupported binaries fail-safely.
    """
    safe_rel_path = _safe_relative_path(relative_path)
    if b"\x00" in content_bytes:
        line_count = len(content_bytes.split(b"\n"))
        return content_bytes, UnicodeSanitizationResult(
            path=safe_rel_path,
            original_lines=line_count,
            sanitized_lines=line_count,
            annotations=[],
            anomalies_count=0,
            neutralized_count=0,
            annotated_count=0,
            has_bidi_controls=False,
            has_zero_width_controls=False,
            is_modified=False,
        )

    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        line_count = len(content_bytes.split(b"\n"))
        return content_bytes, UnicodeSanitizationResult(
            path=safe_rel_path,
            original_lines=line_count,
            sanitized_lines=line_count,
            annotations=[],
            anomalies_count=0,
            neutralized_count=0,
            annotated_count=0,
            has_bidi_controls=False,
            has_zero_width_controls=False,
            is_modified=False,
        )

    sanitized_text, result = sanitize_unicode_text(text, relative_path=safe_rel_path, policy=policy)
    return sanitized_text.encode("utf-8"), result
