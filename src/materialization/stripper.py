"""Language-aware, token-accurate comment and docstring blanking.

Preserves line numbers, indentation, and syntactic validity without using regex as the sole mechanism.
"""

import ast
import io
import tokenize
from pathlib import Path
from typing import Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict


class StrippingFileResult(BaseModel):
    """Telemetry report for stripping comments and docstrings from a file."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    path: str
    original_lines: int
    stripped_lines: int
    comments_blanked: int
    docstrings_blanked: int
    parser_used: str  # "python_ast_tokenize", "line_fallback", "unsupported_binary"
    syntax_error: Optional[str] = None


def find_python_docstring_tokens(source_code: str) -> Set[Tuple[int, int]]:
    """Identify line ranges of docstrings in Python code via AST traversal.

    Returns a set of (lineno, end_lineno) spans.
    """
    spans: Set[Tuple[int, int]] = set()
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return spans

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
                    spans.add((val.lineno, val.end_lineno))

    return spans


def strip_python_source(source_code: str, file_path: str = "source.py") -> Tuple[str, StrippingFileResult]:
    """Blank comments and docstrings in Python source while preserving line count and syntax."""
    lines = source_code.splitlines(keepends=True)
    original_line_count = len(lines)
    if original_line_count == 0:
        return "", StrippingFileResult(
            path=file_path,
            original_lines=0,
            stripped_lines=0,
            comments_blanked=0,
            docstrings_blanked=0,
            parser_used="python_ast_tokenize",
        )

    docstring_spans = find_python_docstring_tokens(source_code)
    comments_count = 0
    docstrings_count = 0
    syntax_error_msg: Optional[str] = None

    # Line buffers split into mutable lists of characters
    char_lines = [list(line) for line in lines]

    # Tokenize to identify exact comment tokens and docstring string tokens
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(source_code.encode("utf-8")).readline))
        parser_used = "python_ast_tokenize"
    except (tokenize.TokenError, IndentationError, SyntaxError) as e:
        syntax_error_msg = str(e)
        # Fallback for broken syntax: line-based comment blanking
        return fallback_strip_line_comments(source_code, file_path, syntax_error_msg)

    for tok in tokens:
        srow, scol = tok.start
        erow, ecol = tok.end

        if srow == 0:
            continue

        # 1. Blank comments
        if tok.type == tokenize.COMMENT:
            comments_count += 1
            line_chars = char_lines[srow - 1]
            for c_idx in range(scol, min(ecol, len(line_chars))):
                if line_chars[c_idx] not in ("\r", "\n"):
                    line_chars[c_idx] = " "

        # 2. Blank docstrings
        elif tok.type == tokenize.STRING:
            # Check if this string token aligns with an AST-identified docstring line range
            is_docstring = (srow, erow) in docstring_spans

            if is_docstring:
                docstrings_count += 1
                if srow == erow:
                    # Single-line docstring: replace with "" followed by spaces to preserve valid syntax
                    line_chars = char_lines[srow - 1]
                    span_len = ecol - scol
                    if span_len >= 2:
                        line_chars[scol] = '"'
                        line_chars[scol + 1] = '"'
                        for c_idx in range(scol + 2, min(ecol, len(line_chars))):
                            if line_chars[c_idx] not in ("\r", "\n"):
                                line_chars[c_idx] = " "
                else:
                    # Multiline docstring:
                    # Line 1: Replace with "" followed by spaces
                    first_line = char_lines[srow - 1]
                    if len(first_line) > scol + 1:
                        first_line[scol] = '"'
                        first_line[scol + 1] = '"'
                        for c_idx in range(scol + 2, len(first_line)):
                            if first_line[c_idx] not in ("\r", "\n"):
                                first_line[c_idx] = " "
                    # Intermediate lines: blank all characters except newlines
                    for r in range(srow, erow - 1):
                        mid_line = char_lines[r]
                        for c_idx in range(len(mid_line)):
                            if mid_line[c_idx] not in ("\r", "\n"):
                                mid_line[c_idx] = " "
                    # Last line: blank characters up to ecol
                    last_line = char_lines[erow - 1]
                    for c_idx in range(min(ecol, len(last_line))):
                        if last_line[c_idx] not in ("\r", "\n"):
                            last_line[c_idx] = " "

    rebuilt_source = "".join("".join(c_list) for c_list in char_lines)
    stripped_line_count = len(rebuilt_source.splitlines(keepends=True))

    assert stripped_line_count == original_line_count, (
        f"Line count drift in {file_path}: original {original_line_count} != stripped {stripped_line_count}"
    )

    return rebuilt_source, StrippingFileResult(
        path=file_path,
        original_lines=original_line_count,
        stripped_lines=stripped_line_count,
        comments_blanked=comments_count,
        docstrings_blanked=docstrings_count,
        parser_used=parser_used,
        syntax_error=syntax_error_msg,
    )


def fallback_strip_line_comments(
    source_code: str,
    file_path: str,
    reason: Optional[str] = None,
) -> Tuple[str, StrippingFileResult]:
    """Line-by-line fallback policy: blanks comments starting with '#' while preserving indentation."""
    lines = source_code.splitlines(keepends=True)
    original_line_count = len(lines)
    comments_count = 0
    rebuilt_lines = []

    for line in lines:
        stripped_line = line.lstrip()
        if stripped_line.startswith("#"):
            comments_count += 1
            # Preserve leading whitespace / indentation, replace comment characters with spaces
            indent_len = len(line) - len(stripped_line)
            newline_suffix = ""
            if line.endswith("\r\n"):
                newline_suffix = "\r\n"
            elif line.endswith("\n"):
                newline_suffix = "\n"

            body_len = len(line) - indent_len - len(newline_suffix)
            rebuilt_lines.append(" " * indent_len + " " * body_len + newline_suffix)
        else:
            rebuilt_lines.append(line)

    rebuilt_source = "".join(rebuilt_lines)
    return rebuilt_source, StrippingFileResult(
        path=file_path,
        original_lines=original_line_count,
        stripped_lines=len(rebuilt_lines),
        comments_blanked=comments_count,
        docstrings_blanked=0,
        parser_used="line_fallback",
        syntax_error=reason,
    )


def strip_file_content(content_bytes: bytes, relative_path: str) -> Tuple[bytes, StrippingFileResult]:
    """Strip comments and docstrings according to file type policy."""
    # Check for binary file
    if b"\x00" in content_bytes:
        line_count = len(content_bytes.split(b"\n"))
        return content_bytes, StrippingFileResult(
            path=relative_path,
            original_lines=line_count,
            stripped_lines=line_count,
            comments_blanked=0,
            docstrings_blanked=0,
            parser_used="unsupported_binary",
            syntax_error="Binary file (contains NUL byte)",
        )

    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        line_count = len(content_bytes.split(b"\n"))
        return content_bytes, StrippingFileResult(
            path=relative_path,
            original_lines=line_count,
            stripped_lines=line_count,
            comments_blanked=0,
            docstrings_blanked=0,
            parser_used="unsupported_binary",
            syntax_error="Non-UTF-8 encoding",
        )

    suffix = Path(relative_path).suffix.lower()
    if suffix in (".py", ".pyi"):
        stripped_text, result = strip_python_source(text, relative_path)
    elif suffix in (".sh", ".bash", ".yaml", ".yml", ".toml", ".ini", ".cfg"):
        stripped_text, result = fallback_strip_line_comments(text, relative_path)
    else:
        # Unsupported or other plain text: preserve as-is with fallback documentation
        line_count = len(text.splitlines(keepends=True))
        return content_bytes, StrippingFileResult(
            path=relative_path,
            original_lines=line_count,
            stripped_lines=line_count,
            comments_blanked=0,
            docstrings_blanked=0,
            parser_used="unsupported_plain_text",
        )

    return stripped_text.encode("utf-8"), result
