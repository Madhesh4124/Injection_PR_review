"""Comprehensive unit tests for workspace materialization and dual source views."""

import ast
import os
from pathlib import Path
import pytest

from src.materialization import (
    PathSafetyError,
    SecurityContainmentError,
    compute_workspace_hash,
    materialize_workspaces,
    strip_python_source,
)


def _setup_base_fixture(tmp_path: Path) -> Path:
    """Set up a representative base repository with code, docs, and metadata."""
    base_dir = tmp_path / "base_repo"
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Main python file with docstrings, comments, and strings
    auth_code = '''"""Module docstring explaining auth system."""

# Import statements
import os

def login(username, password):
    """Verify user credentials.

    Returns boolean success flag.
    """
    # Check admin hardcoded
    sql_query = "SELECT * FROM users WHERE user = '" + username + "' # not a comment"
    return False

class Session:
    """Session manager class."""
    def __init__(self):
        # Initial state
        self.active = True
'''
    (base_dir / "auth.py").write_text(auth_code, encoding="utf-8")

    # 2. README file
    (base_dir / "README.md").write_text("# Documentation\n\nSecurity notice.\n", encoding="utf-8")

    # 3. Non-python config
    (base_dir / "config.yaml").write_text("port: 8080 # default port\nhost: localhost\n", encoding="utf-8")

    return base_dir


def test_1_raw_source_remains_unchanged_after_stripping(tmp_path: Path):
    """Criterion 1: Raw source remains unchanged and immutable after stripping."""
    base_dir = _setup_base_fixture(tmp_path)
    staging_dir = tmp_path / "staging"
    patch = """diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -12,1 +12,2 @@ def login(username, password):
     sql_query = "SELECT * FROM users WHERE user = '" + username + "' # not a comment"
+    print("Login attempt")
"""
    pr_desc = "Add debug log to login"

    workspaces = materialize_workspaces(base_dir, patch, pr_desc, staging_dir)
    raw_path = Path(workspaces.raw_path)
    stripped_path = Path(workspaces.stripped_path)
    assert stripped_path.exists()

    # Verify initial raw hash matches current raw hash
    current_raw_hash = compute_workspace_hash(raw_path)
    assert workspaces.raw_hash == current_raw_hash

    # Verify raw file contains the original comments and docstrings intact
    raw_auth = (raw_path / "auth.py").read_text(encoding="utf-8")
    assert "Module docstring explaining auth system." in raw_auth
    assert "# Import statements" in raw_auth
    assert "Verify user credentials." in raw_auth
    assert 'print("Login attempt")' in raw_auth


def test_2_comments_and_docstrings_blanked_without_shifting_lines(tmp_path: Path):
    """Criterion 2: Comments and docstrings are blanked while strictly preserving line numbers."""
    base_dir = _setup_base_fixture(tmp_path)
    staging_dir = tmp_path / "staging"
    patch = ""
    pr_desc = "Clean review"

    workspaces = materialize_workspaces(base_dir, patch, pr_desc, staging_dir)
    raw_auth = (Path(workspaces.raw_path) / "auth.py").read_text(encoding="utf-8")
    stripped_auth = (Path(workspaces.stripped_path) / "auth.py").read_text(encoding="utf-8")

    raw_lines = raw_auth.splitlines()
    stripped_lines = stripped_auth.splitlines()

    # Exact line-count equality
    assert len(raw_lines) == len(stripped_lines)

    # Prose must be absent from stripped view
    assert "Module docstring explaining auth system." not in stripped_auth
    assert "# Import statements" not in stripped_auth
    assert "Verify user credentials." not in stripped_auth
    assert "# Check admin hardcoded" not in stripped_auth
    assert "Session manager class." not in stripped_auth

    # Code identifiers and keywords must align at exact line numbers
    for idx, (r_line, s_line) in enumerate(zip(raw_lines, stripped_lines, strict=True), start=1):
        if "def login" in r_line:
            assert "def login" in s_line, f"Line {idx} mismatch: expected def login"
        if "class Session" in r_line:
            assert "class Session" in s_line, f"Line {idx} mismatch: expected class Session"
        if "sql_query =" in r_line:
            assert "sql_query =" in s_line, f"Line {idx} mismatch: expected sql_query"

    # Stripped code must be syntactically valid executable Python
    parsed = ast.parse(stripped_auth)
    assert isinstance(parsed, ast.Module)


def test_3_readme_and_pr_description_absent_from_stripped_view(tmp_path: Path):
    """Criterion 3: README files and PR description are absent from the stripped view."""
    base_dir = _setup_base_fixture(tmp_path)
    (base_dir / "README.rst").write_text("Additional readme.", encoding="utf-8")
    (base_dir / "readme.txt").write_text("Text readme.", encoding="utf-8")

    staging_dir = tmp_path / "staging"
    patch = ""
    pr_desc = "Secret PR description"

    workspaces = materialize_workspaces(base_dir, patch, pr_desc, staging_dir)
    stripped_path = Path(workspaces.stripped_path)

    # README files must be absent
    assert not (stripped_path / "README.md").exists()
    assert not (stripped_path / "README.rst").exists()
    assert not (stripped_path / "readme.txt").exists()
    assert len(workspaces.readmes_removed) >= 3

    # PR description must not be staged anywhere in stripped view
    for root, _, files in os.walk(stripped_path):
        for f in files:
            content = (Path(root) / f).read_bytes()
            assert pr_desc.encode("utf-8") not in content


def test_4_strings_containing_comment_like_syntax_preserved():
    """Criterion 4: Strings containing comment-like syntax are preserved intact."""
    source = '''def query():
    sql = "SELECT * FROM users WHERE name = '# not_a_comment'"
    c_style = "/* also not a comment */"
    multiline_assignment = """First line
# second line inside assigned string
Third line"""
    return sql
'''
    stripped, result = strip_python_source(source, "query.py")
    assert result.original_lines == result.stripped_lines

    # Comment-like syntax inside string assignments must remain
    assert "# not_a_comment" in stripped
    assert "/* also not a comment */" in stripped
    assert "# second line inside assigned string" in stripped


def test_5_unicode_source_handled_safely():
    """Criterion 5: Unicode source (characters, comments, emoji, bidi) handled safely."""
    unicode_source = '''# 这是一个中文注释 with emoji 🚀
def greet(name: str):
    """打印问候语."""
    # تعليق عربي
    msg = f"你好, {name}!"
    return msg
'''
    stripped, result = strip_python_source(unicode_source, "unicode_test.py")
    assert result.original_lines == result.stripped_lines

    # Comments and docstrings blanked
    assert "这是一个中文注释" not in stripped
    assert "打印问候语" not in stripped
    assert "تعليق عربي" not in stripped

    # Executable code and Unicode string literal preserved
    assert 'msg = f"你好, {name}!"' in stripped

    # Valid syntax check
    ast.parse(stripped)


def test_6_malformed_and_unsupported_files_handled_by_policy(tmp_path: Path):
    """Criterion 6: Malformed syntax and binary files follow documented fallback policy."""
    base_dir = tmp_path / "base_malformed"
    base_dir.mkdir()

    # 1. Broken Python syntax
    broken_py = "# Broken file header\ndef bad_syntax(\n    return 1 # inline comment\n"
    (base_dir / "broken.py").write_text(broken_py, encoding="utf-8")

    # 2. Binary file (contains NUL byte)
    (base_dir / "binary.dat").write_bytes(b"\x00\x01\x02\x03\x04")

    staging_dir = tmp_path / "staging_malformed"
    workspaces = materialize_workspaces(base_dir, "", "PR", staging_dir)

    stripped_path = Path(workspaces.stripped_path)

    # Broken python should use line fallback, preserving line count
    stripped_broken = (stripped_path / "broken.py").read_text(encoding="utf-8")
    assert len(broken_py.splitlines()) == len(stripped_broken.splitlines())
    assert "# Broken file header" not in stripped_broken

    # Binary file preserved and recorded in unsupported_files
    assert (stripped_path / "binary.dat").read_bytes() == b"\x00\x01\x02\x03\x04"
    assert "binary.dat" in workspaces.unsupported_files


def test_7_symlink_and_traversal_attacks_rejected(tmp_path: Path):
    """Criterion 7: Symlink escapes and patch traversal attacks are strictly rejected."""
    outside_file = tmp_path / "host_sensitive.txt"
    outside_file.write_text("top secret host file", encoding="utf-8")

    base_dir = tmp_path / "base_escape"
    base_dir.mkdir()
    (base_dir / "main.py").write_text("print('safe')", encoding="utf-8")

    # 1. Symlink escape in base repo
    escape_link = base_dir / "escape_link.py"
    try:
        os.symlink(outside_file, escape_link)
        has_symlink = True
    except (OSError, NotImplementedError):
        has_symlink = False

    if has_symlink:
        staging_dir = tmp_path / "staging_escape"
        with pytest.raises(SecurityContainmentError, match="escapes base source directory"):
            materialize_workspaces(base_dir, "", "PR", staging_dir)
        escape_link.unlink()

    # 2. Traversal attack in patch header
    staging_dir2 = tmp_path / "staging_patch_escape"
    traversal_patch = """diff --git a/../../etc/shadow b/../../etc/shadow
--- a/../../etc/shadow
+++ b/../../etc/shadow
@@ -1,1 +1,2 @@
+root:x:0:0
"""
    with pytest.raises(PathSafetyError, match="references unsafe path"):
        materialize_workspaces(base_dir, traversal_patch, "PR", staging_dir2)
