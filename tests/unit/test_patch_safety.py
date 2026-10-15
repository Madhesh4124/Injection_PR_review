"""Unit tests for patch parsing, traversal rejection, and change limits."""

from pathlib import Path
import pytest

from src.materialization.patch_safety import (
    MalformedPatchError,
    inspect_and_validate_patch,
)
from src.materialization.path_safety import (
    ContextLimitExceededError,
    PathSafetyError,
)

SAMPLE_SAFE_PATCH = """diff --git a/src/app.py b/src/app.py
index 1234567..89abcdef 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
 def main():
-    print("old")
+    print("new")
+    return True
"""


def test_inspect_and_validate_patch_positive(tmp_path: Path):
    """Verify safe unified diff parsing and counting."""
    summary = inspect_and_validate_patch(SAMPLE_SAFE_PATCH, tmp_path)
    assert summary.additions == 2
    assert summary.deletions == 1
    assert summary.total_changed_lines == 3
    assert "src/app.py" in summary.modified_files


def test_reject_patch_modifying_outside_workspace(tmp_path: Path):
    """Reject patch referencing parent directory traversal in file header."""
    malicious_patch = """diff --git a/../../etc/passwd b/../../etc/passwd
--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1,1 +1,2 @@
+root::0:0:root:/root:/bin/bash
"""
    with pytest.raises(PathSafetyError, match="references unsafe path"):
        inspect_and_validate_patch(malicious_patch, tmp_path)


def test_reject_patch_exceeding_line_limit(tmp_path: Path):
    """Reject patch that exceeds 2,500 total changed lines."""
    added_lines = "".join(f"+line_{i} = {i}\n" for i in range(2501))
    huge_patch = f"""diff --git a/src/big.py b/src/big.py
--- a/src/big.py
+++ b/src/big.py
@@ -1,1 +1,2502 @@
{added_lines}"""
    with pytest.raises(ContextLimitExceededError, match="exceeds PR limit"):
        inspect_and_validate_patch(huge_patch, tmp_path)


def test_reject_patch_exceeding_byte_limit(tmp_path: Path):
    """Reject patch that exceeds 125 KB total byte size."""
    # Create patch with repeated safe content exceeding 125 KB
    padding = " " * (130 * 1024)
    huge_byte_patch = f"""diff --git a/src/big.py b/src/big.py
--- a/src/big.py
+++ b/src/big.py
@@ -1,1 +1,2 @@
+# {padding}
"""
    with pytest.raises(ContextLimitExceededError, match="Patch byte size"):
        inspect_and_validate_patch(huge_byte_patch, tmp_path)


def test_reject_malformed_patch_syntax(tmp_path: Path):
    """Reject malformed hunk headers or corrupted diff git lines."""
    corrupted_patch = """diff --git a/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ invalid hunk header @@
+test
"""
    with pytest.raises(MalformedPatchError):
        inspect_and_validate_patch(corrupted_patch, tmp_path)
