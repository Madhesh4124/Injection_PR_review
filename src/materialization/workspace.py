"""Workspace materialization providing deterministic Raw and Stripped views."""

import hashlib
import os
import re
import shutil
import stat
from pathlib import Path
from typing import List, Tuple
from pydantic import BaseModel, ConfigDict, Field

from src.materialization.patcher import apply_patch_to_workspace
from src.materialization.path_safety import (
    MAX_FILES_PER_FIXTURE,
    ContextLimitExceededError,
    SecurityContainmentError,
    validate_file_content_limits,
)
from src.materialization.stripper import StrippingFileResult, strip_file_content
from src.materialization.unicode_sanitizer import (
    UnicodeAnnotation,
    detect_unicode_anomalies,
    sanitize_file_unicode,
)

README_PATTERN = re.compile(r"^README(\.[a-zA-Z0-9]+)?$", re.IGNORECASE)
GIT_METADATA_NAMES = {".git", ".gitignore", ".gitattributes", ".gitmodules"}


class WorkspacePair(BaseModel):
    """Pair of materialized workspaces for raw and stripped evaluation views."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    raw_path: str = Field(description="Filesystem path to raw workspace.")
    stripped_path: str = Field(description="Filesystem path to stripped workspace.")
    raw_hash: str = Field(description="Deterministic SHA-256 hash of raw workspace.")
    stripped_hash: str = Field(description="Deterministic SHA-256 hash of stripped workspace.")
    readmes_removed: List[str] = Field(default_factory=list)
    stripped_files: List[str] = Field(default_factory=list)
    unsupported_files: List[str] = Field(default_factory=list)
    syntax_errors: List[str] = Field(default_factory=list)
    pr_description_excluded: bool = Field(default=True)
    file_results: List[StrippingFileResult] = Field(default_factory=list)
    unicode_annotations: List[UnicodeAnnotation] = Field(default_factory=list)
    unicode_anomalies_count: int = Field(default=0)


def compute_workspace_hash(workspace_root: Path) -> str:
    """Compute a deterministic SHA-256 digest of all files in workspace in sorted path order."""
    root_resolved = workspace_root.resolve()
    hasher = hashlib.sha256()

    all_files: List[Tuple[str, Path]] = []
    for dirpath, _, filenames in os.walk(root_resolved):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            # Verify symlink containment
            if fpath.is_symlink():
                target = fpath.resolve()
                try:
                    target.relative_to(root_resolved)
                except ValueError as err:
                    raise SecurityContainmentError(
                        f"Symlink escapes workspace during hashing: {fpath} -> {target}"
                    ) from err
            rel_path = fpath.relative_to(root_resolved).as_posix()
            all_files.append((rel_path, fpath))

    # Sort files deterministically by relative path
    all_files.sort(key=lambda x: x[0])

    for rel_path, fpath in all_files:
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b"\x00")
        content = fpath.read_bytes()
        hasher.update(hashlib.sha256(content).digest())
        hasher.update(b"\x00")

    return hasher.hexdigest()


def _copy_clean_tree(src_dir: Path, dest_dir: Path) -> int:
    """Copy files from src_dir to dest_dir, omitting .git metadata and host-specific files."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    file_count = 0

    for dirpath, dirnames, filenames in os.walk(src_dir):
        # Exclude .git directories in-place from traversal
        dirnames[:] = [d for d in dirnames if d not in GIT_METADATA_NAMES]

        rel_dir = Path(dirpath).relative_to(src_dir)
        target_dir = dest_dir / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        for fname in filenames:
            if fname in GIT_METADATA_NAMES:
                continue

            src_file = Path(dirpath) / fname
            # Check symlink safety before copying
            if src_file.is_symlink():
                resolved = src_file.resolve()
                try:
                    resolved.relative_to(src_dir.resolve())
                except ValueError as err:
                    raise SecurityContainmentError(
                        f"Symlink escapes base source directory: {src_file} -> {resolved}"
                    ) from err

            dest_file = target_dir / fname
            shutil.copy2(src_file, dest_file)
            file_count += 1

            if file_count > MAX_FILES_PER_FIXTURE:
                raise ContextLimitExceededError(
                    f"Fixture exceeds file count limit ({file_count} > {MAX_FILES_PER_FIXTURE})"
                )

    return file_count


def _enforce_immutability(workspace_root: Path) -> None:
    """Set read-only permissions on files to protect raw workspace against accidental mutations."""
    for dirpath, _, filenames in os.walk(workspace_root):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                # Add read-only, remove write
                mode = fpath.stat().st_mode
                fpath.chmod(mode & ~stat.S_IWRITE)
            except OSError:
                pass


def materialize_workspaces(
    base_source_dir: Path,
    patch_content: str,
    pr_description: str,
    staging_dir: Path,
) -> WorkspacePair:
    """Materialize immutable Raw View and derived Stripped View workspaces.

    Guarantees:
    - Raw view contains the patched repo without .git metadata.
    - Stripped view blanks comments/docstrings while preserving line numbers.
    - README files are completely removed from stripped view.
    - PR description is excluded from stripped view.
    - Raw workspace remains untouched after stripped view generation.
    - Returns cryptographic SHA-256 hashes for both workspaces.
    """
    raw_dir = staging_dir / "raw"
    stripped_dir = staging_dir / "stripped"

    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    if stripped_dir.exists():
        shutil.rmtree(stripped_dir)

    # 1. Materialize Raw View
    _copy_clean_tree(base_source_dir, raw_dir)
    apply_patch_to_workspace(raw_dir, patch_content)

    # Validate limits across all raw files & collect Unicode annotations
    all_unicode_annotations: List[UnicodeAnnotation] = []
    total_unicode_anomalies: int = 0
    for dirpath, _, filenames in os.walk(raw_dir):
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            content_bytes = fpath.read_bytes()
            rel_p = fpath.relative_to(raw_dir).as_posix()
            validate_file_content_limits(content_bytes, rel_p)
            _, u_res = sanitize_file_unicode(content_bytes, rel_p)
            if u_res.annotations:
                all_unicode_annotations.extend(u_res.annotations)
                total_unicode_anomalies += u_res.anomalies_count

    initial_raw_hash = compute_workspace_hash(raw_dir)

    # 2. Materialize Stripped View by deterministic cloning from Raw View
    _copy_clean_tree(raw_dir, stripped_dir)

    readmes_removed: List[str] = []
    stripped_files: List[str] = []
    unsupported_files: List[str] = []
    syntax_errors: List[str] = []
    file_results: List[StrippingFileResult] = []

    # Process stripped workspace
    for dirpath, _, filenames in list(os.walk(stripped_dir)):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(stripped_dir).as_posix()

            # Rule: Remove README files
            if README_PATTERN.match(fname):
                fpath.unlink()
                readmes_removed.append(rel_path)
                continue

            # Strip comments and docstrings
            original_bytes = fpath.read_bytes()
            stripped_bytes, result = strip_file_content(original_bytes, rel_path)
            file_results.append(result)

            if result.parser_used == "unsupported_binary":
                unsupported_files.append(rel_path)
            elif result.syntax_error:
                syntax_errors.append(f"{rel_path}: {result.syntax_error}")

            # Apply Unicode sanitization to the stripped view to neutralize residual dangerous controls
            sanitized_bytes, _ = sanitize_file_unicode(stripped_bytes, rel_path)

            if sanitized_bytes != original_bytes:
                stripped_files.append(rel_path)
                fpath.write_bytes(sanitized_bytes)

    stripped_hash = compute_workspace_hash(stripped_dir)

    # 3. Assert raw view was NOT silently modified during stripped materialization
    post_raw_hash = compute_workspace_hash(raw_dir)
    if initial_raw_hash != post_raw_hash:
        raise RuntimeError(
            f"Integrity Violation: Raw view was mutated during stripped generation! ({initial_raw_hash} != {post_raw_hash})"
        )

    # Set raw files read-only
    _enforce_immutability(raw_dir)

    return WorkspacePair(
        raw_path=str(raw_dir.resolve()),
        stripped_path=str(stripped_dir.resolve()),
        raw_hash=initial_raw_hash,
        stripped_hash=stripped_hash,
        readmes_removed=readmes_removed,
        stripped_files=stripped_files,
        unsupported_files=unsupported_files,
        syntax_errors=syntax_errors,
        pr_description_excluded=True,
        file_results=file_results,
        unicode_annotations=all_unicode_annotations,
        unicode_anomalies_count=total_unicode_anomalies,
    )


def materialize_fixture_workspaces(
    fixture,
    staging_dir: Path,
    base_source_dir: Path,
) -> WorkspacePair:
    """Materialize raw and stripped workspaces for a fixture from a base source directory."""
    return materialize_workspaces(
        base_source_dir=base_source_dir,
        patch_content=fixture.patch_content,
        pr_description=fixture.pr_description,
        staging_dir=staging_dir,
    )


