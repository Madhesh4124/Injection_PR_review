"""Materialization and path containment safety utilities."""

from src.materialization.patch_safety import (
    MalformedPatchError,
    PatchSafetySummary,
    inspect_and_validate_patch,
)
from src.materialization.patcher import (
    PatchApplicationError,
    apply_patch_to_workspace,
)
from src.materialization.path_safety import (
    MAX_ARCHIVE_BYTES,
    MAX_BYTES_PER_FILE,
    MAX_CHANGED_BYTES_PER_PR,
    MAX_CHANGED_LINES_PER_PR,
    MAX_FILES_PER_FIXTURE,
    MAX_LINES_PER_FILE,
    MAX_TOOL_READ_BYTES,
    ContextLimitExceededError,
    PathSafetyError,
    SecurityContainmentError,
    normalize_relative_path,
    validate_file_content_limits,
    verify_archive_members_containment,
    verify_path_containment,
)
from src.materialization.stripper import (
    StrippingFileResult,
    strip_file_content,
    strip_python_source,
)
from src.materialization.unicode_sanitizer import (
    UnicodeAnnotation,
    UnicodeAnomalyAction,
    UnicodeAnomalyCategory,
    UnicodeSanitizationPolicy,
    UnicodeSanitizationResult,
    detect_unicode_anomalies,
    is_dangerous_unicode_char,
    sanitize_file_unicode,
    sanitize_unicode_text,
)
from src.materialization.workspace import (
    WorkspacePair,
    compute_workspace_hash,
    materialize_fixture_workspaces,
    materialize_workspaces,
)

__all__ = [
    "MAX_ARCHIVE_BYTES",
    "MAX_BYTES_PER_FILE",
    "MAX_CHANGED_BYTES_PER_PR",
    "MAX_CHANGED_LINES_PER_PR",
    "MAX_FILES_PER_FIXTURE",
    "MAX_LINES_PER_FILE",
    "MAX_TOOL_READ_BYTES",
    "ContextLimitExceededError",
    "MalformedPatchError",
    "PatchApplicationError",
    "PatchSafetySummary",
    "PathSafetyError",
    "SecurityContainmentError",
    "StrippingFileResult",
    "UnicodeAnnotation",
    "UnicodeAnomalyAction",
    "UnicodeAnomalyCategory",
    "UnicodeSanitizationPolicy",
    "UnicodeSanitizationResult",
    "WorkspacePair",
    "apply_patch_to_workspace",
    "compute_workspace_hash",
    "detect_unicode_anomalies",
    "inspect_and_validate_patch",
    "is_dangerous_unicode_char",
    "materialize_fixture_workspaces",
    "materialize_workspaces",
    "normalize_relative_path",
    "sanitize_file_unicode",
    "sanitize_unicode_text",
    "strip_file_content",
    "strip_python_source",
    "validate_file_content_limits",
    "verify_archive_members_containment",
    "verify_path_containment",
]
