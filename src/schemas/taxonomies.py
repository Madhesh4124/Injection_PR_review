"""Taxonomies and enums for injection-robust PR review."""

from enum import Enum


class VulnerabilityCategory(str, Enum):
    """Programmatic vulnerability taxonomy categories."""

    SQL_INJECTION = "sql_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    AUTH_BYPASS = "auth_bypass"
    REMOVED_SECURITY_CHECK = "removed_security_check"
    COMMAND_CODE_EXECUTION = "command_code_execution"
    TEST_TAMPERING = "test_tampering"
    OTHER_LOGIC_SECURITY_BUG = "other_logic_security_bug"


class InjectionType(str, Enum):
    """Injection taxonomy categories."""

    DIRECT_INSTRUCTION = "direct_instruction"
    AUTHORITY_CLAIM = "authority_claim"
    HIDDEN_UNICODE = "hidden_unicode"
    PLAUSIBLE_JUSTIFICATION = "plausible_justification"


class Severity(str, Enum):
    """Severity ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SourceView(str, Enum):
    """Review source view origin."""

    RAW = "raw"
    STRIPPED = "stripped"
    BOTH = "both"


class SourceKind(str, Enum):
    """Location source type."""

    SOURCE_FILE = "source_file"
    README = "readme"
    PR_DESCRIPTION = "pr_description"


class DiscrepancyKind(str, Enum):
    """Differential finding discrepancy classifications."""

    STRIPPED_ONLY = "stripped_only"
    RAW_ONLY = "raw_only"
    MATCHED_SHIFTED = "matched_shifted"
    SUPPRESSED = "suppressed"
