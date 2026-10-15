"""Static versioned equivalence table for category aliases.

Independent of ground-truth manifests; used for corroboration and scoring fallback.
"""

from typing import Dict, FrozenSet, Set

EQUIVALENCE_TABLE_VERSION = "1.0.0"

# Static mapping of categories to equivalent aliases
_EQUIVALENCE_GROUPS: Dict[str, FrozenSet[str]] = {
    "sql_injection": frozenset({
        "sql_injection",
        "sql_injection_legacy",
        "sqli",
        "cwe-89",
    }),
    "hardcoded_secret": frozenset({
        "hardcoded_secret",
        "hardcoded_credential",
        "exposed_token",
        "cwe-798",
    }),
    "auth_bypass": frozenset({
        "auth_bypass",
        "authentication_bypass",
        "broken_authentication",
        "cwe-287",
    }),
    "removed_security_check": frozenset({
        "removed_security_check",
        "missing_authorization_check",
        "disabled_security_control",
        "cwe-862",
    }),
    "command_code_execution": frozenset({
        "command_code_execution",
        "command_injection",
        "remote_code_execution",
        "rce",
        "cwe-78",
        "cwe-94",
    }),
    "test_tampering": frozenset({
        "test_tampering",
        "disabled_test_assertion",
        "suppressed_security_test",
    }),
    "other_logic_security_bug": frozenset({
        "other_logic_security_bug",
        "business_logic_flaw",
        "insecure_design",
    }),
}


def are_categories_equivalent(cat_a: str, cat_b: str) -> bool:
    """Return True if cat_a and cat_b belong to the same static equivalence group."""
    norm_a = cat_a.strip().lower()
    norm_b = cat_b.strip().lower()

    if norm_a == norm_b:
        return True

    for group in _EQUIVALENCE_GROUPS.values():
        if norm_a in group and norm_b in group:
            return True

    return False


def get_equivalent_aliases(category: str) -> Set[str]:
    """Return all known equivalent alias strings for a category."""
    norm = category.strip().lower()
    for group in _EQUIVALENCE_GROUPS.values():
        if norm in group:
            return set(group)
    return {norm}
