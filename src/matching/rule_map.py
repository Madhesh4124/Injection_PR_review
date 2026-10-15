"""Versioned static mapping of scanner rule IDs to vulnerability categories.

Provides mechanical corroboration without LLM inference.
"""

from typing import Dict, Optional

from src.schemas.taxonomies import VulnerabilityCategory

RULE_MAP_VERSION = "1.0.0"

_STATIC_RULE_MAP: Dict[str, VulnerabilityCategory] = {
    # Bandit rule IDs
    "bandit.B608": VulnerabilityCategory.SQL_INJECTION,
    "bandit.B105": VulnerabilityCategory.HARDCODED_SECRET,
    "bandit.B106": VulnerabilityCategory.HARDCODED_SECRET,
    "bandit.B107": VulnerabilityCategory.HARDCODED_SECRET,
    "bandit.B602": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B603": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B604": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B605": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B607": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B102": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B301": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B302": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "bandit.B501": VulnerabilityCategory.AUTH_BYPASS,
    "bandit.B502": VulnerabilityCategory.AUTH_BYPASS,
    "bandit.B503": VulnerabilityCategory.AUTH_BYPASS,

    # Semgrep rule IDs
    "python.sqlalchemy.raw-query": VulnerabilityCategory.SQL_INJECTION,
    "python.lang.security.audit.sqli": VulnerabilityCategory.SQL_INJECTION,
    "python.django.security.injection.sql": VulnerabilityCategory.SQL_INJECTION,
    "python.lang.security.subprocess-shell-true": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "python.lang.security.audit.dangerous-system-call": VulnerabilityCategory.COMMAND_CODE_EXECUTION,
    "generic.secrets.security.detected-jwt-token": VulnerabilityCategory.HARDCODED_SECRET,
    "generic.secrets.security.detected-private-key": VulnerabilityCategory.HARDCODED_SECRET,
    "python.jwt.hardcoded-secret": VulnerabilityCategory.HARDCODED_SECRET,
    "python.flask.security.unprotected-endpoint": VulnerabilityCategory.AUTH_BYPASS,
    "python.security.auth.missing-permission": VulnerabilityCategory.REMOVED_SECURITY_CHECK,
    "python.testing.disabled-assertion": VulnerabilityCategory.TEST_TAMPERING,
}


def map_rule_to_category(rule_id: str) -> Optional[VulnerabilityCategory]:
    """Map a tool rule identifier to a standard VulnerabilityCategory."""
    rule_clean = rule_id.strip()
    if rule_clean in _STATIC_RULE_MAP:
        return _STATIC_RULE_MAP[rule_clean]

    # Prefix fallback (e.g. B608 -> bandit.B608)
    if f"bandit.{rule_clean}" in _STATIC_RULE_MAP:
        return _STATIC_RULE_MAP[f"bandit.{rule_clean}"]

    return None
