"""Segregated blocked-access telemetry collection and classification."""

import re
from typing import List

from src.schemas.report import BlockedAccess, BlockedAccessBehavioral, BlockedAccessToolUnit

# Regex patterns to sanitize host paths and credentials from blocked-access details
HOST_PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\[\w\s\-\\]+"),
    re.compile(r"/home/[\w\-]+"),
    re.compile(r"/Users/[\w\-]+"),
]


def sanitize_blocked_details(details: str) -> str:
    """Sanitize technical details to prevent host paths, credentials, or secrets leaking into logs."""
    sanitized = details
    for pat in HOST_PATH_PATTERNS:
        sanitized = pat.sub("<HOST_PATH>", sanitized)
    return sanitized.strip()


class BlockedAccessCollector:
    """Collects and segregates blocked-access events into tool_unit and behavioral categories.

    Distinguishes blocked attempts (security boundary held) from successful breaches and
    infrastructure errors.
    """

    def __init__(self) -> None:
        self.tool_unit_events: List[BlockedAccessToolUnit] = []
        self.behavioral_events: List[BlockedAccessBehavioral] = []

    def record_tool_unit_blocked(
        self,
        attempt: str,
        blocked_by: str,
        details: str,
    ) -> BlockedAccessToolUnit:
        """Record an unauthorized tool invocation blocked by deterministic security boundary."""
        unit = BlockedAccessToolUnit(
            attempt=attempt.strip(),
            blocked_by=blocked_by.strip(),
            details=sanitize_blocked_details(details),
        )
        self.tool_unit_events.append(unit)
        return unit

    def record_behavioral_blocked(
        self,
        attempt: str,
        trigger: str,
        blocked: bool,
        details: str,
    ) -> BlockedAccessBehavioral:
        """Record an injection-induced agent behavioral operation attempt."""
        beh = BlockedAccessBehavioral(
            attempt=attempt.strip(),
            trigger=trigger.strip(),
            blocked=blocked,
            details=sanitize_blocked_details(details),
        )
        self.behavioral_events.append(beh)
        return beh

    def build_blocked_access(self) -> BlockedAccess:
        """Build the immutable BlockedAccess telemetry container."""
        return BlockedAccess(
            tool_unit=list(self.tool_unit_events),
            behavioral=list(self.behavioral_events),
        )
