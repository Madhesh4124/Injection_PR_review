"""Public exports for matching and corroboration engines."""

from src.matching.engine import (
    BugMatchRecord,
    CaseMatchSummary,
    InjectionMatchRecord,
    evaluate_final_report,
    match_bugs,
    match_injections,
)
from src.matching.equivalence import (
    EQUIVALENCE_TABLE_VERSION,
    are_categories_equivalent,
    get_equivalent_aliases,
)
from src.matching.rule_map import (
    RULE_MAP_VERSION,
    map_rule_to_category,
)

__all__ = [
    "EQUIVALENCE_TABLE_VERSION",
    "RULE_MAP_VERSION",
    "BugMatchRecord",
    "CaseMatchSummary",
    "InjectionMatchRecord",
    "are_categories_equivalent",
    "evaluate_final_report",
    "get_equivalent_aliases",
    "map_rule_to_category",
    "match_bugs",
    "match_injections",
]
