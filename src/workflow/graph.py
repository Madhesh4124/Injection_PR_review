"""Sequential LangGraph pipeline construction and compilation."""

from functools import partial
from langgraph.graph import StateGraph, START, END

from src.detection.provider import LLMProvider
from src.workflow.adapters import (
    node_1_materialize_adapter,
    node_2_scanners_adapter,
    node_3_paired_review_adapter,
    node_4_injection_detect_adapter,
    node_5_report_adapter,
)
from src.workflow.state import ReviewGraphState


def route_after_materialization(state: ReviewGraphState) -> str:
    """Conditional edge routing: bypass downstream review nodes if materialization failed."""
    if not state.get("materialization_success", False):
        return "node_5_report"
    return "node_2_scanners"


def build_review_graph(provider: LLMProvider):
    """Build and compile the authoritative sequential PR review StateGraph.

    Topology:
        START -> node_1_materialize
        node_1_materialize -> [conditional: success?]
            If False: -> node_5_report -> END (0 LLM calls)
            If True:  -> node_2_scanners -> node_3_paired_review -> node_4_injection_detect -> node_5_report -> END
    """
    builder = StateGraph(ReviewGraphState)

    # 1. Register Nodes
    builder.add_node("node_1_materialize", node_1_materialize_adapter)
    builder.add_node("node_2_scanners", node_2_scanners_adapter)
    builder.add_node(
        "node_3_paired_review",
        partial(node_3_paired_review_adapter, provider=provider),
    )
    builder.add_node(
        "node_4_injection_detect",
        partial(node_4_injection_detect_adapter, provider=provider),
    )
    builder.add_node("node_5_report", node_5_report_adapter)

    # 2. START -> Node 1
    builder.add_edge(START, "node_1_materialize")

    # 3. Conditional Edge after Materialization
    builder.add_conditional_edges(
        "node_1_materialize",
        route_after_materialization,
        {
            "node_5_report": "node_5_report",
            "node_2_scanners": "node_2_scanners",
        },
    )

    # 4. Sequential Flow: 2 -> 3 -> 4 -> 5
    builder.add_edge("node_2_scanners", "node_3_paired_review")
    builder.add_edge("node_3_paired_review", "node_4_injection_detect")
    builder.add_edge("node_4_injection_detect", "node_5_report")

    # 5. Node 5 -> END
    builder.add_edge("node_5_report", END)

    return builder.compile()
