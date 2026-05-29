"""State definitions and factories for the DFIR agent graph."""

from typing import Annotated, Any, Dict, List, TypedDict
import operator

import pandas as pd


class InvestigationState(TypedDict):
    """State for investigation graph."""

    # Input
    anomalies: List[Dict[str, Any]]
    parsed_logs: pd.DataFrame

    # Episodic Memory
    iocs_extracted: List[Dict[str, Any]]
    tool_calls: Annotated[List[Dict[str, Any]], operator.add]
    tool_results: Annotated[List[Dict[str, Any]], operator.add]
    reasoning_steps: Annotated[List[str], operator.add]
    planning_steps: Annotated[List[str], operator.add]
    planned_tool_calls: Annotated[List[Dict[str, Any]], operator.add]
    planning_completed: bool
    planning_round: int
    max_planning_rounds: int
    reflection_steps: Annotated[List[str], operator.add]
    post_correlation_follow_up_calls: Annotated[List[Dict[str, Any]], operator.add]
    observation_assessment: str
    reflection_round: int
    max_reflection_rounds: int
    correlation_analysis: str
    normalized_evidence: Annotated[List[Dict[str, Any]], operator.add]
    aggregated_ioc_evidence: Dict[str, Dict[str, Any]]
    tool_selection_trace: Annotated[List[Dict[str, Any]], operator.add]
    tool_validation_trace: Annotated[List[Dict[str, Any]], operator.add]
    agent_trace: Annotated[List[Dict[str, Any]], operator.add]
    investigation_status: str
    investigation_confidence: float
    confidence_factors: List[str]
    supporting_evidence: List[Dict[str, Any]]
    inconclusive_reason: str

    # Output
    investigation_summary: str
    attack_timeline: List[Dict[str, Any]]
    recommendations: List[str]

    # Control
    current_stage: str
    completed: bool
    tool_execution_round: int
    max_tool_execution_rounds: int


def build_initial_state(
    anomalies: List[Dict[str, Any]],
    parsed_logs_df: pd.DataFrame,
    *,
    max_reflection_rounds: int,
    max_tool_execution_rounds: int,
) -> InvestigationState:
    """Build the initial LangGraph state for an investigation run."""
    return {
        "anomalies": anomalies,
        "parsed_logs": parsed_logs_df,
        "iocs_extracted": [],
        "tool_calls": [],
        "tool_results": [],
        "reasoning_steps": [],
        "planning_steps": [],
        "planned_tool_calls": [],
        "planning_completed": False,
        "planning_round": 0,
        "max_planning_rounds": 1,
        "reflection_steps": [],
        "post_correlation_follow_up_calls": [],
        "observation_assessment": "",
        "reflection_round": 0,
        "max_reflection_rounds": max_reflection_rounds,
        "correlation_analysis": "",
        "normalized_evidence": [],
        "aggregated_ioc_evidence": {},
        "tool_selection_trace": [],
        "tool_validation_trace": [],
        "agent_trace": [],
        "investigation_status": "pending",
        "investigation_confidence": 0.0,
        "confidence_factors": [],
        "supporting_evidence": [],
        "inconclusive_reason": "",
        "investigation_summary": "",
        "attack_timeline": [],
        "recommendations": [],
        "current_stage": "init",
        "completed": False,
        "tool_execution_round": 0,
        "max_tool_execution_rounds": max_tool_execution_rounds,
    }
