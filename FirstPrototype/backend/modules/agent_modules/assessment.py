from typing import Any, Dict, Mapping


def decide_evidence_route(agent: Any, state: Mapping[str, Any]) -> str:
    iocs = state.get("iocs_extracted") or []
    if not iocs:
        print("Evidence assessment: no_iocs (no extracted IOCs to enrich)")
        return "no_iocs"

    current_round = agent._coerce_int(state.get("tool_execution_round"), 0)
    max_rounds = agent._coerce_int(
        state.get("max_tool_execution_rounds"), agent.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS
    )
    if current_round >= max_rounds:
        print(
            "Evidence assessment: sufficient_evidence "
            f"(tool round limit reached: {current_round}/{max_rounds})"
        )
        return "sufficient_evidence"

    if current_round > 0 and not agent._has_successful_normalized_evidence(state):
        print(
            "Evidence assessment: no_usable_evidence "
            "(no successful non-skipped enrichment evidence)"
        )
        return "no_usable_evidence"

    follow_up_calls = agent._select_follow_up_tool_calls(state)
    if follow_up_calls:
        print(
            "Evidence assessment: needs_more_evidence "
            f"({len(follow_up_calls)} unqueried enrichment tools available)"
        )
        return "needs_more_evidence"

    print("Evidence assessment: sufficient_evidence (no follow-up tools needed)")
    return "sufficient_evidence"


def assess_evidence(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    decision = decide_evidence_route(agent, state)
    follow_up_count = 0
    if decision == "needs_more_evidence":
        follow_up_count = len(agent._select_follow_up_tool_calls(state))

    assessment = {
        "decision": decision,
        "tool_execution_round": agent._coerce_int(state.get("tool_execution_round"), 0),
        "successful_evidence": agent._has_successful_normalized_evidence(state),
        "follow_up_candidates": follow_up_count,
    }
    return {
        "evidence_route": decision,
        "evidence_assessment": assessment,
        "current_stage": "evidence_assessment_complete",
        "reasoning_steps": [f"Evidence assessment routed investigation to {decision}"],
        "agent_trace": [
            agent._agent_trace_event(
                "assessor",
                "completed",
                f"Evidence assessment decision: {decision}",
            )
        ],
    }


def route_after_assessment(state: Mapping[str, Any]) -> str:
    route = str(state.get("evidence_route") or "sufficient_evidence")
    print(f"Evidence routing: {route}")
    return route
