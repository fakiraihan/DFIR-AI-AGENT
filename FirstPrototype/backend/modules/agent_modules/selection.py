"""Planning and tool-selection node helpers for the DFIR agent."""

from typing import Any, Dict, Mapping
import time
import traceback


def _emit_terminal(agent: Any, line: str, *, progress: int | None = None, level: str = "info") -> None:
    emit = getattr(agent, "_emit_terminal", None)
    if callable(emit):
        emit(line, progress=progress, level=level)


def plan_goals(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Decompose extracted IOCs into an explicit, bounded investigation plan."""
    if agent.status_callback and agent.session_id:
        agent.status_callback(
            agent.session_id,
            "ai_agent",
            "AI sedang menyusun rencana investigasi IOC...",
            65,
        )

    print("\n=== STAGE 2: INVESTIGATION PLANNING ===")
    _emit_terminal(
        agent,
        "=" * 60 + "\nSTAGE 2: INVESTIGATION PLANNING\n" + "=" * 60,
        progress=65,
        level="stage",
    )

    iocs = state.get("iocs_extracted") or []
    planning_round = agent._coerce_int(state.get("planning_round"), 0) + 1
    max_rounds = agent._coerce_int(state.get("max_planning_rounds"), 1)

    if not iocs:
        print("No IOCs available for planning")
        _emit_terminal(agent, "No IOCs available for planning", progress=65, level="warning")
        return {
            "planned_tool_calls": [],
            "planning_steps": [
                "Planner found no extracted IOCs, so enrichment planning was skipped"
            ],
            "planning_completed": True,
            "planning_round": planning_round,
            "current_stage": "planning_complete",
        }

    if planning_round > max_rounds:
        print(
            "Planning round limit reached "
            f"({planning_round - 1}/{max_rounds}); deferring to tool selector"
        )
        _emit_terminal(
            agent,
            f"Planning round limit reached ({planning_round - 1}/{max_rounds}); deferring to tool selector",
            progress=65,
            level="warning",
        )
        return {
            "planned_tool_calls": [],
            "planning_steps": [
                "Planner deferred to tool selector because the planning round limit was reached"
            ],
            "planning_completed": False,
            "planning_round": planning_round,
            "current_stage": "planning_deferred",
        }

    memory_tool_calls, memory_reasons = agent._select_tools_from_memory(iocs)
    plan_source = "procedural memory"
    candidate_calls = memory_tool_calls
    planning_steps = list(memory_reasons[:5])

    if not candidate_calls:
        candidate_calls = agent._fallback_tool_selection(iocs)
        plan_source = "static IOC playbook"
        planning_steps.append(
            "Planner used static IOC playbooks because procedural memory did not provide supported tools"
        )

    planned_calls = agent._dedupe_tool_calls(candidate_calls)
    print(
        f"Planner selected {len(planned_calls)} tool calls from {plan_source} "
        f"for {len(iocs)} IOCs"
    )
    _emit_terminal(
        agent,
        f"Planner selected {len(planned_calls)} tool calls from {plan_source} for {len(iocs)} IOCs",
        progress=66,
        level="success",
    )

    return {
        "planned_tool_calls": planned_calls,
        "planning_steps": [
            f"Planner decomposed {len(iocs)} IOCs into {len(planned_calls)} prioritized enrichment calls using {plan_source}"
        ]
        + planning_steps,
        "planning_completed": True,
        "planning_round": planning_round,
        "current_stage": "planning_complete",
    }


def select_tools(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Select appropriate threat-intel tools for each IOC."""
    if agent.status_callback and agent.session_id:
        agent.status_callback(
            agent.session_id,
            "ai_agent",
            "AI sedang memilih tools untuk analisis...",
            67,
        )

    print("\n=== STAGE 2: TOOL SELECTION ===")
    _emit_terminal(
        agent,
        "=" * 60 + "\nSTAGE 2: TOOL SELECTION\n" + "=" * 60,
        progress=67,
        level="stage",
    )

    iocs = state["iocs_extracted"]

    if not iocs:
        print("No IOCs to investigate")
        _emit_terminal(agent, "No IOCs to investigate", progress=67, level="warning")
        return {
            "tool_calls": [],
            "tool_selection_trace": [],
            "reasoning_steps": ["No IOCs extracted, skipping tool selection"],
        }

    print(f"IOCs to analyze: {len(iocs)}")
    _emit_terminal(agent, f"IOCs to analyze: {len(iocs)}", progress=67)

    reflection_tool_calls = agent._select_new_reflection_tool_calls(state)
    if reflection_tool_calls:
        print(
            "Reflection loop provided "
            f"{len(reflection_tool_calls)} targeted follow-up tool calls"
        )
        _emit_terminal(
            agent,
            f"Reflection loop provided {len(reflection_tool_calls)} targeted follow-up tool calls",
            progress=68,
            level="success",
        )
        return {
            "tool_calls": reflection_tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(reflection_tool_calls),
            "current_stage": "reflection_guided_tool_selection_complete",
            "reasoning_steps": [
                f"Used post-correlation reflection output for {len(reflection_tool_calls)} follow-up tool calls"
            ],
        }

    tool_execution_round = agent._coerce_int(state.get("tool_execution_round"), 0)
    if tool_execution_round > 0:
        tool_calls = agent._select_follow_up_tool_calls(state)
        print(
            "Follow-up selection round "
            f"{tool_execution_round + 1}: {len(tool_calls)} new tool calls"
        )
        _emit_terminal(
            agent,
            f"Follow-up selection round {tool_execution_round + 1}: {len(tool_calls)} new tool calls",
            progress=68,
        )
        if not tool_calls:
            _emit_terminal(
                agent,
                "No unqueried follow-up tools remained after reviewing observations",
                progress=68,
                level="warning",
            )
            return {
                "tool_calls": [],
                "tool_selection_trace": [],
                "current_stage": "follow_up_tool_selection_complete",
                "reasoning_steps": [
                    "No unqueried follow-up tools remained after reviewing observations"
                ],
            }

        return {
            "tool_calls": tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(tool_calls),
            "current_stage": "follow_up_tool_selection_complete",
            "reasoning_steps": [
                f"Selected {len(tool_calls)} follow-up tool calls based on prior observations"
            ],
        }

    planned_tool_calls = agent._select_new_planned_tool_calls(state)
    if planned_tool_calls:
        print(
            "Planner provided "
            f"{len(planned_tool_calls)} ready-to-execute tool calls"
        )
        _emit_terminal(
            agent,
            f"Planner provided {len(planned_tool_calls)} ready-to-execute tool calls",
            progress=68,
            level="success",
        )
        return {
            "tool_calls": planned_tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(planned_tool_calls),
            "current_stage": "planner_guided_tool_selection_complete",
            "reasoning_steps": [
                f"Used Phase 4 planner output for {len(planned_tool_calls)} initial tool calls"
            ],
        }

    memory_tool_calls, memory_reasons = agent._select_tools_from_memory(iocs)
    if memory_tool_calls:
        print(
            "Procedural memory selected "
            f"{len(memory_tool_calls)} tool calls for {len(iocs)} IOCs"
        )
        _emit_terminal(
            agent,
            f"Procedural memory selected {len(memory_tool_calls)} tool calls for {len(iocs)} IOCs",
            progress=68,
            level="success",
        )
        return {
            "tool_calls": memory_tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(memory_tool_calls),
            "current_stage": "memory_guided_tool_selection_complete",
            "reasoning_steps": [
                f"Procedural memory selected {len(memory_tool_calls)} tool calls"
            ]
            + memory_reasons[:5],
        }

    prompt = agent._create_tool_selection_prompt(iocs)
    print(f"\nPrompt length: {len(prompt)} chars")
    print("Sending tool selection request to LLM...")
    _emit_terminal(agent, f"Prompt length: {len(prompt)} chars", progress=68)
    _emit_terminal(agent, "Sending tool selection request to LLM...", progress=68)

    try:
        start_time = time.time()
        response = agent.llm.invoke(prompt)
        elapsed = time.time() - start_time

        print(f"\n[OK] LLM Response received ({elapsed:.2f}s)")
        print("-" * 60)
        print(f"Response preview:\n{response[:300]}")
        if len(response) > 300:
            print(f"... ({len(response) - 300} more chars)")
        print("-" * 60)

        tool_calls = agent._parse_tool_selections(response, iocs)
        _emit_terminal(
            agent,
            f"[OK] LLM tool selection response received ({elapsed:.2f}s)",
            progress=69,
            level="success",
        )

        print(f"\nParsed {len(tool_calls)} tool calls:")
        tool_summary = {}
        for call in tool_calls:
            tool_summary[call["tool"]] = tool_summary.get(call["tool"], 0) + 1

        for tool, count in tool_summary.items():
            print(f"  - {tool}: {count} calls")
        if tool_summary:
            tool_summary_text = ", ".join(
                f"{tool}: {count} calls" for tool, count in tool_summary.items()
            )
            _emit_terminal(agent, f"Parsed {len(tool_calls)} tool calls: {tool_summary_text}", progress=69)

        if tool_calls:
            print("\nExample tool calls:")
            for call in tool_calls[:3]:
                print(f"  - {call['tool']} for {call['ioc_type']}: {call['ioc'][:50]}")

        return {
            "tool_calls": tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(tool_calls),
            "reasoning_steps": [
                f"Selected {len(tool_calls)} tool calls based on IOC types"
            ],
        }

    except Exception as e:
        print(f"\n[WARN] Error in tool selection: {e}")
        print(traceback.format_exc())
        print("\nUsing fallback tool selection...")
        _emit_terminal(
            agent,
            f"[WARN] Error in tool selection: {e}; using fallback tool selection",
            progress=69,
            level="warning",
        )
        tool_calls = agent._fallback_tool_selection(iocs)
        return {
            "tool_calls": tool_calls,
            "tool_selection_trace": agent._tool_selection_trace(tool_calls),
            "reasoning_steps": [f"Used fallback tool selection due to error: {e}"],
        }
