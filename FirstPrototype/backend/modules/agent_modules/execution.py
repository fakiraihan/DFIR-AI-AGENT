"""Tool execution node helpers for the DFIR agent."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Mapping, Optional
import time
import traceback


def _emit_terminal(agent: Any, line: str, *, progress: int | None = None, level: str = "info") -> None:
    emit = getattr(agent, "_emit_terminal", None)
    if callable(emit):
        emit(line, progress=progress, level=level)


def _terminal_ioc(value: Any) -> str:
    text = str(value or "")
    return text if len(text) <= 80 else f"{text[:38]}...{text[-20:]}"


def _result_count(data: Any) -> int:
    if isinstance(data, (list, tuple, dict, set)):
        return len(data)
    return 0


def _tool_result_terminal_line(result: Mapping[str, Any], elapsed: float) -> tuple[str, str]:
    tool_name = str(result.get("tool_call") or result.get("tool") or "unknown_tool")
    ioc = _terminal_ioc(result.get("ioc"))
    ioc_type = str(result.get("ioc_type") or "unknown")

    if result.get("status") == "skipped" or result.get("skipped"):
        return (
            f"[SKIP] {tool_name} for {ioc_type} {ioc} ({elapsed:.2f}s): {result.get('reason', 'skipped')}",
            "warning",
        )
    if result.get("error"):
        http_status = result.get("http_status")
        suffix = f" HTTP {http_status}" if http_status else ""
        return (
            f"[WARN] {tool_name} for {ioc_type} {ioc}{suffix} ({elapsed:.2f}s): {result.get('error')}",
            "warning",
        )
    count = _result_count(result.get("data"))
    if count:
        return (
            f"[OK] {tool_name} for {ioc_type} {ioc} ({elapsed:.2f}s): Found data ({count} item(s))",
            "success",
        )
    return (
        f"[OK] {tool_name} for {ioc_type} {ioc} ({elapsed:.2f}s): No data found",
        "success",
    )


def execute_tools(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Execute selected threat-intel tools."""
    if agent.status_callback and agent.session_id:
        selected_tools = [t["tool"] for t in state.get("tool_calls", [])]
        if selected_tools:
            tool_names = ", ".join(set(selected_tools[:3]))
            agent.status_callback(
                agent.session_id,
                "ai_agent",
                f"Menggunakan tools: {tool_names}...",
                72,
            )
        else:
            agent.status_callback(
                agent.session_id,
                "ai_agent",
                "Menjalankan threat intelligence tools...",
                72,
            )

    print("\n=== STAGE 3: TOOL EXECUTION ===")
    _emit_terminal(
        agent,
        "=" * 60 + "\nSTAGE 3: TOOL EXECUTION\n" + "=" * 60,
        progress=72,
        level="stage",
    )
    all_tool_calls = state["tool_calls"]
    executed_keys = agent._attempted_tool_call_keys(state)
    tool_calls = [
        call for call in all_tool_calls if agent._tool_call_key(call) not in executed_keys
    ]
    validation_trace = [
        agent._validate_tool_call_for_audit(call, "accepted_for_execution")
        for call in tool_calls
    ]
    skipped_existing = len(all_tool_calls) - len(tool_calls)
    print(f"Total tool calls in state: {len(all_tool_calls)}")
    print(f"New tool calls to execute: {len(tool_calls)}")
    _emit_terminal(agent, f"Total tool calls in state: {len(all_tool_calls)}", progress=72)
    _emit_terminal(agent, f"New tool calls to execute: {len(tool_calls)}", progress=72)
    if skipped_existing:
        print(f"Skipping {skipped_existing} previously executed tool calls")
        _emit_terminal(agent, f"Skipping {skipped_existing} previously executed tool calls", progress=72)

    results = []
    next_round = agent._coerce_int(state.get("tool_execution_round"), 0) + 1

    if not tool_calls:
        _emit_terminal(
            agent,
            f"No new threat intel queries to execute in round {next_round}",
            progress=72,
            level="warning",
        )
        evidence_update = agent._build_evidence_state_update(state, [])
        return {
            "tool_results": [],
            "tool_validation_trace": validation_trace,
            "tool_execution_round": next_round,
            "current_stage": "tool_execution_complete",
            "reasoning_steps": [
                f"No new threat intel queries to execute in round {next_round}"
            ],
            "agent_trace": [
                agent._agent_trace_event(
                    "tool_executor",
                    "no_new_tool_calls",
                    f"No new threat intel queries to execute in round {next_round}",
                )
            ],
            **evidence_update,
        }

    max_workers = min(32, len(tool_calls))
    print(f"Executing {len(tool_calls)} tool calls with {max_workers} workers")
    _emit_terminal(
        agent,
        f"Executing {len(tool_calls)} tool calls with {max_workers} workers",
        progress=72,
        level="stage",
    )

    ordered_results: List[Optional[Dict[str, Any]]] = [None] * len(tool_calls)
    elapsed_by_index: Dict[int, float] = {}
    for idx, call in enumerate(tool_calls):
        _emit_terminal(
            agent,
            f"[{idx + 1}/{len(tool_calls)}] Executing: {call.get('tool')}\n  IOC: {_terminal_ioc(call.get('ioc'))} (type: {str(call.get('ioc_type')).lower()})",
            progress=72,
        )
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(agent._execute_single_tool_call, call, idx, len(tool_calls)): idx
            for idx, call in enumerate(tool_calls)
        }
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result, elapsed = future.result()
            except Exception as e:
                call = tool_calls[idx]
                tool_name = str(call.get("tool"))
                ioc = str(call.get("ioc"))
                ioc_type = str(call.get("ioc_type")).lower()
                elapsed = 0.0
                result = {
                    "tool": tool_name,
                    "tool_call": tool_name,
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "error": str(e),
                    "status": "error",
                    "data": [],
                }

            ordered_results[idx] = result
            elapsed_by_index[idx] = elapsed

    for idx, result in enumerate(ordered_results):
        if result is None:
            continue
        tool_name = str(result.get("tool_call") or result.get("tool"))
        ioc_type = str(result.get("ioc_type") or "").lower()
        elapsed = elapsed_by_index.get(idx, 0.0)
        agent._record_tool_performance(tool_name, result, elapsed, ioc_type)
        agent._print_tool_result_summary(result, elapsed)
        terminal_line, terminal_level = _tool_result_terminal_line(result, elapsed)
        _emit_terminal(agent, terminal_line, progress=74, level=terminal_level)
        results.append(result)
        validation_trace[idx]["execution_status"] = result.get("status", "ok")
        if result.get("skipped") or result.get("status") == "skipped":
            validation_trace[idx]["status"] = "rejected"
            validation_trace[idx]["reason"] = result.get("reason", "skipped")
        elif result.get("error") or result.get("status") == "error":
            validation_trace[idx]["status"] = "error"
            validation_trace[idx]["reason"] = result.get("error", "tool error")

    print(f"Executed {len(results)} tool calls")
    _emit_terminal(
        agent,
        f"Executed {len(results)} tool calls",
        progress=75,
        level="success",
    )
    evidence_update = agent._build_evidence_state_update(state, results)

    return {
        "tool_results": results,
        "normalized_evidence": evidence_update["normalized_evidence"],
        "aggregated_ioc_evidence": evidence_update["aggregated_ioc_evidence"],
        "supporting_evidence": evidence_update["supporting_evidence"],
        "investigation_confidence": evidence_update["investigation_confidence"],
        "confidence_factors": evidence_update["confidence_factors"],
        "investigation_status": evidence_update["investigation_status"],
        "tool_validation_trace": validation_trace,
        "agent_trace": [
            agent._agent_trace_event(
                "tool_executor",
                "completed",
                f"Executed {len(results)} threat intel queries in round {next_round}",
            )
        ],
        "tool_execution_round": next_round,
        "current_stage": "tool_execution_complete",
        "reasoning_steps": [
            f"Executed {len(results)} threat intel queries in round {next_round}"
        ],
    }


def execute_single_tool_call(
    agent: Any, call: Mapping[str, Any], index: int, total: int
) -> tuple[Dict[str, Any], float]:
    """Execute one threat-intel call. Safe to run inside a worker thread."""
    tool_name = str(call["tool"])
    ioc = str(call["ioc"])
    ioc_type = str(call["ioc_type"]).lower()

    print(f"\n[{index + 1}/{total}] Executing: {tool_name}")
    print(f"  IOC: {ioc} (type: {ioc_type})")
    start_time = time.time()

    try:
        skip_reason = agent._get_tool_call_skip_reason(tool_name, ioc, ioc_type)
        if skip_reason:
            elapsed = time.time() - start_time
            return (
                {
                    "tool": tool_name,
                    "tool_call": tool_name,
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "status": "skipped",
                    "skipped": True,
                    "reason": skip_reason,
                    "data": [],
                },
                elapsed,
            )

        if tool_name == "threatfox_lookup":
            threatfox_ioc_type = {
                "md5": "md5_hash",
                "sha256": "sha256_hash",
            }.get(ioc_type, ioc_type)
            result = agent.threat_intel.threatfox_lookup(ioc, threatfox_ioc_type)
        elif tool_name == "malwarebazaar_lookup":
            result = agent.threat_intel.malwarebazaar_lookup(ioc)
        elif tool_name == "urlhaus_lookup":
            result = agent.threat_intel.urlhaus_lookup(ioc)
        elif tool_name == "alienvault_otx_lookup":
            otx_ioc_type = "IPv4" if ioc_type == "ip" else ioc_type
            result = agent.threat_intel.alienvault_otx_lookup(ioc, otx_ioc_type)
        elif tool_name == "greynoise_lookup":
            result = agent.threat_intel.greynoise_lookup(ioc)
        elif tool_name == "virustotal_lookup":
            vt_ioc_type = "file" if ioc_type in ["md5", "sha256"] else ioc_type
            result = agent.threat_intel.virustotal_lookup(ioc, vt_ioc_type)
        else:
            result = {
                "tool": tool_name,
                "tool_call": tool_name,
                "ioc": ioc,
                "ioc_type": ioc_type,
                "error": f"Unknown tool: {tool_name}",
                "status": "error",
                "data": [],
            }

        result.setdefault("tool_call", tool_name)
        result.setdefault("ioc", ioc)
        provider_ioc_type = result.get("ioc_type")
        if provider_ioc_type and str(provider_ioc_type).lower() != ioc_type:
            result.setdefault("provider_ioc_type", provider_ioc_type)
        result["ioc_type"] = ioc_type
        result.setdefault("data", [])
        return result, time.time() - start_time

    except Exception as e:
        print(f"  [ERROR] Exception: {e}")
        print(f"  Traceback: {traceback.format_exc()[:200]}")
        return (
            {
                "tool": tool_name,
                "tool_call": tool_name,
                "ioc": ioc,
                "ioc_type": ioc_type,
                "error": str(e),
                "status": "error",
                "data": [],
            },
            time.time() - start_time,
        )


def print_tool_result_summary(result: Mapping[str, Any], elapsed: float) -> None:
    """Print a compact ASCII-only summary for a tool result."""
    if result.get("status") == "skipped" or result.get("skipped"):
        print(f"  [SKIP] ({elapsed:.2f}s): {result.get('reason', 'skipped')}")
    elif result.get("error"):
        http_status = result.get("http_status")
        suffix = f" (HTTP {http_status})" if http_status else ""
        print(f"  [WARN] Error{suffix}: {result['error']}")
    elif result.get("data"):
        print(f"  [OK] Success ({elapsed:.2f}s): Found data")
        if isinstance(result["data"], dict):
            keys = list(result["data"].keys())[:3]
            print(f"    Keys: {keys}")
        elif isinstance(result["data"], list):
            print(f"    Results: {len(result['data'])} items")
    else:
        print(f"  [OK] Completed ({elapsed:.2f}s): No data found")
