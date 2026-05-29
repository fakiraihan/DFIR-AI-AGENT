"""
LangGraph AI Agent for DFIR Investigation
Orchestrates investigation using ReAct pattern with Foundation-Sec-8B
"""

from typing import Dict, List, Any, Optional, Mapping
import time
import pandas as pd

from langgraph.graph import StateGraph, END

from modules.agent_modules import constants as agent_constants
from modules.agent_modules import evidence as agent_evidence
from modules.agent_modules import execution as agent_execution
from modules.agent_modules import ioc as agent_ioc
from modules.agent_modules import prompts as agent_prompts
from modules.agent_modules import recommendations as agent_recommendations
from modules.agent_modules import reporting as agent_reporting
from modules.agent_modules import routing as agent_routing
from modules.agent_modules import selection as agent_selection
from modules.agent_modules.state import InvestigationState, build_initial_state
from modules.agent_modules import timeline as agent_timeline
from modules.agent_modules import tooling as agent_tooling
from modules.procedural_memory import ProceduralMemory
from modules.threat_intel import ThreatIntelToolkit


class DFIRAgent:
    """
    AI Agent for DFIR investigation orchestration
    Uses ReAct pattern: Reasoning -> Action -> Observation
    """

    IOC_TYPES = agent_constants.IOC_TYPES
    EXECUTABLE_FILE_EXTENSIONS = agent_constants.EXECUTABLE_FILE_EXTENSIONS
    TOOL_TO_IOC_TYPES = agent_constants.TOOL_TO_IOC_TYPES
    TOOL_RESULT_ALIASES = agent_constants.TOOL_RESULT_ALIASES
    MEMORY_TOOL_TO_AGENT_TOOL = agent_constants.MEMORY_TOOL_TO_AGENT_TOOL
    AGENT_TOOL_TO_MEMORY_TOOL = agent_constants.AGENT_TOOL_TO_MEMORY_TOOL
    IOC_TYPE_TO_MEMORY_STRATEGY = agent_constants.IOC_TYPE_TO_MEMORY_STRATEGY
    STATIC_FALLBACK_TOOLS = agent_constants.STATIC_FALLBACK_TOOLS
    DEFAULT_MAX_TOOL_EXECUTION_ROUNDS = agent_constants.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS
    DEFAULT_MAX_REFLECTION_ROUNDS = agent_constants.DEFAULT_MAX_REFLECTION_ROUNDS

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "foundation-sec-8b",
        threat_intel_api_keys: Optional[Dict[str, str]] = None,
        llm: Any = None,
        provider_name: str = "ollama",
        procedural_memory_path: Optional[str] = None,
        procedural_memory: Any = None,
    ):
        """
        Initialize DFIR Agent

        Args:
            ollama_base_url: Ollama API URL
            ollama_model: Model name in Ollama
            threat_intel_api_keys: Dict of API keys for threat intel services
            procedural_memory_path: Optional path for persistent procedural memory
            procedural_memory: Optional injected memory object for tests/custom runtimes
        """
        # Initialize LLM
        self.llm = llm
        self.provider_name = provider_name
        self.model_name = ollama_model

        if self.llm is None:
            from langchain_community.llms import Ollama

            self.llm = Ollama(
                base_url=ollama_base_url,
                model=ollama_model,
                temperature=0.1,
                top_p=0.7,
                top_k=20,
                num_ctx=16384,
                num_predict=8192,
                repeat_penalty=1.15,
            )

        # Initialize threat intel toolkit
        self.threat_intel = ThreatIntelToolkit(threat_intel_api_keys or {})

        # Initialize optional procedural memory for memory-guided tool use.
        # The API orchestrator passes a persistent path; tests can inject a fake.
        if procedural_memory is not None:
            self.procedural_memory = procedural_memory
        elif procedural_memory_path:
            self.procedural_memory = ProceduralMemory(str(procedural_memory_path))
        else:
            self.procedural_memory = None

        # Status callback
        self.session_id = None
        self.status_callback = None
        self.telemetry_callback = None

        # Build LangGraph
        self.graph = self._build_graph()
        self.app = self.graph.compile()

    def _build_graph(self) -> StateGraph:
        """Build LangGraph state machine"""
        workflow = StateGraph(InvestigationState)

        # Add nodes
        workflow.add_node("ioc_extractor", self.extract_iocs)
        workflow.add_node("planner", self.plan_goals)
        workflow.add_node("tool_selector", self.select_tools)
        workflow.add_node("tool_executor", self.execute_tools)
        workflow.add_node("correlator", self.correlate_findings)
        workflow.add_node("post_correlation_assessment", self.post_correlation_assessment)
        workflow.add_node("context_only_summary", self.context_only_summary)
        workflow.add_node("inconclusive_correlation", self.inconclusive_correlation)
        workflow.add_node("timeline_builder", self.build_timeline)
        workflow.add_node("report_generator", self.generate_summary)

        # Add edges (agentic control flow with bounded runtime routing)
        workflow.set_entry_point("ioc_extractor")
        workflow.add_conditional_edges(
            "ioc_extractor",
            self._route_after_ioc_extraction,
            {
                "has_iocs": "planner",
                "no_iocs": "context_only_summary",
            },
        )
        workflow.add_edge("planner", "tool_selector")
        workflow.add_edge("tool_selector", "tool_executor")
        workflow.add_conditional_edges(
            "tool_executor",
            self._decide_next_step,
            {
                "needs_more_intel": "tool_selector",
                "sufficient_intel": "correlator",
                "no_iocs": "report_generator",
                "no_successful_evidence": "inconclusive_correlation",
            },
        )
        workflow.add_edge("correlator", "post_correlation_assessment")
        workflow.add_conditional_edges(
            "post_correlation_assessment",
            self._decide_post_correlation_step,
            {
                "more_intel_needed": "tool_selector",
                "sufficient_after_reflection": "timeline_builder",
                "no_iocs": "report_generator",
            },
        )
        workflow.add_edge("timeline_builder", "report_generator")
        workflow.add_edge("context_only_summary", END)
        workflow.add_edge("inconclusive_correlation", "timeline_builder")
        workflow.add_edge("report_generator", END)

        return workflow

    def _route_after_ioc_extraction(self, state: InvestigationState) -> str:
        """Route directly to a safe context-only result when no valid IOC exists."""
        decision = agent_routing.route_after_ioc_extraction(state)
        self._emit_terminal(f"IOC extraction routing: {decision}", progress=64)
        return decision

    def _decide_next_step(self, state: InvestigationState) -> str:
        """Route the graph based on observations from the latest tool round."""
        decision = agent_routing.decide_next_step(
            state,
            default_max_tool_execution_rounds=self.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS,
            coerce_int=self._coerce_int,
            has_successful_normalized_evidence=self._has_successful_normalized_evidence,
            select_follow_up_tool_calls=self._select_follow_up_tool_calls,
        )
        self._emit_terminal(f"Routing decision: {decision}", progress=76)
        return decision

    def extract_iocs(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Extract IOCs from anomalous log parameters
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "Mengekstrak IOCs dari logs...", 62
            )

        print("\n=== STAGE 1: IOC EXTRACTION ===")
        self._emit_terminal(
            "=" * 60 + "\nSTAGE 1: IOC EXTRACTION\n" + "=" * 60,
            progress=62,
            level="stage",
        )

        anomalies = state["anomalies"]
        parsed_logs = state["parsed_logs"]
        self._emit_terminal(
            f"Scanning {len(anomalies)} anomalous windows for IOC candidates...",
            progress=62,
        )

        unique_iocs = agent_ioc.extract_iocs_from_anomalies(
            anomalies,
            parsed_logs,
            self._identify_ioc_type,
        )

        print(f"Extracted {len(unique_iocs)} unique IOCs")
        self._emit_terminal(
            f"Extracted {len(unique_iocs)} unique IOCs",
            progress=64,
            level="success",
        )
        for ioc in unique_iocs[:5]:  # Show first 5
            print(f"  - {ioc['type']}: {ioc['value']}")
            self._emit_terminal(f"  - {ioc['type']}: {ioc['value']}", progress=64)

        return {
            "iocs_extracted": unique_iocs,
            "current_stage": "ioc_extraction_complete",
            "reasoning_steps": [
                f"Extracted {len(unique_iocs)} IOCs from anomalous windows"
            ],
        }

    def plan_goals(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Decompose extracted IOCs into an explicit, bounded investigation plan.

        The planner is fail-open and additive: it never increments the threat-intel
        execution round, and tool selection can still fall back to existing paths.
        """
        return agent_selection.plan_goals(self, state)

    def select_tools(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Use LLM to select appropriate threat intel tools for each IOC
        """
        return agent_selection.select_tools(self, state)

    def execute_tools(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Execute selected threat intel tools
        """
        return agent_execution.execute_tools(self, state)

    def _execute_single_tool_call(
        self, call: Mapping[str, Any], index: int, total: int
    ) -> tuple[Dict[str, Any], float]:
        """Execute one threat-intel call. Safe to run inside a worker thread."""
        return agent_execution.execute_single_tool_call(self, call, index, total)

    def _print_tool_result_summary(self, result: Mapping[str, Any], elapsed: float) -> None:
        """Print a compact ASCII-only summary for a tool result."""
        agent_execution.print_tool_result_summary(result, elapsed)

    def _get_tool_call_skip_reason(
        self, tool_name: str, ioc: str, ioc_type: str
    ) -> Optional[str]:
        return agent_tooling.get_tool_call_skip_reason(
            tool_name,
            ioc,
            ioc_type,
            self.TOOL_TO_IOC_TYPES,
            self.IOC_TYPES,
            self._identify_ioc_type,
        )

    def _select_tools_from_memory(
        self, iocs: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], List[str]]:
        """Build tool calls from procedural memory strategies when available."""
        if not self.procedural_memory:
            return [], []

        tool_calls = []
        reasoning_steps = []
        seen = set()

        for ioc in iocs:
            ioc_type = str(ioc.get("type") or "").lower()
            ioc_value = str(ioc.get("value") or "")
            strategy_key = self.IOC_TYPE_TO_MEMORY_STRATEGY.get(ioc_type)
            if not strategy_key or not ioc_value:
                continue

            try:
                strategy = self.procedural_memory.get_api_strategy(strategy_key)
            except Exception as e:
                print(f"[WARN] Procedural memory strategy lookup failed: {e}")
                continue

            candidate_tools = self._memory_strategy_tool_names(strategy)
            selected_for_ioc = []
            for tool_name in candidate_tools:
                if ioc_type not in self.TOOL_TO_IOC_TYPES.get(tool_name, set()):
                    continue
                call = self._build_tool_call(
                    ioc_value,
                    ioc_type,
                    tool_name,
                    selection_source="fallback_heuristic",
                    selection_reason=f"procedural_memory: {strategy.get('reason') or 'procedural strategy'}",
                )
                key = self._tool_call_key(call)
                if key in seen:
                    continue
                tool_calls.append(call)
                selected_for_ioc.append(tool_name)
                seen.add(key)

            if selected_for_ioc:
                reason = strategy.get("reason") or "procedural strategy"
                reasoning_steps.append(
                    f"Procedural memory selected {', '.join(selected_for_ioc)} for {ioc_type} IOC {ioc_value}: {reason}"
                )

        return tool_calls, reasoning_steps

    def _select_new_planned_tool_calls(
        self, state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Return valid planned calls that have not produced observations yet."""
        return agent_tooling.select_new_tool_calls(
            state,
            "planned_tool_calls",
            self.TOOL_TO_IOC_TYPES,
            self.TOOL_RESULT_ALIASES,
            self._identify_ioc_type,
        )

    def _select_new_reflection_tool_calls(
        self, state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Return post-correlation reflection calls that remain unattempted."""
        return agent_tooling.select_new_tool_calls(
            state,
            "post_correlation_follow_up_calls",
            self.TOOL_TO_IOC_TYPES,
            self.TOOL_RESULT_ALIASES,
            self._identify_ioc_type,
        )

    def _dedupe_tool_calls(
        self, tool_calls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Normalize and deduplicate executable tool calls while preserving order."""
        return agent_tooling.dedupe_tool_calls(
            tool_calls,
            self.TOOL_TO_IOC_TYPES,
            self.TOOL_RESULT_ALIASES,
        )

    def _build_tool_call(
        self,
        ioc: Any,
        ioc_type: Any,
        tool: Any,
        *,
        selection_source: str = "fallback_heuristic",
        selection_reason: str = "static IOC-to-tool mapping",
        expected_evidence: str = "IOC reputation and provider status",
    ) -> Dict[str, Any]:
        """Create a traceable threat-intel tool call without changing core keys."""
        return agent_tooling.build_tool_call(
            ioc,
            ioc_type,
            tool,
            self.TOOL_RESULT_ALIASES,
            selection_source=selection_source,
            selection_reason=selection_reason,
            expected_evidence=expected_evidence,
        )

    def _tool_selection_trace(self, tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build additive audit records for selected tool calls."""
        return agent_tooling.tool_selection_trace(tool_calls)

    def _memory_strategy_tool_names(self, strategy: Mapping[str, Any]) -> List[str]:
        """Convert ProceduralMemory primary/fallback tool keys to agent tool names."""
        return agent_tooling.memory_strategy_tool_names(
            strategy, self.MEMORY_TOOL_TO_AGENT_TOOL
        )

    def _agent_tool_name(self, memory_tool_name: Any) -> Optional[str]:
        return agent_tooling.agent_tool_name(
            memory_tool_name, self.MEMORY_TOOL_TO_AGENT_TOOL
        )

    def _memory_tool_name(self, agent_tool_name: Any) -> str:
        return agent_tooling.memory_tool_name(
            agent_tool_name,
            self.TOOL_RESULT_ALIASES,
            self.AGENT_TOOL_TO_MEMORY_TOOL,
        )

    def _record_tool_performance(
        self,
        tool_name: str,
        result: Mapping[str, Any],
        response_time: float,
        ioc_type: str,
    ) -> None:
        """Record runtime tool performance in procedural memory when enabled."""
        if not self.procedural_memory:
            return

        memory_tool = self._memory_tool_name(tool_name)
        success = self._tool_result_succeeded(result)
        try:
            self.procedural_memory.update_tool_performance(
                tool=memory_tool,
                success=success,
                response_time=response_time,
                ioc_type=ioc_type,
            )
        except Exception as e:
            print(f"[WARN] Procedural memory performance update failed: {e}")

    def _tool_result_succeeded(self, result: Mapping[str, Any]) -> bool:
        return agent_tooling.tool_result_succeeded(result)

    def _validate_tool_call_for_audit(
        self, call: Mapping[str, Any], default_status: str = "accepted"
    ) -> Dict[str, Any]:
        """Return a deterministic validation record for a proposed tool call."""
        return agent_tooling.validate_tool_call_for_audit(
            call,
            default_status,
            self.TOOL_RESULT_ALIASES,
            self.TOOL_TO_IOC_TYPES,
            self.IOC_TYPES,
            self._identify_ioc_type,
        )

    def normalize_tool_result(self, tool_result: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize provider-specific threat-intel output into an auditable schema."""
        return agent_evidence.normalize_tool_result(
            tool_result,
            aliases=self.TOOL_RESULT_ALIASES,
            identify_ioc_type=self._identify_ioc_type,
            is_malicious_tool_result=self._is_malicious_tool_result,
            is_suspicious_tool_result=self._is_suspicious_tool_result,
            safe_positive_count=self._safe_positive_count,
        )

    def aggregate_ioc_evidence(
        self, normalized_evidence: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Aggregate successful normalized evidence per IOC deterministically."""
        return agent_evidence.aggregate_ioc_evidence(normalized_evidence)

    def _build_evidence_state_update(
        self, state: Mapping[str, Any], new_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return agent_evidence.build_evidence_state_update(
            state, new_results, self.normalize_tool_result
        )

    def _supporting_evidence_from_aggregation(
        self, aggregated: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return agent_evidence.supporting_evidence_from_aggregation(aggregated)

    def _derive_investigation_confidence(
        self,
        supporting: List[Dict[str, Any]],
        all_normalized: List[Dict[str, Any]],
    ) -> tuple[float, List[str]]:
        return agent_evidence.derive_investigation_confidence(
            supporting, all_normalized
        )

    def _has_successful_normalized_evidence(self, state: Mapping[str, Any]) -> bool:
        return agent_evidence.has_successful_normalized_evidence(
            state, self.normalize_tool_result
        )

    def _normalized_evidence_succeeded(self, evidence: Mapping[str, Any]) -> bool:
        return agent_evidence.normalized_evidence_succeeded(evidence)

    def _coerce_confidence(self, value: Any, default: float) -> float:
        return agent_evidence.coerce_confidence(value, default)

    def _present_values(self, values: List[Any]) -> List[str]:
        return agent_evidence.present_values(values)

    def _tool_result_raw_reference(
        self, tool_result: Mapping[str, Any], source: str, ioc: str
    ) -> str:
        return agent_evidence.tool_result_raw_reference(tool_result, source, ioc)

    def _agent_trace_event(self, stage: str, action: str, detail: str) -> Dict[str, Any]:
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stage": stage,
            "action": action,
            "detail": detail,
        }

    def _emit_terminal(
        self,
        line: str,
        *,
        stage: str = "ai_agent",
        progress: int | None = None,
        level: str = "info",
    ) -> None:
        """Emit safe observable agent telemetry for the frontend terminal."""
        if not self.telemetry_callback or not self.session_id:
            return
        self.telemetry_callback(
            self.session_id,
            stage,
            line,
            progress=progress,
            level=level,
        )

    def _select_follow_up_tool_calls(
        self, state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Select unqueried enrichment tools for IOCs with suspicious observations."""
        return agent_tooling.select_follow_up_tool_calls(
            state,
            self.STATIC_FALLBACK_TOOLS,
            self.TOOL_RESULT_ALIASES,
            self._identify_ioc_type,
            self._is_malicious_tool_result,
            self._is_suspicious_tool_result,
        )

    def _follow_up_ioc_keys(self, state: InvestigationState) -> set[tuple[str, str]]:
        """Return IOC keys that deserve another enrichment round."""
        return agent_tooling.follow_up_ioc_keys(
            state,
            self._identify_ioc_type,
            self._is_malicious_tool_result,
            self._is_suspicious_tool_result,
        )

    def _attempted_tool_call_keys(
        self, state: InvestigationState
    ) -> set[tuple[str, str, str]]:
        """Return tool/IOC combinations that already produced an observation."""
        return agent_tooling.attempted_tool_call_keys(
            state,
            self.TOOL_RESULT_ALIASES,
            self._identify_ioc_type,
        )

    def _tool_call_key(self, call: Mapping[str, Any]) -> tuple[str, str, str]:
        return agent_tooling.tool_call_key(call, self.TOOL_RESULT_ALIASES)

    def _tool_result_key(
        self, result: Mapping[str, Any]
    ) -> Optional[tuple[str, str, str]]:
        return agent_tooling.tool_result_key(
            result,
            self.TOOL_RESULT_ALIASES,
            self._identify_ioc_type,
        )

    def _normalize_tool_name(self, tool_name: Any) -> str:
        return agent_tooling.normalize_tool_name(tool_name, self.TOOL_RESULT_ALIASES)

    def _extract_tool_result_ioc(self, result: Mapping[str, Any]) -> str:
        return agent_tooling.extract_tool_result_ioc(result)

    def _coerce_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def correlate_findings(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Use LLM to correlate threat intel findings with anomalies
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "AI sedang mengkorelasikan findings...",
                77,
            )

        print("\n=== STAGE 4: CORRELATION ANALYSIS ===")
        print(
            "Correlating threat intel findings with anomalies using ReAct reasoning..."
        )
        self._emit_terminal(
            "=" * 60 + "\nSTAGE 4: CORRELATION ANALYSIS\n" + "=" * 60,
            progress=77,
            level="stage",
        )
        self._emit_terminal(
            "Correlating threat intel findings with anomalies using ReAct workflow...",
            progress=77,
        )

        tool_results = state["tool_results"]
        anomalies = state["anomalies"]

        print(f"Input data:")
        print(f"  - Anomalies: {len(anomalies)}")
        print(f"  - Tool results: {len(tool_results)}")
        print(
            f"  - Malicious IOCs: {sum(1 for r in tool_results if r.get('malware_family'))}"
        )
        malicious_count = sum(1 for r in tool_results if r.get("malware_family"))
        self._emit_terminal(
            f"Input data:\n  - Anomalies: {len(anomalies)}\n  - Tool results: {len(tool_results)}\n  - Malicious IOCs: {malicious_count}",
            progress=77,
        )

        # Create correlation prompt
        prompt = self._create_correlation_prompt(anomalies, tool_results)
        print(f"\nPrompt length: {len(prompt)} chars")
        print("Sending correlation request to LLM...")
        self._emit_terminal(f"Prompt length: {len(prompt)} chars", progress=77)
        self._emit_terminal("Sending correlation request to LLM...", progress=77)

        try:
            import time

            start_time = time.time()
            response = self.llm.invoke(prompt)
            elapsed = time.time() - start_time

            print(f"\n[OK] LLM Correlation Analysis Complete ({elapsed:.2f}s)")
            print("=" * 60)
            self._emit_terminal(
                f"[OK] LLM Correlation Analysis Complete ({elapsed:.2f}s)",
                progress=78,
                level="success",
            )
            print("CORRELATION ANALYSIS RESULT:")
            print("=" * 60)
            print(response[:800] + ("..." if len(response) > 800 else ""))
            print("=" * 60)

            # Store full correlation analysis in state for report generation
            return {
                "correlation_analysis": response,
                "reasoning_steps": [
                    f"Correlation analysis completed: {len(anomalies)} anomalies correlated with {len(tool_results)} threat intel results"
                ],
            }

        except Exception as e:
            print(f"[WARN] Error in correlation: {e}")
            self._emit_terminal(
                f"[WARN] Error in correlation: {e}",
                progress=78,
                level="warning",
            )
            import traceback

            print(traceback.format_exc())
            return {
                "correlation_analysis": f"Correlation error: {str(e)}",
                "reasoning_steps": [f"Correlation error: {e}"],
            }

    def post_correlation_assessment(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Observe correlation output and decide whether bounded self-correction is needed.

        This is the final ReAct-style reflection pass: after acting and observing tool
        results, the agent evaluates evidence gaps and can request one bounded return
        to tool selection. Failures fall forward to timeline/report generation.
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "AI sedang mengevaluasi kecukupan evidence...",
                79,
            )

        print("\n=== STAGE 4B: POST-CORRELATION REFLECTION ===")
        self._emit_terminal(
            "=" * 60 + "\nSTAGE 4B: POST-CORRELATION REFLECTION\n" + "=" * 60,
            progress=79,
            level="stage",
        )

        current_round = self._coerce_int(state.get("reflection_round"), 0)
        max_rounds = self._coerce_int(
            state.get("max_reflection_rounds"), self.DEFAULT_MAX_REFLECTION_ROUNDS
        )
        next_round = current_round + 1

        if not state.get("iocs_extracted"):
            assessment = "Reflection skipped because no IOCs were extracted."
            print(assessment)
            self._emit_terminal(assessment, progress=79, level="warning")
            return {
                "post_correlation_follow_up_calls": [],
                "observation_assessment": assessment,
                "reflection_steps": [assessment],
                "reflection_round": next_round,
                "current_stage": "post_correlation_assessment_complete",
            }

        if current_round >= max_rounds:
            assessment = (
                "Reflection loop limit reached; continuing with available evidence."
            )
            print(assessment)
            self._emit_terminal(assessment, progress=79, level="warning")
            return {
                "post_correlation_follow_up_calls": [],
                "observation_assessment": assessment,
                "reflection_steps": [assessment],
                "reflection_round": next_round,
                "current_stage": "post_correlation_assessment_complete",
            }

        try:
            follow_up_calls, reasons = self._correlation_requires_follow_up(state)
            assessment = (
                f"Reflection round {next_round}/{max_rounds}: "
                f"{len(follow_up_calls)} targeted follow-up calls selected."
            )
            if not follow_up_calls:
                assessment = (
                    f"Reflection round {next_round}/{max_rounds}: evidence is sufficient; "
                    "no new follow-up calls selected."
                )
            print(assessment)
            self._emit_terminal(assessment, progress=79, level="success")
            return {
                "post_correlation_follow_up_calls": follow_up_calls,
                "observation_assessment": assessment,
                "reflection_steps": [assessment] + reasons[:5],
                "reflection_round": next_round,
                "current_stage": "post_correlation_assessment_complete",
                "reasoning_steps": [assessment],
            }
        except Exception as e:
            assessment = (
                f"Reflection failed open due to error: {e}; continuing with available evidence."
            )
            print(f"[WARN] {assessment}")
            self._emit_terminal(f"[WARN] {assessment}", progress=79, level="warning")
            return {
                "post_correlation_follow_up_calls": [],
                "observation_assessment": assessment,
                "reflection_steps": [assessment],
                "reflection_round": next_round,
                "current_stage": "post_correlation_assessment_complete",
                "reasoning_steps": [assessment],
            }

    def _decide_post_correlation_step(self, state: InvestigationState) -> str:
        """Route after reflection without changing the existing tool-executor router."""
        decision = agent_routing.decide_post_correlation_step(
            state,
            default_max_reflection_rounds=self.DEFAULT_MAX_REFLECTION_ROUNDS,
            coerce_int=self._coerce_int,
            select_new_reflection_tool_calls=self._select_new_reflection_tool_calls,
        )
        self._emit_terminal(f"Reflection routing: {decision}", progress=79)
        return decision

    def _correlation_requires_follow_up(
        self, state: InvestigationState
    ) -> tuple[List[Dict[str, Any]], List[str]]:
        """Select targeted post-correlation follow-ups from evidence gaps."""
        iocs = state.get("iocs_extracted") or []
        if not iocs:
            return [], []

        correlation_text = str(state.get("correlation_analysis") or "").lower()
        gap_keywords = (
            "insufficient",
            "not enough",
            "belum cukup",
            "kurang bukti",
            "further enrichment",
            "more intel",
            "additional context",
            "perlu validasi",
            "perlu enrichment",
        )
        has_evidence_gap = any(keyword in correlation_text for keyword in gap_keywords)
        follow_up_keys = self._follow_up_ioc_keys(state)

        if follow_up_keys:
            candidate_iocs = [
                ioc
                for ioc in iocs
                if (
                    str(ioc.get("type", "")).lower(),
                    str(ioc.get("value", "")),
                )
                in follow_up_keys
            ]
            reason = "Reflection selected suspicious/malicious IOCs for corroboration"
        elif has_evidence_gap:
            candidate_iocs = iocs
            reason = "Reflection found an explicit evidence gap in correlation analysis"
        else:
            return [], ["Reflection found no suspicious observations or explicit evidence gaps"]

        memory_calls, memory_reasons = self._select_tools_from_memory(candidate_iocs)
        candidate_calls = memory_calls or self._fallback_tool_selection(candidate_iocs)
        attempted_keys = self._attempted_tool_call_keys(state)
        follow_up_calls = [
            call
            for call in self._dedupe_tool_calls(candidate_calls)
            if self._tool_call_key(call) not in attempted_keys
        ]

        return follow_up_calls, [reason] + memory_reasons[:4]

    def context_only_summary(self, state: InvestigationState) -> Dict[str, Any]:
        """Finish safely when anomaly context exists but no valid IOC was extracted."""
        return agent_reporting.context_only_summary(self, state)

    def inconclusive_correlation(self, state: InvestigationState) -> Dict[str, Any]:
        """Set a safe inconclusive state when enrichment produced no usable evidence."""
        return agent_reporting.inconclusive_correlation(self, state)

    def build_timeline(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Build attack timeline from anomalies
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "Menyusun timeline serangan...", 80
            )

        print("\n=== STAGE 5: TIMELINE CONSTRUCTION ===")
        self._emit_terminal(
            "=" * 60 + "\nSTAGE 5: TIMELINE CONSTRUCTION\n" + "=" * 60,
            progress=80,
            level="stage",
        )

        timeline = agent_timeline.build_attack_timeline(state)

        print(f"Built timeline with {len(timeline)} events")
        self._emit_terminal(
            f"Built timeline with {len(timeline)} events",
            progress=82,
            level="success",
        )

        return {
            "attack_timeline": timeline,
            "reasoning_steps": [
                f"Constructed attack timeline with {len(timeline)} events"
            ],
        }

    def generate_summary(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Node: Generate final investigation summary using LLM
        """
        return agent_reporting.generate_summary(self, state)

    def _extract_recommendations(self, llm_response: str) -> List[str]:
        """Extract recommendations from LLM response."""
        return agent_recommendations.extract_recommendations(llm_response)

    def _generate_default_recommendations(self, state: Mapping[str, Any]) -> List[str]:
        """Generate evidence-based fallback recommendations from current findings."""
        return agent_recommendations.generate_default_recommendations(
            state,
            self._summarize_anomaly_details,
        )

    def _is_malicious_tool_result(self, result: Dict[str, Any]) -> bool:
        return agent_recommendations.is_malicious_tool_result(result)

    def _is_suspicious_tool_result(self, result: Dict[str, Any]) -> bool:
        return agent_recommendations.is_suspicious_tool_result(result)

    def _safe_positive_count(self, value: Any) -> int:
        return agent_recommendations.safe_positive_count(value)

    def _select_priority_anomaly(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        return agent_recommendations.select_priority_anomaly(anomalies)

    def _format_anomaly_recommendation_context(self, anomaly: Dict[str, Any]) -> str:
        return agent_recommendations.format_anomaly_recommendation_context(anomaly)

    def _format_anomaly_artifacts(self, anomaly: Dict[str, Any]) -> str:
        return agent_recommendations.format_anomaly_artifacts(
            anomaly,
            self._summarize_anomaly_details,
        )

    def _format_tool_result_targets(self, results: List[Dict[str, Any]]) -> str:
        return agent_recommendations.format_tool_result_targets(results)

    def _format_ioc_sample(self, iocs: List[Dict[str, Any]]) -> str:
        return agent_recommendations.format_ioc_sample(iocs)

    def _extract_severity(self, llm_response: str) -> str:
        """Extract severity classification from LLM response"""
        return agent_recommendations.extract_severity(llm_response)

    # === Helper Methods ===

    def _identify_ioc_type(self, value: str) -> Optional[str]:
        """Identify type of IOC"""
        return agent_ioc.identify_ioc_type(value, self.EXECUTABLE_FILE_EXTENSIONS)

    def _looks_like_filename(self, value: str) -> bool:
        return agent_ioc.looks_like_filename(value, self.EXECUTABLE_FILE_EXTENSIONS)

    def _looks_like_script_token(self, value: str) -> bool:
        return agent_ioc.looks_like_script_token(value)

    def _create_tool_selection_prompt(self, iocs: List[Dict[str, Any]]) -> str:
        """Create prompt for tool selection using full toolset."""
        return agent_prompts.create_tool_selection_prompt(iocs)

    def _parse_tool_selections(
        self, llm_response: str, iocs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Parse LLM response for tool selections"""
        return agent_tooling.parse_tool_selections(
            llm_response,
            iocs,
            self.TOOL_TO_IOC_TYPES,
            self.STATIC_FALLBACK_TOOLS,
            self.TOOL_RESULT_ALIASES,
        )

    def _fallback_tool_selection(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback tool selection using simple heuristics"""
        return agent_tooling.fallback_tool_selection(
            iocs,
            self.STATIC_FALLBACK_TOOLS,
            self.TOOL_RESULT_ALIASES,
        )

    def _build_timeline_description(self, anomaly: Dict[str, Any]) -> str:
        return agent_timeline.build_timeline_description(anomaly)

    def _timeline_interpretation(self, threat_evidence: List[Dict[str, Any]]) -> str:
        return agent_timeline.timeline_interpretation(threat_evidence)

    def _summarize_anomaly_details(self, anomaly: Dict[str, Any]) -> str:
        return agent_timeline.summarize_anomaly_details(anomaly)

    def _resolve_timeline_timestamp(
        self, log_entry: pd.Series, anomaly: Dict[str, Any]
    ) -> Optional[str]:
        return agent_timeline.resolve_timeline_timestamp(log_entry, anomaly)

    def _create_correlation_prompt(
        self, anomalies: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
    ) -> str:
        """Create prompt for correlation using ReAct pattern"""
        return agent_prompts.create_correlation_prompt(
            anomalies,
            tool_results,
            summarize_anomaly_details=self._summarize_anomaly_details,
            is_malicious_tool_result=self._is_malicious_tool_result,
            is_suspicious_tool_result=self._is_suspicious_tool_result,
            safe_positive_count=self._safe_positive_count,
        )

    def _create_report_prompt(self, state: InvestigationState) -> str:
        """Create prompt for comprehensive report generation using ReAct pattern"""
        return agent_prompts.create_report_prompt(
            state,
            summarize_anomaly_details=self._summarize_anomaly_details,
            is_malicious_tool_result=self._is_malicious_tool_result,
        )

    def investigate(
        self,
        anomalies_df: pd.DataFrame,
        parsed_logs_df: pd.DataFrame,
        session_id: Optional[str] = None,
        status_callback=None,
        telemetry_callback=None,
    ) -> Dict[str, Any]:
        """
        Run full investigation pipeline

        Args:
            anomalies_df: DataFrame of detected anomalies
            parsed_logs_df: DataFrame of all parsed logs
            session_id: Session ID for status tracking
            status_callback: Callback function for status updates

        Returns:
            Investigation results dictionary
        """
        # Store callback
        self.session_id = session_id
        self.status_callback = status_callback
        self.telemetry_callback = telemetry_callback

        print("\n" + "=" * 60)
        print("STARTING AI AGENT INVESTIGATION")
        print("=" * 60)
        self._emit_terminal(
            "=" * 60 + "\nSTARTING AI AGENT INVESTIGATION\n" + "=" * 60,
            progress=60,
            level="stage",
        )

        # Convert anomalies DataFrame to list of dicts
        anomalies = anomalies_df.to_dict("records")

        initial_state = build_initial_state(
            anomalies,
            parsed_logs_df,
            max_reflection_rounds=self.DEFAULT_MAX_REFLECTION_ROUNDS,
            max_tool_execution_rounds=self.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS,
        )

        # Run graph
        try:
            final_state = self.app.invoke(initial_state)

            print("\n" + "=" * 60)
            print("INVESTIGATION COMPLETED")
            print("=" * 60)
            self._emit_terminal(
                "=" * 60 + "\nAI AGENT INVESTIGATION COMPLETED\n" + "=" * 60,
                progress=84,
                level="success",
            )

            return final_state

        except Exception as e:
            print(f"\nError during investigation: {e}")
            self._emit_terminal(
                f"[ERROR] Agent investigation failed: {e}",
                progress=84,
                level="error",
            )
            raise


if __name__ == "__main__":
    # Test agent
    agent = DFIRAgent()
    print("DFIR Agent initialized successfully")
