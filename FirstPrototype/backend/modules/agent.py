"""
LangGraph AI Agent for DFIR Investigation
Orchestrates investigation using ReAct pattern with Foundation-Sec-8B
"""

from typing import Dict, List, Any, TypedDict, Annotated, Optional, Mapping
import operator
import json
import re
import time
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd

from langgraph.graph import StateGraph, END

from modules.procedural_memory import ProceduralMemory
from modules.threat_intel import ThreatIntelToolkit


class InvestigationState(TypedDict):
    """State for investigation graph"""

    # Input
    anomalies: List[Dict[str, Any]]  # Anomalies from DeepLog
    parsed_logs: pd.DataFrame  # Full parsed logs

    # Episodic Memory
    iocs_extracted: List[Dict[str, Any]]  # Extracted IOCs
    tool_calls: Annotated[List[Dict[str, Any]], operator.add]  # Tool call history
    tool_results: Annotated[List[Dict[str, Any]], operator.add]  # Tool results
    reasoning_steps: Annotated[List[str], operator.add]  # Reasoning history
    planning_steps: Annotated[List[str], operator.add]  # Planning/decomposition history
    planned_tool_calls: Annotated[List[Dict[str, Any]], operator.add]
    planning_completed: bool
    planning_round: int
    max_planning_rounds: int
    reflection_steps: Annotated[List[str], operator.add]
    post_correlation_follow_up_calls: Annotated[List[Dict[str, Any]], operator.add]
    observation_assessment: str
    reflection_round: int
    max_reflection_rounds: int
    correlation_analysis: str  # Correlation analysis from LLM

    # Output
    investigation_summary: str
    attack_timeline: List[Dict[str, Any]]
    recommendations: List[str]

    # Control
    current_stage: str
    completed: bool
    tool_execution_round: int
    max_tool_execution_rounds: int


class DFIRAgent:
    """
    AI Agent for DFIR investigation orchestration
    Uses ReAct pattern: Reasoning → Action → Observation
    """

    IOC_TYPES = {"ip", "domain", "url", "md5", "sha256"}
    EXECUTABLE_FILE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".tmp",
        ".sys",
        ".dat",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".lnk",
    }
    TOOL_TO_IOC_TYPES = {
        "threatfox_lookup": {"ip", "domain", "url", "md5", "sha256"},
        "malwarebazaar_lookup": {"md5", "sha256"},
        "urlhaus_lookup": {"url"},
        "alienvault_otx_lookup": {"ip", "domain", "url", "md5", "sha256"},
        "greynoise_lookup": {"ip"},
        "virustotal_lookup": {"ip", "domain", "url", "md5", "sha256"},
    }
    TOOL_RESULT_ALIASES = {
        "threatfox": "threatfox_lookup",
        "malwarebazaar": "malwarebazaar_lookup",
        "urlhaus": "urlhaus_lookup",
        "otx": "alienvault_otx_lookup",
        "alienvault_otx": "alienvault_otx_lookup",
        "greynoise": "greynoise_lookup",
        "virustotal": "virustotal_lookup",
    }
    MEMORY_TOOL_TO_AGENT_TOOL = {
        "threatfox": "threatfox_lookup",
        "malwarebazaar": "malwarebazaar_lookup",
        "urlhaus": "urlhaus_lookup",
        "alienvault_otx": "alienvault_otx_lookup",
        "greynoise": "greynoise_lookup",
        "virustotal": "virustotal_lookup",
    }
    AGENT_TOOL_TO_MEMORY_TOOL = {
        "threatfox_lookup": "threatfox",
        "malwarebazaar_lookup": "malwarebazaar",
        "urlhaus_lookup": "urlhaus",
        "alienvault_otx_lookup": "alienvault_otx",
        "greynoise_lookup": "greynoise",
        "virustotal_lookup": "virustotal",
    }
    IOC_TYPE_TO_MEMORY_STRATEGY = {
        "ip": "ip_address",
        "md5": "file_hash",
        "sha256": "file_hash",
        "domain": "domain",
        "url": "url",
    }
    STATIC_FALLBACK_TOOLS = {
        "ip": [
            "greynoise_lookup",
            "threatfox_lookup",
            "alienvault_otx_lookup",
            "virustotal_lookup",
        ],
        "domain": [
            "threatfox_lookup",
            "alienvault_otx_lookup",
            "virustotal_lookup",
        ],
        "url": ["urlhaus_lookup", "threatfox_lookup", "virustotal_lookup"],
        "md5": ["malwarebazaar_lookup", "virustotal_lookup", "threatfox_lookup"],
        "sha256": ["malwarebazaar_lookup", "virustotal_lookup", "threatfox_lookup"],
    }
    DEFAULT_MAX_TOOL_EXECUTION_ROUNDS = 2
    DEFAULT_MAX_REFLECTION_ROUNDS = 1

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "foundation-sec-8b",
        threat_intel_api_keys: Dict[str, str] = None,
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
                num_ctx=4096,
                num_predict=2048,
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
        workflow.add_node("timeline_builder", self.build_timeline)
        workflow.add_node("report_generator", self.generate_summary)

        # Add edges (agentic control flow with bounded runtime routing)
        workflow.set_entry_point("ioc_extractor")
        workflow.add_edge("ioc_extractor", "planner")
        workflow.add_edge("planner", "tool_selector")
        workflow.add_edge("tool_selector", "tool_executor")
        workflow.add_conditional_edges(
            "tool_executor",
            self._decide_next_step,
            {
                "needs_more_intel": "tool_selector",
                "sufficient_intel": "correlator",
                "no_iocs": "report_generator",
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
        workflow.add_edge("report_generator", END)

        return workflow

    def _decide_next_step(self, state: InvestigationState) -> str:
        """Route the graph based on observations from the latest tool round."""
        iocs = state.get("iocs_extracted") or []
        if not iocs:
            print("Routing decision: no_iocs (no extracted IOCs to enrich)")
            return "no_iocs"

        current_round = self._coerce_int(state.get("tool_execution_round"), 0)
        max_rounds = self._coerce_int(
            state.get("max_tool_execution_rounds"),
            self.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS,
        )
        if current_round >= max_rounds:
            print(
                "Routing decision: sufficient_intel "
                f"(tool round limit reached: {current_round}/{max_rounds})"
            )
            return "sufficient_intel"

        follow_up_calls = self._select_follow_up_tool_calls(state)
        if follow_up_calls:
            print(
                "Routing decision: needs_more_intel "
                f"({len(follow_up_calls)} unqueried enrichment tools available)"
            )
            return "needs_more_intel"

        print("Routing decision: sufficient_intel (no follow-up tools needed)")
        return "sufficient_intel"

    def extract_iocs(self, state: InvestigationState) -> Dict:
        """
        Node: Extract IOCs from anomalous log parameters
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "Mengekstrak IOCs dari logs...", 62
            )

        print("\n=== STAGE 1: IOC EXTRACTION ===")

        anomalies = state["anomalies"]
        parsed_logs = state["parsed_logs"]

        iocs = []

        for anomaly in anomalies:
            # Get logs for this anomaly window
            start_idx = anomaly["start_idx"]
            end_idx = anomaly["end_idx"]
            window_logs = parsed_logs.iloc[start_idx : end_idx + 1]

            # Extract IOCs from parameters
            for _, log_entry in window_logs.iterrows():
                params = json.loads(log_entry.get("parameters", "[]"))

                for param in params:
                    ioc_type = self._identify_ioc_type(param)
                    if ioc_type:
                        iocs.append(
                            {
                                "value": param,
                                "type": ioc_type,
                                "source_line": log_entry["event_id"],
                                "window_id": anomaly["window_id"],
                            }
                        )

        # Deduplicate IOCs
        unique_iocs = []
        seen = set()
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        print(f"Extracted {len(unique_iocs)} unique IOCs")
        for ioc in unique_iocs[:5]:  # Show first 5
            print(f"  - {ioc['type']}: {ioc['value']}")

        return {
            "iocs_extracted": unique_iocs,
            "current_stage": "ioc_extraction_complete",
            "reasoning_steps": [
                f"Extracted {len(unique_iocs)} IOCs from anomalous windows"
            ],
        }

    def plan_goals(self, state: InvestigationState) -> Dict:
        """
        Node: Decompose extracted IOCs into an explicit, bounded investigation plan.

        The planner is fail-open and additive: it never increments the threat-intel
        execution round, and tool selection can still fall back to existing paths.
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "AI sedang menyusun rencana investigasi IOC...",
                65,
            )

        print("\n=== STAGE 2: INVESTIGATION PLANNING ===")

        iocs = state.get("iocs_extracted") or []
        planning_round = self._coerce_int(state.get("planning_round"), 0) + 1
        max_rounds = self._coerce_int(state.get("max_planning_rounds"), 1)

        if not iocs:
            print("No IOCs available for planning")
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
            return {
                "planned_tool_calls": [],
                "planning_steps": [
                    "Planner deferred to tool selector because the planning round limit was reached"
                ],
                "planning_completed": False,
                "planning_round": planning_round,
                "current_stage": "planning_deferred",
            }

        memory_tool_calls, memory_reasons = self._select_tools_from_memory(iocs)
        plan_source = "procedural memory"
        candidate_calls = memory_tool_calls
        planning_steps = list(memory_reasons[:5])

        if not candidate_calls:
            candidate_calls = self._fallback_tool_selection(iocs)
            plan_source = "static IOC playbook"
            planning_steps.append(
                "Planner used static IOC playbooks because procedural memory did not provide supported tools"
            )

        planned_calls = self._dedupe_tool_calls(candidate_calls)
        print(
            f"Planner selected {len(planned_calls)} tool calls from {plan_source} "
            f"for {len(iocs)} IOCs"
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

    def select_tools(self, state: InvestigationState) -> Dict:
        """
        Node: Use LLM to select appropriate threat intel tools for each IOC
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "AI sedang memilih tools untuk analisis...",
                67,
            )

        print("\n=== STAGE 2: TOOL SELECTION ===")

        iocs = state["iocs_extracted"]

        if not iocs:
            print("No IOCs to investigate")
            return {
                "tool_calls": [],
                "reasoning_steps": ["No IOCs extracted, skipping tool selection"],
            }

        print(f"IOCs to analyze: {len(iocs)}")

        reflection_tool_calls = self._select_new_reflection_tool_calls(state)
        if reflection_tool_calls:
            print(
                "Reflection loop provided "
                f"{len(reflection_tool_calls)} targeted follow-up tool calls"
            )
            return {
                "tool_calls": reflection_tool_calls,
                "current_stage": "reflection_guided_tool_selection_complete",
                "reasoning_steps": [
                    f"Used post-correlation reflection output for {len(reflection_tool_calls)} follow-up tool calls"
                ],
            }

        tool_execution_round = self._coerce_int(state.get("tool_execution_round"), 0)
        if tool_execution_round > 0:
            tool_calls = self._select_follow_up_tool_calls(state)
            print(
                "Follow-up selection round "
                f"{tool_execution_round + 1}: {len(tool_calls)} new tool calls"
            )
            if not tool_calls:
                return {
                    "tool_calls": [],
                    "current_stage": "follow_up_tool_selection_complete",
                    "reasoning_steps": [
                        "No unqueried follow-up tools remained after reviewing observations"
                    ],
                }

            return {
                "tool_calls": tool_calls,
                "current_stage": "follow_up_tool_selection_complete",
                "reasoning_steps": [
                    f"Selected {len(tool_calls)} follow-up tool calls based on prior observations"
                ],
            }

        planned_tool_calls = self._select_new_planned_tool_calls(state)
        if planned_tool_calls:
            print(
                "Planner provided "
                f"{len(planned_tool_calls)} ready-to-execute tool calls"
            )
            return {
                "tool_calls": planned_tool_calls,
                "current_stage": "planner_guided_tool_selection_complete",
                "reasoning_steps": [
                    f"Used Phase 4 planner output for {len(planned_tool_calls)} initial tool calls"
                ],
            }

        memory_tool_calls, memory_reasons = self._select_tools_from_memory(iocs)
        if memory_tool_calls:
            print(
                "Procedural memory selected "
                f"{len(memory_tool_calls)} tool calls for {len(iocs)} IOCs"
            )
            return {
                "tool_calls": memory_tool_calls,
                "current_stage": "memory_guided_tool_selection_complete",
                "reasoning_steps": [
                    f"Procedural memory selected {len(memory_tool_calls)} tool calls"
                ]
                + memory_reasons[:5],
            }

        # Create prompt for LLM
        prompt = self._create_tool_selection_prompt(iocs)
        print(f"\nPrompt length: {len(prompt)} chars")
        print("Sending tool selection request to LLM...")

        # Get LLM response
        try:
            import time

            start_time = time.time()
            response = self.llm.invoke(prompt)
            elapsed = time.time() - start_time

            print(f"\n[OK] LLM Response received ({elapsed:.2f}s)")
            print("-" * 60)
            print(f"Response preview:\n{response[:300]}")
            if len(response) > 300:
                print(f"... ({len(response) - 300} more chars)")
            print("-" * 60)

            # Parse tool selections
            tool_calls = self._parse_tool_selections(response, iocs)

            print(f"\nParsed {len(tool_calls)} tool calls:")
            tool_summary = {}
            for call in tool_calls:
                tool_summary[call["tool"]] = tool_summary.get(call["tool"], 0) + 1

            for tool, count in tool_summary.items():
                print(f"  - {tool}: {count} calls")

            # Show examples
            if tool_calls:
                print("\nExample tool calls:")
                for call in tool_calls[:3]:
                    print(
                        f"  - {call['tool']} for {call['ioc_type']}: {call['ioc'][:50]}"
                    )

            return {
                "tool_calls": tool_calls,
                "reasoning_steps": [
                    f"Selected {len(tool_calls)} tool calls based on IOC types"
                ],
            }

        except Exception as e:
            print(f"\n[WARN] Error in tool selection: {e}")
            import traceback

            print(traceback.format_exc())
            # Fallback: use simple heuristics
            print("\nUsing fallback tool selection...")
            tool_calls = self._fallback_tool_selection(iocs)
            return {
                "tool_calls": tool_calls,
                "reasoning_steps": [f"Used fallback tool selection due to error: {e}"],
            }

    def execute_tools(self, state: InvestigationState) -> Dict:
        """
        Node: Execute selected threat intel tools
        """
        if self.status_callback and self.session_id:
            selected_tools = [t["tool"] for t in state.get("tool_calls", [])]
            if selected_tools:
                tool_names = ", ".join(set(selected_tools[:3]))  # Unique tools
                self.status_callback(
                    self.session_id,
                    "ai_agent",
                    f"Menggunakan tools: {tool_names}...",
                    72,
                )
            else:
                self.status_callback(
                    self.session_id,
                    "ai_agent",
                    "Menjalankan threat intelligence tools...",
                    72,
                )

        print("\n=== STAGE 3: TOOL EXECUTION ===")
        all_tool_calls = state["tool_calls"]
        executed_keys = self._attempted_tool_call_keys(state)
        tool_calls = [
            call
            for call in all_tool_calls
            if self._tool_call_key(call) not in executed_keys
        ]
        skipped_existing = len(all_tool_calls) - len(tool_calls)
        print(f"Total tool calls in state: {len(all_tool_calls)}")
        print(f"New tool calls to execute: {len(tool_calls)}")
        if skipped_existing:
            print(f"Skipping {skipped_existing} previously executed tool calls")

        results = []
        next_round = self._coerce_int(state.get("tool_execution_round"), 0) + 1

        if not tool_calls:
            return {
                "tool_results": [],
                "tool_execution_round": next_round,
                "current_stage": "tool_execution_complete",
                "reasoning_steps": [
                    f"No new threat intel queries to execute in round {next_round}"
                ],
            }

        for idx, call in enumerate(tool_calls, 1):
            tool_name = str(call["tool"])
            ioc = str(call["ioc"])
            ioc_type = str(call["ioc_type"]).lower()

            print(f"\n[{idx}/{len(tool_calls)}] Executing: {tool_name}")
            print(f"  IOC: {ioc} (type: {ioc_type})")
            start_time = time.time()

            try:
                skip_reason = self._get_tool_call_skip_reason(tool_name, ioc, ioc_type)
                if skip_reason:
                    elapsed = time.time() - start_time
                    result = {
                        "tool": tool_name,
                        "ioc": ioc,
                        "ioc_type": ioc_type,
                        "status": "skipped",
                        "skipped": True,
                        "reason": skip_reason,
                    }
                    print(f"  [SKIP] ({elapsed:.2f}s): {skip_reason}")
                    results.append(result)
                    continue

                if tool_name == "threatfox_lookup":
                    threatfox_ioc_type = {
                        "md5": "md5_hash",
                        "sha256": "sha256_hash",
                    }.get(ioc_type, ioc_type)
                    result = self.threat_intel.threatfox_lookup(ioc, threatfox_ioc_type)
                elif tool_name == "malwarebazaar_lookup":
                    result = self.threat_intel.malwarebazaar_lookup(ioc)
                elif tool_name == "urlhaus_lookup":
                    result = self.threat_intel.urlhaus_lookup(ioc)
                elif tool_name == "alienvault_otx_lookup":
                    otx_ioc_type = "IPv4" if ioc_type == "ip" else ioc_type
                    result = self.threat_intel.alienvault_otx_lookup(ioc, otx_ioc_type)
                elif tool_name == "greynoise_lookup":
                    result = self.threat_intel.greynoise_lookup(ioc)
                elif tool_name == "virustotal_lookup":
                    vt_ioc_type = "file" if ioc_type in ["md5", "sha256"] else ioc_type
                    result = self.threat_intel.virustotal_lookup(ioc, vt_ioc_type)
                else:
                    result = {"error": f"Unknown tool: {tool_name}"}

                result.setdefault("tool_call", tool_name)
                result.setdefault("ioc", ioc)
                result.setdefault("ioc_type", ioc_type)

                elapsed = time.time() - start_time
                self._record_tool_performance(tool_name, result, elapsed, ioc_type)

                # Print result summary
                if "error" in result:
                    print(f"  [WARN] Error: {result['error']}")
                elif result.get("data"):
                    print(f"  [OK] Success ({elapsed:.2f}s): Found data")
                    # Print brief summary
                    if isinstance(result["data"], dict):
                        keys = list(result["data"].keys())[:3]
                        print(f"    Keys: {keys}")
                    elif isinstance(result["data"], list):
                        print(f"    Results: {len(result['data'])} items")
                else:
                    print(f"  [OK] Completed ({elapsed:.2f}s): No data found")

                results.append(result)

            except Exception as e:
                print(f"  [ERROR] Exception: {e}")
                import traceback

                print(f"  Traceback: {traceback.format_exc()[:200]}")
                elapsed = time.time() - start_time
                result = {
                    "tool": tool_name,
                    "tool_call": tool_name,
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "error": str(e),
                    "status": "error",
                }
                self._record_tool_performance(tool_name, result, elapsed, ioc_type)
                results.append(result)

        print(f"Executed {len(results)} tool calls")

        return {
            "tool_results": results,
            "tool_execution_round": next_round,
            "current_stage": "tool_execution_complete",
            "reasoning_steps": [
                f"Executed {len(results)} threat intel queries in round {next_round}"
            ],
        }

    def _get_tool_call_skip_reason(
        self, tool_name: str, ioc: str, ioc_type: str
    ) -> Optional[str]:
        supported_ioc_types = self.TOOL_TO_IOC_TYPES.get(tool_name)
        if supported_ioc_types is None:
            return f"unsupported tool '{tool_name}'"

        normalized_ioc_type = str(ioc_type or "").lower()
        if normalized_ioc_type not in self.IOC_TYPES:
            return f"unsupported IOC type '{ioc_type}'"

        if normalized_ioc_type not in supported_ioc_types:
            return f"tool '{tool_name}' does not support IOC type '{ioc_type}'"

        identified_ioc_type = self._identify_ioc_type(ioc)
        if identified_ioc_type is None:
            return "IOC value failed validation"

        if identified_ioc_type != normalized_ioc_type:
            return (
                f"IOC value matches type '{identified_ioc_type}', not '{normalized_ioc_type}'"
            )

        return None

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
                call = {"ioc": ioc_value, "ioc_type": ioc_type, "tool": tool_name}
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
        planned_calls = state.get("planned_tool_calls") or []
        if not planned_calls:
            return []

        attempted_keys = self._attempted_tool_call_keys(state)
        return [
            call
            for call in self._dedupe_tool_calls(planned_calls)
            if self._tool_call_key(call) not in attempted_keys
        ]

    def _select_new_reflection_tool_calls(
        self, state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Return post-correlation reflection calls that remain unattempted."""
        follow_up_calls = state.get("post_correlation_follow_up_calls") or []
        if not follow_up_calls:
            return []

        attempted_keys = self._attempted_tool_call_keys(state)
        return [
            call
            for call in self._dedupe_tool_calls(follow_up_calls)
            if self._tool_call_key(call) not in attempted_keys
        ]

    def _dedupe_tool_calls(
        self, tool_calls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Normalize and deduplicate executable tool calls while preserving order."""
        deduped = []
        seen = set()

        for call in tool_calls:
            tool_name = self._normalize_tool_name(call.get("tool"))
            ioc_type = str(call.get("ioc_type") or "").lower()
            ioc_value = str(call.get("ioc") or "")
            if not tool_name or not ioc_type or not ioc_value:
                continue
            if tool_name not in self.TOOL_TO_IOC_TYPES:
                continue
            if ioc_type not in self.TOOL_TO_IOC_TYPES.get(tool_name, set()):
                continue

            normalized_call = {"ioc": ioc_value, "ioc_type": ioc_type, "tool": tool_name}
            key = self._tool_call_key(normalized_call)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(normalized_call)

        return deduped

    def _memory_strategy_tool_names(self, strategy: Mapping[str, Any]) -> List[str]:
        """Convert ProceduralMemory primary/fallback tool keys to agent tool names."""
        tool_names = []
        raw_tools = [strategy.get("primary")] + list(strategy.get("fallback") or [])

        for raw_tool in raw_tools:
            tool_name = self._agent_tool_name(raw_tool)
            if not tool_name or tool_name in tool_names:
                continue
            tool_names.append(tool_name)

        return tool_names

    def _agent_tool_name(self, memory_tool_name: Any) -> Optional[str]:
        normalized = str(memory_tool_name or "").strip().lower()
        if not normalized:
            return None
        return self.MEMORY_TOOL_TO_AGENT_TOOL.get(normalized)

    def _memory_tool_name(self, agent_tool_name: Any) -> str:
        normalized = self._normalize_tool_name(agent_tool_name)
        return self.AGENT_TOOL_TO_MEMORY_TOOL.get(normalized, normalized)

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
        if result.get("error") or result.get("status") == "error":
            return False
        if result.get("status") == "skipped" or result.get("skipped"):
            return False
        return True

    def _select_follow_up_tool_calls(
        self, state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Select unqueried enrichment tools for IOCs with suspicious observations."""
        iocs = state.get("iocs_extracted") or []
        follow_up_ioc_keys = self._follow_up_ioc_keys(state)
        if not iocs or not follow_up_ioc_keys:
            return []

        candidate_iocs = [
            ioc
            for ioc in iocs
            if (
                str(ioc.get("type", "")).lower(),
                str(ioc.get("value", "")),
            )
            in follow_up_ioc_keys
        ]
        attempted_keys = self._attempted_tool_call_keys(state)
        selected_calls = []
        selected_keys = set()

        for call in self._fallback_tool_selection(candidate_iocs):
            key = self._tool_call_key(call)
            if key in attempted_keys or key in selected_keys:
                continue
            selected_calls.append(call)
            selected_keys.add(key)

        return selected_calls

    def _follow_up_ioc_keys(self, state: InvestigationState) -> set[tuple[str, str]]:
        """Return IOC keys that deserve another enrichment round."""
        keys = set()
        for result in state.get("tool_results") or []:
            if not (
                self._is_malicious_tool_result(result)
                or self._is_suspicious_tool_result(result)
            ):
                continue

            ioc_value = self._extract_tool_result_ioc(result)
            if not ioc_value:
                continue

            ioc_type = str(result.get("ioc_type") or "").lower()
            if not ioc_type:
                ioc_type = self._identify_ioc_type(ioc_value) or ""
            if ioc_type:
                keys.add((ioc_type, str(ioc_value)))

        return keys

    def _attempted_tool_call_keys(
        self, state: InvestigationState
    ) -> set[tuple[str, str, str]]:
        """Return tool/IOC combinations that already produced an observation."""
        keys = set()
        for result in state.get("tool_results") or []:
            key = self._tool_result_key(result)
            if key:
                keys.add(key)
        return keys

    def _tool_call_key(self, call: Mapping[str, Any]) -> tuple[str, str, str]:
        tool_name = self._normalize_tool_name(call.get("tool"))
        ioc_type = str(call.get("ioc_type") or "").lower()
        ioc_value = str(call.get("ioc") or "")
        return (tool_name, ioc_type, ioc_value)

    def _tool_result_key(
        self, result: Mapping[str, Any]
    ) -> Optional[tuple[str, str, str]]:
        tool_name = self._normalize_tool_name(
            result.get("tool_call") or result.get("tool")
        )
        ioc_value = self._extract_tool_result_ioc(result)
        ioc_type = str(result.get("ioc_type") or "").lower()
        if not ioc_type and ioc_value:
            ioc_type = self._identify_ioc_type(ioc_value) or ""

        if not tool_name or not ioc_type or not ioc_value:
            return None
        return (tool_name, ioc_type, str(ioc_value))

    def _normalize_tool_name(self, tool_name: Any) -> str:
        normalized = str(tool_name or "").strip().lower()
        return self.TOOL_RESULT_ALIASES.get(normalized, normalized)

    def _extract_tool_result_ioc(self, result: Mapping[str, Any]) -> str:
        return str(
            result.get("ioc")
            or result.get("ip")
            or result.get("domain")
            or result.get("url")
            or result.get("hash")
            or ""
        )

    def _coerce_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def correlate_findings(self, state: InvestigationState) -> Dict:
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

        tool_results = state["tool_results"]
        anomalies = state["anomalies"]

        print(f"Input data:")
        print(f"  - Anomalies: {len(anomalies)}")
        print(f"  - Tool results: {len(tool_results)}")
        print(
            f"  - Malicious IOCs: {sum(1 for r in tool_results if r.get('malware_family'))}"
        )

        # Create correlation prompt
        prompt = self._create_correlation_prompt(anomalies, tool_results)
        print(f"\nPrompt length: {len(prompt)} chars")
        print("Sending correlation request to LLM...")

        try:
            import time

            start_time = time.time()
            response = self.llm.invoke(prompt)
            elapsed = time.time() - start_time

            print(f"\n[OK] LLM Correlation Analysis Complete ({elapsed:.2f}s)")
            print("=" * 60)
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
            import traceback

            print(traceback.format_exc())
            return {
                "correlation_analysis": f"Correlation error: {str(e)}",
                "reasoning_steps": [f"Correlation error: {e}"],
            }

    def post_correlation_assessment(self, state: InvestigationState) -> Dict:
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

        current_round = self._coerce_int(state.get("reflection_round"), 0)
        max_rounds = self._coerce_int(
            state.get("max_reflection_rounds"), self.DEFAULT_MAX_REFLECTION_ROUNDS
        )
        next_round = current_round + 1

        if not state.get("iocs_extracted"):
            assessment = "Reflection skipped because no IOCs were extracted."
            print(assessment)
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
        if not state.get("iocs_extracted"):
            print("Reflection routing: no_iocs")
            return "no_iocs"

        current_round = self._coerce_int(state.get("reflection_round"), 0)
        max_rounds = self._coerce_int(
            state.get("max_reflection_rounds"), self.DEFAULT_MAX_REFLECTION_ROUNDS
        )
        if current_round > max_rounds:
            print(
                "Reflection routing: sufficient_after_reflection "
                f"(limit reached: {current_round}/{max_rounds})"
            )
            return "sufficient_after_reflection"

        follow_up_calls = self._select_new_reflection_tool_calls(state)
        if follow_up_calls:
            print(
                "Reflection routing: more_intel_needed "
                f"({len(follow_up_calls)} targeted follow-up calls)"
            )
            return "more_intel_needed"

        print("Reflection routing: sufficient_after_reflection")
        return "sufficient_after_reflection"

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

    def build_timeline(self, state: InvestigationState) -> Dict:
        """
        Node: Build attack timeline from anomalies
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "Menyusun timeline serangan...", 80
            )

        print("\n=== STAGE 5: TIMELINE CONSTRUCTION ===")

        anomalies = state["anomalies"]
        parsed_logs = state["parsed_logs"]

        timeline = []

        for anomaly in anomalies:
            start_idx = anomaly["start_idx"]

            # Get representative log from window
            if start_idx < len(parsed_logs):
                log_entry = parsed_logs.iloc[start_idx]

                timeline.append(
                    {
                        "window_id": anomaly["window_id"],
                        "timestamp": self._resolve_timeline_timestamp(
                            log_entry, anomaly
                        ),
                        "event_template": anomaly["actual_event"],
                        "severity": "high" if anomaly["is_anomaly"] else "normal",
                        "description": self._build_timeline_description(anomaly),
                    }
                )

        # Sort by window_id (chronological)
        timeline.sort(key=lambda x: x["window_id"])

        print(f"Built timeline with {len(timeline)} events")

        return {
            "attack_timeline": timeline,
            "reasoning_steps": [
                f"Constructed attack timeline with {len(timeline)} events"
            ],
        }

    def generate_summary(self, state: InvestigationState) -> Dict:
        """
        Node: Generate final investigation summary using LLM
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "AI sedang menulis summary...", 83
            )

        print("\n=== STAGE 6: REPORT GENERATION ===")
        print("Generating comprehensive investigation summary with LLM...")

        # Create report generation prompt
        prompt = self._create_report_prompt(state)
        print(f"Prompt length: {len(prompt)} chars")
        print("Sending report generation request to LLM...")

        try:
            import time

            start_time = time.time()
            response = self.llm.invoke(prompt)
            elapsed = time.time() - start_time

            print(f"\n[OK] Investigation Summary Generated ({elapsed:.2f}s)")
            print("-" * 60)
            print(response[:500] + ("..." if len(response) > 500 else ""))
            print("-" * 60)

            # Extract recommendations from LLM response
            recommendations = self._extract_recommendations(response)

            # If extraction fails, use intelligent defaults based on findings
            if not recommendations:
                recommendations = self._generate_default_recommendations(state)

            print(f"\nExtracted Recommendations: {len(recommendations)} items")
            for idx, rec in enumerate(recommendations[:5], 1):
                print(f"  {idx}. {rec[:80]}...")

            return {
                "investigation_summary": response,
                "recommendations": recommendations,
                "current_stage": "completed",
                "completed": True,
                "reasoning_steps": [
                    "Generated comprehensive executive summary with ReAct reasoning"
                ],
            }

        except Exception as e:
            print(f"[WARN] Error generating summary: {e}")
            import traceback

            print(traceback.format_exc())
            return {
                "investigation_summary": f"Error generating summary: {e}",
                "recommendations": self._generate_default_recommendations(state),
                "current_stage": "error",
                "completed": True,
            }

    def _extract_recommendations(self, llm_response: str) -> List[str]:
        """Extract recommendations from LLM response"""
        recommendations = []

        # Look for recommendations section
        if (
            "RECOMMENDATIONS" in llm_response.upper()
            or "REKOMENDASI" in llm_response.upper()
        ):
            lines = llm_response.split("\n")
            in_recommendations = False

            for line in lines:
                # Start capturing
                if "RECOMMENDATION" in line.upper() or "REKOMENDASI" in line.upper():
                    in_recommendations = True
                    continue

                # Stop at next major section
                if in_recommendations and line.strip().startswith("#"):
                    break

                # Capture numbered or bulleted items
                if in_recommendations:
                    stripped = line.strip()
                    if stripped and (
                        stripped[0].isdigit() or stripped.startswith(("-", "•", "*"))
                    ):
                        # Clean up numbering
                        rec = stripped.lstrip("0123456789.-•* ")
                        if len(rec) > 10:  # Meaningful recommendation
                            recommendations.append(rec)

        return recommendations[:10]  # Max 10 recommendations

    def _generate_default_recommendations(self, state: Mapping[str, Any]) -> List[str]:
        """Generate evidence-based fallback recommendations from current findings."""
        anomalies = state.get("anomalies", []) or []
        tool_results = state.get("tool_results", []) or []
        iocs = state.get("iocs_extracted", []) or []
        timeline = state.get("attack_timeline", []) or []
        recommendations = []

        malicious_results = [
            result for result in tool_results if self._is_malicious_tool_result(result)
        ]
        suspicious_results = [
            result
            for result in tool_results
            if not self._is_malicious_tool_result(result)
            and self._is_suspicious_tool_result(result)
        ]
        priority_anomaly = self._select_priority_anomaly(anomalies)
        anomaly_context = self._format_anomaly_recommendation_context(priority_anomaly)
        artifact_context = self._format_anomaly_artifacts(priority_anomaly)
        top_iocs = self._format_ioc_sample(iocs)

        if malicious_results:
            recommendations.append(
                f"Segera containment aset yang terkait dengan IOC malicious {self._format_tool_result_targets(malicious_results[:5])}; korelasikan dengan {anomaly_context}."
            )
            recommendations.append(
                "Blokir IOC malicious pada firewall, proxy, DNS sinkhole, EDR, dan SIEM lalu hunt kemunculan ulang pada host lain."
            )

        if suspicious_results:
            recommendations.append(
                f"Validasi IOC suspicious {self._format_tool_result_targets(suspicious_results[:5])} menggunakan log internal sebelum menaikkan verdict menjadi confirmed incident."
            )

        if priority_anomaly:
            recommendations.append(
                f"Triase {anomaly_context}; periksa raw log, process tree, user, parent process, command line, dan event sebelum/sesudah window tersebut."
            )

        if artifact_context:
            recommendations.append(
                f"Kumpulkan artefak forensik yang relevan dengan {artifact_context}, termasuk event log lengkap, prefetch/process execution, registry autorun, dan koneksi jaringan."
            )

        if top_iocs and not malicious_results:
            recommendations.append(
                f"Enrich dan korelasikan IOC terkurasi {top_iocs} dengan EDR, DNS, proxy, asset inventory, dan threat intelligence tambahan."
            )

        if timeline:
            recommendations.append(
                f"Gunakan {len(timeline)} item timeline untuk memastikan urutan kejadian dan menentukan apakah aktivitas ini merupakan chain serangan atau anomali terpisah."
            )

        if anomalies and not malicious_results and not suspicious_results:
            recommendations.append(
                f"Validasi {len(anomalies)} anomali DeepLog terhadap baseline operasional; jangan langsung tuning model sebelum window prioritas dan artefaknya dinyatakan false positive."
            )

        if not recommendations:
            recommendations.append(
                "Tidak ada deteksi prioritas yang cukup kuat; simpan hasil sebagai baseline dan lanjutkan monitoring pada pola log yang sama."
            )

        return recommendations[:10]

    def _is_malicious_tool_result(self, result: Dict[str, Any]) -> bool:
        if not result or result.get("status") == "skipped" or result.get("skipped"):
            return False
        return (
            result.get("classification") == "malicious"
            or bool(result.get("malware_family"))
            or self._safe_positive_count(result.get("malicious")) > 0
        )

    def _is_suspicious_tool_result(self, result: Dict[str, Any]) -> bool:
        if not result or result.get("status") == "skipped" or result.get("skipped"):
            return False
        return (
            result.get("classification") == "suspicious"
            or self._safe_positive_count(result.get("suspicious")) > 0
        )

    def _safe_positive_count(self, value: Any) -> int:
        try:
            return max(int(value or 0), 0)
        except (TypeError, ValueError):
            return 0

    def _select_priority_anomaly(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not anomalies:
            return {}

        def priority(anomaly: Dict[str, Any]):
            score = anomaly.get("anomaly_score") or anomaly.get("score") or 0
            try:
                numeric_score = float(score)
            except (TypeError, ValueError):
                numeric_score = 0.0
            return numeric_score, int(bool(anomaly.get("strict_is_anomaly")))

        return max(anomalies, key=priority)

    def _format_anomaly_recommendation_context(self, anomaly: Dict[str, Any]) -> str:
        if not anomaly:
            return "window anomali prioritas"

        parts = [f"window DeepLog {anomaly.get('window_id', '-')}"]
        score = anomaly.get("anomaly_score") or anomaly.get("score")
        if score is not None:
            try:
                parts.append(f"score {float(score):.3f}")
            except (TypeError, ValueError):
                parts.append(f"score {score}")

        event = str(anomaly.get("actual_event") or "").strip()
        if event:
            parts.append(f"event `{event[:120]}`")

        return " / ".join(parts)

    def _format_anomaly_artifacts(self, anomaly: Dict[str, Any]) -> str:
        if not anomaly:
            return ""
        return self._summarize_anomaly_details(anomaly)

    def _format_tool_result_targets(self, results: List[Dict[str, Any]]) -> str:
        targets = []
        for result in results:
            target = (
                result.get("ioc")
                or result.get("ip")
                or result.get("url")
                or result.get("hash")
            )
            if target:
                targets.append(f"`{target}`")
        return ", ".join(targets) if targets else "yang ditemukan threat intelligence"

    def _format_ioc_sample(self, iocs: List[Dict[str, Any]]) -> str:
        values = []
        for ioc in iocs[:5]:
            value = ioc.get("value")
            ioc_type = ioc.get("type", "ioc")
            if value:
                values.append(f"{ioc_type} `{value}`")
        return ", ".join(values)

    def _extract_severity(self, llm_response: str) -> str:
        """Extract severity classification from LLM response"""
        response_upper = llm_response.upper()

        # Look for severity keywords
        if "CRITICAL" in response_upper or "KRITIS" in response_upper:
            return "CRITICAL"
        elif "HIGH" in response_upper or "TINGGI" in response_upper:
            return "HIGH"
        elif "MEDIUM" in response_upper or "SEDANG" in response_upper:
            return "MEDIUM"
        elif "LOW" in response_upper or "RENDAH" in response_upper:
            return "LOW"

        # Default based on malicious IOCs count
        return "MEDIUM"

    # === Helper Methods ===

    def _identify_ioc_type(self, value: str) -> Optional[str]:
        """Identify type of IOC"""
        normalized_value = str(value or "").strip()
        if not normalized_value:
            return None

        lowered = normalized_value.lower()

        try:
            ip_address(normalized_value)
            return "ip"
        except ValueError:
            pass

        if normalized_value.startswith(("http://", "https://")):
            parsed_url = urlparse(normalized_value)
            if parsed_url.scheme and parsed_url.netloc:
                return "url"

        if re.fullmatch(r"[a-fA-F0-9]{64}", normalized_value):
            return "sha256"

        if re.fullmatch(r"[a-fA-F0-9]{32}", normalized_value):
            return "md5"

        if any(char in normalized_value for char in ("\\", "/", ":", " ")):
            return None

        if self._looks_like_filename(lowered):
            return None

        if self._looks_like_script_token(normalized_value):
            return None

        if re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", normalized_value):
            return "domain"

        return None

    def _looks_like_filename(self, value: str) -> bool:
        file_suffix = Path(value).suffix.lower()
        if file_suffix in self.EXECUTABLE_FILE_EXTENSIONS:
            return True
        return value in {"localhost", "localdomain"}

    def _looks_like_script_token(self, value: str) -> bool:
        parts = value.split(".")
        if len(parts) < 2:
            return False

        if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", part) for part in parts):
            return False

        lowered_parts = [part.lower() for part in parts]
        first_part = lowered_parts[0]
        last_part = lowered_parts[-1]

        if first_part in {"wscript", "cscript"} and last_part in {
            "shell",
            "createobject",
            "network",
        }:
            return True

        if first_part in {"objshell", "wshshell", "shell"} and last_part in {
            "run",
            "exec",
            "expandenvironmentstrings",
            "regread",
            "regwrite",
            "regdelete",
            "specialfolders",
            "environment",
            "application",
        }:
            return True

        if first_part == "scripting" and last_part == "filesystemobject":
            return True

        if first_part == "adodb" and last_part in {"stream", "connection", "recordset"}:
            return True

        if first_part.startswith("obj") and last_part in {"run", "exec"}:
            return True

        return False

    def _create_tool_selection_prompt(self, iocs: List[Dict]) -> str:
        """Create prompt for tool selection using full toolset."""
        iocs_text = "\n".join(
            [f"- {ioc['type'].upper()}: {ioc['value']}" for ioc in iocs[:15]]
        )

        prompt = f"""# DFIR Tool Selection - Threat Intel Framework

Anda adalah Security Analyst TNI AL yang ahli dalam Digital Forensics & Incident Response.
Tugas: pilih threat intelligence tools yang paling tepat untuk setiap IOC.

## CONTEXT
Total IOC Extracted: {len(iocs)}

**IOC List:**
{iocs_text}

## AVAILABLE TOOLS

1) threatfox_lookup
- Input: IP/domain/url/hash
- Kelebihan: IOC abuse.ch feed, malware family, threat type

2) malwarebazaar_lookup
- Input: MD5/SHA256 file hash
- Kelebihan: file sample intel, signature, tags

3) urlhaus_lookup
- Input: URL saja
- Kelebihan: URL malware hosting status dan payload context

4) alienvault_otx_lookup
- Input: IP/domain/url/hash
- Kelebihan: pulse komunitas, reputasi, IOC relasi

5) greynoise_lookup
- Input: IP saja
- Kelebihan: klasifikasi scanner/noise vs malicious

6) virustotal_lookup
- Input: IP/domain/url/file hash
- Kelebihan: agregasi multi-engine reputation

## MAPPING GUIDELINES
- IP: prioritaskan greynoise_lookup dan threatfox_lookup; tambahkan alienvault_otx_lookup atau virustotal_lookup bila perlu reputasi tambahan.
- Domain: prioritaskan threatfox_lookup, alienvault_otx_lookup, atau virustotal_lookup.
- URL: prioritaskan urlhaus_lookup lalu threatfox_lookup atau virustotal_lookup.
- MD5/SHA256: prioritaskan malwarebazaar_lookup lalu virustotal_lookup; threatfox_lookup dan alienvault_otx_lookup boleh dipakai sebagai pelengkap.

## OUTPUT FORMAT
Gunakan format ini (satu baris per pemanggilan tool):
ip:192.168.1.100 -> greynoise_lookup
ip:192.168.1.100 -> alienvault_otx_lookup
domain:evil.com -> virustotal_lookup
domain:evil.com -> threatfox_lookup
sha256:abc123... -> virustotal_lookup
sha256:abc123... -> malwarebazaar_lookup
url:http://bad.com/payload.exe -> urlhaus_lookup

Pilih 1-3 tools per IOC dan hanya gunakan nama tool dari daftar di atas."""
        return prompt

    def _parse_tool_selections(self, llm_response: str, iocs: List[Dict]) -> List[Dict]:
        """Parse LLM response for tool selections"""
        tool_calls = []
        allowed_tools = set(self.TOOL_TO_IOC_TYPES)
        valid_iocs = {
            (str(ioc.get("type", "")).lower(), str(ioc.get("value", "")))
            for ioc in iocs
        }

        lines = llm_response.split("\n")
        for line in lines:
            if "->" in line:
                try:
                    ioc_part, tool_name = line.split("->")
                    ioc_type, ioc_value = ioc_part.strip().split(":", 1)
                    ioc_type = ioc_type.strip().lower()
                    ioc_value = ioc_value.strip()
                    tool_name = tool_name.strip().lower()

                    if tool_name not in allowed_tools:
                        continue

                    if ioc_type not in self.TOOL_TO_IOC_TYPES.get(tool_name, set()):
                        continue

                    if (ioc_type, ioc_value) not in valid_iocs:
                        continue

                    tool_calls.append(
                        {"ioc": ioc_value, "ioc_type": ioc_type, "tool": tool_name}
                    )
                except (TypeError, ValueError):
                    continue

        # If parsing failed, use fallback
        if not tool_calls:
            tool_calls = self._fallback_tool_selection(iocs)

        return tool_calls

    def _fallback_tool_selection(self, iocs: List[Dict]) -> List[Dict]:
        """Fallback tool selection using simple heuristics"""
        tool_calls = []

        for ioc in iocs:
            ioc_type = ioc["type"]
            ioc_value = ioc["value"]

            if ioc_type == "ip":
                tool_calls.append(
                    {"ioc": ioc_value, "ioc_type": ioc_type, "tool": "greynoise_lookup"}
                )
                tool_calls.append(
                    {"ioc": ioc_value, "ioc_type": ioc_type, "tool": "threatfox_lookup"}
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "alienvault_otx_lookup",
                    }
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "virustotal_lookup",
                    }
                )
            elif ioc_type == "domain":
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "threatfox_lookup",
                    }
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "alienvault_otx_lookup",
                    }
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "virustotal_lookup",
                    }
                )
            elif ioc_type == "url":
                tool_calls.append(
                    {"ioc": ioc_value, "ioc_type": ioc_type, "tool": "urlhaus_lookup"}
                )
                tool_calls.append(
                    {"ioc": ioc_value, "ioc_type": ioc_type, "tool": "threatfox_lookup"}
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "virustotal_lookup",
                    }
                )
            elif ioc_type in ["md5", "sha256"]:
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "malwarebazaar_lookup",
                    }
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "virustotal_lookup",
                    }
                )
                tool_calls.append(
                    {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "tool": "threatfox_lookup",
                    }
                )

        return tool_calls

    def _build_timeline_description(self, anomaly: Dict[str, Any]) -> str:
        detail_summary = self._summarize_anomaly_details(anomaly)
        if detail_summary:
            return (
                f"Anomalous event detected: {anomaly.get('actual_event', 'unknown')} | "
                f"{detail_summary}"
            )
        return f"Anomalous event detected: {anomaly.get('actual_event', 'unknown')}"

    def _summarize_anomaly_details(self, anomaly: Dict[str, Any]) -> str:
        key_fields = []

        anomalous_line = anomaly.get("anomalous_line") or {}
        if isinstance(anomalous_line, dict):
            fields = anomalous_line.get("important_fields") or {}
            if isinstance(fields, dict):
                for key in [
                    "image",
                    "command_line",
                    "parent_image",
                    "target_object",
                    "destination_ip",
                    "destination_port",
                    "query_name",
                    "user",
                ]:
                    value = fields.get(key)
                    if value:
                        key_fields.append(f"{key}={value}")
                    if len(key_fields) >= 4:
                        break

        if not key_fields:
            indicators = anomaly.get("window_key_indicators") or {}
            if isinstance(indicators, dict):
                for key in [
                    "image",
                    "command_line",
                    "target_object",
                    "destination_ip",
                    "query_name",
                    "user",
                ]:
                    values = indicators.get(key) or []
                    if values:
                        key_fields.append(f"{key}={values[0]}")
                    if len(key_fields) >= 4:
                        break

        return " | ".join(key_fields)

    def _resolve_timeline_timestamp(
        self, log_entry: pd.Series, anomaly: Dict[str, Any]
    ) -> Optional[str]:
        log_timestamp = str(log_entry.get("timestamp") or "").strip()
        if log_timestamp:
            return log_timestamp

        anomalous_line = anomaly.get("anomalous_line") or {}
        if isinstance(anomalous_line, dict):
            anomaly_timestamp = str(anomalous_line.get("timestamp") or "").strip()
            if anomaly_timestamp:
                return anomaly_timestamp

        return None

    def _create_correlation_prompt(
        self, anomalies: List[Dict], tool_results: List[Dict]
    ) -> str:
        """Create prompt for correlation using ReAct pattern"""
        anomalies_summary = f"{len(anomalies)} anomali terdeteksi"
        relevant_tool_results = [
            result
            for result in tool_results
            if result.get("status") != "skipped" and not result.get("skipped")
        ]

        # Extract meaningful threat findings
        threat_findings = []
        malicious_count = 0
        suspicious_count = 0

        for result in relevant_tool_results[:20]:  # Analyze more results
            if result.get("status") != "error":
                tool_name = result.get("tool", "unknown")
                ioc = result.get("ioc", "N/A")
                status = result.get("status", "checked")

                # Extract key intel
                if result.get("malware_family"):
                    malicious_count += 1
                    threat_findings.append(
                        f"- **{tool_name}**: IOC `{ioc}` → MALICIOUS | "
                        f"Malware: {result.get('malware_family')} | "
                        f"Threat: {result.get('threat_type', 'unknown')}"
                    )
                elif result.get("data"):
                    suspicious_count += 1
                    threat_findings.append(
                        f"- **{tool_name}**: IOC `{ioc}` → Data found | Status: {status}"
                    )
                else:
                    threat_findings.append(
                        f"- **{tool_name}**: IOC `{ioc}` → Clean/Unknown"
                    )

        findings_text = (
            "\n".join(threat_findings)
            if threat_findings
            else "Tidak ada temuan threat intelligence"
        )

        # Build detailed anomaly context
        anomaly_details = []
        for idx, anomaly in enumerate(anomalies[:10], 1):
            detail_summary = self._summarize_anomaly_details(anomaly)
            detail_suffix = f" | {detail_summary}" if detail_summary else ""
            anomaly_details.append(
                f"{idx}. Window {anomaly.get('window_id')}: "
                f"{anomaly.get('actual_event', 'Unknown')[:80]}...{detail_suffix}"
            )
        anomaly_context = "\n".join(anomaly_details)

        prompt = f"""# DFIR Correlation Analysis - ReAct Framework

Anda adalah Lead DFIR Analyst TNI AL yang berpengalaman dalam cyber threat hunting.
Tugas: Korelasikan temuan anomali dengan threat intelligence untuk membangun hypothesis serangan.

## INPUT DATA

### Anomaly Detection Results
Total Anomalies: {len(anomalies)}
**Anomaly Windows:**
{anomaly_context}

### Threat Intelligence Results
Total Queries: {len(relevant_tool_results)}
- **Malicious IOCs:** {malicious_count}
- **Suspicious IOCs:** {suspicious_count}
- **Clean/Unknown:** {len(relevant_tool_results) - malicious_count - suspicious_count}

**Detailed Findings:**
{findings_text}

## REACT CORRELATION PROCESS

### THOUGHT 1: Analyze Threat Landscape
**Question:** Apa pola IOC yang teridentifikasi?
- Apakah ada IOC malicious yang confirmed?
- Malware family apa yang terlibat?
- Apakah ada clustering IOC (multiple IOC dari satu source)?

**Reasoning:** [Analisis pola threat intelligence]

### THOUGHT 2: Map to Anomalies
**Question:** Bagaimana IOC malicious berkorelasi dengan anomali log?
- Apakah anomali terjadi di timeframe yang sama?
- Apakah ada event sequence yang mencurigakan?
- Pola apa yang menunjukkan serangan terkoordinasi?

**Reasoning:** [Hubungkan IOC dengan anomaly windows]

### THOUGHT 3: Construct Attack Hypothesis
**Question:** Apa skenario serangan yang paling mungkin?
- Vektor serangan awal (initial access)?
- Teknik yang digunakan attacker?
- Tujuan serangan (objective)?

**Reasoning:** [Bangun hypothesis berdasarkan evidence]

## OUTPUT REQUIREMENTS

Provide structured correlation analysis in Bahasa Indonesia:

### 1. THREAT SUMMARY (2-3 kalimat)
Ringkas temuan threat intelligence dan tingkat ancaman.

### 2. CORRELATION FINDINGS (3-5 poin)
- Korelasi spesifik antara IOC malicious dengan anomali
- Evidence linking (window ID, IOC, threat type)
- Pattern identification

### 3. ATTACK HYPOTHESIS (2-3 paragraf)
- Kemungkinan attack vector
- Teknik yang digunakan (jika teridentifikasi)
- Attack progression/kill chain
- Objective estimation

### 4. CONFIDENCE ASSESSMENT
- Overall confidence: High/Medium/Low
- Key evidence supporting hypothesis
- Gaps in analysis

**IMPORTANT:**
- Fokus pada IOC malicious dan suspicious
- Gunakan evidence konkrit (window ID, IOC value, malware family)
- Jika tidak ada IOC malicious, analisis apakah anomali adalah false positive atau threat belum teridentifikasi
- Profesional dan faktual, hindari spekulasi berlebihan

Begin correlation analysis:"""
        return prompt

    def _create_report_prompt(self, state: InvestigationState) -> str:
        """Create prompt for comprehensive report generation using ReAct pattern"""
        num_anomalies = len(state["anomalies"])
        num_iocs = len(state["iocs_extracted"])
        num_tools = len(state["tool_results"])

        # Extract malicious IOCs
        malicious_iocs = []
        for result in state["tool_results"]:
            if result.get("malware_family") or (
                result.get("data") and result.get("status") == "ok"
            ):
                malicious_iocs.append(
                    {
                        "ioc": result.get("ioc", "N/A"),
                        "type": result.get("ioc_type", "unknown"),
                        "malware": result.get("malware_family", "Unknown"),
                        "threat_type": result.get("threat_type", "Unknown"),
                    }
                )

        # Get reasoning steps summary
        reasoning_summary = "\n".join(
            [f"- {step[:150]}" for step in state.get("reasoning_steps", [])[-5:]]
        )

        # Get correlation analysis
        correlation_analysis = state.get(
            "correlation_analysis", "Correlation analysis not available"
        )
        correlation_preview = (
            correlation_analysis[:500] + "..."
            if len(correlation_analysis) > 500
            else correlation_analysis
        )

        # Get timeline summary
        timeline_events = state.get("attack_timeline", [])
        timeline_summary = (
            f"{len(timeline_events)} events"
            if timeline_events
            else "Timeline not constructed"
        )

        anomaly_details = []
        for idx, anomaly in enumerate(state.get("anomalies", [])[:12], 1):
            detail_summary = self._summarize_anomaly_details(anomaly)
            detail_suffix = f" | {detail_summary}" if detail_summary else ""
            anomaly_details.append(
                f"{idx}. Window {anomaly.get('window_id', '-')}: "
                f"event={anomaly.get('actual_event', 'Unknown')} | "
                f"score={anomaly.get('anomaly_score', anomaly.get('score', 'N/A'))}"
                f"{detail_suffix}"
            )
        anomaly_evidence = "\n".join(anomaly_details) if anomaly_details else "Tidak ada detail anomali tersedia."

        timeline_details = []
        for idx, event in enumerate(timeline_events[:12], 1):
            timeline_details.append(
                f"{idx}. timestamp={event.get('timestamp', 'N/A')} | "
                f"event={event.get('event_template') or event.get('event') or 'Unknown'} | "
                f"details={event.get('description') or event.get('details') or 'N/A'}"
            )
        timeline_evidence = "\n".join(timeline_details) if timeline_details else "Timeline belum terbentuk."

        tool_result_details = []
        for idx, result in enumerate(state.get("tool_results", [])[:12], 1):
            tool_result_details.append(
                f"{idx}. tool={result.get('tool', 'unknown')} | "
                f"ioc={result.get('ioc') or result.get('ip') or result.get('url') or result.get('hash') or 'N/A'} | "
                f"classification={result.get('classification', 'N/A')} | "
                f"malicious={result.get('malicious', 'N/A')} | "
                f"suspicious={result.get('suspicious', 'N/A')} | "
                f"status={result.get('status', 'N/A')}"
            )
        tool_evidence = "\n".join(tool_result_details) if tool_result_details else "Tidak ada hasil threat intelligence tersedia."

        prompt = f"""# DFIR Executive Summary Report - ReAct Framework

Anda adalah Chief Security Officer TNI AL yang akan mempresentasikan hasil investigasi kepada stakeholder.
Tugas: Buat laporan investigasi DFIR yang PANJANG, KAYA INFORMASI, COMPREHENSIVE, ACTIONABLE, dan PROFESIONAL.

ATURAN OUTPUT WAJIB:
- Jawab HANYA dalam Bahasa Indonesia formal.
- Jangan membuat contoh log, IOC, timestamp, atau proses yang tidak ada di input.
- Jika evidence tidak cukup, tulis "belum cukup bukti" dan jelaskan gap datanya.
- Setiap klaim penting harus menyebut evidence: window ID, IOC, tool result, timeline, process/user/command line, atau anomaly score.
- Panjang target minimal 900 kata jika data mencukupi. Prioritaskan informasi dan penjelasan dibanding kreativitas.
- Output harus langsung berupa laporan final, bukan soal latihan, bukan template, dan bukan instruksi pengerjaan.

## INVESTIGATION METRICS

### Quantitative Data
- **Total Anomalies Detected:** {num_anomalies} windows
- **IOCs Extracted:** {num_iocs} indicators
- **Threat Intelligence Queries:** {num_tools} API calls
- **Malicious IOCs Confirmed:** {len(malicious_iocs)}
- **Attack Timeline:** {timeline_summary}

### Key Malicious IOCs
{chr(10).join([f"- {ioc['type'].upper()}: {ioc['ioc']} → {ioc['malware']} ({ioc['threat_type']})" for ioc in malicious_iocs[:5]]) if malicious_iocs else "No malicious IOCs confirmed"}

### Correlation Analysis Summary
{correlation_preview}

### DeepLog Anomaly Evidence
{anomaly_evidence}

### Threat Intelligence Evidence
{tool_evidence}

### Timeline Evidence
{timeline_evidence}

### Investigation Reasoning Chain
{reasoning_summary}

## REACT REPORT GENERATION PROCESS

### THOUGHT 1: Incident Classification
**Question:** Apa tingkat severity insiden ini?
- Berapa banyak IOC malicious terconfirm?
- Apakah ada indikasi data exfiltration atau system compromise?
- Seberapa besar scope dampak?

**Classification Criteria:**
- **CRITICAL:** Multiple confirmed malware, C2 communication, data exfiltration evidence
- **HIGH:** Confirmed malware presence, suspicious IOCs, potential compromise
- **MEDIUM:** Some suspicious activity, unclear threat, possible false positives
- **LOW:** Mostly benign anomalies, no confirmed threats

### THOUGHT 2: Attack Analysis
**Question:** Apa yang sebenarnya terjadi?
- Apa attack vector yang digunakan?
- Teknik apa yang teridentifikasi (MITRE ATT&CK)?
- Apakah ini targeted attack atau opportunistic?

### THOUGHT 3: Impact Assessment
**Question:** Apa dampak dan risikonya?
- System/data apa yang terpengaruh?
- Apakah attacker berhasil achieve objectives?
- Apa risiko lanjutan jika tidak ditangani?

### THOUGHT 4: Remediation Priority
**Question:** Apa yang harus dilakukan immediately?
- Isolation/containment?
- IOC blocking?
- Forensics collection?
- System hardening?

## OUTPUT REQUIREMENTS

Generate comprehensive report dalam Bahasa Indonesia dengan struktur:

### 1. RINGKASAN EKSEKUTIF (Executive Summary)
**[3-4 paragraf profesional]**

Paragraf 1: **Incident Overview**
- Kapan investigasi dilakukan
- Berapa anomali dan IOC ditemukan
- Verdict: Apakah ini genuine threat atau false positive dominan

Paragraf 2: **Threat Identification**
- Malware family atau threat actor (jika teridentifikasi)
- Attack vector dan teknik yang digunakan
- IOC malicious yang terconfirm

Paragraf 3: **Impact Assessment**
- Scope compromise (jika ada)
- Data/systems yang terpengaruh
- Potential damage atau risk

Paragraf 4: **Recommended Actions**
- Immediate actions (containment)
- Short-term mitigation
- Long-term improvements

### 2. TINGKAT SEVERITY
**Classification:** [CRITICAL/HIGH/MEDIUM/LOW]
**Confidence Level:** [High/Medium/Low]

**Justification:** [2-3 kalimat explaining severity rating]

### 3. INDIKATOR KOMPROMI UTAMA (Key IOCs)
List 5-10 IOC paling penting dengan konteks:
- IOC value
- Type (IP/domain/hash/URL)
- Threat classification
- Recommended action (block/monitor/investigate)

### 4. MITRE ATT&CK MAPPING (Jika Applicable)
Map temuan ke MITRE ATT&CK Framework:
- **Tactic:** [e.g., Initial Access, Execution, Persistence]
- **Technique:** [e.g., T1566 Phishing, T1059 Command Execution]
- **Evidence:** [Supporting evidence dari logs/IOCs]

### 5. ATTACK TIMELINE (Jika Teridentifikasi)
Kronologi serangan:
- Initial compromise
- Lateral movement (if any)
- Objective achievement
- Detection point

### 6. DAMPAK POTENSIAL
- **Technical Impact:** System compromise, data exposure, service disruption
- **Business Impact:** Operational impact, reputational risk, compliance issues
- **Risk Rating:** Quantify risk level

### 7. RECOMMENDATIONS (Prioritized)
**Immediate (0-24 hours):**
1. [Action item with specific steps]
2. [Action item with specific steps]

**Short-term (1-7 days):**
1. [Mitigation measure]
2. [Investigation follow-up]

**Long-term (Strategic):**
1. [Security improvement]
2. [Process enhancement]

## WRITING GUIDELINES

**Tone:** Profesional, faktual, actionable
**Language:** Bahasa Indonesia formal (untuk laporan TNI AL)
**Evidence-based:** Setiap claim harus didukung data
**Actionable:** Recommendations harus spesifik dan implementable
**Balanced:** Jika tidak ada threat confirmed, clearly state itu adalah false positive atau benign activity

**AVOID:**
- Spekulasi tanpa evidence
- Teknis jargon berlebihan (explain untuk non-technical stakeholders)
- Understatement threat (if genuine)
- Overstatement threat (if false positive)

Tulis laporan final sekarang dalam Bahasa Indonesia. Jangan awali dengan penjelasan bahwa Anda akan menulis laporan. Jangan tampilkan placeholder.

### 1. RINGKASAN EKSEKUTIF
"""
        return prompt

    def investigate(
        self,
        anomalies_df: pd.DataFrame,
        parsed_logs_df: pd.DataFrame,
        session_id: str = None,
        status_callback=None,
    ) -> Dict:
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

        print("\n" + "=" * 60)
        print("STARTING AI AGENT INVESTIGATION")
        print("=" * 60)

        # Convert anomalies DataFrame to list of dicts
        anomalies = anomalies_df.to_dict("records")

        # Initialize state
        initial_state = {
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
            "max_reflection_rounds": self.DEFAULT_MAX_REFLECTION_ROUNDS,
            "correlation_analysis": "",
            "investigation_summary": "",
            "attack_timeline": [],
            "recommendations": [],
            "current_stage": "init",
            "completed": False,
            "tool_execution_round": 0,
            "max_tool_execution_rounds": self.DEFAULT_MAX_TOOL_EXECUTION_ROUNDS,
        }

        # Run graph
        try:
            final_state = self.app.invoke(initial_state)

            print("\n" + "=" * 60)
            print("INVESTIGATION COMPLETED")
            print("=" * 60)

            return final_state

        except Exception as e:
            print(f"\nError during investigation: {e}")
            raise


if __name__ == "__main__":
    # Test agent
    agent = DFIRAgent()
    print("DFIR Agent initialized successfully")
