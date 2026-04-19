"""
LangGraph AI Agent for DFIR Investigation
Orchestrates investigation using ReAct pattern with Foundation-Sec-8B
"""

from typing import Dict, List, Any, TypedDict, Annotated, Optional
import operator
import json
import re
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd

from langgraph.graph import StateGraph, END

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
    correlation_analysis: str  # Correlation analysis from LLM

    # Output
    investigation_summary: str
    attack_timeline: List[Dict[str, Any]]
    recommendations: List[str]

    # Control
    current_stage: str
    completed: bool


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

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "foundation-sec-8b",
        threat_intel_api_keys: Dict[str, str] = None,
        llm: Any = None,
        provider_name: str = "ollama",
    ):
        """
        Initialize DFIR Agent

        Args:
            ollama_base_url: Ollama API URL
            ollama_model: Model name in Ollama
            threat_intel_api_keys: Dict of API keys for threat intel services
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
                temperature=0.4,
                top_p=0.9,
                top_k=40,
            )

        # Initialize threat intel toolkit
        self.threat_intel = ThreatIntelToolkit(threat_intel_api_keys or {})

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
        workflow.add_node("tool_selector", self.select_tools)
        workflow.add_node("tool_executor", self.execute_tools)
        workflow.add_node("correlator", self.correlate_findings)
        workflow.add_node("timeline_builder", self.build_timeline)
        workflow.add_node("report_generator", self.generate_summary)

        # Add edges (sequential flow)
        workflow.set_entry_point("ioc_extractor")
        workflow.add_edge("ioc_extractor", "tool_selector")
        workflow.add_edge("tool_selector", "tool_executor")
        workflow.add_edge("tool_executor", "correlator")
        workflow.add_edge("correlator", "timeline_builder")
        workflow.add_edge("timeline_builder", "report_generator")
        workflow.add_edge("report_generator", END)

        return workflow

    def extract_iocs(self, state: InvestigationState) -> Dict:
        """
        Node: Extract IOCs from anomalous log parameters
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "🔍 Mengekstrak IOCs dari logs...", 62
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

    def select_tools(self, state: InvestigationState) -> Dict:
        """
        Node: Use LLM to select appropriate threat intel tools for each IOC
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "🤖 AI sedang memilih tools untuk analisis...",
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

            print(f"\n✓ LLM Response received ({elapsed:.2f}s)")
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
            print(f"\n⚠ Error in tool selection: {e}")
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
                    f"🛠️ Menggunakan tools: {tool_names}...",
                    72,
                )
            else:
                self.status_callback(
                    self.session_id,
                    "ai_agent",
                    "🛠️ Menjalankan threat intelligence tools...",
                    72,
                )

        print("\n=== STAGE 3: TOOL EXECUTION ===")
        print(f"Total tool calls to execute: {len(state['tool_calls'])}")

        tool_calls = state["tool_calls"]
        results = []

        for idx, call in enumerate(tool_calls, 1):
            tool_name = call["tool"]
            ioc = call["ioc"]
            ioc_type = call["ioc_type"]

            print(f"\n[{idx}/{len(tool_calls)}] Executing: {tool_name}")
            print(f"  IOC: {ioc} (type: {ioc_type})")

            try:
                import time

                start_time = time.time()

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
                    print(f"  ↷ Skipped ({elapsed:.2f}s): {skip_reason}")
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

                elapsed = time.time() - start_time

                # Print result summary
                if "error" in result:
                    print(f"  ⚠ Error: {result['error']}")
                elif result.get("data"):
                    print(f"  ✓ Success ({elapsed:.2f}s): Found data")
                    # Print brief summary
                    if isinstance(result["data"], dict):
                        keys = list(result["data"].keys())[:3]
                        print(f"    Keys: {keys}")
                    elif isinstance(result["data"], list):
                        print(f"    Results: {len(result['data'])} items")
                else:
                    print(f"  ✓ Completed ({elapsed:.2f}s): No data found")

                results.append(result)

            except Exception as e:
                print(f"  ✗ Exception: {e}")
                import traceback

                print(f"  Traceback: {traceback.format_exc()[:200]}")
                results.append({"tool": tool_name, "ioc": ioc, "error": str(e)})

        print(f"Executed {len(results)} tool calls")

        return {
            "tool_results": results,
            "reasoning_steps": [f"Executed {len(results)} threat intel queries"],
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

    def correlate_findings(self, state: InvestigationState) -> Dict:
        """
        Node: Use LLM to correlate threat intel findings with anomalies
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id,
                "ai_agent",
                "🧠 AI sedang mengkorelasikan findings...",
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

            print(f"\n✓ LLM Correlation Analysis Complete ({elapsed:.2f}s)")
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
            print(f"⚠ Error in correlation: {e}")
            import traceback

            print(traceback.format_exc())
            return {
                "correlation_analysis": f"Correlation error: {str(e)}",
                "reasoning_steps": [f"Correlation error: {e}"],
            }

    def build_timeline(self, state: InvestigationState) -> Dict:
        """
        Node: Build attack timeline from anomalies
        """
        if self.status_callback and self.session_id:
            self.status_callback(
                self.session_id, "ai_agent", "⏱️ Menyusun timeline serangan...", 80
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
                self.session_id, "ai_agent", "📝 AI sedang menulis summary...", 83
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

            print(f"\n✓ Investigation Summary Generated ({elapsed:.2f}s)")
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
            print(f"⚠ Error generating summary: {e}")
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

    def _generate_default_recommendations(self, state: InvestigationState) -> List[str]:
        """Generate intelligent default recommendations based on findings"""
        recommendations = []

        # Check if malicious IOCs found
        malicious_count = sum(
            1 for r in state.get("tool_results", []) if r.get("malware_family")
        )

        if malicious_count > 0:
            recommendations.extend(
                [
                    "🚨 IMMEDIATE: Isolasi sistem yang teridentifikasi terkompromi dari jaringan",
                    "🛡️ IMMEDIATE: Block semua IOC malicious di firewall, IDS/IPS, dan proxy",
                    "🔍 URGENT: Lakukan forensik memory dump dan disk imaging pada sistem terdampak",
                    "📊 URGENT: Kumpulkan artifact tambahan: registry, prefetch, event logs, browser history",
                    "🔎 24-48 JAM: Hunt similar IOC patterns di sistem lain menggunakan EDR/SIEM",
                    "📧 24-48 JAM: Notify security team dan stakeholder terkait dengan incident brief",
                    "🔐 1 MINGGU: Force password reset untuk akun yang teridentifikasi compromise",
                    "📈 1 MINGGU: Review dan update detection rules berdasarkan TTPs teridentifikasi",
                    "🎯 STRATEGIC: Implement additional monitoring untuk attack vector yang digunakan",
                    "📚 STRATEGIC: Conduct incident retrospective dan update playbook",
                ]
            )
        else:
            recommendations.extend(
                [
                    "✅ Review anomali DeepLog untuk potential false positives",
                    "🔍 Lakukan manual analysis pada log events yang flagged sebagai anomali",
                    "📊 Collect additional context untuk anomali (user, process, parent process)",
                    "🛠️ Tune DeepLog model parameters jika false positive rate tinggi",
                    "📈 Monitor sistem untuk suspicious activity selama 48 jam",
                    "🔐 Verify sistem tidak ada signs of compromise (persistence, lateral movement)",
                    "📚 Update baseline normal behavior untuk model training",
                    "🎯 Enhance logging untuk better anomaly detection coverage",
                ]
            )

        return recommendations

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

        prompt = f"""# DFIR Executive Summary Report - ReAct Framework

Anda adalah Chief Security Officer TNI AL yang akan mempresentasikan hasil investigasi kepada stakeholder.
Tugas: Buat Executive Summary yang COMPREHENSIVE, ACTIONABLE, dan PROFESIONAL.

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

Begin generating executive summary report:"""
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
            "correlation_analysis": "",
            "investigation_summary": "",
            "attack_timeline": [],
            "recommendations": [],
            "current_stage": "init",
            "completed": False,
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
