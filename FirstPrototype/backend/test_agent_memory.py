import io
import unittest
from contextlib import redirect_stdout
from typing import Any

import pandas as pd

from modules.agent import DFIRAgent, InvestigationState


class FailingLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        raise AssertionError("LLM should not be called when procedural memory selects tools")


class FixedLLM:
    def __init__(self, response: str):
        self.response = response
        self.calls = 0

    def invoke(self, prompt: str) -> str:
        self.calls += 1
        self.last_prompt = prompt
        return self.response


class FakeProceduralMemory:
    def __init__(self):
        self.strategy_requests = []
        self.performance_updates = []

    def get_api_strategy(self, ioc_type: str):
        self.strategy_requests.append(ioc_type)
        strategies = {
            "ip_address": {
                "primary": "greynoise",
                "fallback": ["threatfox"],
                "reason": "Fast IP reputation strategy",
            },
            "domain": {
                "primary": "urlhaus",
                "fallback": ["alienvault_otx", "threatfox"],
                "reason": "Domain enrichment strategy",
            },
        }
        return strategies.get(ioc_type, {"primary": None, "fallback": []})

    def update_tool_performance(
        self, tool: str, success: bool, response_time: float, ioc_type: str | None = None
    ):
        self.performance_updates.append(
            {
                "tool": tool,
                "success": success,
                "response_time": response_time,
                "ioc_type": ioc_type,
            }
        )


class DFIRAgentProceduralMemoryTest(unittest.TestCase):
    def _build_state(self, **overrides: Any) -> InvestigationState:
        state: dict[str, Any] = {
            "anomalies": [],
            "parsed_logs": pd.DataFrame(),
            "iocs_extracted": [],
            "tool_calls": [],
            "tool_results": [],
            "reasoning_steps": [],
            "correlation_analysis": "",
            "investigation_summary": "",
            "attack_timeline": [],
            "recommendations": [],
            "current_stage": "test",
            "completed": False,
            "tool_execution_round": 0,
            "max_tool_execution_rounds": 2,
        }
        state.update(overrides)
        return InvestigationState(**state)

    def test_select_tools_uses_procedural_memory_strategy_when_available(self):
        memory = FakeProceduralMemory()
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=memory)
        iocs = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "domain", "value": "evil.example"},
        ]

        with redirect_stdout(io.StringIO()):
            result = agent.select_tools(
                self._build_state(iocs_extracted=iocs, tool_execution_round=0)
            )

        self.assertEqual(memory.strategy_requests, ["ip_address", "domain"])
        self.assertEqual(result["current_stage"], "memory_guided_tool_selection_complete")
        self.assertEqual(
            result["tool_calls"],
            [
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "greynoise_lookup"},
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "threatfox_lookup"},
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "alienvault_otx_lookup",
                },
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "threatfox_lookup",
                },
            ],
        )

    def test_select_tools_falls_back_to_llm_when_memory_has_no_supported_tools(self):
        class UnsupportedDomainMemory(FakeProceduralMemory):
            def get_api_strategy(self, ioc_type: str):
                self.strategy_requests.append(ioc_type)
                return {
                    "primary": "urlhaus",
                    "fallback": [],
                    "reason": "Unsupported for domain in agent tool validation",
                }

        memory = UnsupportedDomainMemory()
        llm = FixedLLM("domain:evil.example -> threatfox_lookup")
        agent = DFIRAgent(llm=llm, procedural_memory=memory)

        with redirect_stdout(io.StringIO()):
            result = agent.select_tools(
                self._build_state(
                    iocs_extracted=[{"type": "domain", "value": "evil.example"}],
                    tool_execution_round=0,
                )
            )

        self.assertEqual(memory.strategy_requests, ["domain"])
        self.assertEqual(llm.calls, 1)
        self.assertEqual(
            result["tool_calls"],
            [
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "threatfox_lookup",
                }
            ],
        )

    def test_execute_tools_updates_procedural_memory_performance(self):
        memory = FakeProceduralMemory()
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=memory)

        def fake_greynoise_lookup(ip: str):
            return {
                "tool": "greynoise",
                "ip": ip,
                "status": "ok",
                "classification": "benign",
            }

        def fake_threatfox_lookup(ioc: str, ioc_type: str = "ip"):
            return {
                "tool": "threatfox",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "error",
                "error": "temporary failure",
            }

        agent.threat_intel.greynoise_lookup = fake_greynoise_lookup
        agent.threat_intel.threatfox_lookup = fake_threatfox_lookup

        with redirect_stdout(io.StringIO()):
            result = agent.execute_tools(
                self._build_state(
                    tool_calls=[
                        {
                            "tool": "greynoise_lookup",
                            "ioc": "8.8.8.8",
                            "ioc_type": "ip",
                        },
                        {
                            "tool": "threatfox_lookup",
                            "ioc": "8.8.8.8",
                            "ioc_type": "ip",
                        },
                    ],
                    tool_execution_round=0,
                )
            )

        self.assertEqual(len(result["tool_results"]), 2)
        self.assertEqual(
            [update["tool"] for update in memory.performance_updates],
            ["greynoise", "threatfox"],
        )
        self.assertEqual(
            [update["success"] for update in memory.performance_updates],
            [True, False],
        )
        self.assertTrue(
            all(update["ioc_type"] == "ip" for update in memory.performance_updates)
        )


if __name__ == "__main__":
    unittest.main()
