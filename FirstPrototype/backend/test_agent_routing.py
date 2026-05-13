import unittest
from typing import Any

import pandas as pd

from modules.agent import DFIRAgent, InvestigationState


class FakeLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return ""


class DFIRAgentRoutingTest(unittest.TestCase):
    def _build_agent(self) -> DFIRAgent:
        return DFIRAgent(llm=FakeLLM())

    def _build_state(
        self,
        iocs_extracted: list[dict[str, Any]] | None = None,
        tool_results: list[dict[str, Any]] | None = None,
        tool_execution_round: int = 0,
        max_tool_execution_rounds: int = 2,
    ) -> InvestigationState:
        state: dict[str, Any] = {
            "anomalies": [],
            "parsed_logs": pd.DataFrame(),
            "iocs_extracted": iocs_extracted or [],
            "tool_calls": [],
            "tool_results": tool_results or [],
            "reasoning_steps": [],
            "correlation_analysis": "",
            "investigation_summary": "",
            "attack_timeline": [],
            "recommendations": [],
            "current_stage": "test",
            "completed": False,
            "tool_execution_round": tool_execution_round,
            "max_tool_execution_rounds": max_tool_execution_rounds,
        }
        return InvestigationState(**state)

    def test_router_skips_to_report_when_no_iocs_exist(self):
        agent = self._build_agent()

        route = agent._decide_next_step(self._build_state())

        self.assertEqual(route, "no_iocs")

    def test_router_requests_more_intel_for_malicious_ioc_with_unqueried_tools(self):
        agent = self._build_agent()
        state = self._build_state(
            iocs_extracted=[
                {
                    "type": "ip",
                    "value": "8.8.8.8",
                    "source_line": 1,
                    "window_id": 1,
                }
            ],
            tool_results=[
                {
                    "tool": "greynoise",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "classification": "malicious",
                    "status": "ok",
                }
            ],
            tool_execution_round=1,
        )

        route = agent._decide_next_step(state)
        follow_up_calls = agent._select_follow_up_tool_calls(state)

        self.assertEqual(route, "needs_more_intel")
        self.assertTrue(follow_up_calls)
        self.assertNotIn("greynoise_lookup", {call["tool"] for call in follow_up_calls})

    def test_router_stops_when_round_limit_is_reached(self):
        agent = self._build_agent()
        state = self._build_state(
            iocs_extracted=[
                {
                    "type": "ip",
                    "value": "8.8.8.8",
                    "source_line": 1,
                    "window_id": 1,
                }
            ],
            tool_results=[
                {
                    "tool": "greynoise",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "classification": "malicious",
                    "status": "ok",
                }
            ],
            tool_execution_round=2,
            max_tool_execution_rounds=2,
        )

        route = agent._decide_next_step(state)

        self.assertEqual(route, "sufficient_intel")

    def test_router_continues_when_existing_intel_is_sufficient(self):
        agent = self._build_agent()
        state = self._build_state(
            iocs_extracted=[
                {
                    "type": "domain",
                    "value": "example.com",
                    "source_line": 1,
                    "window_id": 1,
                }
            ],
            tool_results=[
                {
                    "tool": "virustotal",
                    "ioc": "example.com",
                    "ioc_type": "domain",
                    "classification": "clean",
                    "status": "ok",
                }
            ],
            tool_execution_round=1,
        )

        route = agent._decide_next_step(state)

        self.assertEqual(route, "sufficient_intel")


if __name__ == "__main__":
    unittest.main()
