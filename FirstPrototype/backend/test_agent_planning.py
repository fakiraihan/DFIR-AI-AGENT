import io
import unittest
from contextlib import redirect_stdout
from typing import Any

import pandas as pd

from modules.agent import DFIRAgent, InvestigationState


class FailingLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        raise AssertionError("LLM should not be called when planner provides tool calls")


class FakeProceduralMemory:
    def __init__(self):
        self.strategy_requests = []

    def get_api_strategy(self, ioc_type: str):
        self.strategy_requests.append(ioc_type)
        strategies = {
            "ip_address": {
                "primary": "greynoise",
                "fallback": ["threatfox"],
                "reason": "Fast IP reputation strategy",
            },
            "domain": {
                "primary": "virustotal",
                "fallback": ["threatfox"],
                "reason": "Domain reputation strategy",
            },
        }
        return strategies.get(ioc_type, {"primary": None, "fallback": []})


class UnsupportedMemory(FakeProceduralMemory):
    def get_api_strategy(self, ioc_type: str):
        self.strategy_requests.append(ioc_type)
        return {
            "primary": "urlhaus",
            "fallback": [],
            "reason": "Unsupported for this IOC type",
        }


class DFIRAgentPlanningTest(unittest.TestCase):
    def _core_calls(self, calls):
        return [
            {"ioc": call["ioc"], "ioc_type": call["ioc_type"], "tool": call["tool"]}
            for call in calls
        ]

    def _assert_traceable_calls(self, calls):
        for call in calls:
            self.assertIn(call.get("selection_source"), {"llm", "fallback_heuristic"})
            self.assertTrue(call.get("selection_reason"))
            self.assertTrue(call.get("expected_evidence"))

    def _build_state(self, **overrides: Any) -> InvestigationState:
        state: dict[str, Any] = {
            "anomalies": [],
            "parsed_logs": pd.DataFrame(),
            "iocs_extracted": [],
            "tool_calls": [],
            "tool_results": [],
            "reasoning_steps": [],
            "planning_steps": [],
            "planned_tool_calls": [],
            "planning_completed": False,
            "planning_round": 0,
            "max_planning_rounds": 1,
            "evidence_assessment": {},
            "evidence_route": "",
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

    def test_planner_prefers_procedural_memory_without_llm(self):
        memory = FakeProceduralMemory()
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=memory)
        state = self._build_state(
            iocs_extracted=[
                {"type": "ip", "value": "8.8.8.8"},
                {"type": "domain", "value": "evil.example"},
            ]
        )

        with redirect_stdout(io.StringIO()):
            result = agent.plan_goals(state)

        self.assertEqual(memory.strategy_requests, ["ip_address", "domain"])
        self.assertTrue(result["planning_completed"])
        self.assertEqual(result["current_stage"], "planning_complete")
        self._assert_traceable_calls(result["planned_tool_calls"])
        self.assertEqual(
            self._core_calls(result["planned_tool_calls"]),
            [
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "greynoise_lookup"},
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "threatfox_lookup"},
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "virustotal_lookup",
                },
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "threatfox_lookup",
                },
            ],
        )

    def test_select_tools_uses_planner_output_before_memory_or_llm(self):
        memory = FakeProceduralMemory()
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=memory)
        planned_call = {
            "ioc": "8.8.8.8",
            "ioc_type": "ip",
            "tool": "greynoise_lookup",
        }
        state = self._build_state(
            iocs_extracted=[{"type": "ip", "value": "8.8.8.8"}],
            planned_tool_calls=[planned_call],
        )

        with redirect_stdout(io.StringIO()):
            result = agent.select_tools(state)

        self.assertEqual(memory.strategy_requests, [])
        self.assertEqual(result["current_stage"], "planner_guided_tool_selection_complete")
        self._assert_traceable_calls(result["tool_calls"])
        self.assertEqual(self._core_calls(result["tool_calls"]), [planned_call])

    def test_planner_falls_back_to_static_playbook_when_memory_has_no_supported_tools(self):
        memory = UnsupportedMemory()
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=memory)
        state = self._build_state(
            iocs_extracted=[{"type": "domain", "value": "evil.example"}]
        )

        with redirect_stdout(io.StringIO()):
            result = agent.plan_goals(state)

        self.assertEqual(memory.strategy_requests, ["domain"])
        self._assert_traceable_calls(result["planned_tool_calls"])
        self.assertEqual(
            self._core_calls(result["planned_tool_calls"]),
            [
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "threatfox_lookup",
                },
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "alienvault_otx_lookup",
                },
                {
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "tool": "virustotal_lookup",
                },
            ],
        )

    def test_planned_tool_calls_are_deduped_and_skip_attempted_results(self):
        agent = DFIRAgent(llm=FailingLLM())
        state = self._build_state(
            planned_tool_calls=[
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "greynoise_lookup"},
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "greynoise_lookup"},
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "threatfox_lookup"},
            ],
            tool_results=[
                {
                    "tool_call": "greynoise_lookup",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "status": "ok",
                }
            ],
        )

        remaining = agent._select_new_planned_tool_calls(state)

        self._assert_traceable_calls(remaining)
        self.assertEqual(
            self._core_calls(remaining),
            [{"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "threatfox_lookup"}],
        )

    def test_planner_handles_no_iocs_without_breaking_no_iocs_route(self):
        agent = DFIRAgent(llm=FailingLLM())
        state = self._build_state()

        with redirect_stdout(io.StringIO()):
            result = agent.plan_goals(state)
            route = agent._decide_next_step(state)

        self.assertEqual(result["planned_tool_calls"], [])
        self.assertTrue(result["planning_completed"])
        self.assertEqual(route, "no_iocs")


if __name__ == "__main__":
    unittest.main()
