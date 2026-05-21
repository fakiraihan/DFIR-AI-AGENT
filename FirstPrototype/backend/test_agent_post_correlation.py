import io
import unittest
from contextlib import redirect_stdout
from typing import Any

import pandas as pd

from modules.agent import DFIRAgent, InvestigationState


class FailingLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        raise AssertionError("Reflection should not require an LLM call in these tests")


class ExplodingMemory:
    def get_api_strategy(self, ioc_type: str):
        _ = ioc_type
        raise RuntimeError("memory unavailable")


class DFIRAgentPostCorrelationTest(unittest.TestCase):
    def _core_calls(self, calls):
        return [
            {"ioc": call["ioc"], "ioc_type": call["ioc_type"], "tool": call["tool"]}
            for call in calls
        ]

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
            "reflection_steps": [],
            "post_correlation_follow_up_calls": [],
            "observation_assessment": "",
            "reflection_round": 0,
            "max_reflection_rounds": 1,
            "correlation_analysis": "",
            "investigation_summary": "",
            "attack_timeline": [],
            "recommendations": [],
            "current_stage": "test",
            "completed": False,
            "tool_execution_round": 1,
            "max_tool_execution_rounds": 2,
        }
        state.update(overrides)
        return InvestigationState(**state)

    def test_post_correlation_evidence_gap_routes_back_for_more_intel(self):
        agent = DFIRAgent(llm=FailingLLM())
        state = self._build_state(
            iocs_extracted=[{"type": "domain", "value": "evil.example"}],
            tool_results=[
                {
                    "tool_call": "threatfox_lookup",
                    "ioc": "evil.example",
                    "ioc_type": "domain",
                    "classification": "clean",
                    "status": "ok",
                }
            ],
            correlation_analysis="Belum cukup bukti, perlu enrichment tambahan untuk validasi IOC.",
        )

        with redirect_stdout(io.StringIO()):
            result = agent.post_correlation_assessment(state)
            merged = dict(state)
            merged.update(result)
            merged_state = self._build_state(**merged)
            route = agent._decide_post_correlation_step(merged_state)

        self.assertEqual(route, "more_intel_needed")
        self.assertTrue(result["post_correlation_follow_up_calls"])
        self.assertNotIn(
            "threatfox_lookup",
            {call["tool"] for call in result["post_correlation_follow_up_calls"]},
        )

    def test_reflection_guided_select_tools_uses_reflection_calls_first(self):
        agent = DFIRAgent(llm=FailingLLM())
        reflection_call = {
            "ioc": "evil.example",
            "ioc_type": "domain",
            "tool": "virustotal_lookup",
        }
        state = self._build_state(
            iocs_extracted=[{"type": "domain", "value": "evil.example"}],
            post_correlation_follow_up_calls=[reflection_call],
            tool_execution_round=1,
        )

        with redirect_stdout(io.StringIO()):
            result = agent.select_tools(state)

        self.assertEqual(result["current_stage"], "reflection_guided_tool_selection_complete")
        self.assertEqual(self._core_calls(result["tool_calls"]), [reflection_call])
        self.assertTrue(result["tool_calls"][0].get("expected_evidence"))

    def test_post_correlation_stops_when_reflection_limit_reached(self):
        agent = DFIRAgent(llm=FailingLLM())
        state = self._build_state(
            iocs_extracted=[{"type": "ip", "value": "8.8.8.8"}],
            post_correlation_follow_up_calls=[
                {"ioc": "8.8.8.8", "ioc_type": "ip", "tool": "threatfox_lookup"}
            ],
            reflection_round=2,
            max_reflection_rounds=1,
        )

        with redirect_stdout(io.StringIO()):
            route = agent._decide_post_correlation_step(state)

        self.assertEqual(route, "sufficient_after_reflection")

    def test_post_correlation_no_followups_moves_to_timeline(self):
        agent = DFIRAgent(llm=FailingLLM())
        state = self._build_state(
            iocs_extracted=[{"type": "ip", "value": "8.8.8.8"}],
            tool_results=[
                {
                    "tool_call": "greynoise_lookup",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "classification": "clean",
                    "status": "ok",
                }
            ],
            correlation_analysis="Evidence is sufficient; no further action required.",
        )

        with redirect_stdout(io.StringIO()):
            result = agent.post_correlation_assessment(state)
            merged = dict(state)
            merged.update(result)
            merged_state = self._build_state(**merged)
            route = agent._decide_post_correlation_step(merged_state)

        self.assertEqual(result["post_correlation_follow_up_calls"], [])
        self.assertEqual(route, "sufficient_after_reflection")

    def test_post_correlation_uses_static_fallback_on_memory_error(self):
        agent = DFIRAgent(llm=FailingLLM(), procedural_memory=ExplodingMemory())
        state = self._build_state(
            iocs_extracted=[{"type": "domain", "value": "evil.example"}],
            correlation_analysis="Belum cukup bukti, perlu enrichment tambahan.",
        )

        with redirect_stdout(io.StringIO()):
            result = agent.post_correlation_assessment(state)
            merged = dict(state)
            merged.update(result)
            merged_state = self._build_state(**merged)
            route = agent._decide_post_correlation_step(merged_state)

        self.assertTrue(result["post_correlation_follow_up_calls"])
        self.assertEqual(route, "more_intel_needed")


if __name__ == "__main__":
    unittest.main()
