import io
import unittest
from contextlib import redirect_stdout
from typing import Any

import pandas as pd

from modules.agent import DFIRAgent, InvestigationState


class CorrelationLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return "Evidence is sufficient for a suspicious C2 hypothesis."


class DFIRAgentCorrelationTest(unittest.TestCase):
    def _build_state(self, **overrides: Any) -> InvestigationState:
        state: dict[str, Any] = {
            "anomalies": [{"window_id": 1, "actual_event": "Network connection"}],
            "parsed_logs": pd.DataFrame(),
            "iocs_extracted": [{"type": "ip", "value": "8.8.8.8"}],
            "tool_calls": [],
            "tool_results": [
                {
                    "tool_call": "greynoise_lookup",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "classification": "malicious",
                    "status": "ok",
                }
            ],
            "reasoning_steps": [],
            "planning_steps": [],
            "planned_tool_calls": [],
            "planning_completed": True,
            "planning_round": 1,
            "max_planning_rounds": 1,
            "reflection_steps": [],
            "post_correlation_follow_up_calls": [],
            "observation_assessment": "",
            "evidence_assessment": {},
            "evidence_route": "",
            "reflection_round": 0,
            "max_reflection_rounds": 1,
            "correlation_analysis": "",
            "structured_correlation": {},
            "evidence_gaps": [],
            "follow_up_requests": [],
            "normalized_evidence": [
                {
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "source": "greynoise_lookup",
                    "verdict": "malicious",
                    "confidence": 0.85,
                    "evidence_summary": "classification=malicious",
                    "raw_status": "ok",
                    "raw_reference": "greynoise_lookup:8.8.8.8",
                }
            ],
            "aggregated_ioc_evidence": {},
            "tool_selection_trace": [],
            "tool_validation_trace": [],
            "agent_trace": [],
            "investigation_status": "evidence_collected",
            "investigation_confidence": 0.85,
            "confidence_factors": [],
            "supporting_evidence": [
                {
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "source": "greynoise_lookup",
                    "verdict": "malicious",
                    "confidence": 0.85,
                    "evidence_summary": "classification=malicious",
                }
            ],
            "inconclusive_reason": "",
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

    def test_correlator_returns_structured_correlation(self):
        agent = DFIRAgent(llm=CorrelationLLM())

        with redirect_stdout(io.StringIO()):
            result = agent.correlate_findings(self._build_state())

        structured = result["structured_correlation"]
        self.assertEqual(structured["verdict"], "confirmed_threat")
        self.assertEqual(structured["confidence"], "medium")
        self.assertEqual(structured["evidence_gaps"], [])
        self.assertEqual(result["evidence_gaps"], [])
        self.assertTrue(structured["correlation_findings"])


if __name__ == "__main__":
    unittest.main()
