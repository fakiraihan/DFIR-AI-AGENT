import unittest
import io
from contextlib import redirect_stdout

import pandas as pd

from modules.agent import DFIRAgent
from modules.agent_modules.state import InvestigationState


class EchoScaffoldLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return (
            "[3-4 paragraf profesional]\n\n"
            "Paragraf 1: **Incident Overview**\n"
            "- Kapan investigasi dilakukan?\n"
            "- Berapa anomali ditemukan?\n\n"
            "### 7. RECOMMENDATIONS (Prioritized)\n"
            "1. [Action item with specific steps]\n"
            "2. [Mitigation measure]\n"
        )


class EchoInstructionLineLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return (
            "- Avoid technical jargon, speculation without evidence, "
            "understatements of threat severity, or overstatements beyond available data."
        )


class EchoConditionalInstructionLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return "- If no malicious IOCs are confirmed from this case, state that there is insufficient evidence."


class EchoOverclaimingInstructionLLM:
    def invoke(self, prompt: str) -> str:
        _ = prompt
        return "- Avoid overclaiming severity if genuine compromise is unsupported by log evidence."


class ReportPromptNoEchoTest(unittest.TestCase):
    def _build_state(self) -> InvestigationState:
        return InvestigationState(
            anomalies=[
                {
                    "window_id": 23,
                    "actual_event": "EventID 4661 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "anomaly_score": 1.0,
                    "strict_is_anomaly": True,
                    "anomalous_line": {
                        "important_fields": {
                            "user": "administrator",
                            "host": "WIN-77LTAPHIQ1R",
                        }
                    },
                }
            ],
            parsed_logs=pd.DataFrame(),
            iocs_extracted=[{"type": "ip", "value": "10.0.2.15"}],
            tool_calls=[],
            tool_results=[
                {
                    "tool": "virustotal",
                    "ioc": "10.0.2.15",
                    "classification": "clean",
                    "malicious": 0,
                    "suspicious": 0,
                    "status": "ok",
                }
            ],
            reasoning_steps=[],
            planning_steps=[],
            planned_tool_calls=[],
            planning_completed=False,
            planning_round=0,
            max_planning_rounds=1,
            reflection_steps=[],
            post_correlation_follow_up_calls=[],
            observation_assessment="",
            reflection_round=0,
            max_reflection_rounds=1,
            correlation_analysis="",
            normalized_evidence=[],
            aggregated_ioc_evidence={},
            tool_selection_trace=[],
            tool_validation_trace=[],
            agent_trace=[],
            investigation_status="evidence_collected",
            investigation_confidence=0.54,
            confidence_factors=[],
            supporting_evidence=[],
            inconclusive_reason="",
            investigation_summary="",
            attack_timeline=[
                {
                    "event_template": "EventID 4661 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "description": "Object access anomaly by administrator",
                }
            ],
            recommendations=[],
            current_stage="test",
            completed=False,
            tool_execution_round=1,
            max_tool_execution_rounds=1,
        )

    def test_report_prompt_does_not_embed_copyable_scaffold(self):
        agent = DFIRAgent(llm=EchoScaffoldLLM())
        prompt = agent._create_report_prompt(self._build_state())

        forbidden_fragments = [
            "[3-4 paragraf profesional]",
            "[Action item with specific steps]",
            "[Mitigation measure]",
            "Question:",
            "- Kapan investigasi dilakukan",
            "Paragraf 1:",
        ]
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, prompt)

    def test_generate_summary_replaces_prompt_echo_with_evidence_bound_summary(self):
        agent = DFIRAgent(llm=EchoScaffoldLLM())

        with redirect_stdout(io.StringIO()):
            result = agent.generate_summary(self._build_state())

        summary = result["investigation_summary"]
        lowered = summary.lower()
        self.assertIn("EventID 4661", summary)
        self.assertIn("window 23", summary)
        self.assertIn("10.0.2.15", summary)
        self.assertNotIn("[Action item with specific steps]", summary)
        self.assertNotIn("paragraf 1:", lowered)
        self.assertIn("LLM report response looked like prompt echo", result["confidence_factors"])

    def test_generate_summary_replaces_single_instruction_echo(self):
        agent = DFIRAgent(llm=EchoInstructionLineLLM())

        with redirect_stdout(io.StringIO()):
            result = agent.generate_summary(self._build_state())

        summary = result["investigation_summary"]
        lowered = summary.lower()
        self.assertIn("EventID 4661", summary)
        self.assertIn("window 23", summary)
        self.assertIn("10.0.2.15", summary)
        self.assertNotIn("avoid technical jargon", lowered)
        self.assertNotIn("understatements of threat severity", lowered)
        self.assertIn("LLM report response looked like prompt echo", result["confidence_factors"])

    def test_generate_summary_replaces_conditional_instruction_echo(self):
        agent = DFIRAgent(llm=EchoConditionalInstructionLLM())

        with redirect_stdout(io.StringIO()):
            result = agent.generate_summary(self._build_state())

        summary = result["investigation_summary"]
        lowered = summary.lower()
        self.assertIn("EventID 4661", summary)
        self.assertIn("window 23", summary)
        self.assertNotIn("if no malicious iocs are confirmed", lowered)
        self.assertIn("LLM report response looked like prompt echo", result["confidence_factors"])

    def test_generate_summary_replaces_overclaiming_instruction_echo(self):
        agent = DFIRAgent(llm=EchoOverclaimingInstructionLLM())

        with redirect_stdout(io.StringIO()):
            result = agent.generate_summary(self._build_state())

        summary = result["investigation_summary"]
        lowered = summary.lower()
        self.assertIn("EventID 4661", summary)
        self.assertIn("window 23", summary)
        self.assertNotIn("avoid overclaiming severity", lowered)
        self.assertIn("LLM report response looked like prompt echo", result["confidence_factors"])

    def test_inconclusive_summary_uses_available_evidence(self):
        agent = DFIRAgent(llm=EchoInstructionLineLLM())
        state = self._build_state()
        state["investigation_status"] = "inconclusive"
        state["investigation_summary"] = ""
        state["correlation_analysis"] = ""
        state["recommendations"] = []
        state["evaluation_evidence_brief"] = "- tactic_folder: Discovery"

        with redirect_stdout(io.StringIO()):
            result = agent.generate_summary(state)

        summary = result["investigation_summary"]
        lowered = summary.lower()
        self.assertIn("inconclusive", lowered)
        self.assertIn("EventID 4661", summary)
        self.assertIn("Discovery", summary)
        self.assertIn("window 23", summary)
        self.assertIn("10.0.2.15", summary)
        self.assertNotIn("evidence yang tersedia belum cukup", lowered)
        self.assertEqual(result["investigation_status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
