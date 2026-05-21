import unittest

import pandas as pd

from modules.llm_filter import LLMAnomalyFilter


class FakeLLM:
    def __init__(self, response: str):
        self.response = response
        self.calls = 0

    def invoke(self, prompt: str) -> str:
        self.calls += 1
        self.last_prompt = prompt
        return self.response


class SequentialFakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.prompts = []

    def invoke(self, prompt: str) -> str:
        self.calls += 1
        self.prompts.append(prompt)
        if self.responses:
            return self.responses.pop(0)
        return "not-json"


class LLMAnomalyFilterTest(unittest.TestCase):
    def _build_anomalies_df(self) -> pd.DataFrame:
        return pd.DataFrame(
            [
                {
                    "window_id": 1,
                    "start_idx": 0,
                    "end_idx": 3,
                    "is_anomaly": True,
                    "strict_is_anomaly": True,
                    "anomaly_score": 0.92,
                    "unknown_ratio": 0.05,
                    "actual_event": "Suspicious Event",
                    "predicted_event": "Normal Event",
                    "window_key_indicators": {"destination_ip": ["8.8.8.8"]},
                },
                {
                    "window_id": 2,
                    "start_idx": 4,
                    "end_idx": 7,
                    "is_anomaly": True,
                    "strict_is_anomaly": False,
                    "anomaly_score": 0.11,
                    "unknown_ratio": 0.9,
                    "actual_event": "Benign Event",
                    "predicted_event": "Benign Event",
                    "window_key_indicators": {},
                },
            ]
        )

    def test_batch_gate_calls_llm_once(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"keep_high_confidence_only","confidence":0.8,"reason":"fokus pada anomali paling kuat"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(fake_llm.calls, 1)
        self.assertEqual(len(result_df), 1)
        self.assertEqual(int(result_df.iloc[0]["window_id"]), 1)
        self.assertEqual(result_df.iloc[0]["llm_gate_mode"], "batch_sanity")
        self.assertEqual(
            result_df.iloc[0]["llm_gate_policy"], "keep_high_confidence_only"
        )

    def test_batch_gate_fail_open_on_invalid_json(self):
        fake_llm = FakeLLM("not-json")
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        input_df = self._build_anomalies_df()
        result_df = anomaly_filter.filter_anomalies(input_df, pd.DataFrame())

        self.assertEqual(fake_llm.calls, 2)
        self.assertEqual(len(result_df), len(input_df))
        self.assertTrue((result_df["llm_gate_policy"] == "keep_all").all())

    def test_batch_gate_retries_with_simplified_prompt_after_invalid_json(self):
        fake_llm = SequentialFakeLLM(
            [
                "not-json",
                '{"recommended_action":"prioritize_critical","priority_window_ids":[1],"confidence":0.82,"reason":"retry ok"}',
            ]
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(fake_llm.calls, 2)
        self.assertEqual(len(result_df), 1)
        self.assertEqual(int(result_df.iloc[0]["window_id"]), 1)
        self.assertEqual(result_df.iloc[0]["llm_gate_policy"], "prioritize_critical")

    def test_low_confidence_destructive_policy_fails_open(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"prioritize_critical","priority_window_ids":[2],"confidence":0.2,"reason":"uncertain"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(len(result_df), 2)
        self.assertTrue((result_df["llm_gate_policy"] == "keep_all").all())
        self.assertIn("Low-confidence", result_df.iloc[0]["llm_reason"])

    def test_batch_summary_uses_twenty_samples_and_prompt_distribution(self):
        rows = []
        for idx in range(25):
            rows.append(
                {
                    "window_id": idx + 1,
                    "anomaly_score": idx / 25,
                    "strict_is_anomaly": False,
                    "unknown_ratio": 0.1,
                    "actual_event": f"Event {idx}",
                    "predicted_event": "Expected",
                    "window_key_indicators": {},
                }
            )
        anomalies_df = pd.DataFrame(rows)
        anomaly_filter = LLMAnomalyFilter(llm=FakeLLM('{"recommended_action":"keep_all"}'))

        summaries = anomaly_filter._build_batch_summaries(anomalies_df)
        prompt = anomaly_filter._build_batch_prompt(anomalies_df, summaries)

        self.assertEqual(len(summaries), 20)
        self.assertIn("score_distribution", prompt)
        self.assertIn("prefer English", prompt)

    def test_prioritize_critical_uses_requested_window_ids(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"prioritize_critical","priority_window_ids":[2],"confidence":0.81,"reason":"window 2 perlu prioritas"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(len(result_df), 1)
        self.assertEqual(int(result_df.iloc[0]["window_id"]), 2)
        self.assertEqual(result_df.iloc[0]["llm_gate_policy"], "prioritize_critical")
        self.assertEqual(result_df.iloc[0]["llm_gate_priority"], "critical_priority")
        self.assertEqual(float(result_df.iloc[0]["llm_gate_confidence"]), 0.81)

    def test_request_more_context_keeps_all_and_marks_context_need(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"request_more_context","requested_context":"butuh parent process","confidence":0.64,"reason":"konteks proses kurang"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(len(result_df), 2)
        self.assertTrue((result_df["llm_gate_policy"] == "request_more_context").all())
        self.assertTrue(
            (result_df["llm_gate_requested_context"] == "butuh parent process").all()
        )
        self.assertTrue((result_df["llm_gate_priority"] == "needs_more_context").all())

    def test_skip_low_signal_with_note_keeps_high_signal_only(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"skip_low_signal_with_note","confidence":0.75,"reason":"drop window noise rendah"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(len(result_df), 1)
        self.assertEqual(int(result_df.iloc[0]["window_id"]), 1)
        self.assertEqual(
            result_df.iloc[0]["llm_gate_policy"], "skip_low_signal_with_note"
        )
        self.assertTrue(bool(result_df.iloc[0]["llm_gate_active"]))

    def test_missing_confidence_destructive_policy_fails_open(self):
        fake_llm = FakeLLM(
            '{"recommended_action":"skip_low_signal_with_note","reason":"missing confidence"}'
        )
        anomaly_filter = LLMAnomalyFilter(llm=fake_llm)

        result_df = anomaly_filter.filter_anomalies(
            self._build_anomalies_df(), pd.DataFrame()
        )

        self.assertEqual(len(result_df), 2)
        self.assertTrue((result_df["llm_gate_policy"] == "keep_all").all())
        self.assertIn("Low-confidence", result_df.iloc[0]["llm_reason"])


if __name__ == "__main__":
    unittest.main()
