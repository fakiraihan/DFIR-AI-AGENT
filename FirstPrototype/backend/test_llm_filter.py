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
            '{"recommended_action":"keep_high_confidence_only","reason":"fokus pada anomali paling kuat"}'
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

        self.assertEqual(fake_llm.calls, 1)
        self.assertEqual(len(result_df), len(input_df))
        self.assertTrue((result_df["llm_gate_policy"] == "keep_all").all())


if __name__ == "__main__":
    unittest.main()
