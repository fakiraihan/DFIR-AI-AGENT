import unittest
from pathlib import Path
import sys

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services.orchestrator_service import (  # noqa: E402
    _is_recall_preserving_deeplog_policy,
    _merge_llm_gate_annotations,
)


class OrchestratorRecallPolicyTest(unittest.TestCase):
    def test_recall_policy_preserves_candidates_and_merges_llm_annotations(self):
        candidates_df = pd.DataFrame(
            [
                {"window_id": 1, "is_anomaly": True, "candidate_tier": "high"},
                {"window_id": 2, "is_anomaly": True, "candidate_tier": "low"},
            ]
        )
        filtered_df = pd.DataFrame(
            [
                {
                    "window_id": 1,
                    "llm_filtered": True,
                    "llm_gate_policy": "keep_high_confidence_only",
                    "llm_gate_priority": "high_confidence",
                    "llm_gate_priority_rank": 2,
                }
            ]
        )

        merged = _merge_llm_gate_annotations(candidates_df, filtered_df)

        self.assertEqual(len(merged), 2)
        self.assertTrue(bool(merged.loc[merged["window_id"] == 1, "llm_filtered"].iloc[0]))
        self.assertFalse(bool(merged.loc[merged["window_id"] == 2, "llm_filtered"].iloc[0]))
        self.assertEqual(
            merged.loc[merged["window_id"] == 2, "llm_gate_priority"].iloc[0],
            "not_retained_by_llm_gate",
        )

    def test_f1_constrained_recall_policy_is_recall_preserving(self):
        self.assertTrue(_is_recall_preserving_deeplog_policy("f1_constrained_recall"))
        self.assertFalse(_is_recall_preserving_deeplog_policy("topk"))


if __name__ == "__main__":
    unittest.main()
