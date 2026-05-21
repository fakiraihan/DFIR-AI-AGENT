import asyncio
import inspect
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pandas as pd

from services import analyze_service, orchestrator_service  # pyright: ignore[reportImplicitRelativeImport]


class ServiceAnomalySummaryTest(unittest.TestCase):
    def test_summary_preserves_existing_keys_and_adds_status_distribution(self):
        results_df = pd.DataFrame(
            {
                "evaluation_status": [
                    "evaluated",
                    "unknown_template",
                    "unknown_template_ratio_exceeded",
                    "evtx_sparse_fallback",
                    "deeplog_topk_miss",
                ],
                "strict_is_anomaly": [False, False, False, False, True],
                "unknown_ratio": [0.0, 1.0, 0.5, 1.0, 0.0],
            }
        )

        skipped, strict_count, avg_unknown_ratio, status_counts = (
            analyze_service._summarize_anomaly_results(results_df)
        )

        self.assertEqual(skipped, 2)
        self.assertEqual(strict_count, 1)
        self.assertAlmostEqual(avg_unknown_ratio, 0.5)
        self.assertEqual(
            status_counts,
            {
                "unknown_template": 1,
                "unknown_template_ratio_exceeded": 1,
                "evtx_sparse_fallback": 1,
                "deeplog_topk_miss": 1,
            },
        )

    def test_orchestrator_status_counter_uses_evaluation_status_column(self):
        results_df = pd.DataFrame(
            {
                "evaluation_status": [
                    "unknown_template",
                    "unknown_template",
                    "evtx_sparse_fallback",
                    "deeplog_topk_miss",
                    "evaluated",
                ]
            }
        )

        self.assertEqual(
            orchestrator_service._count_evaluation_statuses(results_df),
            {
                "unknown_template": 2,
                "unknown_template_ratio_exceeded": 0,
                "evtx_sparse_fallback": 1,
                "deeplog_topk_miss": 1,
            },
        )

    def test_quick_analysis_passes_unknown_and_fallback_settings_to_detector(self):
        captured_kwargs = {}

        def fake_detect(*args, **kwargs):
            captured_kwargs.update(kwargs)
            results_df = pd.DataFrame(
                {
                    "evaluation_status": ["unknown_template", "deeplog_topk_miss"],
                    "is_anomaly": [False, True],
                    "strict_is_anomaly": [False, True],
                    "unknown_ratio": [1.0, 0.0],
                }
            )
            return results_df, results_df[results_df["is_anomaly"] == True].copy()

        parsed_df = pd.DataFrame(
            {
                "event_template": ["EventA", "EventB", "EventC"],
                "line_number": [1, 2, 3],
                "event_id": [1, 2, 3],
            }
        )
        profile = {
            "name": "test-profile",
            "window_size": 2,
            "model_path": Path(__file__),
            "vocab_path": Path(__file__),
            "template_strategy": "drain",
        }
        file = types.SimpleNamespace(filename="sample.log")

        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            stack.enter_context(patch("services.analyze_service.DATA_DIR", Path(temp_dir)))
            stack.enter_context(
                patch("services.analyze_service.generate_session_id", return_value="analyze_service_summary_test")
            )
            stack.enter_context(
                patch("services.analyze_service.save_upload_file", new=AsyncMock())
            )
            stack.enter_context(
                patch(
                    "services.analyze_service.parse_with_profile",
                    return_value=(parsed_df, {"EventA": 1}, profile),
                )
            )
            stack.enter_context(
                patch("modules.anomaly.detect_anomalies_in_logs", side_effect=fake_detect)
            )
            stack.enter_context(
                patch.object(analyze_service.settings, "deeplog_unknown_template_mode", "anomaly")
            )
            stack.enter_context(
                patch.object(
                    analyze_service.settings,
                    "deeplog_evtx_sparse_fallback_enabled",
                    False,
                )
            )
            stack.enter_context(
                patch.object(
                    analyze_service.settings,
                    "deeplog_evtx_sparse_fallback_threshold",
                    0.9,
                )
            )

            response = asyncio.run(
                analyze_service.run_quick_analysis(
                    file,
                    max_lines=10,
                    sample_step=1,
                    anomaly_limit=5,
                )
            )

        self.assertEqual(captured_kwargs["unknown_template_mode"], "anomaly")
        self.assertFalse(captured_kwargs["evtx_sparse_fallback_enabled"])
        self.assertEqual(captured_kwargs["evtx_sparse_fallback_threshold"], 0.9)
        for key in (
            "window_count",
            "anomaly_count",
            "strict_anomaly_count",
            "skipped_windows",
            "avg_unknown_ratio",
        ):
            self.assertIn(key, response["summary"])
        self.assertEqual(response["summary"]["evaluation_status_counts"]["unknown_template"], 1)
        self.assertEqual(response["summary"]["evaluation_status_counts"]["deeplog_topk_miss"], 1)

    def test_full_investigation_detector_call_passes_unknown_and_fallback_settings(self):
        source = inspect.getsource(orchestrator_service.run_investigation_pipeline)

        self.assertIn(
            "unknown_template_mode=settings.deeplog_unknown_template_mode",
            source,
        )
        self.assertIn(
            "evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled",
            source,
        )
        self.assertIn(
            "evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold",
            source,
        )


if __name__ == "__main__":
    _ = unittest.main()
