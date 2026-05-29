import unittest
from pathlib import Path
import sys

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from evaluation.deeplog_eval import (  # noqa: E402
    auto_detect_label_column,
    auto_detect_line_id_column,
    build_parsed_df_from_structured_csv,
    build_arg_parser,
    build_window_ground_truth,
    compute_metrics,
    normalize_label,
)
from evaluation.calibration import calibrate_score_threshold  # noqa: E402
from evaluation.cached_records import (  # noqa: E402
    CachedSession,
    build_cached_windows,
    compose_cached_run_dir,
    deduplicate_cached_sessions,
    expand_cached_predictions,
)
from evaluation.promotion_gate import evaluate_promotion_gate  # noqa: E402


class DeepLogEvaluationHelpersTest(unittest.TestCase):
    def test_normalize_label_handles_lmd_and_binary_values(self):
        cases = {
            "-": 0,
            "Normal": 0,
            "0": 0,
            0: 0,
            "EoRS": 1,
            "EoHT": 1,
            "1": 1,
            1: 1,
        }

        for raw_value, expected in cases.items():
            with self.subTest(raw_value=raw_value):
                self.assertEqual(normalize_label(raw_value), expected)

    def test_auto_detect_label_and_line_id_columns(self):
        df = pd.DataFrame({"LineId": [1, 2], "Label": ["-", "EoRS"]})

        self.assertEqual(auto_detect_label_column(df), "Label")
        self.assertEqual(auto_detect_line_id_column(df), "LineId")

    def test_compute_metrics_returns_binary_confusion_counts(self):
        metrics = compute_metrics(
            y_true=[0, 0, 1, 1],
            y_pred=[0, 1, 0, 1],
            y_score=[0.1, 0.7, 0.2, 0.9],
            mode_name="is_anomaly",
        )

        self.assertEqual(metrics["confusion_matrix"], {"tn": 1, "fp": 1, "fn": 1, "tp": 1})
        self.assertAlmostEqual(metrics["accuracy"], 0.5)
        self.assertAlmostEqual(metrics["precision"], 0.5)
        self.assertAlmostEqual(metrics["recall"], 0.5)
        self.assertAlmostEqual(metrics["f1_score"], 0.5)
        self.assertEqual(metrics["support_normal"], 2)
        self.assertEqual(metrics["support_anomaly"], 2)
        self.assertNotEqual(metrics["roc_auc"], "N/A")

    def test_calibrate_score_threshold_maximizes_f1_with_recall_floor(self):
        calibration = calibrate_score_threshold(
            y_true=[1, 1, 0, 0],
            y_score=[0.9, 0.6, 0.8, 0.1],
            base_pred=[0, 0, 0, 0],
            target_recall=0.75,
        )

        self.assertEqual(calibration["recommended_threshold"], 0.6)
        self.assertAlmostEqual(calibration["recommended_metrics"]["recall"], 1.0)
        self.assertAlmostEqual(calibration["recommended_metrics"]["f1_score"], 0.8)

    def test_calibrate_score_threshold_fails_when_recall_floor_is_impossible(self):
        with self.assertRaises(ValueError):
            calibrate_score_threshold(
                y_true=[1, 0],
                y_score=[0.9, 0.1],
                base_pred=[0, 0],
                target_recall=1.01,
            )

    def test_calibrate_score_threshold_fails_when_health_constraints_are_not_met(self):
        with self.assertRaises(ValueError):
            calibrate_score_threshold(
                y_true=[1, 1, 0, 0],
                y_score=[0.9, 0.6, 0.8, 0.1],
                base_pred=[0, 0, 0, 0],
                target_recall=0.75,
                min_precision=0.90,
                max_fpr=0.10,
                max_precision_recall_gap=0.10,
                require_healthy_threshold=True,
            )

    def test_build_window_ground_truth_maps_end_idx_to_line_id(self):
        parsed_df = pd.DataFrame(
            {
                "line_number": [1, 2, 3, 4],
                "event_template": ["A", "B", "C", "D"],
                "raw_line": ["raw A", "raw B", "raw C", "raw D"],
            }
        )
        labels_df = pd.DataFrame(
            {
                "line_number": [1, 2, 3, 4],
                "y_true": [0, 0, 1, 0],
            }
        )
        results_df = pd.DataFrame(
            {
                "window_id": [7],
                "start_idx": [0],
                "end_idx": [2],
                "is_anomaly": [True],
                "strict_is_anomaly": [False],
                "anomaly_score": [0.8],
                "evaluation_status": ["deeplog_topk_miss"],
                "actual_event": ["C"],
            }
        )

        aligned = build_window_ground_truth(
            results_df=results_df,
            parsed_df=parsed_df,
            labels_df=labels_df,
            policy="target_event",
        )

        self.assertEqual(len(aligned), 1)
        row = aligned.iloc[0]
        self.assertEqual(row["target_line_number"], 3)
        self.assertEqual(row["y_true"], 1)
        self.assertTrue(row["y_pred_is_anomaly"])
        self.assertEqual(row["label_policy_used"], "target_event")
        self.assertEqual(row["event_template"], "C")

    def test_build_parsed_df_from_structured_csv_uses_expected_columns(self):
        source_df = pd.DataFrame(
            {
                "LineId": [10, 11],
                "EventTemplate": ["Template A", "Template B"],
                "Content": ["raw A", "raw B"],
                "SystemTime": ["2026-01-01 00:00:00", "2026-01-01 00:00:01"],
                "Label": ["-", "EoHT"],
            }
        )

        parsed_df = build_parsed_df_from_structured_csv(source_df)

        self.assertEqual(parsed_df["line_number"].tolist(), [10, 11])
        self.assertEqual(parsed_df["event_template"].tolist(), ["Template A", "Template B"])
        self.assertEqual(parsed_df["raw_line"].tolist(), ["raw A", "raw B"])
        self.assertEqual(
            parsed_df["timestamp"].tolist(),
            ["2026-01-01 00:00:00", "2026-01-01 00:00:01"],
        )

    def test_arg_parser_accepts_lmd_enriched_profile(self):
        args = build_arg_parser().parse_args(["--profile", "lmd_enriched"])

        self.assertEqual(args.profile, "lmd_enriched")

    def test_promotion_gate_requires_healthy_natural_metrics(self):
        decision = evaluate_promotion_gate(
            {
                "precision": 0.72,
                "recall": 0.84,
                "f1_score": 0.77,
                "false_positive_rate": 0.22,
            }
        )

        self.assertTrue(decision["passed"])
        self.assertEqual(decision["failed_criteria"], [])

    def test_promotion_gate_rejects_unbalanced_recall_only_metrics(self):
        decision = evaluate_promotion_gate(
            {
                "precision": 0.40,
                "recall": 0.95,
                "f1_score": 0.56,
                "false_positive_rate": 0.80,
            }
        )

        self.assertFalse(decision["passed"])
        self.assertIn("precision", decision["failed_criteria"])
        self.assertIn("false_positive_rate", decision["failed_criteria"])
        self.assertIn("precision_recall_gap", decision["failed_criteria"])

    def test_deduplicate_cached_sessions_matches_training_last_label_policy(self):
        raw_records = [
            {"EventTemplate": ["A", "B", "C"], "Label": [0, 1, 0]},
            {"EventTemplate": ["A", "B", "C"], "Label": [0, 0, 0]},
            {"EventTemplate": ["A", "D", "E"], "Label": 1},
        ]

        sessions = deduplicate_cached_sessions(raw_records)

        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0].sequence, ["A", "B", "C"])
        self.assertEqual(sessions[0].label, 0)
        self.assertEqual(sessions[0].count, 2)
        self.assertEqual(sessions[1].sequence, ["A", "D", "E"])
        self.assertEqual(sessions[1].label, 1)
        self.assertEqual(sessions[1].count, 1)

    def test_build_cached_windows_uses_history_size_targets(self):
        sessions = [CachedSession(sequence=["A", "B", "C", "D"], label=1, count=2)]
        windows = build_cached_windows(sessions, history_size=2, pad_token="padding")

        self.assertEqual(len(windows), 2)
        self.assertEqual(windows[0].session_idx, 0)
        self.assertEqual(windows[0].history, ["A", "B"])
        self.assertEqual(windows[0].target, "C")
        self.assertEqual(windows[1].history, ["B", "C"])
        self.assertEqual(windows[1].target, "D")

    def test_expand_cached_predictions_repeats_by_original_session_count(self):
        sessions = [
            CachedSession(sequence=["A"], label=0, count=2),
            CachedSession(sequence=["B"], label=1, count=3),
        ]

        y_true, y_pred, scores = expand_cached_predictions(
            sessions=sessions,
            session_predictions=[0, 1],
            session_scores=[0.1, 0.9],
        )

        self.assertEqual(y_true, [0, 0, 1, 1, 1])
        self.assertEqual(y_pred, [0, 0, 1, 1, 1])
        self.assertEqual(scores, [0.1, 0.1, 0.9, 0.9, 0.9])

    def test_compose_cached_run_dir_matches_training_layout(self):
        config = {
            "output_dir": "./output_lmd2023_2_3m_per_host/",
            "dataset_name": "lmd2023",
            "grouping": "sliding",
            "window_size": 20,
            "step_size": 20,
            "is_chronological": True,
            "train_size": 0.8,
            "split_mode": "per_host_chronological",
        }

        run_dir = compose_cached_run_dir(
            config,
            config_path=Path(r"D:\FAKI\NEWMLMODL\config\deeplog_lmd2023_2_3m_per_host.yaml"),
        )

        self.assertEqual(
            run_dir,
            Path(
                r"D:\FAKI\NEWMLMODL\output_lmd2023_2_3m_per_host"
                r"\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological"
            ),
        )


if __name__ == "__main__":
    unittest.main()
