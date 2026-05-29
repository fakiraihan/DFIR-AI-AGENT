# pyright: reportMissingImports=false

import types
import unittest
import json
from pathlib import Path
import sys

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.anomaly import DeepLogDetector  # pyright: ignore[reportImplicitRelativeImport]


class FakeVocab:
    def __init__(self):
        self.security_audit_template = (
            "EventID <*> Provider Microsoft-Windows-Security-Auditing "
            "Channel Security Task <*> Rule Windows audit <*> <*>"
        )
        self.itos = [
            "<UNK>",
            "EventA",
            "EventB",
            "EventC",
            self.security_audit_template,
            "<BOS>",
        ]
        self.stoi = {event: index for index, event in enumerate(self.itos)}
        self.unk_index = 0

    def get_event(self, event_template):
        return self.stoi.get(event_template, self.unk_index)


class DeepLogUnknownTemplateTest(unittest.TestCase):
    def _detector(self, mode="ignore", max_unknown_ratio=0.4):
        detector = DeepLogDetector.__new__(DeepLogDetector)
        detector.window_size = 2
        detector.step_size = 1
        detector.topk = 2
        detector.device = "cpu"
        detector.skip_unknown_windows = mode == "ignore"
        detector.max_unknown_ratio = max_unknown_ratio
        detector.unknown_template_mode = mode
        detector.evtx_sparse_fallback_enabled = True
        detector.evtx_sparse_fallback_threshold = 0.75
        detector.template_similarity_enabled = False
        detector.template_similarity_threshold = 0.65
        detector.use_bos_context = False
        detector.bos_token = "<BOS>"
        detector.bos_count = 2
        detector._template_similarity_cache = {}
        detector._template_similarity_candidates = None
        detector.vocab = FakeVocab()
        detector.unk_index = detector.vocab.unk_index
        detector._predict_topk = types.MethodType(
            lambda self, window_indices, actual_idx: ([1, 2], [0.7, 0.2], 0.05),
            detector,
        )
        return detector

    def _df(self, templates):
        return pd.DataFrame(
            {
                "event_template": templates,
                "line_number": list(range(1, len(templates) + 1)),
                "timestamp": [""] * len(templates),
                "raw_line": templates,
            }
        )

    def test_unknown_actual_event_can_be_marked_anomalous_by_mode(self):
        detector = self._detector(mode="anomaly")

        results = detector.detect_anomalies(self._df(["EventA", "EventB", "UnknownEvent"]))
        row = results.iloc[0]

        self.assertTrue(row["is_anomaly"])
        self.assertEqual(row["evaluation_status"], "unknown_template")
        self.assertEqual(row["anomaly_score"], 1.0)
        self.assertEqual(row["actual_event"], "UnknownEvent")

    def test_evaluate_mode_keeps_deeplog_topk_decision_for_unknown(self):
        detector = self._detector(mode="evaluate")

        results = detector.detect_anomalies(self._df(["EventA", "EventB", "UnknownEvent"]))
        row = results.iloc[0]

        self.assertTrue(row["is_anomaly"])
        self.assertTrue(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "deeplog_topk_miss")
        self.assertEqual(row["actual_event"], "UnknownEvent")

    def test_template_similarity_maps_canonical_evtx_to_vocab_template(self):
        detector = self._detector(mode="evaluate")
        detector.template_similarity_enabled = True
        runtime_template = (
            "EventID 4624 Provider Microsoft-Windows-Security-Auditing "
            "Channel Security Task 12544 Level 0"
        )

        event_index = detector._event_to_index(runtime_template)

        self.assertEqual(
            detector._index_to_event(event_index),
            detector.vocab.security_audit_template,
        )

    def test_high_unknown_ratio_can_warn_without_forcing_normal(self):
        detector = self._detector(mode="warn", max_unknown_ratio=0.3)

        results = detector.detect_anomalies(self._df(["UnknownEvent", "EventB", "EventA"]))
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "unknown_template_ratio_exceeded")
        self.assertGreater(row["unknown_ratio"], 0.3)

    def test_warn_mode_does_not_flag_plain_unknown_without_evtx_signal(self):
        detector = self._detector(mode="warn")

        results = detector.detect_anomalies(self._df(["EventA", "EventB", "UnknownEvent"]))
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "unknown_template")
        self.assertEqual(row["actual_event"], "UnknownEvent")

    def test_ignore_mode_preserves_old_unknown_skip_behavior(self):
        detector = self._detector(mode="ignore")

        results = detector.detect_anomalies(self._df(["EventA", "EventB", "UnknownEvent"]))
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["anomaly_score"], 0.0)
        self.assertEqual(row["evaluation_status"], "unknown_template")

    def test_known_template_topk_miss_still_flags_deeplog_anomaly(self):
        detector = self._detector(mode="ignore")

        results = detector.detect_anomalies(self._df(["EventA", "EventB", "EventC"]))
        row = results.iloc[0]

        self.assertTrue(row["is_anomaly"])
        self.assertTrue(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "deeplog_topk_miss")
        self.assertEqual(row["actual_event"], "EventC")

    def test_known_template_topk_hit_remains_normal_with_evaluated_status(self):
        detector = self._detector(mode="ignore")

        results = detector.detect_anomalies(self._df(["EventA", "EventC", "EventB"]))
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "evaluated")
        self.assertEqual(row["actual_event"], "EventB")
        self.assertIn("EventB", row["predicted_events"])

    def test_recall_policy_flags_topk_hit_when_score_crosses_threshold(self):
        detector = self._detector(mode="evaluate")
        detector.decision_policy = "f1_constrained_recall"
        detector.score_threshold = 0.6
        detector.medium_score_threshold = 0.7
        detector.recall_floor = 0.8
        detector._predict_topk = types.MethodType(
            lambda self, window_indices, actual_idx: ([actual_idx, 1], [0.35, 0.3], 0.35),
            detector,
        )

        results = detector.detect_anomalies(self._df(["EventA", "EventC", "EventB"]))
        row = results.iloc[0]

        self.assertTrue(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "score_threshold_exceeded")
        self.assertEqual(row["candidate_tier"], "low")
        self.assertIn("score_threshold", row["candidate_reasons"])
        self.assertEqual(row["decision_policy"], "f1_constrained_recall")
        self.assertEqual(row["score_threshold"], 0.6)
        self.assertEqual(row["recall_floor"], 0.8)

    def test_candidate_tier_is_high_for_topk_miss_and_medium_for_high_score(self):
        detector = self._detector(mode="evaluate")
        detector.decision_policy = "f1_constrained_recall"
        detector.score_threshold = 0.6
        detector.medium_score_threshold = 0.7
        detector.recall_floor = 0.8

        miss_results = detector.detect_anomalies(self._df(["EventA", "EventB", "EventC"]))
        self.assertEqual(miss_results.iloc[0]["candidate_tier"], "high")
        self.assertIn("topk_miss", miss_results.iloc[0]["candidate_reasons"])

        detector._predict_topk = types.MethodType(
            lambda self, window_indices, actual_idx: ([actual_idx, 1], [0.2, 0.2], 0.2),
            detector,
        )
        score_results = detector.detect_anomalies(self._df(["EventA", "EventC", "EventB"]))
        self.assertTrue(score_results.iloc[0]["is_anomaly"])
        self.assertFalse(score_results.iloc[0]["strict_is_anomaly"])
        self.assertEqual(score_results.iloc[0]["candidate_tier"], "medium")

    def test_bos_context_allows_single_event_deeplog_evaluation(self):
        detector = self._detector(mode="evaluate")
        detector.use_bos_context = True
        detector.bos_count = 2

        results = detector.detect_anomalies(self._df(["EventA"]))
        row = results.iloc[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(row["actual_event"], "EventA")
        self.assertEqual(row["window_templates"], "<BOS> | <BOS>")
        self.assertFalse(row["is_anomaly"])
        self.assertEqual(row["evaluation_status"], "evaluated")
        self.assertEqual(len(row["lines"]), 1)

    def test_sparse_evtx_surrogate_uses_explicit_fallback_for_suspicious_row(self):
        detector = self._detector(mode="ignore")
        detector.window_size = 10
        parameter_map = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }
        df = pd.DataFrame(
            {
                "event_template": ["Microsoft-Windows-Sysmon EventID=1"],
                "EventId": [1],
                "Component": ["Microsoft-Windows-Sysmon"],
                "EventTemplate": ["Microsoft-Windows-Sysmon EventID=1"],
                "Content": ["Process Create powershell encodedcommand"],
                "ParameterList": [json.dumps(list(parameter_map.values()))],
                "Level": ["Warning"],
                "parameter_map": [json.dumps(parameter_map)],
                "line_number": [1],
                "timestamp": [""],
                "raw_line": ["powershell.exe -EncodedCommand SQBFAFgA"],
            }
        )

        results = detector.detect_anomalies(df)
        row = results.iloc[0]

        self.assertTrue(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "evtx_sparse_fallback")
        self.assertNotEqual(row["evaluation_status"], "deeplog_topk_miss")
        self.assertGreaterEqual(row["anomaly_score"], 0.75)
        self.assertEqual(row["predicted_events"], "")
        self.assertIn("field:command_line", row["fallback_reasons"])

    def test_sparse_evtx_surrogate_keeps_benign_row_non_anomalous(self):
        detector = self._detector(mode="ignore")
        detector.window_size = 10
        df = pd.DataFrame(
            {
                "event_template": ["Microsoft-Windows-Security-Auditing EventID=4624"],
                "EventId": [4624],
                "Component": ["Microsoft-Windows-Security-Auditing"],
                "EventTemplate": ["Microsoft-Windows-Security-Auditing EventID=4624"],
                "Content": ["An account was successfully logged on"],
                "ParameterList": [json.dumps(["User=alice", "LogonType=2"])],
                "Level": ["Information"],
                "parameter_map": [json.dumps({"User": "alice", "LogonType": "2"})],
                "line_number": [1],
                "timestamp": [""],
                "raw_line": ["User=alice LogonType=2"],
            }
        )

        results = detector.detect_anomalies(df)
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "evtx_sparse_fallback")
        self.assertLess(row["anomaly_score"], 0.75)


if __name__ == "__main__":
    _ = unittest.main()
