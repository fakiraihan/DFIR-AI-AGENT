# pyright: reportMissingImports=false

import types
import unittest
import json

import pandas as pd

from modules.anomaly import DeepLogDetector  # pyright: ignore[reportImplicitRelativeImport]


class FakeVocab:
    def __init__(self):
        self.itos = ["<UNK>", "EventA", "EventB", "EventC"]
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

    def test_high_unknown_ratio_can_warn_without_forcing_normal(self):
        detector = self._detector(mode="warn", max_unknown_ratio=0.3)

        results = detector.detect_anomalies(self._df(["UnknownEvent", "EventB", "EventA"]))
        row = results.iloc[0]

        self.assertFalse(row["is_anomaly"])
        self.assertFalse(row["strict_is_anomaly"])
        self.assertEqual(row["evaluation_status"], "unknown_template_ratio_exceeded")
        self.assertGreater(row["unknown_ratio"], 0.3)

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
