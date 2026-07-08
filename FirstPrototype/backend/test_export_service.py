import json
import tempfile
import unittest
from pathlib import Path
import sys

import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services.export_service import build_export_artifacts


class ExportServiceTest(unittest.TestCase):
    def test_build_export_artifacts_writes_all_formats_and_manifest(self):
        parsed_df = pd.DataFrame(
            [
                {
                    "line_number": 1,
                    "event_id": 1,
                    "timestamp": "2026-05-31T08:00:00Z",
                    "event_template": "EventID 4624 Provider Security",
                    "parameter_array": ["10.0.0.1"],
                    "parameter_map": {"destination_ip": "10.0.0.1"},
                    "raw_line": "login success from 10.0.0.1",
                    "cluster_id": "template-1",
                },
                {
                    "line_number": 2,
                    "event_id": 2,
                    "timestamp": "2026-05-31T08:00:01Z",
                    "event_template": "EventID 4688 Provider Security",
                    "parameter_array": ["powershell.exe"],
                    "parameter_map": {"image": "powershell.exe"},
                    "raw_line": "process launch powershell.exe",
                    "cluster_id": "template-2",
                },
            ]
        )
        results_df = pd.DataFrame(
            [
                {
                    "window_id": 10,
                    "is_anomaly": True,
                    "candidate_tier": "high",
                    "evaluation_status": "deeplog_topk_miss",
                    "anomaly_score": 0.94,
                    "lines": [
                        {"line_number": 1, "is_anomalous_line": False},
                        {"line_number": 2, "is_anomalous_line": True},
                    ],
                }
            ]
        )
        anomalies_df = pd.DataFrame(
            [
                {
                    "window_id": 10,
                }
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_session_dir = Path(temp_dir) / "session_x"
            output_session_dir.mkdir(parents=True, exist_ok=True)
            artifacts = build_export_artifacts(
                session_id="session_x",
                file_name="sample.evtx",
                output_session_dir=output_session_dir,
                parsed_df=parsed_df,
                results_df=results_df,
                anomalies_df=anomalies_df,
                selected_profile={
                    "name": "windows_evtx",
                    "template_strategy": "windows_evtx_canonical",
                    "window_size": 20,
                    "topk": 9,
                },
            )

            manifest_path = Path(artifacts["manifest_path"])
            jsonl_path = Path(artifacts["jsonl_path"])
            ndjson_path = Path(artifacts["ndjson_path"])
            csv_path = Path(artifacts["csv_path"])

            self.assertTrue(manifest_path.exists())
            self.assertTrue(jsonl_path.exists())
            self.assertTrue(ndjson_path.exists())
            self.assertTrue(csv_path.exists())

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["session_id"], "session_x")
            self.assertEqual(manifest["summary"]["parsed_lines"], 2)
            self.assertEqual(manifest["summary"]["anomaly_window_count"], 1)
            self.assertEqual(manifest["summary"]["retained_anomaly_window_count"], 1)

            jsonl_records = [
                json.loads(line)
                for line in jsonl_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(jsonl_records), 2)
            self.assertEqual(jsonl_records[1]["kanban"]["lane"], "investigated")
            self.assertTrue(jsonl_records[1]["deeplog"]["is_anomalous_line"])

            ndjson_lines = [line for line in ndjson_path.read_text(encoding="utf-8").splitlines() if line]
            self.assertEqual(len(ndjson_lines), 4)
            first_meta = json.loads(ndjson_lines[0])
            self.assertEqual(first_meta["index"]["_index"], "firstprototype-parsed-logs")


if __name__ == "__main__":
    unittest.main()
