import tempfile
import unittest
from pathlib import Path
import sys

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.deeplog_template_enrichment import (  # noqa: E402
    enrich_event_template,
    enrich_structured_dataframe,
)
from services.parsing_service import apply_template_enrichment, build_model_profile  # noqa: E402
from tools.build_lmd_enriched_dataset import build_enriched_dataset  # noqa: E402


class DeepLogTemplateEnrichmentTest(unittest.TestCase):
    def test_enriches_network_connect_with_stable_context_buckets(self):
        row = {
            "EventTemplate": "Microsoft-Windows-Sysmon EventID=3",
            "Content": (
                "Microsoft-Windows-Sysmon EventID=3 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                "User=DOMAIN\\alice DestinationIp=10.0.0.5 DestinationPort=4444"
            ),
        }

        template = enrich_event_template(row)

        self.assertIn("EventID=3", template)
        self.assertIn("ImageClass=powershell", template)
        self.assertIn("UserClass=user", template)
        self.assertIn("DestinationClass=private", template)
        self.assertIn("DestinationPortClass=high", template)

    def test_enriches_process_create_command_and_parent_classes(self):
        row = {
            "EventTemplate": "Microsoft-Windows-Sysmon EventID=1",
            "Content": (
                "Microsoft-Windows-Sysmon EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                "CommandLine=\"powershell.exe -EncodedCommand SQBFAFgA\" "
                "ParentImage=C:\\Windows\\System32\\cmd.exe User=DOMAIN\\bob"
            ),
        }

        template = enrich_event_template(row)

        self.assertIn("EventID=1", template)
        self.assertIn("ImageClass=powershell", template)
        self.assertIn("CmdClass=encoded", template)
        self.assertIn("ParentClass=cmd", template)
        self.assertIn("UserClass=user", template)

    def test_enriches_process_access_lsass_context(self):
        row = {
            "EventTemplate": "Microsoft-Windows-Sysmon EventID=10",
            "Content": (
                "Microsoft-Windows-Sysmon EventID=10 SourceImage=C:\\Windows\\System32\\rundll32.exe "
                "TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010 User=NT AUTHORITY\\SYSTEM"
            ),
        }

        template = enrich_event_template(row)

        self.assertIn("EventID=10", template)
        self.assertIn("SourceClass=rundll32", template)
        self.assertIn("TargetClass=lsass", template)
        self.assertIn("AccessClass=high", template)
        self.assertIn("UserClass=system", template)

    def test_enrich_structured_dataframe_preserves_original_template(self):
        df = pd.DataFrame(
            {
                "LineId": [1],
                "EventTemplate": ["Microsoft-Windows-Sysmon EventID=3"],
                "Content": [
                    "Microsoft-Windows-Sysmon EventID=3 Image=System DestinationIp=8.8.8.8 DestinationPort=53"
                ],
            }
        )

        enriched = enrich_structured_dataframe(df)

        self.assertEqual(
            enriched.loc[0, "OriginalEventTemplate"],
            "Microsoft-Windows-Sysmon EventID=3",
        )
        self.assertIn("DestinationClass=public", enriched.loc[0, "EventTemplate"])
        self.assertIn("DestinationPortClass=dns", enriched.loc[0, "EventTemplate"])

    def test_apply_template_enrichment_updates_runtime_columns_and_templates(self):
        parsed_df = pd.DataFrame(
            {
                "line_number": [1],
                "event_template": ["Microsoft-Windows-Sysmon EventID=1"],
                "raw_line": [
                    "Microsoft-Windows-Sysmon EventID=1 Image=C:\\Windows\\System32\\cmd.exe CommandLine=\"cmd.exe /c whoami\""
                ],
            }
        )
        templates = [{"cluster_id": "old", "template": "Microsoft-Windows-Sysmon EventID=1", "size": 1}]

        enriched_df, enriched_templates = apply_template_enrichment(
            parsed_df,
            templates,
            "lmd_sysmon_v1",
        )

        self.assertIn("ImageClass=cmd", enriched_df.loc[0, "event_template"])
        self.assertEqual(enriched_df.loc[0, "EventTemplate"], enriched_df.loc[0, "event_template"])
        self.assertEqual(enriched_templates[0]["size"], 1)
        self.assertIn("ImageClass=cmd", enriched_templates[0]["template"])

    def test_build_enriched_dataset_writes_chunked_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "lmd2023.log_structured.csv"
            output_path = Path(tmpdir) / "enriched" / "lmd2023.log_structured.csv"
            pd.DataFrame(
                {
                    "LineId": [1, 2],
                    "Timestamp": [1, 2],
                    "Label": ["-", "EoRS"],
                    "EventId": [1, 3],
                    "EventTemplate": [
                        "Microsoft-Windows-Sysmon EventID=1",
                        "Microsoft-Windows-Sysmon EventID=3",
                    ],
                    "Content": [
                        "Microsoft-Windows-Sysmon EventID=1 Image=C:\\Windows\\System32\\cmd.exe CommandLine=\"cmd.exe /c whoami\"",
                        "Microsoft-Windows-Sysmon EventID=3 Image=System DestinationIp=10.0.0.8 DestinationPort=445",
                    ],
                    "AgentName": ["host-a", "host-a"],
                }
            ).to_csv(input_path, index=False)

            summary = build_enriched_dataset(
                input_path=input_path,
                output_path=output_path,
                chunksize=1,
            )

            written = pd.read_csv(output_path)
            self.assertEqual(summary["rows"], 2)
            self.assertEqual(len(written), 2)
            self.assertIn("OriginalEventTemplate", written.columns)
            self.assertIn("ImageClass=cmd", written.loc[0, "EventTemplate"])
            self.assertIn("DestinationPortClass=smb", written.loc[1, "EventTemplate"])

    def test_sysmon_profile_can_promote_enriched_model_independently(self):
        class DummySettings:
            sysmon_deeplog_model_path = "D:/models/enriched/DeepLog.pt"
            sysmon_deeplog_vocab_path = "D:/models/enriched/DeepLog.pkl"
            sysmon_deeplog_window_size = 10
            sysmon_deeplog_topk = 9
            sysmon_parser_template_strategy = "provider_eventid"
            sysmon_deeplog_template_enrichment = "lmd_sysmon_v1"
            deeplog_topk = 3

        profile = build_model_profile("sysmon", DummySettings())

        self.assertEqual(profile["topk"], 9)
        self.assertEqual(profile["window_size"], 10)
        self.assertEqual(profile["template_enrichment"], "lmd_sysmon_v1")


if __name__ == "__main__":
    unittest.main()
