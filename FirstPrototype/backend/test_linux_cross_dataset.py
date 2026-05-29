import gzip
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from tools.build_linux_cross_dataset import (  # noqa: E402
    build_linux_loghub_dataset,
    build_organizationx_dataset,
)


class LinuxCrossDatasetBuilderTest(unittest.TestCase):
    def test_build_linux_loghub_dataset_uses_linux_templates_and_normal_labels(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "Linux_2k.log"
            source.write_text(
                "\n".join(
                    [
                        "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
                        "Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_linux_loghub_dataset(
                input_log=source,
                output_dir=root / "out",
                log_name="linux_loghub.log",
            )
            written = pd.read_csv(root / "out" / "linux_loghub.log_structured.csv")

            self.assertEqual(summary["rows"], 2)
            self.assertEqual(written["Label"].tolist(), ["-", "-"])
            self.assertEqual(written["Timestamp"].tolist(), [1, 2])
            self.assertEqual(written["AgentName"].unique().tolist(), ["loghub_linux"])
            self.assertEqual(
                written["EventTemplate"].tolist(),
                [
                    "LinuxAuth process=sshd action=pam_auth_failure",
                    "LinuxAuth process=su action=pam_session_open",
                ],
            )

    def test_build_organizationx_dataset_applies_yaml_rules_and_gzip_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "organization-x"
            ground_truth = root / "ground-truth"
            log_dir = root / "log" / "apache2"
            ground_truth.mkdir(parents=True)
            log_dir.mkdir(parents=True)
            (root / "log").mkdir(exist_ok=True)
            (ground_truth / "organization-x.yaml").write_text(
                "\n".join(
                    [
                        "- id: sql_injection_attempt",
                        "  ground_truth_label: sql_injection_attempt",
                        "  filter:",
                        "    - \"UNION%\"",
                        "    - \"select+\"",
                        "- id: bruteforce_login_server_attempt",
                        "  ground_truth_label: bruteforce_login_server_attempt",
                        "  filter:",
                        "    - \"authentication failure\"",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "log" / "auth.log").write_text(
                "Oct  6 10:00:01 web sshd[1]: authentication failure; user=root\n",
                encoding="utf-8",
            )
            with gzip.open(log_dir / "web-access.log.1.gz", "wt", encoding="utf-8") as handle:
                handle.write(
                    '10.0.0.1 - - [06/Oct/2025:10:01:02 +0000] "GET /?q=UNION+select+1 HTTP/1.1" 200 42 "-" "curl"\n'
                )
                handle.write(
                    '10.0.0.2 - - [06/Oct/2025:10:01:03 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"\n'
                )

            summary = build_organizationx_dataset(
                input_root=root,
                output_dir=root / "out",
                log_name="linux_organizationx.log",
                include_sources=("auth", "apache"),
            )
            written = pd.read_csv(root / "out" / "linux_organizationx.log_structured.csv")

            self.assertEqual(summary["rows"], 3)
            self.assertEqual(summary["label_counts"], {"attack": 2, "-": 1})
            self.assertEqual(set(written["LogSource"]), {"auth", "apache"})
            self.assertIn("sql_injection_attempt", "|".join(written["AttackLabels"].dropna()))
            self.assertIn(
                "ApacheAccess method=GET status=200 action=sql_probe",
                written["EventTemplate"].tolist(),
            )


if __name__ == "__main__":
    unittest.main()
