import json
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from evaluation.deeplog_eval import build_arg_parser  # noqa: E402
from modules.linux_log_templates import (  # noqa: E402
    build_linux_event_template,
    classify_linux_log_source,
)
from modules.parsing import parse_log_file  # noqa: E402
from services.parsing_service import build_model_profile  # noqa: E402
from tools.build_linux_ait_lds_dataset import build_linux_ait_lds_dataset  # noqa: E402


class LinuxAitLdsProfileTest(unittest.TestCase):
    def test_linux_template_builder_normalizes_auth_audit_and_syslog(self):
        auth_template = build_linux_event_template(
            "Jan 24 04:37:58 intranet-server sudo:    jhall : "
            "TTY=pts/1 ; PWD=/var/www/intranet ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            source_hint="auth",
        )
        audit_template = build_linux_event_template(
            "type=USER_AUTH msg=audit(1642999060.603:2226): pid=27950 uid=33 "
            "msg='op=PAM:authentication acct=\"jhall\" exe=\"/bin/su\" res=success'",
            source_hint="audit",
        )
        syslog_template = build_linux_event_template(
            "Jan 24 04:18:10 intranet-server systemd[1]: Started Session 42 of user jhall.",
            source_hint="syslog",
        )

        self.assertEqual(auth_template, "LinuxAuth process=sudo action=sudo_command")
        self.assertEqual(
            audit_template,
            "LinuxAudit type=USER_AUTH op=PAM:authentication exe=su res=success",
        )
        self.assertEqual(
            syslog_template,
            "LinuxSyslog process=systemd action=started_session",
        )

    def test_linux_template_builder_handles_loghub_pam_process_names(self):
        raw_line = (
            "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; "
            "logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"
        )

        self.assertEqual(classify_linux_log_source(raw_line=raw_line), "auth")
        self.assertEqual(
            build_linux_event_template(raw_line),
            "LinuxAuth process=sshd action=pam_auth_failure",
        )

    def test_build_linux_ait_lds_dataset_uses_mirrored_jsonl_labels(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            gather_logs = root / "gather" / "intranet_server" / "logs"
            labels_logs = root / "labels" / "intranet_server" / "logs"
            (gather_logs / "audit").mkdir(parents=True)
            (labels_logs / "audit").mkdir(parents=True)

            (gather_logs / "auth.log").write_text(
                "\n".join(
                    [
                        "Jan 24 04:17:01 intranet-server CRON[27933]: pam_unix(cron:session): session opened for user root by (uid=0)",
                        "Jan 24 04:37:58 intranet-server sudo:    jhall : TTY=pts/1 ; PWD=/var/www/intranet ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (labels_logs / "auth.log").write_text(
                json.dumps(
                    {
                        "line": 2,
                        "labels": ["escalated_command", "escalate"],
                        "rules": {"escalate": ["attacker.escalate.sudo.command"]},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (gather_logs / "audit" / "audit.log").write_text(
                "type=USER_AUTH msg=audit(1642999060.603:2226): pid=27950 uid=33 "
                "msg='op=PAM:authentication acct=\"jhall\" exe=\"/bin/su\" res=success'\n",
                encoding="utf-8",
            )
            (gather_logs / "syslog").write_text(
                "Jan 24 04:18:10 intranet-server systemd[1]: Started Session 42 of user jhall.\n",
                encoding="utf-8",
            )
            (gather_logs / "apache_access.log").write_text(
                '127.0.0.1 - - [24/Jan/2022:04:18:10 +0000] "GET / HTTP/1.1" 200 2\n',
                encoding="utf-8",
            )
            config_dir = root / "gather" / "intranet_server" / "configs" / "systemd" / "system"
            config_dir.mkdir(parents=True)
            (config_dir / "syslog.service").write_text(
                "[Service]\nExecStart=/usr/sbin/rsyslogd -n\n",
                encoding="utf-8",
            )

            output_dir = root / "out"
            summary = build_linux_ait_lds_dataset(
                input_root=root,
                output_dir=output_dir,
                log_name="linux_ait_lds.log",
                default_year=2022,
            )

            structured_path = output_dir / "linux_ait_lds.log_structured.csv"
            written = pd.read_csv(structured_path)

            self.assertEqual(summary["rows"], 4)
            self.assertEqual(written["Label"].value_counts().to_dict(), {"-": 3, "attack": 1})
            attack_row = written[written["Label"] == "attack"].iloc[0]
            self.assertEqual(attack_row["AttackLabels"], "escalate|escalated_command")
            self.assertIn("sudo_command", attack_row["EventTemplate"])
            self.assertEqual(set(written["LogSource"]), {"auth", "audit", "syslog"})
            self.assertEqual(written["AgentName"].unique().tolist(), ["intranet_server"])
            self.assertIn("EventId", written.columns)
            self.assertTrue((written["Timestamp"] > 0).all())
            self.assertNotIn("apache_access.log", summary["sources"])
            self.assertNotIn("intranet_server/configs/systemd/system/syslog.service", summary["sources"])

    def test_linux_parser_strategy_uses_deterministic_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_log = Path(tmpdir) / "auth.log"
            auth_log.write_text(
                "Jan 24 04:37:58 intranet-server sudo:    jhall : "
                "TTY=pts/1 ; PWD=/var/www/intranet ; USER=root ; COMMAND=/bin/cat /etc/shadow\n",
                encoding="utf-8",
            )

            parsed_df, templates = parse_log_file(
                str(auth_log),
                template_strategy="linux_ait_lds",
            )

            self.assertEqual(len(parsed_df), 1)
            self.assertEqual(
                parsed_df.loc[0, "event_template"],
                "LinuxAuth process=sudo action=sudo_command",
            )
            self.assertGreater(int(parsed_df.loc[0, "timestamp"]), 0)
            self.assertEqual(templates[0]["template"], parsed_df.loc[0, "event_template"])

    def test_linux_profile_and_evaluator_choice_are_registered(self):
        class DummySettings:
            linux_ait_lds_deeplog_model_path = "D:/models/linux/DeepLog.pt"
            linux_ait_lds_deeplog_vocab_path = "D:/models/linux/DeepLog.pkl"
            linux_ait_lds_deeplog_window_size = 10
            linux_ait_lds_deeplog_topk = 9
            linux_ait_lds_parser_template_strategy = "linux_ait_lds"
            linux_ait_lds_deeplog_template_enrichment = "none"

        profile = build_model_profile("linux_ait_lds", DummySettings())
        args = build_arg_parser().parse_args(["--profile", "linux_ait_lds"])

        self.assertEqual(profile["name"], "linux_ait_lds")
        self.assertEqual(profile["template_strategy"], "linux_ait_lds")
        self.assertEqual(profile["topk"], 9)
        self.assertEqual(args.profile, "linux_ait_lds")


if __name__ == "__main__":
    unittest.main()
