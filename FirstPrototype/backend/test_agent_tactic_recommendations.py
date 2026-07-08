import unittest

from modules.agent import DFIRAgent


class NoopLLM:
    def invoke(self, prompt: str) -> str:
        return ""


class AgentTacticRecommendationsTest(unittest.TestCase):
    def _agent(self) -> DFIRAgent:
        return DFIRAgent(llm=NoopLLM())

    def test_defense_evasion_prioritizes_log_clear_and_registry_evidence(self):
        state = {
            "evaluation_evidence_brief": "- tactic_folder: Defense Evasion",
            "tool_results": [],
            "iocs_extracted": [],
            "attack_timeline": [],
            "anomalies": [
                {
                    "window_id": 1,
                    "actual_event": "EventID 5156 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "anomaly_score": 0.999,
                    "anomalous_line": {
                        "important_fields": {
                            "destination_port": "547",
                            "domain": "PC01.example.corp",
                        },
                        "parameters": {"EventID": "5156"},
                    },
                },
                {
                    "window_id": 0,
                    "actual_event": "EventID 1102 Provider Microsoft-Windows-Eventlog Channel Security",
                    "anomaly_score": 0.987,
                    "anomalous_line": {
                        "important_fields": {"domain": "PC01.example.corp"},
                        "parameters": {
                            "EventID": "1102",
                            "Computer": "PC01.example.corp",
                        },
                    },
                },
                {
                    "window_id": 2,
                    "actual_event": "EventID 4663 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "anomaly_score": 0.981,
                    "anomalous_line": {
                        "important_fields": {
                            "object_name": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy",
                            "process_name": r"C:\Windows\System32\svchost.exe",
                            "subject_user": "LOCAL",
                        },
                        "parameters": {"EventID": "4663"},
                    },
                },
            ],
        }

        text = "\n".join(self._agent()._generate_default_recommendations(state))

        self.assertIn("EventID 1102", text)
        self.assertIn("security log cleared", text)
        self.assertIn("FipsAlgorithmPolicy", text)
        self.assertIn("svchost.exe", text)

    def test_discovery_recommendations_identify_actor_object_and_authorization(self):
        state = {
            "evaluation_evidence_brief": "- tactic_folder: Discovery",
            "tool_results": [],
            "iocs_extracted": [],
            "attack_timeline": [],
            "anomalies": [
                {
                    "window_id": 23,
                    "actual_event": "EventID 4661 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "anomaly_score": 0.999,
                    "anomalous_line": {
                        "important_fields": {
                            "object_name": "DC=example",
                            "object_type": "SAM_DOMAIN",
                            "access_mask": "0x0000002d",
                            "subject_user": "administrator",
                            "process_name": r"C:\Windows\System32\lsass.exe",
                        },
                        "parameters": {"EventID": "4661"},
                    },
                },
                {
                    "window_id": 10,
                    "actual_event": "EventID 5145 Provider Microsoft-Windows-Security-Auditing Channel Security",
                    "anomaly_score": 0.991,
                    "anomalous_line": {
                        "important_fields": {
                            "relative_target_name": "samr",
                            "share_name": r"\\*\IPC$",
                            "subject_user": "user01",
                            "destination_ip": "10.0.2.17",
                        },
                        "parameters": {"EventID": "5145"},
                    },
                },
            ],
        }

        text = "\n".join(self._agent()._generate_default_recommendations(state))

        self.assertIn("EventID 4661", text)
        self.assertIn("administrator", text)
        self.assertIn("SAM_DOMAIN", text)
        self.assertIn("DC=example", text)
        self.assertIn("Domain Admins", text)
        self.assertIn("SAMR/IPC", text)

    def test_privilege_escalation_recommendations_validate_unquoted_service_path(self):
        state = {
            "evaluation_evidence_brief": "- tactic_folder: Privilege Escalation",
            "tool_results": [],
            "iocs_extracted": [],
            "attack_timeline": [],
            "anomalies": [
                {
                    "window_id": 0,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=11 ImageClass=windows_service TargetPathClass=unknown UserClass=system",
                    "anomaly_score": 0.999,
                    "anomalous_line": {
                        "important_fields": {
                            "target_object": r"C:\program.exe",
                            "image": r"C:\Windows\system32\cmd.exe",
                            "user": "NT AUTHORITY\\SYSTEM",
                            "parent_image": r"C:\Windows\System32\services.exe",
                        },
                        "parameters": {"EventID": "11"},
                    },
                },
                {
                    "window_id": 1,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=1 ImageClass=windows_service UserClass=system",
                    "anomaly_score": 0.998,
                    "anomalous_line": {
                        "important_fields": {
                            "image": r"C:\Windows\System32\svchost.exe",
                            "parent_image": r"C:\Windows\System32\services.exe",
                            "process_guid": "{747f3d96-b764-5ea4}",
                        },
                        "parameters": {"EventID": "1"},
                    },
                },
            ],
        }

        text = "\n".join(self._agent()._generate_default_recommendations(state))

        self.assertIn("Sysmon EventID 11", text)
        self.assertIn("C:\\program.exe", text)
        self.assertIn("unquoted service path", text)
        self.assertIn("service ImagePath", text)
        self.assertIn("privilege boundary", text)


if __name__ == "__main__":
    unittest.main()
