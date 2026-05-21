import json
import unittest
from typing import ClassVar

from modules.agent import DFIRAgent  # pyright: ignore[reportImplicitRelativeImport]
from modules.report import ReportGenerator  # pyright: ignore[reportImplicitRelativeImport]


class ReportGeneratorTest(unittest.TestCase):
    LEGACY_REPORT_KEYS: ClassVar[set[str]] = {
        "metadata",
        "executive_summary",
        "technical_findings",
        "ioc_analysis",
        "attack_timeline",
        "recommendations",
        "evidence_references",
    }
    V2_REPORT_KEYS: ClassVar[set[str]] = {
        "report_version",
        "standards_profile",
        "case_overview",
        "objectives_scope",
        "methodology",
        "evidence_provenance",
        "detection_analysis",
        "mitre_attack_mapping",
        "impact_assessment",
        "limitations_confidence",
        "appendices",
    }
    CANONICAL_MARKDOWN_HEADINGS: ClassVar[list[str]] = [
        "## Metadata & Case Overview",
        "## Executive Summary",
        "## Objectives & Scope",
        "## Methodology & Tools",
        "## Evidence & Provenance",
        "## Detection & Analysis Findings",
        "## MITRE ATT&CK Mapping",
        "## Incident Timeline",
        "## Impact Assessment",
        "## Recommendations",
        "## Limitations & Confidence",
        "## Appendices",
    ]
    generator: ReportGenerator = ReportGenerator()

    def setUp(self):
        self.generator = ReportGenerator()

    def _build_state(self):
        return {
            "anomalies": [
                {"window_id": 3, "actual_event": "Microsoft-Windows-Sysmon EventID=1"},
                {"window_id": 7, "actual_event": "Microsoft-Windows-Sysmon EventID=1"},
                {
                    "window_id": 11,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=13",
                },
            ],
            "iocs_extracted": [
                {"type": "domain", "value": "a.exe", "source_line": 4, "window_id": 3},
                {
                    "type": "domain",
                    "value": "microsoft.net",
                    "source_line": 6,
                    "window_id": 3,
                },
                {"type": "ip", "value": "1.0.0.0", "source_line": 4, "window_id": 3},
                {
                    "type": "sha256",
                    "value": "5DE788D23B247B29F116CD0583280CE10A429E9F8C1D80C42DEAB20C6F4DBB4E",
                    "source_line": 4,
                    "window_id": 3,
                },
            ],
            "tool_results": [
                {
                    "tool": "greynoise",
                    "ip": "1.0.0.0",
                    "error": "404 Client Error: Not Found for url: https://api.greynoise.io/v3/community/1.0.0.0",
                },
                {
                    "tool": "otx",
                    "hash": "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e",
                    "error": "API key required (get free at otx.alienvault.com)",
                },
            ],
            "attack_timeline": [
                {
                    "timestamp": "2026-04-14T10:58:24.564830",
                    "event": "Microsoft-Windows-Sysmon EventID=1",
                    "details": "Anomalous event detected: suspicious process execution",
                }
            ],
            "investigation_summary": "### 1. Incident Overview\nInvestigation dilakukan pada tanggal [tanggal] dengan hasil penemuan anomali dan IOC sebanyak [jumlah].",
            "recommendations": [
                "🔐 Verify sistem tidak ada signs of compromise (persist<|reserved_special_token_103|>ence, lateral movement)"
            ],
        }

    def _build_v2_state(
        self,
        *,
        anomalies=None,
        iocs=None,
        tool_results=None,
        attack_timeline=None,
        investigation_summary="short",
        recommendations=None,
    ):
        return {
            "anomalies": anomalies if anomalies is not None else [],
            "iocs_extracted": iocs if iocs is not None else [],
            "tool_results": tool_results if tool_results is not None else [],
            "attack_timeline": attack_timeline if attack_timeline is not None else [],
            "investigation_summary": investigation_summary,
            "recommendations": recommendations if recommendations is not None else [],
        }

    def test_report_v2_adds_required_keys_without_removing_legacy_contract(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        self.assertEqual(report["report_version"], "2.0")
        self.assertTrue(self.LEGACY_REPORT_KEYS.issubset(report.keys()))
        self.assertTrue(self.V2_REPORT_KEYS.issubset(report.keys()))
        self.assertEqual(
            set(report["metadata"].keys()),
            {"session_id", "report_id", "timestamp", "log_file", "model", "severity"},
        )
        self.assertIsInstance(report["metadata"], dict)
        self.assertIsInstance(report["executive_summary"], str)
        self.assertIsInstance(report["technical_findings"], list)
        self.assertIsInstance(report["ioc_analysis"], list)
        self.assertIsInstance(report["attack_timeline"], list)
        self.assertIsInstance(report["recommendations"], list)
        self.assertIsInstance(report["evidence_references"], list)
        self.assertEqual(
            report["standards_profile"]["certification_status"], "Not certified"
        )
        self.assertIn(
            "MITRE ATT&CK Enterprise technique taxonomy",
            report["standards_profile"]["references"],
        )

    def test_report_v2_empty_state_has_safe_section_defaults(self):
        report = self.generator.generate_report(
            session_id="empty-session",
            file_name="empty.log",
            investigation_state={},
        )

        self.assertEqual(report["report_version"], "2.0")
        self.assertTrue(self.LEGACY_REPORT_KEYS.issubset(report.keys()))
        self.assertTrue(self.V2_REPORT_KEYS.issubset(report.keys()))
        self.assertEqual(report["case_overview"]["session_id"], "empty-session")
        self.assertEqual(report["case_overview"]["log_file"], "empty.log")
        self.assertEqual(report["case_overview"]["case_status"], "Not assessed")
        self.assertEqual(
            report["methodology"]["validation_status"],
            "Generated from available investigation_state only",
        )
        self.assertEqual(report["evidence_provenance"]["chain_of_custody"], [])
        self.assertEqual(report["evidence_provenance"]["items"], [])
        self.assertEqual(report["detection_analysis"]["anomaly_count"], 0)
        self.assertEqual(report["detection_analysis"]["ioc_count"], 0)
        self.assertEqual(report["detection_analysis"]["tool_result_count"], 0)
        self.assertEqual(report["mitre_attack_mapping"]["status"], "Not assessed")
        self.assertEqual(report["mitre_attack_mapping"]["techniques"], [])
        self.assertEqual(report["impact_assessment"]["status"], "Not assessed")
        self.assertEqual(report["impact_assessment"]["data_exposure"], "Not assessed")
        self.assertEqual(report["limitations_confidence"]["confidence_level"], "Low")
        self.assertIn(
            "No IOC was available",
            "\n".join(report["limitations_confidence"]["limitations"]),
        )
        self.assertEqual(report["appendices"]["ioc_table"], [])
        self.assertEqual(report["appendices"]["timeline"], [])
        self.assertEqual(report["appendices"]["raw_references"], [])

    def test_report_v2_methodology_lists_pipeline_tools(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        self.assertEqual(
            report["methodology"]["tools"],
            [
                "Drain",
                "DeepLog",
                "LLM anomaly gate",
                "LangGraph DFIRAgent",
                "threat-intel enrichment",
                "report generator",
            ],
        )
        step_text = "\n".join(step["step"] for step in report["methodology"]["steps_performed"])
        self.assertIn("DeepLog", step_text)
        self.assertIn("threat-intel enrichment", step_text)
        self.assertIn("report", step_text)

    def test_report_v2_evidence_items_have_stable_ids_and_detection_refs(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        items = report["evidence_provenance"]["items"]
        evidence_ids = [item["evidence_id"] for item in items]
        self.assertEqual(
            evidence_ids,
            ["EV-LOG-001", "EV-LOG-002", "EV-LOG-003", "EV-TOOL-004", "EV-TOOL-005"],
        )
        self.assertEqual(items[0]["reference"], "window:3")
        self.assertEqual(items[0]["hash"], "Not available")
        self.assertEqual(
            report["evidence_provenance"]["sources"][0]["hashes"]["sha256"],
            "Not available",
        )
        findings_by_title = {
            finding["title"]: finding
            for finding in report["detection_analysis"]["findings"]
        }
        self.assertIn("finding_id", findings_by_title["Deteksi anomali utama"])
        self.assertTrue(
            all(
                evidence_id.startswith("EV-LOG-")
                for evidence_id in findings_by_title["Deteksi anomali utama"]["evidence_ids"]
            )
        )
        self.assertTrue(
            all(
                evidence_id.startswith("EV-TOOL-")
                for evidence_id in findings_by_title["IOC terkurasi"]["evidence_ids"]
            )
        )
        self.assertTrue(
            all(
                evidence_id.startswith("EV-TOOL-")
                for evidence_id in findings_by_title["Keterbatasan enrichment"]["evidence_ids"]
            )
        )
        for finding in report["detection_analysis"]["findings"]:
            self.assertTrue(set(finding["evidence_ids"]).issubset(evidence_ids))

    def test_report_v2_impact_uses_safe_defaults_without_overclaiming(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        impact = report["impact_assessment"]
        self.assertEqual(impact["status"], "Not assessed")
        self.assertEqual(impact["business_impact"], "Not assessed")
        self.assertEqual(impact["operational_impact"], "Not assessed")
        self.assertEqual(impact["data_exposure"], "Not assessed")
        self.assertEqual(impact["service_disruption"], "Not assessed")
        self.assertEqual(impact["recoverability"], "Not assessed")
        self.assertNotIn("data theft", str(impact).lower())
        self.assertNotIn("exfiltration", str(impact).lower())

    def test_report_v2_limitations_record_missing_data_and_sanitized_tool_errors(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        limitations = "\n".join(report["limitations_confidence"]["limitations"])
        self.assertIn("GREYNOISE: tidak ada reputasi publik", limitations)
        self.assertIn("OTX: layanan enrichment belum terkonfigurasi", limitations)
        self.assertNotIn("API key required", limitations)
        self.assertNotIn("404 Client Error", limitations)
        self.assertNotIn("benign", limitations.lower())
        self.assertNotIn("malicious", limitations.lower())
        self.assertEqual(report["limitations_confidence"]["confidence_level"], "Low")

    def test_report_v2_limitations_record_no_ioc_empty_anomalies_and_low_evidence(self):
        report = self.generator.generate_report(
            session_id="empty-session",
            file_name="empty.log",
            investigation_state={},
        )

        limitations = "\n".join(report["limitations_confidence"]["limitations"])
        self.assertIn("No IOC was available", limitations)
        self.assertIn("No anomaly windows were available", limitations)
        self.assertIn("Low-evidence condition", limitations)

    def test_report_v2_no_ioc_fixture_keeps_safe_defaults_without_fabrication(self):
        report = self.generator.generate_report(
            session_id="no-ioc-session",
            file_name="no-ioc.log",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {
                        "window_id": 7,
                        "actual_event": "Observed anomaly without IOC detail",
                    }
                ]
            ),
        )

        self.assertEqual(report["detection_analysis"]["ioc_count"], 0)
        self.assertEqual(report["mitre_attack_mapping"]["status"], "No supported mappings")
        self.assertEqual(report["mitre_attack_mapping"]["techniques"], [])
        self.assertEqual(report["impact_assessment"]["data_exposure"], "Not assessed")
        self.assertNotIn("exfiltration", str(report["impact_assessment"]).lower())

    def test_report_v2_all_noisy_iocs_are_filtered_without_claims(self):
        report = self.generator.generate_report(
            session_id="noisy-ioc-session",
            file_name="noisy.log",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {
                        "window_id": 11,
                        "actual_event": "Observed anomaly without execution context",
                    }
                ],
                iocs=[
                    {"type": "domain", "value": "a.exe", "source_line": 4, "window_id": 11},
                    {
                        "type": "domain",
                        "value": "microsoft.net",
                        "source_line": 5,
                        "window_id": 11,
                    },
                ],
            ),
        )

        self.assertEqual(report["detection_analysis"]["ioc_count"], 0)
        self.assertEqual(report["ioc_analysis"], [])
        self.assertEqual(report["mitre_attack_mapping"]["techniques"], [])
        self.assertNotIn("data theft", str(report).lower())

    def test_report_v2_tool_errors_are_sanitized_in_user_facing_fields(self):
        report = self.generator.generate_report(
            session_id="tool-error-session",
            file_name="tool-error.log",
            investigation_state=self._build_v2_state(
                tool_results=[
                    {
                        "tool": "greynoise",
                        "ip": "1.0.0.0",
                        "error": "404 Client Error: Not Found for url: https://api.greynoise.io/v3/community/1.0.0.0",
                    },
                    {
                        "tool": "otx",
                        "hash": "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e",
                        "error": "API key required (get free at otx.alienvault.com)",
                    },
                ]
            ),
        )

        limitations = "\n".join(report["limitations_confidence"]["limitations"])
        evidence_text = "\n".join(item["description"] for item in report["evidence_references"])
        self.assertIn("GREYNOISE: tidak ada reputasi publik yang relevan untuk IOC ini", limitations)
        self.assertIn("OTX: layanan enrichment belum terkonfigurasi", limitations)
        self.assertNotIn("API key required", limitations)
        self.assertNotIn("404 Client Error", limitations)
        self.assertNotIn("API key required", evidence_text)
        self.assertNotIn("404 Client Error", evidence_text)

    def test_report_v2_missing_timestamp_uses_fallback_and_flags_limitations(self):
        report = self.generator.generate_report(
            session_id="missing-timestamp-session",
            file_name="missing-timestamp.log",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {"window_id": 5, "actual_event": "Microsoft-Windows-Sysmon EventID=13"}
                ],
                attack_timeline=[
                    {"event": "Registry change observed", "details": "missing timestamp"}
                ],
            ),
        )

        self.assertEqual(
            report["appendices"]["timeline"][0]["timestamp"],
            report["metadata"]["timestamp"],
        )
        self.assertEqual(
            report["evidence_provenance"]["items"][0]["timestamp"],
            "Not available",
        )
        self.assertIn(
            "One or more timeline timestamps are missing or unavailable.",
            "\n".join(report["limitations_confidence"]["limitations"]),
        )

    def test_report_v2_evidence_timestamp_requires_stable_timeline_reference(self):
        report = self.generator.generate_report(
            session_id="stable-timestamp-session",
            file_name="stable-timestamp.log",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {"window_id": 5, "actual_event": "Microsoft-Windows-Sysmon EventID=13"},
                    {"window_id": 9, "actual_event": "Microsoft-Windows-Sysmon EventID=1"},
                ],
                attack_timeline=[
                    {
                        "timestamp": "2026-05-19T11:00:00",
                        "event": "Unlinked event",
                        "details": "No provenance reference",
                    },
                    {
                        "timestamp": "2026-05-19T11:05:00",
                        "event": "Window 9 event",
                        "details": "Has provenance reference",
                        "source_window": 9,
                    },
                ],
            ),
        )

        items = report["evidence_provenance"]["items"]
        self.assertEqual(items[0]["reference"], "window:5")
        self.assertEqual(items[0]["timestamp"], "Not available")
        self.assertEqual(items[1]["reference"], "window:9")
        self.assertEqual(items[1]["timestamp"], "2026-05-19T11:05:00")

    def test_markdown_timeline_evidence_id_requires_stable_reference(self):
        report = self.generator.generate_report(
            session_id="timeline-evidence-session",
            file_name="timeline-evidence.log",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {"window_id": 5, "actual_event": "Microsoft-Windows-Sysmon EventID=13"}
                ],
                attack_timeline=[
                    {
                        "timestamp": "2026-05-19T12:00:00",
                        "event": "Unlinked event",
                        "details": "No reference",
                    },
                    {
                        "timestamp": "2026-05-19T12:05:00",
                        "event": "Linked event",
                        "details": "References window 5",
                        "evidence_reference": "window:5",
                    },
                ],
            ),
        )

        markdown = self.generator._to_markdown(report)
        self.assertIn(
            "2026-05-19T12:00:00 | Unlinked event | No reference | Evidence ID: Not available",
            markdown,
        )
        self.assertIn(
            "2026-05-19T12:05:00 | Linked event | References window 5 | Evidence ID: EV-LOG-001",
            markdown,
        )

    def test_report_v2_out_of_order_timeline_preserves_input_order(self):
        timeline = [
            {"timestamp": "2026-05-19T10:05:00", "event": "Later event", "details": "second"},
            {"timestamp": "2026-05-19T09:55:00", "event": "Earlier event", "details": "first"},
        ]
        report = self.generator.generate_report(
            session_id="timeline-session",
            file_name="timeline.log",
            investigation_state=self._build_v2_state(
                anomalies=[{"window_id": 1, "actual_event": "Observed anomaly"}],
                attack_timeline=timeline,
            ),
        )

        built_timeline = report["appendices"]["timeline"]
        self.assertEqual([item["event"] for item in built_timeline], ["Later event", "Earlier event"])
        self.assertEqual([item["timestamp"] for item in built_timeline], [
            "2026-05-19T10:05:00",
            "2026-05-19T09:55:00",
        ])

    def test_report_v2_duplicate_evidence_keeps_sequential_ids(self):
        duplicated_anomaly = {"window_id": 7, "actual_event": "Microsoft-Windows-Sysmon EventID=1"}
        duplicated_tool = {"tool": "virustotal", "ioc": "8.8.8.8", "suspicious": 1}
        report = self.generator.generate_report(
            session_id="duplicate-session",
            file_name="duplicate.log",
            investigation_state=self._build_v2_state(
                anomalies=[duplicated_anomaly, duplicated_anomaly],
                tool_results=[duplicated_tool, duplicated_tool],
                attack_timeline=[
                    {"event": "dup-1", "details": "first"},
                    {"event": "dup-2", "details": "second"},
                    {"event": "dup-3", "details": "third"},
                    {"event": "dup-4", "details": "fourth"},
                ],
            ),
        )

        self.assertEqual(
            [item["reference"] for item in report["evidence_references"]],
            ["window:7", "window:7", "virustotal:8.8.8.8", "virustotal:8.8.8.8"],
        )
        self.assertEqual(
            [item["evidence_id"] for item in report["evidence_provenance"]["items"]],
            ["EV-LOG-001", "EV-LOG-002", "EV-TOOL-003", "EV-TOOL-004"],
        )

    def test_report_v2_conflicting_tool_output_prefers_stronger_enrichment(self):
        report = self.generator.generate_report(
            session_id="conflict-session",
            file_name="conflict.log",
            investigation_state=self._build_v2_state(
                anomalies=[{"window_id": 4, "actual_event": "Observed anomaly"}],
                iocs=[{"type": "ip", "value": "8.8.8.8", "source_line": 12, "window_id": 4}],
                tool_results=[
                    {"tool": "virustotal", "ioc": "8.8.8.8", "classification": "benign"},
                    {"tool": "virustotal", "ioc": "8.8.8.8", "malicious": 4},
                ],
            ),
        )

        ioc_entry = report["ioc_analysis"][0]
        self.assertEqual(ioc_entry["threat_level"], "high")
        self.assertIn("malicious=4", ioc_entry["threat_intel"])
        self.assertEqual(report["mitre_attack_mapping"]["techniques"], [])

    def test_report_v2_missing_provenance_uses_unknown_and_not_available_defaults(self):
        report = self.generator.generate_report(
            session_id="missing-provenance-session",
            file_name="missing-provenance.log",
            investigation_state=self._build_v2_state(
                tool_results=[{"tool": "custom_enricher", "classification": "suspicious"}],
            ),
        )

        evidence_item = report["evidence_provenance"]["items"][0]
        self.assertEqual(evidence_item["reference"], "custom_enricher:unknown")
        self.assertEqual(evidence_item["timestamp"], "Not available")
        self.assertEqual(evidence_item["hash"], "Not available")
        self.assertEqual(report["evidence_provenance"]["sources"][0]["hashes"]["sha256"], "Not available")

    def test_report_v2_large_ioc_and_evidence_lists_are_capped_and_stable(self):
        anomalies = [
            {"window_id": index, "actual_event": "Observed anomaly"}
            for index in range(1, 36)
        ]
        iocs = [
            {
                "type": "ip",
                "value": f"198.51.100.{index}",
                "source_line": index,
                "window_id": index,
            }
            for index in range(1, 36)
        ]
        tool_results = [
            {"tool": "virustotal", "ioc": f"198.51.100.{index}", "suspicious": 1}
            for index in range(1, 36)
        ]
        report = self.generator.generate_report(
            session_id="large-fixture-session",
            file_name="large-fixture.log",
            investigation_state=self._build_v2_state(
                anomalies=anomalies,
                iocs=iocs,
                tool_results=tool_results,
            ),
        )

        self.assertEqual(len(report["ioc_analysis"]), 25)
        self.assertEqual(len(report["evidence_provenance"]["items"]), 60)
        self.assertEqual(report["evidence_provenance"]["items"][0]["evidence_id"], "EV-LOG-001")
        self.assertEqual(report["evidence_provenance"]["items"][29]["evidence_id"], "EV-LOG-030")
        self.assertEqual(report["evidence_provenance"]["items"][30]["evidence_id"], "EV-TOOL-031")
        self.assertEqual(report["evidence_provenance"]["items"][-1]["evidence_id"], "EV-TOOL-060")

    def test_mitre_mapping_maps_powershell_command_to_t1059_001(self):
        state = {
            "anomalies": [
                {
                    "window_id": 42,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=3",
                    "anomalous_line": {
                        "important_fields": {
                            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "command_line": "powershell -enc SQBFAFgA",
                            "user": "alice",
                        }
                    },
                }
            ],
            "iocs_extracted": [],
            "tool_results": [],
            "attack_timeline": [],
            "investigation_summary": "short",
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="powershell.evtx",
            investigation_state=state,
        )

        techniques = report["mitre_attack_mapping"]["techniques"]
        powershell = next(
            item for item in techniques if item["technique_id"] == "T1059.001"
        )
        self.assertEqual(powershell["tactic"], "Execution")
        self.assertEqual(powershell["technique_name"], "PowerShell")
        self.assertIn(powershell["confidence"], {"medium", "high"})
        self.assertTrue(powershell["evidence_ids"])
        self.assertTrue(all(item.startswith("EV-LOG-") for item in powershell["evidence_ids"]))
        self.assertIn("PowerShell", powershell["rationale"])

    def test_mitre_mapping_maps_registry_modification_only_with_registry_detail(self):
        state = {
            "anomalies": [
                {
                    "window_id": 13,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=13",
                    "anomalous_line": {
                        "important_fields": {
                            "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                            "details": "C:\\Users\\alice\\updater.exe",
                        }
                    },
                }
            ],
            "iocs_extracted": [],
            "tool_results": [],
            "attack_timeline": [],
            "investigation_summary": "short",
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="registry.evtx",
            investigation_state=state,
        )

        techniques = report["mitre_attack_mapping"]["techniques"]
        registry = next(item for item in techniques if item["technique_id"] == "T1112")
        self.assertEqual(registry["tactic"], "Defense Evasion")
        self.assertEqual(registry["technique_name"], "Modify Registry")
        self.assertTrue(registry["evidence_ids"])
        self.assertIn("registry", registry["rationale"].lower())

    def test_mitre_mapping_leaves_unsupported_generic_event_unmapped(self):
        state = {
            "anomalies": [
                {
                    "window_id": 99,
                    "actual_event": "Anomalous event",
                }
            ],
            "iocs_extracted": [],
            "tool_results": [],
            "attack_timeline": [],
            "investigation_summary": "short",
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="generic.log",
            investigation_state=state,
        )

        self.assertEqual(report["mitre_attack_mapping"]["status"], "No supported mappings")
        self.assertEqual(report["mitre_attack_mapping"]["techniques"], [])
        self.assertEqual(report["mitre_attack_mapping"]["tactics"], [])

    def test_mitre_mapping_omits_techniques_when_evidence_ids_are_missing(self):
        anomalies = [
            {
                "window_id": 42,
                "actual_event": "Microsoft-Windows-Sysmon EventID=1",
                "anomalous_line": {
                    "important_fields": {
                        "image": "powershell.exe",
                        "command_line": "powershell -enc SQBFAFgA",
                    }
                },
            }
        ]

        mapping = self.generator._build_mitre_attack_mapping(anomalies, [], [])

        self.assertEqual(mapping["status"], "No supported mappings")
        self.assertEqual(mapping["techniques"], [])
        self.assertEqual(mapping["tactics"], [])

    def test_mitre_mapping_emits_only_medium_or_high_confidence_techniques(self):
        state = {
            "anomalies": [
                {
                    "window_id": 1,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=1",
                    "anomalous_line": {
                        "important_fields": {
                            "image": "C:\\Windows\\System32\\cmd.exe",
                            "command_line": "cmd.exe /c whoami",
                        }
                    },
                },
                {
                    "window_id": 3,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=3 network connection https",
                    "anomalous_line": {
                        "important_fields": {
                            "destination_ip": "8.8.8.8",
                            "destination_port": "443",
                            "protocol": "https",
                        }
                    },
                },
                {
                    "window_id": 13,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=13",
                    "anomalous_line": {
                        "important_fields": {
                            "target_object": "HKLM\\Software\\Example\\Setting",
                        }
                    },
                },
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "8.8.8.8", "source_line": 3, "window_id": 3}
            ],
            "tool_results": [],
            "attack_timeline": [],
            "investigation_summary": "short",
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="confidence.evtx",
            investigation_state=state,
        )

        techniques = report["mitre_attack_mapping"]["techniques"]
        technique_ids = {item["technique_id"] for item in techniques}
        self.assertTrue({"T1059", "T1071", "T1112"}.issubset(technique_ids))
        for technique in techniques:
            self.assertIn(technique["confidence"], {"medium", "high"})
            self.assertTrue(technique["evidence_ids"])
            self.assertTrue(technique["rationale"])

    def test_mitre_record_helper_omits_low_confidence_technique_candidates(self):
        mapped = {}

        self.generator._record_mitre_mapping(
            mapped,
            technique_id="T1059",
            tactic="Execution",
            technique_name="Command and Scripting Interpreter",
            confidence="low",
            evidence_ids=["EV-LOG-001"],
            rationale="Weak candidate should not be emitted as a technique.",
        )

        self.assertEqual(mapped, {})

    def test_replaces_placeholder_executive_summary(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        self.assertNotIn("[tanggal]", report["executive_summary"])
        self.assertNotIn("[jumlah]", report["executive_summary"])
        self.assertIn("sample.evtx", report["executive_summary"])
        self.assertIn("3 window anomali", report["executive_summary"])

    def test_sanitizes_tool_errors_and_filters_noisy_iocs(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        ioc_values = [ioc["value"] for ioc in report["ioc_analysis"]]
        self.assertNotIn("a.exe", ioc_values)
        self.assertNotIn("microsoft.net", [value.lower() for value in ioc_values])

        threat_text = " ".join(ioc["threat_intel"] for ioc in report["ioc_analysis"])
        self.assertNotIn("API key required", threat_text)
        self.assertNotIn("404 Client Error", threat_text)

    def test_markdown_hides_placeholders_and_special_tokens(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )
        markdown = self.generator._to_markdown(report)

        self.assertNotIn("[tanggal]", markdown)
        self.assertNotIn("API key required", markdown)
        self.assertNotIn("404 Client Error", markdown)
        self.assertNotIn("reserved_special_token", markdown)

    def test_markdown_uses_canonical_report_v2_section_order(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )
        markdown = self.generator._to_markdown(report)

        heading_lines = [line for line in markdown.splitlines() if line.startswith("## ")]
        self.assertEqual(heading_lines, self.CANONICAL_MARKDOWN_HEADINGS)
        self.assertNotIn("## Technical Findings", markdown)
        self.assertNotIn("## IOC List", markdown)
        self.assertNotIn("## Attack Timeline", markdown)
        self.assertNotIn("## Evidence References", markdown)

    def test_markdown_reflects_report_v2_json_values_and_evidence_ids(self):
        report = self.generator.generate_report(
            session_id="markdown-session",
            file_name="markdown.evtx",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {
                        "window_id": 42,
                        "actual_event": "Microsoft-Windows-Sysmon EventID=3 network connection https",
                        "anomalous_line": {
                            "important_fields": {
                                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                "command_line": "powershell -enc SQBFAFgA",
                                "destination_ip": "203.0.113.50",
                                "destination_port": "443",
                                "protocol": "https",
                                "user": "alice",
                            }
                        },
                    }
                ],
                iocs=[
                    {
                        "type": "ip",
                        "value": "203.0.113.50",
                        "source_line": 10,
                        "window_id": 42,
                    }
                ],
                tool_results=[
                    {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 3}
                ],
                attack_timeline=[
                    {
                        "timestamp": "2026-05-19T08:00:00",
                        "event": "PowerShell network connection",
                        "details": "Observed connection to 203.0.113.50",
                        "source_window": 42,
                    }
                ],
                recommendations=["Review PowerShell evidence EV-LOG-001 before containment."],
            ),
        )
        markdown = self.generator._to_markdown(report)

        expected_values = [
            report["report_version"],
            report["standards_profile"]["profile_name"],
            report["case_overview"]["session_id"],
            report["case_overview"]["log_file"],
            "Drain",
            "DeepLog",
            "EV-LOG-001",
            "EV-TOOL-002",
            "DF-001",
            "203.0.113.50",
            "PowerShell network connection",
            "2026-05-19T08:00:00",
            "T1059.001",
            "PowerShell",
            "Execution",
            report["impact_assessment"]["status"],
            report["limitations_confidence"]["confidence_level"],
        ]

        for value in expected_values:
            self.assertIn(value, markdown)
        for recommendation in report["recommendations"]:
            self.assertIn(recommendation, markdown)
        for technique in report["mitre_attack_mapping"]["techniques"]:
            for evidence_id in technique["evidence_ids"]:
                self.assertIn(evidence_id, markdown)

        self.assertNotIn("data theft", markdown.lower())
        self.assertNotIn("exfiltration", markdown.lower())
        self.assertNotIn("API key required", markdown)
        self.assertNotIn("404 Client Error", markdown)
        self.assertNotIn("[tanggal]", markdown)

    def test_report_v2_json_round_trip_and_markdown_fixture(self):
        report = self.generator.generate_report(
            session_id="roundtrip-session",
            file_name="roundtrip.evtx",
            investigation_state=self._build_v2_state(
                anomalies=[
                    {
                        "window_id": 9,
                        "actual_event": "Microsoft-Windows-Sysmon EventID=13",
                        "anomalous_line": {
                            "important_fields": {
                                "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                                "details": "C:\\Users\\alice\\updater.exe",
                            }
                        },
                    }
                ],
                iocs=[
                    {
                        "type": "sha256",
                        "value": "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e",
                        "source_line": 3,
                        "window_id": 9,
                    }
                ],
                tool_results=[
                    {
                        "tool": "otx",
                        "hash": "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e",
                        "error": "API key required (get free at otx.alienvault.com)",
                    }
                ],
                attack_timeline=[
                    {
                        "timestamp": "2026-05-19T09:30:00",
                        "event": "Registry modification observed",
                        "details": "Run key changed by updater.exe",
                        "evidence_reference": "window:9",
                    }
                ],
            ),
        )

        decoded = json.loads(json.dumps(report, ensure_ascii=False))
        markdown = self.generator._to_markdown(decoded)

        self.assertTrue(self.V2_REPORT_KEYS.issubset(decoded.keys()))
        self.assertTrue(markdown.strip())
        for heading in self.CANONICAL_MARKDOWN_HEADINGS:
            self.assertIn(heading, markdown)
        self.assertIn("T1112", markdown)
        self.assertIn("EV-LOG-001", markdown)
        self.assertIn("Not assessed", markdown)

        forbidden_fragments = [
            "[tanggal]",
            "api key required",
            "404 client error",
            "data theft",
            "exfiltration",
            "legally admissible",
        ]
        lowered_markdown = markdown.lower()
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, lowered_markdown)

    def test_matches_ioc_enrichment_case_insensitively(self):
        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=self._build_state(),
        )

        sha256_entry = next(
            ioc for ioc in report["ioc_analysis"] if ioc["type"] == "sha256"
        )
        self.assertEqual(
            sha256_entry["threat_intel"],
            "OTX: layanan enrichment belum terkonfigurasi",
        )

    def test_does_not_double_count_malicious_or_suspicious_hits(self):
        tool_results = [
            {"tool": "virustotal", "classification": "malicious", "malicious": 2},
            {"tool": "greynoise", "classification": "suspicious", "suspicious": 1},
            {
                "tool": "otx",
                "classification": "benign",
                "malicious": 0,
                "suspicious": 0,
            },
        ]

        self.assertEqual(self.generator._count_malicious_hits(tool_results), 1)
        self.assertEqual(self.generator._count_suspicious_hits(tool_results), 1)

    def test_deduplicates_duplicate_tool_hits_for_same_ioc(self):
        tool_results = [
            {"tool": "virustotal", "ioc": "8.8.8.8", "malicious": 2},
            {"tool": "otx", "ioc": "8.8.8.8", "classification": "malicious"},
            {"tool": "greynoise", "ioc": "8.8.8.8", "classification": "suspicious"},
            {"tool": "virustotal", "ioc": "evil.example", "suspicious": 1},
        ]

        self.assertEqual(self.generator._count_malicious_hits(tool_results), 1)
        self.assertEqual(self.generator._count_suspicious_hits(tool_results), 2)

    def test_tool_hit_counts_tolerate_non_numeric_values(self):
        tool_results = [
            {"tool": "virustotal", "ioc": "1.1.1.1", "malicious": "unknown"},
            {"tool": "otx", "ioc": "2.2.2.2", "suspicious": ""},
            {"tool": "greynoise", "ioc": "3.3.3.3", "malicious": None},
            {"tool": "threatfox", "ioc": "4.4.4.4", "suspicious": "2"},
        ]

        self.assertEqual(self.generator._count_malicious_hits(tool_results), 0)
        self.assertEqual(self.generator._count_suspicious_hits(tool_results), 1)

    def test_prefers_stronger_tool_result_for_same_ioc(self):
        iocs = [{"type": "ip", "value": "8.8.8.8", "source_line": 1, "window_id": 1}]
        tool_results = [
            {"tool": "greynoise", "ip": "8.8.8.8", "classification": "benign"},
            {"tool": "virustotal", "ioc": "8.8.8.8", "malicious": 3},
        ]

        ioc_analysis = self.generator._build_ioc_analysis(iocs, tool_results)

        self.assertEqual(ioc_analysis[0]["threat_level"], "high")
        self.assertIn("malicious=3", ioc_analysis[0]["threat_intel"])

    def test_report_recommendations_are_contextual_to_detection_evidence(self):
        state = {
            "anomalies": [
                {
                    "window_id": 42,
                    "anomaly_score": 0.987,
                    "strict_is_anomaly": True,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=3",
                    "anomalous_line": {
                        "important_fields": {
                            "image": "powershell.exe",
                            "command_line": "powershell -enc AAA",
                            "user": "alice",
                        }
                    },
                    "window_key_indicators": {"destination_ip": ["203.0.113.50"]},
                }
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42},
                {"type": "domain", "value": "evil.example", "source_line": 11, "window_id": 42},
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4},
                {"tool": "otx", "ioc": "evil.example", "suspicious": 2},
            ],
            "attack_timeline": [
                {"event_template": "initial event", "description": "first"},
                {"event_template": "network event", "description": "second"},
                {"event_template": "follow-up event", "description": "third"},
            ],
            "investigation_summary": "short",
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=state,
        )
        recommendation_text = "\n".join(report["recommendations"])

        self.assertIn("203.0.113.50", recommendation_text)
        self.assertIn("evil.example", recommendation_text)
        self.assertIn("window 42", recommendation_text)
        self.assertIn("score 0.987", recommendation_text)
        self.assertIn("Microsoft-Windows-Sysmon EventID=3", recommendation_text)
        self.assertIn("powershell.exe", recommendation_text)
        self.assertIn("3 item timeline", recommendation_text)

    def test_rejects_hallucinated_summary_that_does_not_match_evidence(self):
        state = {
            "anomalies": [
                {
                    "window_id": 42,
                    "anomaly_score": 0.987,
                    "actual_event": "Microsoft-Windows-Sysmon EventID=3",
                    "anomalous_line": {
                        "important_fields": {
                            "image": "powershell.exe",
                            "user": "alice",
                        }
                    },
                }
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42}
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4}
            ],
            "attack_timeline": [
                {"event_template": "Microsoft-Windows-Sysmon EventID=3", "description": "powershell network connection"}
            ],
            "investigation_summary": (
                "### Ringkasan Eksekutif\n"
                "Tanggal Serangan: 12 Mei 2024. Jenis Serangan: Malware atau Phishing. "
                "Korban: Windows Server 2019. Dampak: Data sensitif dicuri dari server internal. "
                "Aktivitas command-and-control terlihat menuju 88.88.88.88 melalui proses tidak dikenal."
            ),
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=state,
        )

        self.assertNotIn("88.88.88.88", report["executive_summary"])
        self.assertNotIn("Windows Server 2019", report["executive_summary"])
        self.assertNotIn("Data sensitif dicuri", report["executive_summary"])
        self.assertIn("sample.evtx", report["executive_summary"])
        self.assertIn("1 window anomali", report["executive_summary"])

    def test_rejects_raw_traceback_summary_before_report_output(self):
        state = {
            "anomalies": [
                {"window_id": 42, "actual_event": "Microsoft-Windows-Sysmon EventID=3"}
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42}
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4}
            ],
            "attack_timeline": [],
            "investigation_summary": (
                "Traceback (most recent call last)\n"
                "  File \"modules/report.py\", line 99, in generate_report\n"
                "RuntimeError: API key required for upstream summary generation\n"
                "Window 42 and IOC 203.0.113.50 were present in the failed prompt."
            ),
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="traceback-summary-session",
            file_name="traceback.evtx",
            investigation_state=state,
        )
        markdown = self.generator._to_markdown(report)

        self.assertNotIn("Traceback (most recent call last)", report["executive_summary"])
        self.assertNotIn("RuntimeError:", report["executive_summary"])
        self.assertNotIn("API key required", markdown)
        self.assertIn("traceback.evtx", report["executive_summary"])

    def test_rejects_module_qualified_http_error_summary_before_report_output(self):
        state = {
            "anomalies": [
                {"window_id": 42, "actual_event": "Microsoft-Windows-Sysmon EventID=3"}
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42}
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4}
            ],
            "attack_timeline": [],
            "investigation_summary": (
                "### Ringkasan Upstream\n"
                "Investigasi menemukan aktivitas pada window 42 dengan event "
                "Microsoft-Windows-Sysmon EventID=3 dan IOC 203.0.113.50.\n"
                "requests.exceptions.HTTPError: 500 Server Error: Internal Server Error "
                "for url: https://api.example.test/report"
            ),
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="module-http-error-summary-session",
            file_name="module-http-error.evtx",
            investigation_state=state,
        )
        markdown = self.generator._to_markdown(report)

        self.assertNotIn("requests.exceptions.HTTPError", report["executive_summary"])
        self.assertNotIn("500 Server Error", report["executive_summary"])
        self.assertNotIn("requests.exceptions.HTTPError", markdown)
        self.assertNotIn("500 Server Error", markdown)
        self.assertIn("module-http-error.evtx", report["executive_summary"])

    def test_keeps_supported_unavailability_prose_with_error_word(self):
        state = {
            "anomalies": [
                {"window_id": 42, "actual_event": "Microsoft-Windows-Sysmon EventID=3"}
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42}
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4}
            ],
            "attack_timeline": [],
            "investigation_summary": (
                "### Ringkasan Investigasi\n"
                "Analisis pada window 42 menemukan Microsoft-Windows-Sysmon EventID=3 "
                "dengan IOC 203.0.113.50. Beberapa error enrichment tidak tersedia "
                "untuk mendukung klaim tambahan, sehingga kesimpulan dibatasi pada "
                "evidence lokal dan sinyal malicious yang sudah ada."
            ),
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="safe-error-prose-session",
            file_name="safe-error-prose.evtx",
            investigation_state=state,
        )

        self.assertIn("Beberapa error enrichment tidak tersedia", report["executive_summary"])
        self.assertIn("203.0.113.50", report["executive_summary"])

    def test_keeps_llm_summary_when_it_references_actual_evidence(self):
        state = {
            "anomalies": [
                {"window_id": 42, "actual_event": "Microsoft-Windows-Sysmon EventID=3"}
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "203.0.113.50", "source_line": 10, "window_id": 42}
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "203.0.113.50", "malicious": 4}
            ],
            "attack_timeline": [],
            "investigation_summary": (
                "### Laporan Investigasi\n"
                "Investigasi menemukan aktivitas pada window 42 dengan event "
                "Microsoft-Windows-Sysmon EventID=3. IOC 203.0.113.50 perlu "
                "diprioritaskan karena enrichment menunjukkan sinyal malicious. "
                "Kesimpulan ini dibatasi pada evidence yang tersedia dan belum cukup "
                "untuk menyatakan exfiltration tanpa log tambahan."
            ),
            "recommendations": [],
        }

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=state,
        )

        self.assertIn("### Laporan Investigasi", report["executive_summary"])
        self.assertIn("203.0.113.50", report["executive_summary"])

    def test_agent_default_recommendations_are_contextual_to_state(self):
        agent = DFIRAgent.__new__(DFIRAgent)
        state = {
            "anomalies": [
                {
                    "window_id": 9,
                    "anomaly_score": 0.765,
                    "actual_event": "Suspicious Process",
                    "anomalous_line": {
                        "important_fields": {
                            "image": "cmd.exe",
                            "command_line": "cmd /c whoami",
                        }
                    },
                }
            ],
            "tool_results": [
                {"tool": "virustotal", "ioc": "198.51.100.10", "malicious": "unknown"},
                {"tool": "otx", "ioc": "198.51.100.11", "suspicious": "1"},
            ],
            "iocs_extracted": [
                {"type": "ip", "value": "198.51.100.11", "window_id": 9}
            ],
            "attack_timeline": [{"event_template": "Suspicious Process"}],
        }

        recommendations = agent._generate_default_recommendations(state)
        recommendation_text = "\n".join(recommendations)

        self.assertIn("198.51.100.11", recommendation_text)
        self.assertIn("window DeepLog 9", recommendation_text)
        self.assertIn("score 0.765", recommendation_text)
        self.assertIn("cmd.exe", recommendation_text)
        self.assertIn("1 item timeline", recommendation_text)

    def test_rejects_template_like_summary_without_bracket_placeholders(self):
        state = self._build_state()
        state["investigation_summary"] = (
            "### 2. Threat Identification\n"
            "Insiden ini teridentifikasi menggunakan teknik yang masih perlu dijelaskan.\n\n"
            "### 3. Impact Assessment\n"
            "Dampak perlu ditinjau lebih lanjut.\n\n"
            "### 5. Severity Classification\n"
            "Severity perlu diklasifikasikan kembali berdasarkan review akhir."
        )

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=state,
        )

        self.assertIn("sample.evtx", report["executive_summary"])
        self.assertNotIn("Threat Identification", report["executive_summary"])

    def test_skipped_results_do_not_create_ioc_or_evidence_noise(self):
        state = self._build_state()
        state["iocs_extracted"] = [
            {
                "type": "domain",
                "value": "skipped.example",
                "source_line": 12,
                "window_id": 7,
            },
            {"type": "ip", "value": "8.8.8.8", "source_line": 13, "window_id": 7},
        ]
        state["tool_results"] = [
            {
                "tool": "threatfox_lookup",
                "ioc": "skipped.example",
                "status": "skipped",
                "skipped": True,
                "reason": "unsupported IOC format",
            },
            {
                "tool": "virustotal_lookup",
                "ioc": "8.8.8.8",
                "classification": "suspicious",
                "suspicious": 1,
            },
            {
                "tool": "otx",
                "ioc": "8.8.8.8",
                "error": "API key required (get free at otx.alienvault.com)",
            },
        ]
        state["investigation_summary"] = "short"

        report = self.generator.generate_report(
            session_id="test-session",
            file_name="sample.evtx",
            investigation_state=state,
        )

        skipped_ioc = next(
            ioc for ioc in report["ioc_analysis"] if ioc["value"] == "skipped.example"
        )
        self.assertEqual(
            skipped_ioc["threat_intel"],
            "Belum ada data enrichment eksternal untuk IOC ini",
        )

        tool_refs = [
            evidence["reference"]
            for evidence in report["evidence_references"]
            if evidence["type"] == "tool_result"
        ]
        self.assertNotIn("threatfox_lookup:skipped.example", tool_refs)
        self.assertIn("virustotal_lookup:8.8.8.8", tool_refs)
        self.assertIn("otx:8.8.8.8", tool_refs)
        self.assertIn("total 2 hasil enrichment", report["executive_summary"])

    def test_correlation_prompt_excludes_skipped_results_from_counts_and_findings(self):
        agent = DFIRAgent.__new__(DFIRAgent)
        anomalies = [
            {
                "window_id": 5,
                "actual_event": "Microsoft-Windows-Sysmon EventID=3",
                "window_key_indicators": {"destination_ip": ["8.8.8.8"]},
            }
        ]
        tool_results = [
            {
                "tool": "threatfox_lookup",
                "ioc": "skip.me",
                "status": "skipped",
                "skipped": True,
                "reason": "unsupported IOC format",
            },
            {
                "tool": "virustotal_lookup",
                "ioc": "8.8.8.8",
                "classification": "suspicious",
                "data": {"verdict": "community flag"},
                "status": "ok",
            },
            {
                "tool": "greynoise_lookup",
                "ioc": "1.1.1.1",
                "status": "ok",
            },
        ]

        prompt = agent._create_correlation_prompt(anomalies, tool_results)

        self.assertIn("Total Queries: 2", prompt)
        self.assertIn("- **Suspicious IOCs:** 1", prompt)
        self.assertIn("- **Clean/Unknown:** 1", prompt)
        self.assertNotIn("skip.me", prompt)
        self.assertNotIn("skipped", prompt.lower())


if __name__ == "__main__":
    unittest.main()
