import unittest

from modules.agent import DFIRAgent
from modules.report import ReportGenerator


class ReportGeneratorTest(unittest.TestCase):
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

    def test_prefers_stronger_tool_result_for_same_ioc(self):
        iocs = [{"type": "ip", "value": "8.8.8.8", "source_line": 1, "window_id": 1}]
        tool_results = [
            {"tool": "greynoise", "ip": "8.8.8.8", "classification": "benign"},
            {"tool": "virustotal", "ioc": "8.8.8.8", "malicious": 3},
        ]

        ioc_analysis = self.generator._build_ioc_analysis(iocs, tool_results)

        self.assertEqual(ioc_analysis[0]["threat_level"], "high")
        self.assertIn("malicious=3", ioc_analysis[0]["threat_intel"])

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
