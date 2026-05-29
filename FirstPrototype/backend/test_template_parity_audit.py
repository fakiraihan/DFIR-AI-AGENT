import unittest

from modules.parsing import DrainParser  # pyright: ignore[reportImplicitRelativeImport]


PROVIDER = "Microsoft-Windows-Sysmon"
EVENT_ID = "1"
RAW_LINE = "Microsoft-Windows-Sysmon EventID=1 ProcessId=1234"


class TemplateParityAuditTest(unittest.TestCase):
    @staticmethod
    def _evtx_attack_template(provider: str, event_id: str) -> str:
        return f"{provider} EventID={event_id}"

    @staticmethod
    def _source_entrytype_template(source: str, entry_type: str) -> str:
        def clean(value: object) -> str:
            if value in (None, "", "0"):
                return "Unknown"
            return str(value).strip()

        source_clean = clean(source).replace(" ", "")
        entry_type_clean = clean(entry_type)
        if entry_type_clean == "Unknown":
            entry_type_clean = "Information"
        return f"{source_clean}_{entry_type_clean}"

    def test_provider_eventid_runtime_matches_evtx_attack_preprocessing(self):
        parser = DrainParser.__new__(DrainParser)
        parser.template_strategy = "provider_eventid"

        runtime_template, runtime_cluster = parser._build_evtx_template(
            PROVIDER,
            EVENT_ID,
            RAW_LINE,
        )

        expected = self._evtx_attack_template(PROVIDER, EVENT_ID)

        self.assertEqual(runtime_template, expected)
        self.assertEqual(runtime_cluster, expected)

    def test_windows_apt_evtx_runtime_uses_metadata_order(self):
        parser = DrainParser.__new__(DrainParser)
        parser.template_strategy = "windows_apt_evtx"

        runtime_template, runtime_cluster = parser._build_evtx_template(
            "Microsoft-Windows-Security-Auditing",
            "4624",
            "Microsoft-Windows-Security-Auditing EventID=4624",
            channel="Security",
            task="12544",
            level="0",
        )

        expected = (
            "EventID 4624 Provider Microsoft-Windows-Security-Auditing "
            "Channel Security Task 12544 Level 0"
        )
        self.assertEqual(runtime_template, expected)
        self.assertEqual(runtime_cluster, expected)

    def test_known_training_schemes_are_not_silent_equivalents(self):
        evtx_attack_template = self._evtx_attack_template(PROVIDER, EVENT_ID)

        source_entrytype_template = self._source_entrytype_template(
            PROVIDER,
            "Error",
        )
        self.assertEqual(source_entrytype_template, "Microsoft-Windows-Sysmon_Error")
        self.assertNotEqual(source_entrytype_template, evtx_attack_template)

        drain_input_message = "Process Create: ParentImage=C:\\Windows\\explorer.exe"
        self.assertNotEqual(drain_input_message, evtx_attack_template)


if __name__ == "__main__":
    _ = unittest.main()
