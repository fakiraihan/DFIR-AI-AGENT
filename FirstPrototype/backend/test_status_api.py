import unittest

from fastapi.testclient import TestClient

from main import app, session_store


class InvestigationStatusApiTest(unittest.TestCase):
    def setUp(self):
        session_store.clear()
        self.client = TestClient(app)

    def tearDown(self):
        session_store.clear()

    def test_status_endpoint_returns_lightweight_payload(self):
        session_store.set_session("session_test", {
            "file_name": "sample.evtx",
            "status": "processing",
            "stage": "ai_agent",
            "progress": 72,
            "current_message": "AI sedang mengekstrak IOCs",
            "activity_events": [
                {
                    "sequence": 1,
                    "timestamp": "2026-04-14T10:00:00",
                    "stage": "ai_agent",
                    "action": "status_update",
                    "level": "status",
                    "line": "AI sedang mengekstrak IOCs",
                    "message": "AI sedang mengekstrak IOCs",
                    "progress": 72,
                }
            ],
            "last_update": "2026-04-14T10:00:00",
            "parsed_logs_count": 120,
            "templates_count": 18,
            "anomalies_count": 6,
            "report": {"metadata": {"report_id": "secret-report"}},
            "traceback": "should-not-leak",
        })

        response = self.client.get("/api/status/session_test")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "session_id": "session_test",
                "status": "processing",
                "stage": "ai_agent",
                "progress": 72,
                "current_message": "AI sedang mengekstrak IOCs",
                "activity_events": [
                    {
                        "sequence": 1,
                        "timestamp": "2026-04-14T10:00:00",
                        "stage": "ai_agent",
                        "action": "status_update",
                        "level": "status",
                        "line": "AI sedang mengekstrak IOCs",
                        "message": "AI sedang mengekstrak IOCs",
                        "progress": 72,
                    }
                ],
                "error": None,
                "last_update": "2026-04-14T10:00:00",
                "file_name": "sample.evtx",
                "summary": {
                    "parsed_logs": 120,
                    "templates": 18,
                    "anomalies": 6,
                },
            },
        )

    def test_status_endpoint_sanitizes_activity_events(self):
        session_store.set_session("session_trace", {
            "file_name": "sample.evtx",
            "status": "processing",
            "stage": "ai_agent",
            "progress": 80,
            "current_message": "AI sedang mengkorelasikan findings",
            "activity_events": [
                {
                    "sequence": 7,
                    "timestamp": "2026-04-14T10:05:00",
                    "stage": "ai_agent",
                    "action": "status_update",
                    "level": "stage",
                    "line": "=== STAGE 4: CORRELATION ANALYSIS ===",
                    "message": "AI sedang mengkorelasikan findings",
                    "progress": 80,
                    "raw_reasoning": "should-not-leak",
                    "traceback": "should-not-leak",
                }
            ],
        })

        response = self.client.get("/api/status/session_trace")

        self.assertEqual(response.status_code, 200)
        event = response.json()["activity_events"][0]
        self.assertEqual(
            event,
            {
                "sequence": 7,
                "timestamp": "2026-04-14T10:05:00",
                "stage": "ai_agent",
                "action": "status_update",
                "level": "stage",
                "line": "=== STAGE 4: CORRELATION ANALYSIS ===",
                "message": "AI sedang mengkorelasikan findings",
                "progress": 80,
            },
        )
        self.assertNotIn("raw_reasoning", event)
        self.assertNotIn("traceback", event)


if __name__ == "__main__":
    unittest.main()
