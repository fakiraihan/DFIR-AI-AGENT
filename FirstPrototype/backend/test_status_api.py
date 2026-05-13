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


if __name__ == "__main__":
    unittest.main()
