import unittest
import tempfile
import os
from pathlib import Path

TEMP_ROOT = Path(tempfile.mkdtemp(prefix="dfir_sessions_api_test_"))
os.environ.setdefault("SESSION_CACHE_PATH", str(TEMP_ROOT / "session_cache"))
os.environ.setdefault("AUTH_DB_PATH", str(TEMP_ROOT / "dfir_auth.sqlite3"))

from fastapi.testclient import TestClient

import routers.investigation as investigation_router
from main import app, session_store
from modules.auth_store import auth_store


class SessionsApiTest(unittest.TestCase):
    def setUp(self):
        session_store.clear()
        auth_store.clear_all()
        self.client = TestClient(app)

    def tearDown(self):
        session_store.clear()
        auth_store.clear_all()

    def register_user(self, username="historyuser", email="history@example.test"):
        response = self.client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "history password",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["user"]

    def test_sessions_endpoint_returns_lightweight_history(self):
        user = self.register_user()
        session_store.cache.set("legacy_bad_record", "legacy payload")
        session_store.set_session("session_old", {
            "user_id": user["id"],
            "file_name": "old.evtx",
            "status": "completed",
            "stage": "completed",
            "progress": 100,
            "upload_time": "2026-04-13T09:00:00",
            "completion_time": "2026-04-13T09:30:00",
            "parsed_logs_count": 25,
            "templates_count": 4,
            "anomalies_count": 2,
            "report": {
                "metadata": {
                    "report_id": "RPT-old",
                    "severity": "LOW",
                },
                "executive_summary": "Full report should not be included in history list.",
            },
        })
        session_store.set_session("session_new", {
            "user_id": user["id"],
            "file_name": "new.evtx",
            "status": "processing",
            "stage": "ai_agent",
            "progress": 65,
            "current_message": "Correlating events",
            "upload_time": "2026-04-14T10:00:00",
            "last_update": "2026-04-14T10:10:00",
            "report": {"metadata": {"report_id": "hidden-detail"}},
        })

        response = self.client.get("/api/sessions")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([item["session_id"] for item in payload["sessions"]], ["session_new", "session_old"])
        self.assertEqual(payload["sessions"][0]["file_name"], "new.evtx")
        self.assertEqual(payload["sessions"][0]["current_message"], "Correlating events")
        self.assertEqual(payload["sessions"][1]["report_id"], "RPT-old")
        self.assertEqual(payload["sessions"][1]["severity"], "LOW")
        self.assertNotIn("report", payload["sessions"][1])
        self.assertNotIn("executive_summary", payload["sessions"][1])

    def test_rename_session_updates_history_title(self):
        user = self.register_user()
        session_store.set_session("session_rename", {
            "user_id": user["id"],
            "file_name": "original.evtx",
            "status": "uploaded",
            "upload_time": "2026-04-14T10:00:00",
        })

        response = self.client.patch("/api/sessions/session_rename", json={"title": "Case Alpha"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["title"], "Case Alpha")
        self.assertEqual(session_store.get_session("session_rename")["title"], "Case Alpha")

    def test_delete_session_removes_metadata_raw_logs_and_report_dir(self):
        user = self.register_user()
        with tempfile.TemporaryDirectory() as temp_dir:
            original_output_dir = investigation_router.OUTPUT_DIR
            original_raw_logs_dir = session_store.raw_logs_dir
            temp_output_dir = Path(temp_dir) / "output"
            temp_raw_logs_dir = Path(temp_dir) / "raw_logs"
            temp_raw_logs_dir.mkdir(parents=True, exist_ok=True)
            investigation_router.OUTPUT_DIR = temp_output_dir
            session_store.raw_logs_dir = temp_raw_logs_dir

            try:
                session_store.set_session("session_delete", {
                    "user_id": user["id"],
                    "file_name": "delete.evtx",
                    "status": "completed",
                })
                raw_session_dir = session_store.raw_logs_dir / "session_delete"
                output_session_dir = temp_output_dir / "session_delete"
                raw_session_dir.mkdir(parents=True, exist_ok=True)
                output_session_dir.mkdir(parents=True, exist_ok=True)
                (raw_session_dir / "delete.evtx").write_text("raw log", encoding="utf-8")
                (output_session_dir / "report.md").write_text("report", encoding="utf-8")

                response = self.client.delete("/api/sessions/session_delete")

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {"session_id": "session_delete", "deleted": True})
                self.assertIsNone(session_store.get_session("session_delete"))
                self.assertFalse(raw_session_dir.exists())
                self.assertFalse(output_session_dir.exists())
            finally:
                investigation_router.OUTPUT_DIR = original_output_dir
                session_store.raw_logs_dir = original_raw_logs_dir


if __name__ == "__main__":
    unittest.main()
