import tempfile
import unittest
from pathlib import Path
import sys
import os

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEMP_ROOT = Path(tempfile.mkdtemp(prefix="dfir_export_api_test_"))
os.environ.setdefault("SESSION_CACHE_PATH", str(TEMP_ROOT / "session_cache"))
os.environ.setdefault("AUTH_DB_PATH", str(TEMP_ROOT / "dfir_auth.sqlite3"))

import routers.investigation as investigation_router
from main import app, session_store
from modules.auth_store import auth_store


class ExportApiTest(unittest.TestCase):
    def setUp(self):
        session_store.clear()
        auth_store.clear_all()
        self.client = TestClient(app)

    def tearDown(self):
        session_store.clear()
        auth_store.clear_all()

    def register_user(self):
        response = self.client.post(
            "/api/auth/register",
            json={
                "username": "exportuser",
                "email": "export@example.test",
                "password": "export password",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["user"]

    def test_export_endpoint_downloads_manifest_and_jsonl(self):
        user = self.register_user()
        with tempfile.TemporaryDirectory() as temp_dir:
            original_output_dir = investigation_router.OUTPUT_DIR
            investigation_router.OUTPUT_DIR = Path(temp_dir) / "output"
            export_dir = investigation_router.OUTPUT_DIR / "session_export" / "exports"
            export_dir.mkdir(parents=True, exist_ok=True)

            manifest_path = export_dir / "export_manifest.json"
            jsonl_path = export_dir / "parsed_logs.jsonl"
            manifest_path.write_text('{"session_id":"session_export"}', encoding="utf-8")
            jsonl_path.write_text('{"line_number":1}\n', encoding="utf-8")

            try:
                session_store.set_session(
                    "session_export",
                    {
                        "user_id": user["id"],
                        "status": "completed",
                        "parsed_export_manifest_path": str(manifest_path),
                        "parsed_export_jsonl_path": str(jsonl_path),
                    },
                )

                manifest_response = self.client.get("/api/export/session_export")
                self.assertEqual(manifest_response.status_code, 200)
                self.assertIn("session_export-export-manifest.json", manifest_response.headers["content-disposition"])

                jsonl_response = self.client.get("/api/export/session_export?format=jsonl")
                self.assertEqual(jsonl_response.status_code, 200)
                self.assertIn("session_export-parsed-logs.jsonl", jsonl_response.headers["content-disposition"])
            finally:
                investigation_router.OUTPUT_DIR = original_output_dir

    def test_export_endpoint_rejects_unknown_format(self):
        user = self.register_user()
        session_store.set_session("session_unknown", {"user_id": user["id"], "status": "completed"})

        response = self.client.get("/api/export/session_unknown?format=xml")

        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported export format", response.json()["detail"])

    def test_export_endpoint_returns_not_found_when_artifact_missing(self):
        user = self.register_user()
        session_store.set_session(
            "session_missing",
            {
                "user_id": user["id"],
                "status": "completed",
                "parsed_export_csv_path": "D:/FAKI/FirstPrototype/output/session_missing/exports/parsed_logs.csv",
            },
        )

        response = self.client.get("/api/export/session_missing?format=csv")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Export artifact", response.json()["detail"])

    def test_report_pdf_endpoint_returns_selectable_pdf_attachment(self):
        self.register_user()
        original_renderer = investigation_router.render_html_report_pdf
        investigation_router.render_html_report_pdf = lambda html: b"%PDF-1.4 selectable text pdf"

        try:
            response = self.client.post(
                "/api/report-export/pdf",
                json={
                    "filename": "case 1.pdf",
                    "html": "<!doctype html><html><body><h1>Case 1</h1></body></html>",
                },
            )
        finally:
            investigation_router.render_html_report_pdf = original_renderer

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertIn("case-1.pdf", response.headers["content-disposition"])
        self.assertEqual(response.content, b"%PDF-1.4 selectable text pdf")


if __name__ == "__main__":
    unittest.main()
