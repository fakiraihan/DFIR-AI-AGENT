import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

_TEMP_PATH = Path(tempfile.mkdtemp(prefix="dfir_auth_api_test_"))
os.environ["SESSION_CACHE_PATH"] = str(_TEMP_PATH / "session_cache")
os.environ["AUTH_DB_PATH"] = str(_TEMP_PATH / "dfir_auth.sqlite3")

from main import app, session_store  # noqa: E402
from modules.auth_store import auth_store  # noqa: E402


class AuthApiTest(unittest.TestCase):
    def setUp(self):
        session_store.clear()
        auth_store.clear_all()
        self.client = TestClient(app)

    def tearDown(self):
        session_store.clear()
        auth_store.clear_all()

    def register(
        self,
        username="analystone",
        email="analyst@example.test",
        password="correct horse battery",
    ):
        return self.client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
            },
        )

    def login(self, username="analystone", password="correct horse battery"):
        return self.client.post(
            "/api/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )

    def test_register_logs_user_in_and_me_returns_profile(self):
        register_response = self.register()

        self.assertEqual(register_response.status_code, 200)
        payload = register_response.json()
        self.assertEqual(payload["user"]["username"], "analystone")
        self.assertEqual(payload["user"]["email"], "analyst@example.test")
        self.assertEqual(payload["user"]["name"], "analystone")
        self.assertIn("dfir_session", register_response.headers.get("set-cookie", ""))

        me_response = self.client.get("/api/auth/me")

        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["user"]["username"], "analystone")
        self.assertEqual(me_response.json()["user"]["email"], "analyst@example.test")

    def test_duplicate_register_rejects_existing_username_or_email(self):
        self.assertEqual(self.register().status_code, 200)

        duplicate_response = self.register()

        self.assertEqual(duplicate_response.status_code, 409)
        self.assertIn("already registered", duplicate_response.json()["detail"].lower())

    def test_login_and_logout_session_cookie(self):
        self.assertEqual(self.register().status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

        login_response = self.login()

        self.assertEqual(login_response.status_code, 200)
        self.assertEqual(login_response.json()["user"]["username"], "analystone")
        self.assertEqual(login_response.json()["user"]["email"], "analyst@example.test")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)

    def test_session_history_requires_login_and_is_scoped_to_current_user(self):
        session_store.set_session(
            "session_user_a",
            {
                "user_id": "user-a",
                "file_name": "a.evtx",
                "status": "completed",
                "upload_time": "2026-06-03T10:00:00",
            },
        )
        session_store.set_session(
            "session_user_b",
            {
                "user_id": "user-b",
                "file_name": "b.evtx",
                "status": "completed",
                "upload_time": "2026-06-03T11:00:00",
            },
        )

        anonymous_response = self.client.get("/api/sessions")
        self.assertEqual(anonymous_response.status_code, 401)

        register_response = self.register(username="usera", email="a@example.test")
        user_id = register_response.json()["user"]["id"]
        session_store.update_session("session_user_a", {"user_id": user_id})

        history_response = self.client.get("/api/sessions")

        self.assertEqual(history_response.status_code, 200)
        self.assertEqual(
            [item["session_id"] for item in history_response.json()["sessions"]],
            ["session_user_a"],
        )

        foreign_status_response = self.client.get("/api/status/session_user_b")
        self.assertEqual(foreign_status_response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
