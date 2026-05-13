import tempfile
import unittest
from pathlib import Path

from session_store import SessionStore


class SessionStorePersistenceTest(unittest.TestCase):
    def test_zero_timeout_keeps_sessions_and_raw_dirs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            cache_dir = base_dir / "cache"
            raw_logs_dir = base_dir / "raw_logs"
            stale_session_dir = raw_logs_dir / "session_stale"
            stale_session_dir.mkdir(parents=True)

            store = SessionStore(cache_dir, raw_logs_dir, session_timeout_minutes=0)
            restarted_store = None

            try:
                _ = store.set_session("session_test", {"status": "uploaded"})
                store.cleanup_expired_sessions()

                self.assertEqual(store.get_session("session_test"), {"status": "uploaded"})
                self.assertTrue(stale_session_dir.exists())
                store.cache.close()

                restarted_store = SessionStore(cache_dir, raw_logs_dir, session_timeout_minutes=0)

                self.assertEqual(restarted_store.get_session("session_test"), {"status": "uploaded"})
                self.assertTrue(stale_session_dir.exists())
            finally:
                store.cache.close()
                if restarted_store is not None:
                    restarted_store.cache.close()


if __name__ == "__main__":
    unittest.main()
