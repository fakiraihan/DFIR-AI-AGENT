from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import shutil
from typing import Any

from diskcache import Cache


class SessionStore:
    """Prototype-friendly disk-backed session storage.

    A timeout value of 0 keeps sessions indefinitely so investigation history can
    survive backend restarts. Positive timeout values preserve the previous
    expiring-session behavior for deployments that need automatic cleanup.
    """

    def __init__(
        self,
        cache_dir: Path,
        raw_logs_dir: Path,
        session_timeout_minutes: int,
    ):
        self.cache_dir = Path(cache_dir)
        self.raw_logs_dir = Path(raw_logs_dir)
        self.session_timeout_minutes = max(0, int(session_timeout_minutes))
        self.timeout_seconds = (
            self.session_timeout_minutes * 60 if self.session_timeout_minutes > 0 else None
        )

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.raw_logs_dir.mkdir(parents=True, exist_ok=True)
        self.cache = Cache(str(self.cache_dir))
        self.cleanup_expired_sessions()

    def _expiry_timestamp(self) -> str:
        if self.timeout_seconds is None:
            raise RuntimeError("Session expiry is disabled")
        return (datetime.now() + timedelta(seconds=self.timeout_seconds)).isoformat()

    def _normalize_session(self, session: dict[str, Any]) -> dict[str, Any]:
        payload = dict(session)
        if self.timeout_seconds is None:
            payload.pop("_expires_at", None)
        else:
            payload["_expires_at"] = self._expiry_timestamp()
        return payload

    def cleanup_expired_sessions(self) -> None:
        if self.timeout_seconds is None:
            return

        self.cache.expire()
        active_session_ids = {str(key) for key in self.cache}
        now = datetime.now()

        for session_dir in self.raw_logs_dir.iterdir():
            if not session_dir.is_dir():
                continue
            if session_dir.name in active_session_ids:
                continue

            age = now - datetime.fromtimestamp(session_dir.stat().st_mtime)
            if age >= timedelta(minutes=self.session_timeout_minutes):
                shutil.rmtree(session_dir, ignore_errors=True)

    def set_session(self, session_id: str, session: dict[str, Any]) -> dict[str, Any]:
        self.cleanup_expired_sessions()
        payload = self._normalize_session(session)
        self.cache.set(session_id, payload, expire=self.timeout_seconds)
        return self._public_session(payload)

    def get_session(
        self,
        session_id: str,
        default: dict[str, Any] | None = None,
        *,
        touch: bool = False,
    ) -> dict[str, Any] | None:
        self.cleanup_expired_sessions()
        session = self.cache.get(session_id)
        if session is None:
            return default
        if touch:
            session = self._normalize_session(session)
            self.cache.set(session_id, session, expire=self.timeout_seconds)
        return self._public_session(session)

    def update_session(self, session_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        session = self.get_session(session_id, touch=False)
        if session is None:
            return None
        session.update(updates)
        return self.set_session(session_id, session)

    def delete_session(self, session_id: str) -> None:
        self.cache.pop(session_id, None)

    def clear(self) -> None:
        self.cache.clear()

    def __contains__(self, session_id: str) -> bool:
        return self.get_session(session_id, touch=False) is not None

    def __iter__(self):
        self.cleanup_expired_sessions()
        return iter([str(key) for key in self.cache])

    def __len__(self) -> int:
        self.cleanup_expired_sessions()
        return len(self.cache)

    def _public_session(self, session: dict[str, Any]) -> dict[str, Any]:
        payload = dict(session)
        payload.pop("_expires_at", None)
        return payload
