"""SQLite-backed user authentication store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import re
from typing import Any
from uuid import uuid4

from config import settings


PASSWORD_ITERATIONS = 210_000
SESSION_DAYS = 7
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hash_password(password: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest = encoded_hash.split("$", 3)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256" or int(iterations) != PASSWORD_ITERATIONS:
        return False

    candidate = _hash_password(password, salt_hex).split("$", 3)[3]
    return hmac.compare_digest(candidate, digest)


def _legacy_username_from_email(email: str, fallback_id: str) -> str:
    prefix = str(email or "").split("@", 1)[0].strip().lower()
    candidate = re.sub(r"[^a-z0-9._-]+", "-", prefix).strip(".-_")
    if not candidate or not candidate[0].isalnum():
        candidate = f"user-{fallback_id[:8]}"
    if len(candidate) < 3:
        candidate = f"{candidate}-user"
    return candidate[:40]


class AuthStore:
    """Small SQLite repository for users and browser auth sessions."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        if not self.db_path.is_absolute():
            self.db_path = Path(__file__).resolve().parents[2] / self.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ensure_schema()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        return connection

    def ensure_schema(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    session_token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_auth_sessions_token
                    ON auth_sessions(session_token_hash);
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
                    ON auth_sessions(user_id);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "username" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN username TEXT")
                rows = connection.execute("SELECT id, email FROM users").fetchall()
                used_usernames: set[str] = set()
                for row in rows:
                    base = _legacy_username_from_email(row["email"], row["id"])
                    username = base
                    suffix = 1
                    while username in used_usernames:
                        suffix += 1
                        username = f"{base[: 39 - len(str(suffix))]}-{suffix}"
                    used_usernames.add(username)
                    connection.execute(
                        "UPDATE users SET username = ? WHERE id = ?",
                        (username, row["id"]),
                    )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)"
                )

    def clear_all(self) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM auth_sessions")
            connection.execute("DELETE FROM users")

    def create_user(self, *, username: str, email: str, password: str) -> dict[str, Any]:
        clean_username = normalize_username(username)
        clean_email = normalize_email(email)
        now = _iso(_utcnow())
        user = {
            "id": uuid4().hex,
            "username": clean_username,
            "email": clean_email,
            "name": clean_username,
            "password_hash": _hash_password(password),
            "created_at": now,
            "updated_at": now,
        }
        with self.connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO users (id, username, email, name, password_hash, created_at, updated_at)
                    VALUES (:id, :username, :email, :name, :password_hash, :created_at, :updated_at)
                    """,
                    user,
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Username or email already registered") from exc
        return public_user(user)

    def authenticate_user(self, *, username: str, password: str) -> dict[str, Any] | None:
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not _verify_password(password, user["password_hash"]):
            return None
        return public_user(user)

    def create_auth_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        now = _utcnow()
        session = {
            "id": uuid4().hex,
            "user_id": user_id,
            "session_token_hash": _hash_session_token(token),
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(days=SESSION_DAYS)),
            "revoked_at": None,
        }
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_sessions
                    (id, user_id, session_token_hash, created_at, expires_at, revoked_at)
                VALUES
                    (:id, :user_id, :session_token_hash, :created_at, :expires_at, :revoked_at)
                """,
                session,
            )
        return token

    def revoke_auth_session(self, token: str) -> None:
        if not token:
            return
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE session_token_hash = ? AND revoked_at IS NULL
                """,
                (_iso(_utcnow()), _hash_session_token(token)),
            )

    def get_user_for_token(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT users.id, users.username, users.email, users.name, users.created_at, users.updated_at
                FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.session_token_hash = ?
                    AND auth_sessions.revoked_at IS NULL
                    AND auth_sessions.expires_at > ?
                """,
                (_hash_session_token(token), _iso(_utcnow())),
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (normalize_email(email),),
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (normalize_username(username),),
            ).fetchone()
        return dict(row) if row else None


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def normalize_username(username: str) -> str:
    cleaned = str(username or "").strip().lower()
    if not USERNAME_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Username must be 3-40 characters and use letters, numbers, dot, dash, or underscore"
        )
    return cleaned


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user.get("username") or normalize_email(user["email"]).split("@", 1)[0],
        "email": user["email"],
        "name": user["name"],
        "created_at": user.get("created_at"),
    }


auth_store = AuthStore(settings.auth_db_path)
