"""Independent login and server-side sessions for the ADCS JSON API.

The upstream ADCS project is not involved in web authentication.
Compatible with Python 3.9+, only standard-library dependencies.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time

PBKDF2_ITERATIONS = 600_000
FAIL_WINDOW_SECONDS = 300
MAX_FAILED_ATTEMPTS = 6


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must have at least 12 characters")
    salt = secrets.token_bytes(24)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(PBKDF2_ITERATIONS, salt.hex(), key.hex())


def check_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, rounds, salt, expected = stored_hash.split("$", 3)
        rounds = int(rounds)
        if scheme != "pbkdf2_sha256" or not 100_000 <= rounds <= 5_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), rounds)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (TypeError, ValueError, OverflowError):
        return False


class SessionStore:
    """SQLite sessions: logout invalidates tokens across all API workers."""

    def __init__(self, db_file: str, ttl_seconds: int = 3600):
        self.db_file = str(Path(db_file).expanduser().resolve())
        self.ttl_seconds = ttl_seconds
        directory = Path(self.db_file).parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not Path(self.db_file).exists():
            # Limit file permissions even with a permissive process umask;
            # a second API worker may create the file first.
            try:
                fd = os.open(self.db_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS sessions ("
                       "token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS attempts ("
                       "ip TEXT PRIMARY KEY, failures INTEGER NOT NULL, starts_at INTEGER NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)")

    def _connect(self):
        db = sqlite3.connect(self.db_file, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + self.ttl_seconds
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            db.execute("INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
                       (self._digest(token), username, expires_at))
        return token

    def lookup(self, token: str):
        if not token or len(token) > 512:
            return None
        with self._connect() as db:
            row = db.execute("SELECT username, expires_at FROM sessions "
                             "WHERE token_hash = ? AND expires_at > ?",
                             (self._digest(token), int(time.time()))).fetchone()
        return {"username": row[0], "expires_at": row[1]} if row else None

    def revoke(self, token: str):
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (self._digest(token),))

    def locked(self, ip: str) -> bool:
        now = int(time.time())
        with self._connect() as db:
            row = db.execute("SELECT failures, starts_at FROM attempts WHERE ip = ?", (ip,)).fetchone()
        return bool(row and row[1] > now - FAIL_WINDOW_SECONDS and row[0] >= MAX_FAILED_ATTEMPTS)

    def note_failure(self, ip: str):
        now = int(time.time())
        with self._connect() as db:
            db.execute("INSERT INTO attempts (ip, failures, starts_at) VALUES (?, 1, ?) "
                       "ON CONFLICT(ip) DO UPDATE SET "
                       "failures = CASE WHEN starts_at <= ? THEN 1 ELSE failures + 1 END, "
                       "starts_at = CASE WHEN starts_at <= ? THEN ? ELSE starts_at END",
                       (ip, now, now - FAIL_WINDOW_SECONDS, now - FAIL_WINDOW_SECONDS, now))

    def clear_failures(self, ip: str):
        with self._connect() as db:
            db.execute("DELETE FROM attempts WHERE ip = ?", (ip,))


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "hash-password":
        first = getpass.getpass("New API password (min 12 chars): ")
        second = getpass.getpass("Repeat password: ")
        if first != second:
            sys.exit("Passwords don't match")
        print(hash_password(first))
    else:
        sys.exit("Usage: python -m api.auth hash-password")


if __name__ == "__main__":
    main()
