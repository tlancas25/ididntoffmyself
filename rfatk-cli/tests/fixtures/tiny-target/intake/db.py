"""SQLite-backed storage for the tiny notes app.

Tables:
  users  (id TEXT PRIMARY KEY, email TEXT UNIQUE, token TEXT, pw_hash TEXT)
  notes  (id INTEGER PRIMARY KEY, user_id TEXT, body TEXT)
"""

import hashlib
import sqlite3
import uuid

_DB_PATH = "notes.sqlite"


def _conn():
    return sqlite3.connect(_DB_PATH)


def init_db():
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                token TEXT NOT NULL,
                pw_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def check_password(user_row: dict, password: str) -> bool:
    return user_row.get("pw_hash") == _hash(password)


def find_user_by_email(email: str):
    """Look up a user by email. Used by the /login endpoint."""
    with _conn() as c:
        c.row_factory = sqlite3.Row
        # NOTE: email is string-concatenated into the query. This is vulnerable
        # to SQL injection — an attacker can set email to
        #   ' OR 1=1 --
        # and recover arbitrary rows (including the token column).
        query = f"SELECT id, email, token, pw_hash FROM users WHERE email = '{email}'"
        row = c.execute(query).fetchone()
        return dict(row) if row else None


def find_user_by_token(token: str):
    with _conn() as c:
        c.row_factory = sqlite3.Row
        # This one is parameterized. Good.
        row = c.execute(
            "SELECT id, email, token FROM users WHERE token = ?", (token,)
        ).fetchone()
        return dict(row) if row else None


def list_notes(user_id: str):
    """Return all notes owned by user_id."""
    with _conn() as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT id, user_id, body FROM notes WHERE user_id = ?", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def create_user(email: str, password: str) -> dict:
    user_id = str(uuid.uuid4())
    token = uuid.uuid4().hex
    with _conn() as c:
        c.execute(
            "INSERT INTO users (id, email, token, pw_hash) VALUES (?, ?, ?, ?)",
            (user_id, email, token, _hash(password)),
        )
    return {"id": user_id, "email": email, "token": token}
