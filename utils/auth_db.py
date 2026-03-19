"""
Phantom AI — User Database (SQLite)
Manages users, roles, and authentication for multi-user access.

Roles:
  admin — full access, can run all scans
  user  — read-only, can view dashboard and reports, cannot run scans
"""

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phantom_users.db")


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                email         TEXT UNIQUE NOT NULL,
                name          TEXT,
                provider      TEXT NOT NULL DEFAULT 'email',
                password_hash TEXT,
                google_sub    TEXT,
                role          TEXT NOT NULL DEFAULT 'user',
                created_at    TEXT NOT NULL
            )
        """)
        db.commit()


def _row(db, query, *args):
    row = db.execute(query, args).fetchone()
    return dict(row) if row else None


def get_by_id(user_id: str):
    with _conn() as db:
        return _row(db, "SELECT * FROM users WHERE id = ?", user_id)


def get_by_email(email: str):
    with _conn() as db:
        return _row(db, "SELECT * FROM users WHERE email = ?", email.lower())


def get_by_google_sub(sub: str):
    with _conn() as db:
        return _row(db, "SELECT * FROM users WHERE google_sub = ?", sub)


def all_users():
    with _conn() as db:
        rows = db.execute(
            "SELECT id, email, name, provider, role, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def _is_admin_email(email: str) -> bool:
    raw = os.environ.get("ADMIN_EMAILS", "")
    admins = [e.strip().lower() for e in raw.split(",") if e.strip()]
    return email.lower() in admins


def _make_id():
    return secrets.token_hex(16)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{h}"


def check_password(password: str, stored_hash: str) -> bool:
    try:
        salt, h = stored_hash.split(":", 1)
        return hashlib.sha256((password + salt).encode()).hexdigest() == h
    except Exception:
        return False


def register_email_user(email: str, name: str, password: str):
    """Create a new email/password user. Returns user dict or raises ValueError."""
    email = email.lower().strip()
    if get_by_email(email):
        raise ValueError("An account with this email already exists.")
    role = "admin" if _is_admin_email(email) else "user"
    uid = _make_id()
    with _conn() as db:
        db.execute(
            "INSERT INTO users (id, email, name, provider, password_hash, role, created_at) VALUES (?,?,?,?,?,?,?)",
            (uid, email, name, "email", hash_password(password), role, datetime.utcnow().isoformat()),
        )
        db.commit()
    return get_by_id(uid)


def login_email_user(email: str, password: str):
    """Validate email/password. Returns user dict or None."""
    user = get_by_email(email.lower().strip())
    if not user or user["provider"] != "email":
        return None
    if not user.get("password_hash") or not check_password(password, user["password_hash"]):
        return None
    return user


def upsert_google_user(email: str, name: str, google_sub: str):
    """Create or update a Google OAuth user. Role is auto-set based on ADMIN_EMAILS."""
    email = email.lower()
    role = "admin" if _is_admin_email(email) else "user"

    user = get_by_google_sub(google_sub) or get_by_email(email)
    if user:
        with _conn() as db:
            db.execute(
                "UPDATE users SET name=?, google_sub=?, role=? WHERE id=?",
                (name, google_sub, role, user["id"]),
            )
            db.commit()
        return get_by_id(user["id"])

    uid = _make_id()
    with _conn() as db:
        db.execute(
            "INSERT INTO users (id, email, name, provider, google_sub, role, created_at) VALUES (?,?,?,?,?,?,?)",
            (uid, email, name, "google", google_sub, role, datetime.utcnow().isoformat()),
        )
        db.commit()
    return get_by_id(uid)


def delete_user(user_id: str):
    with _conn() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()


def update_role(user_id: str, role: str):
    with _conn() as db:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()


# Initialize DB on import
try:
    init_db()
except Exception as e:
    print(f"[auth_db] DB init warning: {e}")
