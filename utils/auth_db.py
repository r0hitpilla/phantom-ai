"""
Phantom AI — User Database (SQLite)
OWASP-hardened: Fernet-encrypted PII, HMAC email index, Werkzeug PBKDF2 passwords,
account lockout, and audit logging.

Roles:
  admin — full access, can run all scans
  user  — read-only, can view dashboard and reports, cannot run scans
"""

import hashlib
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from utils.security import decrypt_field, encrypt_field, hash_for_lookup

_default_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phantom_users.db")
DB_PATH = os.environ.get("DB_PATH", _default_db)

# Account lockout config (OWASP A07)
LOCKOUT_THRESHOLD = 5          # failed attempts before lockout
LOCKOUT_WINDOW_MINUTES = 15    # rolling window for counting failures
LOCKOUT_DURATION_MINUTES = 30  # how long the account stays locked


# ──────────────────────────────────────────────────────────────────────────────
# DB connection + schema
# ──────────────────────────────────────────────────────────────────────────────

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _existing_columns(db, table: str) -> set:
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()}


_NEW_SCHEMA = """
    CREATE TABLE users_new (
        id            TEXT PRIMARY KEY,
        email_enc     TEXT NOT NULL DEFAULT '',
        email_hash    TEXT DEFAULT '',
        name_enc      TEXT,
        provider      TEXT NOT NULL DEFAULT 'email',
        password_hash TEXT,
        google_sub    TEXT,
        role          TEXT NOT NULL DEFAULT 'user',
        is_active     INTEGER NOT NULL DEFAULT 1,
        locked_until  TEXT,
        last_login    TEXT,
        created_at    TEXT NOT NULL
    )
"""


def _needs_recreation(db) -> bool:
    """True if users table exists but still has the old NOT NULL email column."""
    cols = {r[1]: r for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if "users" not in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        return False  # table doesn't exist yet
    # Old schema had 'email' column; new schema has 'email_enc' / 'email_hash'
    return "email" in cols and "email_hash" not in cols


def init_db():
    with _conn() as db:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        # ── Recreate users table if it uses the old schema ──────────────────
        if "users" in tables and _needs_recreation(db):
            print("[auth_db] Migrating users table to new encrypted schema…")
            db.execute(_NEW_SCHEMA)
            # Fetch every old row (includes plain-text email / name columns)
            old_rows = db.execute(
                "SELECT id, email, name, provider, password_hash, google_sub, role, created_at FROM users"
            ).fetchall()
            for row in old_rows:
                plain_email = (row["email"] or "").strip().lower()
                plain_name = (row["name"] or "").strip()
                db.execute(
                    """INSERT INTO users_new
                       (id, email_enc, email_hash, name_enc, provider, password_hash,
                        google_sub, role, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        row["id"],
                        encrypt_field(plain_email),
                        hash_for_lookup(plain_email) if plain_email else "",
                        encrypt_field(plain_name),
                        row["provider"],
                        row["password_hash"],
                        row["google_sub"],
                        row["role"],
                        row["created_at"],
                    ),
                )
            db.execute("DROP TABLE users")
            db.execute("ALTER TABLE users_new RENAME TO users")
            db.commit()
            print(f"[auth_db] Migrated {len(old_rows)} users. Table recreated.")

        # ── Create fresh if not present ──────────────────────────────────────
        if "users" not in tables:
            db.execute(_NEW_SCHEMA.replace("users_new", "users"))

        # ── Add any still-missing columns (idempotent) ───────────────────────
        cols = _existing_columns(db, "users")
        for col, col_def in {
            "email_enc":    "TEXT NOT NULL DEFAULT ''",
            "email_hash":   "TEXT DEFAULT ''",
            "name_enc":     "TEXT",
            "is_active":    "INTEGER NOT NULL DEFAULT 1",
            "locked_until": "TEXT",
            "last_login":   "TEXT",
        }.items():
            if col not in cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")

        db.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT NOT NULL,
                ip TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                ts TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                ip TEXT,
                ts TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_attempts_hash_ts ON login_attempts(email_hash, ts)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
        db.commit()

    # Populate encrypted columns from legacy plain-text data
    migrate_legacy_rows()

    # Create unique indexes after data is in place
    with _conn() as db:
        for stmt in [
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash) WHERE email_hash != ''",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL",
        ]:
            try:
                db.execute(stmt)
            except Exception:
                pass
        db.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_id() -> str:
    return secrets.token_hex(16)


def _check_legacy_password(password: str, stored_hash: str) -> bool:
    """Backward compat for SHA256+salt hashes created before the OWASP upgrade."""
    try:
        salt, h = stored_hash.split(":", 1)
        return hashlib.sha256((password + salt).encode()).hexdigest() == h
    except Exception:
        return False


def _is_admin_email(email: str) -> bool:
    raw = os.environ.get("ADMIN_EMAILS", "")
    admins = [e.strip().lower() for e in raw.split(",") if e.strip()]
    return email.lower() in admins


def _decrypt_user(row: dict) -> dict:
    """Decrypt encrypted fields before returning to caller."""
    if not row:
        return row
    row = dict(row)
    row["email"] = decrypt_field(row.get("email_enc", ""))
    row["name"] = decrypt_field(row.get("name_enc", "")) or ""
    return row


def _row(db, query, *args) -> dict | None:
    row = db.execute(query, args).fetchone()
    return dict(row) if row else None


# ──────────────────────────────────────────────────────────────────────────────
# Account lockout helpers
# ──────────────────────────────────────────────────────────────────────────────

def _record_attempt(db, email_hash: str, ip: str | None, success: bool):
    db.execute(
        "INSERT INTO login_attempts (email_hash, ip, success, ts) VALUES (?,?,?,?)",
        (email_hash, ip or "unknown", 1 if success else 0, datetime.utcnow().isoformat()),
    )


def _recent_failures(db, email_hash: str) -> int:
    since = (datetime.utcnow() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat()
    row = db.execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE email_hash=? AND success=0 AND ts >= ?",
        (email_hash, since),
    ).fetchone()
    return row["n"] if row else 0


def _is_locked(user: dict) -> bool:
    locked_until = user.get("locked_until")
    if locked_until:
        try:
            if datetime.utcnow() < datetime.fromisoformat(locked_until):
                return True
        except ValueError:
            pass
    return False


def _apply_lockout_if_needed(db, user_id: str, email_hash: str):
    failures = _recent_failures(db, email_hash)
    if failures >= LOCKOUT_THRESHOLD:
        until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
        db.execute("UPDATE users SET locked_until=? WHERE id=?", (until, user_id))


# ──────────────────────────────────────────────────────────────────────────────
# Audit logging
# ──────────────────────────────────────────────────────────────────────────────

def audit(action: str, user_id: str | None = None, detail: str | None = None, ip: str | None = None):
    """Append an immutable audit record. Fire-and-forget — never raises."""
    try:
        with _conn() as db:
            db.execute(
                "INSERT INTO audit_log (user_id, action, detail, ip, ts) VALUES (?,?,?,?,?)",
                (user_id, action, detail, ip or "unknown", datetime.utcnow().isoformat()),
            )
            db.commit()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Public read functions
# ──────────────────────────────────────────────────────────────────────────────

def get_by_id(user_id: str) -> dict | None:
    with _conn() as db:
        row = _row(db, "SELECT * FROM users WHERE id = ?", user_id)
    return _decrypt_user(row)


def get_by_email(email: str) -> dict | None:
    target = email.lower().strip()
    h = hash_for_lookup(target)

    with _conn() as db:
        # 1. Fast path: HMAC hash index
        row = _row(db, "SELECT * FROM users WHERE email_hash = ?", h)
        if row:
            return _decrypt_user(row)

        # 2. Legacy plain-text email column (old schema still present)
        cols = _existing_columns(db, "users")
        if "email" in cols:
            row = _row(db, "SELECT * FROM users WHERE LOWER(email) = ?", target)
            if row:
                return _decrypt_user(row)

        # 3. Full-scan fallback: decrypt email_enc and compare
        #    Handles empty/wrong email_hash (migration issues, SECRET_KEY change)
        rows = db.execute("SELECT * FROM users").fetchall()
        for r in rows:
            try:
                stored = decrypt_field(dict(r).get("email_enc", "")).lower().strip()
                if stored == target:
                    found = dict(r)
                    # Heal the hash so future lookups are fast
                    if not found.get("email_hash"):
                        db.execute(
                            "UPDATE users SET email_hash=? WHERE id=?",
                            (h, found["id"]),
                        )
                        db.commit()
                    return _decrypt_user(found)
            except Exception:
                pass

    return None


def get_by_google_sub(sub: str) -> dict | None:
    with _conn() as db:
        row = _row(db, "SELECT * FROM users WHERE google_sub = ?", sub)
    return _decrypt_user(row)


def all_users() -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [_decrypt_user(dict(r)) for r in rows]


# ──────────────────────────────────────────────────────────────────────────────
# Registration + authentication
# ──────────────────────────────────────────────────────────────────────────────

def register_email_user(email: str, name: str, password: str) -> dict:
    """Create a new email/password user. Raises ValueError if email already taken."""
    email = email.lower().strip()
    email_hash = hash_for_lookup(email)

    if get_by_email(email):
        raise ValueError("An account with this email already exists.")

    role = "admin" if _is_admin_email(email) else "user"
    uid = _make_id()

    with _conn() as db:
        db.execute(
            """INSERT INTO users
               (id, email_enc, email_hash, name_enc, provider, password_hash, role, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                uid,
                encrypt_field(email),
                email_hash,
                encrypt_field(name),
                "email",
                generate_password_hash(password),
                role,
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()

    audit("register", user_id=uid, detail=f"provider=email role={role}")
    return get_by_id(uid)


def login_email_user(email: str, password: str, ip: str | None = None) -> dict | None:
    """
    Validate email/password with lockout enforcement.
    Returns user dict on success, None on failure.
    Callers should also call check_rate_limit(ip) before invoking this.
    """
    email = email.lower().strip()
    email_hash = hash_for_lookup(email)
    user = get_by_email(email)

    with _conn() as db:
        if not user:
            print(f"[auth] login fail: user not found for email hash {email_hash[:8]}", file=sys.stderr)
            _record_attempt(db, email_hash, ip, success=False)
            db.commit()
            return None

        if user.get("provider") != "email":
            print(f"[auth] login fail: provider={user.get('provider')} not email", file=sys.stderr)
            _record_attempt(db, email_hash, ip, success=False)
            db.commit()
            return None

        if not user.get("is_active", 1):
            print(f"[auth] login fail: account inactive uid={user['id']}", file=sys.stderr)
            audit("login_blocked_inactive", user_id=user["id"], ip=ip)
            return None

        if _is_locked(user):
            print(f"[auth] login fail: account locked uid={user['id']}", file=sys.stderr)
            audit("login_blocked_locked", user_id=user["id"], ip=ip)
            _record_attempt(db, email_hash, ip, success=False)
            db.commit()
            return None

        pw_hash = user.get("password_hash", "")
        # Try werkzeug PBKDF2 first; fall back to legacy SHA256+salt for migrated accounts
        password_ok = False
        if pw_hash:
            try:
                password_ok = check_password_hash(pw_hash, password)
            except Exception:
                password_ok = False
            if not password_ok:
                password_ok = _check_legacy_password(password, pw_hash)
                if password_ok:
                    # Upgrade legacy hash to werkzeug on successful login
                    db.execute(
                        "UPDATE users SET password_hash=? WHERE id=?",
                        (generate_password_hash(password), user["id"]),
                    )

        if not password_ok:
            print(f"[auth] login fail: wrong password uid={user['id']}", file=sys.stderr)
            _record_attempt(db, email_hash, ip, success=False)
            _apply_lockout_if_needed(db, user["id"], email_hash)
            db.commit()
            audit("login_fail", user_id=user["id"], ip=ip)
            return None

        # Successful login
        _record_attempt(db, email_hash, ip, success=True)
        db.execute(
            "UPDATE users SET locked_until=NULL, last_login=? WHERE id=?",
            (datetime.utcnow().isoformat(), user["id"]),
        )
        db.commit()

    audit("login_success", user_id=user["id"], ip=ip)
    return get_by_id(user["id"])


def upsert_google_user(email: str, name: str, google_sub: str, ip: str | None = None) -> dict:
    """Create or update a Google OAuth user. Role auto-set from ADMIN_EMAILS."""
    email = email.lower().strip()
    email_hash = hash_for_lookup(email)
    role = "admin" if _is_admin_email(email) else "user"

    user = get_by_google_sub(google_sub) or get_by_email(email)
    if user:
        with _conn() as db:
            db.execute(
                """UPDATE users
                   SET name_enc=?, email_enc=?, email_hash=?, google_sub=?, role=?, last_login=?
                   WHERE id=?""",
                (
                    encrypt_field(name),
                    encrypt_field(email),
                    email_hash,
                    google_sub,
                    role,
                    datetime.utcnow().isoformat(),
                    user["id"],
                ),
            )
            db.commit()
        audit("google_login", user_id=user["id"], ip=ip)
        return get_by_id(user["id"])

    uid = _make_id()
    with _conn() as db:
        db.execute(
            """INSERT INTO users
               (id, email_enc, email_hash, name_enc, provider, google_sub, role, last_login, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                uid,
                encrypt_field(email),
                email_hash,
                encrypt_field(name),
                "google",
                google_sub,
                role,
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()
    audit("google_register", user_id=uid, detail=f"role={role}", ip=ip)
    return get_by_id(uid)


# ──────────────────────────────────────────────────────────────────────────────
# Admin operations
# ──────────────────────────────────────────────────────────────────────────────

def delete_user(user_id: str, by_admin_id: str | None = None):
    with _conn() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
    audit("user_delete", user_id=by_admin_id, detail=f"deleted_user={user_id}")


def update_role(user_id: str, role: str, by_admin_id: str | None = None):
    with _conn() as db:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()
    audit("role_change", user_id=by_admin_id, detail=f"target={user_id} new_role={role}")


def deactivate_user(user_id: str, by_admin_id: str | None = None):
    with _conn() as db:
        db.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        db.commit()
    audit("user_deactivate", user_id=by_admin_id, detail=f"target={user_id}")


# ──────────────────────────────────────────────────────────────────────────────
# Migration helper: upgrade legacy plain-text email rows
# ──────────────────────────────────────────────────────────────────────────────

def migrate_legacy_rows():
    """
    Populate email_enc / email_hash / name_enc for any rows that still have
    blank email_hash (either copied from old schema or freshly added).
    Safe to call multiple times.
    """
    try:
        with _conn() as db:
            cols = _existing_columns(db, "users")
            # Nothing stored in plain-text columns — nothing to migrate
            if "email" not in cols and "name" not in cols:
                return

            # Find rows not yet migrated (email_hash still blank)
            rows = db.execute(
                "SELECT id, email, name FROM users WHERE COALESCE(email_hash, '') = ''"
            ).fetchall()

            for r in rows:
                plain_email = (r["email"] or "") if "email" in cols else ""
                plain_name = (r["name"] or "") if "name" in cols else ""
                db.execute(
                    "UPDATE users SET email_enc=?, email_hash=?, name_enc=? WHERE id=?",
                    (
                        encrypt_field(plain_email),
                        hash_for_lookup(plain_email.lower()) if plain_email else "",
                        encrypt_field(plain_name),
                        r["id"],
                    ),
                )

            if rows:
                print(f"[auth_db] Migrated {len(rows)} legacy rows to encrypted schema")
            db.commit()
    except Exception as e:
        print(f"[auth_db] migration warning: {e}")


# Initialize DB on import
try:
    init_db()
except Exception as e:
    print(f"[auth_db] DB init warning: {e}")
