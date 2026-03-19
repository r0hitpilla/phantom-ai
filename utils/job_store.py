"""
Persistent store for scan jobs, scheduled jobs, and campaigns.
Backed by SQLite — survives restarts and redeploys.
"""

import json
import os
import sqlite3
from datetime import datetime

_default_db = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "jobs.db"
)
DB_PATH = os.environ.get("JOBS_DB_PATH", _default_db)


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                job_id       TEXT PRIMARY KEY,
                module       TEXT,
                target       TEXT,
                status       TEXT DEFAULT 'running',
                progress     INTEGER DEFAULT 0,
                progress_log TEXT DEFAULT '[]',
                results      TEXT,
                error        TEXT,
                notify_email TEXT,
                sched_id     TEXT,
                created_at   TEXT
            );

            CREATE TABLE IF NOT EXISTS scheduled_jobs (
                sched_id     TEXT PRIMARY KEY,
                module       TEXT,
                target       TEXT,
                scan_depth   TEXT,
                notify_email TEXT,
                run_at       TEXT,
                status       TEXT DEFAULT 'pending',
                job_id       TEXT,
                created_at   TEXT
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                data        TEXT,
                created_at  TEXT
            );
        """)


# ─── Scan jobs ────────────────────────────────────────────────────────────────

def save_job(job):
    """Insert or replace a job dict into the DB."""
    with _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scan_jobs
               (job_id, module, target, status, progress, progress_log,
                results, error, notify_email, sched_id, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                job["job_id"],
                job.get("module"),
                job.get("target"),
                job.get("status", "running"),
                job.get("progress", 0),
                json.dumps(job.get("progress_log") or []),
                json.dumps(job.get("results")) if job.get("results") is not None else None,
                job.get("error"),
                job.get("notify_email"),
                job.get("sched_id"),
                job.get("created_at", datetime.utcnow().isoformat()),
            ),
        )


def update_job(job_id, **kwargs):
    """Update specific fields on a job row."""
    allowed = {"status", "progress", "progress_log", "results", "error", "notify_email"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    for key in ("progress_log", "results"):
        if key in updates and not isinstance(updates[key], str):
            updates[key] = json.dumps(updates[key])
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [job_id]
    with _connect() as conn:
        conn.execute(f"UPDATE scan_jobs SET {set_clause} WHERE job_id = ?", values)


def get_job(job_id):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    return _deserialize_job(dict(row)) if row else None


def get_all_jobs():
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_jobs ORDER BY created_at DESC"
        ).fetchall()
    return {r["job_id"]: _deserialize_job(dict(r)) for r in rows}


def _deserialize_job(d):
    for key in ("progress_log", "results"):
        if d.get(key) and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


# ─── Scheduled jobs ───────────────────────────────────────────────────────────

def save_scheduled_job(sched):
    with _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scheduled_jobs
               (sched_id, module, target, scan_depth, notify_email,
                run_at, status, job_id, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                sched["sched_id"],
                sched.get("module"),
                sched.get("target"),
                sched.get("scan_depth"),
                sched.get("notify_email"),
                sched.get("run_at"),
                sched.get("status", "pending"),
                sched.get("job_id"),
                sched.get("created_at", datetime.utcnow().isoformat()),
            ),
        )


def update_scheduled_job(sched_id, **kwargs):
    allowed = {"status", "job_id"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [sched_id]
    with _connect() as conn:
        conn.execute(
            f"UPDATE scheduled_jobs SET {set_clause} WHERE sched_id = ?", values
        )


def get_scheduled_job(sched_id):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_jobs WHERE sched_id = ?", (sched_id,)
        ).fetchone()
    return dict(row) if row else None


def get_all_scheduled_jobs():
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scheduled_jobs ORDER BY created_at DESC"
        ).fetchall()
    return {r["sched_id"]: dict(r) for r in rows}


# ─── Campaigns ────────────────────────────────────────────────────────────────

def save_campaign(campaign_id, campaign_data):
    with _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO campaigns (campaign_id, data, created_at)
               VALUES (?,?,?)""",
            (
                campaign_id,
                json.dumps(campaign_data),
                datetime.utcnow().isoformat(),
            ),
        )


def get_all_campaigns():
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC"
        ).fetchall()
    result = {}
    for r in rows:
        try:
            result[r["campaign_id"]] = json.loads(r["data"])
        except (json.JSONDecodeError, TypeError):
            pass
    return result
