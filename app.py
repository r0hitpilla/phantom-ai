"""
PHANTOM AI — Main Flask Application
Authorized Security Testing Platform
For use only on systems you own or have written authorization to test.
"""

import io
import json
import os
import threading
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from apscheduler.schedulers.background import BackgroundScheduler
from authlib.integrations.flask_client import OAuth
from config import SECRET_KEY
from modules.appsec import AppSecScanner
from utils.auth_db import (
    all_users, audit, delete_user, get_by_id,
    login_email_user, register_email_user, update_role,
    upsert_google_user,
)
from utils.emailer import notifier
from utils.security import (
    add_security_headers,
    check_rate_limit,
    generate_csrf_token,
    get_client_ip,
    is_safe_redirect_url,
    reset_rate_limit,
    sanitize_string,
    validate_csrf_token,
    validate_email,
    validate_password_strength,
)
from modules.cognitive import CognitiveProfiler
from modules.deepfake import DeepfakeSimulator
from modules.redteam import RedTeamAgent
from modules.scanner import AIScanner
from modules.supply_chain import SupplyChainScanner

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Session security (OWASP A07) ──────────────────────────────────────────────
IS_PRODUCTION = bool(
    os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("PRODUCTION")
    or os.environ.get("RAILWAY_STATIC_URL")
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PRODUCTION,   # HTTPS-only in production
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# ---------------------------------------------------------------------------
# Google OAuth setup
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

oauth = OAuth(app)
if GOOGLE_ENABLED:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# ---------------------------------------------------------------------------
# Security hooks
# ---------------------------------------------------------------------------

@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)


@app.before_request
def enforce_session_timeout():
    """Expire sessions that have been idle longer than the configured lifetime."""
    if session.get("logged_in") and session.get("login_time"):
        try:
            login_time = datetime.fromisoformat(session["login_time"])
            if datetime.utcnow() - login_time > timedelta(hours=8):
                session.clear()
                flash("Your session has expired. Please log in again.", "info")
                return redirect(url_for("login"))
        except (ValueError, TypeError):
            session.clear()
            return redirect(url_for("login"))


@app.before_request
def csrf_protect():
    """Validate CSRF token on all state-changing form submissions (non-API)."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Skip API endpoints that use JSON (protected by SameSite + auth)
        if request.path.startswith("/api/"):
            return
        # Skip OAuth callbacks (no session CSRF possible there)
        if request.path.startswith("/auth/"):
            return
        submitted = request.form.get("_csrf_token", "")
        if not validate_csrf_token(session, submitted):
            audit("csrf_fail", ip=get_client_ip(request), detail=request.path)
            flash("Security validation failed. Please try again.", "error")
            return redirect(request.referrer or url_for("login"))


@app.context_processor
def inject_csrf():
    """Make csrf_token() available in all templates."""
    def csrf_token():
        return generate_csrf_token(session)
    return {"csrf_token": csrf_token}


# ---------------------------------------------------------------------------
# Global stores
# ---------------------------------------------------------------------------

# Global job store: {job_id: {status, progress, module, results, created_at}}
jobs = {}

# Campaign store (for deepfake module)
campaigns = {}

# Scheduled job store: {sched_id: {sched_id, module, target, run_at, status, job_id, ...}}
scheduled_jobs = {}

# APScheduler instance
_scheduler = BackgroundScheduler(timezone="UTC")
_scheduler.start()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

PHANTOM_PASSWORD = os.environ.get("PHANTOM_PASSWORD", "phantom2024")
PHANTOM_USERNAME = "admin"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def authorization_required(f):
    """Decorator that checks for authorization token in POST body."""
    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        authorized = data.get("authorized", False)
        if not authorized:
            return jsonify({
                "error": "Authorization required",
                "message": (
                    "You must confirm you own or have written authorization to test "
                    "the target system. Check the authorization checkbox and retry."
                ),
            }), 403
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator that restricts route to admin-role users only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        # Legacy admin session (username/password with no user_id)
        if not session.get("user_id") and session.get("username") == PHANTOM_USERNAME:
            return f(*args, **kwargs)
        # New user system: check role
        if session.get("role") == "admin":
            return f(*args, **kwargs)
        # Block non-admin
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({
                "error": "Admin access required",
                "message": "Your account does not have permission to run scans.",
            }), 403
        return render_template("403.html"), 403
    return decorated


@app.context_processor
def inject_user_context():
    """Inject current_user and is_admin into all templates."""
    user_id = session.get("user_id")
    if user_id:
        user = get_by_id(user_id)
        if user:
            return {"current_user": user, "is_admin": user["role"] == "admin"}
    # Legacy admin session
    if session.get("logged_in") and not session.get("user_id"):
        return {
            "current_user": {
                "id": "legacy",
                "email": session.get("username", "admin"),
                "name": "Admin",
                "role": "admin",
                "provider": "password",
            },
            "is_admin": True,
        }
    return {"current_user": None, "is_admin": False}


# ---------------------------------------------------------------------------
# Email notification helper
# ---------------------------------------------------------------------------

def _notify(job_id: str, override_email: str = None):
    """Send scan-complete email in a background thread."""
    job = jobs.get(job_id)
    if not job:
        return
    # Temporarily override notify_email if caller specified one
    original = notifier.notify_email
    if override_email:
        notifier.notify_email = override_email
    try:
        threading.Thread(
            target=notifier.send_scan_complete,
            args=(job_id, job),
            daemon=True,
        ).start()
    finally:
        notifier.notify_email = original


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ip = get_client_ip(request)

        # Rate limit before any processing (OWASP A07)
        if not check_rate_limit(ip):
            audit("rate_limit_login", ip=ip)
            flash("Too many login attempts. Please wait 15 minutes before trying again.", "error")
            return render_template("login.html", google_enabled=GOOGLE_ENABLED), 429

        username = sanitize_string(request.form.get("username", ""), max_length=254)
        password = request.form.get("password", "")

        # Legacy admin login
        if username == PHANTOM_USERNAME and password == PHANTOM_PASSWORD:
            reset_rate_limit(ip)
            _set_user_session({
                "id": None, "email": username, "name": "Admin",
                "role": "admin", "provider": "password",
            })
            session.pop("user_id", None)  # Mark as legacy session
            next_url = request.args.get("next", "")
            if next_url and is_safe_redirect_url(next_url, request.host):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        # Email/password login via user DB
        user = login_email_user(username, password, ip=ip)
        if user:
            reset_rate_limit(ip)
            _set_user_session(user)
            next_url = request.args.get("next", "")
            if next_url and is_safe_redirect_url(next_url, request.host):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        # Generic error — no enumeration hints
        flash("Invalid credentials. Please try again.", "error")

    return render_template("login.html", google_enabled=GOOGLE_ENABLED)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = sanitize_string(request.form.get("name", ""), max_length=100)
        email = sanitize_string(request.form.get("email", ""), max_length=254)
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
        elif not validate_email(email):
            flash("Please enter a valid email address.", "error")
        else:
            pw_ok, pw_reason = validate_password_strength(password)
            if not pw_ok:
                flash(pw_reason, "error")
            elif password != confirm:
                flash("Passwords do not match.", "error")
            else:
                try:
                    user = register_email_user(email, name, password)
                    _set_user_session(user)
                    flash(
                        f"Welcome, {name}! Your account has been created."
                        + (" You have admin access." if user["role"] == "admin" else " You have read-only access."),
                        "success" if user["role"] == "admin" else "info",
                    )
                    return redirect(url_for("dashboard"))
                except ValueError as e:
                    flash(str(e), "error")

    return render_template("register.html", google_enabled=GOOGLE_ENABLED)


@app.route("/auth/google")
def google_login():
    if not GOOGLE_ENABLED:
        flash("Google OAuth is not configured.", "error")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    if not GOOGLE_ENABLED:
        return redirect(url_for("login"))
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get("userinfo") or {}
        email = user_info.get("email", "")
        name = user_info.get("name", email)
        sub = user_info.get("sub", "")
        if not email:
            flash("Google login failed — no email returned.", "error")
            return redirect(url_for("login"))
        user = upsert_google_user(email, name, sub, ip=get_client_ip(request))
        _set_user_session(user)
        return redirect(url_for("dashboard"))
    except Exception as exc:
        traceback.print_exc()
        flash(f"Google login failed: {exc}", "error")
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def _set_user_session(user: dict):
    # Session regeneration on login — prevents session fixation (OWASP A07)
    session.clear()
    session.permanent = True
    session["logged_in"] = True
    session["user_id"] = user.get("id")
    session["username"] = user.get("email", "")
    session["role"] = user.get("role", "user")
    session["login_time"] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    recent_jobs = sorted(
        [
            {
                "job_id": jid,
                "module": jdata.get("module", "Unknown"),
                "target": jdata.get("target", "Unknown"),
                "status": jdata.get("status", "Unknown"),
                "progress": jdata.get("progress", 0),
                "created_at": jdata.get("created_at", ""),
                "risk_score": jdata.get("results", {}).get("risk_score", None)
                if jdata.get("results")
                else None,
            }
            for jid, jdata in jobs.items()
        ],
        key=lambda x: x["created_at"],
        reverse=True,
    )[:10]

    stats = {
        "total_scans": len(jobs),
        "completed_scans": sum(1 for j in jobs.values() if j.get("status") == "completed"),
        "critical_findings": sum(
            1
            for j in jobs.values()
            if j.get("results", {}).get("risk_score", 0) >= 75
        ),
        "companies_protected": len(set(j.get("target", "") for j in jobs.values() if j.get("target"))),
    }

    return render_template(
        "dashboard.html",
        recent_jobs=recent_jobs,
        stats=stats,
    )


# ---------------------------------------------------------------------------
# Module 1 — AI Attack Surface Scanner
# ---------------------------------------------------------------------------

@app.route("/module/scanner")
@login_required
def module_scanner():
    return render_template("scanner.html")


@app.route("/api/scanner/start", methods=["POST"])
@login_required
@admin_required
@authorization_required
def scanner_start():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "AI Scanner",
        "target": domain,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_scan():
        try:
            scanner = AIScanner(domain=domain, authorization_token=job_id)
            # Attach progress updates to job
            original_log = scanner._log

            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = scanner.progress
                jobs[job_id]["progress_log"] = scanner.progress_log

            scanner._log = patched_log
            results = scanner.run_full_scan()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/scanner/status/<job_id>")
@login_required
def scanner_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "progress_log": job.get("progress_log", [])[-10:],
        "error": job.get("error"),
    })


@app.route("/api/scanner/results/<job_id>")
@login_required
def scanner_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "error": "Scan not yet completed",
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Module 2 — Deepfake Social Engineering Simulation
# ---------------------------------------------------------------------------

@app.route("/module/deepfake")
@login_required
def module_deepfake():
    return render_template("deepfake.html", campaigns=list(campaigns.values()))


@app.route("/api/deepfake/generate", methods=["POST"])
@login_required
@admin_required
@authorization_required
def deepfake_generate():
    data = request.get_json(silent=True) or {}
    company_name = data.get("company_name", "").strip()
    exec_name = data.get("exec_name", "").strip()
    exec_title = data.get("exec_title", "").strip()
    target_employees = data.get("target_employees", [])
    scenario_type = data.get("scenario_type", "credential_reset")

    if not company_name or not exec_name:
        return jsonify({"error": "company_name and exec_name are required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "Deepfake Simulator",
        "target": company_name,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_generation():
        try:
            simulator = DeepfakeSimulator(
                company_name=company_name,
                target_employees=target_employees,
                exec_name=exec_name,
                exec_title=exec_title,
            )
            jobs[job_id]["progress"] = 20
            scenarios = simulator.generate_scenarios()
            jobs[job_id]["progress"] = 50

            # Find the scenario matching the requested type
            target_scenario = next(
                (s for s in scenarios if s.get("type") == scenario_type), scenarios[0]
            )

            # Generate script for first employee or a generic target
            sample_employee = (
                target_employees[0]
                if target_employees
                else {"name": "Target Employee", "title": "Staff Member", "department": "General"}
            )
            call_script = simulator.generate_call_script(target_scenario, sample_employee)
            jobs[job_id]["progress"] = 75

            email_campaign = simulator.generate_email_campaign(target_scenario)
            jobs[job_id]["progress"] = 90

            training_content = simulator.generate_training_content(target_scenario)

            jobs[job_id]["results"] = {
                "company": company_name,
                "scenarios": scenarios,
                "selected_scenario": target_scenario,
                "call_script": call_script,
                "email_campaign": email_campaign,
                "training_content": training_content,
                "generated_at": datetime.utcnow().isoformat(),
            }
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_generation, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/deepfake/campaign", methods=["POST"])
@login_required
@admin_required
@authorization_required
def deepfake_campaign():
    data = request.get_json(silent=True) or {}
    company_name = data.get("company_name", "").strip()
    exec_name = data.get("exec_name", "").strip()
    exec_title = data.get("exec_title", "CEO").strip()
    targets = data.get("targets", [])
    scenario_type = data.get("scenario_type", "credential_reset")

    if not company_name or not targets:
        return jsonify({"error": "company_name and targets are required"}), 400

    simulator = DeepfakeSimulator(
        company_name=company_name,
        target_employees=targets,
        exec_name=exec_name,
        exec_title=exec_title,
    )
    campaign = simulator.create_campaign(targets, scenario_type)
    campaigns[campaign["campaign_id"]] = campaign

    return jsonify(campaign)


@app.route("/api/deepfake/campaigns")
@login_required
def deepfake_campaigns():
    return jsonify(list(campaigns.values()))


@app.route("/api/deepfake/status/<job_id>")
@login_required
def deepfake_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "error": job.get("error"),
    })


@app.route("/api/deepfake/results/<job_id>")
@login_required
def deepfake_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Module 3 — Autonomous AI Red Team Agent
# ---------------------------------------------------------------------------

@app.route("/module/redteam")
@login_required
def module_redteam():
    return render_template("redteam.html")


@app.route("/api/redteam/start", methods=["POST"])
@login_required
@admin_required
@authorization_required
def redteam_start():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    industry = data.get("industry", "Technology")
    employee_count = data.get("employee_count", "100-500")

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "Red Team Agent",
        "target": domain,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_redteam():
        try:
            agent = RedTeamAgent(
                company_domain=domain,
                industry=industry,
                employee_count=employee_count,
            )

            original_log = agent._log

            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = agent.progress
                jobs[job_id]["progress_log"] = agent.progress_log

            agent._log = patched_log
            results = agent.run_autonomous_scan()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_redteam, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/redteam/status/<job_id>")
@login_required
def redteam_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "progress_log": job.get("progress_log", [])[-10:],
        "error": job.get("error"),
    })


@app.route("/api/redteam/results/<job_id>")
@login_required
def redteam_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Module 4 — AI Supply Chain Attack Simulator
# ---------------------------------------------------------------------------

@app.route("/module/supplychain")
@login_required
def module_supplychain():
    return render_template("supplychain.html")


@app.route("/api/supplychain/scan", methods=["POST"])
@login_required
@admin_required
@authorization_required
def supplychain_scan():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    known_ai_tools = data.get("known_ai_tools", [])

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "Supply Chain Scanner",
        "target": domain,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_scan():
        try:
            scanner = SupplyChainScanner(domain=domain, known_ai_tools=known_ai_tools)

            original_log = scanner._log

            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = scanner.progress
                jobs[job_id]["progress_log"] = scanner.progress_log

            scanner._log = patched_log
            results = scanner.run_full_scan()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/supplychain/status/<job_id>")
@login_required
def supplychain_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "progress_log": job.get("progress_log", [])[-10:],
        "error": job.get("error"),
    })


@app.route("/api/supplychain/results/<job_id>")
@login_required
def supplychain_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Module 5 — Cognitive Attack Profiling
# ---------------------------------------------------------------------------

@app.route("/module/cognitive")
@login_required
def module_cognitive():
    return render_template("cognitive.html")


@app.route("/api/cognitive/profile", methods=["POST"])
@login_required
@admin_required
@authorization_required
def cognitive_profile():
    data = request.get_json(silent=True) or {}
    company_name = data.get("company_name", "").strip()
    employees_data = data.get("employees", [])

    if not company_name:
        return jsonify({"error": "company_name is required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "Cognitive Profiler",
        "target": company_name,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_profiling():
        try:
            profiler = CognitiveProfiler(
                company_name=company_name,
                employees_data=employees_data,
            )

            original_log = profiler._log

            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = profiler.progress
                jobs[job_id]["progress_log"] = profiler.progress_log

            profiler._log = patched_log
            results = profiler.run_full_profiling()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_profiling, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/cognitive/status/<job_id>")
@login_required
def cognitive_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "progress_log": job.get("progress_log", [])[-10:],
        "error": job.get("error"),
    })


@app.route("/api/cognitive/results/<job_id>")
@login_required
def cognitive_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Module 6 — Application Security Tester
# ---------------------------------------------------------------------------

@app.route("/module/appsec")
@login_required
def module_appsec():
    return render_template("appsec.html")


@app.route("/api/appsec/start", methods=["POST"])
@login_required
@admin_required
@authorization_required
def appsec_start():
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    scan_depth = data.get("scan_depth", "standard")

    if not target_url:
        return jsonify({"error": "Application URL is required"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "module": "AppSec Tester",
        "target": target_url,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    def run_scan():
        try:
            scanner = AppSecScanner(
                target_url=target_url,
                authorization_token=job_id,
                scan_depth=scan_depth,
            )

            original_log = scanner._log

            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = scanner.progress
                jobs[job_id]["progress_log"] = scanner.progress_log

            scanner._log = patched_log
            results = scanner.run_full_scan()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, jobs[job_id].get("notify_email"))
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/appsec/status/<job_id>")
@login_required
def appsec_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "progress_log": job.get("progress_log", [])[-15:],
        "error": job.get("error"),
    })


@app.route("/api/appsec/results/<job_id>")
@login_required
def appsec_results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({
            "status": job["status"],
            "progress": job.get("progress", 0),
        }), 202
    return jsonify(job["results"])


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route("/api/report/<job_id>")
@login_required
def generate_report(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({"error": "Scan not yet completed"}), 202

    try:
        from fpdf import FPDF

        results = job.get("results", {})
        module = job.get("module", "Security Assessment")
        target = job.get("target", "Unknown")
        created_at = job.get("created_at", datetime.utcnow().isoformat())

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Header
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_fill_color(10, 14, 26)
        pdf.set_text_color(255, 62, 62)
        pdf.cell(0, 12, "PHANTOM AI", new_x="LMARGIN", new_y="NEXT", align="C")

        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(0, 212, 255)
        pdf.cell(0, 8, f"Security Assessment Report — {module}", new_x="LMARGIN", new_y="NEXT", align="C")

        pdf.ln(4)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, f"Target: {target}  |  Date: {created_at[:10]}  |  Job ID: {job_id}", new_x="LMARGIN", new_y="NEXT", align="C")

        # Authorization banner
        pdf.ln(4)
        pdf.set_fill_color(255, 62, 62)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 8, "FOR AUTHORIZED SECURITY TESTING ONLY — CONFIDENTIAL", new_x="LMARGIN", new_y="NEXT", align="C", fill=True)

        pdf.ln(6)
        pdf.set_text_color(30, 30, 30)

        # Risk Score
        risk_score = results.get("risk_score", results.get("overall_vulnerability_score", 0))
        if risk_score:
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(200, 0, 0) if risk_score >= 75 else pdf.set_text_color(200, 100, 0) if risk_score >= 50 else pdf.set_text_color(0, 150, 80)
            pdf.cell(0, 10, f"Overall Risk Score: {risk_score}/100", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30)

        # Executive Summary / Findings
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

        findings_text = (
            results.get("findings_summary")
            or results.get("findings")
            or results.get("narrative_report")
            or results.get("profiling_report")
            or "See detailed results for full findings."
        )
        # Sanitize text for PDF (remove markdown)
        findings_clean = _sanitize_for_pdf(str(findings_text), max_len=3000)
        pdf.multi_cell(0, 5, findings_clean)

        pdf.ln(6)

        # Key statistics section
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Key Statistics", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

        stats = _extract_stats_for_pdf(results, module)
        for stat_line in stats:
            pdf.cell(0, 6, stat_line, new_x="LMARGIN", new_y="NEXT")

        # Footer
        pdf.ln(10)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(130, 130, 130)
        pdf.cell(
            0, 6,
            "PHANTOM AI — This report is confidential and for authorized security testing use only.",
            new_x="LMARGIN", new_y="NEXT", align="C"
        )

        # AppSec Tester — per-finding structured report
        if module == "AppSec Tester":
            findings = results.get("findings", [])
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

            for i, finding in enumerate(findings_sorted, 1):
                pdf.add_page()
                sev = finding.get("severity", "INFO")
                sev_colors = {
                    "CRITICAL": (255, 62, 62),
                    "HIGH": (255, 140, 0),
                    "MEDIUM": (200, 165, 0),
                    "LOW": (0, 180, 90),
                    "INFO": (0, 180, 220),
                }
                r_col, g_col, b_col = sev_colors.get(sev, (150, 150, 150))

                # Finding header
                pdf.set_fill_color(r_col, g_col, b_col)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 8,
                    f"Finding #{i:02d} — {sev} — {_sanitize_for_pdf(finding.get('category', 'Unknown'))}",
                    new_x="LMARGIN", new_y="NEXT", fill=True
                )

                pdf.set_text_color(30, 30, 30)
                fields = [
                    ("Affected URL / Service", finding.get("affected_url", "—")),
                    ("Observations", finding.get("observations", "—")),
                    ("Business Risk", finding.get("business_risk", "—")),
                    ("Technical Impact", finding.get("impact", "—")),
                    ("Recommendations", finding.get("recommendations", "—")),
                    ("Industry Standards Mapping", finding.get("standards_mapping", "—")),
                    ("CWE Mapping", finding.get("cwe_mapping", "—")),
                ]
                for label, value in fields:
                    pdf.ln(3)
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_text_color(0, 100, 180)
                    pdf.cell(0, 6, label, new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 9)
                    pdf.set_text_color(40, 40, 40)
                    pdf.multi_cell(0, 5, _sanitize_for_pdf(str(value)))

        # Generate PDF bytes
        pdf_bytes = pdf.output()
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="phantom-ai-report-{job_id[:8]}.pdf"'
            },
        )

    except ImportError:
        # fpdf2 not available — return JSON report
        return jsonify({
            "message": "PDF generation requires fpdf2. Install it with: pip install fpdf2",
            "report_data": job.get("results", {}),
        })
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"Report generation failed: {exc}"}), 500


# ---------------------------------------------------------------------------
# Job Queue UI
# ---------------------------------------------------------------------------

@app.route("/jobs")
@login_required
def job_queue():
    return render_template("jobs.html")


# ---------------------------------------------------------------------------
# Admin — User Management
# ---------------------------------------------------------------------------

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    return render_template(
        "users.html",
        users=all_users(),
        admin_emails=os.environ.get("ADMIN_EMAILS", ""),
    )


@app.route("/admin/users/<user_id>/role", methods=["POST"])
@login_required
@admin_required
def admin_set_role(user_id):
    role = request.form.get("role", "user")
    if role not in ("admin", "user"):
        flash("Invalid role.", "error")
    else:
        update_role(user_id, role, by_admin_id=session.get("user_id"))
        flash(f"Role updated to {role}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    current_uid = session.get("user_id")
    if user_id == current_uid:
        flash("You cannot delete your own account.", "error")
    else:
        delete_user(user_id, by_admin_id=current_uid)
        flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# API — Job listing
# ---------------------------------------------------------------------------

@app.route("/api/jobs")
@login_required
def list_jobs():
    job_list = [
        {
            "job_id": jid,
            "module": jdata.get("module"),
            "target": jdata.get("target"),
            "status": jdata.get("status"),
            "progress": jdata.get("progress", 0),
            "created_at": jdata.get("created_at"),
            "risk_score": (
                jdata.get("results", {}).get("risk_score")
                or jdata.get("results", {}).get("overall_vulnerability_score")
            ) if jdata.get("results") else None,
        }
        for jid, jdata in jobs.items()
    ]
    job_list.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return jsonify(job_list)


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def _run_scheduled_job(sched_id: str):
    """Called by APScheduler when a scheduled job fires."""
    sched = scheduled_jobs.get(sched_id)
    if not sched or sched["status"] != "pending":
        return

    sched["status"] = "running"
    module = sched["module"]
    target = sched["target"]
    scan_depth = sched.get("scan_depth", "standard")
    notify_email = sched.get("notify_email", "")

    job_id = str(uuid.uuid4())
    module_labels = {
        "appsec": "AppSec Tester",
        "scanner": "AI Scanner",
        "redteam": "Red Team Agent",
        "supplychain": "Supply Chain Scanner",
    }
    jobs[job_id] = {
        "job_id": job_id,
        "module": module_labels.get(module, module),
        "target": target,
        "status": "running",
        "progress": 0,
        "results": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "notify_email": notify_email,
        "sched_id": sched_id,
    }
    sched["job_id"] = job_id

    def run():
        try:
            if module == "appsec":
                scanner = AppSecScanner(target_url=target, authorization_token=job_id, scan_depth=scan_depth)
            elif module == "scanner":
                from modules.scanner import AIScanner
                scanner = AIScanner(domain=target, authorization_token=job_id)
            elif module == "redteam":
                from modules.redteam import RedTeamAgent
                scanner = RedTeamAgent(company_domain=target, industry="Technology", employee_count="100-500")
            elif module == "supplychain":
                from modules.supply_chain import SupplyChainScanner
                scanner = SupplyChainScanner(domain=target, known_ai_tools=[])
            else:
                raise ValueError(f"Unknown module: {module}")

            original_log = scanner._log
            def patched_log(message, level="INFO"):
                original_log(message, level)
                jobs[job_id]["progress"] = scanner.progress
                jobs[job_id]["progress_log"] = scanner.progress_log
            scanner._log = patched_log

            results = scanner.run_full_scan() if hasattr(scanner, "run_full_scan") else scanner.run_autonomous_scan()
            jobs[job_id]["results"] = results
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["progress"] = 100
            _notify(job_id, notify_email)
            sched["status"] = "completed"
        except Exception as exc:
            traceback.print_exc()
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(exc)
            sched["status"] = "failed"

    threading.Thread(target=run, daemon=True).start()


@app.route("/scheduler")
@login_required
def scheduler_page():
    return render_template(
        "scheduler.html",
        email_configured=notifier.is_configured(),
        notify_email=notifier.notify_email,
        app_url=notifier.app_url,
    )


@app.route("/api/scheduler/create", methods=["POST"])
@login_required
@admin_required
def scheduler_create():
    data = request.get_json(silent=True) or {}
    module = data.get("module", "").strip()
    target = data.get("target", "").strip()
    run_at_str = data.get("run_at")
    scan_depth = data.get("scan_depth", "standard")
    notify_email = data.get("notify_email", "").strip() or notifier.notify_email
    authorized = data.get("authorized", False)

    if not module or not target:
        return jsonify({"error": "module and target are required"}), 400
    if not authorized:
        return jsonify({"error": "Authorization confirmation required"}), 403

    sched_id = str(uuid.uuid4())
    sched_entry = {
        "sched_id": sched_id,
        "module": module,
        "target": target,
        "scan_depth": scan_depth,
        "notify_email": notify_email,
        "run_at": run_at_str,
        "status": "pending",
        "job_id": None,
        "created_at": datetime.utcnow().isoformat(),
    }

    if not run_at_str:
        # Run immediately
        scheduled_jobs[sched_id] = sched_entry
        _run_scheduled_job(sched_id)
        return jsonify({"sched_id": sched_id, "job_id": scheduled_jobs[sched_id].get("job_id"), "status": "started"})

    # Parse scheduled time and add to APScheduler
    try:
        run_at = datetime.fromisoformat(run_at_str).replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify({"error": f"Invalid run_at format: {run_at_str}. Use YYYY-MM-DDTHH:MM:SS"}), 400

    if run_at <= datetime.now(timezone.utc):
        return jsonify({"error": "Scheduled time must be in the future"}), 400

    scheduled_jobs[sched_id] = sched_entry
    _scheduler.add_job(
        _run_scheduled_job,
        trigger="date",
        run_date=run_at,
        args=[sched_id],
        id=sched_id,
    )

    return jsonify({"sched_id": sched_id, "status": "scheduled", "run_at": run_at_str})


@app.route("/api/scheduler/list")
@login_required
def scheduler_list():
    items = sorted(scheduled_jobs.values(), key=lambda x: x["created_at"], reverse=True)
    return jsonify(items)


@app.route("/api/scheduler/cancel/<sched_id>", methods=["DELETE"])
@login_required
def scheduler_cancel(sched_id):
    sched = scheduled_jobs.get(sched_id)
    if not sched:
        return jsonify({"error": "Scheduled job not found"}), 404
    if sched["status"] != "pending":
        return jsonify({"error": "Only pending jobs can be cancelled"}), 400

    try:
        _scheduler.remove_job(sched_id)
    except Exception:
        pass
    sched["status"] = "cancelled"
    return jsonify({"status": "cancelled"})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html") if os.path.exists("templates/404.html") else (
        jsonify({"error": "Not found"}), 404
    )


@app.errorhandler(500)
def server_error(e):
    traceback.print_exc()
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _sanitize_for_pdf(text: str, max_len: int = 0) -> str:
    """Remove markdown and replace Unicode with ASCII-safe equivalents for fpdf Helvetica."""
    import re
    # Strip markdown
    text = re.sub(r"#{1,6}\s*", "", text)
    text = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", text)
    text = re.sub(r"`{1,3}[^`]*`{1,3}", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)

    # Replace common Unicode punctuation with ASCII equivalents
    replacements = {
        "\u2014": "-",   # em dash —
        "\u2013": "-",   # en dash –
        "\u2012": "-",   # figure dash
        "\u2015": "-",   # horizontal bar
        "\u2018": "'",   # left single quote '
        "\u2019": "'",   # right single quote '
        "\u201a": ",",   # single low quote ‚
        "\u201c": '"',   # left double quote "
        "\u201d": '"',   # right double quote "
        "\u201e": '"',   # double low quote „
        "\u2022": "-",   # bullet •
        "\u2023": "-",   # triangular bullet ‣
        "\u2026": "...", # ellipsis …
        "\u00b7": "*",   # middle dot ·
        "\u2192": "->",  # right arrow →
        "\u2190": "<-",  # left arrow ←
        "\u00a0": " ",   # non-breaking space
        "\u00ae": "(R)", # registered ®
        "\u00a9": "(C)", # copyright ©
        "\u00b0": " deg",# degree °
        "\u2264": "<=",  # less-than or equal ≤
        "\u2265": ">=",  # greater-than or equal ≥
    }
    for uni, ascii_equiv in replacements.items():
        text = text.replace(uni, ascii_equiv)

    # Drop any remaining characters outside Windows-1252 range
    result = []
    for char in text:
        cp = ord(char)
        # Keep printable ASCII (32-126) + extended latin (160-255) used by Helvetica
        if (32 <= cp <= 126) or (160 <= cp <= 255):
            result.append(char)
        elif char in ("\n", "\r", "\t"):
            result.append(char)
        else:
            result.append(" ")

    text = "".join(result)
    if max_len:
        text = text[:max_len]
    return text


def _extract_stats_for_pdf(results: dict, module: str) -> list:
    """Extract key statistics as formatted strings for PDF."""
    stats = []
    if module == "AI Scanner":
        stats.append(f"AI Endpoints Discovered: {len(results.get('ai_systems', []))}")
        stats.append(f"Accessible Without Auth: {sum(1 for s in results.get('ai_systems', []) if s.get('accessible'))}")
        stats.append(f"Prompt Injection Vulns: {sum(1 for i in results.get('prompt_injection', []) if i.get('vulnerable'))}")
        stats.append(f"Subdomains Found: {len(results.get('subdomains', []))}")
    elif module == "Red Team Agent":
        stats.append(f"Attack Chains Generated: {len(results.get('attack_chains', []))}")
        stats.append(f"Subdomains Enumerated: {len(results.get('osint', {}).get('subdomains', []))}")
        stats.append(f"Technologies Detected: {len(results.get('company_profile', {}).get('technologies', []))}")
    elif module == "Supply Chain Scanner":
        stats.append(f"AI Dependencies Detected: {len(results.get('dependencies', []))}")
        stats.append(f"Prompt Leakage Tests: {len(results.get('leakage_tests', []))}")
        stats.append(f"Provenance Checks: {len(results.get('provenance_checks', []))}")
    elif module == "Cognitive Profiler":
        stats.append(f"Employees Profiled: {len(results.get('profiles', []))}")
        stats.append(f"High-Value Targets: {sum(1 for p in results.get('profiles', []) if p.get('high_value_target'))}")
        stats.append(f"Overall Vulnerability Score: {results.get('overall_vulnerability_score', 0)}/100")
        critical = sum(1 for p in results.get('profiles', []) if p.get('training_priority') == 'CRITICAL')
        stats.append(f"Critical Training Priority: {critical} employees")
    elif module == "AppSec Tester":
        counts = results.get("findings_count", {})
        stats.append(f"Total Findings: {sum(counts.values())}")
        stats.append(f"Critical: {counts.get('critical', 0)}")
        stats.append(f"High: {counts.get('high', 0)}")
        stats.append(f"Medium: {counts.get('medium', 0)}")
        stats.append(f"Low: {counts.get('low', 0)}")
        tech = results.get("tech_stack", {})
        if tech:
            stats.append(f"Tech Stack: {', '.join(f'{k}: {v}' for k, v in tech.items())}")
    return stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
