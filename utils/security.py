"""
Phantom AI — Security Utilities
OWASP-aligned security controls for authentication, session management,
input validation, encryption, CSRF protection, and rate limiting.
"""

import base64
import hashlib
import hmac
import html
import ipaddress
import os
import re
import secrets
import time
from collections import defaultdict
from threading import Lock
from urllib.parse import urlparse

# ──────────────────────────────────────────────────────────────────────────────
# Field-Level Encryption (Fernet / AES-128-CBC)
# Used for PII stored in the database (name, email display values)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def _derive_fernet_key() -> bytes:
    """Derive a 32-byte Fernet key from SECRET_KEY using PBKDF2-HMAC-SHA256."""
    secret = os.environ.get("SECRET_KEY", "phantom-ai-secret-change-me").encode()
    key = hashlib.pbkdf2_hmac("sha256", secret, b"phantom-ai-db-salt-v1", 200_000)
    return base64.urlsafe_b64encode(key)


_fernet_instance = None
_fernet_lock = Lock()


def _get_fernet():
    global _fernet_instance
    if _fernet_instance is None and _CRYPTO_AVAILABLE:
        with _fernet_lock:
            if _fernet_instance is None:
                _fernet_instance = Fernet(_derive_fernet_key())
    return _fernet_instance


def encrypt_field(plaintext: str) -> str:
    """Encrypt a string for database storage. Returns empty string for empty input."""
    if not plaintext:
        return ""
    f = _get_fernet()
    if not f:
        return plaintext  # Fallback if cryptography not installed
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_field(ciphertext: str) -> str:
    """Decrypt a field from the database. Falls back gracefully for legacy data."""
    if not ciphertext:
        return ""
    f = _get_fernet()
    if not f:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except Exception:
        # Not encrypted (legacy data) — return as-is
        return ciphertext


def hash_for_lookup(value: str) -> str:
    """One-way HMAC hash of a value — used for indexed lookups without storing plaintext."""
    secret = os.environ.get("SECRET_KEY", "phantom-ai-secret-change-me").encode()
    return hmac.new(secret, value.lower().encode("utf-8"), hashlib.sha256).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# CSRF Protection
# Token stored in session, validated on all state-changing form requests
# ──────────────────────────────────────────────────────────────────────────────

def generate_csrf_token(session: dict) -> str:
    """Generate (or retrieve) a CSRF token bound to this session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(session: dict, submitted_token: str) -> bool:
    """Constant-time comparison of submitted token vs session token."""
    expected = session.get("_csrf_token", "")
    if not expected or not submitted_token:
        return False
    return hmac.compare_digest(expected, submitted_token)


# ──────────────────────────────────────────────────────────────────────────────
# Rate Limiter (in-process, per-IP)
# Thread-safe, sliding window. Resets automatically after window expires.
# ──────────────────────────────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self):
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str, max_attempts: int, window_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            timestamps = self._store[key]
            # Purge expired timestamps
            self._store[key] = [t for t in timestamps if now - t < window_seconds]
            if len(self._store[key]) >= max_attempts:
                return False
            self._store[key].append(now)
            return True

    def get_remaining(self, key: str, max_attempts: int, window_seconds: int) -> int:
        now = time.time()
        with self._lock:
            timestamps = self._store[key]
            recent = [t for t in timestamps if now - t < window_seconds]
            return max(0, max_attempts - len(recent))

    def reset(self, key: str):
        with self._lock:
            self._store.pop(key, None)


_rate_limiter = _RateLimiter()

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900  # 15 minutes


def check_rate_limit(ip: str) -> bool:
    """Returns True if request is allowed, False if rate-limited."""
    return _rate_limiter.is_allowed(f"login:{ip}", LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS)


def reset_rate_limit(ip: str):
    """Reset rate limit counter after successful login."""
    _rate_limiter.reset(f"login:{ip}")


def get_rate_limit_remaining(ip: str) -> int:
    return _rate_limiter.get_remaining(f"login:{ip}", LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS)


# ──────────────────────────────────────────────────────────────────────────────
# Input Validation & Sanitisation
# ──────────────────────────────────────────────────────────────────────────────

def sanitize_string(value: str, max_length: int = 255) -> str:
    """Strip leading/trailing whitespace and limit length. No HTML encoding — use Jinja2 for that."""
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]


def validate_email(email: str) -> bool:
    pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    return bool(pattern.match(email)) and len(email) <= 254


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Returns (valid, reason). OWASP minimum: 8 chars."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 128:
        return False, "Password must be at most 128 characters."
    return True, ""


def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc) and len(url) <= 2048
    except Exception:
        return False


def validate_domain(domain: str) -> bool:
    domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain)) and len(domain) <= 253


def is_safe_redirect_url(url: str, host: str) -> bool:
    """Only allow redirects to relative paths or same host — prevents open redirect."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        # Relative URL (no scheme or netloc)
        if not parsed.scheme and not parsed.netloc:
            return url.startswith("/") and not url.startswith("//")
        return parsed.netloc == host
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Security Response Headers
# Applied to every response via @app.after_request
# ──────────────────────────────────────────────────────────────────────────────

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
    "font-src https://fonts.googleapis.com https://fonts.gstatic.com; "
    "img-src 'self' data: https:; "
    "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com; "
    "frame-src https://accounts.google.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self' https://accounts.google.com;"
)

IS_PRODUCTION = bool(
    os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("PRODUCTION")
    or os.environ.get("RAILWAY_STATIC_URL")
)


def add_security_headers(response):
    """Add OWASP-recommended security headers to every HTTP response."""
    h = response.headers

    h["X-Frame-Options"] = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["X-XSS-Protection"] = "0"  # Disabled per OWASP — rely on CSP instead
    h["Referrer-Policy"] = "strict-origin-when-cross-origin"
    h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    h["Content-Security-Policy"] = CSP
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"

    # HSTS omitted — Railway's proxy enforces HTTPS at the edge.
    # Setting it here causes redirect loops behind the proxy.

    # Prevent caching of authenticated/sensitive pages
    if response.content_type and "text/html" in response.content_type:
        h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        h["Pragma"] = "no-cache"
        h["Expires"] = "0"

    # Remove server identification headers
    h.pop("Server", None)
    h.pop("X-Powered-By", None)

    return response


# ──────────────────────────────────────────────────────────────────────────────
# Client IP Extraction (trust Railway's proxy)
# ──────────────────────────────────────────────────────────────────────────────

def get_client_ip(request) -> str:
    """Extract real client IP respecting X-Forwarded-For from trusted proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass
    return request.remote_addr or "unknown"
