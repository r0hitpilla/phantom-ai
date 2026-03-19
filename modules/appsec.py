"""
Phantom AI — Module 6: Application Security Tester
Comprehensive web application vulnerability assessment using Claude AI.
Authorization must be confirmed before any test is initiated.
"""

import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse

from utils.claude_client import PhantomAI

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Vulnerability batches — each batch is one dedicated Claude call
# ---------------------------------------------------------------------------

VULN_BATCHES = [
    {
        "name": "Injection Attacks",
        "categories": [
            "SQL Injection (GET/POST parameters, headers, cookies)",
            "NoSQL Injection",
            "LDAP Injection",
            "XPath Injection",
            "Command Injection / OS Injection",
            "Server-Side Template Injection (SSTI)",
            "XML External Entity (XXE) Injection",
            "HTTP Header / Response Splitting Injection",
        ],
    },
    {
        "name": "XSS & Client-Side Attacks",
        "categories": [
            "Reflected Cross-Site Scripting (XSS)",
            "Stored / Persistent XSS",
            "DOM-Based XSS",
            "JavaScript Injection",
            "HTML Injection",
            "CSS Injection",
            "Clickjacking / UI Redressing",
            "Content-Type Sniffing / MIME Confusion",
        ],
    },
    {
        "name": "Authentication & Session",
        "categories": [
            "Broken Authentication — Weak Password Policy",
            "Brute Force / Credential Stuffing — Missing Rate Limiting",
            "Session Fixation",
            "Session Hijacking — Cookie Security Flags",
            "Multi-Factor Authentication Bypass",
            "OAuth 2.0 / OpenID Connect Misconfiguration",
            "JWT Vulnerabilities (algorithm confusion, weak secret, none alg)",
            "Password Reset Flaws (token predictability, host header injection)",
            "Default or Hardcoded Credentials",
        ],
    },
    {
        "name": "Access Control & Business Logic",
        "categories": [
            "Broken Access Control — IDOR (Insecure Direct Object Reference)",
            "Horizontal Privilege Escalation",
            "Vertical Privilege Escalation",
            "Directory / Path Traversal",
            "Unrestricted File Upload",
            "Business Logic Flaws (price manipulation, workflow bypass)",
            "Mass Assignment / Parameter Pollution",
            "Server-Side Request Forgery (SSRF)",
            "Cross-Site Request Forgery (CSRF)",
            "Open Redirect",
        ],
    },
    {
        "name": "Transport, Headers & Crypto",
        "categories": [
            "HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)",
            "TLS/SSL Configuration (protocol version, cipher suites, certificate)",
            "Cookie Security (Secure, HttpOnly, SameSite, __Host- prefix)",
            "CORS Misconfiguration",
            "Cache-Control & Sensitive Data Caching",
            "Mixed Content (HTTP resources on HTTPS page)",
            "HTTP/2 Request Smuggling",
            "Insecure Deserialization",
            "Cryptographic Failures — Weak Hashing / Encryption",
        ],
    },
    {
        "name": "Information Disclosure & Infrastructure",
        "categories": [
            "Sensitive Data Exposure (PII, credentials, API keys in responses)",
            "Error Message / Stack Trace Information Disclosure",
            "Directory Listing Enabled",
            "Backup / Temp File Exposure (.bak, .old, .swp, .git)",
            "Source Code Disclosure",
            "Server / Technology Version Fingerprinting",
            "Using Components with Known Vulnerabilities (CVEs)",
            "Security Misconfiguration (admin panels, debug endpoints)",
            "Insufficient Logging & Monitoring",
            "API Security (GraphQL introspection, REST over-fetching, lack of versioning)",
            "DNS / Subdomain Takeover",
            "Dependency Confusion / Supply Chain Risk",
        ],
    },
]

# Flat list for display purposes
VULNERABILITY_CATEGORIES = [cat for batch in VULN_BATCHES for cat in batch["categories"]]

# ---------------------------------------------------------------------------
# Mock data for demo mode
# ---------------------------------------------------------------------------

MOCK_APPSEC_RESULTS = {
    "target_url": "https://demo-app.example.com",
    "scan_date": "2026-03-19T10:00:00",
    "risk_score": 78,
    "findings_count": {"critical": 2, "high": 4, "medium": 4, "low": 2, "info": 2},
    "findings": [
        {
            "id": 1,
            "category": "Cookie Security",
            "severity": "CRITICAL",
            "affected_url": "https://demo-app.example.com/login",
            "observations": "Session cookie 'SESSIONID' is set without HttpOnly flag, Secure flag, or SameSite attribute. Cookie is transmitted over plain HTTP alongside HTTPS.",
            "business_risk": "Session tokens can be stolen via JavaScript (XSS) or network interception, enabling full account takeover for any user including administrators. This represents a direct path to data breach.",
            "impact": "Complete account compromise through session hijacking. An attacker who steals a session token gains full access to the victim's account without needing credentials.",
            "recommendations": "Set HttpOnly, Secure, and SameSite=Strict on all session cookies. Enforce HTTPS-only cookie transmission. Implement cookie prefixes (__Host- or __Secure-). Regenerate session ID after authentication.",
            "standards_mapping": "OWASP Top 10 A07:2021 Identification and Authentication Failures, NIST SP 800-63B Section 7.1, PCI DSS Requirement 6.4.3, CIS Controls v8 Control 16.9",
            "cwe_mapping": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute; CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        },
        {
            "id": 2,
            "category": "HTTP Security Headers",
            "severity": "HIGH",
            "affected_url": "https://demo-app.example.com",
            "observations": "Missing security headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy. Server header exposes version: Apache/2.4.41 (Ubuntu).",
            "business_risk": "Absent security headers expose users to clickjacking, MIME-type confusion attacks, and XSS. Version disclosure aids attackers in targeting known CVEs for the exposed software version.",
            "impact": "Attackers can embed the application in malicious iframes (clickjacking), execute MIME-type attacks, and leverage known CVEs against the disclosed Apache 2.4.41 version.",
            "recommendations": "Add Content-Security-Policy with strict-src directives. Set X-Frame-Options: DENY. Enable HSTS with max-age=31536000; includeSubDomains; preload. Remove or mask Server header. Add X-Content-Type-Options: nosniff.",
            "standards_mapping": "OWASP Top 10 A05:2021 Security Misconfiguration, NIST SP 800-53 SI-10, ISO 27001 A.14.1.2, CIS Controls v8 Control 16.1",
            "cwe_mapping": "CWE-693: Protection Mechanism Failure; CWE-116: Improper Encoding or Escaping of Output",
        },
        {
            "id": 3,
            "category": "SQL Injection",
            "severity": "CRITICAL",
            "affected_url": "https://demo-app.example.com/search?q=",
            "observations": "PHP/MySQL tech stack with unparameterized query patterns inferred from error responses. URL parameter 'q' reflects unsanitized input in response body. Database errors visible under anomalous input.",
            "business_risk": "Successful SQL injection allows attackers to dump the entire database, extract credentials, bypass authentication, and potentially execute OS commands — constituting a full system compromise.",
            "impact": "Complete database exfiltration, authentication bypass, potential remote code execution via INTO OUTFILE or xp_cmdshell. Regulatory breach notification required if PII is exposed.",
            "recommendations": "Use parameterized queries / prepared statements exclusively. Implement input validation at all entry points. Apply principle of least privilege for DB accounts. Deploy a WAF with SQL injection signatures. Suppress all database error messages in production.",
            "standards_mapping": "OWASP Top 10 A03:2021 Injection, NIST SP 800-53 SI-10, PCI DSS Requirement 6.3.1, ISO 27001 A.14.2.5",
            "cwe_mapping": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        },
        {
            "id": 4,
            "category": "Cross-Site Scripting (XSS) — Reflected, Stored, DOM",
            "severity": "HIGH",
            "affected_url": "https://demo-app.example.com/search",
            "observations": "Search parameter value is reflected in response without HTML encoding. No Content-Security-Policy header present. Response Content-Type is text/html. User-supplied input rendered in multiple DOM locations.",
            "business_risk": "XSS enables session token theft, credential harvesting, malicious redirects, and defacement — damaging user trust and creating regulatory liability.",
            "impact": "Attacker can steal session cookies, perform actions on behalf of victims, redirect to phishing pages, or install persistent malware in the browser.",
            "recommendations": "HTML-encode all user input before rendering. Implement a strict Content-Security-Policy. Use modern templating frameworks with auto-escaping. Validate and sanitize input server-side. Deploy DOM-based XSS protections.",
            "standards_mapping": "OWASP Top 10 A03:2021 Injection, NIST SP 800-53 SI-10, ISO 27001 A.14.2.5, CIS Controls v8 Control 16.1",
            "cwe_mapping": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        },
        {
            "id": 5,
            "category": "CORS Misconfiguration",
            "severity": "MEDIUM",
            "affected_url": "https://demo-app.example.com/api/",
            "observations": "Access-Control-Allow-Origin: * present on API endpoints. No Access-Control-Allow-Credentials restriction enforced. Any origin can make cross-origin requests.",
            "business_risk": "Overly permissive CORS allows malicious websites to make authenticated API requests on behalf of logged-in users, potentially leaking sensitive data.",
            "impact": "Cross-origin data theft. Malicious sites can silently read API responses containing user data when victims visit attacker-controlled pages.",
            "recommendations": "Replace wildcard CORS with explicit allowed origins. Set Access-Control-Allow-Credentials: false for public APIs. Validate Origin header server-side against an allowlist.",
            "standards_mapping": "OWASP Top 10 A05:2021 Security Misconfiguration, NIST SP 800-53 AC-3, ISO 27001 A.14.1.3",
            "cwe_mapping": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        },
        {
            "id": 6,
            "category": "Insufficient Logging & Monitoring",
            "severity": "MEDIUM",
            "affected_url": "https://demo-app.example.com",
            "observations": "No observable rate-limiting on login endpoint. No CAPTCHA or account lockout detected after repeated failed authentication attempts. No security event logging headers (e.g., Report-To, NEL) present.",
            "business_risk": "Without adequate logging and monitoring, attacks may go undetected for extended periods, increasing dwell time and data exfiltration windows.",
            "impact": "Brute-force attacks against user accounts can proceed undetected. Attacker dwell time after initial compromise is extended due to absence of anomaly detection.",
            "recommendations": "Implement account lockout after 5 failed attempts. Deploy CAPTCHA on login. Enable centralized security logging with SIEM integration. Set up alerting for anomalous authentication patterns.",
            "standards_mapping": "OWASP Top 10 A09:2021 Security Logging and Monitoring Failures, NIST SP 800-53 AU-2, ISO 27001 A.12.4.1, PCI DSS Requirement 10.2",
            "cwe_mapping": "CWE-778: Insufficient Logging; CWE-307: Improper Restriction of Excessive Authentication Attempts",
        },
        {
            "id": 7,
            "category": "TLS/SSL Configuration",
            "severity": "MEDIUM",
            "affected_url": "https://demo-app.example.com",
            "observations": "HTTP to HTTPS redirect is in place but HSTS header is absent. TLS version support not directly observable but Apache 2.4.41 default config may support TLS 1.0/1.1.",
            "business_risk": "Without HSTS, browsers may connect via HTTP on first visit, enabling SSL-stripping attacks. Legacy TLS versions expose users to known protocol-level attacks (POODLE, BEAST).",
            "impact": "Man-in-the-middle attackers on the same network can downgrade connections from HTTPS to HTTP (SSL stripping), intercepting credentials and session tokens.",
            "recommendations": "Enable HSTS with max-age=31536000; includeSubDomains; preload. Submit to HSTS preload list. Disable TLS 1.0 and 1.1. Configure TLS 1.2/1.3 only. Use strong cipher suites (ECDHE + AES-GCM).",
            "standards_mapping": "OWASP Top 10 A02:2021 Cryptographic Failures, NIST SP 800-52r2, PCI DSS Requirement 4.1, ISO 27001 A.10.1.1",
            "cwe_mapping": "CWE-319: Cleartext Transmission of Sensitive Information; CWE-326: Inadequate Encryption Strength",
        },
        {
            "id": 8,
            "category": "Rate Limiting & Brute Force Protection",
            "severity": "HIGH",
            "affected_url": "https://demo-app.example.com/login",
            "observations": "Login endpoint does not return rate-limiting headers (X-RateLimit-*, Retry-After). No CAPTCHA challenge observed. Repeated requests return identical responses without throttling.",
            "business_risk": "Unrestricted login attempts enable credential stuffing and password spraying attacks against user accounts, leading to unauthorized access and data breach.",
            "impact": "Attackers can systematically test millions of username/password combinations against user accounts with no imposed delay or lockout mechanism.",
            "recommendations": "Implement account lockout after 5 failed attempts with exponential backoff. Deploy CAPTCHA (hCaptcha/reCAPTCHA) on login. Rate-limit by IP and account. Alert on >10 failed attempts per minute.",
            "standards_mapping": "OWASP Top 10 A07:2021 Identification and Authentication Failures, NIST SP 800-63B Section 5.2.2, CIS Controls v8 Control 6.2",
            "cwe_mapping": "CWE-307: Improper Restriction of Excessive Authentication Attempts; CWE-799: Improper Control of Interaction Frequency",
        },
        {
            "id": 9,
            "category": "Sensitive Data Exposure / Information Disclosure",
            "severity": "LOW",
            "affected_url": "https://demo-app.example.com/robots.txt",
            "observations": "robots.txt exposes internal path structure including admin panel paths (/admin/, /internal/, /backup/). Server header reveals exact software version. PHP version exposed via X-Powered-By header.",
            "business_risk": "Exposed directory structure and technology versions accelerate attacker reconnaissance, reducing time needed to identify and exploit targeted vulnerabilities.",
            "impact": "Attackers gain knowledge of administrative interface locations and can target known CVEs for exposed software versions without extensive probing.",
            "recommendations": "Remove sensitive paths from robots.txt — it is not a security control. Strip Server and X-Powered-By headers. Implement a robots.txt that only lists intended crawl paths.",
            "standards_mapping": "OWASP Top 10 A05:2021 Security Misconfiguration, NIST SP 800-53 CM-7, ISO 27001 A.13.1.3",
            "cwe_mapping": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor; CWE-16: Configuration",
        },
        {
            "id": 10,
            "category": "Content-Type Sniffing",
            "severity": "LOW",
            "affected_url": "https://demo-app.example.com",
            "observations": "X-Content-Type-Options header is absent. Some responses use incorrect or generic Content-Type values. Browser MIME-type sniffing is active.",
            "business_risk": "MIME-type sniffing allows browsers to execute uploaded files as scripts even when served with a non-executable Content-Type, enabling file upload XSS attacks.",
            "impact": "If file upload functionality exists, an attacker can upload a file with a .jpg extension containing HTML/JavaScript that the browser executes as a script.",
            "recommendations": "Add X-Content-Type-Options: nosniff to all responses. Serve all resources with correct, explicit Content-Type headers. Validate file types server-side on upload.",
            "standards_mapping": "OWASP Top 10 A05:2021 Security Misconfiguration, NIST SP 800-53 SI-3, CIS Controls v8 Control 10.1",
            "cwe_mapping": "CWE-430: Deployment of Wrong Handler; CWE-436: Interpretation Conflict",
        },
    ],
    "executive_summary": (
        "The application security assessment of demo-app.example.com identified 14 vulnerabilities across 10 categories, "
        "with 2 critical issues requiring immediate remediation. The most severe findings — insecure session cookie configuration "
        "and a SQL injection vector — represent direct paths to full account compromise and database exfiltration respectively.\n\n"
        "Key vulnerability clusters include absent HTTP security headers, missing rate limiting on the authentication endpoint, "
        "overly permissive CORS configuration on API endpoints, and information disclosure via server version headers. Together, "
        "these create a compounded attack surface that allows attackers to chain low-severity issues into high-impact exploits.\n\n"
        "Recommended remediation priority: (1) Fix cookie security flags and SQL injection within 7 days, (2) Implement security "
        "headers and rate limiting within 30 days, (3) Address CORS and TLS configuration within 60 days. A follow-up scan "
        "should be scheduled after remediation to verify closure of all critical and high findings."
    ),
    "tech_stack": {"server": "Apache/2.4.41", "language": "PHP", "cms": "WordPress 6.1"},
}


# ---------------------------------------------------------------------------
# Main Scanner Class
# ---------------------------------------------------------------------------

class AppSecScanner:
    """
    Application Security Tester.
    Probes HTTP responses and uses Claude AI to generate structured security findings.
    """

    def __init__(self, target_url: str, authorization_token: str, scan_depth: str = "standard"):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc
        self.authorization_token = authorization_token
        self.scan_depth = scan_depth
        self.ai_client = PhantomAI()
        self.progress_log = []
        self.progress = 0

    def _log(self, message: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
        }
        self.progress_log.append(entry)
        print(f"[AppSecScanner][{level}] {message}")

    def run_full_scan(self) -> dict:
        self._log(f"Starting application security scan: {self.target_url}")
        self.progress = 5

        results = {
            "target_url": self.target_url,
            "domain": self.domain,
            "scan_date": datetime.utcnow().isoformat(),
            "scan_depth": self.scan_depth,
            "risk_score": 0,
            "findings": [],
            "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "tech_stack": {},
            "http_probe": {},
            "executive_summary": "",
            "progress_log": self.progress_log,
        }

        # Phase 1: HTTP Probe
        self._log("Phase 1: Probing HTTP response, headers, cookies, and redirects...")
        self.progress = 15
        http_data = self._probe_http()
        results["http_probe"] = http_data
        results["tech_stack"] = http_data.get("tech_stack", {})

        if http_data.get("error"):
            self._log(f"HTTP probe warning: {http_data['error']}", "WARNING")
        else:
            self._log(
                f"HTTP probe complete. Status: {http_data.get('status_code', 'N/A')} | "
                f"Cookies: {len(http_data.get('cookies', []))} | "
                f"Server: {http_data.get('tech_stack', {}).get('server', 'unknown')}",
                "SUCCESS"
            )

        self.progress = 35

        # Phase 2: Claude AI security analysis — one call per vulnerability batch
        self._log(f"Phase 2: Running {len(VULN_BATCHES)} targeted vulnerability batch scans...")
        all_findings = []
        batch_progress_start = 35
        batch_progress_range = 55  # 35% → 90%
        for i, batch in enumerate(VULN_BATCHES):
            self._log(f"  Batch {i+1}/{len(VULN_BATCHES)}: {batch['name']}...")
            batch_findings = self._ai_analyze_batch(http_data, batch, len(all_findings))
            all_findings.extend(batch_findings)
            self.progress = batch_progress_start + int((i + 1) / len(VULN_BATCHES) * batch_progress_range)
            self._log(f"  Batch {i+1} complete — {len(batch_findings)} findings", "SUCCESS")

        results["findings"] = all_findings
        self.progress = 90
        self._log(f"All batches complete. Total findings: {len(all_findings)}.", "SUCCESS")

        # Phase 3: Severity counts & risk score
        self._log("Phase 3: Calculating risk score...")
        self.progress = 85
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "INFO").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            else:
                sev_counts["info"] += 1
        results["findings_count"] = sev_counts
        results["risk_score"] = self._calculate_risk_score(sev_counts)
        self._log(f"Risk score: {results['risk_score']}/100", "SUCCESS")

        # Phase 4: Executive summary
        self._log("Phase 4: Generating executive summary...")
        self.progress = 93
        results["executive_summary"] = self._generate_executive_summary(results)

        self.progress = 100
        self._log("Application security scan complete.", "SUCCESS")
        return results

    def _probe_http(self) -> dict:
        """Make real HTTP request and collect observable security data."""
        probe = {
            "status_code": None,
            "headers": {},
            "cookies": [],
            "redirects": [],
            "final_url": self.target_url,
            "tech_stack": {},
            "error": None,
        }

        if not REQUESTS_AVAILABLE:
            probe["error"] = "requests library not available — using AI analysis without live probe"
            return probe

        try:
            session = requests.Session()
            resp = session.get(
                self.target_url,
                timeout=15,
                verify=True,
                allow_redirects=True,
                headers={
                    "User-Agent": "PhantomAI-AppSec/1.0 (Authorized Security Assessment)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )

            probe["status_code"] = resp.status_code
            probe["headers"] = dict(resp.headers)
            probe["final_url"] = resp.url

            if resp.history:
                probe["redirects"] = [
                    {"url": r.url, "status": r.status_code} for r in resp.history
                ]

            # Cookies — inspect security attributes
            for cookie in session.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": bool(cookie.secure),
                    "http_only": "httponly" in str(cookie._rest).lower() if hasattr(cookie, "_rest") else False,
                    "same_site": None,
                    "domain": cookie.domain,
                    "path": cookie.path,
                }
                if hasattr(cookie, "_rest") and cookie._rest:
                    for key, val in cookie._rest.items():
                        if key.lower() == "samesite":
                            cookie_info["same_site"] = val
                        if key.lower() == "httponly":
                            cookie_info["http_only"] = True
                probe["cookies"].append(cookie_info)

            # Tech stack detection
            tech_stack = {}
            server = resp.headers.get("Server", "")
            if server:
                tech_stack["server"] = server
            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                tech_stack["powered_by"] = x_powered

            body_lower = resp.text[:8000].lower()
            if "wp-content" in body_lower or "wordpress" in body_lower:
                tech_stack["cms"] = "WordPress"
            elif "drupal" in body_lower:
                tech_stack["cms"] = "Drupal"
            elif "joomla" in body_lower:
                tech_stack["cms"] = "Joomla"

            if "laravel" in body_lower:
                tech_stack["framework"] = "Laravel (PHP)"
            elif "django" in body_lower:
                tech_stack["framework"] = "Django (Python)"
            elif "__rails" in body_lower:
                tech_stack["framework"] = "Ruby on Rails"
            elif "asp.net" in body_lower or ".aspx" in body_lower:
                tech_stack["framework"] = "ASP.NET"
            elif "spring" in body_lower:
                tech_stack["framework"] = "Spring (Java)"
            elif "express" in body_lower:
                tech_stack["framework"] = "Express.js (Node)"

            if "react" in body_lower or "__next" in body_lower:
                tech_stack["frontend"] = "React/Next.js"
            elif "angular" in body_lower:
                tech_stack["frontend"] = "Angular"
            elif "vue" in body_lower:
                tech_stack["frontend"] = "Vue.js"

            probe["tech_stack"] = tech_stack

        except requests.exceptions.SSLError as e:
            probe["error"] = f"SSL/TLS error: {e}"
        except requests.exceptions.ConnectionError as e:
            probe["error"] = f"Connection failed: {e}"
        except requests.exceptions.Timeout:
            probe["error"] = "Request timed out after 15 seconds"
        except Exception as e:
            probe["error"] = f"Probe error: {e}"

        return probe

    def _build_context(self, http_data: dict) -> str:
        """Build the shared probe context string for all batch prompts."""
        headers_str = "\n".join(
            f"  {k}: {v}" for k, v in http_data.get("headers", {}).items()
        ) or "  (no headers captured)"

        cookies_str = "\n".join(
            "  {} — secure={}, httponly={}, samesite={}".format(
                c["name"], c["secure"], c["http_only"], c["same_site"] or "not set"
            )
            for c in http_data.get("cookies", [])
        ) or "  (no cookies observed in response)"

        tech_str = ", ".join(
            f"{k}: {v}" for k, v in http_data.get("tech_stack", {}).items()
        ) or "unknown"

        redirects_str = " → ".join(
            f"{r['url']} [{r['status']}]" for r in http_data.get("redirects", [])
        ) or "none"

        error_note = ""
        if http_data.get("error"):
            error_note = (
                f"\nNote: HTTP probe error: {http_data['error']}. "
                "Infer findings from URL structure, tech stack, and common patterns."
            )

        return (
            f"Target: {self.target_url}\n"
            f"HTTP Status: {http_data.get('status_code', 'N/A')}\n"
            f"Final URL: {http_data.get('final_url', self.target_url)}\n"
            f"Tech Stack: {tech_str}\n"
            f"Redirect Chain: {redirects_str}"
            f"{error_note}\n\n"
            f"HTTP Response Headers Observed:\n{headers_str}\n\n"
            f"Cookies in Response:\n{cookies_str}"
        )

    def _ai_analyze_batch(self, http_data: dict, batch: dict, id_offset: int) -> list:
        """
        Run one Claude call for a specific vulnerability batch.
        Returns a list of finding dicts, IDs starting from id_offset+1.
        """
        context = self._build_context(http_data)
        categories_str = "\n".join(f"  {i+1}. {cat}" for i, cat in enumerate(batch["categories"]))

        # Depth controls detail level, not finding count
        detail = {
            "deep":     "Extremely detailed — multiple sub-variants per category where applicable. Generate a separate finding for each distinct sub-vulnerability.",
            "standard": "Detailed — one thorough finding per applicable category.",
            "stealth":  "Concise — one finding per category, shorter observations.",
        }.get(self.scan_depth, "Detailed — one thorough finding per applicable category.")

        prompt = f"""You are a senior application security penetration tester conducting an authorized assessment.

{context}

TASK: Assess the target for the following vulnerability group: {batch['name']}

Test EVERY category below and generate a finding for each one that applies:
{categories_str}

For categories you cannot directly observe (e.g. SQL injection without live testing), base your finding on:
- Tech stack clues (framework, CMS, server version)
- URL structure and parameter patterns
- Presence/absence of protective headers or tokens
- Common vulnerability patterns for the detected stack
- Mark the finding observations as "Inferred from tech stack" where appropriate

Detail level: {detail}

Format: Return a JSON array. Each finding object has EXACTLY these fields:
{{
  "id": <integer starting from {id_offset + 1}>,
  "category": "<exact category name from the list above>",
  "severity": "<CRITICAL | HIGH | MEDIUM | LOW | INFO>",
  "affected_url": "<specific URL, endpoint, header, or component>",
  "observations": "<what was observed or technically inferred — be specific, cite actual header names/values/cookie flags>",
  "business_risk": "<business consequence: data breach, compliance penalty, reputational damage, financial loss>",
  "impact": "<technical impact: what an attacker achieves — be precise>",
  "recommendations": "<numbered actionable steps with specific config/code examples>",
  "standards_mapping": "<OWASP Top 10 A0X:YEAR, NIST SP 800-53 control, PCI DSS requirement, ISO 27001 annex, CIS Controls>",
  "cwe_mapping": "<CWE-ID: Full CWE Name>"
}}

Rules:
- Generate a finding for EVERY category in the list — mark as INFO if no evidence of vulnerability
- Do NOT skip any category
- Severity: CRITICAL=exploitable immediately with high impact, HIGH=significant risk, MEDIUM=moderate, LOW=minor, INFO=no evidence of issue
- Respond with ONLY the JSON array. No markdown fences, no text before or after.
"""

        response = self.ai_client.analyze(prompt)

        try:
            clean = response.strip()
            clean = re.sub(r"^```(?:json)?\s*", "", clean)
            clean = re.sub(r"\s*```$", "", clean)
            match = re.search(r"\[[\s\S]*\]", clean)
            if match:
                findings = json.loads(match.group())
                if isinstance(findings, list):
                    # Renumber IDs sequentially
                    for i, f in enumerate(findings):
                        f["id"] = id_offset + i + 1
                    return findings
        except Exception as e:
            self._log(f"JSON parse error in batch '{batch['name']}': {e}", "WARNING")

        # Fallback: generate placeholder findings for this batch
        return [
            {
                "id": id_offset + i + 1,
                "category": cat,
                "severity": "INFO",
                "affected_url": self.target_url,
                "observations": "Analysis unavailable for this batch — API error or parse failure.",
                "business_risk": "Unknown — manual review required.",
                "impact": "Unknown — manual review required.",
                "recommendations": "Perform manual testing for this vulnerability category.",
                "standards_mapping": "See OWASP Testing Guide for this category.",
                "cwe_mapping": "See OWASP/CWE reference for this category.",
            }
            for i, cat in enumerate(batch["categories"])
        ]

    def _calculate_risk_score(self, sev_counts: dict) -> int:
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        score = sum(weights.get(sev, 0) * count for sev, count in sev_counts.items())
        return min(score, 100)

    def _generate_executive_summary(self, results: dict) -> str:
        counts = results["findings_count"]
        total = sum(counts.values())
        risk = results["risk_score"]
        tech = results.get("tech_stack", {})

        top_findings = [
            f['category'] for f in results.get('findings', [])
            if f.get('severity') in ('CRITICAL', 'HIGH')
        ][:5]

        prompt = f"""Write a 3-paragraph executive summary for an application security assessment report.

Target Application: {results['target_url']}
Overall Risk Score: {risk}/100
Total Findings: {total} ({counts.get('critical', 0)} Critical, {counts.get('high', 0)} High, {counts.get('medium', 0)} Medium, {counts.get('low', 0)} Low, {counts.get('info', 0)} Informational)
Technology Stack: {tech}
Critical/High Findings: {', '.join(top_findings) if top_findings else 'See findings list'}

Paragraph 1: Overall risk posture, most critical finding, and immediate action required
Paragraph 2: Key vulnerability patterns discovered across the application and their business implications
Paragraph 3: Prioritized remediation roadmap with 7-day, 30-day, and 90-day milestones

Write in professional CISO/board-level language. Be direct, action-oriented, and specific.
Do not use markdown formatting. Plain text only."""

        return self.ai_client.analyze(prompt)
