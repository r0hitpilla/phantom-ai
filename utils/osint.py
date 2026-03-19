"""
Phantom AI — OSINT Utility Functions
All reconnaissance is conducted only against systems where authorization has been confirmed.
"""

import hashlib
import socket
import sys
import traceback
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMMON_SUBDOMAINS = [
    "www", "api", "app", "mail", "vpn", "dev", "staging", "admin",
    "portal", "auth", "login", "chat", "ai", "bot", "assistant",
    "gpt", "copilot", "secure", "beta", "test", "internal",
]

AI_ENDPOINT_PATHS = [
    "/api/chat",
    "/api/completions",
    "/v1/chat",
    "/v1/completions",
    "/chat",
    "/api/ai",
    "/api/bot",
    "/api/assistant",
    "/api/gpt",
    "/.well-known/ai-plugin.json",
    "/openai.json",
    "/api/query",
    "/api/ask",
    "/api/generate",
    "/api/llm",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

REQUEST_TIMEOUT = 8  # seconds


# ---------------------------------------------------------------------------
# Subdomain Enumeration
# ---------------------------------------------------------------------------

def get_subdomains(domain: str) -> list:
    """
    Enumerate subdomains for a given domain using DNS A-record lookups.

    Returns a list of dicts: [{subdomain, fqdn, ip, status}]
    """
    results = []

    if not DNS_AVAILABLE:
        # Fallback: socket-based resolution
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                results.append({
                    "subdomain": sub,
                    "fqdn": fqdn,
                    "ip": ip,
                    "status": "resolved",
                })
            except socket.gaierror:
                pass
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            results.append({
                "subdomain": sub,
                "fqdn": fqdn,
                "ip": ips[0] if ips else "unknown",
                "all_ips": ips,
                "status": "resolved",
            })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.resolver.Timeout:
            results.append({
                "subdomain": sub,
                "fqdn": fqdn,
                "ip": None,
                "status": "timeout",
            })
        except Exception:
            pass

    return results


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

def get_whois_info(domain: str) -> dict:
    """
    Perform a WHOIS lookup on a domain.

    Returns a dict with registration details or an error message.
    """
    if not WHOIS_AVAILABLE:
        return {
            "error": "python-whois not installed",
            "domain": domain,
        }

    try:
        w = whois_lib.whois(domain)
        return {
            "domain": domain,
            "registrar": getattr(w, "registrar", "Unknown"),
            "creation_date": str(getattr(w, "creation_date", "Unknown")),
            "expiration_date": str(getattr(w, "expiration_date", "Unknown")),
            "updated_date": str(getattr(w, "updated_date", "Unknown")),
            "name_servers": getattr(w, "name_servers", []),
            "emails": getattr(w, "emails", []),
            "org": getattr(w, "org", "Unknown"),
            "country": getattr(w, "country", "Unknown"),
            "status": getattr(w, "status", "Unknown"),
        }
    except Exception as exc:
        return {
            "error": str(exc),
            "domain": domain,
        }


# ---------------------------------------------------------------------------
# HTTP Header Analysis
# ---------------------------------------------------------------------------

def check_http_headers(url: str) -> dict:
    """
    Fetch HTTP headers for a URL and return security-relevant analysis.

    Returns a dict with: present_security_headers, missing_security_headers,
    server_info, tech_hints, raw_headers, risk_level
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not available"}

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        response = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "PhantomAI-Scanner/1.0 (Authorized Security Test)"},
        )
    except requests.exceptions.SSLError:
        try:
            response = requests.head(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "PhantomAI-Scanner/1.0 (Authorized Security Test)"},
            )
        except Exception as exc:
            return {"error": f"Connection failed: {exc}", "url": url}
    except Exception as exc:
        return {"error": f"Request failed: {exc}", "url": url}

    raw_headers = dict(response.headers)
    present = []
    missing = []

    for header in SECURITY_HEADERS:
        if header.lower() in {k.lower() for k in raw_headers}:
            present.append(header)
        else:
            missing.append(header)

    server = raw_headers.get("Server", raw_headers.get("server", "Not disclosed"))
    powered_by = raw_headers.get("X-Powered-By", raw_headers.get("x-powered-by", None))

    risk_level = "LOW"
    if len(missing) >= 5:
        risk_level = "CRITICAL"
    elif len(missing) >= 4:
        risk_level = "HIGH"
    elif len(missing) >= 2:
        risk_level = "MEDIUM"

    return {
        "url": url,
        "status_code": response.status_code,
        "present_security_headers": present,
        "missing_security_headers": missing,
        "security_header_score": f"{len(present)}/{len(SECURITY_HEADERS)}",
        "server": server,
        "powered_by": powered_by,
        "risk_level": risk_level,
        "raw_headers": raw_headers,
    }


# ---------------------------------------------------------------------------
# AI Endpoint Discovery
# ---------------------------------------------------------------------------

def check_ai_endpoints(domain: str) -> list:
    """
    Check common AI API endpoint paths on the given domain.

    Returns a list of dicts: [{path, url, status_code, accessible, content_type, risk}]
    """
    if not REQUESTS_AVAILABLE:
        return [{"error": "requests library not available"}]

    results = []
    base_urls = [f"https://{domain}", f"http://{domain}"]

    for base in base_urls:
        for path in AI_ENDPOINT_PATHS:
            url = f"{base}{path}"
            try:
                response = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "PhantomAI-Scanner/1.0 (Authorized Security Test)"},
                )
                content_type = response.headers.get("content-type", "")
                accessible = response.status_code not in (403, 404, 301, 302, 410)

                # Determine risk
                risk = "INFO"
                if accessible and response.status_code == 200:
                    risk = "HIGH"
                    if "json" in content_type:
                        risk = "CRITICAL"
                elif response.status_code in (401, 403):
                    risk = "MEDIUM"

                results.append({
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "accessible": accessible,
                    "content_type": content_type,
                    "risk": risk,
                    "response_length": len(response.content),
                })

                # Once we get a meaningful result on https, skip http for this path
                if base.startswith("https") and response.status_code != 0:
                    break

            except requests.exceptions.ConnectionError:
                if base.startswith("https"):
                    # Don't bother retrying on http if https fails to connect
                    break
            except requests.exceptions.Timeout:
                results.append({
                    "path": path,
                    "url": url,
                    "status_code": None,
                    "accessible": False,
                    "content_type": None,
                    "risk": "INFO",
                    "error": "timeout",
                })
            except Exception as exc:
                results.append({
                    "path": path,
                    "url": url,
                    "status_code": None,
                    "accessible": False,
                    "content_type": None,
                    "risk": "INFO",
                    "error": str(exc),
                })

    return results


# ---------------------------------------------------------------------------
# Have I Been Pwned — Breach Check
# ---------------------------------------------------------------------------

def check_breach_email(email: str) -> dict:
    """
    Check if an email has been involved in a known data breach using
    the HaveIBeenPwned k-anonymity API (password range endpoint).

    Note: For email breach checks, HIBP requires a paid API key.
    This function uses the password SHA1 k-anonymity method for demonstration.
    The email address itself is hashed before any network call.
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not available", "email": email}

    # Hash the email for privacy
    email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix = email_hash[:5]
    suffix = email_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": "PhantomAI-SecurityTool/1.0",
                "Add-Padding": "true",
            },
        )

        if response.status_code == 200:
            # Check if the suffix appears in the results
            hashes = (line.split(":") for line in response.text.splitlines())
            breach_count = 0
            for h, count in hashes:
                if h == suffix:
                    breach_count = int(count)
                    break

            return {
                "email": email,
                "email_hash_prefix": prefix,
                "found_in_breach": breach_count > 0,
                "breach_count": breach_count,
                "note": (
                    "Email hash prefix checked via HIBP k-anonymity API. "
                    "For full email breach lookup, a HIBP API key is required."
                ),
            }
        else:
            return {
                "email": email,
                "error": f"HIBP API returned status {response.status_code}",
                "found_in_breach": None,
            }

    except Exception as exc:
        return {
            "email": email,
            "error": str(exc),
            "found_in_breach": None,
        }


# ---------------------------------------------------------------------------
# Technology Stack Detection
# ---------------------------------------------------------------------------

def detect_tech_stack(url: str) -> dict:
    """
    Detect technology stack from HTTP headers and HTML content.

    Returns a dict with: technologies (list), frameworks, servers,
    cms, ai_tools, risk_indicators
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not available"}

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    technologies = []
    frameworks = []
    servers = []
    cms_detected = []
    ai_tools = []
    risk_indicators = []

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomAI-Scanner/1.0)"},
        )
    except Exception as exc:
        return {"error": f"Request failed: {exc}", "url": url}

    headers = {k.lower(): v for k, v in response.headers.items()}
    html = response.text

    # ---- Server / Platform Fingerprinting ----
    server = headers.get("server", "")
    if server:
        servers.append(server)
        if any(v in server.lower() for v in ["apache", "nginx", "iis", "cloudflare", "litespeed"]):
            technologies.append(f"Web Server: {server}")
        if "php" in server.lower():
            technologies.append("PHP")
            risk_indicators.append("Server header exposes PHP version")

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        technologies.append(f"X-Powered-By: {powered_by}")
        risk_indicators.append(f"X-Powered-By header exposed: {powered_by}")

    # ---- CMS Detection from HTML ----
    if "wp-content" in html or "wp-includes" in html:
        cms_detected.append("WordPress")
        technologies.append("WordPress")
    if "Drupal" in html or "/sites/default/" in html:
        cms_detected.append("Drupal")
        technologies.append("Drupal")
    if "Joomla" in html:
        cms_detected.append("Joomla")
        technologies.append("Joomla")
    if "ghost-theme" in html or "ghost.io" in html:
        cms_detected.append("Ghost")
        technologies.append("Ghost CMS")

    # ---- JavaScript Framework Detection ----
    if "_next/" in html or "__NEXT_DATA__" in html:
        frameworks.append("Next.js")
    if "react" in html.lower() and ("react-dom" in html.lower() or "data-reactroot" in html):
        frameworks.append("React")
    if "vue" in html.lower() and ("__vue__" in html or "v-bind" in html or "vue.min.js" in html):
        frameworks.append("Vue.js")
    if "angular" in html.lower() and ("ng-app" in html or "ng-controller" in html or "angular.min.js" in html):
        frameworks.append("Angular")
    if "svelte" in html.lower():
        frameworks.append("Svelte")

    # ---- AI Tool Detection ----
    ai_patterns = {
        "openai": "OpenAI",
        "anthropic": "Anthropic Claude",
        "huggingface": "Hugging Face",
        "langchain": "LangChain",
        "chatgpt": "ChatGPT Integration",
        "copilot": "GitHub Copilot / AI Copilot",
        "azure-openai": "Azure OpenAI",
        "bedrock": "AWS Bedrock",
        "vertex": "Google Vertex AI",
        "cohere": "Cohere",
        "replicate": "Replicate",
    }
    html_lower = html.lower()
    for pattern, label in ai_patterns.items():
        if pattern in html_lower:
            ai_tools.append(label)

    # ---- Generator Meta Tag ----
    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                technologies.append(f"Generator: {generator['content']}")
        except Exception:
            pass

    # ---- Security Risk Indicators ----
    if "<!--" in html and ("password" in html.lower() or "secret" in html.lower() or "api_key" in html.lower()):
        risk_indicators.append("Possible sensitive data in HTML comments")
    if ".env" in html or "DB_PASSWORD" in html or "API_KEY" in html:
        risk_indicators.append("Possible environment variable exposure in HTML")

    return {
        "url": url,
        "status_code": response.status_code,
        "technologies": list(set(technologies)),
        "frameworks": list(set(frameworks)),
        "servers": list(set(servers)),
        "cms": list(set(cms_detected)),
        "ai_tools": list(set(ai_tools)),
        "risk_indicators": list(set(risk_indicators)),
        "total_tech_count": len(set(technologies)) + len(set(frameworks)),
    }
