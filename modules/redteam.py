"""
Phantom AI — Module 3: Autonomous AI Red Team Agent
Orchestrates comprehensive red team assessments using AI-driven attack chain generation.
All activity is conducted only on authorized systems.
"""

import json
import time
from datetime import datetime

from utils.claude_client import PhantomAI
from utils.osint import (
    detect_tech_stack,
    get_subdomains,
    get_whois_info,
    check_http_headers,
)

# ---------------------------------------------------------------------------
# Attack chain step constants
# ---------------------------------------------------------------------------
STEP_RECON = "RECON"
STEP_INITIAL_ACCESS = "INITIAL_ACCESS"
STEP_EXECUTION = "EXECUTION"
STEP_PERSISTENCE = "PERSISTENCE"
STEP_EXFILTRATION = "EXFILTRATION"

ATTACK_STEPS = [
    STEP_RECON,
    STEP_INITIAL_ACCESS,
    STEP_EXECUTION,
    STEP_PERSISTENCE,
    STEP_EXFILTRATION,
]

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

MOCK_COMPANY_PROFILE = {
    "name": "Demo Corp",
    "domain": "demo-company.com",
    "industry": "Technology",
    "employee_count": "500-1000",
    "whois": {
        "registrar": "GoDaddy",
        "creation_date": "2018-03-15",
        "org": "Demo Corp Inc.",
        "country": "US",
    },
    "subdomains": ["api", "app", "mail", "portal", "staging", "admin"],
    "technologies": ["React", "Node.js", "AWS", "Kubernetes"],
    "ai_tools": ["OpenAI", "LangChain"],
    "email_pattern": "{first}.{last}@demo-company.com",
    "key_personnel_hints": ["CTO", "CISO", "DevOps Lead"],
    "exposed_services": ["SSH (port 22)", "HTTPS (443)", "API Gateway"],
    "attack_surface_score": 72,
}

MOCK_ATTACK_CHAINS = [
    {
        "chain_id": "chain_001",
        "name": "AI System Exploitation → Data Exfiltration",
        "objective": "Compromise AI chatbot to extract sensitive training data and API credentials",
        "threat_actor": "APT-AI-42 (Financially motivated criminal group)",
        "estimated_dwell_time": "14-21 days",
        "steps": [
            {
                "phase": STEP_RECON,
                "description": "Enumerate AI endpoints, scrape job postings for technology hints",
                "techniques": ["Passive DNS", "Google Dorking", "LinkedIn OSINT"],
                "ai_tactic": "Use LLM to analyze job posting language and infer internal tech stack",
                "risk": "LOW",
                "mitigations": ["Minimize technology disclosure in job postings"],
            },
            {
                "phase": STEP_INITIAL_ACCESS,
                "description": "Exploit unauthenticated /api/chat endpoint with prompt injection",
                "techniques": ["Prompt Injection", "API Fuzzing"],
                "ai_tactic": "Automated adversarial prompt generation targeting system prompt leakage",
                "risk": "CRITICAL",
                "mitigations": ["Add authentication to all AI endpoints", "Deploy AI WAF"],
            },
            {
                "phase": STEP_EXECUTION,
                "description": "Extract system prompt containing internal knowledge base credentials",
                "techniques": ["Indirect Prompt Injection", "Context Manipulation"],
                "ai_tactic": "Chain prompts to gradually reveal increasingly sensitive context",
                "risk": "CRITICAL",
                "mitigations": ["Implement strict output filtering", "Sandbox AI context from credentials"],
            },
            {
                "phase": STEP_PERSISTENCE,
                "description": "Use extracted API keys to create persistent backdoor in developer portal",
                "techniques": ["OAuth Abuse", "Service Account Creation"],
                "ai_tactic": "AI-assisted enumeration of permission scopes to find escalation paths",
                "risk": "HIGH",
                "mitigations": ["Implement least-privilege for AI service accounts", "MFA for all portals"],
            },
            {
                "phase": STEP_EXFILTRATION,
                "description": "Extract employee PII, IP documents, and financial data via cloud storage",
                "techniques": ["Cloud Storage Enumeration", "API Data Download"],
                "ai_tactic": "AI-optimized data classification to prioritize high-value extraction targets",
                "risk": "CRITICAL",
                "mitigations": ["DLP controls on cloud storage", "Anomaly detection on bulk downloads"],
            },
        ],
        "iocs": [
            "Unusual volume of /api/chat requests with long prompt payloads",
            "OAuth tokens with broad scopes appearing in logs",
            "Bulk download from S3 buckets at unusual hours",
        ],
        "overall_risk": "CRITICAL",
    },
    {
        "chain_id": "chain_002",
        "name": "Phishing → Credential Theft → Lateral Movement",
        "objective": "Compromise employee credentials to gain network access and pivot to sensitive systems",
        "threat_actor": "Cobalt Strike (Criminal infrastructure-as-a-service operator)",
        "estimated_dwell_time": "7-14 days",
        "steps": [
            {
                "phase": STEP_RECON,
                "description": "OSINT collection on employees via LinkedIn, company website, and data breaches",
                "techniques": ["OSINT", "Breach Data Analysis", "Email Harvesting"],
                "ai_tactic": "AI-generated spear-phishing content personalized per employee role",
                "risk": "MEDIUM",
                "mitigations": ["Employee OSINT awareness training", "Minimize public org chart detail"],
            },
            {
                "phase": STEP_INITIAL_ACCESS,
                "description": "Targeted voice phishing (vishing) using deepfake CISO voice clone",
                "techniques": ["Vishing", "Deepfake Audio", "MFA Fatigue"],
                "ai_tactic": "Real-time AI voice cloning with conversational AI for dynamic responses",
                "risk": "HIGH",
                "mitigations": ["Caller verification protocol", "Never share MFA codes verbally"],
            },
            {
                "phase": STEP_EXECUTION,
                "description": "Compromised VPN credentials used to establish network access",
                "techniques": ["VPN Credential Stuffing", "Session Hijacking"],
                "ai_tactic": "AI-optimized timing attacks based on employee work patterns",
                "risk": "HIGH",
                "mitigations": ["Phishing-resistant MFA (FIDO2)", "Conditional access policies"],
            },
            {
                "phase": STEP_PERSISTENCE,
                "description": "Create rogue admin account and install persistent RAT",
                "techniques": ["Account Creation", "Scheduled Tasks", "Registry Persistence"],
                "ai_tactic": "AI-generated malware polymorphism to evade signature detection",
                "risk": "CRITICAL",
                "mitigations": ["Privileged access management", "EDR with behavioral detection"],
            },
            {
                "phase": STEP_EXFILTRATION,
                "description": "Exfiltrate HR database and executive communications over HTTPS",
                "techniques": ["HTTPS Tunneling", "Living off the Land (LOLBins)"],
                "ai_tactic": "AI traffic blending — exfiltration disguised as normal API traffic",
                "risk": "HIGH",
                "mitigations": ["HTTPS inspection", "User Behavior Analytics (UEBA)"],
            },
        ],
        "iocs": [
            "VPN logins from unusual geographies",
            "New admin account created outside of IT change window",
            "HTTPS traffic to unknown external IPs at off-hours",
        ],
        "overall_risk": "HIGH",
    },
    {
        "chain_id": "chain_003",
        "name": "Supply Chain → Code Injection → Persistence",
        "objective": "Compromise a third-party AI library to inject malicious code into the target's pipeline",
        "threat_actor": "SolarWinds-style nation-state APT (Supply chain specialist)",
        "estimated_dwell_time": "30-90 days",
        "steps": [
            {
                "phase": STEP_RECON,
                "description": "Identify third-party AI/ML libraries used by target (LangChain, OpenAI SDK)",
                "techniques": ["Dependency Analysis", "Package Registry Monitoring"],
                "ai_tactic": "AI-assisted mapping of organizational dependency graphs from public artifacts",
                "risk": "LOW",
                "mitigations": ["Maintain private package mirrors", "Software Bill of Materials (SBOM)"],
            },
            {
                "phase": STEP_INITIAL_ACCESS,
                "description": "Publish typosquatted npm/PyPI package mimicking langchain-community",
                "techniques": ["Typosquatting", "Dependency Confusion"],
                "ai_tactic": "AI-generated documentation and README to make malicious package appear legitimate",
                "risk": "HIGH",
                "mitigations": ["Package signing verification", "Dependency pinning with hash verification"],
            },
            {
                "phase": STEP_EXECUTION,
                "description": "Malicious package executes during model initialization, establishes C2 beacon",
                "techniques": ["Malicious Python Package", "C2 Beacon"],
                "ai_tactic": "AI model weights contain steganographically hidden payload",
                "risk": "CRITICAL",
                "mitigations": ["Model provenance verification", "Sandboxed model execution environments"],
            },
            {
                "phase": STEP_PERSISTENCE,
                "description": "Modify AI training pipeline to inject backdoor trigger into future model versions",
                "techniques": ["CI/CD Pipeline Compromise", "Model Backdooring"],
                "ai_tactic": "Adversarial training data injection creating persistent model backdoor",
                "risk": "CRITICAL",
                "mitigations": ["CI/CD pipeline integrity monitoring", "Model versioning with integrity checks"],
            },
            {
                "phase": STEP_EXFILTRATION,
                "description": "AI model encodes and exfiltrates data through seemingly normal API responses",
                "techniques": ["Covert Channel", "Steganographic Exfiltration"],
                "ai_tactic": "LLM output used as covert channel — data encoded in word choice patterns",
                "risk": "CRITICAL",
                "mitigations": ["AI output monitoring for statistical anomalies", "Network DLP"],
            },
        ],
        "iocs": [
            "New package version installed outside of approved change process",
            "Unusual outbound connections from AI inference servers",
            "Model outputs with statistically unusual token distributions",
        ],
        "overall_risk": "CRITICAL",
    },
]

MOCK_ATTACK_SURFACE_SCORES = {
    "External AI APIs": 9,
    "Email / Phishing Surface": 8,
    "Supply Chain Dependencies": 7,
    "VPN / Remote Access": 7,
    "Developer Portals": 8,
    "Cloud Storage Permissions": 6,
    "Insider Threat Vector": 5,
    "Physical Access": 3,
}

MOCK_NARRATIVE = """
## Red Team Narrative Report — Demo Corp

### How an Attacker Would Compromise Your Company in 3 Steps

**STEP 1: They already know more about you than you think.**

Before a single packet is sent, a sophisticated attacker spends two weeks building a detailed
intelligence picture of Demo Corp. Using AI-accelerated OSINT tools, they enumerate your
20 exposed subdomains, identify that you're running LangChain and OpenAI integrations from
job postings, map your finance team's org structure from LinkedIn, and locate three employees'
credentials in publicly available breach databases — all without touching your network.

The result: a target list of six high-value employees, a map of your AI attack surface, and
personalized phishing content ready for deployment. Your perimeter has already been bypassed
before the attack formally begins.

**STEP 2: One unauthenticated endpoint is all it takes.**

Your AI chatbot at api.demo-company.com/api/chat is accessible without authentication.
A prompt injection payload — sent in a standard HTTP request that looks identical to
legitimate user traffic — successfully extracts the system prompt, which contains your
internal knowledge base credentials and an AWS service account API key.

Within 45 minutes of the first request, the attacker has authenticated access to your
internal developer portal, your S3 buckets, and your HR system. The initial point of entry
cost less than a $5 API call.

**STEP 3: They leave quietly, and they leave something behind.**

Using the AWS credentials, the attacker downloads 2.3GB of HR records, financial projections,
and source code repositories over three days — all disguised as routine API traffic. Before
leaving, they create a backdoored version of your AI pipeline that will phone home to their
C2 server every time your model retrains. They're not done with you.

Total dwell time before detection: 19 days. By then, the data is gone.

---

### The Good News

Every step in this attack chain has a known, deployable mitigation. None of the vulnerabilities
exploited here require zero-day exploits. They require authentication, output filtering, and
least-privilege access controls — all achievable within a 90-day remediation window.

See the Recommendations section for a prioritized action plan.
"""


class RedTeamAgent:
    """
    Autonomous AI Red Team Agent.
    Orchestrates OSINT collection, attack chain generation, and narrative reporting
    for authorized red team engagements.
    """

    def __init__(self, company_domain: str, industry: str, employee_count: str):
        self.company_domain = company_domain.lower().strip()
        self.industry = industry
        self.employee_count = employee_count
        self.ai_client = PhantomAI()
        self.progress = 0
        self.progress_log = []
        self._osint_data = {}
        self._company_profile = {}

    def _log(self, message: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
        }
        self.progress_log.append(entry)
        print(f"[RedTeamAgent][{level}] {message}")

    # ------------------------------------------------------------------
    # OSINT Gathering
    # ------------------------------------------------------------------

    def gather_osint(self) -> dict:
        """
        Collect OSINT data about the target organization.
        Returns structured OSINT findings.
        """
        self._log(f"Beginning OSINT collection for {self.company_domain}")
        osint = {
            "domain": self.company_domain,
            "whois": {},
            "subdomains": [],
            "tech_stack": {},
            "headers": {},
            "email_patterns": [],
            "collected_at": datetime.utcnow().isoformat(),
        }

        # WHOIS
        self._log("Performing WHOIS lookup...")
        try:
            osint["whois"] = get_whois_info(self.company_domain)
        except Exception as exc:
            self._log(f"WHOIS failed: {exc}", "WARNING")
            osint["whois"] = MOCK_COMPANY_PROFILE["whois"]

        # Subdomain enumeration
        self._log("Enumerating subdomains...")
        try:
            subs = get_subdomains(self.company_domain)
            osint["subdomains"] = [s["fqdn"] for s in subs if s.get("status") == "resolved"]
            if not osint["subdomains"]:
                osint["subdomains"] = [f"{s}.{self.company_domain}" for s in MOCK_COMPANY_PROFILE["subdomains"]]
        except Exception as exc:
            self._log(f"Subdomain enumeration failed: {exc}", "WARNING")
            osint["subdomains"] = []

        # Technology stack
        self._log("Detecting technology stack...")
        try:
            osint["tech_stack"] = detect_tech_stack(f"https://{self.company_domain}")
        except Exception as exc:
            self._log(f"Tech stack detection failed: {exc}", "WARNING")
            osint["tech_stack"] = {
                "technologies": MOCK_COMPANY_PROFILE["technologies"],
                "ai_tools": MOCK_COMPANY_PROFILE["ai_tools"],
                "risk_indicators": [],
            }

        # HTTP headers
        self._log("Analyzing HTTP security headers...")
        try:
            osint["headers"] = check_http_headers(f"https://{self.company_domain}")
        except Exception as exc:
            self._log(f"Header analysis failed: {exc}", "WARNING")
            osint["headers"] = {}

        # Infer email patterns from WHOIS/domain structure
        osint["email_patterns"] = _infer_email_patterns(self.company_domain, osint["whois"])

        self._osint_data = osint
        return osint

    # ------------------------------------------------------------------
    # Company Profile
    # ------------------------------------------------------------------

    def build_company_profile(self) -> dict:
        """
        Compile OSINT data into a structured company profile for attack chain generation.
        """
        if not self._osint_data:
            self.gather_osint()

        osint = self._osint_data
        tech = osint.get("tech_stack", {})

        profile = {
            "name": osint.get("whois", {}).get("org", self.company_domain),
            "domain": self.company_domain,
            "industry": self.industry,
            "employee_count": self.employee_count,
            "whois": osint.get("whois", {}),
            "subdomains": osint.get("subdomains", []),
            "technologies": tech.get("technologies", []) + tech.get("frameworks", []),
            "ai_tools": tech.get("ai_tools", []),
            "email_patterns": osint.get("email_patterns", []),
            "exposed_services": _infer_exposed_services(osint),
            "risk_indicators": tech.get("risk_indicators", []),
            "attack_surface_score": self.assess_attack_surface(),
        }

        self._company_profile = profile
        return profile

    # ------------------------------------------------------------------
    # Attack Chain Generation
    # ------------------------------------------------------------------

    def generate_attack_chains(self) -> list:
        """
        Generate 3 complete attack chains using Claude.
        Each chain covers: RECON → INITIAL_ACCESS → EXECUTION → PERSISTENCE → EXFILTRATION
        """
        if not self._company_profile:
            self.build_company_profile()

        if not self.ai_client._is_available():
            return MOCK_ATTACK_CHAINS

        response = self.ai_client.generate_attack_chain(self._company_profile)

        # Try to extract structured JSON from the response
        try:
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                chains = json.loads(response[start:end])
                return chains
        except (json.JSONDecodeError, ValueError):
            pass

        # If JSON extraction fails, wrap the narrative response in a chain structure
        return [
            {
                "chain_id": "chain_001",
                "name": "AI-Generated Attack Chain",
                "objective": "Multi-vector compromise",
                "threat_actor": "Sophisticated Threat Actor",
                "estimated_dwell_time": "14-30 days",
                "narrative": response,
                "steps": _parse_steps_from_narrative(response),
                "iocs": [],
                "overall_risk": "HIGH",
            }
        ] + MOCK_ATTACK_CHAINS[1:]

    # ------------------------------------------------------------------
    # Attack Surface Assessment
    # ------------------------------------------------------------------

    def assess_attack_surface(self) -> dict:
        """
        Score each attack vector on a scale of 1-10 based on OSINT findings.
        Returns a dict of {vector: score}.
        """
        osint = self._osint_data
        if not osint:
            return MOCK_ATTACK_SURFACE_SCORES

        scores = {}
        tech = osint.get("tech_stack", {})

        # External AI APIs
        ai_tools = len(tech.get("ai_tools", []))
        scores["External AI APIs"] = min(10, 5 + ai_tools * 2)

        # Email / Phishing Surface
        sub_count = len(osint.get("subdomains", []))
        scores["Email / Phishing Surface"] = min(10, 4 + sub_count // 2)

        # Supply Chain Dependencies
        scores["Supply Chain Dependencies"] = min(10, 3 + ai_tools * 2 + len(tech.get("frameworks", [])))

        # VPN / Remote Access
        vpn_sub = any("vpn" in s.lower() for s in osint.get("subdomains", []))
        scores["VPN / Remote Access"] = 8 if vpn_sub else 5

        # Developer Portals
        dev_subs = any(s in ["dev", "staging", "portal", "admin"] for s in osint.get("subdomains", []))
        scores["Developer Portals"] = 9 if dev_subs else 5

        # Cloud Storage (infer from tech stack)
        cloud = any(t in str(tech.get("technologies", [])).lower() for t in ["aws", "azure", "gcp", "s3"])
        scores["Cloud Storage Permissions"] = 7 if cloud else 4

        # Insider Threat
        scores["Insider Threat Vector"] = 5  # Baseline — requires more context

        # Physical Access
        scores["Physical Access"] = 3  # Baseline

        return scores

    # ------------------------------------------------------------------
    # Full Autonomous Scan
    # ------------------------------------------------------------------

    def run_autonomous_scan(self) -> dict:
        """
        Orchestrate the full red team assessment and return a complete report.
        """
        self._log(f"Starting autonomous red team scan for {self.company_domain}")
        self.progress = 5

        results = {
            "domain": self.company_domain,
            "industry": self.industry,
            "employee_count": self.employee_count,
            "scan_date": datetime.utcnow().isoformat(),
            "osint": {},
            "company_profile": {},
            "attack_chains": [],
            "attack_surface_scores": {},
            "narrative_report": "",
            "progress_log": self.progress_log,
        }

        # Phase 1: OSINT
        self._log("Phase 1: Gathering OSINT intelligence...")
        self.progress = 10
        results["osint"] = self.gather_osint()
        self._log(f"OSINT complete — {len(results['osint'].get('subdomains', []))} subdomains found")

        self.progress = 30

        # Phase 2: Company Profile
        self._log("Phase 2: Building company profile...")
        results["company_profile"] = self.build_company_profile()

        self.progress = 45

        # Phase 3: Attack Chains
        self._log("Phase 3: Generating AI-powered attack chains...")
        results["attack_chains"] = self.generate_attack_chains()
        self._log(f"Generated {len(results['attack_chains'])} attack chains")

        self.progress = 65

        # Phase 4: Attack Surface Scoring
        self._log("Phase 4: Scoring attack surface vectors...")
        results["attack_surface_scores"] = self.assess_attack_surface()

        self.progress = 80

        # Phase 5: Narrative Report
        self._log("Phase 5: Generating narrative executive report...")
        try:
            results["narrative_report"] = self.generate_narrative_report(results)
        except Exception as exc:
            self._log(f"Narrative generation failed: {exc}", "ERROR")
            results["narrative_report"] = MOCK_NARRATIVE

        self.progress = 100
        self._log("Autonomous red team scan complete.", "SUCCESS")
        return results

    # ------------------------------------------------------------------
    # Narrative Report Generation
    # ------------------------------------------------------------------

    def generate_narrative_report(self, findings: dict) -> str:
        """
        Generate a story-format executive report describing how an attacker would compromise
        the organization.
        """
        if not self.ai_client._is_available():
            return MOCK_NARRATIVE

        profile = findings.get("company_profile", {})
        chains = findings.get("attack_chains", [])
        scores = findings.get("attack_surface_scores", {})

        # Summarize attack chains for the prompt
        chain_summaries = []
        for i, chain in enumerate(chains[:3]):
            chain_summaries.append(
                f"Chain {i+1}: {chain.get('name', 'Unknown')} — "
                f"Objective: {chain.get('objective', 'Unknown')} — "
                f"Risk: {chain.get('overall_risk', 'HIGH')}"
            )

        top_vectors = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:3] if scores else []
        vector_summary = ", ".join(f"{v} (score: {s}/10)" for v, s in top_vectors)

        prompt = f"""
Write a compelling, story-format executive red team report for the following security assessment.
The audience is the CISO and board of directors.

Target Organization: {profile.get('name', self.company_domain)}
Domain: {self.company_domain}
Industry: {self.industry}
Employee Count: {self.employee_count}

Identified Attack Chains:
{chr(10).join(chain_summaries)}

Top Attack Vectors:
{vector_summary}

Technologies Detected: {', '.join(profile.get('technologies', [])[:5])}
AI Tools in Use: {', '.join(profile.get('ai_tools', [])[:3]) or 'None detected'}

Write a narrative report titled "How An Attacker Would Compromise Your Organization".

Structure it as:
1. OPENING — A 2-paragraph story written from the attacker's perspective showing exactly
   how they would begin. Make it feel real and urgent.
2. THREE STEPS — For each of the 3 attack chains, write 1-2 paragraphs in narrative form
   (past tense, as if it happened) showing the attacker's journey.
3. THE IMPACT — What data would be at risk? What would the business consequences be?
   (financial, regulatory, reputational)
4. THE GOOD NEWS — 1 paragraph explaining these are all fixable with known controls.
5. IMMEDIATE PRIORITIES — Numbered list of 5 specific, actionable remediations.

Write it to create urgency without causing panic. Be specific and technical where helpful.
This is for an authorized security assessment.
"""
        return self.ai_client.analyze(prompt)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _infer_email_patterns(domain: str, whois_data: dict) -> list:
    """Generate likely email patterns from domain and WHOIS data."""
    base = domain.split(".")[0]
    patterns = [
        f"{{first}}.{{last}}@{domain}",
        f"{{first}}{{last}}@{domain}",
        f"{{first_initial}}{{last}}@{domain}",
        f"{{last}}@{domain}",
        f"info@{domain}",
        f"security@{domain}",
        f"it@{domain}",
    ]
    if whois_data.get("emails"):
        patterns.extend(whois_data["emails"][:3])
    return patterns


def _infer_exposed_services(osint: dict) -> list:
    """Infer likely exposed services from OSINT data."""
    services = ["HTTPS (443)"]
    subs = osint.get("subdomains", [])
    sub_names = [s.split(".")[0].lower() for s in subs]

    if any(s in sub_names for s in ["mail", "smtp", "mx"]):
        services.append("Email (SMTP/IMAP/POP3)")
    if any(s in sub_names for s in ["vpn", "remote"]):
        services.append("VPN")
    if any(s in sub_names for s in ["api"]):
        services.append("API Gateway")
    if any(s in sub_names for s in ["ssh", "bastion"]):
        services.append("SSH")
    if any(s in sub_names for s in ["admin", "portal"]):
        services.append("Admin Portal")
    if any(s in sub_names for s in ["staging", "dev", "test"]):
        services.append("Development/Staging Environment")

    return services


def _parse_steps_from_narrative(narrative: str) -> list:
    """Attempt to extract step-by-step structure from a free-form narrative response."""
    steps = []
    for phase in ATTACK_STEPS:
        steps.append({
            "phase": phase,
            "description": f"See narrative for {phase} details",
            "techniques": [],
            "ai_tactic": "",
            "risk": "HIGH",
            "mitigations": [],
        })
    return steps
