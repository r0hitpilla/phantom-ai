"""
Phantom AI — Claude Client Wrapper
Wraps the Anthropic Python SDK for all AI-powered analysis tasks.
"""

import os
import sys
import traceback

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# ---------------------------------------------------------------------------
# Mock responses used when no API key is present
# ---------------------------------------------------------------------------

MOCK_ATTACK_CHAIN = """
## Multi-Step Attack Chain Analysis

### Phase 1: Reconnaissance
The threat actor begins by enumerating publicly available information about the target organization.
They collect employee names from LinkedIn, domain infrastructure from DNS records, and technology
stack details from job postings. AI-powered tools accelerate this phase from days to hours.

### Phase 2: Initial Access via AI System Exploitation
A vulnerable AI chatbot endpoint at /api/chat is identified with no rate limiting or authentication.
The attacker crafts prompt injection payloads to extract system prompt contents, revealing internal
knowledge-base documents and integration credentials.

### Phase 3: Credential Harvesting
Using extracted API keys found in the AI system prompt, the attacker authenticates to internal
developer portals. OAuth tokens with excessive scopes are leveraged to access adjacent services.

### Phase 4: Lateral Movement
The attacker pivots from the AI system's service account to cloud storage buckets. Misconfigured
IAM roles allow read access to HR and finance directories.

### Phase 5: Data Exfiltration
Sensitive employee PII, financial records, and IP documents are exfiltrated over encrypted channels
disguised as normal AI API traffic. The total dwell time before detection: 22 days.

### Recommendations
- Enforce strict input/output filtering on all AI endpoints
- Rotate and scope service account credentials quarterly
- Implement AI-specific WAF rules
- Deploy anomaly detection on AI API traffic patterns
"""

MOCK_PHISHING_SCRIPT = """
## Deepfake Social Engineering Call Script

**Scenario:** Urgent IT Security Credential Reset
**Caller Persona:** IT Help Desk (voice-cloned executive)

---

[CALL OPENS]

"Hi, this is [EXEC NAME] from IT Security. I'm calling because our security systems have flagged
unusual activity on your account in the last 30 minutes. We need to verify your identity and
reset your credentials immediately to prevent a potential breach.

I know this is unexpected, but this is time-sensitive. Our CISO has been briefed and we're
doing this for all senior staff right now.

Can you confirm your employee ID so I can pull up your account? ... Great. Now, I'm going to
send you a one-time verification code — can you read that back to me once you receive it?

[PAUSE FOR RESPONSE]

Perfect. I'm resetting your access now. You'll receive a new password setup link in about
two minutes. Please complete that right away and don't share it with anyone.

Thank you for your cooperation. This is exactly the right way to handle a security incident."

[CALL ENDS]

---

**Training Note:** This script exploits authority bias (exec voice), urgency bias (time pressure),
and compliance with security procedures. Employees should be trained to verify caller identity
through a separate channel before providing any credentials or MFA codes.
"""

MOCK_COGNITIVE_ANALYSIS = """
## Cognitive Vulnerability Analysis

### High-Risk Profile: CFO / VP Finance
**Dominant Vulnerabilities:**
- **Authority Bias (Score: 9/10):** Conditioned to respond immediately to C-suite requests
- **Urgency Bias (Score: 8/10):** Quarter-end pressure creates cognitive shortcuts
- **Reciprocity (Score: 7/10):** Long tenure creates strong sense of loyalty and obligation

**Recommended Attack Vector:** CEO fraud (BEC) targeting wire transfer authorization during
Q4 close. Voice clone of CEO calling from "travel" requesting urgent vendor payment.

### Medium-Risk Profile: IT Administrator
**Dominant Vulnerabilities:**
- **Fear of Missing Out (Score: 8/10):** Concerned about missing critical patches/incidents
- **Social Proof (Score: 6/10):** Trusts requests that appear to come from vendor support
- **Authority Bias (Score: 7/10):** Responds to "security emergency" escalations

**Recommended Attack Vector:** Fake vendor security advisory with malicious patch link.

### Lower-Risk Profile: New Employee (< 6 months)
**Dominant Vulnerabilities:**
- **Social Proof (Score: 9/10):** Wants to fit in, follows apparent norms
- **Authority Bias (Score: 9/10):** Does not yet know who to question
- **Fear of Consequences (Score: 8/10):** Does not want to appear incompetent

**Recommended Attack Vector:** Onboarding phishing — fake HR portal credential collection.
"""

MOCK_REPORT_SUMMARY = """
## Executive Summary — PHANTOM AI Security Assessment

**Assessment Date:** 2026-03-19
**Risk Rating:** HIGH

### Key Findings

This assessment identified significant attack surface exposure across AI systems, human
vulnerability vectors, and third-party supply chain dependencies.

**Critical Issues (Immediate Action Required):**
1. Unauthenticated AI API endpoints exposed to the public internet
2. Prompt injection vulnerabilities allowing system prompt extraction
3. Finance team identified as highest social engineering risk (vulnerability score: 78/100)

**High-Priority Issues:**
1. Third-party LLM dependencies with unvalidated model provenance
2. Excessive AI service account permissions enabling lateral movement
3. No anomaly detection on AI API traffic

**Summary Statistics:**
- Attack Surface Score: 72/100 (High Risk)
- Social Engineering Vulnerability: 68/100
- Supply Chain Risk: 61/100
- Cognitive Attack Surface: 74/100

### Immediate Recommendations
1. Place all AI endpoints behind authentication within 30 days
2. Implement prompt injection filtering (OWASP LLM Top 10 controls)
3. Conduct targeted security awareness training for finance and HR teams
4. Audit all third-party AI service permissions and rotate credentials
5. Deploy AI-specific SIEM rules for anomaly detection
"""


# ---------------------------------------------------------------------------
# Main PhantomAI Client Class
# ---------------------------------------------------------------------------

class PhantomAI:
    """
    Wrapper around the Anthropic Python SDK.
    Falls back to mock data gracefully when no API key is configured.
    """

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = "claude-sonnet-4-6"
        self.client = None
        self._init_client()

    def _init_client(self):
        """Initialize the Anthropic client if credentials are available."""
        if not ANTHROPIC_AVAILABLE:
            return
        if self.api_key:
            try:
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as exc:
                print(f"[PhantomAI] Failed to initialize Anthropic client: {exc}", file=sys.stderr)
                self.client = None

    def _is_available(self) -> bool:
        return self.client is not None

    # ------------------------------------------------------------------
    # Core analyze method
    # ------------------------------------------------------------------

    def analyze(self, prompt: str, system: str = None) -> str:
        """
        Send a prompt to Claude and return the text response.
        Falls back to a generic mock if the API is unavailable.
        """
        if not self._is_available():
            return (
                "[DEMO MODE] ANTHROPIC_API_KEY not configured. "
                "Set the environment variable to enable live AI analysis.\n\n"
                f"Prompt received: {prompt[:200]}..."
            )

        try:
            messages = [{"role": "user", "content": prompt}]
            kwargs = {
                "model": self.model,
                "max_tokens": 4096,
                "messages": messages,
            }
            if system:
                kwargs["system"] = system

            response = self.client.messages.create(**kwargs)
            return response.content[0].text
        except anthropic.APIConnectionError as exc:
            return f"[ERROR] Connection to Anthropic API failed: {exc}"
        except anthropic.RateLimitError:
            return "[ERROR] Anthropic API rate limit exceeded. Please retry in a moment."
        except anthropic.APIStatusError as exc:
            return f"[ERROR] Anthropic API error {exc.status_code}: {exc.message}"
        except Exception as exc:
            traceback.print_exc()
            return f"[ERROR] Unexpected error during AI analysis: {exc}"

    # ------------------------------------------------------------------
    # Specialized generation methods
    # ------------------------------------------------------------------

    def generate_attack_chain(self, company_info: dict) -> str:
        """
        Generate a multi-step attack narrative tailored to the target company.

        company_info keys: name, domain, industry, employee_count,
                           technologies (list), ai_tools (list)
        """
        if not self._is_available():
            return MOCK_ATTACK_CHAIN

        system = (
            "You are an expert red team operator writing attack chain narratives for authorized "
            "penetration testing engagements. Your output is used by security teams to understand "
            "and remediate vulnerabilities. Be technical, realistic, and actionable. "
            "Always frame findings as educational content for defenders."
        )

        name = company_info.get("name", "the target organization")
        domain = company_info.get("domain", "unknown.com")
        industry = company_info.get("industry", "technology")
        employee_count = company_info.get("employee_count", "unknown")
        technologies = ", ".join(company_info.get("technologies", [])) or "unknown"
        ai_tools = ", ".join(company_info.get("ai_tools", [])) or "none detected"

        prompt = f"""
You are conducting an authorized red team assessment for {name} ({domain}).

Company Profile:
- Industry: {industry}
- Employee Count: {employee_count}
- Detected Technologies: {technologies}
- AI Tools in Use: {ai_tools}

Generate 3 complete, realistic attack chains that a sophisticated threat actor could execute
against this organization. For each chain, include:

1. Chain Name and Objective
2. Threat Actor Profile (APT group style, nation-state or criminal)
3. Steps (use phases: RECON → INITIAL_ACCESS → EXECUTION → PERSISTENCE → EXFILTRATION)
4. AI-specific tactics used in each phase
5. Estimated dwell time
6. Indicators of Compromise (IOCs) defenders should watch for
7. Specific mitigations for each step

Format each chain clearly with headers. Be technically precise and realistic.
This report is for authorized security testing and defensive purposes only.
"""
        return self.analyze(prompt, system=system)

    def generate_phishing_script(self, target_info: dict, scenario: str) -> str:
        """
        Generate a realistic deepfake social engineering call script.

        target_info keys: name, title, department, company, exec_name, exec_title
        scenario: one of 'wire_transfer', 'credential_reset', 'data_access'
        """
        if not self._is_available():
            return MOCK_PHISHING_SCRIPT

        system = (
            "You are a social engineering awareness trainer creating simulation scripts for "
            "authorized security awareness programs. These scripts are used to train employees "
            "to recognize and resist social engineering attacks. All content is for defensive "
            "training purposes within authorized engagements."
        )

        target_name = target_info.get("name", "Target Employee")
        target_title = target_info.get("title", "Employee")
        target_dept = target_info.get("department", "General")
        company = target_info.get("company", "the organization")
        exec_name = target_info.get("exec_name", "The CEO")
        exec_title = target_info.get("exec_title", "CEO")

        scenario_descriptions = {
            "wire_transfer": "urgent wire transfer request to a new vendor account",
            "credential_reset": "emergency IT security credential reset",
            "data_access": "emergency data access request due to a security incident",
        }
        scenario_desc = scenario_descriptions.get(scenario, scenario)

        prompt = f"""
Create a realistic deepfake social engineering simulation call script for an authorized
security awareness training program at {company}.

Target Employee: {target_name}, {target_title} ({target_dept} department)
Simulated Caller Persona: {exec_name}, {exec_title} (voice cloned by attacker)
Scenario: {scenario_desc}

Write a complete call script including:
1. Opening gambit and identity establishment
2. Urgency creation techniques used
3. Psychological manipulation tactics employed (label each one)
4. The specific ask / malicious request
5. Objection handling if the target pushes back
6. Closing and follow-up instructions

After the script, include a TRAINING DEBRIEF section explaining:
- What red flags the employee should have noticed
- What the correct response is
- Which cognitive biases were exploited

Format the script as a realistic transcript. Label speaker turns clearly.
This is for authorized security awareness training only.
"""
        return self.analyze(prompt, system=system)

    def analyze_cognitive_profile(self, employee_data: dict) -> str:
        """
        Analyze cognitive vulnerabilities for a given employee profile.

        employee_data keys: name, title, department, years_at_company,
                            linkedin_url (optional), notes (optional)
        """
        if not self._is_available():
            return MOCK_COGNITIVE_ANALYSIS

        system = (
            "You are a behavioral security analyst specializing in cognitive vulnerability "
            "assessment for authorized red team engagements. Your analysis helps security teams "
            "prioritize security awareness training and identify high-risk individuals who need "
            "additional protection and coaching."
        )

        name = employee_data.get("name", "Employee")
        title = employee_data.get("title", "Unknown Role")
        department = employee_data.get("department", "Unknown Department")
        years = employee_data.get("years_at_company", "unknown")
        notes = employee_data.get("notes", "")

        prompt = f"""
Conduct a cognitive vulnerability profile for the following employee as part of an authorized
security assessment:

Name: {name}
Title: {title}
Department: {department}
Years at Company: {years}
Additional Context: {notes}

Analyze and score (1-10) the following cognitive vulnerabilities:
1. Authority Bias — tendency to comply with apparent authority figures
2. Urgency Bias — susceptibility to artificial time pressure
3. Fear of Missing Out (FOMO) — concern about being excluded from critical information
4. Reciprocity — obligation from perceived favors or relationships
5. Social Proof — following apparent group behavior
6. Fear of Consequences — acting to avoid perceived negative outcomes
7. Curiosity — clicking on interesting/unusual content

For each vulnerability:
- Score (1-10, with justification)
- Most likely exploitation scenario
- Recommended social engineering approach an attacker would use
- Training intervention to reduce this vulnerability

Conclude with:
- Overall Risk Score (0-100)
- Top 3 recommended attack vectors
- Training Priority (CRITICAL/HIGH/MEDIUM/LOW)
- 3 specific training recommendations

This analysis is for authorized security assessment and training purposes only.
"""
        return self.analyze(prompt, system=system)

    def generate_report_summary(self, findings: dict) -> str:
        """
        Generate a professional executive summary from raw scan findings.

        findings keys: module, target, scan_date, risk_score, critical_count,
                       high_count, medium_count, low_count, key_findings (list),
                       recommendations (list)
        """
        if not self._is_available():
            return MOCK_REPORT_SUMMARY

        system = (
            "You are a senior cybersecurity consultant writing an executive summary for a "
            "board-level security report. Write clearly, concisely, and with appropriate urgency. "
            "Avoid jargon where possible. Every finding should map to a business risk."
        )

        module = findings.get("module", "Security Assessment")
        target = findings.get("target", "Target Organization")
        scan_date = findings.get("scan_date", "2026-03-19")
        risk_score = findings.get("risk_score", 50)
        critical_count = findings.get("critical_count", 0)
        high_count = findings.get("high_count", 0)
        medium_count = findings.get("medium_count", 0)
        low_count = findings.get("low_count", 0)
        key_findings = "\n".join(
            f"- {f}" for f in findings.get("key_findings", [])
        )
        recommendations = "\n".join(
            f"- {r}" for r in findings.get("recommendations", [])
        )

        prompt = f"""
Write a professional executive summary for the following security assessment report.

Assessment Details:
- Module: {module}
- Target: {target}
- Date: {scan_date}
- Overall Risk Score: {risk_score}/100

Finding Counts:
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Key Findings:
{key_findings}

Recommended Remediations:
{recommendations}

Write a 3-5 paragraph executive summary that:
1. Opens with the overall risk posture and most critical issue
2. Summarizes the key attack vectors discovered
3. Quantifies the business risk (data breach potential, regulatory exposure, reputational risk)
4. Provides a prioritized remediation roadmap
5. Closes with a recommended timeline and next steps

Use clear, business-friendly language. This will be presented to the board of directors.
"""
        return self.analyze(prompt, system=system)
