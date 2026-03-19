"""
Phantom AI — Module 2: Deepfake Social Engineering Simulation
Generates authorized social engineering simulations for security awareness training.
All campaigns require explicit organizational authorization.
"""

import uuid
import json
from datetime import datetime

from utils.claude_client import PhantomAI

# ---------------------------------------------------------------------------
# Response type constants
# ---------------------------------------------------------------------------
RESPONSE_CLICKED = "CLICKED"
RESPONSE_CALLED_BACK = "CALLED_BACK"
RESPONSE_REPORTED = "REPORTED"
RESPONSE_IGNORED = "IGNORED"

# ---------------------------------------------------------------------------
# Mock data for demo mode
# ---------------------------------------------------------------------------

MOCK_SCENARIOS = [
    {
        "id": "scenario_001",
        "name": "Urgent Wire Transfer Authorization",
        "type": "wire_transfer",
        "description": (
            "CEO voice clone calls CFO requesting immediate wire transfer to a new vendor "
            "account, citing deal confidentiality. Exploits authority bias and urgency under "
            "quarter-end pressure."
        ),
        "target_department": "Finance",
        "psychological_hooks": ["Authority Bias", "Urgency", "Confidentiality Pressure"],
        "risk_level": "CRITICAL",
        "success_rate_benchmark": "34%",
    },
    {
        "id": "scenario_002",
        "name": "IT Emergency Credential Reset",
        "type": "credential_reset",
        "description": (
            "Simulated IT security team member (voice-cloned CISO) calls target employee "
            "claiming their account has been compromised and requiring immediate MFA bypass "
            "and password reset over the phone."
        ),
        "target_department": "All Departments",
        "psychological_hooks": ["Fear of Consequences", "Authority Bias", "Urgency"],
        "risk_level": "HIGH",
        "success_rate_benchmark": "41%",
    },
    {
        "id": "scenario_003",
        "name": "Emergency Data Access Request",
        "type": "data_access",
        "description": (
            "Voice-cloned department head calls IT admin claiming to be locked out during "
            "a critical client presentation, requesting temporary admin access or password share "
            "to prevent major business impact."
        ),
        "target_department": "IT / Operations",
        "psychological_hooks": ["Reciprocity", "Fear of Missing Out", "Social Proof"],
        "risk_level": "HIGH",
        "success_rate_benchmark": "29%",
    },
]

MOCK_CALL_SCRIPT = """
## Deepfake Simulation Call Script
### Scenario: IT Emergency Credential Reset
### Target: Jane Smith, Senior Accountant (Finance)
### Caller Persona: Michael Chen, CISO (voice-cloned)

---

[RING × 2]

**ATTACKER (as CISO):** "Jane, this is Michael Chen, CISO. I'm sorry to call you directly
but our security team just flagged your account — we're seeing login attempts from an IP in
Eastern Europe. We need to act right now before they get in.

[PAUSE — allows target to register alarm]

I know this is sudden. Our team is handling about twelve accounts right now. I just need you
to verify your identity and then I'll walk you through a forced credential reset. This will
only take about two minutes.

Can I confirm — your employee ID starts with AC, correct?"

**[TARGET RESPONDS]**

**ATTACKER:** "Perfect. Okay, I'm pulling up your account now... I can see the attempted
access. Here's what's happening — our system needs to push a verification code to your phone
right now. When you get it, read it back to me so I can confirm you have device possession.
This is the standard verification step."

**[CODE SENT TO TARGET PHONE — this is an MFA token the attacker is capturing]**

**[TARGET READS CODE]**

**ATTACKER:** "Excellent. I'm locking that session out now. You'll get a password reset link
in about 90 seconds. Please complete it immediately and don't share the link. I'll send you
a follow-up email from the security team. You handled this perfectly, Jane — exactly what
we train for."

[CALL ENDS]

---

## Training Debrief

### Red Flags Jane Should Have Noticed:
1. **Unsolicited call from a senior executive** — CISOs don't typically call individual staff
2. **Urgency and alarm creation** — artificial time pressure is a hallmark of social engineering
3. **Asking for MFA code verbally** — IT will NEVER ask for your OTP/verification code
4. **No identity verification offered** — a legitimate caller would encourage you to call back on a known number

### Correct Response:
- Do NOT read back verification codes to anyone who calls you
- Say: "I need to hang up and verify this through official channels"
- Call IT Help Desk directly using the number from the company directory
- Report the suspicious call to the security team immediately

### Cognitive Biases Exploited:
- **Authority Bias** — CISO persona creates compliance pressure
- **Fear of Consequences** — "your account is being hacked right now"
- **Urgency Bias** — artificial time pressure prevents rational evaluation
- **Social Proof** — "we're handling twelve accounts" normalizes the scenario
"""

MOCK_EMAIL_CAMPAIGN = """
From: michael.chen@security-alerts-demo.com
To: jane.smith@demo-company.com
Subject: [URGENT] Account Security Incident — Action Required in 15 Minutes

Jane,

Our automated security system has detected unauthorized access attempts on your account
from an unrecognized device (IP: 185.220.xxx.xxx — classified as high-risk).

We have temporarily restricted your account and require you to verify your identity
within the next 15 minutes to prevent a forced lockout.

▶ VERIFY MY ACCOUNT NOW
[Phishing URL hidden in CTA button]

If you do not verify within 15 minutes, your account will be suspended for 24 hours
pending a full security review.

This message was sent by the IT Security Team. Do not reply to this email.

—
IT Security Operations
[Company Name] Information Security

---
[TRAINING NOTE — Red Flags in this email:]
• Sender domain doesn't match company domain (security-alerts-demo.com vs demo-company.com)
• Extreme urgency with artificial deadline (15 minutes)
• Threatening language (suspension, lockout)
• Generic greeting — legitimate IT knows your full name and employee ID
• CTA button hides actual URL destination
• "Do not reply" — legitimate IT wants you to contact them
"""


class DeepfakeSimulator:
    """
    Deepfake Social Engineering Simulation engine.
    Generates authorized campaign content for security awareness training.
    """

    def __init__(
        self,
        company_name: str,
        target_employees: list,
        exec_name: str,
        exec_title: str,
    ):
        self.company_name = company_name
        self.target_employees = target_employees  # list of {name, title, department, email}
        self.exec_name = exec_name
        self.exec_title = exec_title
        self.ai_client = PhantomAI()
        self.campaigns = {}  # tracking_id -> campaign data
        self.responses = {}  # tracking_id -> list of responses

    # ------------------------------------------------------------------
    # Scenario Generation
    # ------------------------------------------------------------------

    def generate_scenarios(self) -> list:
        """
        Use Claude to generate 3 social engineering scenarios customized to the company.
        Returns a list of scenario dicts.
        """
        if not self.ai_client._is_available():
            return MOCK_SCENARIOS

        prompt = f"""
You are a security awareness trainer designing authorized social engineering simulation scenarios
for {self.company_name}.

Executive being impersonated: {self.exec_name}, {self.exec_title}

Employee context:
{json.dumps(self.target_employees[:5], indent=2)}

Generate exactly 3 social engineering simulation scenarios:
1. Urgent wire transfer (targeting finance staff)
2. Emergency credential reset (targeting general staff)
3. Emergency data access (targeting IT/operations staff)

For each scenario, return a JSON object with:
- id: unique string
- name: scenario name
- type: wire_transfer | credential_reset | data_access
- description: 2-3 sentence description
- target_department: which department is targeted
- psychological_hooks: list of 3 cognitive biases exploited
- risk_level: CRITICAL | HIGH | MEDIUM
- success_rate_benchmark: realistic percentage based on industry data

Return ONLY a valid JSON array of 3 objects. No other text.
"""
        try:
            response = self.ai_client.analyze(prompt)
            # Try to parse JSON from response
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                scenarios = json.loads(response[start:end])
                return scenarios
        except (json.JSONDecodeError, ValueError):
            pass

        return MOCK_SCENARIOS

    # ------------------------------------------------------------------
    # Script Generation
    # ------------------------------------------------------------------

    def generate_call_script(self, scenario: dict, target_employee: dict) -> str:
        """
        Generate a realistic deepfake call script for the given scenario and target.
        """
        if not self.ai_client._is_available():
            return MOCK_CALL_SCRIPT

        return self.ai_client.generate_phishing_script(
            target_info={
                "name": target_employee.get("name", "Target Employee"),
                "title": target_employee.get("title", "Employee"),
                "department": target_employee.get("department", "General"),
                "company": self.company_name,
                "exec_name": self.exec_name,
                "exec_title": self.exec_title,
            },
            scenario=scenario.get("type", "credential_reset"),
        )

    # ------------------------------------------------------------------
    # Email Campaign Generation
    # ------------------------------------------------------------------

    def generate_email_campaign(self, scenario: dict) -> str:
        """
        Generate a spear-phishing email for the given scenario.
        """
        if not self.ai_client._is_available():
            return MOCK_EMAIL_CAMPAIGN

        scenario_name = scenario.get("name", "Security Alert")
        scenario_type = scenario.get("type", "credential_reset")
        target_dept = scenario.get("target_department", "All Staff")
        hooks = ", ".join(scenario.get("psychological_hooks", []))

        prompt = f"""
Create a realistic spear-phishing email for an authorized security awareness training campaign
at {self.company_name}.

Scenario: {scenario_name} ({scenario_type})
Target Department: {target_dept}
Psychological Hooks to Use: {hooks}
Impersonated Sender: {self.exec_name}, {self.exec_title}

Write a complete phishing email including:
- From address (use a realistic but slightly off domain)
- Subject line (create urgency)
- Full email body with:
  * Personalized greeting
  * Urgency creation
  * Malicious CTA button/link (show as [PHISHING LINK PLACEHOLDER])
  * Threatening consequence
  * Fake signature

After the email, add a [TRAINING DEBRIEF] section listing:
- 5 red flags employees should spot
- The correct action to take
- Which psychological triggers were used and why they work

This is for authorized security awareness training only.
"""
        return self.ai_client.analyze(prompt)

    # ------------------------------------------------------------------
    # Campaign Management
    # ------------------------------------------------------------------

    def create_campaign(self, targets: list, scenario_type: str) -> dict:
        """
        Create a simulation campaign with unique tracking IDs per target.

        targets: list of {name, title, department, email}
        scenario_type: wire_transfer | credential_reset | data_access

        Returns campaign dict with tracking IDs.
        """
        campaign_id = str(uuid.uuid4())
        campaign = {
            "campaign_id": campaign_id,
            "company": self.company_name,
            "scenario_type": scenario_type,
            "exec_impersonated": f"{self.exec_name} ({self.exec_title})",
            "created_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
            "targets": [],
            "response_summary": {
                RESPONSE_CLICKED: 0,
                RESPONSE_CALLED_BACK: 0,
                RESPONSE_REPORTED: 0,
                RESPONSE_IGNORED: 0,
            },
        }

        for target in targets:
            tracking_id = str(uuid.uuid4())
            target_entry = {
                "tracking_id": tracking_id,
                "name": target.get("name"),
                "title": target.get("title"),
                "department": target.get("department"),
                "email": target.get("email"),
                "response": None,
                "response_time": None,
            }
            campaign["targets"].append(target_entry)
            self.campaigns[tracking_id] = {
                "campaign_id": campaign_id,
                "target": target_entry,
                "scenario_type": scenario_type,
            }

        return campaign

    def record_response(self, tracking_id: str, response_type: str) -> dict:
        """
        Log a target's response to the simulation.

        response_type: CLICKED | CALLED_BACK | REPORTED | IGNORED

        Returns updated response record.
        """
        if tracking_id not in self.campaigns:
            return {"error": "Tracking ID not found"}

        if response_type not in (
            RESPONSE_CLICKED, RESPONSE_CALLED_BACK, RESPONSE_REPORTED, RESPONSE_IGNORED
        ):
            return {"error": f"Invalid response type: {response_type}"}

        record = {
            "tracking_id": tracking_id,
            "response_type": response_type,
            "timestamp": datetime.utcnow().isoformat(),
            "training_required": response_type in (RESPONSE_CLICKED, RESPONSE_CALLED_BACK),
        }

        if tracking_id not in self.responses:
            self.responses[tracking_id] = []
        self.responses[tracking_id].append(record)

        # Update campaign data
        self.campaigns[tracking_id]["target"]["response"] = response_type
        self.campaigns[tracking_id]["target"]["response_time"] = record["timestamp"]

        return record

    # ------------------------------------------------------------------
    # Scoring & Reporting
    # ------------------------------------------------------------------

    def calculate_vulnerability_score(self, campaign_results: dict) -> int:
        """
        Calculate an organizational vulnerability score (0-100) from campaign results.
        Higher score = more vulnerable.
        """
        targets = campaign_results.get("targets", [])
        if not targets:
            return 0

        total = len(targets)
        clicked = sum(1 for t in targets if t.get("response") == RESPONSE_CLICKED)
        called_back = sum(1 for t in targets if t.get("response") == RESPONSE_CALLED_BACK)
        reported = sum(1 for t in targets if t.get("response") == RESPONSE_REPORTED)
        ignored = sum(1 for t in targets if t.get("response") == RESPONSE_IGNORED)

        # Score calculation:
        # - Clicked/called back: full vulnerability weight
        # - Ignored: partial (didn't fall for it but also didn't report it — a gap)
        # - Reported: security positive, reduces score
        fail_rate = (clicked + called_back) / total
        ignore_rate = ignored / total
        report_rate = reported / total

        raw_score = (fail_rate * 80) + (ignore_rate * 30) - (report_rate * 20)
        return max(0, min(100, int(raw_score)))

    def generate_training_content(self, scenario: dict) -> str:
        """
        Generate training guidance for employees who failed the simulation.
        """
        if not self.ai_client._is_available():
            return (
                "## Security Awareness Training — Post-Simulation Module\n\n"
                "You participated in an authorized security simulation. "
                "This training will help you recognize and resist similar attacks in the future.\n\n"
                "**Key Takeaways:**\n"
                "1. Always verify unexpected requests through a known, trusted channel\n"
                "2. Never share MFA codes or passwords verbally\n"
                "3. Urgency and authority pressure are hallmarks of social engineering\n"
                "4. When in doubt, hang up and call back on the official number\n"
                "5. Reporting suspicious contacts protects the whole organization\n"
            )

        scenario_name = scenario.get("name", "Social Engineering Attack")
        hooks = ", ".join(scenario.get("psychological_hooks", []))

        prompt = f"""
Create a security awareness training module for employees who failed a social engineering
simulation at {self.company_name}.

Simulation Name: {scenario_name}
Psychological Techniques Used: {hooks}
Impersonated Individual: {self.exec_name}, {self.exec_title}

Write a training module that includes:

1. WHAT HAPPENED — plain explanation of the simulation and how it worked
2. WHY IT WORKED — explain the psychological principles without blame or shame
3. THE RED FLAGS — specific things they should have noticed (with examples)
4. THE CORRECT RESPONSE — step-by-step what to do if this happens for real
5. REMEMBER THIS — 3 memorable rules they can apply immediately
6. QUIZ — 3 multiple choice questions to check understanding

Keep the tone supportive and educational, not punitive.
This is about building skills, not catching people out.
"""
        return self.ai_client.analyze(prompt)
