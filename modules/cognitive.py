"""
Phantom AI — Module 5: Cognitive Attack Profiling
Maps human cognitive vulnerabilities across the organization for targeted security training.
Used exclusively to improve security awareness; never for unauthorized targeting.
"""

import json
from datetime import datetime

from utils.claude_client import PhantomAI

# ---------------------------------------------------------------------------
# Cognitive bias categories
# ---------------------------------------------------------------------------

COGNITIVE_BIASES = [
    "authority_bias",
    "urgency_bias",
    "fear_of_missing_out",
    "reciprocity",
    "social_proof",
    "fear_of_consequences",
    "curiosity",
]

# High-value target role indicators
HIGH_VALUE_ROLES = {
    "c_suite": ["ceo", "cfo", "cto", "ciso", "coo", "chro", "cmo", "chief"],
    "finance": ["finance", "accounting", "payroll", "treasurer", "controller", "accounts payable", "bookkeeper"],
    "it_admin": ["it admin", "sysadmin", "system administrator", "devops", "network engineer", "security engineer", "infrastructure"],
    "hr": ["hr", "human resources", "recruiter", "talent", "people ops"],
    "executive_assistant": ["executive assistant", "ea to", "assistant to the", "personal assistant"],
    "legal": ["legal", "counsel", "attorney", "compliance", "privacy"],
}

# Training priority mapping
TRAINING_PRIORITY = {
    (80, 100): "CRITICAL",
    (60, 79): "HIGH",
    (40, 59): "MEDIUM",
    (0, 39): "LOW",
}

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

MOCK_PROFILES = [
    {
        "name": "Sarah Chen",
        "title": "VP Finance",
        "department": "Finance",
        "risk_score": 82,
        "high_value_target": True,
        "target_category": "finance",
        "top_vulnerabilities": [
            {"bias": "authority_bias", "score": 9, "description": "High compliance with C-suite requests"},
            {"bias": "urgency_bias", "score": 8, "description": "Quarter-end time pressure reduces scrutiny"},
            {"bias": "reciprocity", "score": 7, "description": "Long tenure creates strong obligation to colleagues"},
        ],
        "recommended_attack_type": "CEO fraud (BEC) — urgent wire transfer during Q4 close",
        "training_priority": "CRITICAL",
        "training_notes": "Prioritize wire transfer verification procedures and CEO fraud awareness",
    },
    {
        "name": "Marcus Rivera",
        "title": "IT Administrator",
        "department": "IT",
        "risk_score": 71,
        "high_value_target": True,
        "target_category": "it_admin",
        "top_vulnerabilities": [
            {"bias": "fear_of_consequences", "score": 8, "description": "Worried about missing security incidents"},
            {"bias": "authority_bias", "score": 7, "description": "Responds to vendor 'emergency' escalations"},
            {"bias": "social_proof", "score": 6, "description": "Trusts requests that appear internally sanctioned"},
        ],
        "recommended_attack_type": "Fake vendor security advisory with malicious patch link",
        "training_priority": "HIGH",
        "training_notes": "Focus on vendor verification and change management procedures",
    },
    {
        "name": "Priya Patel",
        "title": "Junior Developer",
        "department": "Engineering",
        "risk_score": 58,
        "high_value_target": False,
        "target_category": None,
        "top_vulnerabilities": [
            {"bias": "social_proof", "score": 9, "description": "New employee wants to fit in with team norms"},
            {"bias": "authority_bias", "score": 8, "description": "Does not yet know who to question"},
            {"bias": "fear_of_consequences", "score": 7, "description": "Afraid to appear incompetent"},
        ],
        "recommended_attack_type": "Fake onboarding phishing — HR portal credential collection",
        "training_priority": "MEDIUM",
        "training_notes": "Onboarding security training is critical for new employees",
    },
    {
        "name": "James Thompson",
        "title": "CEO",
        "department": "Executive",
        "risk_score": 65,
        "high_value_target": True,
        "target_category": "c_suite",
        "top_vulnerabilities": [
            {"bias": "urgency_bias", "score": 7, "description": "High trust in direct reports reduces verification"},
            {"bias": "reciprocity", "score": 8, "description": "Long-standing relationships exploited"},
            {"bias": "fear_of_missing_out", "score": 6, "description": "Competitive pressure creates urgency"},
        ],
        "recommended_attack_type": "Whaling — direct deepfake impersonation for board-level access",
        "training_priority": "HIGH",
        "training_notes": "Executive phishing simulation and board-level security briefing recommended",
    },
]

MOCK_ORG_HEATMAP = {
    "Finance": 78,
    "IT / Security": 68,
    "Executive": 65,
    "HR": 62,
    "Engineering": 52,
    "Sales": 48,
    "Marketing": 44,
    "Operations": 40,
}

MOCK_ATTACK_WINDOWS = [
    {
        "event": "Quarter-End Close",
        "timing": "Last 2 weeks of each quarter",
        "risk_multiplier": 1.8,
        "vulnerable_depts": ["Finance", "Executive"],
        "reason": "Time pressure reduces scrutiny of unusual payment requests",
        "attack_type": "BEC / Wire Transfer Fraud",
    },
    {
        "event": "Annual Performance Reviews",
        "timing": "January-February",
        "risk_multiplier": 1.4,
        "vulnerable_depts": ["HR", "All Staff"],
        "reason": "Anxiety about reviews increases social engineering susceptibility",
        "attack_type": "Phishing emails themed around performance/bonuses",
    },
    {
        "event": "Product Launch / Major Announcement",
        "timing": "Pre-launch window",
        "risk_multiplier": 1.6,
        "vulnerable_depts": ["Marketing", "Engineering", "Executive"],
        "reason": "All-hands urgency creates openings for impersonation attacks",
        "attack_type": "Spear phishing posing as vendor partners or media",
    },
    {
        "event": "Organizational Restructuring / Layoffs",
        "timing": "During uncertainty periods",
        "risk_multiplier": 2.1,
        "vulnerable_depts": ["All Departments"],
        "reason": "Fear and uncertainty maximally impairs security judgment",
        "attack_type": "HR phishing, fake severance / benefits portals",
    },
    {
        "event": "New Employee Onboarding Wave",
        "timing": "January, September (typical hiring cycles)",
        "risk_multiplier": 1.5,
        "vulnerable_depts": ["Engineering", "Sales", "Operations"],
        "reason": "New employees don't know verification procedures and want to fit in",
        "attack_type": "Onboarding phishing — fake IT portals and HR systems",
    },
]


class CognitiveProfiler:
    """
    Cognitive Attack Profiling engine.
    Maps organizational human vulnerability landscape for targeted security training.
    """

    def __init__(self, company_name: str, employees_data: list):
        """
        employees_data: list of {name, title, department, linkedin_url (optional),
                                  years_at_company, notes (optional)}
        """
        self.company_name = company_name
        self.employees_data = employees_data
        self.ai_client = PhantomAI()
        self.profiles = []
        self.progress = 0
        self.progress_log = []

    def _log(self, message: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
        }
        self.progress_log.append(entry)
        print(f"[CognitiveProfiler][{level}] {message}")

    # ------------------------------------------------------------------
    # Org Structure Analysis
    # ------------------------------------------------------------------

    def analyze_org_structure(self) -> dict:
        """
        Identify high-value targets and departmental risk structure.

        Returns {high_value_targets, departments, employee_count, risk_groups}.
        """
        high_value = []
        departments = {}

        for employee in self.employees_data:
            title_lower = employee.get("title", "").lower()
            dept = employee.get("department", "Unknown")

            # Count by department
            departments[dept] = departments.get(dept, 0) + 1

            # Identify high-value target category
            hvt_category = _identify_hvt_category(title_lower)
            if hvt_category:
                high_value.append({
                    "name": employee.get("name"),
                    "title": employee.get("title"),
                    "department": dept,
                    "category": hvt_category,
                })

        # Group by risk
        risk_groups = {
            "immediate_priority": [],  # C-suite + Finance
            "high_priority": [],       # IT + HR + Legal
            "standard_priority": [],   # All others
        }

        for hvt in high_value:
            if hvt["category"] in ("c_suite", "finance", "executive_assistant"):
                risk_groups["immediate_priority"].append(hvt)
            elif hvt["category"] in ("it_admin", "hr", "legal"):
                risk_groups["high_priority"].append(hvt)
            else:
                risk_groups["standard_priority"].append(hvt)

        return {
            "high_value_targets": high_value,
            "departments": departments,
            "employee_count": len(self.employees_data),
            "risk_groups": risk_groups,
        }

    # ------------------------------------------------------------------
    # Cognitive Vulnerability Mapping
    # ------------------------------------------------------------------

    def map_cognitive_vulnerabilities(self, employee: dict) -> dict:
        """
        Map likely cognitive biases and vulnerabilities for an employee.

        Returns {name, title, biases (dict of bias: score), overall_vulnerability}.
        """
        title_lower = employee.get("title", "").lower()
        dept_lower = employee.get("department", "").lower()
        years = employee.get("years_at_company", 0)

        try:
            years = float(years)
        except (TypeError, ValueError):
            years = 3  # default assumption

        biases = {}

        # Authority bias — high for new employees and direct reports of execs
        if years < 1:
            biases["authority_bias"] = 9
        elif any(k in title_lower for k in ["junior", "associate", "coordinator", "assistant"]):
            biases["authority_bias"] = 8
        elif any(k in title_lower for k in ["vp", "director", "head of", "senior"]):
            biases["authority_bias"] = 6
        else:
            biases["authority_bias"] = 7

        # Urgency bias — high for finance and operations roles
        if any(k in dept_lower for k in ["finance", "operations", "sales"]):
            biases["urgency_bias"] = 8
        elif any(k in title_lower for k in ["executive", "ceo", "cfo", "coo"]):
            biases["urgency_bias"] = 7
        else:
            biases["urgency_bias"] = 6

        # FOMO — high for IT, security, and competitive roles
        if any(k in dept_lower for k in ["it", "security", "engineering", "product"]):
            biases["fear_of_missing_out"] = 8
        elif any(k in dept_lower for k in ["sales", "marketing", "business development"]):
            biases["fear_of_missing_out"] = 7
        else:
            biases["fear_of_missing_out"] = 5

        # Reciprocity — increases with tenure
        if years > 10:
            biases["reciprocity"] = 8
        elif years > 5:
            biases["reciprocity"] = 7
        elif years > 2:
            biases["reciprocity"] = 6
        else:
            biases["reciprocity"] = 4

        # Social proof — high for new employees and HR/comms roles
        if years < 1:
            biases["social_proof"] = 9
        elif any(k in dept_lower for k in ["hr", "communications", "marketing"]):
            biases["social_proof"] = 7
        else:
            biases["social_proof"] = 5

        # Fear of consequences — high for junior staff and compliance-adjacent roles
        if years < 2 or any(k in dept_lower for k in ["compliance", "legal", "audit"]):
            biases["fear_of_consequences"] = 8
        elif any(k in title_lower for k in ["junior", "coordinator", "intern"]):
            biases["fear_of_consequences"] = 8
        else:
            biases["fear_of_consequences"] = 5

        # Curiosity — high for technical and research roles
        if any(k in dept_lower for k in ["engineering", "research", "data", "ai", "product"]):
            biases["curiosity"] = 7
        else:
            biases["curiosity"] = 5

        overall = sum(biases.values()) / len(biases) * 10
        return {
            "name": employee.get("name"),
            "title": employee.get("title"),
            "biases": biases,
            "overall_vulnerability": round(overall),
        }

    # ------------------------------------------------------------------
    # Attack Window Identification
    # ------------------------------------------------------------------

    def identify_attack_windows(self) -> list:
        """
        Identify organizational moments of elevated vulnerability.
        Returns the standard attack window calendar.
        """
        return MOCK_ATTACK_WINDOWS

    # ------------------------------------------------------------------
    # Individual Risk Profiles
    # ------------------------------------------------------------------

    def generate_risk_profile(self, employee: dict) -> dict:
        """
        Generate a complete risk profile for an individual employee.

        Returns {name, title, department, risk_score, top_vulnerabilities,
                  recommended_attack_type, training_priority}.
        """
        # Map cognitive vulnerabilities
        vuln_map = self.map_cognitive_vulnerabilities(employee)
        biases = vuln_map.get("biases", {})

        # Calculate risk score
        title_lower = employee.get("title", "").lower()
        hvt_category = _identify_hvt_category(title_lower)
        hvt_bonus = 15 if hvt_category in ("c_suite", "finance") else (10 if hvt_category else 0)

        base_score = vuln_map.get("overall_vulnerability", 50)
        risk_score = min(100, base_score + hvt_bonus)

        # Top 3 vulnerabilities
        sorted_biases = sorted(biases.items(), key=lambda x: x[1], reverse=True)
        top_vulnerabilities = [
            {
                "bias": bias,
                "score": score,
                "description": _describe_bias(bias, employee),
            }
            for bias, score in sorted_biases[:3]
        ]

        # Recommended attack type
        recommended_attack = _recommend_attack_type(hvt_category, biases, employee)

        # Training priority
        training_priority = _score_to_priority(risk_score)

        profile = {
            "name": employee.get("name", "Unknown"),
            "title": employee.get("title", "Unknown"),
            "department": employee.get("department", "Unknown"),
            "years_at_company": employee.get("years_at_company", 0),
            "high_value_target": bool(hvt_category),
            "hvt_category": hvt_category,
            "risk_score": risk_score,
            "bias_scores": biases,
            "top_vulnerabilities": top_vulnerabilities,
            "recommended_attack_type": recommended_attack,
            "training_priority": training_priority,
        }

        # Optionally enrich with AI analysis
        if self.ai_client._is_available() and risk_score >= 60:
            try:
                ai_analysis = self.ai_client.analyze_cognitive_profile(employee)
                profile["ai_analysis"] = ai_analysis
            except Exception:
                profile["ai_analysis"] = None
        else:
            profile["ai_analysis"] = None

        return profile

    # ------------------------------------------------------------------
    # Org-Level Heatmap
    # ------------------------------------------------------------------

    def generate_org_heatmap(self) -> dict:
        """
        Return department-level vulnerability scores for heatmap visualization.

        Returns {department: avg_risk_score}.
        """
        if not self.employees_data:
            return MOCK_ORG_HEATMAP

        dept_scores = {}
        dept_counts = {}

        for employee in self.employees_data:
            dept = employee.get("department", "Unknown")
            profile = self.generate_risk_profile(employee)
            score = profile.get("risk_score", 50)

            dept_scores[dept] = dept_scores.get(dept, 0) + score
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

        heatmap = {}
        for dept, total in dept_scores.items():
            count = dept_counts[dept]
            heatmap[dept] = round(total / count)

        return heatmap

    # ------------------------------------------------------------------
    # Full Profiling Run
    # ------------------------------------------------------------------

    def run_full_profiling(self) -> dict:
        """
        Run cognitive profiling across the entire employee roster.
        Returns complete profiling results.
        """
        self._log(f"Starting cognitive profiling for {self.company_name}")
        self.progress = 5

        # Use mock data if no employees provided
        if not self.employees_data:
            self._log("No employee data provided — returning demo profiles", "WARNING")
            return {
                "company": self.company_name,
                "scan_date": datetime.utcnow().isoformat(),
                "profiles": MOCK_PROFILES,
                "org_heatmap": MOCK_ORG_HEATMAP,
                "attack_windows": MOCK_ATTACK_WINDOWS,
                "org_structure": {
                    "employee_count": len(MOCK_PROFILES),
                    "high_value_targets": [p for p in MOCK_PROFILES if p.get("high_value_target")],
                    "departments": {},
                    "risk_groups": {"immediate_priority": [], "high_priority": [], "standard_priority": []},
                },
                "overall_vulnerability_score": 67,
                "profiling_report": "",
                "progress_log": self.progress_log,
            }

        results = {
            "company": self.company_name,
            "scan_date": datetime.utcnow().isoformat(),
            "profiles": [],
            "org_heatmap": {},
            "attack_windows": [],
            "org_structure": {},
            "overall_vulnerability_score": 0,
            "profiling_report": "",
            "progress_log": self.progress_log,
        }

        # Phase 1: Org Structure
        self._log("Phase 1: Analyzing organizational structure...")
        results["org_structure"] = self.analyze_org_structure()
        self.progress = 20

        # Phase 2: Individual Profiles
        self._log("Phase 2: Generating individual risk profiles...")
        total = len(self.employees_data)
        for i, employee in enumerate(self.employees_data):
            profile = self.generate_risk_profile(employee)
            results["profiles"].append(profile)
            self.progress = 20 + int((i / total) * 40)
            self._log(f"  Profiled: {employee.get('name')} — Risk: {profile.get('risk_score')}/100")

        self.profiles = results["profiles"]
        self.progress = 60

        # Phase 3: Org Heatmap
        self._log("Phase 3: Generating organizational vulnerability heatmap...")
        results["org_heatmap"] = self.generate_org_heatmap()
        self.progress = 70

        # Phase 4: Attack Windows
        self._log("Phase 4: Identifying attack windows...")
        results["attack_windows"] = self.identify_attack_windows()
        self.progress = 80

        # Phase 5: Overall Score
        if results["profiles"]:
            total_score = sum(p.get("risk_score", 0) for p in results["profiles"])
            results["overall_vulnerability_score"] = round(total_score / len(results["profiles"]))
        self._log(f"Overall org vulnerability score: {results['overall_vulnerability_score']}/100")

        # Phase 6: Report
        self._log("Phase 6: Generating profiling report...")
        try:
            results["profiling_report"] = self.generate_profiling_report(results["profiles"])
        except Exception as exc:
            self._log(f"Report generation failed: {exc}", "ERROR")
            results["profiling_report"] = _mock_profiling_report(self.company_name)

        self.progress = 100
        self._log("Cognitive profiling complete.", "SUCCESS")
        return results

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_profiling_report(self, profiles: list) -> str:
        """
        Use Claude to generate a detailed cognitive security report.
        """
        if not self.ai_client._is_available():
            return _mock_profiling_report(self.company_name)

        if not profiles:
            return _mock_profiling_report(self.company_name)

        # Summarize key stats
        total = len(profiles)
        critical_count = sum(1 for p in profiles if p.get("training_priority") == "CRITICAL")
        high_count = sum(1 for p in profiles if p.get("training_priority") == "HIGH")
        avg_score = sum(p.get("risk_score", 0) for p in profiles) // max(total, 1)
        hvt_count = sum(1 for p in profiles if p.get("high_value_target"))

        # Top 5 risk profiles
        top_profiles = sorted(profiles, key=lambda p: p.get("risk_score", 0), reverse=True)[:5]
        profile_summaries = "\n".join(
            f"- {p['name']}, {p['title']}: Risk {p.get('risk_score')}/100, "
            f"Top bias: {p.get('top_vulnerabilities', [{}])[0].get('bias', 'N/A') if p.get('top_vulnerabilities') else 'N/A'}"
            for p in top_profiles
        )

        dept_heatmap = self.generate_org_heatmap()
        top_depts = sorted(dept_heatmap.items(), key=lambda x: x[1], reverse=True)[:3]
        dept_summary = ", ".join(f"{d}: {s}/100" for d, s in top_depts)

        prompt = f"""
Write a cognitive security profiling report for {self.company_name}.

Assessment Statistics:
- Employees profiled: {total}
- Critical training priority: {critical_count}
- High training priority: {high_count}
- Average vulnerability score: {avg_score}/100
- High-value targets identified: {hvt_count}

Top Risk Individuals:
{profile_summaries}

Highest Risk Departments: {dept_summary}

Write a comprehensive cognitive security report with these sections:

1. EXECUTIVE SUMMARY — 2 paragraphs on overall human attack surface
2. HIGHEST-RISK TARGETS — Analysis of top 3 most vulnerable individuals and why they're targeted
3. DEPARTMENTAL RISK BREAKDOWN — Which departments are most at risk and why
4. KEY COGNITIVE VULNERABILITIES — The top 3 biases exploited most across the org
5. ATTACK SCENARIOS MOST LIKELY TO SUCCEED — 3 specific scenarios with rationale
6. ATTACK WINDOWS — 3 specific organizational moments of elevated risk
7. TRAINING RECOMMENDATIONS — Prioritized list of training interventions by department
8. 30/60/90 DAY ACTION PLAN — Specific steps for each timeframe

Keep findings specific, actionable, and tied to the data above.
This report is for authorized security awareness improvement purposes.
"""
        return self.ai_client.analyze(prompt)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _identify_hvt_category(title_lower: str) -> str:
    """Return HVT category for a given title, or None."""
    for category, keywords in HIGH_VALUE_ROLES.items():
        if any(kw in title_lower for kw in keywords):
            return category
    return None


def _describe_bias(bias: str, employee: dict) -> str:
    """Return a human-readable description of a bias for a given employee."""
    title = employee.get("title", "this employee")
    descriptions = {
        "authority_bias": f"High compliance with authority figures — {title} likely to follow urgent executive requests without verification",
        "urgency_bias": f"Susceptible to artificial time pressure — {title} may shortcut verification under deadline stress",
        "fear_of_missing_out": f"Concern about missing critical information — likely to open suspicious but 'urgent' messages",
        "reciprocity": f"Strong sense of professional obligation — long relationships create trust that can be exploited",
        "social_proof": f"Follows apparent group behavior — will comply with requests that appear to be organizational norm",
        "fear_of_consequences": f"Motivated by fear of negative outcomes — may comply with threats of account suspension or discipline",
        "curiosity": f"Likely to engage with unusual or intriguing content — click-bait and lure content effective",
    }
    return descriptions.get(bias, f"Elevated {bias.replace('_', ' ')} vulnerability")


def _recommend_attack_type(hvt_category: str, biases: dict, employee: dict) -> str:
    """Recommend the most effective attack type for an employee."""
    top_bias = max(biases.items(), key=lambda x: x[1])[0] if biases else "authority_bias"

    recommendations = {
        "c_suite": "Whaling — direct targeting with executive-grade social engineering",
        "finance": "CEO fraud / BEC — impersonation of exec for fraudulent wire transfer",
        "it_admin": "Vendor impersonation — fake security advisory with malicious patch",
        "hr": "Candidate portal phishing — fake HR management system credential harvest",
        "executive_assistant": "Calendar / meeting phishing — compromising EA to reach exec",
        "legal": "Court document / legal notice phishing — urgency-based credential theft",
    }

    if hvt_category and hvt_category in recommendations:
        return recommendations[hvt_category]

    bias_attacks = {
        "authority_bias": "Executive impersonation — urgent request from apparent authority figure",
        "urgency_bias": "Time-pressure phishing — account expiry or security incident lure",
        "fear_of_missing_out": "Information lure — 'important announcement' or 'security alert' phishing",
        "reciprocity": "Relationship exploitation — impersonation of known colleague or vendor",
        "social_proof": "Mass phishing — 'everyone is doing this' or 'required for all staff' lure",
        "fear_of_consequences": "Threat-based phishing — suspension, legal, or security consequence lure",
        "curiosity": "Lure phishing — intriguing subject line or 'exclusive access' invitation",
    }
    return bias_attacks.get(top_bias, "General spear phishing with personalized content")


def _score_to_priority(score: int) -> str:
    """Convert a numeric risk score to a training priority label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def _mock_profiling_report(company_name: str) -> str:
    return f"""
## Cognitive Security Profiling Report — {company_name}

### Executive Summary

This cognitive security assessment identified significant human attack surface exposure
across multiple departments. Finance and executive staff represent the highest-risk targets,
with authority bias and urgency susceptibility as the dominant vulnerability vectors.
The organization's overall vulnerability score of 67/100 indicates a HIGH risk posture that
requires immediate training intervention for at least 4 identified individuals.

### Highest-Risk Targets

**VP Finance (Risk: 82/100 — CRITICAL)**
Quarter-end time pressure combined with high authority compliance creates a near-ideal
target for CEO fraud attacks. Historical BEC losses in the financial services sector average
$132,000 per incident at companies of similar size.

**CEO (Risk: 65/100 — HIGH)**
The CEO's high reciprocity score (long relationships with executive team) makes them
susceptible to impersonation attacks that leverage trusted colleague relationships. Whaling
attacks targeting executives have a 78% higher success rate than generic phishing.

### Top Cognitive Vulnerabilities Across Organization

1. **Authority Bias (avg: 7.5/10)** — Present across all levels. Most exploitable for
   BEC, vishing, and impersonation attacks.
2. **Urgency Bias (avg: 7.1/10)** — Particularly high in Finance and Operations. Creates
   the most reliable attack opening during high-pressure periods.
3. **Social Proof (avg: 6.3/10)** — Highest in HR and junior staff. Enables mass phishing
   campaigns with "required for all staff" framing.

### Immediate Recommendations

1. Conduct CEO fraud simulation for all Finance staff within 30 days
2. Implement out-of-band verification requirement for all wire transfers over $5,000
3. Deploy security awareness training module on authority manipulation for all staff
4. Brief executive team on whaling tactics and implement personal verification codes
5. Establish "challenge word" system for phone-based verification of sensitive requests
"""
