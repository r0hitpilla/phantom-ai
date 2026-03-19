# PHANTOM AI — Next-Generation Offensive AI Cybersecurity Platform

A futuristic AI-powered red team platform built for authorized security testing. PHANTOM AI simulates the attacks of the next 5–10 years — AI vs AI — so your defenses can stay ahead.

> ⚠️ **Authorized use only.** This platform is designed exclusively for companies testing their own systems, licensed penetration testers, and security researchers. All usage is logged and requires explicit authorization confirmation.

---

## What This Does

- **AI Scanner** — Tests your AI endpoints for prompt injection, jailbreaks, and data exfiltration vulnerabilities
- **Deepfake Simulator** — Generates realistic social engineering scenarios (voice, video, text) to test employee awareness
- **Red Team Agent** — Autonomous AI agent that chains OSINT → attack paths → executive narrative reports
- **Supply Chain Scanner** — Detects vulnerable AI dependencies and simulates poisoning attacks on your ML pipeline
- **Cognitive Profiler** — Maps employee behavioral vulnerabilities and generates org-wide risk heatmaps

---

## Features

| Feature | Details |
|---|---|
| AI-Native Attacks | Tests vulnerabilities unique to LLM/AI systems (prompt injection, model extraction) |
| Autonomous Red Team | AI agent that plans and simulates multi-step attack chains |
| Deepfake Campaign Sim | Voice + video + text social engineering test scenarios |
| Supply Chain Risk | Scans AI dependencies for poisoning and backdoor vulnerabilities |
| Cognitive Profiling | OSINT-based employee vulnerability mapping with org heatmap |
| PDF Reports | Executive-ready reports for every scan |
| Authorization Gate | Explicit legal consent required before any test runs |

---

## Tech Stack

- **Backend:** Python, Flask, Gunicorn
- **AI Engine:** Anthropic Claude (claude-sonnet-4-6)
- **Frontend:** Custom dark terminal UI with matrix rain animation
- **Hosting:** Railway
- **Optional:** ElevenLabs (voice deepfake), Shodan (attack surface)

---

## Setup (Run Locally)

### 1. Clone the repo
```bash
git clone https://github.com/r0hitpilla/phantom-ai.git
cd phantom-ai
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Add your API keys
Edit `config.py` or set environment variables:
```bash
ANTHROPIC_API_KEY=your_anthropic_key
PHANTOM_PASSWORD=your_login_password
SECRET_KEY=your_random_secret_key
```

### 4. Run
```bash
python app.py
```
Open `http://localhost:5000` — login with your password.

> Works without API keys too — all modules fall back to realistic mock data for demos.

---

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Add environment variables:

| Variable | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `PHANTOM_PASSWORD` | Login password for the platform |
| `SECRET_KEY` | Random 32-char secret string |

---

## Modules

### AI Scanner
Tests AI endpoints for prompt injection, jailbreaks, model extraction, and data leakage. Generates risk scores and remediation steps.

### Deepfake Simulator
Creates and tracks synthetic social engineering campaigns — voice clones, video scenarios, phishing text. Tests human detection rates.

### Red Team Agent
Autonomous AI that performs OSINT on a target domain, generates multi-stage attack chains, and writes executive-level narrative reports.

### Supply Chain Scanner
Identifies AI/ML dependencies in your stack, flags known vulnerabilities, and simulates dependency poisoning attacks.

### Cognitive Profiler
Maps individual employee behavioral profiles using OSINT, identifies social engineering susceptibility, and generates org-wide vulnerability heatmaps.

---

## Important Disclaimer

> ⚠️ PHANTOM AI is for **authorized security testing only**.
> You must own or have explicit written permission to test any target system.
> Unauthorized use is illegal. The developers are not responsible for misuse.
> All sessions require authorization confirmation before scanning begins.

---

Built for the security teams of the future.
