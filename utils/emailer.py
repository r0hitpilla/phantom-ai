"""
Phantom AI — Email Notification Utility
Sends scan completion emails with PDF report download links.

Required environment variables:
  SMTP_USER      — Gmail address (e.g. you@gmail.com)
  SMTP_PASS      — Gmail App Password (16-char, from Google Account > Security > App Passwords)
  NOTIFY_EMAIL   — Recipient email address
  APP_URL        — Your Railway app URL (e.g. https://phantom-ai-production.up.railway.app)
"""

import os
import smtplib
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


class EmailNotifier:
    def __init__(self):
        self.smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("SMTP_USER", "")
        self.smtp_pass = os.environ.get("SMTP_PASS", "")
        self.notify_email = os.environ.get("NOTIFY_EMAIL", "")
        self.app_url = os.environ.get(
            "APP_URL", "https://phantom-ai-production.up.railway.app"
        ).rstrip("/")

    def is_configured(self) -> bool:
        return bool(self.smtp_user and self.smtp_pass and self.notify_email)

    def send_scan_complete(self, job_id: str, job_data: dict) -> bool:
        """Send a scan completion email with PDF download link."""
        if not self.is_configured():
            print("[Emailer] Not configured — skipping notification.")
            return False

        try:
            results = job_data.get("results") or {}
            module = job_data.get("module", "Security Assessment")
            target = job_data.get("target", "Unknown")
            created_at = job_data.get("created_at", "")[:16].replace("T", " ")
            risk_score = (
                results.get("risk_score")
                or results.get("overall_vulnerability_score")
                or "N/A"
            )

            # Severity counts
            counts = results.get("findings_count", {})
            critical = counts.get("critical", 0)
            high = counts.get("high", 0)
            medium = counts.get("medium", 0)
            low = counts.get("low", 0)
            total = sum(counts.values()) if counts else "—"

            pdf_url = f"{self.app_url}/api/report/{job_id}"
            dashboard_url = f"{self.app_url}/dashboard"

            risk_color = "#FF3E3E" if isinstance(risk_score, int) and risk_score >= 75 \
                else "#FF8C00" if isinstance(risk_score, int) and risk_score >= 50 \
                else "#00D4FF"

            html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e1a; margin: 0; padding: 20px; }}
  .container {{ max-width: 600px; margin: 0 auto; background: #0d1224; border: 1px solid rgba(0,212,255,0.2); border-radius: 12px; overflow: hidden; }}
  .header {{ background: linear-gradient(135deg, #0a0e1a 0%, #1a0a2e 100%); padding: 30px; text-align: center; border-bottom: 1px solid rgba(0,212,255,0.2); }}
  .logo {{ font-size: 28px; font-weight: 900; letter-spacing: 4px; color: #FF3E3E; margin: 0; }}
  .logo-sub {{ color: #00D4FF; font-size: 12px; letter-spacing: 3px; margin-top: 4px; }}
  .body {{ padding: 30px; }}
  .scan-complete-badge {{ display: inline-block; background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.3); color: #00D4FF; padding: 4px 14px; border-radius: 20px; font-size: 12px; letter-spacing: 2px; font-weight: 700; margin-bottom: 20px; }}
  h2 {{ color: #fff; font-size: 20px; margin: 0 0 8px 0; }}
  .target {{ color: #00D4FF; font-family: monospace; font-size: 14px; margin-bottom: 24px; }}
  .risk-score {{ text-align: center; padding: 20px; background: rgba(0,0,0,0.3); border-radius: 10px; margin: 20px 0; }}
  .risk-num {{ font-size: 52px; font-weight: 900; color: {risk_color}; line-height: 1; }}
  .risk-label {{ color: #666; font-size: 12px; margin-top: 4px; }}
  .stats-row {{ display: flex; gap: 10px; margin: 20px 0; }}
  .stat {{ flex: 1; text-align: center; padding: 12px; border-radius: 8px; }}
  .stat.critical {{ background: rgba(255,62,62,0.1); border: 1px solid rgba(255,62,62,0.2); }}
  .stat.high {{ background: rgba(255,140,0,0.1); border: 1px solid rgba(255,140,0,0.2); }}
  .stat.medium {{ background: rgba(255,215,0,0.08); border: 1px solid rgba(255,215,0,0.2); }}
  .stat.low {{ background: rgba(0,255,136,0.06); border: 1px solid rgba(0,255,136,0.15); }}
  .stat-num {{ font-size: 22px; font-weight: 900; }}
  .stat.critical .stat-num {{ color: #FF3E3E; }}
  .stat.high .stat-num {{ color: #FF8C00; }}
  .stat.medium .stat-num {{ color: #FFD700; }}
  .stat.low .stat-num {{ color: #00FF88; }}
  .stat-label {{ font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 1px; }}
  .btn {{ display: block; text-align: center; padding: 14px 20px; border-radius: 8px; font-weight: 700; font-size: 14px; letter-spacing: 1px; text-decoration: none; margin: 10px 0; }}
  .btn-primary {{ background: linear-gradient(135deg, #FF3E3E, #cc0000); color: #fff; }}
  .btn-secondary {{ background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.3); color: #00D4FF; }}
  .meta {{ color: #444; font-size: 11px; margin-top: 24px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); }}
  .footer {{ background: #060a14; padding: 16px 30px; text-align: center; color: #333; font-size: 11px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">PHANTOM AI</div>
    <div class="logo-sub">AUTHORIZED SECURITY TESTING PLATFORM</div>
  </div>
  <div class="body">
    <div class="scan-complete-badge">SCAN COMPLETE</div>
    <h2>{module} Report Ready</h2>
    <div class="target">Target: {target}</div>

    <div class="risk-score">
      <div class="risk-num">{risk_score}</div>
      <div class="risk-label">OVERALL RISK SCORE / 100</div>
    </div>

    <div class="stats-row">
      <div class="stat critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
      <div class="stat medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
    </div>

    <a href="{pdf_url}" class="btn btn-primary">DOWNLOAD PDF REPORT</a>
    <a href="{dashboard_url}" class="btn btn-secondary">VIEW DASHBOARD</a>

    <div class="meta">
      Job ID: {job_id}<br/>
      Module: {module}<br/>
      Completed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC<br/>
      Total Findings: {total}
    </div>
  </div>
  <div class="footer">
    PHANTOM AI &mdash; Authorized Security Testing Only &mdash; Confidential Report
  </div>
</div>
</body>
</html>"""

            plain = (
                f"PHANTOM AI — Scan Complete\n\n"
                f"Module: {module}\n"
                f"Target: {target}\n"
                f"Risk Score: {risk_score}/100\n"
                f"Findings: {critical} Critical, {high} High, {medium} Medium, {low} Low\n\n"
                f"Download PDF Report:\n{pdf_url}\n\n"
                f"View Dashboard:\n{dashboard_url}\n\n"
                f"Job ID: {job_id}\n"
                f"This report is confidential — authorized security testing only.\n"
            )

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[PHANTOM AI] {module} Complete — {target} — Risk Score: {risk_score}/100"
            msg["From"] = f"PHANTOM AI <{self.smtp_user}>"
            msg["To"] = self.notify_email
            msg.attach(MIMEText(plain, "plain"))
            msg.attach(MIMEText(html, "html"))

            # Try STARTTLS (port 587) first, fall back to SSL (port 465)
            try:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.ehlo()
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_pass)
                    server.sendmail(self.smtp_user, self.notify_email, msg.as_string())
            except OSError:
                # Port 587 blocked (common on Railway) — try SSL on port 465
                with smtplib.SMTP_SSL(self.smtp_host, 465) as server:
                    server.login(self.smtp_user, self.smtp_pass)
                    server.sendmail(self.smtp_user, self.notify_email, msg.as_string())

            print(f"[Emailer] Notification sent to {self.notify_email} for job {job_id[:8]}")
            return True

        except OSError as e:
            print(f"[Emailer] Network unreachable — SMTP blocked by host (job {job_id[:8]}): {e}")
            return False
        except smtplib.SMTPException as e:
            print(f"[Emailer] SMTP error for job {job_id[:8]}: {e}")
            return False
        except Exception:
            traceback.print_exc()
            return False


# Singleton
notifier = EmailNotifier()
