"""
VPN Security Monitoring Agent
NorthBridge Consulting Group — DMIT2034 Phase 2
----------------------------------------------
Reads Suricata EVE JSON and firewall logs from the past 24 hours,
sends them to the Anthropic Claude API for analysis, and saves a
timestamped daily security digest report.

Requirements:
    pip install anthropic

Usage:
    sudo -E python3 agent.py

Cron (daily at 07:00 MDT):
    0 7 * * * ANTHROPIC_API_KEY=sk-ant-... /usr/bin/python3 /home/aags/vpn_agent/agent.py >> /var/log/vpn_agent.log 2>&1
"""

import json
import os
import sys
import smtplib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from email.mime.text import MIMEText
import anthropic

# ── Configuration ────────────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# Timezone — Mountain Time (Edmonton, AB) UTC-6
MDT = timezone(timedelta(hours=-6))

# Log file paths
SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
OPENVPN_LOG      = "/var/log/openvpn/openvpn.log"
WIREGUARD_LOG    = "/var/log/syslog"

# Where to save daily reports
REPORT_DIR = Path("/home/aags/vpn_agent/reports")

# Optional email alerting
ENABLE_EMAIL  = False
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USER     = "you@gmail.com"
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_TO      = "security@northbridgeconsulting.ca"

# Max log lines to send per source
MAX_SURICATA_EVENTS = 200
MAX_OPENVPN_LINES   = 100

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_mdt() -> datetime:
    """Return current time in Mountain Time (MDT, UTC-6)."""
    return datetime.now(MDT)

def now_utc() -> datetime:
    """Return current time in UTC."""
    return datetime.now(timezone.utc)

def format_mdt(dt: datetime) -> str:
    """Format a datetime as a readable MDT timestamp."""
    return dt.strftime("%Y-%m-%d %H:%M:%S MDT")

# ── Log Collection ────────────────────────────────────────────────────────────

def load_suricata_events(log_path: str, max_events: int) -> list[dict]:
    """
    Parse Suricata EVE JSON log. Each line is a JSON object.
    Filter to last 24 hours and collect alerts, drops, and anomalies.
    """
    events = []
    cutoff = now_utc() - timedelta(hours=24)
    path = Path(log_path)

    if not path.exists():
        print(f"[WARN] Suricata log not found: {log_path}")
        return events

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    ts_str = event.get("timestamp", "")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str[:19]).replace(tzinfo=timezone.utc)
                        if ts < cutoff:
                            continue
                    event_type = event.get("event_type", "")
                    if event_type in ("alert", "drop", "anomaly", "fileinfo"):
                        events.append({
                            "timestamp":  event.get("timestamp", ""),
                            "event_type": event_type,
                            "src_ip":     event.get("src_ip", ""),
                            "dest_ip":    event.get("dest_ip", ""),
                            "proto":      event.get("proto", ""),
                            "alert":      event.get("alert", {}).get("signature", "") if event_type == "alert" else "",
                            "severity":   event.get("alert", {}).get("severity", "") if event_type == "alert" else "",
                            "category":   event.get("alert", {}).get("category", "") if event_type == "alert" else "",
                        })
                except (json.JSONDecodeError, ValueError):
                    continue
    except PermissionError:
        print(f"[ERROR] Permission denied reading {log_path}. Run with sudo -E.")

    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events[:max_events]


def load_text_log(log_path: str, max_lines: int, keyword_filter: list[str] = None) -> str:
    """
    Load a plain-text log file, optionally filtering by keywords.
    Returns last max_lines matching lines as a single string.
    """
    path = Path(log_path)
    if not path.exists():
        return f"[Log not found: {log_path}]"

    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except PermissionError:
        return f"[Permission denied: {log_path}]"

    if keyword_filter:
        lines = [l for l in lines if any(kw.lower() in l.lower() for kw in keyword_filter)]

    return "".join(lines[-max_lines:])


def load_wireguard_stats() -> str:
    """Run wg show to get live WireGuard peer status."""
    try:
        import subprocess
        result = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=5)
        return result.stdout if result.returncode == 0 else "[wg show unavailable]"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "[wg command not found — ensure WireGuard is installed]"


def load_fail2ban_status() -> str:
    """Get Fail2ban jail status summary."""
    try:
        import subprocess
        result = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout if result.returncode == 0 else "[fail2ban-client unavailable]"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "[fail2ban not found]"


# ── Claude API Analysis ───────────────────────────────────────────────────────

def build_prompt(
    suricata_events: list[dict],
    openvpn_log: str,
    wg_stats: str,
    fail2ban_status: str,
    report_date: str,
    report_time: str,
) -> str:
    suricata_summary = json.dumps(suricata_events, indent=2) if suricata_events else "No Suricata events in the last 24 hours."

    prompt = f"""You are a network security analyst reviewing logs for NorthBridge Consulting Group's VPN infrastructure.

Report date: {report_date}
Report time: {report_time}
Timezone: Mountain Time (MDT, UTC-6) — Edmonton, Alberta, Canada
Review period: Last 24 hours

Your job is to produce a concise daily security digest. Be direct and actionable — this report goes to an IT administrator, not an executive.

---
SURICATA IDS/IPS EVENTS ({len(suricata_events)} events):
{suricata_summary}

---
OPENVPN LOG (last 100 lines):
{openvpn_log}

---
WIREGUARD PEER STATUS:
{wg_stats}

---
FAIL2BAN STATUS:
{fail2ban_status}

---

Please produce a report in exactly this format:

## VPN Security Daily Digest — {report_date} {report_time}

### Overall risk level
[ROUTINE / ELEVATED / CRITICAL] — one word followed by a one-sentence justification.

### Summary
2-4 sentences covering the most important things that happened in the last 24 hours.

### Suricata alerts
List any significant IDS/IPS events. Group by source IP if there are repeats. If none, say "No significant alerts."

### VPN connection activity
Summarize OpenVPN and WireGuard activity — new connections, disconnections, authentication failures, unusual patterns.

### Blocked threats
What did Fail2ban ban? Any IPs blocked by the firewall? List IPs and reason if available.

### Anomalies and concerns
Anything unusual that doesn't fit the above categories. If nothing, say "None detected."

### Recommended actions
Up to 3 specific, actionable recommendations based on today's data. If everything looks routine, say so.
"""
    return prompt


def analyze_with_claude(prompt: str) -> str:
    """Send logs to Claude API and return the analysis."""
    if not ANTHROPIC_API_KEY:
        return "[ERROR] ANTHROPIC_API_KEY environment variable not set. Export it before running."

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    except anthropic.APIConnectionError:
        return "[ERROR] Could not connect to Anthropic API. Check network connectivity."
    except anthropic.RateLimitError:
        return "[ERROR] Anthropic API rate limit reached. Will retry on next run."
    except anthropic.APIStatusError as e:
        return f"[ERROR] Anthropic API error {e.status_code}: {e.message}"


# ── Report Saving ─────────────────────────────────────────────────────────────

def save_report(report_text: str, report_date: str, report_time: str) -> Path:
    """Save the report to a timestamped markdown file."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"security_digest_{report_date.replace('-', '')}.md"
    report_path = REPORT_DIR / filename

    with open(report_path, "w") as f:
        f.write(report_text)
        f.write("\n\n---\n")
        f.write(f"*Generated by VPN Security Agent — {report_date} {report_time}*\n")
        f.write(f"*NorthBridge Consulting Group — DMIT2034 Phase 2*\n")

    return report_path


def send_email_alert(report_text: str, report_date: str, risk_level: str):
    """Send digest via email if ENABLE_EMAIL is True."""
    if not ENABLE_EMAIL:
        return

    subject = f"[{risk_level}] VPN Security Digest — {report_date}"
    msg = MIMEText(report_text)
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_TO

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[INFO] Email alert sent to {ALERT_TO}")
    except Exception as e:
        print(f"[WARN] Email sending failed: {e}")


def extract_risk_level(report_text: str) -> str:
    """Parse the risk level from the report."""
    for line in report_text.splitlines():
        upper = line.upper()
        if "ROUTINE" in upper:
            return "ROUTINE"
        if "ELEVATED" in upper:
            return "ELEVATED"
        if "CRITICAL" in upper:
            return "CRITICAL"
    return "UNKNOWN"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    now         = now_mdt()
    report_date = now.strftime("%Y-%m-%d")
    report_time = now.strftime("%H:%M:%S MDT")

    print(f"[{format_mdt(now)}] VPN Security Agent starting — {report_date}")

    print("[INFO] Loading Suricata events...")
    suricata_events = load_suricata_events(SURICATA_EVE_LOG, MAX_SURICATA_EVENTS)
    print(f"[INFO] {len(suricata_events)} Suricata events found in last 24h")

    print("[INFO] Loading OpenVPN log...")
    openvpn_log = load_text_log(
        OPENVPN_LOG,
        MAX_OPENVPN_LINES,
        keyword_filter=["error", "warning", "client", "connected", "disconnected", "auth", "failed"]
    )

    print("[INFO] Getting WireGuard status...")
    wg_stats = load_wireguard_stats()

    print("[INFO] Getting Fail2ban status...")
    fail2ban_status = load_fail2ban_status()

    print("[INFO] Sending logs to Claude API for analysis...")
    prompt = build_prompt(suricata_events, openvpn_log, wg_stats, fail2ban_status, report_date, report_time)
    report = analyze_with_claude(prompt)

    if report.startswith("[ERROR]"):
        print(report)
        sys.exit(1)

    report_path = save_report(report, report_date, report_time)
    print(f"[INFO] Report saved: {report_path}")

    print("\n" + "="*60)
    print(report)
    print("="*60 + "\n")

    risk_level = extract_risk_level(report)
    send_email_alert(report, report_date, risk_level)

    print(f"[{format_mdt(now_mdt())}] Agent completed. Risk level: {risk_level}")


if __name__ == "__main__":
    main()
