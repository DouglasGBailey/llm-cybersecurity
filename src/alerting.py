"""Email alerting: notifies when a diff has new findings.

Opt-in via file presence -- if config/alerts.yaml doesn't exist, alerting
is silently a no-op (same convention as ScopeGuard's scope.yaml and
AiTriageAnalyzer's --ai-triage flag: absence means "not configured", not
an error).

Credentials are NEVER read directly from alerts.yaml -- the config
references environment variable NAMES (username_env/password_env),
resolved at send time. This mirrors why scope.yaml/llm_probes.yaml are
gitignored: a real SMTP password has no business sitting in a plaintext
config file on disk, even a gitignored one.

A send failure (bad SMTP host, auth failure, network issue) is logged and
swallowed -- alerting is a side effect of a successful scan, and must
never cause the scan run itself to fail or crash.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import yaml

from src.agents.report_generator import format_finding_detail
from src.logging_setup import get_logger, log_with_fields

DEFAULT_ALERTS_CONFIG = Path(__file__).resolve().parent.parent / "config" / "alerts.yaml"

logger = get_logger("alerting")


def load_alert_config(path: str | Path = DEFAULT_ALERTS_CONFIG) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists():
        return None
    with path.open() as f:
        return yaml.safe_load(f) or {}


def format_alert_email(target_name: str, diff: dict[str, Any]) -> tuple[str, str]:
    new_findings = diff.get("new_findings", [])
    resolved_count = len(diff.get("resolved_findings", []))
    unchanged_count = len(diff.get("unchanged_findings", []))

    subject = f"[security-scan] {len(new_findings)} new finding(s) on {target_name}"

    lines = [
        f"New findings detected on '{target_name}' since the last scan:",
        "",
    ]
    for finding in new_findings:
        ftype = finding.get("type", "unknown")
        detail = format_finding_detail(finding)
        lines.append(f"- {ftype}" + (f" ({detail})" if detail else ""))
    lines.append("")
    lines.append(f"{resolved_count} finding(s) resolved, {unchanged_count} unchanged since last scan.")
    lines.append("")
    lines.append("See the full report in reports/ for details.")
    body = "\n".join(lines)

    return subject, body


def send_email_alert(config: dict[str, Any], subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["from_addr"]
    msg["To"] = ", ".join(config["to_addrs"])
    msg.set_content(body)

    with smtplib.SMTP(config["smtp_host"], config.get("smtp_port", 587), timeout=15) as smtp:
        if config.get("use_tls", True):
            smtp.starttls()
        username_env = config.get("username_env")
        password_env = config.get("password_env")
        if username_env and password_env:
            username = os.environ.get(username_env)
            password = os.environ.get(password_env)
            if not username or not password:
                raise RuntimeError(
                    f"alerts.yaml references {username_env}/{password_env} but one or both "
                    "are not set in the environment"
                )
            smtp.login(username, password)
        smtp.send_message(msg)


def send_alerts(
    target_name: str, diff: dict[str, Any], config_path: str | Path = DEFAULT_ALERTS_CONFIG
) -> list[str]:
    if not diff.get("has_new_findings"):
        return []

    config = load_alert_config(config_path)
    if config is None:
        return []

    subject, body = format_alert_email(target_name, diff)
    try:
        send_email_alert(config, subject, body)
    except Exception as e:  # noqa: BLE001 - alerting must never crash the scan run
        log_with_fields(logger, logging.ERROR, f"failed to send email alert: {e}", target=target_name)
        return []

    return ["email"]
