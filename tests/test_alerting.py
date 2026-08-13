import textwrap
from unittest.mock import MagicMock, patch

import pytest

from src.alerting import format_alert_email, load_alert_config, send_alerts


@pytest.fixture
def diff_with_new_findings():
    return {
        "is_first_run": False,
        "new_findings": [{"type": "tls-certificate-expired", "not_after": "2020-01-01T00:00:00+00:00"}],
        "resolved_findings": [],
        "unchanged_findings": [{"type": "open-port", "port": 80}],
        "has_new_findings": True,
    }


@pytest.fixture
def diff_with_no_new_findings():
    return {
        "is_first_run": False,
        "new_findings": [],
        "resolved_findings": [],
        "unchanged_findings": [{"type": "open-port", "port": 80}],
        "has_new_findings": False,
    }


@pytest.fixture
def alerts_config_path(tmp_path):
    p = tmp_path / "alerts.yaml"
    p.write_text(textwrap.dedent("""
        smtp_host: smtp.example.com
        smtp_port: 587
        use_tls: true
        username_env: TEST_SMTP_USER
        password_env: TEST_SMTP_PASS
        from_addr: scanner@example.com
        to_addrs:
          - alerts@example.com
    """))
    return p


def test_load_alert_config_returns_none_when_missing(tmp_path):
    assert load_alert_config(tmp_path / "does-not-exist.yaml") is None


def test_load_alert_config_parses_present_file(alerts_config_path):
    config = load_alert_config(alerts_config_path)
    assert config["smtp_host"] == "smtp.example.com"
    assert config["to_addrs"] == ["alerts@example.com"]


def test_no_config_means_no_alert_sent(tmp_path, diff_with_new_findings):
    with patch("smtplib.SMTP") as mock_smtp:
        channels = send_alerts("local-dvwa", diff_with_new_findings, config_path=tmp_path / "missing.yaml")
        mock_smtp.assert_not_called()
    assert channels == []


def test_no_new_findings_means_no_alert_sent(alerts_config_path, diff_with_no_new_findings):
    with patch("smtplib.SMTP") as mock_smtp:
        channels = send_alerts("local-dvwa", diff_with_no_new_findings, config_path=alerts_config_path)
        mock_smtp.assert_not_called()
    assert channels == []


def test_alert_sent_with_resolved_credentials(monkeypatch, alerts_config_path, diff_with_new_findings):
    monkeypatch.setenv("TEST_SMTP_USER", "resolved-user")
    monkeypatch.setenv("TEST_SMTP_PASS", "resolved-pass")

    mock_conn = MagicMock()
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.return_value.__enter__.return_value = mock_conn
        channels = send_alerts("local-dvwa", diff_with_new_findings, config_path=alerts_config_path)

    assert channels == ["email"]
    mock_conn.starttls.assert_called_once()
    mock_conn.login.assert_called_once_with("resolved-user", "resolved-pass")
    mock_conn.send_message.assert_called_once()
    sent_msg = mock_conn.send_message.call_args[0][0]
    assert "1 new finding(s)" in sent_msg["Subject"]
    assert sent_msg["To"] == "alerts@example.com"


def test_missing_env_vars_fails_gracefully(monkeypatch, alerts_config_path, diff_with_new_findings):
    monkeypatch.delenv("TEST_SMTP_USER", raising=False)
    monkeypatch.delenv("TEST_SMTP_PASS", raising=False)

    mock_conn = MagicMock()
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.return_value.__enter__.return_value = mock_conn
        channels = send_alerts("local-dvwa", diff_with_new_findings, config_path=alerts_config_path)

    assert channels == []
    mock_conn.send_message.assert_not_called()


def test_smtp_exception_is_caught_not_raised(monkeypatch, alerts_config_path, diff_with_new_findings):
    monkeypatch.setenv("TEST_SMTP_USER", "u")
    monkeypatch.setenv("TEST_SMTP_PASS", "p")

    with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
        channels = send_alerts("local-dvwa", diff_with_new_findings, config_path=alerts_config_path)

    assert channels == []


def test_format_alert_email_includes_finding_details():
    diff = {
        "new_findings": [{"type": "open-port", "port": 8080}],
        "resolved_findings": [{"type": "server-banner", "value": "old"}],
        "unchanged_findings": [{"type": "a"}, {"type": "b"}],
    }
    subject, body = format_alert_email("local-dvwa", diff)
    assert "local-dvwa" in subject
    assert "open-port" in body
    assert "port=8080" in body
    assert "1 finding(s) resolved" in body
    assert "2 unchanged" in body
