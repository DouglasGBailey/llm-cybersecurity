import subprocess
import textwrap
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.agents.infra_analyzer import InfraAnalyzer
from src.scope_guard import OutOfScopeError, ScopeGuard


@pytest.fixture
def guard(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
    """))
    return ScopeGuard(p)


def fake_dig(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def make_self_signed_cert_der(common_name: str, not_valid_after: datetime) -> bytes:
    """Build a throwaway self-signed cert DER blob for testing cert parsing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_after - timedelta(days=365))
        .not_valid_after(not_valid_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_out_of_scope_target_rejected_before_any_check(guard):
    agent = InfraAnalyzer(guard, dry_run=False)
    with patch("subprocess.run") as mock_run, patch.object(InfraAnalyzer, "_fetch_peer_cert") as mock_cert:
        with pytest.raises(OutOfScopeError):
            agent.run("evil.example.com")
        mock_run.assert_not_called()
        mock_cert.assert_not_called()


def test_dry_run_makes_no_real_connections(guard):
    agent = InfraAnalyzer(guard, dry_run=True)
    with patch("subprocess.run") as mock_run, patch("shutil.which", return_value="/usr/bin/fake"), \
         patch.object(InfraAnalyzer, "_fetch_peer_cert") as mock_cert:
        result = agent.run("127.0.0.1:8443")
        mock_run.assert_not_called()
        mock_cert.assert_not_called()
    assert result.status == "ok"


def test_no_port_given_skips_tls_check_without_guessing(guard):
    """Regression test: must never default to port 443. On a shared host,
    an authorized bare IP does not authorize probing every port on it."""
    agent = InfraAnalyzer(guard, dry_run=False)
    with patch.object(InfraAnalyzer, "_fetch_peer_cert") as mock_cert, \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_dig):
        result = agent.run("127.0.0.1")
        mock_cert.assert_not_called()
    assert [f for f in result.findings if f["type"] == "tls-check-skipped"]


def test_tls_certificate_valid_reports_days_remaining(guard):
    agent = InfraAnalyzer(guard, dry_run=False)
    not_after = datetime.now(timezone.utc) + timedelta(days=90)
    der_cert = make_self_signed_cert_der("127.0.0.1", not_after)
    with patch.object(InfraAnalyzer, "_fetch_peer_cert", return_value=der_cert), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_dig):
        result = agent.run("127.0.0.1:8443")

    cert_findings = [f for f in result.findings if f["type"] == "tls-certificate"]
    assert cert_findings
    assert cert_findings[0]["subject_cn"] == "127.0.0.1"
    assert cert_findings[0]["days_remaining"] >= 89
    assert not [f for f in result.findings if f["type"] == "tls-certificate-expiring-soon"]
    assert not [f for f in result.findings if f["type"] == "tls-certificate-expired"]


def test_tls_certificate_expiring_soon_flagged(guard):
    agent = InfraAnalyzer(guard, dry_run=False)
    not_after = datetime.now(timezone.utc) + timedelta(days=10)
    der_cert = make_self_signed_cert_der("127.0.0.1", not_after)
    with patch.object(InfraAnalyzer, "_fetch_peer_cert", return_value=der_cert), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_dig):
        result = agent.run("127.0.0.1:8443")

    assert [f for f in result.findings if f["type"] == "tls-certificate-expiring-soon"]


def test_tls_certificate_expired_flagged(guard):
    agent = InfraAnalyzer(guard, dry_run=False)
    not_after = datetime.now(timezone.utc) - timedelta(days=5)
    der_cert = make_self_signed_cert_der("127.0.0.1", not_after)
    with patch.object(InfraAnalyzer, "_fetch_peer_cert", return_value=der_cert), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_dig):
        result = agent.run("127.0.0.1:8443")

    assert [f for f in result.findings if f["type"] == "tls-certificate-expired"]


def test_tls_connection_failure_recorded_not_crashed(guard):
    agent = InfraAnalyzer(guard, dry_run=False)
    with patch.object(InfraAnalyzer, "_fetch_peer_cert", side_effect=ConnectionRefusedError("no TLS here")), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_dig):
        result = agent.run("127.0.0.1:8443")

    assert result.status == "ok"
    assert [f for f in result.findings if f["type"] == "tls-unavailable"]


def test_spf_dmarc_dnssec_parsed_from_dig_output(guard):
    agent = InfraAnalyzer(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        if "TXT" in cmd and "_dmarc.127.0.0.1" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout='"v=DMARC1; p=reject"\n', stderr="")
        if "TXT" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout='"v=spf1 include:_spf.example.com -all"\n', stderr="")
        if "+dnssec" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="RRSIG A 8 2 3600 ...\nA 93.184.216.34\n", stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    with patch.object(InfraAnalyzer, "_fetch_peer_cert", side_effect=ConnectionRefusedError("no tls")), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_run):
        result = agent.run("127.0.0.1")

    types = {f["type"] for f in result.findings}
    assert "spf-record-found" in types
    assert "dmarc-record-found" in types
    assert "dnssec-enabled" in types


def test_missing_spf_dmarc_flagged_when_txt_records_exist_but_dont_match(guard):
    agent = InfraAnalyzer(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        if "+dnssec" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="A 93.184.216.34\n", stderr="")
        # some unrelated TXT record present, but not SPF/DMARC
        return subprocess.CompletedProcess(cmd, 0, stdout='"google-site-verification=abc123"\n', stderr="")

    with patch.object(InfraAnalyzer, "_fetch_peer_cert", side_effect=ConnectionRefusedError("no tls")), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_run):
        result = agent.run("127.0.0.1")

    types = {f["type"] for f in result.findings}
    assert "spf-record-missing" in types
    assert "dmarc-record-missing" in types
    assert "dnssec-enabled" not in types


def test_missing_spf_dmarc_flagged_when_no_txt_records_at_all(guard):
    """Regression: a domain with zero TXT records (dig returns empty
    output, not just a non-matching record) must still be flagged missing,
    not silently skipped."""
    agent = InfraAnalyzer(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with patch.object(InfraAnalyzer, "_fetch_peer_cert", side_effect=ConnectionRefusedError("no tls")), \
         patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=fake_run):
        result = agent.run("127.0.0.1")

    types = {f["type"] for f in result.findings}
    assert "spf-record-missing" in types
    assert "dmarc-record-missing" in types
