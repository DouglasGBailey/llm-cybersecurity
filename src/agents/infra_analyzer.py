"""Infrastructure Analyzer: TLS certificate hygiene and DNS security records.

Scope: a read-only TLS handshake (via Python's `ssl`/`socket` standard
library -- no external binary needed) to inspect certificate validity and
subject, plus DNS TXT record checks for SPF/DMARC and a DNSSEC presence
check via `dig`. No exploitation, no key extraction beyond what any normal
TLS client sees during a handshake.

Deliberately deferred: cloud-metadata-endpoint checks (e.g. probing
169.254.169.254) are NOT implemented here. That check targets the scanning
host's own environment, not the authorized remote target -- adding it would
mean this agent reaches outside the scope boundary that ScopeGuard enforces
everywhere else. Left as a documented TODO rather than implemented unsafely.

IMPORTANT: the TLS check never assumes a default port (e.g. 443). On a
shared host, `scope.yaml` authorizing a bare IP like 127.0.0.1 does not mean
every port on that IP belongs to the target you intend to test -- other
unrelated services may be listening on other ports of the same loopback/LAN
address. The TLS certificate check only runs when the target string
explicitly includes a port (`host:port`, e.g. via a target's `tls_port` in
scope.yaml); otherwise it's skipped and recorded as such, never guessed.
"""
from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields

CERT_EXPIRY_WARNING_DAYS = 30


class InfraAnalyzer(BaseAgent):
    name = "infra-analyzer"
    # TLS inspection uses Python's ssl/socket standard library (no external
    # binary). `dig` is used for DNS TXT/DNSSEC record checks.
    allowed_tools = ["dig"]
    tls_timeout_seconds = 10

    def run(self, target: str) -> AgentResult:
        host, port = self._split_host_port(target)
        self.scope_guard.authorize(host)
        result = AgentResult(
            agent_name=self.name, target=target, timestamp=self._now(), status="ok"
        )

        if port is None:
            # No explicit port given -- do NOT guess 443. On a shared host,
            # an authorized bare IP does not authorize scanning every port
            # on it; only a target with `tls_port` set in scope.yaml gets a
            # TLS check.
            result.findings.append({
                "type": "tls-check-skipped",
                "detail": "no tls_port configured for this target; TLS check not run",
            })
        else:
            try:
                self._check_tls_certificate(host, port, result)
            except Exception as e:  # noqa: BLE001 - connection refused/timeout/non-TLS port etc.
                log_with_fields(self.logger, logging.WARNING, str(e), target=host)
                result.findings.append({"type": "tls-unavailable", "detail": str(e)})

        for step in (self._check_spf, self._check_dmarc, self._check_dnssec):
            try:
                step(host, result)
            except FileNotFoundError as e:
                log_with_fields(self.logger, logging.WARNING, str(e), target=host)
                result.findings.append({"type": "tool-unavailable", "detail": str(e)})
            except Exception as e:  # noqa: BLE001 - surface any tool failure as a finding
                log_with_fields(self.logger, logging.ERROR, str(e), target=host)
                result.findings.append({"type": "error", "step": step.__name__, "detail": str(e)})

        return result

    @staticmethod
    def _split_host_port(target: str) -> tuple[str, int | None]:
        if ":" in target:
            host, _, port_str = target.rpartition(":")
            try:
                return host, int(port_str)
            except ValueError:
                return target, None
        return target, None

    def _check_tls_certificate(self, host: str, port: int, result: AgentResult) -> None:
        self._respect_rate_limit()
        log_with_fields(self.logger, logging.INFO, "TLS handshake", host=host, port=port)
        if self.dry_run:
            log_with_fields(self.logger, logging.INFO, "dry-run: not executing", host=host, port=port)
            return

        der_cert = self._fetch_peer_cert(host, port)
        cert = x509.load_der_x509_certificate(der_cert)
        not_after = cert.not_valid_after_utc
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = cn_attrs[0].value if cn_attrs else None
        not_after_str = not_after.isoformat()

        result.raw_output.append(f"TLS cert for {host}:{port} expires {not_after_str}")
        result.findings.append({
            "type": "tls-certificate",
            "subject_cn": subject_cn,
            "not_after": not_after_str,
            "days_remaining": days_remaining,
        })
        if days_remaining < 0:
            result.findings.append({"type": "tls-certificate-expired", "not_after": not_after_str})
        elif days_remaining < CERT_EXPIRY_WARNING_DAYS:
            result.findings.append({"type": "tls-certificate-expiring-soon", "days_remaining": days_remaining})

    def _fetch_peer_cert(self, host: str, port: int) -> bytes:
        # verify_mode=CERT_NONE deliberately: we want to inspect whatever
        # certificate is presented (including self-signed lab certs), not
        # validate trust. getpeercert() only returns parsed fields for
        # validated certs, so fetch the raw DER bytes and parse with
        # `cryptography` instead -- works regardless of trust validation.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=self.tls_timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert(binary_form=True)

    def _check_spf(self, host: str, result: AgentResult) -> None:
        proc = self._run_tool(["dig", "+short", "TXT", host])
        result.raw_output.append(f"dig TXT {host}: {proc.stdout.strip()}")
        spf_records = [line for line in proc.stdout.splitlines() if "v=spf1" in line]
        if spf_records:
            result.findings.append({"type": "spf-record-found", "value": spf_records[0].strip()})
        else:
            result.findings.append({"type": "spf-record-missing", "host": host})

    def _check_dmarc(self, host: str, result: AgentResult) -> None:
        dmarc_host = f"_dmarc.{host}"
        proc = self._run_tool(["dig", "+short", "TXT", dmarc_host])
        result.raw_output.append(f"dig TXT {dmarc_host}: {proc.stdout.strip()}")
        dmarc_records = [line for line in proc.stdout.splitlines() if "v=dmarc1" in line.lower()]
        if dmarc_records:
            result.findings.append({"type": "dmarc-record-found", "value": dmarc_records[0].strip()})
        else:
            result.findings.append({"type": "dmarc-record-missing", "host": dmarc_host})

    def _check_dnssec(self, host: str, result: AgentResult) -> None:
        proc = self._run_tool(["dig", "+dnssec", "+short", host])
        result.raw_output.append(f"dig +dnssec {host}: {proc.stdout.strip()}")
        if "RRSIG" in proc.stdout:
            result.findings.append({"type": "dnssec-enabled", "host": host})
